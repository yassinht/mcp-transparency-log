// Package rules is the rule set the scan runs over tool text: regular
// expressions a reader can run themselves, looking for text addressed to the
// model rather than to the user. A tool description is injected straight into
// the model's context, so this is the one place in MCP where a string is an
// attack surface.
//
// There is deliberately no model doing the judging: a flag that cannot be
// reproduced from the archived bytes is an opinion, and the log does not
// record opinions. Output says "this pattern occurs here", never "this is
// malicious": most matches are clumsy prose, and the few that are not are
// exactly what a human should look at.
//
// Scope: description, title, and every nested description in inputSchema.
// Parameter descriptions are read by the model too and are the vector most
// scanners skip.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type Rule struct {
	ID       string
	Category string
	Re       *regexp.Regexp
	Note     string
}

var Rules = []Rule{
	// Override: telling the model to discard what it was told before.
	{"OVERRIDE-1", "override",
		regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any|your)\b.{0,30}\b(instruction|prompt|rule|guideline|constraint|directive)s?\b`),
		"asks the model to discard prior instructions"},
	{"OVERRIDE-2", "override",
		regexp.MustCompile(`(?i)\bsystem\s+prompt\b`),
		"refers to the system prompt"},

	// Steering: manipulating which tool the model picks.
	// "before" was in the first version of this pattern and matched ordinary
	// workflow prose ("call X before handing off"). Preference over an
	// alternative is the signal; sequencing is not.
	{"STEER-1", "steering",
		regexp.MustCompile(`(?i)\b(prefer(red)?|use|choose|select|pick)\b(\s+this(\s+tool)?)?\s+(over|instead\s+of|rather\s+than|in\s+preference\s+to)\b`),
		"tells the model to prefer this tool over alternatives"},
	{"STEER-2", "steering",
		regexp.MustCompile(`(?i)\b(do\s+not|don'?t|never)\s+(use|call|invoke|try)\s+(any\s+)?(other|the|a|web|built[- ]?in)\b.{0,20}\b(tool|search|function|api)s?\b`),
		"tells the model not to use other tools"},
	{"STEER-3", "steering",
		regexp.MustCompile(`(?i)\b(always|must|should)\s+(call|use|invoke|run)\s+(this|me|it)\b`),
		"tells the model it must call this tool"},

	// Exfiltration: moving conversation or user data somewhere.
	{"EXFIL-1", "exfil",
		regexp.MustCompile(`(?i)\b(send|forward|transmit|post|upload|include|attach|copy|log|report)\b.{0,60}\b(conversation|chat\s+history|message\s+history|user'?s?\s+(message|data|input|query|question)s?|previous\s+messages|context\s+window|full\s+context)\b`),
		"asks to move conversation or user content somewhere"},
	{"EXFIL-2", "exfil",
		regexp.MustCompile(`(?i)\b(exfiltrat|siphon|harvest)\w*`),
		"exfiltration vocabulary"},

	// Secrets: soliciting credentials through a description.
	{"SECRET-1", "secrets",
		regexp.MustCompile(`(?i)\b(provide|enter|include|paste|share|pass|supply|send)\b.{0,40}\b(api[ _-]?key|password|passphrase|secret|access\s+token|auth\s+token|bearer\s+token|credential|private\s+key|seed\s+phrase)s?\b`),
		"asks for credentials in prose"},

	// Model-directed voice: text written to the assistant, not the user.
	// The first version also matched "the agent will need to reuse later",
	// which describes a future need rather than instructing the model. Only
	// second-person address and explicit role assignment are kept.
	{"MODEL-1", "model-voice",
		regexp.MustCompile(`(?i)\b(you\s+are\s+(an?\s+)?(ai|assistant|llm|language\s+model|agent)\b|as\s+an?\s+(ai|assistant|llm|language\s+model)\b|the\s+(assistant|model)\s+(should|must)\s+(always|never|not|only)\b|dear\s+(assistant|ai|model|claude|gpt|llm)\b)`),
		"addresses the model directly"},

	// Hidden content: things a human reviewer would not see.
	// U+200C/U+200D (ZWNJ/ZWJ) are excluded: they are how emoji sequences
	// and several scripts are composed, and flagging a face emoji as hidden
	// content is exactly the kind of noise that buries the real bidi overrides.
	{"HIDDEN-1", "hidden",
		regexp.MustCompile(`[\x{200B}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]`),
		"zero-width space or bidi control characters"},
	{"HIDDEN-2", "hidden",
		regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`),
		"long base64-like run"},
	{"HIDDEN-3", "hidden",
		regexp.MustCompile(`(?i)<\s*(script|img|iframe|style|svg|object|embed)\b`),
		"HTML tag"},
}

// Two rules are not regular expressions over one string and live outside
// Rules: URLExt (a link to a host other than the server's own) and Length (a
// description far longer than any normal one).
const (
	URLExt = "URL-EXT"
	Length = "LENGTH-1"
)

var URLRe = regexp.MustCompile(`https?://[^\s"'<>)\]]+`)

// Review marks the patterns whose matches a security reviewer should actually
// read. The rest are informational: they describe a property of the text that
// is worth knowing but that legitimate tools exhibit constantly -- a parameter
// documented as "pass your token here", a data tool linking to the SEC, a long
// description. Counting those alongside the others produced a 57% flag rate in
// the first pass, a number that would not survive thirty seconds in front of
// anyone who then read one example.
var Review = map[string]bool{
	"OVERRIDE-1": true, "OVERRIDE-2": true,
	"STEER-2": true, "STEER-3": true,
	"EXFIL-1": true, "EXFIL-2": true,
	"MODEL-1":  true,
	"HIDDEN-1": true,
}

// negationRe matches a negating word just before a hit. "never include
// secrets" and "do not forward the conversation" are the opposite of what the
// exfil and secrets rules look for, and the first pass counted them as hits.
// Go's regexp has no lookbehind, so the window before the match is checked
// separately.
var negationRe = regexp.MustCompile(`(?i)\b(never|not|don'?t|do\s+not|doesn'?t|won'?t|without|avoid|no|cannot|can'?t|must\s+not|should\s+not)\W*$`)

// PlaceholderHost is a URL host that documents the shape of a value rather
// than pointing anywhere: example.com in a parameter description is a hint
// to the caller, not an off-host link.
func PlaceholderHost(h string) bool {
	switch {
	case h == "...", strings.Trim(h, ".") == "",
		h == "example.com", h == "example.org", h == "example.net",
		strings.HasSuffix(h, ".example.com"), strings.HasSuffix(h, ".example.org"),
		h == "localhost", strings.HasPrefix(h, "127."), h == "0.0.0.0",
		strings.Contains(h, "{"), strings.Contains(h, "<"), strings.Contains(h, "your-"),
		strings.Contains(h, "yourdomain"), strings.Contains(h, "placeholder"):
		return true
	}
	return false
}

// FirstUnnegated returns the first match of re in s whose preceding text is
// not a negation, or nil.
func FirstUnnegated(re *regexp.Regexp, s string) []int {
	for _, loc := range re.FindAllStringIndex(s, -1) {
		start := loc[0] - 24
		if start < 0 {
			start = 0
		}
		if negationRe.MatchString(s[start:loc[0]]) {
			continue
		}
		return loc
	}
	return nil
}

// LengthOutlier is above the p99 measured on the 2026-08-29 census (3,495
// chars). A description several times longer than any normal one is doing
// something other than describing.
const LengthOutlier = 4000

// Order is the order rules are reported in: the regex rules, then the two
// structural ones.
func Order() []string {
	order := make([]string, 0, len(Rules)+2)
	for _, r := range Rules {
		order = append(order, r.ID)
	}
	return append(order, URLExt, Length)
}

func Notes() map[string]string {
	notes := map[string]string{
		URLExt: "URL to a host other than the server's own",
		Length: fmt.Sprintf("description longer than %d chars", LengthOutlier),
	}
	for _, r := range Rules {
		notes[r.ID] = r.Note
	}
	return notes
}

func Categories() map[string]string {
	cats := map[string]string{URLExt: "links", Length: "length"}
	for _, r := range Rules {
		cats[r.ID] = r.Category
	}
	return cats
}

// Version fingerprints the rule set. Any change to a pattern, the length
// threshold or the rule list produces a new value, which is what cached
// verdicts are keyed by.
func Version() string {
	h := sha256.New()
	fmt.Fprintf(h, "scan-cache/v1\n%d\n", LengthOutlier)
	for _, r := range Rules {
		fmt.Fprintf(h, "%s\t%s\n", r.ID, r.Re.String())
	}
	fmt.Fprintf(h, "%s\n%s\n", URLExt, Length)
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// Hit is one place a rule matched: enough to find and read it.
type Hit struct {
	Server  string `json:"server,omitempty"`
	Tool    string `json:"tool"`
	Rule    string `json:"rule,omitempty"`
	Field   string `json:"field"`
	Snippet string `json:"snippet"`
}

// Field is one string the model will read, with the path it was found at.
type Field struct{ Name, Text string }

// TextFields pulls every string the model will read out of a tool definition:
// the description, the title, and every description nested in the input
// schema, however deep.
func TextFields(raw json.RawMessage) []Field {
	var t struct {
		Description string          `json:"description"`
		Title       string          `json:"title"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	if json.Unmarshal(raw, &t) != nil {
		return nil
	}
	out := []Field{}
	if t.Description != "" {
		out = append(out, Field{"description", t.Description})
	}
	if t.Title != "" {
		out = append(out, Field{"title", t.Title})
	}
	if len(t.InputSchema) > 0 {
		var v any
		if json.Unmarshal(t.InputSchema, &v) == nil {
			walkDescriptions(v, "schema", &out)
		}
	}
	return out
}

func walkDescriptions(v any, path string, out *[]Field) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if (k == "description" || k == "title") && path != "" {
				if s, ok := val.(string); ok && s != "" {
					*out = append(*out, Field{path + "." + k, s})
				}
				continue
			}
			walkDescriptions(val, path+"."+k, out)
		}
	case []any:
		for i, val := range x {
			walkDescriptions(val, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// SameSite treats a URL host as the server's own if it is the host or a
// parent/child of it: docs.example.com on api.example.com is not off-host.
func SameSite(urlHost, serverHost string) bool {
	if urlHost == serverHost {
		return true
	}
	a := strings.Split(urlHost, ".")
	b := strings.Split(serverHost, ".")
	if len(a) < 2 || len(b) < 2 {
		return false
	}
	return strings.Join(a[len(a)-2:], ".") == strings.Join(b[len(b)-2:], ".")
}

// Snippet is the matched text with a little context, whitespace collapsed.
func Snippet(s string, loc []int) string {
	start := loc[0] - 40
	if start < 0 {
		start = 0
	}
	end := loc[1] + 60
	if end > len(s) {
		end = len(s)
	}
	out := strings.Join(strings.Fields(s[start:end]), " ")
	if start > 0 {
		out = "..." + out
	}
	if end < len(s) {
		out += "..."
	}
	return out
}

// Hits evaluates every rule over one server's tools (by name) and returns the
// first hit per rule. Tools are visited in name order so the "first hit" is
// the same whoever runs it, which is what makes the result cacheable and
// comparable between observers.
func Hits(tools map[string]json.RawMessage, host string) map[string]Hit {
	host = strings.ToLower(host)
	hits := map[string]Hit{}
	names := make([]string, 0, len(tools))
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := tools[name]
		for _, f := range TextFields(raw) {
			for _, r := range Rules {
				if _, seen := hits[r.ID]; seen {
					continue
				}
				if loc := FirstUnnegated(r.Re, f.Text); loc != nil {
					hits[r.ID] = Hit{Tool: name, Field: f.Name, Snippet: Snippet(f.Text, loc)}
				}
			}
			if _, seen := hits[URLExt]; !seen {
				for _, u := range URLRe.FindAllString(f.Text, -1) {
					pu, perr := url.Parse(u)
					if perr != nil {
						continue
					}
					h := strings.ToLower(pu.Hostname())
					if h == "" || SameSite(h, host) || PlaceholderHost(h) {
						continue
					}
					hits[URLExt] = Hit{Tool: name, Field: f.Name, Snippet: u}
					break
				}
			}
			if _, seen := hits[Length]; !seen && f.Name == "description" && len(f.Text) > LengthOutlier {
				hits[Length] = Hit{Tool: name, Field: "description", Snippet: fmt.Sprintf("%d chars", len(f.Text))}
			}
		}
	}
	return hits
}
