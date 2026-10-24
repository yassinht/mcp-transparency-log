package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yassinht/mcp-transparency-log/internal/store"
)

// scan looks for text in tool surfaces that is addressed to the model rather
// than to the user: instructions to ignore prior rules, to prefer this tool
// over others, to forward the conversation somewhere, to supply secrets. A
// tool description is injected straight into the model's context, so this is
// the one place in MCP where a string is an attack surface.
//
// Every rule is a regular expression a reader can run themselves. There is
// deliberately no model doing the judging: a flag that cannot be reproduced
// from the archived bytes is an opinion, and this log does not record
// opinions. The output says "this pattern occurs here", never "this is
// malicious" -- most matches will turn out to be clumsy prose, and the few
// that are not are exactly what a human should look at.
//
// Scope: description, title, and every nested description in inputSchema.
// Parameter descriptions are read by the model too and are the vector most
// scanners skip.

type scanRule struct {
	ID       string
	Category string
	Re       *regexp.Regexp
	Note     string
}

var scanRules = []scanRule{
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

var urlRe = regexp.MustCompile(`https?://[^\s"'<>)\]]+`)

// reviewRules are the patterns whose matches a security reviewer should
// actually read. The rest are informational: they describe a property of the
// text that is worth knowing but that legitimate tools exhibit constantly --
// a parameter documented as "pass your token here", a data tool linking to the
// SEC, a long description. Counting those alongside the others produced a 57%
// flag rate in the first pass, a number that would not survive thirty seconds
// in front of anyone who then read one example.
var reviewRules = map[string]bool{
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

// placeholderHost is a URL host that documents the shape of a value rather
// than pointing anywhere: example.com in a parameter description is a hint
// to the caller, not an off-host link.
func placeholderHost(h string) bool {
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

// firstUnnegated returns the first match of re in s whose preceding text is
// not a negation, or nil.
func firstUnnegated(re *regexp.Regexp, s string) []int {
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

// lengthOutlier is above the p99 measured on the 2026-08-29 census (3,495
// chars). A description several times longer than any normal one is doing
// something other than describing.
const lengthOutlier = 4000

type scanHit struct {
	Server, Tool, Rule, Field, Snippet string
}

type serverScan struct {
	Server string   `json:"server"`
	Host   string   `json:"host"`
	Tools  int      `json:"tools"`
	Rules  []string `json:"rules"`
	Hits   int      `json:"hits"`
}

func cmdScan(dataDir, runID string, jsonOut string) error {
	if runID == "" {
		ids, err := runIDs(dataDir)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return fmt.Errorf("no runs")
		}
		runID = ids[len(ids)-1]
	}
	obs, err := loadRun(dataDir, runID)
	if err != nil {
		return err
	}

	var (
		tools, servers   int
		ruleTools        = map[string]int{}
		ruleServers      = map[string]map[string]bool{}
		ruleOwners       = map[string]map[string]int{}
		examples         = map[string]scanHit{}
		flaggedServers   = map[string]*serverScan{}
		urlExt, urlTotal int
		longDesc         int
		schemaHits       int
	)
	for _, r := range scanRules {
		ruleServers[r.ID] = map[string]bool{}
		ruleOwners[r.ID] = map[string]int{}
	}
	totalByOwner := map[string]int{} // enumerable servers per publisher, flagged or not

	for _, o := range obs {
		if o.Outcome != "ok" || len(o.PageBlobs) == 0 {
			continue
		}
		tl, err := toolsOf(dataDir, o.PageBlobs)
		if err != nil {
			continue
		}
		servers++
		totalByOwner[ownerOf(o.Server)]++
		host := strings.ToLower(o.Host)
		var srv *serverScan
		mark := func(id string) {
			if srv == nil {
				srv = &serverScan{Server: o.Server, Host: o.Host, Tools: len(tl)}
				flaggedServers[o.Server+"\x00"+o.Endpoint] = srv
			}
			srv.Hits++
			found := false
			for _, x := range srv.Rules {
				if x == id {
					found = true
					break
				}
			}
			if !found {
				srv.Rules = append(srv.Rules, id)
			}
		}

		for name, raw := range tl {
			tools++
			fields := textFields(raw)
			toolRules := map[string]bool{}

			for _, f := range fields {
				for _, r := range scanRules {
					if loc := firstUnnegated(r.Re, f.text); loc != nil {
						if !toolRules[r.ID] {
							toolRules[r.ID] = true
							ruleTools[r.ID]++
							if !ruleServers[r.ID][o.Server] {
								ruleServers[r.ID][o.Server] = true
								ruleOwners[r.ID][ownerOf(o.Server)]++
							}
							if _, ok := examples[r.ID]; !ok {
								examples[r.ID] = scanHit{o.Server, name, r.ID, f.name, snippet(f.text, loc)}
							}
							if strings.HasPrefix(f.name, "schema.") {
								schemaHits++
							}
						}
						mark(r.ID)
					}
				}
				// URLs pointing somewhere other than the server's own host.
				for _, u := range urlRe.FindAllString(f.text, -1) {
					urlTotal++
					if pu, perr := url.Parse(u); perr == nil {
						h := strings.ToLower(pu.Hostname())
						if h != "" && !sameSite(h, host) && !placeholderHost(h) {
							urlExt++
							if !toolRules["URL-EXT"] {
								toolRules["URL-EXT"] = true
								ruleTools["URL-EXT"]++
								if ruleServers["URL-EXT"] == nil {
									ruleServers["URL-EXT"] = map[string]bool{}
									ruleOwners["URL-EXT"] = map[string]int{}
								}
								if !ruleServers["URL-EXT"][o.Server] {
									ruleServers["URL-EXT"][o.Server] = true
									ruleOwners["URL-EXT"][ownerOf(o.Server)]++
								}
								if _, ok := examples["URL-EXT"]; !ok {
									examples["URL-EXT"] = scanHit{o.Server, name, "URL-EXT", f.name, u}
								}
							}
							mark("URL-EXT")
						}
					}
				}
				if f.name == "description" && len(f.text) > lengthOutlier {
					longDesc++
					if !toolRules["LENGTH-1"] {
						toolRules["LENGTH-1"] = true
						ruleTools["LENGTH-1"]++
						if ruleServers["LENGTH-1"] == nil {
							ruleServers["LENGTH-1"] = map[string]bool{}
							ruleOwners["LENGTH-1"] = map[string]int{}
						}
						if !ruleServers["LENGTH-1"][o.Server] {
							ruleServers["LENGTH-1"][o.Server] = true
							ruleOwners["LENGTH-1"][ownerOf(o.Server)]++
						}
						if _, ok := examples["LENGTH-1"]; !ok {
							examples["LENGTH-1"] = scanHit{o.Server, name, "LENGTH-1", "description",
								fmt.Sprintf("%d chars", len(f.text))}
						}
					}
					mark("LENGTH-1")
				}
			}
		}
	}

	// ------------------------------------------------------------ report
	fmt.Printf("scan of %s\n", runID)
	fmt.Printf("  %d tools across %d enumerable servers\n", tools, servers)
	fmt.Printf("  %d servers carry at least one flag (%.1f%%)\n\n",
		len(flaggedServers), pct(len(flaggedServers), servers))

	order := []string{}
	for _, r := range scanRules {
		order = append(order, r.ID)
	}
	order = append(order, "URL-EXT", "LENGTH-1")
	notes := map[string]string{"URL-EXT": "URL to a host other than the server's own", "LENGTH-1": fmt.Sprintf("description longer than %d chars", lengthOutlier)}
	for _, r := range scanRules {
		notes[r.ID] = r.Note
	}

	fmt.Printf("  %-11s %6s %7s %6s  %s\n", "rule", "tools", "servers", "owners", "what it matches")
	for _, id := range order {
		if ruleTools[id] == 0 {
			continue
		}
		fmt.Printf("  %-11s %6d %7d %6d  %s\n", id, ruleTools[id], len(ruleServers[id]), len(ruleOwners[id]), notes[id])
	}
	fmt.Printf("\n  %d of %d flagged strings were in inputSchema parameter descriptions, not the tool description\n", schemaHits, sumInts(ruleTools))
	fmt.Printf("  %d URLs in descriptions, %d pointing off-host\n", urlTotal, urlExt)

	// Concentration: is a pattern one publisher's template, or spread out?
	fmt.Printf("\n  concentration (share of flagged servers from the top owner):\n")
	for _, id := range order {
		if len(ruleServers[id]) < 5 {
			continue
		}
		top := topN(ruleOwners[id], 1)
		if len(top) == 1 {
			fmt.Printf("    %-11s %5.1f%%  %s\n", id, pct(top[0].n, len(ruleServers[id])), top[0].k)
		}
	}

	// The two numbers that are actually defensible. First: how many servers
	// carry a flag a reviewer should read, as opposed to an informational one.
	// Second: what the picture looks like once template replication is set
	// aside -- one publisher shipping the same text on a thousand servers is a
	// finding about that publisher, not about a thousand independent choices.
	reviewServers := 0
	flaggedByOwner := map[string]int{}
	reviewByOwner := map[string]int{}
	for _, s := range flaggedServers {
		own := ownerOf(s.Server)
		flaggedByOwner[own]++
		for _, id := range s.Rules {
			if reviewRules[id] {
				reviewServers++
				reviewByOwner[own]++
				break
			}
		}
	}
	fmt.Printf("\n  review-tier flags (%s):\n", strings.Join(sortedKeys(reviewRules), " "))
	fmt.Printf("    %d servers carry at least one (%.1f%% of enumerable)\n", reviewServers, pct(reviewServers, servers))

	top := topN(flaggedByOwner, 2)
	exFlag, exTotal, exReview := 0, 0, 0
	names := []string{}
	for _, kv := range top {
		exFlag += kv.n
		exTotal += totalByOwner[kv.k]
		exReview += reviewByOwner[kv.k]
		names = append(names, kv.k)
	}
	if len(top) > 0 {
		fmt.Printf("\n  template replication: %d of %d flagged servers belong to %s\n",
			exFlag, len(flaggedServers), strings.Join(names, " and "))
		rest := servers - exTotal
		fmt.Printf("  excluding those publishers: %d of %d servers flagged (%.1f%%), %d review-tier (%.1f%%)\n",
			len(flaggedServers)-exFlag, rest, pct(len(flaggedServers)-exFlag, rest),
			reviewServers-exReview, pct(reviewServers-exReview, rest))
	}

	fmt.Printf("\n  one example per rule:\n")
	for _, id := range order {
		e, ok := examples[id]
		if !ok {
			continue
		}
		fmt.Printf("\n    %s  %s / %s  [%s]\n      %s\n", e.Rule, e.Server, e.Tool, e.Field, e.Snippet)
	}

	// ------------------------------------------------------------ json
	if jsonOut != "" {
		rows := make([]serverScan, 0, len(flaggedServers))
		for _, s := range flaggedServers {
			sort.Strings(s.Rules)
			rows = append(rows, *s)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Hits > rows[j].Hits })
		out := map[string]any{
			"run":             runID,
			"tools":           tools,
			"servers":         servers,
			"flagged_servers": len(flaggedServers),
			"rules":           ruleTools,
			"flagged":         rows,
		}
		if err := os.MkdirAll(filepath.Dir(jsonOut), 0o755); err != nil {
			return err
		}
		if err := writeJSON(jsonOut, out); err != nil {
			return err
		}
		fmt.Printf("\n  wrote %s\n", jsonOut)
	}
	return nil
}

type textField struct{ name, text string }

// textFields pulls every string the model will read out of a tool definition:
// the description, the title, and every description nested in the input
// schema, however deep.
func textFields(raw json.RawMessage) []textField {
	var t struct {
		Description string          `json:"description"`
		Title       string          `json:"title"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	if json.Unmarshal(raw, &t) != nil {
		return nil
	}
	out := []textField{}
	if t.Description != "" {
		out = append(out, textField{"description", t.Description})
	}
	if t.Title != "" {
		out = append(out, textField{"title", t.Title})
	}
	if len(t.InputSchema) > 0 {
		var v any
		if json.Unmarshal(t.InputSchema, &v) == nil {
			walkDescriptions(v, "schema", &out)
		}
	}
	return out
}

func walkDescriptions(v any, path string, out *[]textField) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if (k == "description" || k == "title") && path != "" {
				if s, ok := val.(string); ok && s != "" {
					*out = append(*out, textField{path + "." + k, s})
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

// sameSite treats a URL host as the server's own if it is the host or a
// parent/child of it: docs.example.com on api.example.com is not off-host.
func sameSite(urlHost, serverHost string) bool {
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

func snippet(s string, loc []int) string {
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

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sumInts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

var _ = store.ReadBlob
