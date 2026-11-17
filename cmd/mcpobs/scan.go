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

	"github.com/yassinht/mcp-transparency-log/internal/canon"
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

// Two rules are not regular expressions over one string and live outside
// scanRules: URL-EXT (a link to a host other than the server's own) and
// LENGTH-1 (a description far longer than any normal one).
const (
	ruleURLExt = "URL-EXT"
	ruleLength = "LENGTH-1"
)

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

// scanOrder is the order rules are reported in: the regex rules, then the
// two structural ones.
func scanOrder() []string {
	order := make([]string, 0, len(scanRules)+2)
	for _, r := range scanRules {
		order = append(order, r.ID)
	}
	return append(order, ruleURLExt, ruleLength)
}

func scanNotes() map[string]string {
	notes := map[string]string{
		ruleURLExt: "URL to a host other than the server's own",
		ruleLength: fmt.Sprintf("description longer than %d chars", lengthOutlier),
	}
	for _, r := range scanRules {
		notes[r.ID] = r.Note
	}
	return notes
}

func scanCategories() map[string]string {
	cats := map[string]string{ruleURLExt: "links", ruleLength: "length"}
	for _, r := range scanRules {
		cats[r.ID] = r.Category
	}
	return cats
}

// scanHit is one place a rule matched: enough to find and read it.
type scanHit struct {
	Server  string `json:"server,omitempty"`
	Tool    string `json:"tool"`
	Rule    string `json:"rule,omitempty"`
	Field   string `json:"field"`
	Snippet string `json:"snippet"`
}

// serverScan is one server's flags. Detail holds the first hit per rule so a
// page can show the matched text, not just the rule name.
type serverScan struct {
	Server   string             `json:"server"`
	Endpoint string             `json:"endpoint"`
	Host     string             `json:"host"`
	Tools    int                `json:"tools"`
	Rules    []string           `json:"rules"`
	Review   int                `json:"review"`
	Hits     int                `json:"hits"`
	Detail   map[string]scanHit `json:"detail"`
}

// scanReport is everything a scan of one run produced, before any printing.
// cmdScan prints it; export folds it into the site.
type scanReport struct {
	Run            string
	Tools, Servers int
	Flagged        map[string]*serverScan // by endpoint
	RuleTools      map[string]int
	RuleServers    map[string]map[string]bool
	RuleOwners     map[string]map[string]int
	Examples       map[string]scanHit
	URLTotal       int
	URLExt         int
	LongDesc       int
	SchemaHits     int
	TotalByOwner   map[string]int // enumerable servers per publisher, flagged or not

	// Digests is the jcs-v1 / MTL/1 tool-set digest of every enumerable
	// server, by endpoint: the hash HISTOR and CrawlCheck also compute, so
	// our record can be compared with theirs. Undigestible says why a server
	// has none (a nameless tool, a number with no double).
	Digests      map[string]string
	Undigestible map[string]string
}

func newScanReport(runID string) *scanReport {
	rep := &scanReport{
		Run:          runID,
		Flagged:      map[string]*serverScan{},
		RuleTools:    map[string]int{},
		RuleServers:  map[string]map[string]bool{},
		RuleOwners:   map[string]map[string]int{},
		Examples:     map[string]scanHit{},
		TotalByOwner: map[string]int{},
		Digests:      map[string]string{},
		Undigestible: map[string]string{},
	}
	for _, id := range scanOrder() {
		rep.RuleServers[id] = map[string]bool{}
		rep.RuleOwners[id] = map[string]int{}
	}
	return rep
}

// runScan scans every enumerable server of one run. It is the shared core of
// `mcpobs scan` and of the per-server pages the site exports.
func runScan(dataDir, runID string) (*scanReport, error) {
	if runID == "" {
		ids, err := runIDs(dataDir)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("no runs")
		}
		runID = ids[len(ids)-1]
	}
	obs, err := loadRun(dataDir, runID)
	if err != nil {
		return nil, err
	}
	rep := newScanReport(runID)
	for _, o := range obs {
		if o.Outcome != "ok" || len(o.PageBlobs) == 0 {
			continue
		}
		tl, err := toolsOf(dataDir, o.PageBlobs)
		if err != nil {
			continue
		}
		rep.scanServer(o, tl)

		raws := make([]json.RawMessage, 0, len(tl))
		for _, raw := range tl {
			raws = append(raws, raw)
		}
		if d, reason, derr := canon.JCSToolsDigest(raws); derr == nil {
			if d != "" {
				rep.Digests[o.Endpoint] = d
			} else {
				rep.Undigestible[o.Endpoint] = reason
			}
		}
	}
	for _, s := range rep.Flagged {
		sort.Strings(s.Rules)
		for _, id := range s.Rules {
			if reviewRules[id] {
				s.Review++
			}
		}
	}
	return rep, nil
}

func (rep *scanReport) scanServer(o obs, tl map[string]json.RawMessage) {
	rep.Servers++
	rep.TotalByOwner[ownerOf(o.Server)]++
	host := strings.ToLower(o.Host)

	var srv *serverScan
	// mark records that rule id hit this server; detail is the first place
	// it did, kept so a reader can go and look.
	mark := func(id string, hit scanHit) {
		if srv == nil {
			srv = &serverScan{Server: o.Server, Endpoint: o.Endpoint, Host: o.Host, Tools: len(tl), Detail: map[string]scanHit{}}
			rep.Flagged[o.Endpoint] = srv
		}
		srv.Hits++
		if _, seen := srv.Detail[id]; !seen {
			srv.Rules = append(srv.Rules, id)
			srv.Detail[id] = hit
		}
	}
	// count registers a (rule, tool) pair once in the aggregate tables.
	count := func(id, tool string, hit scanHit, toolRules map[string]bool) {
		if toolRules[id] {
			return
		}
		toolRules[id] = true
		rep.RuleTools[id]++
		if !rep.RuleServers[id][o.Server] {
			rep.RuleServers[id][o.Server] = true
			rep.RuleOwners[id][ownerOf(o.Server)]++
		}
		if _, ok := rep.Examples[id]; !ok {
			hit.Server, hit.Rule = o.Server, id
			rep.Examples[id] = hit
		}
	}

	for name, raw := range tl {
		rep.Tools++
		toolRules := map[string]bool{}
		for _, f := range textFields(raw) {
			for _, r := range scanRules {
				loc := firstUnnegated(r.Re, f.text)
				if loc == nil {
					continue
				}
				hit := scanHit{Tool: name, Field: f.name, Snippet: snippet(f.text, loc)}
				if !toolRules[r.ID] && strings.HasPrefix(f.name, "schema.") {
					rep.SchemaHits++
				}
				count(r.ID, name, hit, toolRules)
				mark(r.ID, hit)
			}
			// URLs pointing somewhere other than the server's own host.
			for _, u := range urlRe.FindAllString(f.text, -1) {
				rep.URLTotal++
				pu, perr := url.Parse(u)
				if perr != nil {
					continue
				}
				h := strings.ToLower(pu.Hostname())
				if h == "" || sameSite(h, host) || placeholderHost(h) {
					continue
				}
				rep.URLExt++
				hit := scanHit{Tool: name, Field: f.name, Snippet: u}
				count(ruleURLExt, name, hit, toolRules)
				mark(ruleURLExt, hit)
			}
			if f.name == "description" && len(f.text) > lengthOutlier {
				rep.LongDesc++
				hit := scanHit{Tool: name, Field: "description", Snippet: fmt.Sprintf("%d chars", len(f.text))}
				count(ruleLength, name, hit, toolRules)
				mark(ruleLength, hit)
			}
		}
	}
}

// reviewServers counts servers carrying at least one review-tier flag.
func (rep *scanReport) reviewServers() int {
	n := 0
	for _, s := range rep.Flagged {
		if s.Review > 0 {
			n++
		}
	}
	return n
}

// ruleSummary is one row of the published scan summary.
type ruleSummary struct {
	ID       string  `json:"id"`
	Category string  `json:"category"`
	Note     string  `json:"note"`
	Review   bool    `json:"review"`
	Tools    int     `json:"tools"`
	Servers  int     `json:"servers"`
	Owners   int     `json:"owners"`
	TopOwner string  `json:"top_owner,omitempty"`
	TopShare float64 `json:"top_share,omitempty"`
}

type scanSummary struct {
	Run            string             `json:"run"`
	Date           string             `json:"date"`
	Tools          int                `json:"tools"`
	Servers        int                `json:"servers"`
	FlaggedServers int                `json:"flagged_servers"`
	ReviewServers  int                `json:"review_servers"`
	SchemaHits     int                `json:"schema_hits"`
	URLTotal       int                `json:"urls"`
	URLExt         int                `json:"urls_off_host"`
	Rules          []ruleSummary      `json:"rules"`
	Templates      templateNote       `json:"template_replication"`
	Examples       map[string]scanHit `json:"examples"`
	LengthOutlier  int                `json:"length_outlier"`
}

// templateNote is the picture once the two publishers that flag most are set
// aside: one operator shipping the same text on a thousand servers is a
// finding about that operator, not about a thousand independent choices.
type templateNote struct {
	Publishers     []string `json:"publishers"`
	Flagged        int      `json:"flagged"`
	Review         int      `json:"review"`
	Servers        int      `json:"servers"`
	RestFlagged    int      `json:"rest_flagged"`
	RestReview     int      `json:"rest_review"`
	RestServers    int      `json:"rest_servers"`
	RestFlaggedPct float64  `json:"rest_flagged_pct"`
	RestReviewPct  float64  `json:"rest_review_pct"`
}

func (rep *scanReport) templates() templateNote {
	flaggedByOwner := map[string]int{}
	reviewByOwner := map[string]int{}
	for _, s := range rep.Flagged {
		own := ownerOf(s.Server)
		flaggedByOwner[own]++
		if s.Review > 0 {
			reviewByOwner[own]++
		}
	}
	t := templateNote{Publishers: []string{}}
	for _, kv := range topN(flaggedByOwner, 2) {
		t.Publishers = append(t.Publishers, kv.k)
		t.Flagged += kv.n
		t.Servers += rep.TotalByOwner[kv.k]
		t.Review += reviewByOwner[kv.k]
	}
	t.RestServers = rep.Servers - t.Servers
	t.RestFlagged = len(rep.Flagged) - t.Flagged
	t.RestReview = rep.reviewServers() - t.Review
	t.RestFlaggedPct = pct(t.RestFlagged, t.RestServers)
	t.RestReviewPct = pct(t.RestReview, t.RestServers)
	return t
}

func (rep *scanReport) summary() scanSummary {
	notes, cats := scanNotes(), scanCategories()
	s := scanSummary{
		Run: rep.Run, Date: rep.Run[:10],
		Tools: rep.Tools, Servers: rep.Servers,
		FlaggedServers: len(rep.Flagged), ReviewServers: rep.reviewServers(),
		SchemaHits: rep.SchemaHits, URLTotal: rep.URLTotal, URLExt: rep.URLExt,
		Rules:         []ruleSummary{},
		Templates:     rep.templates(),
		Examples:      rep.Examples,
		LengthOutlier: lengthOutlier,
	}
	for _, id := range scanOrder() {
		r := ruleSummary{ID: id, Category: cats[id], Note: notes[id], Review: reviewRules[id],
			Tools: rep.RuleTools[id], Servers: len(rep.RuleServers[id]), Owners: len(rep.RuleOwners[id])}
		if r.Servers >= 5 {
			if top := topN(rep.RuleOwners[id], 1); len(top) == 1 {
				r.TopOwner, r.TopShare = top[0].k, pct(top[0].n, r.Servers)
			}
		}
		s.Rules = append(s.Rules, r)
	}
	return s
}

func cmdScan(dataDir, runID string, jsonOut string) error {
	rep, err := runScan(dataDir, runID)
	if err != nil {
		return err
	}
	sum := rep.summary()

	fmt.Printf("scan of %s\n", rep.Run)
	fmt.Printf("  %d tools across %d enumerable servers\n", rep.Tools, rep.Servers)
	fmt.Printf("  %d servers carry at least one flag (%.1f%%)\n\n",
		len(rep.Flagged), pct(len(rep.Flagged), rep.Servers))

	fmt.Printf("  %-11s %6s %7s %6s  %s\n", "rule", "tools", "servers", "owners", "what it matches")
	for _, r := range sum.Rules {
		if r.Tools == 0 {
			continue
		}
		fmt.Printf("  %-11s %6d %7d %6d  %s\n", r.ID, r.Tools, r.Servers, r.Owners, r.Note)
	}
	fmt.Printf("\n  %d of %d flagged strings were in inputSchema parameter descriptions, not the tool description\n", rep.SchemaHits, sumInts(rep.RuleTools))
	fmt.Printf("  %d URLs in descriptions, %d pointing off-host\n", rep.URLTotal, rep.URLExt)

	// Concentration: is a pattern one publisher's template, or spread out?
	fmt.Printf("\n  concentration (share of flagged servers from the top owner):\n")
	for _, r := range sum.Rules {
		if r.TopOwner != "" {
			fmt.Printf("    %-11s %5.1f%%  %s\n", r.ID, r.TopShare, r.TopOwner)
		}
	}

	// The two numbers that are actually defensible: servers carrying a flag a
	// reviewer should read, and the same once template replication is set aside.
	fmt.Printf("\n  review-tier flags (%s):\n", strings.Join(sortedKeys(reviewRules), " "))
	fmt.Printf("    %d servers carry at least one (%.1f%% of enumerable)\n", sum.ReviewServers, pct(sum.ReviewServers, rep.Servers))
	t := sum.Templates
	if len(t.Publishers) > 0 {
		fmt.Printf("\n  template replication: %d of %d flagged servers belong to %s\n",
			t.Flagged, len(rep.Flagged), strings.Join(t.Publishers, " and "))
		fmt.Printf("  excluding those publishers: %d of %d servers flagged (%.1f%%), %d review-tier (%.1f%%)\n",
			t.RestFlagged, t.RestServers, t.RestFlaggedPct, t.RestReview, t.RestReviewPct)
	}

	fmt.Printf("\n  one example per rule:\n")
	for _, id := range scanOrder() {
		e, ok := rep.Examples[id]
		if !ok {
			continue
		}
		fmt.Printf("\n    %s  %s / %s  [%s]\n      %s\n", e.Rule, e.Server, e.Tool, e.Field, e.Snippet)
	}

	if jsonOut != "" {
		rows := make([]serverScan, 0, len(rep.Flagged))
		for _, s := range rep.Flagged {
			rows = append(rows, *s)
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Review != rows[j].Review {
				return rows[i].Review > rows[j].Review
			}
			return rows[i].Hits > rows[j].Hits
		})
		out := map[string]any{"summary": sum, "flagged": rows}
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
