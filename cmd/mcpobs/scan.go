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

	"github.com/yassinht/mcp-transparency-log/pkg/canon"
	"github.com/yassinht/mcp-transparency-log/pkg/rules"
)

// The rule set lives in pkg/rules so the hosted service and anyone else can
// run the same rules; these names keep this file readable.
type (
	scanHit   = rules.Hit
	textField = rules.Field
)

var (
	scanRules   = rules.Rules
	reviewRules = rules.Review
	urlRe       = rules.URLRe
)

const (
	ruleURLExt    = rules.URLExt
	ruleLength    = rules.Length
	lengthOutlier = rules.LengthOutlier
)

func scanOrder() []string                              { return rules.Order() }
func scanNotes() map[string]string                     { return rules.Notes() }
func scanCategories() map[string]string                { return rules.Categories() }
func textFields(raw json.RawMessage) []textField       { return rules.TextFields(raw) }
func firstUnnegated(re *regexp.Regexp, s string) []int { return rules.FirstUnnegated(re, s) }
func sameSite(a, b string) bool                        { return rules.SameSite(a, b) }
func placeholderHost(h string) bool                    { return rules.PlaceholderHost(h) }
func snippet(s string, loc []int) string               { return rules.Snippet(s, loc) }

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
				loc := firstUnnegated(r.Re, f.Text)
				if loc == nil {
					continue
				}
				hit := scanHit{Tool: name, Field: f.Name, Snippet: snippet(f.Text, loc)}
				if !toolRules[r.ID] && strings.HasPrefix(f.Name, "schema.") {
					rep.SchemaHits++
				}
				count(r.ID, name, hit, toolRules)
				mark(r.ID, hit)
			}
			// URLs pointing somewhere other than the server's own host.
			for _, u := range urlRe.FindAllString(f.Text, -1) {
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
				hit := scanHit{Tool: name, Field: f.Name, Snippet: u}
				count(ruleURLExt, name, hit, toolRules)
				mark(ruleURLExt, hit)
			}
			if f.Name == "description" && len(f.Text) > lengthOutlier {
				rep.LongDesc++
				hit := scanHit{Tool: name, Field: "description", Snippet: fmt.Sprintf("%d chars", len(f.Text))}
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
