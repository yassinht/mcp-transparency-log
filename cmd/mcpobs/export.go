package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/yassinht/mcp-transparency-log/internal/mlog"
	"github.com/yassinht/mcp-transparency-log/internal/store"
)

// export writes the small derived files a static site can read.
//
// The archive is gigabytes and lives on the crawler's disk; GitHub Pages holds
// about a gigabyte and runs nothing. So the site gets a derivation, never the
// record itself. That split is deliberate rather than a limitation: a page
// built from derived data cannot be mistaken for the log, and the log stays
// something you verify with `mcpobs verify` against signed heads rather than
// something you read off a web page and hope is honest.
//
// Everything written here is recomputable from the archive. If a number on the
// site is ever disputed, the answer is to re-run this command, not to trust it.
//
// Files, all under <out>/data:
//
//	census.json          one row per nightly run
//	servers.json         one row per endpoint ever observed (large; weekly)
//	changes/<date>.json  what moved on that day
//	s/<ab>/<slug>.json   one server's full history: events, tools, flags
//	badge/<ab>/<slug>.json        shields.io endpoint: surface stability
//	badge/<ab>/<slug>-scan.json   shields.io endpoint: scan result
//	scan.json            the rule scan of the latest run, summarised
//	leaves/              leaf hashes of the Merkle log (what verify checks)
//
// Per-server files and badges are written only when their content changed,
// and they contain nothing that changes with the calendar -- "unchanged since
// 2026-09-12", never "unchanged for 44 days" -- so a quiet server costs the
// repository nothing night after night. The site computes "44 days" itself
// from the latest census date.

type censusDay struct {
	Run       string         `json:"run"`
	Date      string         `json:"date"`
	Endpoints int            `json:"endpoints"`
	Outcomes  map[string]int `json:"outcomes"`
	Tools     int            `json:"tools"`
	Complete  bool           `json:"complete"`
}

type serverRow struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Host        string `json:"host"`
	Endpoint    string `json:"endpoint"`
	Outcome     string `json:"outcome"`
	Tools       int    `json:"tools"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
	Days        int    `json:"days"`
	Changes     int    `json:"changes"`
	StableSince string `json:"stable_since,omitempty"`
	Review      int    `json:"review,omitempty"`
	Flags       int    `json:"flags,omitempty"`
	Listed      bool   `json:"listed"`
	Surface     string `json:"surface,omitempty"`
}

// serverEvent is one thing that happened to one endpoint on one night.
//
//	first_seen       the endpoint entered the registry (or the log began)
//	enumerable       its tool list was readable for the first time
//	surface_changed  tools, descriptions or schemas differ from last night
//	unreachable      it stopped answering (outcome says how)
//	recovered        it answers again; changed=true if the surface moved meanwhile
//	delisted         the registry no longer lists it (only on complete censuses)
//	relisted         it is back in the registry
type serverEvent struct {
	Date    string   `json:"date"`
	Kind    string   `json:"kind"`
	Tools   int      `json:"tools,omitempty"`
	Outcome string   `json:"outcome,omitempty"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	Changed bool     `json:"changed,omitempty"`
	Surface string   `json:"surface,omitempty"`
}

type pageFlag struct {
	Rule    string `json:"rule"`
	Review  bool   `json:"review"`
	Note    string `json:"note"`
	Tool    string `json:"tool"`
	Field   string `json:"field"`
	Snippet string `json:"snippet"`
}

// serverPage is what server.html renders. Everything in it is a function of
// the event history plus the latest scan, so it is stable across quiet nights.
type serverPage struct {
	Slug        string        `json:"slug"`
	Names       []string      `json:"names"`
	Host        string        `json:"host"`
	Endpoint    string        `json:"endpoint"`
	FirstSeen   string        `json:"first_seen"`
	Listed      bool          `json:"listed"`
	Outcome     string        `json:"outcome"`
	Tools       int           `json:"tools"`
	ToolNames   []string      `json:"tool_names,omitempty"`
	Surface     string        `json:"surface,omitempty"`
	ToolsSRI    string        `json:"jcs_v1_tools_sha256,omitempty"`
	StableSince string        `json:"stable_since,omitempty"`
	Changes     int           `json:"changes"`
	ScanRun     string        `json:"scan_run,omitempty"`
	Flags       []pageFlag    `json:"flags"`
	Events      []serverEvent `json:"events"`
}

// badge is the shields.io endpoint schema:
// https://shields.io/badges/endpoint-badge
type badge struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
	CacheSeconds  int    `json:"cacheSeconds"`
}

type epState struct {
	page      serverPage
	names     map[string]bool
	surface   string // last good surface, "" while unreachable
	lastGood  string // last good surface ever, for changes across a gap
	toolNames []string
	days      int
	lastDate  string // date of the last run this endpoint appeared in
	lastEvent string // date of the most recent event, for badges
}

func cmdExport(dataDir, outDir string) error {
	runs, err := runIDs(dataDir)
	if err != nil {
		return err
	}
	if len(runs) == 0 {
		return fmt.Errorf("no runs in %s", dataDir)
	}
	dataOut := filepath.Join(outDir, "data")
	for _, d := range []string{"", "changes", "s", "badge", "peers"} {
		if err := os.MkdirAll(filepath.Join(dataOut, d), 0o755); err != nil {
			return err
		}
	}

	// ------------------------------------------------------------- census
	var census []censusDay
	complete := map[string]bool{}
	for _, id := range runs {
		s, serr := store.SummarizeRun(dataDir, id)
		if serr != nil {
			continue
		}
		if m, merr := readMeta(dataDir, id); merr == nil {
			complete[id] = m.Complete
		}
		census = append(census, censusDay{
			Run: id, Date: id[:10], Endpoints: s.Records, Outcomes: s.Outcomes,
			Tools: s.Tools, Complete: complete[id],
		})
	}
	if err := writeJSON(filepath.Join(dataOut, "census.json"), census); err != nil {
		return err
	}
	fmt.Printf("census.json      %d days\n", len(census))

	// ------------------------------------------------------ per-endpoint history
	// One pass per run, carrying forward what each endpoint looked like last
	// time. Holding every run in memory at once would not survive a year of
	// this; holding one run plus a running summary will.
	states := map[string]*epState{}
	var latestObs map[string]obs

	for i, id := range runs {
		obs, lerr := loadRun(dataDir, id)
		if lerr != nil {
			continue
		}
		if i == len(runs)-1 {
			latestObs = obs
		}
		date := id[:10]
		var dayChanges []map[string]any
		note := func(kind string, st *epState, extra map[string]any) {
			if i == 0 {
				return // day one: everything is new and it means nothing
			}
			e := map[string]any{"kind": kind, "server": st.page.Names[0], "host": st.page.Host,
				"endpoint": st.page.Endpoint, "slug": st.page.Slug}
			for k, v := range extra {
				e[k] = v
			}
			dayChanges = append(dayChanges, e)
		}

		for _, o := range obs {
			st, known := states[o.Endpoint]
			if known && st.lastDate == date {
				// Two registry names for one remote in the same run: same server.
				if !st.names[o.Server] {
					st.names[o.Server] = true
					st.page.Names = append(st.page.Names, o.Server)
				}
				continue
			}
			if !known {
				st = &epState{
					page: serverPage{
						Slug: slugOf(o.Endpoint), Names: []string{o.Server}, Host: o.Host, Endpoint: o.Endpoint,
						FirstSeen: date, Listed: true, Outcome: o.Outcome, Tools: o.ToolCount,
						Flags: []pageFlag{}, Events: []serverEvent{},
					},
					names:    map[string]bool{o.Server: true},
					lastDate: date, days: 1,
				}
				states[o.Endpoint] = st
				st.addEvent(serverEvent{Date: date, Kind: "first_seen", Outcome: o.Outcome, Tools: o.ToolCount})
				if o.Outcome == "ok" {
					st.surface, st.lastGood, st.toolNames = o.Surface, o.Surface, o.ToolNames
					st.page.Surface, st.page.ToolNames, st.page.StableSince = o.Surface, o.ToolNames, date
				}
				note("appeared", st, map[string]any{"tools": o.ToolCount, "outcome": o.Outcome})
				continue
			}

			st.lastDate = date
			st.days++
			st.page.Outcome = o.Outcome
			st.page.Tools = o.ToolCount
			if !st.page.Listed {
				st.page.Listed = true
				st.addEvent(serverEvent{Date: date, Kind: "relisted", Outcome: o.Outcome, Tools: o.ToolCount})
				note("relisted", st, nil)
			}

			if o.Outcome != "ok" {
				if st.surface != "" {
					st.addEvent(serverEvent{Date: date, Kind: "unreachable", Outcome: o.Outcome})
					note("unreachable", st, map[string]any{"outcome": o.Outcome})
					st.surface = ""
				}
				continue
			}
			switch {
			case st.lastGood == "":
				// First time the tool list was readable at all.
				st.addEvent(serverEvent{Date: date, Kind: "enumerable", Tools: o.ToolCount})
				st.page.StableSince = date
				note("enumerable", st, map[string]any{"tools": o.ToolCount})
			case st.surface == "":
				// Back after a gap. Whether it came back the same matters.
				ev := serverEvent{Date: date, Kind: "recovered", Tools: o.ToolCount}
				if o.Surface != st.lastGood {
					ev.Changed = true
					ev.Added, ev.Removed = missing(st.toolNames, o.ToolNames), missing(o.ToolNames, st.toolNames)
					ev.Surface = o.Surface
					st.page.Changes++
					st.page.StableSince = date
				}
				st.addEvent(ev)
				note("recovered", st, map[string]any{"tools": o.ToolCount, "changed": ev.Changed})
			case o.Surface != st.surface:
				ev := serverEvent{Date: date, Kind: "surface_changed", Tools: o.ToolCount, Surface: o.Surface,
					Added: missing(st.toolNames, o.ToolNames), Removed: missing(o.ToolNames, st.toolNames)}
				st.addEvent(ev)
				st.page.Changes++
				st.page.StableSince = date
				note("surface_changed", st, map[string]any{"tools": o.ToolCount,
					"added": len(ev.Added), "removed": len(ev.Removed)})
			}
			st.surface, st.lastGood, st.toolNames = o.Surface, o.Surface, o.ToolNames
			st.page.Surface, st.page.ToolNames = o.Surface, o.ToolNames
		}

		// Delisting is only knowable from a census that reached everything; an
		// incomplete night would otherwise "delist" whatever it did not get to.
		if i > 0 && complete[id] {
			for _, st := range states {
				if st.page.Listed && st.lastDate != date {
					st.page.Listed = false
					st.addEvent(serverEvent{Date: date, Kind: "delisted"})
					note("delisted", st, nil)
				}
			}
		}

		if i > 0 {
			sort.Slice(dayChanges, func(a, b int) bool {
				return fmt.Sprint(dayChanges[a]["server"]) < fmt.Sprint(dayChanges[b]["server"])
			})
			if dayChanges == nil {
				dayChanges = []map[string]any{}
			}
			if err := writeJSON(filepath.Join(dataOut, "changes", date+".json"), dayChanges); err != nil {
				return err
			}
		}
	}
	fmt.Printf("changes/         %d days\n", len(runs)-1)

	// -------------------------------------------------------------- scan
	// The latest run's tool text, through the same rules `mcpobs scan` prints.
	latest := runs[len(runs)-1]
	today := latest[:10]
	rep, serr := runScan(dataDir, latest)
	if serr != nil {
		fmt.Printf("scan             skipped: %v\n", serr)
	} else {
		sum := rep.summary()
		if err := writeJSON(filepath.Join(dataOut, "scan.json"), sum); err != nil {
			return err
		}
		fmt.Printf("scan.json        %d tools, %d servers flagged, %d review-tier\n",
			sum.Tools, sum.FlaggedServers, sum.ReviewServers)

		// One row per endpoint of the latest run, in the shape other observers
		// read for cross-checks (HISTOR docs/cross-check.md): name, endpoint,
		// jcs-v1 digest or null with the outcome, and when it was read. This is
		// how a second, independent crawler and this one catch each other out.
		if n, err := writePeersList(dataOut, latest, latestObs, rep); err != nil {
			return err
		} else {
			fmt.Printf("peers/           %d rows, %d with a digest\n", n, len(rep.Digests))
		}
	}
	notes := scanNotes()

	// ------------------------------------------------- pages, badges, index
	rows := make([]serverRow, 0, len(states))
	var pagesWritten, pagesSame, badgesWritten int
	for _, st := range states {
		p := &st.page
		sort.Strings(p.Names)
		p.Flags = p.Flags[:0]
		p.ToolsSRI = ""
		if rep != nil {
			if p.Outcome == "ok" {
				p.ToolsSRI = rep.Digests[p.Endpoint]
			}
			if s, ok := rep.Flagged[p.Endpoint]; ok && p.Outcome == "ok" {
				p.ScanRun = rep.Run
				for _, id := range s.Rules {
					h := s.Detail[id]
					p.Flags = append(p.Flags, pageFlag{Rule: id, Review: reviewRules[id], Note: notes[id],
						Tool: h.Tool, Field: h.Field, Snippet: h.Snippet})
				}
			} else if p.Outcome == "ok" {
				p.ScanRun = rep.Run
			}
		}
		review := 0
		for _, f := range p.Flags {
			if f.Review {
				review++
			}
		}

		w, err := writeJSONIfChanged(shardPath(filepath.Join(dataOut, "s"), p.Slug, ".json"), p)
		if err != nil {
			return err
		}
		if w {
			pagesWritten++
		} else {
			pagesSame++
		}

		// Badges only for servers whose tools were ever readable: a badge that
		// can only ever say "not observable" is noise in a README.
		if st.lastGood != "" {
			for suffix, b := range map[string]badge{
				".json":      surfaceBadge(p, st, today),
				"-scan.json": scanBadge(p, review),
			} {
				w, err := writeJSONIfChanged(shardPath(filepath.Join(dataOut, "badge"), p.Slug, suffix), b)
				if err != nil {
					return err
				}
				if w {
					badgesWritten++
				}
			}
		}

		rows = append(rows, serverRow{
			Name: p.Names[0], Slug: p.Slug, Host: p.Host, Endpoint: p.Endpoint,
			Outcome: p.Outcome, Tools: p.Tools, FirstSeen: p.FirstSeen, LastSeen: st.lastDate,
			Days: st.days, Changes: p.Changes, StableSince: p.StableSince,
			Review: review, Flags: len(p.Flags), Listed: p.Listed, Surface: st.surface,
		})
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].Name < rows[b].Name })
	if err := writeJSON(filepath.Join(dataOut, "servers.json"), rows); err != nil {
		return err
	}
	fmt.Printf("servers.json     %d endpoints\n", len(rows))
	fmt.Printf("s/               %d pages written, %d unchanged\n", pagesWritten, pagesSame)
	fmt.Printf("badge/           %d badges written\n", badgesWritten)

	// Leaf hashes last, and separately from everything above: the files in
	// data/ are a convenience for the site and can be regenerated any way I
	// like, while these are what a stranger checks the signed heads against.
	// Past runs re-export byte-identically, so git stores only the new day.
	logDir := filepath.Join(dataDir, "tlog")
	if _, err := os.Stat(filepath.Join(logDir, "size")); err == nil {
		man, lerr := mlog.ExportLeaves(logDir, filepath.Join(dataOut, "leaves"))
		if lerr != nil {
			fmt.Printf("leaves/          skipped: %v\n", lerr)
		} else {
			fmt.Printf("leaves/          %d leaves across %d files (%.1f MB)\n",
				man.Size, len(man.Runs), float64(man.Size*32)/(1<<20))
		}
	}

	fmt.Printf("\nwrote to %s\n", outDir)
	return nil
}

// writePeersList publishes the latest census as a cross-check list. Rows are
// sorted by endpoint so the file diffs cleanly; the index beside it says what
// the digest is and how often the list is rewritten.
func writePeersList(dataOut, runID string, latest map[string]obs, rep *scanReport) (int, error) {
	type row struct {
		Name     string  `json:"name"`
		Endpoint string  `json:"endpoint"`
		Digest   *string `json:"digest"`
		ReadAt   string  `json:"read_at"`
		Tools    int     `json:"tools,omitempty"`
		Outcome  string  `json:"outcome,omitempty"`
		Reason   string  `json:"reason,omitempty"`
	}
	rows := make([]row, 0, len(latest))
	for _, o := range latest {
		r := row{Name: o.Server, Endpoint: o.Endpoint, ReadAt: o.ObservedAt, Tools: o.ToolCount}
		if d, ok := rep.Digests[o.Endpoint]; ok && o.Outcome == "ok" {
			r.Digest = &d
		} else {
			r.Outcome = o.Outcome
			if o.Outcome == "ok" {
				r.Outcome = "undigestible"
				r.Reason = rep.Undigestible[o.Endpoint]
				if r.Reason == "" {
					// The scan skipped it: no archived tool page, or one that
					// would not parse. Say so rather than leave a reader guessing.
					r.Reason = "tool pages not readable from the archive"
				}
			}
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(a, b int) bool {
		if rows[a].Endpoint != rows[b].Endpoint {
			return rows[a].Endpoint < rows[b].Endpoint
		}
		return rows[a].Name < rows[b].Name
	})
	var buf bytes.Buffer
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			return 0, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	dir := filepath.Join(dataOut, "peers")
	if err := os.WriteFile(filepath.Join(dir, "tool-digests-latest.jsonl"), buf.Bytes(), 0o644); err != nil {
		return 0, err
	}
	index := map[string]any{
		"kind":         "mcp-transparency-log-peer-list",
		"v":            1,
		"run":          runID,
		"date":         runID[:10],
		"method":       "digest",
		"digest":       "jcs-v1 / MTL/1 tool-set digest: contract {name, description, inputSchema, outputSchema?} per tool, sorted by name in UTF-16 code units, RFC 8785, SHA-256 as SRI",
		"window_hours": 24,
		"schedule":     "rewritten after every nightly census, about 04:00 UTC",
		"since":        "2026-11-17",
		"rows":         len(rows),
		"with_digest":  len(rep.Digests),
		"sources": []map[string]string{{
			"name": "list",
			"url":  "https://yassinht.github.io/mcp-transparency-log/data/peers/tool-digests-latest.jsonl",
		}},
		"log":     "https://github.com/yassinht/mcp-transparency-log",
		"contact": "https://github.com/yassinht/mcp-transparency-log/issues",
	}
	return len(rows), writeJSON(filepath.Join(dir, "index.json"), index)
}

func (st *epState) addEvent(e serverEvent) {
	st.page.Events = append(st.page.Events, e)
	st.lastEvent = e.Date
}

// surfaceBadge says, in a README, whether the server is still serving what
// it served. Colour is a function of how long the surface has stood: it
// flips at 7 and 30 days, so a quiet server rewrites its badge twice in its
// life and never again.
func surfaceBadge(p *serverPage, st *epState, today string) badge {
	b := badge{SchemaVersion: 1, Label: "mcp surface", CacheSeconds: 3600}
	switch {
	case !p.Listed:
		b.Message, b.Color = "delisted "+st.lastEvent, "lightgrey"
	case p.Outcome != "ok":
		b.Message, b.Color = "unreachable since "+st.lastEvent, "red"
	default:
		age := daysBetween(p.StableSince, today)
		switch {
		case p.Changes > 0 && age < 7:
			b.Message, b.Color = "changed "+p.StableSince, "orange"
		case age < 7:
			b.Message, b.Color = "unchanged since "+p.StableSince, "yellow"
		case age < 30:
			b.Message, b.Color = "unchanged since "+p.StableSince, "green"
		default:
			b.Message, b.Color = "unchanged since "+p.StableSince, "brightgreen"
		}
	}
	return b
}

func scanBadge(p *serverPage, review int) badge {
	b := badge{SchemaVersion: 1, Label: "mcp scan", CacheSeconds: 3600}
	switch {
	case p.Outcome != "ok" || !p.Listed:
		b.Message, b.Color = "not observable", "lightgrey"
	case review > 0:
		b.Message, b.Color = fmt.Sprintf("%d rule%s to review", review, plural(review)), "orange"
	case len(p.Flags) > 0:
		b.Message, b.Color = "no review flags", "green"
	default:
		b.Message, b.Color = "clean", "brightgreen"
	}
	return b
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func daysBetween(from, to string) int {
	a, err1 := time.Parse("2006-01-02", from)
	b, err2 := time.Parse("2006-01-02", to)
	if err1 != nil || err2 != nil {
		return 0
	}
	return int(b.Sub(a).Hours() / 24)
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// writeJSONIfChanged leaves an identical file untouched so git sees nothing.
func writeJSONIfChanged(path string, v any) (bool, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return false, err
	}
	if old, rerr := os.ReadFile(path); rerr == nil && bytes.Equal(old, b) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, b, 0o644)
}
