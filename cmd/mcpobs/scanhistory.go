package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yassinht/mcp-transparency-log/pkg/rules"
)

// scan --since replays the rule set over every census in a date range and
// answers the question a single night cannot: when did a pattern first
// appear, on whose server, and how did it spread. The archive makes this
// possible because raw bytes were kept from the first night; a scanner that
// stored only its verdicts could not re-ask the question with a new rule.
//
// The work is keyed by (surface hash, host): a surface that did not change
// scans the same way every night, so eighty nights of a stable server cost one
// scan. Results are cached on disk under a key derived from the rule set, so
// editing a rule invalidates the cache instead of silently reusing stale
// verdicts.

// cacheEntry is one scanned (surface, host): the rules that hit and the first
// place each did, enough to show a reader the text without rescanning.
type cacheEntry struct {
	Key  string             `json:"k"`
	Hits map[string]scanHit `json:"r"`
}

func cacheKey(surface, host string) string { return surface + "|" + strings.ToLower(host) }

type scanCache struct {
	path    string
	entries map[string]map[string]scanHit
	w       *bufio.Writer
	f       *os.File
	loaded  int
	added   int
}

func openScanCache(dir string) (*scanCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	c := &scanCache{path: filepath.Join(dir, "rules-"+rules.Version()+".jsonl"), entries: map[string]map[string]scanHit{}}
	if f, err := os.Open(c.path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
		for sc.Scan() {
			var e cacheEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil && e.Key != "" {
				c.entries[e.Key] = e.Hits
			}
		}
		f.Close()
		c.loaded = len(c.entries)
	}
	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	c.f, c.w = f, bufio.NewWriterSize(f, 1<<20)
	return c, nil
}

func (c *scanCache) get(key string) (map[string]scanHit, bool) {
	e, ok := c.entries[key]
	return e, ok
}

func (c *scanCache) put(key string, hits map[string]scanHit) error {
	c.entries[key] = hits
	c.added++
	b, err := json.Marshal(cacheEntry{Key: key, Hits: hits})
	if err != nil {
		return err
	}
	_, err = c.w.Write(append(b, '\n'))
	return err
}

func (c *scanCache) close() error {
	if err := c.w.Flush(); err != nil {
		return err
	}
	return c.f.Close()
}

// ---------------------------------------------------------------- history

type ruleHistory struct {
	ID            string      `json:"id"`
	Category      string      `json:"category"`
	Note          string      `json:"note"`
	Review        bool        `json:"review"`
	FirstSeen     string      `json:"first_seen,omitempty"`
	FirstServer   string      `json:"first_server,omitempty"`
	FirstEndpoint string      `json:"first_endpoint,omitempty"`
	FirstOwner    string      `json:"first_owner,omitempty"`
	FirstHit      *scanHit    `json:"first_hit,omitempty"`
	Servers       int         `json:"servers"`        // distinct endpoints ever hit
	Owners        int         `json:"owners"`         // distinct publishers ever hit
	NightsPresent int         `json:"nights_present"` // nights with at least one hit
	LastNight     int         `json:"last_night_servers"`
	Series        []nightHits `json:"series"`
	// NewPerNight is how many endpoints were hit by this rule for the first
	// time that night: the spread, as opposed to the standing count.
	NewPerNight []nightHits `json:"new_per_night"`
	// Owners' first appearance, newest publishers last, capped for size.
	OwnerFirstSeen []ownerFirst `json:"owner_first_seen"`

	servers    map[string]string // endpoint -> first date
	owners     map[string]string // owner -> first date
	ownerCount map[string]int    // owner -> distinct endpoints hit
}

type nightHits struct {
	Date    string `json:"date"`
	Servers int    `json:"servers"`
}

type ownerFirst struct {
	Owner     string `json:"owner"`
	FirstSeen string `json:"first_seen"`
	Servers   int    `json:"servers"`
}

type nightTotals struct {
	Date       string `json:"date"`
	Enumerable int    `json:"enumerable"`
	Flagged    int    `json:"flagged"`
	Review     int    `json:"review"`
	Scanned    int    `json:"scanned"`
	Unreadable int    `json:"unreadable"`
}

type scanHistory struct {
	Since           string         `json:"since"`
	Until           string         `json:"until"`
	Nights          []nightTotals  `json:"nights"`
	SurfacesScanned int            `json:"surfaces_scanned"`
	CacheHits       int            `json:"cache_hits"`
	CacheFile       string         `json:"cache_file"`
	RulesVersion    string         `json:"rules_version"`
	Rules           []*ruleHistory `json:"rules"`
	Duration        string         `json:"duration"`
}

func cmdScanSince(dataDir, since, until, cacheDir, jsonOut string) error {
	start := time.Now()
	if cacheDir == "" {
		cacheDir = filepath.Join(dataDir, "scan-cache")
	}
	ids, err := runIDs(dataDir)
	if err != nil {
		return err
	}
	var runs []string
	for _, id := range ids {
		d := id
		if len(d) > 10 {
			d = d[:10]
		}
		if d < since || (until != "" && d > until) {
			continue
		}
		m, merr := readMeta(dataDir, id)
		if merr != nil || !m.Complete && len(runs) > 0 && runs[len(runs)-1][:10] == d {
			// A resumed or aborted run beside a complete one on the same day
			// would double count the day; keep the first.
			continue
		}
		if len(runs) > 0 && runs[len(runs)-1][:10] == d {
			continue
		}
		runs = append(runs, id)
	}
	if len(runs) == 0 {
		return fmt.Errorf("no runs between %s and %s", since, until)
	}
	cache, err := openScanCache(cacheDir)
	if err != nil {
		return err
	}
	defer cache.close()
	fmt.Fprintf(os.Stderr, "replaying %d rules over %d nights (%s → %s); cache %s holds %d surfaces\n",
		len(scanOrder()), len(runs), runs[0][:10], runs[len(runs)-1][:10], filepath.Base(cache.path), cache.loaded)

	notes, cats := scanNotes(), scanCategories()
	hist := &scanHistory{Since: runs[0][:10], Until: runs[len(runs)-1][:10], RulesVersion: rules.Version(), CacheFile: cache.path}
	byID := map[string]*ruleHistory{}
	for _, id := range scanOrder() {
		r := &ruleHistory{ID: id, Category: cats[id], Note: notes[id], Review: reviewRules[id],
			servers: map[string]string{}, owners: map[string]string{}, ownerCount: map[string]int{}, Series: []nightHits{}, NewPerNight: []nightHits{}, OwnerFirstSeen: []ownerFirst{}}
		byID[id] = r
		hist.Rules = append(hist.Rules, r)
	}

	var cacheHits, scanned int
	for _, run := range runs {
		date := run[:10]
		obsMap, lerr := loadRun(dataDir, run)
		if lerr != nil {
			return lerr
		}
		list := make([]obs, 0, len(obsMap))
		for _, o := range obsMap {
			if o.Outcome == "ok" && len(o.PageBlobs) > 0 && o.Surface != "" {
				list = append(list, o)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Server < list[j].Server })

		tot := nightTotals{Date: date, Enumerable: len(list)}
		hitTonight := map[string]int{}
		newTonight := map[string]int{}
		seenEndpoint := map[string]bool{}
		for _, o := range list {
			if seenEndpoint[o.Endpoint] {
				continue // two registry names on one endpoint: one server
			}
			seenEndpoint[o.Endpoint] = true
			key := cacheKey(o.Surface, o.Host)
			hits, ok := cache.get(key)
			if ok {
				cacheHits++
			} else {
				tl, terr := toolsOf(dataDir, o.PageBlobs)
				if terr != nil {
					tot.Unreadable++
					continue
				}
				hits = rules.Hits(tl, o.Host)
				scanned++
				if perr := cache.put(key, hits); perr != nil {
					return perr
				}
			}
			tot.Scanned++
			if len(hits) > 0 {
				tot.Flagged++
			}
			review := false
			for id, h := range hits {
				r := byID[id]
				if r == nil {
					continue
				}
				if reviewRules[id] {
					review = true
				}
				hitTonight[id]++
				own := ownerOf(o.Server)
				if _, known := r.servers[o.Endpoint]; !known {
					r.servers[o.Endpoint] = date
					r.ownerCount[own]++
					newTonight[id]++
				}
				if _, known := r.owners[own]; !known {
					r.owners[own] = date
				}
				if r.FirstSeen == "" {
					hh := h
					r.FirstSeen, r.FirstServer, r.FirstEndpoint, r.FirstOwner, r.FirstHit = date, o.Server, o.Endpoint, own, &hh
				}
			}
			if review {
				tot.Review++
			}
		}
		for _, r := range hist.Rules {
			n := hitTonight[r.ID]
			r.Series = append(r.Series, nightHits{Date: date, Servers: n})
			r.NewPerNight = append(r.NewPerNight, nightHits{Date: date, Servers: newTonight[r.ID]})
			if n > 0 {
				r.NightsPresent++
			}
			r.LastNight = n
		}
		hist.Nights = append(hist.Nights, tot)
		fmt.Fprintf(os.Stderr, "  %s  %6d enumerable  %5d flagged  %4d review  (%d scanned, %d from cache so far)\n",
			date, tot.Enumerable, tot.Flagged, tot.Review, scanned, cacheHits)
	}
	hist.SurfacesScanned, hist.CacheHits = scanned, cacheHits
	hist.Duration = time.Since(start).Round(time.Second).String()

	for _, r := range hist.Rules {
		r.Servers, r.Owners = len(r.servers), len(r.owners)
		for own, d := range r.owners {
			r.OwnerFirstSeen = append(r.OwnerFirstSeen, ownerFirst{Owner: own, FirstSeen: d, Servers: r.ownerCount[own]})
		}
		sort.Slice(r.OwnerFirstSeen, func(i, j int) bool {
			if r.OwnerFirstSeen[i].FirstSeen != r.OwnerFirstSeen[j].FirstSeen {
				return r.OwnerFirstSeen[i].FirstSeen < r.OwnerFirstSeen[j].FirstSeen
			}
			return r.OwnerFirstSeen[i].Owner < r.OwnerFirstSeen[j].Owner
		})
		if len(r.OwnerFirstSeen) > 200 {
			r.OwnerFirstSeen = r.OwnerFirstSeen[:200]
		}
	}

	printScanHistory(hist)
	if jsonOut != "" {
		if err := os.MkdirAll(filepath.Dir(jsonOut), 0o755); err != nil {
			return err
		}
		if err := writeJSON(jsonOut, hist); err != nil {
			return err
		}
		fmt.Printf("\n  wrote %s\n", jsonOut)
	}
	return nil
}

func printScanHistory(h *scanHistory) {
	first, last := h.Nights[0], h.Nights[len(h.Nights)-1]
	fmt.Printf("rules replayed over %d nights, %s → %s  (%s; %d surfaces scanned, %d served from cache)\n\n",
		len(h.Nights), h.Since, h.Until, h.Duration, h.SurfacesScanned, h.CacheHits)
	fmt.Printf("  %-11s %-10s  %7s %6s %6s %9s  %s\n", "rule", "first seen", "servers", "owners", "nights", "last night", "first on")
	for _, r := range h.Rules {
		if r.FirstSeen == "" {
			fmt.Printf("  %-11s %-10s  %7s %6s %6s %9s  %s\n", r.ID, "never", "0", "0", "0", "0", "")
			continue
		}
		fmt.Printf("  %-11s %-10s  %7d %6d %6d %9d  %s\n", r.ID, r.FirstSeen, r.Servers, r.Owners, r.NightsPresent, r.LastNight, r.FirstServer)
	}
	fmt.Printf("\n  first night %s: %d enumerable, %d flagged, %d review-tier\n", first.Date, first.Enumerable, first.Flagged, first.Review)
	fmt.Printf("  last night  %s: %d enumerable, %d flagged, %d review-tier\n", last.Date, last.Enumerable, last.Flagged, last.Review)

	// Rules that arrived after the series began are the interesting ones: a
	// pattern nobody used on night one and many use now is either a new
	// template or a new idea spreading.
	var late []*ruleHistory
	for _, r := range h.Rules {
		if r.FirstSeen != "" && r.FirstSeen > h.Since {
			late = append(late, r)
		}
	}
	if len(late) > 0 {
		fmt.Printf("\n  appeared after the first night:\n")
		for _, r := range late {
			fmt.Printf("    %-11s %s  on %s (%s)\n", r.ID, r.FirstSeen, r.FirstServer, r.FirstOwner)
			if r.FirstHit != nil {
				fmt.Printf("                 %s [%s]: %s\n", r.FirstHit.Tool, r.FirstHit.Field, r.FirstHit.Snippet)
			}
		}
	}
	// The biggest single-night jumps in new servers per rule: where a template
	// shipped, or a publisher onboarded a fleet.
	fmt.Printf("\n  largest one-night spreads (new servers carrying the rule that night):\n")
	type jump struct {
		id   string
		date string
		n    int
	}
	var jumps []jump
	for _, r := range h.Rules {
		for i, p := range r.NewPerNight {
			if i == 0 || p.Servers == 0 {
				continue
			}
			jumps = append(jumps, jump{r.ID, p.Date, p.Servers})
		}
	}
	sort.Slice(jumps, func(i, j int) bool { return jumps[i].n > jumps[j].n })
	if len(jumps) > 8 {
		jumps = jumps[:8]
	}
	for _, j := range jumps {
		fmt.Printf("    %-11s %s  +%d\n", j.id, j.date, j.n)
	}
}
