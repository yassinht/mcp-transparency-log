package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/yassinht/mcp-transparency-log/internal/canon"
	"github.com/yassinht/mcp-transparency-log/internal/evidence"
	"github.com/yassinht/mcp-transparency-log/internal/probe"
)

// mcp.lock pins the tool surface of every MCP server a project depends on,
// the way package-lock.json pins dependency versions. `mcpobs check` probes
// each server live, recomputes the surface hash, and exits non-zero when a
// server is no longer serving what was reviewed. Run in CI, that turns a
// silently rewritten tool description -- the rug-pull shape this whole
// project exists to catch -- into a failed build with a diff.
//
// The check is live rather than read from the log on purpose. Dependabot
// does not consult a mirror of npm to tell you a package changed; it looks.
// The log's role here is evidence and history: the hash in the lock can be
// matched against what the log observed on the day it was written, and the
// issue the Action opens links to the server's history page.
//
// Format is deliberately boring JSON. A lockfile is read by humans in code
// review far more often than by machines, and it must diff cleanly. The tool
// text itself lives beside it in <lock>.d/ (see snapshot.go), so the diff of
// a change is the diff of the text.

const lockVersion = 1

const lockUserAgent = "mcpobs-lock/0.1 (+https://github.com/yassinht/mcp-transparency-log)"

type lockFile struct {
	Version   int         `json:"version"`
	Generated string      `json:"generated"`
	Log       string      `json:"log"`
	Servers   []lockEntry `json:"servers"`
}

type lockEntry struct {
	Name     string `json:"name,omitempty"`
	Endpoint string `json:"endpoint"`
	Surface  string `json:"surface_sha256"`
	// ToolsSRI is the jcs-v1 / MTL/1 tool-set digest of the same list, the
	// hash CrawlCheck's lockfiles and HISTOR's records carry, so a lock written
	// here can be compared with what either of them observed.
	ToolsSRI  string   `json:"jcs_v1_tools_sha256,omitempty"`
	Tools     []string `json:"tools"`
	LockedAt  string   `json:"locked_at"`
	Transport string   `json:"transport,omitempty"`
	// Auth names where the credential comes from ("env:MCPOBS_HEADER_X"),
	// never what it is. See auth.go.
	Auth string `json:"auth,omitempty"`
}

// errDrift is returned by check when at least one server no longer matches
// its lock. main turns it into exit status 1 so CI fails.
var errDrift = errors.New("one or more servers drifted from mcp.lock")

// probeSurface fetches a server's current tool surface and reduces it to the
// same canonical hash the crawler records, so a lock written today matches
// what the log observed tonight.
type probed struct {
	Surface   string
	ToolsSRI  string
	Tools     []string
	Transport string
	// Canonical is the sorted, canonicalised tool list the hash was computed
	// over: what the snapshot stores and the evidence file shows.
	Canonical []json.RawMessage
}

func probeSurface(endpoint string, hdr http.Header) (*probed, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cfg := probe.DefaultConfig(lockUserAgent)
	cfg.Headers = hdr
	p := probe.New(cfg)
	res := p.Probe(ctx, endpoint, "")
	if res.Outcome != probe.OutcomeOK {
		reason := res.FailReason
		if reason == "" {
			reason = string(res.Outcome)
		}
		return &probed{Transport: res.Transport}, fmt.Errorf("%s: %s", res.Outcome, reason)
	}
	s, err := canon.SurfaceOf(res.ToolPages)
	if err != nil {
		return &probed{Transport: res.Transport}, fmt.Errorf("canonicalize: %w", err)
	}
	out := &probed{Surface: s.SurfaceSHA256, Tools: s.ToolNames, Transport: res.Transport, Canonical: s.Tools}
	var all []json.RawMessage
	for _, page := range res.ToolPages {
		all = append(all, page...)
	}
	if d, _, derr := canon.JCSToolsDigest(all); derr == nil {
		out.ToolsSRI = d
	}
	return out, nil
}

func readLock(path string) (*lockFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lf lockFile
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if lf.Version != lockVersion {
		return nil, fmt.Errorf("%s: version %d, this build understands %d", path, lf.Version, lockVersion)
	}
	return &lf, nil
}

func writeLock(path string, lf *lockFile) error {
	// A lockfile is read in code review; "servers": null is not what a reader
	// of an empty one should see.
	if lf.Servers == nil {
		lf.Servers = []lockEntry{}
	}
	sort.Slice(lf.Servers, func(i, j int) bool { return lf.Servers[i].Endpoint < lf.Servers[j].Endpoint })
	b, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// cmdLock adds or refreshes the given endpoints in the lockfile. Existing
// entries for other endpoints are kept, so `lock` can be run incrementally.
func cmdLock(path string, endpoints []string) error {
	if len(endpoints) == 0 {
		return errors.New("usage: mcpobs lock <endpoint>... [--lock mcp.lock]")
	}
	lf, err := readLock(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		lf = &lockFile{Version: lockVersion, Log: "https://github.com/yassinht/mcp-transparency-log", Servers: []lockEntry{}}
	}
	byEndpoint := map[string]int{}
	for i, e := range lf.Servers {
		byEndpoint[e.Endpoint] = i
	}

	now := time.Now().UTC().Format(time.RFC3339)
	var failed int
	for _, ep := range endpoints {
		name, endpoint := splitNameEndpoint(ep)
		hdr, envKey, herr := headersFor(name, endpoint)
		if herr != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", endpoint, herr)
			failed++
			continue
		}
		fmt.Fprintf(os.Stderr, "probing %s ... ", endpoint)
		pr, perr := probeSurface(endpoint, hdr)
		if perr != nil {
			if len(hdr) == 0 && strings.HasPrefix(perr.Error(), string(probe.OutcomeAuth)) {
				fmt.Fprintf(os.Stderr, "FAILED (%v; set %s=\"Header-Name: value\" to send credentials)\n", perr, envKey)
			} else {
				fmt.Fprintf(os.Stderr, "FAILED (%v)\n", perr)
			}
			failed++
			continue
		}
		auth := authRef(envKey, hdr)
		fmt.Fprintf(os.Stderr, "%d tools, surface %s, jcs-v1 %s%s\n", len(pr.Tools), pr.Surface[:12], pr.ToolsSRI,
			map[bool]string{true: " (authenticated via " + envKey + ")", false: ""}[auth != ""])
		entry := lockEntry{Name: name, Endpoint: endpoint, Surface: pr.Surface, ToolsSRI: pr.ToolsSRI, Tools: pr.Tools, LockedAt: now, Transport: pr.Transport, Auth: auth}
		if i, ok := byEndpoint[endpoint]; ok {
			if entry.Name == "" {
				entry.Name = lf.Servers[i].Name
			}
			lf.Servers[i] = entry
		} else {
			byEndpoint[endpoint] = len(lf.Servers)
			lf.Servers = append(lf.Servers, entry)
		}
		if rel, serr := writeSnapshot(path, entry, pr.Canonical); serr != nil {
			fmt.Fprintf(os.Stderr, "  snapshot not written: %v\n", serr)
		} else {
			fmt.Fprintf(os.Stderr, "  text recorded in %s\n", rel)
		}
	}
	lf.Generated = now
	if err := writeLock(path, lf); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d servers)\n", path, len(lf.Servers))
	if failed > 0 {
		return fmt.Errorf("%d endpoint(s) could not be locked", failed)
	}
	return nil
}

// cmdCheck re-probes every locked server and reports drift. It prints a
// human-readable report to stdout and, with the matching flags, a JSON
// result, a Markdown report the GitHub Action posts as an issue, and an
// evidence file with the tool text before and after (see evidence.CheckFormat).
func cmdCheck(path string, jsonOut, mdOut, evidenceOut string, update bool) error {
	lf, err := readLock(path)
	if err != nil {
		return err
	}
	if len(lf.Servers) == 0 {
		return fmt.Errorf("%s has no servers", path)
	}

	type result struct {
		Entry     lockEntry `json:"entry"`
		Status    string    `json:"status"` // ok | changed | unreachable | misconfigured
		Surface   string    `json:"surface_now,omitempty"`
		Tools     []string  `json:"tools_now,omitempty"`
		Added     []string  `json:"added,omitempty"`
		Removed   []string  `json:"removed,omitempty"`
		Error     string    `json:"error,omitempty"`
		Transport string    `json:"transport,omitempty"`
		// Edited is filled when the locked text is on hand: which members of
		// which tools changed, with the old and new description.
		Edited   []evidence.EditedTool `json:"edited,omitempty"`
		Snapshot string                `json:"snapshot,omitempty"`
		Note     string                `json:"note,omitempty"`
	}
	var (
		results                             []result
		evServers                           []evidence.CheckedServer
		changed, unreachable, misconfigured int
		now                                 = time.Now().UTC().Format(time.RFC3339)
	)

	fmt.Printf("%s: %d server(s)\n\n", path, len(lf.Servers))
	for i, e := range lf.Servers {
		r := result{Entry: e}
		ev := evidence.CheckedServer{Name: e.Name, Endpoint: e.Endpoint, LockedAt: e.LockedAt, Auth: e.Auth, SurfaceLocked: e.Surface, JCSLocked: e.ToolsSRI}
		label := e.Name
		if label == "" {
			label = e.Endpoint
		}
		// A server locked with a credential must be checked with one. Probing
		// it bare would report "unreachable" and hide a missing secret behind
		// a network-looking failure.
		hdr, envKey, herr := headersFor(e.Name, e.Endpoint)
		if herr != nil || (e.Auth != "" && len(hdr) == 0) {
			r.Status = "misconfigured"
			r.Error = "credential " + envKey + " is not set in this environment"
			if herr != nil {
				r.Error = herr.Error()
			}
			misconfigured++
			fmt.Printf("  MISCONFIGURED %s\n               %s\n", label, r.Error)
			results = append(results, r)
			ev.Status, ev.Error = r.Status, r.Error
			evServers = append(evServers, ev)
			continue
		}
		pr, perr := probeSurface(e.Endpoint, hdr)
		surface, tools, transport := pr.Surface, pr.Tools, pr.Transport
		r.Transport = transport
		switch {
		case perr != nil:
			r.Status, r.Error = "unreachable", perr.Error()
			unreachable++
			fmt.Printf("  UNREACHABLE  %s\n               %s\n", label, perr)
		case surface == e.Surface:
			r.Status = "ok"
			fmt.Printf("  ok           %s  %d tools  %s\n", label, len(tools), surface[:12])
		default:
			r.Status, r.Surface, r.Tools = "changed", surface, tools
			r.Added = missing(e.Tools, tools)
			r.Removed = missing(tools, e.Tools)
			changed++
			fmt.Printf("  CHANGED      %s  %d -> %d tools\n", label, len(e.Tools), len(tools))
			if len(r.Added) > 0 {
				fmt.Printf("               + %s\n", strings.Join(clip(r.Added, 8), ", "))
			}
			if len(r.Removed) > 0 {
				fmt.Printf("               - %s\n", strings.Join(clip(r.Removed, 8), ", "))
			}
			if len(r.Added) == 0 && len(r.Removed) == 0 {
				fmt.Printf("               same tool names; a description or schema was edited in place\n")
			}
			fmt.Printf("               surface %s -> %s\n", e.Surface[:12], surface[:12])

			// With the locked text on hand, say exactly what moved.
			ev.SurfaceNow, ev.JCSNow, ev.ToolsAfter = surface, pr.ToolsSRI, pr.Canonical
			if snap, rel, serr := readSnapshot(path, e); serr != nil {
				r.Note = serr.Error()
				ev.Note = serr.Error()
				fmt.Printf("               (%s)\n", serr)
			} else {
				r.Snapshot, ev.Snapshot, ev.ToolsBefore = rel, rel, snap.Tools
				_, _, r.Edited = evidence.DiffTools(snap.Tools, pr.Canonical)
				ev.Added, ev.Removed, ev.Edited = evidence.DiffTools(snap.Tools, pr.Canonical)
				for _, ed := range r.Edited {
					fmt.Printf("               ~ %s: %s changed\n", ed.Tool, strings.Join(ed.Fields, ", "))
				}
			}
			if update {
				lf.Servers[i] = lockEntry{Name: e.Name, Endpoint: e.Endpoint, Surface: surface, ToolsSRI: pr.ToolsSRI, Tools: tools, LockedAt: now, Transport: transport, Auth: e.Auth}
				if _, serr := writeSnapshot(path, lf.Servers[i], pr.Canonical); serr != nil {
					fmt.Printf("               snapshot not written: %v\n", serr)
				}
			}
		}
		results = append(results, r)
		ev.Status, ev.Error = r.Status, r.Error
		if ev.Added == nil {
			ev.Added = r.Added
		}
		if ev.Removed == nil {
			ev.Removed = r.Removed
		}
		evServers = append(evServers, ev)
	}

	fmt.Printf("\n%d ok, %d changed, %d unreachable, %d misconfigured\n", len(lf.Servers)-changed-unreachable-misconfigured, changed, unreachable, misconfigured)

	if jsonOut != "" {
		out := map[string]any{"lock": path, "checked_at": now, "changed": changed, "unreachable": unreachable, "misconfigured": misconfigured, "results": results}
		if err := writeJSON(jsonOut, out); err != nil {
			return err
		}
	}
	// Markdown for the GitHub Action to post as an issue. Written to read well
	// in a notification: what moved, in which direction, and how to accept it
	// -- not a dump of hashes.
	if mdOut != "" {
		var b strings.Builder
		fmt.Fprintf(&b, "## MCP server tool surface changed\n\n")
		fmt.Fprintf(&b, "`%s` pins %d server(s). Checked %s: **%d changed**, %d unreachable, %d unchanged.\n\n",
			path, len(lf.Servers), now, changed, unreachable, len(lf.Servers)-changed-unreachable)
		for _, r := range results {
			label := r.Entry.Name
			if label == "" {
				label = r.Entry.Endpoint
			}
			hist := "https://yassinht.github.io/mcp-transparency-log/server.html?e=" + urlQuery(r.Entry.Endpoint)
			switch r.Status {
			case "changed":
				fmt.Fprintf(&b, "### %s\n\n`%s`\n\n", label, r.Entry.Endpoint)
				fmt.Fprintf(&b, "Tools: %d → %d · surface `%s…` → `%s…` · locked %s\n\n",
					len(r.Entry.Tools), len(r.Tools), r.Entry.Surface[:12], r.Surface[:12], r.Entry.LockedAt[:10])
				if len(r.Added) == 0 && len(r.Removed) == 0 {
					fmt.Fprintf(&b, "Same tool names — **a description or input schema was edited in place.** This is the change a client never sees; read the new text before accepting it.\n\n")
				}
				if len(r.Added) > 0 {
					fmt.Fprintf(&b, "Added: `%s`\n\n", strings.Join(r.Added, "`, `"))
				}
				if len(r.Removed) > 0 {
					fmt.Fprintf(&b, "Removed: `%s`\n\n", strings.Join(r.Removed, "`, `"))
				}
				for _, ed := range r.Edited {
					fmt.Fprintf(&b, "**`%s`** — %s changed", ed.Tool, strings.Join(ed.Fields, ", "))
					if ed.DescriptionBefore != ed.DescriptionAfter {
						fmt.Fprintf(&b, ":\n\n> before: %s\n>\n> after: %s\n", quoteClip(ed.DescriptionBefore), quoteClip(ed.DescriptionAfter))
					}
					fmt.Fprintf(&b, "\n")
				}
				if r.Note != "" {
					fmt.Fprintf(&b, "_%s_\n\n", r.Note)
				}
				fmt.Fprintf(&b, "[Observed history of this server](%s)\n\n", hist)
			case "unreachable":
				fmt.Fprintf(&b, "### %s — unreachable\n\n`%s` · %s\n\nNot counted as drift; the lock could not be verified this run.\n\n", label, r.Entry.Endpoint, r.Error)
			case "misconfigured":
				fmt.Fprintf(&b, "### %s — not checked\n\n`%s` · %s\n\nThis entry was locked with a credential. Set that variable on the step that runs the check (from a repository secret in GitHub Actions).\n\n", label, r.Entry.Endpoint, r.Error)
			}
		}
		fmt.Fprintf(&b, "---\n\nTo accept after review: `mcpobs --lock %s check --update`, then commit the lockfile and `%s/`.\n\n", path, snapshotDir(path))
		fmt.Fprintf(&b, "Every nightly observation behind the history links is in a signed, independently verifiable log: `mcpobs verify --leaves docs/data/leaves --heads heads --pubkey heads/key.pub` in a clone of https://github.com/yassinht/mcp-transparency-log.\n")
		if err := os.WriteFile(mdOut, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}
	// The evidence file: the text before and after for every changed server,
	// the diff, and the newest public head as a freshness anchor. Verified
	// later with `mcpobs verify-evidence`.
	if evidenceOut != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		head, note := fetchPublicHead(ctx)
		cancel()
		ce := evidence.CheckEvidence{
			Format: evidence.CheckFormat, CheckedAt: now,
			Lock:      evidence.LockRef{Path: path, Generated: lf.Generated},
			PublicLog: head, Servers: evServers,
			Notes: []string{
				"Produced by `mcpobs check` in the environment that ran it. The public log never saw these servers: there is no inclusion proof here, and this file proves nothing about the probe itself.",
				"What it holds is the tool text at lock time (from the snapshot beside the lockfile) and at check time, with the exact diff. `mcpobs verify-evidence` recomputes both surface hashes from the text, so the text cannot be edited afterwards without disagreeing with the lockfile and the CI log.",
				"The public head, when present, was fetched at check time and anchors this file in time: it was produced after that head was published.",
			},
		}
		if note != "" {
			ce.Notes = append(ce.Notes, note)
		}
		if err := writeJSON(evidenceOut, ce); err != nil {
			return err
		}
		fmt.Printf("evidence written to %s\n", evidenceOut)
	}
	if update && changed > 0 {
		lf.Generated = now
		if err := writeLock(path, lf); err != nil {
			return err
		}
		fmt.Printf("updated %s to the current surfaces\n", path)
		return nil
	}
	if changed > 0 {
		return errDrift
	}
	if misconfigured > 0 {
		return fmt.Errorf("%d locked server(s) need a credential that is not set; the check is incomplete", misconfigured)
	}
	return nil
}

// quoteClip keeps a description readable inside a Markdown quote.
func quoteClip(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	if s == "" {
		return "(empty)"
	}
	return s
}

// splitNameEndpoint accepts "name=https://..." or a bare URL.
func splitNameEndpoint(s string) (name, endpoint string) {
	if i := strings.Index(s, "="); i > 0 && !strings.HasPrefix(s, "http") {
		return s[:i], s[i+1:]
	}
	return "", s
}
