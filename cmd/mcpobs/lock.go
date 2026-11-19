package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yassinht/mcp-transparency-log/pkg/evidence"
	"github.com/yassinht/mcp-transparency-log/pkg/lock"
	"github.com/yassinht/mcp-transparency-log/pkg/probe"
)

// The lock and check commands: the engine is pkg/lock, this file is the
// printing, the Markdown the Action posts, and the evidence file.

// errDrift is returned by check when at least one server no longer matches
// its lock. main turns it into exit status 1 so CI fails.
var errDrift = errors.New("one or more servers drifted from mcp.lock")

// cmdLock adds or refreshes the given endpoints in the lockfile. Existing
// entries for other endpoints are kept, so `lock` can be run incrementally.
func cmdLock(path string, endpoints []string) error {
	if len(endpoints) == 0 {
		return errors.New("usage: mcpobs lock <endpoint>... [--lock mcp.lock]")
	}
	lf, err := lock.Read(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		lf = lock.New()
	}
	byEndpoint := map[string]int{}
	for i, e := range lf.Servers {
		byEndpoint[e.Endpoint] = i
	}

	now := time.Now().UTC()
	var failed int
	for _, ep := range endpoints {
		name, endpoint := splitNameEndpoint(ep)
		hdr, envKey, herr := lock.HeadersFor(name, endpoint)
		if herr != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", endpoint, herr)
			failed++
			continue
		}
		fmt.Fprintf(os.Stderr, "probing %s ... ", endpoint)
		pr, perr := lock.Probe(context.Background(), endpoint, hdr)
		if perr != nil {
			if len(hdr) == 0 && strings.HasPrefix(perr.Error(), string(probe.OutcomeAuth)) {
				fmt.Fprintf(os.Stderr, "FAILED (%v; set %s=\"Header-Name: value\" to send credentials)\n", perr, envKey)
			} else {
				fmt.Fprintf(os.Stderr, "FAILED (%v)\n", perr)
			}
			failed++
			continue
		}
		auth := lock.AuthRef(envKey, hdr)
		fmt.Fprintf(os.Stderr, "%d tools, surface %s, jcs-v1 %s%s\n", len(pr.Tools), pr.Surface[:12], pr.ToolsSRI,
			map[bool]string{true: " (authenticated via " + envKey + ")", false: ""}[auth != ""])
		entry := lock.EntryFrom(name, endpoint, pr, auth, now)
		if i, ok := byEndpoint[endpoint]; ok {
			if entry.Name == "" {
				entry.Name = lf.Servers[i].Name
			}
			lf.Servers[i] = entry
		} else {
			byEndpoint[endpoint] = len(lf.Servers)
			lf.Servers = append(lf.Servers, entry)
		}
		if rel, serr := lock.WriteSnapshot(path, entry, pr.Canonical); serr != nil {
			fmt.Fprintf(os.Stderr, "  snapshot not written: %v\n", serr)
		} else {
			fmt.Fprintf(os.Stderr, "  text recorded in %s\n", rel)
		}
	}
	lf.Generated = now.Format(time.RFC3339)
	if err := lock.Write(path, lf); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d servers)\n", path, len(lf.Servers))
	if failed > 0 {
		return fmt.Errorf("%d endpoint(s) could not be locked", failed)
	}
	return nil
}

// checkResult is the JSON shape of --check-json, kept stable for the Action.
type checkResult struct {
	Entry     lock.Entry            `json:"entry"`
	Status    string                `json:"status"` // ok | changed | unreachable | misconfigured
	Surface   string                `json:"surface_now,omitempty"`
	Tools     []string              `json:"tools_now,omitempty"`
	Added     []string              `json:"added,omitempty"`
	Removed   []string              `json:"removed,omitempty"`
	Error     string                `json:"error,omitempty"`
	Transport string                `json:"transport,omitempty"`
	Edited    []evidence.EditedTool `json:"edited,omitempty"`
	Snapshot  string                `json:"snapshot,omitempty"`
	Note      string                `json:"note,omitempty"`
}

// cmdCheck re-probes every locked server and reports drift. It prints a
// human-readable report to stdout and, with the matching flags, a JSON
// result, a Markdown report the GitHub Action posts as an issue, and an
// evidence file with the tool text before and after (see evidence.CheckFormat).
func cmdCheck(path string, jsonOut, mdOut, evidenceOut string, update bool) error {
	lf, err := lock.Read(path)
	if err != nil {
		return err
	}
	if len(lf.Servers) == 0 {
		return fmt.Errorf("%s has no servers", path)
	}

	var (
		results                             []checkResult
		evServers                           []evidence.CheckedServer
		changed, unreachable, misconfigured int
		now                                 = time.Now().UTC().Format(time.RFC3339)
	)

	fmt.Printf("%s: %d server(s)\n\n", path, len(lf.Servers))
	for i, e := range lf.Servers {
		label := e.Label()
		// The locked text, when it was recorded.
		var before []json.RawMessage
		snap, rel, serr := lock.ReadSnapshot(path, e)
		if serr == nil {
			before = snap.Tools
		}
		res := lock.Check(context.Background(), e, lock.EnvCredentials, before)

		r := checkResult{Entry: e, Status: string(res.Status), Error: res.Error, Snapshot: rel}
		ev := evidence.CheckedServer{Name: e.Name, Endpoint: e.Endpoint, LockedAt: e.LockedAt, Auth: e.Auth,
			SurfaceLocked: e.Surface, JCSLocked: e.ToolsSRI, Status: string(res.Status), Error: res.Error}
		if res.Now != nil {
			r.Transport = res.Now.Transport
		}
		switch res.Status {
		case lock.StatusMisconfigured:
			misconfigured++
			fmt.Printf("  MISCONFIGURED %s\n               %s\n", label, res.Error)
		case lock.StatusUnreachable:
			unreachable++
			fmt.Printf("  UNREACHABLE  %s\n               %s\n", label, res.Error)
		case lock.StatusOK:
			fmt.Printf("  ok           %s  %d tools  %s\n", label, len(res.Now.Tools), res.Now.Surface[:12])
		case lock.StatusChanged:
			changed++
			r.Surface, r.Tools, r.Added, r.Removed, r.Edited = res.Now.Surface, res.Now.Tools, res.Added, res.Removed, res.Edited
			fmt.Printf("  CHANGED      %s  %d -> %d tools\n", label, len(e.Tools), len(res.Now.Tools))
			if len(r.Added) > 0 {
				fmt.Printf("               + %s\n", strings.Join(clip(r.Added, 8), ", "))
			}
			if len(r.Removed) > 0 {
				fmt.Printf("               - %s\n", strings.Join(clip(r.Removed, 8), ", "))
			}
			if res.InPlace() {
				fmt.Printf("               same tool names; a description or schema was edited in place\n")
			}
			fmt.Printf("               surface %s -> %s\n", e.Surface[:12], res.Now.Surface[:12])
			ev.SurfaceNow, ev.JCSNow, ev.ToolsAfter = res.Now.Surface, res.Now.ToolsSRI, res.Now.Canonical
			ev.Added, ev.Removed, ev.Edited = res.Added, res.Removed, res.Edited
			if serr != nil {
				r.Note, ev.Note = serr.Error(), serr.Error()
				fmt.Printf("               (%s)\n", serr)
			} else {
				ev.Snapshot, ev.ToolsBefore = rel, snap.Tools
				for _, ed := range res.Edited {
					fmt.Printf("               ~ %s: %s changed\n", ed.Tool, strings.Join(ed.Fields, ", "))
				}
			}
			if update {
				lf.Servers[i] = lock.EntryFrom(e.Name, e.Endpoint, res.Now, e.Auth, time.Now())
				if _, werr := lock.WriteSnapshot(path, lf.Servers[i], res.Now.Canonical); werr != nil {
					fmt.Printf("               snapshot not written: %v\n", werr)
				}
			}
		}
		results = append(results, r)
		evServers = append(evServers, ev)
	}

	fmt.Printf("\n%d ok, %d changed, %d unreachable, %d misconfigured\n", len(lf.Servers)-changed-unreachable-misconfigured, changed, unreachable, misconfigured)

	if jsonOut != "" {
		out := map[string]any{"lock": path, "checked_at": now, "changed": changed, "unreachable": unreachable, "misconfigured": misconfigured, "results": results}
		if err := writeJSON(jsonOut, out); err != nil {
			return err
		}
	}
	if mdOut != "" {
		if err := os.WriteFile(mdOut, []byte(driftMarkdown(path, now, results, changed, unreachable)), 0o644); err != nil {
			return err
		}
	}
	// The evidence file: the text before and after for every changed server,
	// the diff, and the newest public head as a freshness anchor. Verified
	// later with `mcpobs verify-evidence`.
	if evidenceOut != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		head, note := lock.FetchPublicHead(ctx)
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
		if err := lock.Write(path, lf); err != nil {
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

// driftMarkdown is what the GitHub Action posts as an issue. Written to read
// well in a notification: what moved, in which direction, and how to accept
// it -- not a dump of hashes.
func driftMarkdown(path, now string, results []checkResult, changed, unreachable int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## MCP server tool surface changed\n\n")
	fmt.Fprintf(&b, "`%s` pins %d server(s). Checked %s: **%d changed**, %d unreachable, %d unchanged.\n\n",
		path, len(results), now, changed, unreachable, len(results)-changed-unreachable)
	for _, r := range results {
		label := r.Entry.Label()
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
	fmt.Fprintf(&b, "---\n\nTo accept after review: `mcpobs --lock %s check --update`, then commit the lockfile and `%s/`.\n\n", path, lock.SnapshotDir(path))
	fmt.Fprintf(&b, "Every nightly observation behind the history links is in a signed, independently verifiable log: `mcpobs verify --leaves docs/data/leaves --heads heads --pubkey heads/key.pub` in a clone of https://github.com/yassinht/mcp-transparency-log.\n")
	return b.String()
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
