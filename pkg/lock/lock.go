// Package lock pins the tool surface of MCP servers and checks them live.
//
// mcp.lock is to MCP servers what package-lock.json is to packages. Check
// probes each server, recomputes the surface hash, and reports when a server
// is no longer serving what was reviewed. Run in CI, that turns a silently
// rewritten tool description -- the rug-pull shape the log exists to catch --
// into a failed build with a diff.
//
// The check is live rather than read from the log on purpose. Dependabot does
// not consult a mirror of npm to tell you a package changed; it looks. The
// log's role here is evidence and history.
//
// The lockfile format is deliberately boring JSON: read in code review far
// more often than by machines, and it must diff cleanly. The tool text itself
// lives beside it in <lock>.d/ (snapshot.go), so the diff of a change is the
// diff of the text.
package lock

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/yassinht/mcp-transparency-log/pkg/canon"
	"github.com/yassinht/mcp-transparency-log/pkg/evidence"
	"github.com/yassinht/mcp-transparency-log/pkg/probe"
)

const Version = 1

// UserAgent is what the lock and check probes announce.
const UserAgent = "mcpobs-lock/0.1 (+https://github.com/yassinht/mcp-transparency-log)"

// LogRepo is recorded in every lockfile so a reader knows which record the
// hashes can be compared with.
const LogRepo = "https://github.com/yassinht/mcp-transparency-log"

type File struct {
	Version   int     `json:"version"`
	Generated string  `json:"generated"`
	Log       string  `json:"log"`
	Servers   []Entry `json:"servers"`
}

type Entry struct {
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

// Label is the entry's name, or its endpoint when it has none.
func (e Entry) Label() string {
	if e.Name != "" {
		return e.Name
	}
	return e.Endpoint
}

// New is an empty lockfile.
func New() *File { return &File{Version: Version, Log: LogRepo, Servers: []Entry{}} }

// Probed is a server's current tool surface reduced to the same canonical
// hash the crawler records, so a lock written today matches what the log
// observed tonight.
type Probed struct {
	Surface   string
	ToolsSRI  string
	Tools     []string
	Transport string
	// Canonical is the sorted, canonicalised tool list the hash was computed
	// over: what the snapshot stores and the evidence file shows.
	Canonical []json.RawMessage
}

// Probe fetches a server's tool surface with the given extra headers. On
// failure the Probed carries only the transport, and the error names the
// outcome the way the crawler would record it.
func Probe(ctx context.Context, endpoint string, hdr http.Header) (*Probed, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	cfg := probe.DefaultConfig(UserAgent)
	cfg.Headers = hdr
	p := probe.New(cfg)
	res := p.Probe(ctx, endpoint, "")
	if res.Outcome != probe.OutcomeOK {
		reason := res.FailReason
		if reason == "" {
			reason = string(res.Outcome)
		}
		return &Probed{Transport: res.Transport}, fmt.Errorf("%s: %s", res.Outcome, reason)
	}
	s, err := canon.SurfaceOf(res.ToolPages)
	if err != nil {
		return &Probed{Transport: res.Transport}, fmt.Errorf("canonicalize: %w", err)
	}
	out := &Probed{Surface: s.SurfaceSHA256, Tools: s.ToolNames, Transport: res.Transport, Canonical: s.Tools}
	var all []json.RawMessage
	for _, page := range res.ToolPages {
		all = append(all, page...)
	}
	if d, _, derr := canon.JCSToolsDigest(all); derr == nil {
		out.ToolsSRI = d
	}
	return out, nil
}

// EntryFrom builds a lock entry from a probe result.
func EntryFrom(name, endpoint string, pr *Probed, auth string, now time.Time) Entry {
	return Entry{Name: name, Endpoint: endpoint, Surface: pr.Surface, ToolsSRI: pr.ToolsSRI, Tools: pr.Tools,
		LockedAt: now.UTC().Format(time.RFC3339), Transport: pr.Transport, Auth: auth}
}

func Read(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lf File
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if lf.Version != Version {
		return nil, fmt.Errorf("%s: version %d, this build understands %d", path, lf.Version, Version)
	}
	return &lf, nil
}

func Write(path string, lf *File) error {
	// A lockfile is read in code review; "servers": null is not what a reader
	// of an empty one should see.
	if lf.Servers == nil {
		lf.Servers = []Entry{}
	}
	sort.Slice(lf.Servers, func(i, j int) bool { return lf.Servers[i].Endpoint < lf.Servers[j].Endpoint })
	b, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Status of one checked entry.
type Status string

const (
	StatusOK            Status = "ok"
	StatusChanged       Status = "changed"
	StatusUnreachable   Status = "unreachable"
	StatusMisconfigured Status = "misconfigured"
)

// Result is one entry's check: what the server serves now against what was
// locked, and when the locked text is on hand, exactly what moved.
type Result struct {
	Entry     Entry
	Status    Status
	Now       *Probed // nil when unreachable or misconfigured
	Added     []string
	Removed   []string
	Edited    []evidence.EditedTool
	Before    []json.RawMessage // the locked text, when a snapshot exists
	Snapshot  string            // path of that snapshot
	Error     string
	Note      string
	CheckedAt time.Time
}

// Credentials resolves the headers for an entry and names where they came
// from, without ever exposing the value in an error. The CLI reads the
// environment (EnvCredentials); a hosted service reads its vault.
type Credentials func(e Entry) (hdr http.Header, ref string, err error)

// Check probes one entry and compares it with its lock. before is the locked
// text when the caller has it (from a snapshot or a store); nil means only
// names can be compared.
func Check(ctx context.Context, e Entry, creds Credentials, before []json.RawMessage) Result {
	r := Result{Entry: e, CheckedAt: time.Now().UTC(), Before: before}
	// A server locked with a credential must be checked with one. Probing it
	// bare would report "unreachable" and hide a missing secret behind a
	// network-looking failure.
	hdr, ref, herr := creds(e)
	if herr != nil || (e.Auth != "" && len(hdr) == 0) {
		r.Status = StatusMisconfigured
		r.Error = "credential " + ref + " is not set in this environment"
		if herr != nil {
			r.Error = herr.Error()
		}
		return r
	}
	pr, perr := Probe(ctx, e.Endpoint, hdr)
	if perr != nil {
		r.Status, r.Error = StatusUnreachable, perr.Error()
		return r
	}
	r.Now = pr
	if pr.Surface == e.Surface {
		r.Status = StatusOK
		return r
	}
	r.Status = StatusChanged
	if before != nil {
		r.Added, r.Removed, r.Edited = evidence.DiffTools(before, pr.Canonical)
	} else {
		r.Added = Missing(e.Tools, pr.Tools)
		r.Removed = Missing(pr.Tools, e.Tools)
	}
	return r
}

// InPlace says whether a change kept every tool name: a description or schema
// was edited underneath the same names, which is the change a client never sees.
func (r Result) InPlace() bool {
	return r.Status == StatusChanged && len(r.Added) == 0 && len(r.Removed) == 0
}

// Missing returns the entries of want that are absent from have.
func Missing(have, want []string) []string {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	var out []string
	for _, w := range want {
		if !set[w] {
			out = append(out, w)
		}
	}
	return out
}
