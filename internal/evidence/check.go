package evidence

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/yassinht/mcp-transparency-log/internal/canon"
	"github.com/yassinht/mcp-transparency-log/internal/mlog"
)

// CheckFormat is the evidence `mcpobs check --check-evidence` writes from a
// CI run. It is a different thing from a log bundle and says so in its name:
// the public log never saw a private server, so there is no inclusion proof
// here. What it holds is the exact tool text at lock time and at check time,
// the diff, and the newest public head as a freshness anchor (the file was
// produced after that head was published). Its verifier recomputes the hashes
// from the text, so the text cannot be edited after the fact without the
// surface hashes in the lockfile and the CI log disagreeing with it.
const CheckFormat = "mcp-check-evidence/v1"

type CheckEvidence struct {
	Format    string          `json:"format"`
	CheckedAt string          `json:"checked_at"`
	Lock      LockRef         `json:"lock"`
	PublicLog *PublicHead     `json:"public_log"`
	Servers   []CheckedServer `json:"servers"`
	Notes     []string        `json:"notes"`
}

type LockRef struct {
	Path      string `json:"path"`
	Generated string `json:"generated"`
}

// PublicHead is the newest signed head of the public log at check time, as
// fetched. It anchors the file in time; it says nothing about the servers.
type PublicHead struct {
	HeadFile    string `json:"head_file"`
	Head        string `json:"head"`
	FetchedFrom string `json:"fetched_from"`
}

type CheckedServer struct {
	Name          string            `json:"name,omitempty"`
	Endpoint      string            `json:"endpoint"`
	Status        string            `json:"status"` // ok | changed | unreachable | misconfigured
	LockedAt      string            `json:"locked_at"`
	Auth          string            `json:"auth,omitempty"`
	SurfaceLocked string            `json:"surface_locked"`
	SurfaceNow    string            `json:"surface_now,omitempty"`
	JCSLocked     string            `json:"jcs_v1_locked,omitempty"`
	JCSNow        string            `json:"jcs_v1_now,omitempty"`
	Snapshot      string            `json:"snapshot,omitempty"`
	ToolsBefore   []json.RawMessage `json:"tools_before,omitempty"`
	ToolsAfter    []json.RawMessage `json:"tools_after,omitempty"`
	Added         []string          `json:"added,omitempty"`
	Removed       []string          `json:"removed,omitempty"`
	Edited        []EditedTool      `json:"edited,omitempty"`
	Error         string            `json:"error,omitempty"`
	Note          string            `json:"note,omitempty"`
}

// DiffTools compares two tool lists by name: which names appeared, which
// vanished, and for the rest which members changed. The first tool of a
// duplicated name is the one compared.
func DiffTools(before, after []json.RawMessage) (added, removed []string, edited []EditedTool) {
	a, b := byName(before), byName(after)
	for name, nt := range b {
		ot, ok := a[name]
		if !ok {
			added = append(added, name)
			continue
		}
		if fields := changedFields(ot, nt); len(fields) > 0 {
			e := EditedTool{Tool: name, Fields: fields, Before: members(ot, fields), After: members(nt, fields)}
			if contains(fields, "description") {
				e.DescriptionBefore, e.DescriptionAfter = descriptionOf(ot), descriptionOf(nt)
			}
			edited = append(edited, e)
		}
	}
	for name := range a {
		if _, ok := b[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Slice(edited, func(i, j int) bool { return edited[i].Tool < edited[j].Tool })
	return added, removed, edited
}

// members picks the named top-level members of a tool, canonicalised so the
// same value never shows as a change of whitespace or key order.
func members(t json.RawMessage, fields []string) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(t, &m) != nil {
		return nil
	}
	out := map[string]json.RawMessage{}
	for _, f := range fields {
		if v, ok := m[f]; ok {
			if c, err := canon.Canonicalize(v); err == nil {
				out[f] = c
			} else {
				out[f] = v
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func byName(tools []json.RawMessage) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, t := range tools {
		var nm struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(t, &nm) == nil && nm.Name != "" {
			if _, dup := out[nm.Name]; !dup {
				out[nm.Name] = t
			}
		}
	}
	return out
}

// VerifyCheck recomputes everything in a CI evidence file that can be
// recomputed: the surface and jcs-v1 digests of both tool texts, the diff, and
// the signature on the public head. A passing report means the text in the
// file is the text those hashes were computed over, nothing more.
func VerifyCheck(c *CheckEvidence, opt Options) *Report {
	rep := &Report{}
	if c.Format != CheckFormat {
		rep.add("format", c.Format, false, "this build understands "+CheckFormat)
		return rep
	}
	rep.add("format", c.Format, true, "")

	if c.PublicLog != nil {
		trusted := opt.TrustedKey
		if trusted == nil {
			trusted = pinnedKey()
		}
		head, err := mlog.ParseHead([]byte(c.PublicLog.Head))
		switch {
		case err != nil:
			rep.add("public head", c.PublicLog.HeadFile, false, err.Error())
		case head.Verify(trusted) != nil:
			rep.add("public head", c.PublicLog.HeadFile, false, "signature does not verify under the trusted key")
		default:
			rep.add("public head", c.PublicLog.HeadFile, true, fmt.Sprintf("size %d, signed %s", head.Size, head.Time.Format("2006-01-02")))
			if opt.PublishedHeads != nil {
				pub, ok := opt.PublishedHeads[c.PublicLog.HeadFile]
				rep.add("head published", c.PublicLog.HeadFile, ok && normalize(pub) == normalize(c.PublicLog.Head), "")
			}
		}
	} else {
		rep.add("public head", "none", true, "no freshness anchor in this file")
	}

	for _, s := range c.Servers {
		ref := s.Name
		if ref == "" {
			ref = s.Endpoint
		}
		switch s.Status {
		case "ok", "changed":
		default:
			rep.add("server", ref, true, s.Status)
			continue
		}
		if s.ToolsBefore != nil {
			sf, err := canon.SurfaceOf([][]json.RawMessage{s.ToolsBefore})
			if err != nil || sf.SurfaceSHA256 != s.SurfaceLocked {
				rep.add("locked text", ref, false, "tools_before does not hash to surface_locked")
				continue
			}
			if s.JCSLocked != "" {
				if d, _, derr := canon.JCSToolsDigest(s.ToolsBefore); derr != nil || d != s.JCSLocked {
					rep.add("locked text", ref, false, "tools_before does not produce jcs_v1_locked")
					continue
				}
			}
		}
		if s.Status == "ok" {
			if s.SurfaceNow != "" && s.SurfaceNow != s.SurfaceLocked {
				rep.add("server", ref, false, "status ok but surfaces differ")
				continue
			}
			rep.add("server", ref, true, "unchanged")
			continue
		}
		if s.ToolsAfter == nil {
			rep.add("server", ref, false, "changed but tools_after is missing")
			continue
		}
		sf, err := canon.SurfaceOf([][]json.RawMessage{s.ToolsAfter})
		if err != nil || sf.SurfaceSHA256 != s.SurfaceNow {
			rep.add("current text", ref, false, "tools_after does not hash to surface_now")
			continue
		}
		if s.JCSNow != "" {
			if d, _, derr := canon.JCSToolsDigest(s.ToolsAfter); derr != nil || d != s.JCSNow {
				rep.add("current text", ref, false, "tools_after does not produce jcs_v1_now")
				continue
			}
		}
		if s.ToolsBefore != nil {
			added, removed, edited := DiffTools(s.ToolsBefore, s.ToolsAfter)
			x, _ := json.Marshal(struct {
				A, R []string
				E    []EditedTool
			}{added, removed, edited})
			y, _ := json.Marshal(struct {
				A, R []string
				E    []EditedTool
			}{s.Added, s.Removed, s.Edited})
			if string(x) != string(y) {
				rep.add("diff", ref, false, "the listed diff is not the diff of the two texts")
				continue
			}
		}
		rep.add("server", ref, true, fmt.Sprintf("changed: +%d −%d edited %d", len(s.Added), len(s.Removed), len(s.Edited)))
		rep.Verified++
	}
	return rep
}

func pinnedKey() []byte {
	raw, _ := decodeB64(OperatorPublicKey)
	return raw
}
