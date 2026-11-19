// Package pack is the evidence pack a hosted service hands a customer: every
// check of one server over a period, every distinct surface with its full
// text, every decision taken and every alert sent, signed by the service.
//
// It is the private-server counterpart of the public log's bundle. There are
// no inclusion proofs, because a private server is not in the public tree;
// what the pack offers instead is recomputability. The verifier re-derives
// every surface hash from the text, every diff from the two texts, every
// severity grade from the same rules, and checks the signature. A pack can
// therefore not say "the description changed" without carrying both
// descriptions, nor grade a change "info" when the rules say "high".
//
// The verifier is here, in the public repository, for the same reason the
// bundle's is: evidence a customer cannot check with code they can read is
// not evidence.
package pack

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/yassinht/mcp-transparency-log/pkg/canon"
	"github.com/yassinht/mcp-transparency-log/pkg/evidence"
	"github.com/yassinht/mcp-transparency-log/pkg/mlog"
	"github.com/yassinht/mcp-transparency-log/pkg/severity"
)

const Format = "surfacelog-evidence/v1"

type Pack struct {
	Format      string               `json:"format"`
	GeneratedAt string               `json:"generated_at"`
	GeneratedBy string               `json:"generated_by,omitempty"`
	Service     string               `json:"service"`
	Workspace   string               `json:"workspace"`
	Server      Server               `json:"server"`
	Range       Range                `json:"range"`
	Versions    []Version            `json:"versions"`
	Checks      []Check              `json:"checks"`
	Decisions   []Decision           `json:"decisions"`
	Alerts      []Alert              `json:"alerts"`
	PublicLog   *evidence.PublicHead `json:"public_log"`
	Notes       []string             `json:"notes"`
	Signature   *Signature           `json:"signature,omitempty"`
}

type Server struct {
	Name       string `json:"name"`
	Endpoint   string `json:"endpoint"`
	Host       string `json:"host"`
	Slug       string `json:"slug"`
	Schedule   string `json:"schedule"`
	HistoryURL string `json:"public_history_url"`
	AddedAt    string `json:"added_at"`
}

type Range struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Checks int    `json:"checks"`
}

type Version struct {
	ID        int64             `json:"id"`
	Surface   string            `json:"surface_sha256"`
	JCS       string            `json:"jcs_v1_tools_sha256,omitempty"`
	ToolCount int               `json:"tool_count"`
	Tools     []string          `json:"tools"`
	Text      []json.RawMessage `json:"text"`
	FirstSeen string            `json:"first_seen"`
	LastSeen  string            `json:"last_seen"`
	TimesSeen int               `json:"times_seen"`
}

type Check struct {
	At            string                `json:"at"`
	Trigger       string                `json:"trigger"`
	Status        string                `json:"status"`
	VersionID     int64                 `json:"version_id,omitempty"`
	PrevVersionID int64                 `json:"prev_version_id,omitempty"`
	Severity      string                `json:"severity,omitempty"`
	Reasons       []severity.Reason     `json:"reasons,omitempty"`
	Added         []string              `json:"added,omitempty"`
	Removed       []string              `json:"removed,omitempty"`
	Edited        []evidence.EditedTool `json:"edited,omitempty"`
	Error         string                `json:"error,omitempty"`
}

type Decision struct {
	ChangeID      int64  `json:"change_id"`
	DetectedAt    string `json:"detected_at"`
	Severity      string `json:"severity"`
	State         string `json:"state"`
	FromVersionID int64  `json:"from_version_id,omitempty"`
	ToVersionID   int64  `json:"to_version_id"`
	DecidedBy     string `json:"decided_by,omitempty"`
	DecidedAt     string `json:"decided_at,omitempty"`
	Note          string `json:"note,omitempty"`
}

type Alert struct {
	At      string `json:"at"`
	Kind    string `json:"kind"`
	Event   string `json:"event"`
	Status  string `json:"status"`
	Subject string `json:"subject,omitempty"`
}

type Signature struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	SignedAt  string `json:"signed_at"`
	Value     string `json:"value"`
}

// SigningBytes is the canonical form of the pack without its signature: the
// bytes that are signed and the bytes a verifier re-derives.
func (p *Pack) SigningBytes() ([]byte, error) {
	cp := *p
	cp.Signature = nil
	raw, err := json.Marshal(&cp)
	if err != nil {
		return nil, err
	}
	return canon.Canonicalize(raw)
}

// Sign attaches an Ed25519 signature over SigningBytes.
func Sign(p *Pack, priv ed25519.PrivateKey, now time.Time) error {
	p.Signature = nil
	b, err := p.SigningBytes()
	if err != nil {
		return err
	}
	p.Signature = &Signature{Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		SignedAt: now.UTC().Format(time.RFC3339), Value: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))}
	return nil
}

// Options for Verify. TrustedKey pins the service key; when nil the key named
// in the pack is used and the report says so, so a reader compares it with
// the key the service publishes. OperatorKey pins the public log's key for
// the freshness anchor; nil means the key built into evidence.
type Options struct {
	TrustedKey  ed25519.PublicKey
	OperatorKey ed25519.PublicKey
}

// Verify recomputes everything in a pack that can be recomputed.
func Verify(p *Pack, opt Options) *evidence.Report {
	rep := &evidence.Report{}
	add := func(name, ref string, ok bool, detail string) {
		rep.Checks = append(rep.Checks, evidence.Check{Name: name, Ref: ref, OK: ok, Detail: detail})
		if !ok {
			rep.Failed++
		}
	}
	if p.Format != Format {
		add("format", p.Format, false, "this build understands "+Format)
		return rep
	}
	add("format", p.Format, true, "")

	// 1. Signature.
	if p.Signature == nil {
		add("signature", "none", false, "the pack is not signed")
	} else {
		key := opt.TrustedKey
		pinned := key != nil
		if key == nil {
			raw, err := base64.StdEncoding.DecodeString(p.Signature.PublicKey)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				add("signature", "key", false, "the pack names a malformed key")
			} else {
				key = ed25519.PublicKey(raw)
			}
		} else if base64.StdEncoding.EncodeToString(key) != p.Signature.PublicKey {
			add("signature", "key", false, "the pack names a different key than the one trusted")
		}
		if key != nil {
			b, err := p.SigningBytes()
			sig, derr := base64.StdEncoding.DecodeString(p.Signature.Value)
			switch {
			case err != nil || derr != nil || p.Signature.Alg != "ed25519":
				add("signature", p.Signature.Alg, false, "unreadable signature")
			case !ed25519.Verify(key, b, sig):
				add("signature", "ed25519", false, "does not verify: the pack was altered after signing")
			case pinned:
				add("signature", "ed25519", true, "verified under the trusted key")
			default:
				add("signature", "ed25519", true, "verified under the key named in the pack: "+p.Signature.PublicKey+" (compare it with the key the service publishes)")
			}
		}
	}

	// 2. Every version's text hashes to its surface.
	byID := map[int64]Version{}
	for _, v := range p.Versions {
		byID[v.ID] = v
		s, err := canon.SurfaceOf([][]json.RawMessage{v.Text})
		if err != nil || s.SurfaceSHA256 != v.Surface {
			add("version text", short(v.Surface), false, "text does not hash to the surface")
			continue
		}
		if len(s.ToolNames) != v.ToolCount || !equal(s.ToolNames, v.Tools) {
			add("version text", short(v.Surface), false, "tool names or count do not match the text")
			continue
		}
		if v.JCS != "" {
			if d, _, derr := canon.JCSToolsDigest(v.Text); derr != nil || d != v.JCS {
				add("version text", short(v.Surface), false, "text does not produce the jcs-v1 digest")
				continue
			}
		}
		add("version text", short(v.Surface), true, fmt.Sprintf("%d tools", v.ToolCount))
	}

	// 3. Every changed check's diff and grade follow from the two texts.
	for _, c := range p.Checks {
		ref := c.At
		if c.Status != "changed" {
			if c.VersionID != 0 {
				if _, ok := byID[c.VersionID]; !ok {
					add("check", ref, false, "refers to a version the pack does not carry")
					continue
				}
			}
			rep.Verified++
			continue
		}
		cur, okC := byID[c.VersionID]
		prev, okP := byID[c.PrevVersionID]
		if !okC || !okP {
			add("check", ref, false, "a changed check must carry both versions")
			continue
		}
		added, removed, edited := evidence.DiffTools(prev.Text, cur.Text)
		x, _ := json.Marshal(struct {
			A, R []string
			E    []evidence.EditedTool
		}{added, removed, edited})
		y, _ := json.Marshal(struct {
			A, R []string
			E    []evidence.EditedTool
		}{c.Added, c.Removed, c.Edited})
		if string(x) != string(y) {
			add("check diff", ref, false, "the listed diff is not the diff of the two texts")
			continue
		}
		v := severity.Classify(prev.Text, cur.Text, p.Server.Host)
		if string(v.Level) != c.Severity || !sameCodes(v.Reasons, c.Reasons) {
			add("check severity", ref, false, fmt.Sprintf("rules grade this change %s, the pack says %s", v.Level, c.Severity))
			continue
		}
		add("check", ref, true, "changed, diff and grade recomputed")
		rep.Verified++
	}

	// 4. Decisions point at versions in the pack.
	for _, d := range p.Decisions {
		if _, ok := byID[d.ToVersionID]; !ok {
			add("decision", fmt.Sprintf("change %d", d.ChangeID), false, "refers to a version the pack does not carry")
			continue
		}
		if d.State != "pending" && d.State != "approved" && d.State != "rejected" {
			add("decision", fmt.Sprintf("change %d", d.ChangeID), false, "unknown state "+d.State)
			continue
		}
	}
	add("decisions", fmt.Sprintf("%d", len(p.Decisions)), true, "")

	// 5. The public head, when present, must be a genuine signed head.
	if p.PublicLog != nil {
		opKey := opt.OperatorKey
		if opKey == nil {
			raw, _ := base64.StdEncoding.DecodeString(evidence.OperatorPublicKey)
			opKey = ed25519.PublicKey(raw)
		}
		h, err := mlog.ParseHead([]byte(p.PublicLog.Head))
		switch {
		case err != nil:
			add("public head", p.PublicLog.HeadFile, false, err.Error())
		case h.Verify(opKey) != nil:
			add("public head", p.PublicLog.HeadFile, false, "signature does not verify under the public log's key")
		default:
			add("public head", p.PublicLog.HeadFile, true, fmt.Sprintf("size %d, a lower bound on when this pack was made", h.Size))
		}
	}
	return rep
}

func sameCodes(a, b []severity.Reason) bool {
	ka, kb := codes(a), codes(b)
	if len(ka) != len(kb) {
		return false
	}
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

func codes(rs []severity.Reason) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Tool+"/"+r.Code)
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

var _ = errors.New
