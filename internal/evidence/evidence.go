// Package evidence turns a slice of the log into something a stranger can
// check: every observation of one server between two dates, the archived
// bytes behind each one, and an inclusion proof per observation against a
// published, signed head.
//
// The bundle is one JSON file. It is meant to be handed over -- to an auditor,
// a customer's security team, an incident review -- and verified by them,
// offline, with `mcpobs verify-evidence`. Nothing in it is taken on trust:
// the verifier recomputes every leaf hash from the record text, checks every
// proof against the head, re-hashes every archived blob, and recomputes the
// surface hash from the tool text to confirm the text really is what the tree
// committed to. The summary sections (versions, changes) are derived and the
// verifier rebuilds them too, so a bundle cannot carry a flattering summary of
// honest data.
//
// What a verified bundle does not prove, and the bundle says so in its notes:
// that the operator actually visited the server and recorded what it served.
// A consistent lie is still consistent. Independent observers are the answer
// to that, which is why the log publishes digests other observers can compare.
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/yassinht/mcp-transparency-log/internal/canon"
	"github.com/yassinht/mcp-transparency-log/internal/mlog"
	"golang.org/x/mod/sumdb/tlog"
)

// Format names the bundle shape. A verifier refuses any other value rather than
// guessing, for the same reason ParseHead is strict.
const Format = "mcp-evidence/v1"

// OperatorPublicKey is the key the MCP Transparency Log signs its heads with,
// pinned in the binary that is built from the public repository. A bundle that
// names any other key is refused unless the verifier is told explicitly to
// trust a different one. evidence_test asserts this equals heads/key.pub.
const OperatorPublicKey = "4DNVWgqiY5HKiGH3PFcKt5O+fn9EmdoTNvj4aYbwQ4E="

const (
	LogName = "MCP Transparency Log"
	LogRepo = "https://github.com/yassinht/mcp-transparency-log"
	LogSite = "https://yassinht.github.io/mcp-transparency-log/"
)

type Bundle struct {
	Format       string        `json:"format"`
	GeneratedAt  string        `json:"generated_at"`
	Log          LogInfo       `json:"log"`
	Subject      Subject       `json:"subject"`
	Range        Range         `json:"range"`
	Observations []Observation `json:"observations"`
	// Blobs holds the archived response bodies the observations point at,
	// keyed by content address (SHA-256 of the raw bytes), base64-encoded so
	// the bytes survive JSON untouched.
	Blobs    map[string]string `json:"blobs"`
	Versions []Version         `json:"versions"`
	Changes  []Change          `json:"changes"`
	Notes    []string          `json:"notes"`
}

type LogInfo struct {
	Name      string `json:"name"`
	Repo      string `json:"repo"`
	Site      string `json:"site"`
	PublicKey string `json:"public_key"` // base64 Ed25519
	HeadFile  string `json:"head_file"`  // name under heads/ in the repo
	Head      string `json:"head"`       // the signed head, verbatim
}

type Subject struct {
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"server_name,omitempty"`
	Slug       string `json:"slug"`
	HistoryURL string `json:"history_url"`
}

type Range struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Nights int    `json:"nights"`
}

// Observation is one leaf of the tree and its proof. Record is the exact line
// the crawler wrote; everything else here is pulled out of it for readers and
// is cross-checked by the verifier.
type Observation struct {
	LeafIndex     int64    `json:"leaf_index"`
	Record        string   `json:"record"`
	Proof         []string `json:"proof"` // base64 hashes, tlog order
	RunID         string   `json:"run_id"`
	ObservedAt    string   `json:"observed_at"`
	Outcome       string   `json:"outcome"`
	SurfaceSHA256 string   `json:"surface_sha256,omitempty"`
	ToolCount     int      `json:"tool_count"`
	PageBlobs     []string `json:"page_blobs,omitempty"`
}

// Version is one distinct tool surface and the nights it was served.
type Version struct {
	SurfaceSHA256 string   `json:"surface_sha256"`
	JCSv1         string   `json:"jcs_v1_tools_sha256,omitempty"`
	FirstSeen     string   `json:"first_seen"`
	LastSeen      string   `json:"last_seen"`
	Nights        int      `json:"nights"`
	ToolCount     int      `json:"tool_count"`
	Tools         []string `json:"tools"`
	Blobs         []string `json:"blobs"`
}

// Change is the step from one version to the next, with the exact text that
// moved, which is the thing an incident review actually needs.
type Change struct {
	At          string       `json:"at"`
	FromSurface string       `json:"from_surface"`
	ToSurface   string       `json:"to_surface"`
	Added       []string     `json:"added,omitempty"`
	Removed     []string     `json:"removed,omitempty"`
	Edited      []EditedTool `json:"edited,omitempty"`
}

type EditedTool struct {
	Tool              string   `json:"tool"`
	Fields            []string `json:"fields"`
	DescriptionBefore string   `json:"description_before,omitempty"`
	DescriptionAfter  string   `json:"description_after,omitempty"`
	// Before and After carry the old and new value of every changed member,
	// so a schema edit is shown and not just named.
	Before map[string]json.RawMessage `json:"before,omitempty"`
	After  map[string]json.RawMessage `json:"after,omitempty"`
}

// Record is the subset of a stored observation line the evidence code needs.
// It is decoded here rather than imported so the verifier depends on nothing
// that could change the meaning of a stored line.
type Record struct {
	RunID         string   `json:"run_id"`
	ObservedAt    string   `json:"observed_at"`
	ServerName    string   `json:"server_name"`
	Endpoint      string   `json:"endpoint"`
	Outcome       string   `json:"outcome"`
	ToolCount     int      `json:"tool_count"`
	ToolNames     []string `json:"tool_names"`
	SurfaceSHA256 string   `json:"surface_sha256"`
	PageBlobs     []string `json:"page_blobs"`
}

// Slug is the same sixteen hex characters the site uses to name a server's
// files: SHA-256 over the endpoint.
func Slug(endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:8])
}

// ---------------------------------------------------------------- verify

// Check is one verification step and its outcome. The verifier reports every
// step, passed or failed, so a reader sees what was actually examined.
type Check struct {
	Name   string
	Ref    string
	OK     bool
	Detail string
}

type Report struct {
	Checks []Check
	Failed int
	// Verified is the number of observations whose proof, record and tool
	// text all checked out.
	Verified int
}

func (r *Report) add(name, ref string, ok bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Ref: ref, OK: ok, Detail: detail})
	if !ok {
		r.Failed++
	}
}

func (r *Report) OK() bool { return r.Failed == 0 }

// Options for Verify. TrustedKey is the key the verifier believes in; when nil
// the pinned OperatorPublicKey is used. PublishedHeads, if given, maps a head
// file name to its text as published, so the bundle's head can be shown to be
// one the operator actually released.
type Options struct {
	TrustedKey     ed25519.PublicKey
	PublishedHeads map[string]string
}

// Verify checks a bundle offline. It never returns early on a failure it can
// get past: every check runs so the report names each failing item, which is
// more useful to a reader than the first error.
func Verify(b *Bundle, opt Options) *Report {
	rep := &Report{}
	if b.Format != Format {
		rep.add("format", b.Format, false, "this build understands "+Format)
		return rep
	}
	rep.add("format", b.Format, true, "")

	// 1. The key. The bundle carries one so a reader can see which key is
	// claimed, but the verifier trusts only what it was built with or told.
	trusted := opt.TrustedKey
	if trusted == nil {
		raw, _ := base64.StdEncoding.DecodeString(OperatorPublicKey)
		trusted = ed25519.PublicKey(raw)
	}
	if b.Log.PublicKey != base64.StdEncoding.EncodeToString(trusted) {
		rep.add("key", "bundle names a different key", false, "trusted "+base64.StdEncoding.EncodeToString(trusted)+", bundle "+b.Log.PublicKey)
	} else {
		rep.add("key", "matches the trusted key", true, "")
	}

	// 2. The head: parses, verifies under the key, and if published heads are
	// at hand, is byte-for-byte one of them.
	head, err := mlog.ParseHead([]byte(b.Log.Head))
	if err != nil {
		rep.add("head", b.Log.HeadFile, false, err.Error())
		return rep
	}
	if err := head.Verify(trusted); err != nil {
		rep.add("head signature", b.Log.HeadFile, false, err.Error())
	} else {
		rep.add("head signature", b.Log.HeadFile, true, fmt.Sprintf("size %d", head.Size))
	}
	if opt.PublishedHeads != nil {
		pub, ok := opt.PublishedHeads[b.Log.HeadFile]
		switch {
		case !ok:
			rep.add("head published", b.Log.HeadFile, false, "no head of that name among the published heads")
		case normalize(pub) != normalize(b.Log.Head):
			rep.add("head published", b.Log.HeadFile, false, "the published head of that name differs")
		default:
			rep.add("head published", b.Log.HeadFile, true, "")
		}
	}

	// 3. The archived bytes: each must hash to its own address.
	blobs := map[string][]byte{}
	for sum, enc := range b.Blobs {
		raw, derr := base64.StdEncoding.DecodeString(enc)
		if derr != nil {
			rep.add("blob", sum, false, "not base64")
			continue
		}
		if got := canon.SHA256Hex(raw); got != sum {
			rep.add("blob hash", short(sum), false, "bytes hash to "+short(got))
			continue
		}
		blobs[sum] = raw
	}
	rep.add("blobs", fmt.Sprintf("%d archived bodies", len(blobs)), len(blobs) == len(b.Blobs), "")

	// 4. Every observation: proof, record, cross-checked fields, tool text.
	var recs []Record
	for _, o := range b.Observations {
		ref := fmt.Sprintf("leaf %d (%s)", o.LeafIndex, o.RunID)
		proof, perr := decodeProof(o.Proof)
		if perr != nil {
			rep.add("inclusion", ref, false, perr.Error())
			continue
		}
		if err := tlog.CheckRecord(proof, head.Size, head.Root, o.LeafIndex, tlog.RecordHash([]byte(o.Record))); err != nil {
			rep.add("inclusion", ref, false, "proof does not reach the signed root")
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(o.Record), &r); err != nil {
			rep.add("record", ref, false, "record is not JSON")
			continue
		}
		switch {
		case r.Endpoint != b.Subject.Endpoint:
			rep.add("record", ref, false, "record is about "+r.Endpoint)
			continue
		case r.RunID != o.RunID || r.ObservedAt != o.ObservedAt || r.Outcome != o.Outcome ||
			r.SurfaceSHA256 != o.SurfaceSHA256 || r.ToolCount != o.ToolCount || !equal(r.PageBlobs, o.PageBlobs):
			rep.add("record", ref, false, "summary fields do not match the record text")
			continue
		}
		// The archived bytes must be the bytes the record hashed. Recomputing
		// the surface from them is what ties the tool text in this file to the
		// signed tree; without it the blobs would be decoration.
		if r.Outcome == "ok" && len(r.PageBlobs) > 0 {
			bodies, ok := bodiesOf(r.PageBlobs, blobs)
			if !ok {
				rep.add("surface", ref, false, "an archived body this record names is not in the bundle")
				continue
			}
			s, serr := surfaceOfBodies(bodies)
			if serr != nil || s.SurfaceSHA256 != r.SurfaceSHA256 {
				rep.add("surface", ref, false, "tool text does not hash to the recorded surface")
				continue
			}
		}
		rep.add("inclusion", ref, true, o.ObservedAt)
		rep.Verified++
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		rep.add("observations", "none verified", false, "")
		return rep
	}
	if len(recs) != len(b.Observations) {
		rep.add("observations", fmt.Sprintf("%d of %d verified", len(recs), len(b.Observations)), false, "")
	}

	// 5. The derived sections must be what the verified observations imply.
	wantV, wantC := Derive(recs, blobs)
	if !sameVersions(wantV, b.Versions) {
		rep.add("versions", fmt.Sprintf("%d listed", len(b.Versions)), false, fmt.Sprintf("observations imply %d distinct surfaces", len(wantV)))
	} else {
		rep.add("versions", fmt.Sprintf("%d distinct surfaces", len(wantV)), true, "")
	}
	if !sameChanges(wantC, b.Changes) {
		rep.add("changes", fmt.Sprintf("%d listed", len(b.Changes)), false, fmt.Sprintf("observations imply %d changes", len(wantC)))
	} else {
		rep.add("changes", fmt.Sprintf("%d changes", len(wantC)), true, "")
	}
	return rep
}

func decodeProof(p []string) (tlog.RecordProof, error) {
	out := make(tlog.RecordProof, len(p))
	for i, s := range p {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(raw) != tlog.HashSize {
			return nil, errors.New("proof is not a list of hashes")
		}
		copy(out[i][:], raw)
	}
	return out, nil
}

func encodeProof(p tlog.RecordProof) []string {
	out := make([]string, len(p))
	for i, h := range p {
		out[i] = base64.StdEncoding.EncodeToString(h[:])
	}
	return out
}

func normalize(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n") }

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
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

// ---------------------------------------------------------------- tool text

// toolsInBody pulls the tools arrays out of an archived response body, one
// page per JSON-RPC result, in order. The crawler stored the body as received
// (plain JSON or SSE frames) and hashed the tools it parsed from it; this is
// the same parse, so the surface recomputed here must match the record's.
func toolsInBody(body []byte) [][]json.RawMessage {
	var pages [][]json.RawMessage
	for _, msg := range jsonMessages(body) {
		var r struct {
			Result struct {
				Tools []json.RawMessage `json:"tools"`
			} `json:"result"`
		}
		if json.Unmarshal(msg, &r) != nil || r.Result.Tools == nil {
			continue
		}
		pages = append(pages, r.Result.Tools)
	}
	return pages
}

func jsonMessages(body []byte) [][]byte {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") {
		return [][]byte{[]byte(trimmed)}
	}
	var out [][]byte
	var data []string
	flush := func() {
		if len(data) == 0 {
			return
		}
		joined := strings.Join(data, "\n")
		data = nil
		if strings.HasPrefix(strings.TrimSpace(joined), "{") {
			out = append(out, []byte(joined))
		}
	}
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line[5:], " "), " "))
		}
	}
	flush()
	return out
}

func toolsInBodies(bodies [][]byte) [][]json.RawMessage {
	var pages [][]json.RawMessage
	for _, b := range bodies {
		pages = append(pages, toolsInBody(b)...)
	}
	return pages
}

func surfaceOfBodies(bodies [][]byte) (*canon.Surface, error) {
	return canon.SurfaceOf(toolsInBodies(bodies))
}

func bodiesOf(sums []string, blobs map[string][]byte) ([][]byte, bool) {
	var out [][]byte
	for _, s := range sums {
		b, ok := blobs[s]
		if !ok {
			return nil, false
		}
		out = append(out, b)
	}
	return out, len(out) > 0
}

// ---------------------------------------------------------------- derive

// Derive computes the versions and changes implied by a set of records and
// their archived bodies. Builder and verifier both call it, which is what
// makes the summary checkable rather than asserted.
func Derive(recs []Record, blobs map[string][]byte) ([]Version, []Change) {
	sorted := append([]Record(nil), recs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ObservedAt < sorted[j].ObservedAt })
	versions := []Version{}
	changes := []Change{}
	byHash := map[string]int{}
	prev := -1
	for _, r := range sorted {
		if r.Outcome != "ok" || r.SurfaceSHA256 == "" {
			continue
		}
		night := r.ObservedAt
		if len(night) > 10 {
			night = night[:10]
		}
		i, seen := byHash[r.SurfaceSHA256]
		if !seen {
			v := Version{SurfaceSHA256: r.SurfaceSHA256, FirstSeen: night, LastSeen: night, Nights: 1, ToolCount: r.ToolCount, Tools: r.ToolNames, Blobs: r.PageBlobs}
			if bodies, ok := bodiesOf(r.PageBlobs, blobs); ok {
				var all []json.RawMessage
				for _, p := range toolsInBodies(bodies) {
					all = append(all, p...)
				}
				if d, _, err := canon.JCSToolsDigest(all); err == nil {
					v.JCSv1 = d
				}
			}
			if v.Tools == nil {
				v.Tools = []string{}
			}
			if v.Blobs == nil {
				v.Blobs = []string{}
			}
			versions = append(versions, v)
			i = len(versions) - 1
			byHash[r.SurfaceSHA256] = i
		} else {
			versions[i].LastSeen = night
			versions[i].Nights++
		}
		if prev >= 0 && prev != i {
			changes = append(changes, diffVersions(versions[prev], versions[i], r.ObservedAt, blobs))
		}
		prev = i
	}
	return versions, changes
}

func diffVersions(from, to Version, at string, blobs map[string][]byte) Change {
	c := Change{At: at, FromSurface: from.SurfaceSHA256, ToSurface: to.SurfaceSHA256}
	fb, okF := bodiesOf(from.Blobs, blobs)
	tb, okT := bodiesOf(to.Blobs, blobs)
	if !okF || !okT {
		// Without both bodies only the names can be compared.
		c.Added = missing(from.Tools, to.Tools)
		c.Removed = missing(to.Tools, from.Tools)
		return c
	}
	c.Added, c.Removed, c.Edited = DiffTools(flatten(toolsInBodies(fb)), flatten(toolsInBodies(tb)))
	return c
}

func flatten(pages [][]json.RawMessage) []json.RawMessage {
	var all []json.RawMessage
	for _, p := range pages {
		all = append(all, p...)
	}
	return all
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// changedFields names the top-level members of a tool whose canonical bytes
// differ. Comparing member by member, rather than the whole tool, is what lets
// the report say "the description changed" instead of "something changed".
func changedFields(a, b json.RawMessage) []string {
	var ma, mb map[string]json.RawMessage
	if json.Unmarshal(a, &ma) != nil || json.Unmarshal(b, &mb) != nil {
		return []string{"(unparseable)"}
	}
	keys := map[string]bool{}
	for k := range ma {
		keys[k] = true
	}
	for k := range mb {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		va, inA := ma[k]
		vb, inB := mb[k]
		if inA != inB {
			out = append(out, k)
			continue
		}
		ca, _ := canon.Canonicalize(va)
		cb, _ := canon.Canonicalize(vb)
		if !bytes.Equal(ca, cb) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func descriptionOf(t json.RawMessage) string {
	var d struct {
		Description string `json:"description"`
	}
	_ = json.Unmarshal(t, &d)
	return d.Description
}

func missing(have, want []string) []string {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	var out []string
	for _, w := range want {
		if !set[w] {
			out = append(out, w)
		}
	}
	sort.Strings(out)
	return out
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func sameVersions(a, b []Version) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].SurfaceSHA256 != b[i].SurfaceSHA256 || a[i].FirstSeen != b[i].FirstSeen ||
			a[i].LastSeen != b[i].LastSeen || a[i].Nights != b[i].Nights || a[i].ToolCount != b[i].ToolCount ||
			a[i].JCSv1 != b[i].JCSv1 || !equal(a[i].Tools, b[i].Tools) || !equal(a[i].Blobs, b[i].Blobs) {
			return false
		}
	}
	return true
}

func sameChanges(a, b []Change) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, _ := json.Marshal(a[i])
		y, _ := json.Marshal(b[i])
		if !bytes.Equal(x, y) {
			return false
		}
	}
	return true
}
