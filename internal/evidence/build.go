package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yassinht/mcp-transparency-log/internal/mlog"
	"github.com/yassinht/mcp-transparency-log/internal/store"
)

// BuildOptions says which server, which nights, and where the archive is.
// From and To are dates (YYYY-MM-DD), inclusive; empty means open-ended.
type BuildOptions struct {
	DataDir  string
	LogDir   string
	HeadsDir string
	Endpoint string
	From, To string
	// PublicKey overrides the key named in the bundle (base64). Empty means
	// heads/key.pub beside the heads, falling back to the pinned key.
	PublicKey string
	Now       time.Time
}

// Build runs on the operator's side, where the archive is. It picks the newest
// published head, finds every committed observation of the endpoint in range,
// proves each one against that head, and packs the archived bodies in.
//
// Only leaves below the head's size are included: a proof against a tree
// nobody has signed yet would be a proof against a promise. An observation
// taken after the latest head is left out and said so in the notes.
func Build(o BuildOptions) (*Bundle, error) {
	if o.Endpoint == "" {
		return nil, fmt.Errorf("evidence: an endpoint is required")
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	headFile, headText, head, err := newestHead(o.HeadsDir)
	if err != nil {
		return nil, err
	}
	pubKey := o.PublicKey
	if pubKey == "" {
		if b, rerr := os.ReadFile(filepath.Join(o.HeadsDir, "key.pub")); rerr == nil {
			pubKey = strings.TrimSpace(string(b))
		} else {
			pubKey = OperatorPublicKey
		}
	}
	if raw, derr := base64.StdEncoding.DecodeString(pubKey); derr != nil || len(raw) != 32 {
		return nil, fmt.Errorf("evidence: public key is not a base64 Ed25519 key")
	} else if verr := head.Verify(raw); verr != nil {
		return nil, fmt.Errorf("evidence: head %s does not verify under the key; refusing to build on it", headFile)
	}

	man, err := mlog.ReadManifest(o.LogDir)
	if err != nil {
		return nil, err
	}
	// Leaf position of line k of a run: walk that run's manifest entries in
	// order (a resumed census has several).
	leafIndex := func(runID string, k int64) (int64, bool) {
		var seen int64
		for _, e := range man {
			if e.RunID != runID {
				continue
			}
			if k < seen+e.Leaves {
				return e.FirstLeaf + (k - seen), true
			}
			seen += e.Leaves
		}
		return 0, false
	}
	committed := map[string]bool{}
	for _, e := range man {
		committed[e.RunID] = true
	}

	runs, err := runIDs(o.DataDir)
	if err != nil {
		return nil, err
	}
	l, err := mlog.Open(o.LogDir)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	if l.Size() < head.Size {
		return nil, fmt.Errorf("evidence: the local tree holds %d leaves but head %s names %d; is this the operator's archive?", l.Size(), headFile, head.Size)
	}

	// The exact token json.Marshal wrote for this endpoint, so the prefilter
	// over millions of lines is a byte search, not a parse.
	tok, _ := json.Marshal(o.Endpoint)
	needle := append([]byte(`"endpoint":`), tok...)

	b := &Bundle{
		Format:      Format,
		GeneratedAt: o.Now.UTC().Format(time.RFC3339),
		Log:         LogInfo{Name: LogName, Repo: LogRepo, Site: LogSite, PublicKey: pubKey, HeadFile: headFile, Head: headText},
		Subject:     Subject{Endpoint: o.Endpoint, Slug: Slug(o.Endpoint), HistoryURL: LogSite + "server.html?s=" + Slug(o.Endpoint)},
		Blobs:       map[string]string{},
	}
	var (
		recs       []Record
		nights     = map[string]bool{}
		beyond     int
		uncommit   int
		unreadable []string
	)
	for _, run := range runs {
		date := run
		if len(date) > 10 {
			date = date[:10]
		}
		if (o.From != "" && date < o.From) || (o.To != "" && date > o.To) {
			continue
		}
		if !committed[run] {
			uncommit++
			continue
		}
		lines, lerr := mlog.IndexLines(o.DataDir, run)
		if lerr != nil {
			return nil, fmt.Errorf("run %s: %w", run, lerr)
		}
		for k, line := range lines {
			if !bytes.Contains(line, needle) {
				continue
			}
			var r Record
			if json.Unmarshal(line, &r) != nil || r.Endpoint != o.Endpoint {
				continue
			}
			idx, ok := leafIndex(run, int64(k))
			if !ok {
				uncommit++
				continue
			}
			if idx >= head.Size {
				beyond++
				continue
			}
			proof, perr := l.ProveRecordAt(head.Size, idx)
			if perr != nil {
				return nil, perr
			}
			b.Observations = append(b.Observations, Observation{
				LeafIndex: idx, Record: string(line), Proof: encodeProof(proof),
				RunID: r.RunID, ObservedAt: r.ObservedAt, Outcome: r.Outcome,
				SurfaceSHA256: r.SurfaceSHA256, ToolCount: r.ToolCount, PageBlobs: r.PageBlobs,
			})
			nights[date] = true
			for _, sum := range r.PageBlobs {
				if _, have := b.Blobs[sum]; have {
					continue
				}
				raw, rerr := store.ReadBlob(o.DataDir, sum)
				if rerr != nil {
					unreadable = append(unreadable, sum)
					continue
				}
				b.Blobs[sum] = base64.StdEncoding.EncodeToString(raw)
			}
			recs = append(recs, r)
		}
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("evidence: no committed observation of %s in that range", o.Endpoint)
	}
	sort.SliceStable(b.Observations, func(i, j int) bool { return b.Observations[i].ObservedAt < b.Observations[j].ObservedAt })
	b.Subject.ServerName = recs[len(recs)-1].ServerName
	dates := make([]string, 0, len(nights))
	for d := range nights {
		dates = append(dates, d)
	}
	sort.Strings(dates)
	b.Range = Range{From: dates[0], To: dates[len(dates)-1], Nights: len(dates)}

	blobs := map[string][]byte{}
	for sum, enc := range b.Blobs {
		raw, _ := base64.StdEncoding.DecodeString(enc)
		blobs[sum] = raw
	}
	b.Versions, b.Changes = Derive(recs, blobs)

	b.Notes = []string{
		"Each observation is one line of the log exactly as the crawler wrote it, with an inclusion proof against the signed head above. Recompute the leaf hash from the line, follow the proof, and you arrive at the head's root.",
		"The archived bodies are the bytes the server returned to tools/list. The surface hash in each record is recomputed from them by the verifier, which ties this text to the tree.",
		"A verified bundle proves the operator committed to these records before signing the head, and has not altered them since. It does not by itself prove the records describe what the server really served; independent observers do that, and the log publishes digests for them to compare.",
		"Verify offline: mcpobs verify-evidence <this file>. Add --heads heads --pubkey heads/key.pub from a clone of the repository to check the head against the published ones.",
	}
	if beyond > 0 {
		b.Notes = append(b.Notes, fmt.Sprintf("%d observation(s) newer than head %s are not included; they will be provable once the next head is published.", beyond, headFile))
	}
	if uncommit > 0 {
		b.Notes = append(b.Notes, fmt.Sprintf("%d observation(s) in the range are not yet committed to the tree and are not included.", uncommit))
	}
	if len(unreadable) > 0 {
		b.Notes = append(b.Notes, fmt.Sprintf("%d archived body(ies) could not be read from the archive and are missing from this bundle; the records that name them will not pass the surface check.", len(unreadable)))
	}
	return b, nil
}

// newestHead returns the published head with the largest tree size. Ties go to
// the later file name. The text is returned verbatim: it is signed bytes.
func newestHead(dir string) (name, text string, head *mlog.Head, err error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", "", nil, fmt.Errorf("heads: %w", err)
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			return "", "", nil, rerr
		}
		h, perr := mlog.ParseHead(raw)
		if perr != nil {
			return "", "", nil, fmt.Errorf("%s: %w", e.Name(), perr)
		}
		if head == nil || h.Size > head.Size || (h.Size == head.Size && e.Name() > name) {
			name, text, head = e.Name(), string(raw), h
		}
	}
	if head == nil {
		return "", "", nil, fmt.Errorf("no signed heads in %s", dir)
	}
	return name, text, head, nil
}

func runIDs(dataDir string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(dataDir, "runs"))
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range ents {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// LoadPublishedHeads reads every head file in a directory, by name, for the
// verifier's "is this head one the operator published" check.
func LoadPublishedHeads(dir string) (map[string]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			return nil, rerr
		}
		out[e.Name()] = string(raw)
	}
	return out, nil
}
