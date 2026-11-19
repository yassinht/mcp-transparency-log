package mlog

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/sumdb/tlog"
)

// Publishing leaf hashes is what turns "trust me" into "check it".
//
// The observation records are about 20 GB and stay on the crawler's disk. The
// leaf hashes are 32 bytes each -- roughly 800 KB for a day of 25,000
// endpoints -- small enough to keep in git forever. From them anyone can
// rebuild the tree, arrive at the root in a signed head, prove that a given
// leaf is included, and prove that each day's tree extends the previous day's
// rather than replacing it.
//
// What this still does not prove is that the leaves correspond to servers I
// actually visited: nothing stops an operator from inventing a consistent
// history. Only independent observation fixes that, which is what witnesses
// are for. Saying so plainly is part of the job.

// LeavesFileVersion is written into the manifest. Bump it if the on-disk shape
// changes, so a verifier built against an older version refuses rather than
// silently misreads.
const LeavesFileVersion = 1

type LeavesManifest struct {
	Version int           `json:"version"`
	Size    int64         `json:"size"`
	Root    string        `json:"root"`
	Runs    []LeavesRange `json:"runs"`
}

type LeavesRange struct {
	Run   string `json:"run"`
	First int64  `json:"first_leaf"`
	Count int64  `json:"leaves"`
	File  string `json:"file"`
}

// ExportLeaves writes one binary file per run plus a manifest describing the
// order they must be concatenated in. The files hold raw 32-byte hashes with no
// framing: a verifier reads them sequentially and needs no parser.
func ExportLeaves(logDir, outDir string) (*LeavesManifest, error) {
	l, err := Open(logDir)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	if l.Size() == 0 {
		return nil, fmt.Errorf("mlog: tree is empty")
	}

	man, err := ReadManifest(logDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	root, err := l.TreeHash()
	if err != nil {
		return nil, err
	}
	out := &LeavesManifest{Version: LeavesFileVersion, Size: l.Size(), Root: root.String()}

	// Several entries can share a run id when a census was resumed; each keeps
	// its own range so the concatenation order stays exactly the append order.
	seen := map[string]int{}
	for _, e := range man {
		seen[e.RunID]++
		name := e.RunID + ".bin"
		if seen[e.RunID] > 1 {
			name = fmt.Sprintf("%s.%d.bin", e.RunID, seen[e.RunID])
		}
		hashes, herr := l.LeafHashes(e.FirstLeaf, e.Leaves)
		if herr != nil {
			return nil, herr
		}
		buf := make([]byte, 0, len(hashes)*hashSize)
		for _, h := range hashes {
			buf = append(buf, h[:]...)
		}
		if werr := os.WriteFile(filepath.Join(outDir, name), buf, 0o644); werr != nil {
			return nil, werr
		}
		out.Runs = append(out.Runs, LeavesRange{
			Run: e.RunID, First: e.FirstLeaf, Count: e.Leaves, File: name,
		})
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), b, 0o644); err != nil {
		return nil, err
	}
	return out, nil
}

// VerifyFromLeaves rebuilds the tree from published leaf hashes alone and
// returns the size and root it arrives at. This is the function a stranger
// runs: it never touches the records, the stored hash file, or anything else
// the operator could have written to match a lie.
func VerifyFromLeaves(leavesDir string) (int64, string, error) {
	b, err := os.ReadFile(filepath.Join(leavesDir, "manifest.json"))
	if err != nil {
		return 0, "", err
	}
	var man LeavesManifest
	if err := json.Unmarshal(b, &man); err != nil {
		return 0, "", fmt.Errorf("leaves manifest: %w", err)
	}
	if man.Version != LeavesFileVersion {
		return 0, "", fmt.Errorf("leaves manifest version %d, this build understands %d",
			man.Version, LeavesFileVersion)
	}

	tmp, err := os.MkdirTemp("", "mlog-leaves-*")
	if err != nil {
		return 0, "", err
	}
	defer os.RemoveAll(tmp)

	l, err := Open(tmp)
	if err != nil {
		return 0, "", err
	}
	defer l.Close()

	for _, r := range man.Runs {
		raw, rerr := os.ReadFile(filepath.Join(leavesDir, r.File))
		if rerr != nil {
			return 0, "", rerr
		}
		if int64(len(raw)) != r.Count*hashSize {
			return 0, "", fmt.Errorf("%s: %d bytes, manifest claims %d leaves",
				r.File, len(raw), r.Count)
		}
		// The manifest's own ordering must be a straight append; a gap or
		// overlap would let a rewritten history look like a continuation.
		if r.First != l.Size() {
			return 0, "", fmt.Errorf("%s starts at leaf %d but the tree is at %d",
				r.File, r.First, l.Size())
		}
		hashes := make([]tlog.Hash, r.Count)
		for i := int64(0); i < r.Count; i++ {
			copy(hashes[i][:], raw[i*hashSize:(i+1)*hashSize])
		}
		if _, aerr := l.AppendHashes(hashes); aerr != nil {
			return 0, "", aerr
		}
	}

	if l.Size() == 0 {
		return 0, "", fmt.Errorf("no leaves")
	}
	root, err := l.TreeHash()
	if err != nil {
		return 0, "", err
	}
	return l.Size(), root.String(), nil
}

var _ = binary.BigEndian
