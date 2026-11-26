package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// peers-dated writes the index of every nightly copy of the peer list.
//
// The list is rewritten each night at one URL. That suits a reader who wants
// tonight's copy and nobody who wants to rerun a comparison next month. Git
// already keeps every copy, and a raw link pinned to a commit never changes,
// so the dated index costs no storage: it only says which commit carried
// which night, and the SHA-256 a fetched copy must have.
//
// It is rebuilt from `git log` on every run instead of appended to. A failed
// push followed by a rebase rewrites the ids of the nights that never left
// the server, and an appended index would keep pointing at commits nobody can
// fetch. Entries already in the file are reused by commit id, so a quiet
// night hashes one file, not the whole history.

const (
	peersListPath  = "docs/data/peers/tool-digests-latest.jsonl"
	peersIndexPath = "docs/data/peers/index.json"
	peersDatedPath = "docs/data/peers/dated.json"
	peersRawBase   = "https://raw.githubusercontent.com/yassinht/mcp-transparency-log/"
	peersDatedURL  = "https://yassinht.github.io/mcp-transparency-log/data/peers/dated.json"
)

type datedNight struct {
	Date       string `json:"date"`
	Run        string `json:"run,omitempty"`
	Rows       int    `json:"rows,omitempty"`
	WithDigest int    `json:"with_digest,omitempty"`
	SHA256     string `json:"sha256"`
	Bytes      int    `json:"bytes"`
	Commit     string `json:"commit"`
	URL        string `json:"url"`
}

type datedIndex struct {
	Kind   string       `json:"kind"`
	V      int          `json:"v"`
	Note   string       `json:"note"`
	Nights []datedNight `json:"nights"`
}

func cmdPeersDated(clone string) error {
	known := map[string]datedNight{}
	if b, err := os.ReadFile(filepath.Join(clone, peersDatedPath)); err == nil {
		var old datedIndex
		if json.Unmarshal(b, &old) == nil {
			for _, n := range old.Nights {
				known[n.Commit] = n
			}
		}
	}

	out, err := gitIn(clone, "log", "--format=%H", "--reverse", "--", peersListPath)
	if err != nil {
		return fmt.Errorf("peers-dated: %w", err)
	}

	// Oldest first, so that when two commits carry the same bytes (a human
	// re-exporting the site from a laptop, say) the night is pinned to the
	// first commit that published it.
	var nights []datedNight
	seen := map[string]bool{}
	for _, c := range strings.Fields(string(out)) {
		n, ok := known[c]
		if !ok {
			body, err := gitIn(clone, "show", c+":"+peersListPath)
			if err != nil {
				continue // the commit that deleted the file, if one ever does
			}
			sum := sha256.Sum256(body)
			n = datedNight{
				SHA256: hex.EncodeToString(sum[:]),
				Bytes:  len(body),
				Commit: c,
				URL:    peersRawBase + c + "/" + peersListPath,
			}
			if ib, err := gitIn(clone, "show", c+":"+peersIndexPath); err == nil {
				var idx struct {
					Date       string `json:"date"`
					Run        string `json:"run"`
					Rows       int    `json:"rows"`
					WithDigest int    `json:"with_digest"`
				}
				if json.Unmarshal(ib, &idx) == nil {
					n.Date, n.Run, n.Rows, n.WithDigest = idx.Date, idx.Run, idx.Rows, idx.WithDigest
				}
			}
			if n.Date == "" {
				d, err := gitIn(clone, "show", "-s", "--format=%cs", c)
				if err != nil {
					return fmt.Errorf("peers-dated: %w", err)
				}
				n.Date = strings.TrimSpace(string(d))
			}
		}
		if seen[n.SHA256] {
			continue
		}
		seen[n.SHA256] = true
		nights = append(nights, n)
	}
	// Newest first: the night a reader most often wants is the top entry.
	for i, j := 0, len(nights)-1; i < j; i, j = i+1, j-1 {
		nights[i], nights[j] = nights[j], nights[i]
	}

	idx := datedIndex{
		Kind: "mcp-transparency-log-peer-list-dated",
		V:    1,
		Note: "One entry per distinct nightly copy of data/peers/tool-digests-latest.jsonl, newest first. " +
			"url is pinned to the commit that first published that copy and never changes; " +
			"a fetched copy must hash to sha256. date, run, rows and with_digest come from the index.json in the same commit.",
		Nights: nights,
	}
	b, err := json.MarshalIndent(idx, "", " ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := filepath.Join(clone, peersDatedPath)
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		fmt.Printf("peers/dated.json %d nights, unchanged\n", len(nights))
		return nil
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("peers/dated.json %d nights\n", len(nights))
	return nil
}

func gitIn(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
