package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"}, args...)
	out, err := exec.Command("git", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func publishNight(t *testing.T, dir, date, list string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(peersListPath))
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(list), 0o644)
	idx, _ := json.Marshal(map[string]any{"date": date, "run": date + "T030000Z", "rows": strings.Count(list, "\n")})
	os.WriteFile(filepath.Join(dir, filepath.FromSlash(peersIndexPath)), idx, 0o644)
	gitT(t, dir, "add", "-A")
	gitT(t, dir, "commit", "-q", "-m", "night "+date)
	return gitT(t, dir, "rev-parse", "HEAD")
}

func readDated(t *testing.T, dir string) datedIndex {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(peersDatedPath)))
	if err != nil {
		t.Fatal(err)
	}
	var idx datedIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestPeersDated(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitT(t, dir, "init", "-q")

	c1 := publishNight(t, dir, "2026-11-17", "{\"a\":1}\n")
	c2 := publishNight(t, dir, "2026-11-18", "{\"a\":1}\n{\"b\":2}\n")
	// A commit that touches something else must not appear.
	os.WriteFile(filepath.Join(dir, "README"), []byte("x"), 0o644)
	gitT(t, dir, "add", "-A")
	gitT(t, dir, "commit", "-q", "-m", "docs")

	if err := cmdPeersDated(dir); err != nil {
		t.Fatal(err)
	}
	idx := readDated(t, dir)
	if len(idx.Nights) != 2 {
		t.Fatalf("want 2 nights, got %d: %+v", len(idx.Nights), idx.Nights)
	}
	top := idx.Nights[0]
	if top.Date != "2026-11-18" || top.Commit != c2 || top.Rows != 2 {
		t.Fatalf("newest night wrong: %+v", top)
	}
	sum := sha256.Sum256([]byte("{\"a\":1}\n{\"b\":2}\n"))
	if top.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 = %s", top.SHA256)
	}
	if top.URL != peersRawBase+c2+"/"+peersListPath {
		t.Fatalf("url = %s", top.URL)
	}
	if idx.Nights[1].Commit != c1 {
		t.Fatalf("oldest night pinned to %s, want %s", idx.Nights[1].Commit, c1)
	}

	// Same bytes committed again later stay pinned to the first commit.
	os.WriteFile(filepath.Join(dir, filepath.FromSlash(peersListPath)), []byte("{\"a\":1}\n"), 0o644)
	gitT(t, dir, "add", "-A")
	gitT(t, dir, "commit", "-q", "-m", "revert to night one")
	c4 := publishNight(t, dir, "2026-11-19", "{\"c\":3}\n")
	if err := cmdPeersDated(dir); err != nil {
		t.Fatal(err)
	}
	idx = readDated(t, dir)
	if len(idx.Nights) != 3 || idx.Nights[0].Commit != c4 || idx.Nights[2].Commit != c1 {
		t.Fatalf("after re-commit: %+v", idx.Nights)
	}

	// A rewritten night (the rebase after a failed push) must drop the old
	// commit id rather than keep a link nobody can fetch.
	gitT(t, dir, "commit", "-q", "--amend", "-m", "night 2026-11-19 rebased")
	c4b := gitT(t, dir, "rev-parse", "HEAD")
	if err := cmdPeersDated(dir); err != nil {
		t.Fatal(err)
	}
	idx = readDated(t, dir)
	if idx.Nights[0].Commit != c4b {
		t.Fatalf("rebased night still pinned to %s, want %s", idx.Nights[0].Commit, c4b)
	}
	for _, n := range idx.Nights {
		if n.Commit == c4 {
			t.Fatalf("stale commit %s still listed", c4)
		}
	}
}
