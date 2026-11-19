package mlog

import (
	"os"
	"path/filepath"
	"testing"
)

// The point of publishing leaf hashes is that someone holding nothing but
// those hashes reaches the same root the operator signed. If that fails, the
// published files are decoration.
func TestVerifyFromLeavesMatchesTheRealTree(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	logDir := filepath.Join(base, "tlog")
	leaves := filepath.Join(base, "leaves")

	writeRun(t, dataDir, "2026-10-01T030000Z", 300)
	writeRun(t, dataDir, "2026-10-02T030000Z", 412)
	for _, r := range []string{"2026-10-01T030000Z", "2026-10-02T030000Z"} {
		if _, err := CommitRun(logDir, dataDir, r); err != nil {
			t.Fatal(err)
		}
	}

	l, err := Open(logDir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := l.TreeHash()
	if err != nil {
		t.Fatal(err)
	}
	wantSize := l.Size()
	l.Close()

	man, err := ExportLeaves(logDir, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if man.Size != wantSize || man.Root != want.String() {
		t.Fatalf("manifest disagrees with the tree it came from")
	}

	size, root, err := VerifyFromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if size != wantSize || root != want.String() {
		t.Fatalf("rebuilt from leaves gives %d/%s, want %d/%s",
			size, root, wantSize, want.String())
	}
}

// A verifier must reject tampered leaf files rather than quietly computing a
// different root and reporting success.
func TestVerifyFromLeavesRejectsTampering(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	logDir := filepath.Join(base, "tlog")
	leaves := filepath.Join(base, "leaves")

	writeRun(t, dataDir, "2026-10-01T030000Z", 128)
	if _, err := CommitRun(logDir, dataDir, "2026-10-01T030000Z"); err != nil {
		t.Fatal(err)
	}
	man, err := ExportLeaves(logDir, leaves)
	if err != nil {
		t.Fatal(err)
	}
	_, honest, err := VerifyFromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}

	// Flip one byte of one leaf hash.
	p := filepath.Join(leaves, man.Runs[0].File)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[64] ^= 0xff
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	_, tampered, err := VerifyFromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if tampered == honest {
		t.Fatal("a flipped leaf byte produced the same root")
	}

	// Truncating a file must be an error, not a shorter tree reported as valid.
	if err := os.WriteFile(p, raw[:len(raw)-hashSize], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyFromLeaves(leaves); err == nil {
		t.Fatal("a truncated leaf file was accepted")
	}
}

// Resumed censuses contribute two ranges under one run id; the exported files
// must keep them apart or the concatenation order silently changes.
func TestExportLeavesHandlesResumedRuns(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	logDir := filepath.Join(base, "tlog")
	leaves := filepath.Join(base, "leaves")
	run := "2026-10-01T030000Z"

	writeRun(t, dataDir, run, 100)
	if _, err := CommitRun(logDir, dataDir, run); err != nil {
		t.Fatal(err)
	}
	writeRun(t, dataDir, run, 175) // resumed: 75 more
	if _, err := CommitRun(logDir, dataDir, run); err != nil {
		t.Fatal(err)
	}

	man, err := ExportLeaves(logDir, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if len(man.Runs) != 2 {
		t.Fatalf("expected 2 ranges for a resumed run, got %d", len(man.Runs))
	}
	if man.Runs[0].File == man.Runs[1].File {
		t.Fatal("both ranges wrote to the same file")
	}
	size, root, err := VerifyFromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if size != 175 || root != man.Root {
		t.Fatalf("resumed run rebuilt to %d/%s, want 175/%s", size, root, man.Root)
	}
}
