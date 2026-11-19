package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/yassinht/mcp-transparency-log/pkg/canon"
)

func TestPutBlobWritesGzipAndReadBlobReadsBoth(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root, "2026-11-18T000000Z")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	body := bytes.Repeat([]byte(`{"tools":[{"name":"a","description":"same text again and again"}]}`), 50)
	sum, err := s.PutBlob(body)
	if err != nil {
		t.Fatal(err)
	}
	gz := filepath.Join(root, "blobs", sum[:2], sum+".gz")
	st, err := os.Stat(gz)
	if err != nil {
		t.Fatalf("compressed blob not written: %v", err)
	}
	if st.Size() >= int64(len(body)) {
		t.Fatalf("blob did not shrink: %d >= %d", st.Size(), len(body))
	}
	if _, err := os.Stat(filepath.Join(root, "blobs", sum[:2], sum)); err == nil {
		t.Fatal("plain blob written alongside the compressed one")
	}
	got, err := ReadBlob(root, sum)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("round trip: %v, equal=%v", err, bytes.Equal(got, body))
	}

	// A blob archived before 2026-11-18 is plain on disk; it must still read,
	// and writing the same bytes again must not create a second copy.
	legacy := []byte(`{"tools":[]}`)
	lsum := canon.SHA256Hex(legacy)
	ldir := filepath.Join(root, "blobs", lsum[:2])
	if err := os.MkdirAll(ldir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ldir, lsum), legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = ReadBlob(root, lsum)
	if err != nil || !bytes.Equal(got, legacy) {
		t.Fatalf("legacy read: %v", err)
	}
	if _, err := s.PutBlob(legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ldir, lsum+".gz")); err == nil {
		t.Fatal("PutBlob re-wrote a blob that already existed in plain form")
	}
}
