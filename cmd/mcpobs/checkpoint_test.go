package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yassinht/mcp-transparency-log/pkg/checkpoint"
	"github.com/yassinht/mcp-transparency-log/pkg/mlog"
)

// The full nightly path on a real (small) log: two signed nights, checkpoints
// derived from them, one witness asked, the result verified as a stranger would.
func TestCheckpointWitnessVerify(t *testing.T) {
	root := t.TempDir()
	heads := filepath.Join(root, "heads")
	logDir := filepath.Join(root, "data", "tlog")
	os.MkdirAll(heads, 0o755)
	pub, err := mlog.GenerateKey(filepath.Join(heads, "key"))
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := mlog.LoadKey(filepath.Join(heads, "key"))

	l, err := mlog.Open(logDir)
	if err != nil {
		t.Fatal(err)
	}
	night := func(date string, k int) {
		var recs [][]byte
		for i := 0; i < k; i++ {
			recs = append(recs, []byte(fmt.Sprintf("%s obs %d", date, i)))
		}
		if _, err := l.Append(recs); err != nil {
			t.Fatal(err)
		}
		h, err := l.Sign(priv, time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(heads, date+".txt"), []byte(h.String()), 0o644)
	}
	night("2026-11-25", 9)
	night("2026-11-26", 14)
	size := l.Size()
	l.Close()

	pubPath := filepath.Join(heads, "key.pub")
	if err := cmdCheckpoint(heads, pubPath, filepath.Join(heads, "key")); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"checkpoints/2026-11-25.txt", "checkpoints/2026-11-26.txt", "checkpoint", "key.vkey"} {
		if _, err := os.Stat(filepath.Join(heads, f)); err != nil {
			t.Fatalf("missing %s", f)
		}
	}
	// Rerunning changes nothing.
	before, _ := os.ReadFile(filepath.Join(heads, "checkpoint"))
	if err := cmdCheckpoint(heads, pubPath, filepath.Join(heads, "key")); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(heads, "checkpoint"))
	if !bytes.Equal(before, after) {
		t.Fatal("a second run rewrote the checkpoint")
	}
	// The loader of signed heads must not trip over the new files.
	if hs, err := loadHeads(heads); err != nil || len(hs) != 2 {
		t.Fatalf("loadHeads after checkpoint: %d %v", len(hs), err)
	}

	// One witness that cosigns whatever verifies under the log key.
	wpub, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	wname := "witness.test/w1"
	wkey := append([]byte{0x04}, wpub...)
	sum := sha256.Sum256(append([]byte(wname+"\n"), wkey...))
	vkey := fmt.Sprintf("%s+%x+%s", wname, sum[:4], base64.StdEncoding.EncodeToString(wkey))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, cp, _ := bytes.Cut(body, []byte("\n\n"))
		c, err := checkpoint.Open(cp, pub)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusForbidden)
			return
		}
		ts := uint64(1764130000)
		msg := fmt.Sprintf("cosignature/v1\ntime %d\n%s", ts, c.Note.Text)
		raw := append(append(append([]byte{}, sum[:4]...), binary.BigEndian.AppendUint64(nil, ts)...), ed25519.Sign(wpriv, []byte(msg))...)
		fmt.Fprintf(rw, "— %s %s\n", wname, base64.StdEncoding.EncodeToString(raw))
	}))
	defer srv.Close()
	witnessHTTPClient = srv.Client()
	list := filepath.Join(root, "witnesses")
	os.WriteFile(list, []byte("# test witness\n"+vkey+" "+srv.URL+"\n"), 0o644)
	state := filepath.Join(root, "data", "witness-state.json")

	if err := cmdWitness(filepath.Join(root, "data"), logDir, heads, pubPath, list, state); err != nil {
		t.Fatal(err)
	}
	cp, _ := os.ReadFile(filepath.Join(heads, "checkpoint"))
	if strings.Count(string(cp), "— ") != 2 {
		t.Fatalf("published checkpoint should carry log + witness signatures:\n%s", cp)
	}
	dated, _ := os.ReadFile(filepath.Join(heads, "checkpoints", "2026-11-26.txt"))
	if !bytes.Equal(cp, dated) {
		t.Fatal("dated checkpoint and latest checkpoint differ")
	}
	st, _ := os.ReadFile(state)
	if !strings.Contains(string(st), fmt.Sprintf("%q: %d", wname, size)) {
		t.Fatalf("state not recorded: %s", st)
	}
	// Asking again the same night adds no second signature.
	if err := cmdWitness(filepath.Join(root, "data"), logDir, heads, pubPath, list, state); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filepath.Join(heads, "checkpoint"))
	if !bytes.Equal(cp, again) {
		t.Fatalf("second witness run changed the checkpoint:\n%s", again)
	}
	// And the checkpoint step keeps the cosignature instead of resetting it.
	if err := cmdCheckpoint(heads, pubPath, filepath.Join(heads, "key")); err != nil {
		t.Fatal(err)
	}
	kept, _ := os.ReadFile(filepath.Join(heads, "checkpoint"))
	if !bytes.Equal(cp, kept) {
		t.Fatal("checkpoint step dropped the cosignature")
	}
	if err := cmdVerifyCheckpoint(filepath.Join(heads, "checkpoint"), heads, pubPath, list); err != nil {
		t.Fatal(err)
	}
	// A checkpoint whose tree no head names is refused.
	other, _ := checkpoint.Sign(3, mlog.RecordHash([]byte("x")), priv)
	stray := filepath.Join(root, "stray")
	os.WriteFile(stray, other, 0o644)
	if err := cmdVerifyCheckpoint(stray, heads, pubPath, list); err == nil {
		t.Fatal("verified a checkpoint no signed head names")
	}
}
