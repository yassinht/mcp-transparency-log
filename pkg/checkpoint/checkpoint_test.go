package checkpoint

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// memTree is a tiny RFC 6962 tree, enough to make real consistency proofs.
type memTree struct {
	salt   string // a different salt is a different history
	n      int64
	hashes []tlog.Hash
}

func (m *memTree) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = m.hashes[x]
	}
	return out, nil
}

func (m *memTree) add(t *testing.T, k int) {
	t.Helper()
	for i := 0; i < k; i++ {
		hs, err := tlog.StoredHashes(m.n, []byte(fmt.Sprintf("%sleaf %d", m.salt, m.n)), m)
		if err != nil {
			t.Fatal(err)
		}
		m.hashes = append(m.hashes, hs...)
		m.n++
	}
}

func (m *memTree) root(t *testing.T) tlog.Hash {
	t.Helper()
	h, err := tlog.TreeHash(m.n, m)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (m *memTree) prover(size int64) ProofFunc {
	return func(old int64) (tlog.TreeProof, error) { return tlog.ProveTree(size, old, m) }
}

// fakeWitness follows c2sp.org/tlog-witness closely enough to fail the way a
// real one would.
type fakeWitness struct {
	mu       sync.Mutex
	name     string
	priv     ed25519.PrivateKey
	logPub   ed25519.PublicKey
	knowsLog bool
	size     int64
	root     tlog.Hash
	now      int64
}

func newFakeWitness(t *testing.T, logPub ed25519.PublicKey) (*fakeWitness, string) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	w := &fakeWitness{name: "witness.test/w1", priv: priv, logPub: logPub, knowsLog: true, now: 1764000000}
	key := append([]byte{algCosignatureV1}, pub...)
	vkey := fmt.Sprintf("%s+%08x+%s", w.name, keyID(w.name, key), base64.StdEncoding.EncodeToString(key))
	return w, vkey
}

func (w *fakeWitness) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.Path != "/add-checkpoint" {
		http.Error(rw, "no", http.StatusNotFound)
		return
	}
	body, _ := io.ReadAll(r.Body)
	head, cp, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		http.Error(rw, "no blank line", http.StatusBadRequest)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(head))
	sc.Scan()
	old, err := strconv.ParseInt(strings.TrimPrefix(sc.Text(), "old "), 10, 64)
	if err != nil {
		http.Error(rw, "bad old", http.StatusBadRequest)
		return
	}
	var proof tlog.TreeProof
	for sc.Scan() {
		h, err := tlog.ParseHash(sc.Text())
		if err != nil {
			http.Error(rw, "bad proof", http.StatusBadRequest)
			return
		}
		proof = append(proof, h)
	}
	if !w.knowsLog {
		http.Error(rw, "unknown log", http.StatusNotFound)
		return
	}
	c, err := Open(cp, w.logPub)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	if old > c.Size {
		http.Error(rw, "old > size", http.StatusBadRequest)
		return
	}
	if old != w.size {
		rw.Header().Set("Content-Type", "text/x.tlog.size")
		rw.WriteHeader(http.StatusConflict)
		fmt.Fprintf(rw, "%d\n", w.size)
		return
	}
	switch {
	case old == 0 && len(proof) != 0:
		http.Error(rw, "proof from zero", http.StatusUnprocessableEntity)
		return
	case old == c.Size && c.Root != w.root:
		http.Error(rw, "same size, other root", http.StatusUnprocessableEntity)
		return
	case old > 0 && old < c.Size:
		if err := tlog.CheckTree(proof, c.Size, c.Root, old, w.root); err != nil {
			http.Error(rw, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}
	w.size, w.root = c.Size, c.Root
	w.now++
	var m bytes.Buffer
	fmt.Fprintf(&m, "cosignature/v1\ntime %d\n%s", w.now, c.Note.Text)
	sig := ed25519.Sign(w.priv, m.Bytes())
	raw := make([]byte, 4, 4+8+len(sig))
	binary.BigEndian.PutUint32(raw, keyID(w.name, append([]byte{algCosignatureV1}, w.priv.Public().(ed25519.PublicKey)...)))
	raw = binary.BigEndian.AppendUint64(raw, uint64(w.now))
	raw = append(raw, sig...)
	fmt.Fprintf(rw, "— %s %s\n", w.name, base64.StdEncoding.EncodeToString(raw))
}

func TestSignOpen(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tr := &memTree{}
	tr.add(t, 5)
	cp, err := Sign(tr.n, tr.root(t), priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(cp), Origin+"\n5\n"+tr.root(t).String()+"\n\n— "+Origin+" ") {
		t.Fatalf("not a C2SP checkpoint:\n%s", cp)
	}
	again, _ := Sign(tr.n, tr.root(t), priv)
	if !bytes.Equal(cp, again) {
		t.Fatal("signing the same head twice gave different bytes")
	}
	c, err := Open(cp, pub)
	if err != nil {
		t.Fatal(err)
	}
	if c.Size != 5 || c.Root != tr.root(t) {
		t.Fatalf("opened %d %v", c.Size, c.Root)
	}
	vkey, _ := VKey(pub)
	if !strings.HasPrefix(vkey, Origin+"+") {
		t.Fatalf("vkey %s", vkey)
	}
	if v, err := NewVerifier(vkey); err != nil || v.Name() != Origin {
		t.Fatalf("own vkey does not parse: %v", err)
	}

	tampered := bytes.Replace(cp, []byte("\n5\n"), []byte("\n6\n"), 1)
	if _, err := Open(tampered, pub); err == nil {
		t.Fatal("a checkpoint with an edited size opened")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Open(cp, other); err == nil {
		t.Fatal("a checkpoint opened under the wrong key")
	}
}

func TestCosign(t *testing.T) {
	logPub, logPriv, _ := ed25519.GenerateKey(rand.Reader)
	fw, vkey := newFakeWitness(t, logPub)
	srv := httptest.NewTLSServer(fw)
	defer srv.Close()
	ws, err := ParseWitnesses("# test\n" + vkey + " " + srv.URL + "/\n")
	if err != nil {
		t.Fatal(err)
	}
	w := ws[0]
	ctx, hc := context.Background(), srv.Client()

	tr := &memTree{}
	tr.add(t, 7)
	cp1, _ := Sign(tr.n, tr.root(t), logPriv)

	// First contact: the log knows nothing, the witness holds nothing.
	lines, err := Cosign(ctx, hc, w, cp1, tr.n, 0, tr.prover(tr.n))
	if err != nil {
		t.Fatal(err)
	}
	merged := Merge(cp1, lines)
	c, err := Open(merged, logPub, Verifiers(ws)...)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Note.Sigs) != 2 {
		t.Fatalf("want log + witness signatures, got %d", len(c.Note.Sigs))
	}
	if at, ok := CosignedAt(c.Note.Sigs[1]); !ok || at.Unix() != fw.now {
		t.Fatalf("cosignature time %v %v", at, ok)
	}

	// Next night, the log grew and remembers what the witness holds.
	tr.add(t, 13)
	cp2, _ := Sign(tr.n, tr.root(t), logPriv)
	if _, err := Cosign(ctx, hc, w, cp2, tr.n, 7, tr.prover(tr.n)); err != nil {
		t.Fatal(err)
	}

	// The log lost its state: 409 tells it the size, the retry carries a proof.
	tr.add(t, 4)
	cp3, _ := Sign(tr.n, tr.root(t), logPriv)
	if _, err := Cosign(ctx, hc, w, cp3, tr.n, 0, tr.prover(tr.n)); err != nil {
		t.Fatalf("recover from 409: %v", err)
	}
	if fw.size != tr.n {
		t.Fatalf("witness holds %d, want %d", fw.size, tr.n)
	}

	// Asking twice about the same tree gives a second timestamp; Merge keeps one.
	again, err := Cosign(ctx, hc, w, cp3, tr.n, tr.n, tr.prover(tr.n))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := Cosign(ctx, hc, w, cp3, tr.n, tr.n, tr.prover(tr.n))
	m := Merge(cp3, first, again)
	if strings.Count(string(m), "— "+fw.name+" ") != 1 {
		t.Fatalf("merge kept duplicate cosignatures:\n%s", m)
	}

	// A forked history: a bigger tree that does not extend what the witness saw.
	fork := &memTree{salt: "rewritten "}
	fork.add(t, int(tr.n)+3)
	forkRoot := fork.root(t)
	cpFork, _ := Sign(fork.n, forkRoot, logPriv)
	_, err = Cosign(ctx, hc, w, cpFork, fork.n, tr.n, fork.prover(fork.n))
	if !errors.Is(err, ErrInconsistent) {
		t.Fatalf("fork: want ErrInconsistent, got %v", err)
	}

	// A witness that never heard of the log.
	fw.knowsLog = false
	if _, err := Cosign(ctx, hc, w, cp3, tr.n, tr.n, tr.prover(tr.n)); !errors.Is(err, ErrUnknownLog) {
		t.Fatalf("want ErrUnknownLog, got %v", err)
	}
}

func TestParseWitnesses(t *testing.T) {
	_, vkey := newFakeWitness(t, nil)
	if _, err := ParseWitnesses(vkey + " http://insecure.example\n"); err == nil {
		t.Fatal("accepted a plain-http witness")
	}
	if _, err := ParseWitnesses(vkey + " https://a.example\n" + vkey + " https://b.example\n"); err == nil {
		t.Fatal("accepted the same witness twice")
	}
	mldsa := "staging.witness.example/w+5774b075+" + base64.StdEncoding.EncodeToString(append([]byte{0x06}, make([]byte, 1312)...))
	if _, err := ParseWitnesses(mldsa + " https://w.example\n"); err == nil || !strings.Contains(err.Error(), "ML-DSA-44") {
		t.Fatalf("ML-DSA key: %v", err)
	}
	bad := strings.Replace(vkey, "+", "+0000", 1)
	if _, err := ParseWitnesses(bad + " https://w.example\n"); err == nil {
		t.Fatal("accepted a vkey whose hash does not match")
	}
	ws, err := ParseWitnesses("\n# none yet\n")
	if err != nil || len(ws) != 0 {
		t.Fatalf("empty list: %v %v", ws, err)
	}
}

// Vectors from transparency-dev/formats (note/note_cosigv1_test.go): a real
// witness key from the witness network, and a real cosignature timestamp.
func TestReferenceVectors(t *testing.T) {
	v, err := NewVerifier("remora.n621.de+da77ade7+BOvN63jn/bLvkieywe8R6UYAtVtNbZpXh34x7onlmtw2")
	if err != nil {
		t.Fatalf("real witness key refused: %v", err)
	}
	if v.Name() != "remora.n621.de" || v.KeyHash() != 0xda77ade7 {
		t.Fatalf("parsed %s %08x", v.Name(), v.KeyHash())
	}
	for _, bad := range []string{
		"bananas.sigstore.dev+12344556",
		"rekor.sigstore.dev+12345678+THIS_IS_NOT_BASE64!",
		"rekor.sigstore.dev+12345678+AwEB",
		"remora.n621.de+00000000+BOvN63jn/bLvkieywe8R6UYAtVtNbZpXh34x7onlmtw2",
	} {
		if _, err := NewVerifier(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	at, ok := CosignedAt(note.Signature{Base64: "ZGhGuQAAAABm/qTPeyKXD+R2rzyQsxPiP8mXum7qq/iF0u4vanlqJyocWODBt97w9uL+8qT7S5gxEHWWOworDcFiEBYJXORmnFBOBA=="})
	if !ok || at.Unix() != 1727964367 {
		t.Fatalf("timestamp %v %v", at, ok)
	}
}
