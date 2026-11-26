// Package checkpoint publishes this log's tree heads in the interoperable
// format independent witnesses cosign (c2sp.org/tlog-checkpoint).
//
// Until now the log has had one weakness no amount of code could close: there
// is one operator. A verifier can check that every head extends the one
// before, but nothing stops that operator from showing one history to one
// reader and a different history to another. Certificate Transparency closes
// that with gossip and witnesses, and the transparency.dev community runs a
// witness network for exactly this. A witness keeps the last tree size it saw
// for a log, checks a consistency proof before cosigning a new one, and so a
// head that carries cosignatures from witnesses run by other people is a head
// that was shown to them too.
//
// The existing head format stays. It is what the series since 2026-08-30 is
// written in, and the evidence bundles pin it. A checkpoint is derived from a
// head: same size, same root, same key, so it adds no new claim, only a format
// other people's software already speaks.
package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Origin names this log to witnesses. It is the first line of every
// checkpoint and the name in the log's verifier key, and it can never change:
// a witness tracks a log by its origin, so a new origin is a new log with no
// history.
const Origin = "yassinht.github.io/mcp-transparency-log"

const (
	algEd25519       = 0x01 // the log's own signature (c2sp.org/signed-note)
	algCosignatureV1 = 0x04 // an Ed25519 witness cosignature (c2sp.org/tlog-cosignature)
)

// Text is the signed body of a checkpoint. No extension lines: the spec
// recommends against them, and a witness signing ML-DSA-44 would not cover them.
func Text(size int64, root tlog.Hash) string {
	return fmt.Sprintf("%s\n%d\n%s\n", Origin, size, root.String())
}

// keyID is the note key hash: SHA-256(name || "\n" || alg || key)[:4].
func keyID(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	return binary.BigEndian.Uint32(h.Sum(nil)[:4])
}

// Signer turns the log's existing Ed25519 key into a note signer named Origin.
func Signer(priv ed25519.PrivateKey) (note.Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("checkpoint: not an Ed25519 private key")
	}
	pub := priv.Public().(ed25519.PublicKey)
	id := keyID(Origin, append([]byte{algEd25519}, pub...))
	skey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", Origin, id,
		base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, priv.Seed()...)))
	return note.NewSigner(skey)
}

// VKey is the log's public key in vkey form, what a witness is configured with.
func VKey(pub ed25519.PublicKey) (string, error) {
	return note.NewEd25519VerifierKey(Origin, pub)
}

// Sign returns a checkpoint for (size, root) signed by the log key. Ed25519 is
// deterministic, so signing the same head twice gives the same bytes, which is
// what lets the nightly job rewrite old checkpoints without churn.
func Sign(size int64, root tlog.Hash, priv ed25519.PrivateKey) ([]byte, error) {
	s, err := Signer(priv)
	if err != nil {
		return nil, err
	}
	return note.Sign(&note.Note{Text: Text(size, root)}, s)
}

// Checkpoint is an opened checkpoint: the tree it names and every signature
// that verified, the log's own first.
type Checkpoint struct {
	Size int64
	Root tlog.Hash
	Note *note.Note
}

// Open verifies a checkpoint against the log key and any witness verifiers.
// The log's signature must be present and valid. A signature from a known
// witness key must also be valid, or the whole note is refused; signatures
// from keys nobody configured are kept in Note.UnverifiedSigs and mean nothing.
func Open(msg []byte, pub ed25519.PublicKey, witnesses ...note.Verifier) (*Checkpoint, error) {
	vkey, err := VKey(pub)
	if err != nil {
		return nil, err
	}
	lv, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, err
	}
	n, err := note.Open(msg, note.VerifierList(append([]note.Verifier{lv}, witnesses...)...))
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	logSigned := false
	for _, s := range n.Sigs {
		if s.Name == lv.Name() && s.Hash == lv.KeyHash() {
			logSigned = true
		}
	}
	if !logSigned {
		return nil, errors.New("checkpoint: not signed by the log key")
	}
	size, root, err := parseText(n.Text)
	if err != nil {
		return nil, err
	}
	return &Checkpoint{Size: size, Root: root, Note: n}, nil
}

// parseText is strict for the same reason ParseHead is: a verifier that reads
// malformed input generously is a verifier that can be fooled.
func parseText(text string) (int64, tlog.Hash, error) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 3 {
		return 0, tlog.Hash{}, fmt.Errorf("checkpoint: expected 3 lines, got %d", len(lines))
	}
	if lines[0] != Origin {
		return 0, tlog.Hash{}, fmt.Errorf("checkpoint: origin %q is not this log", lines[0])
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 || strconv.FormatInt(size, 10) != lines[1] {
		return 0, tlog.Hash{}, fmt.Errorf("checkpoint: bad size line %q", lines[1])
	}
	root, err := tlog.ParseHash(lines[2])
	if err != nil || root.String() != lines[2] {
		return 0, tlog.Hash{}, fmt.Errorf("checkpoint: bad root line %q", lines[2])
	}
	return size, root, nil
}

// NewVerifier parses a vkey. Two kinds are understood: the log's own Ed25519
// key (0x01) and an Ed25519 witness cosignature key (0x04). ML-DSA-44 witness
// keys (0x06) are refused with a clear error rather than silently trusted: the
// Go standard library has no ML-DSA yet, and an unchecked cosignature is worse
// than none, because it looks like one.
func NewVerifier(vkey string) (note.Verifier, error) {
	name, rest, ok := strings.Cut(vkey, "+")
	hexID, b64, ok2 := strings.Cut(rest, "+")
	if !ok || !ok2 || name == "" {
		return nil, fmt.Errorf("vkey %q: want name+hash+key", vkey)
	}
	id, err := strconv.ParseUint(hexID, 16, 32)
	if err != nil || len(hexID) != 8 {
		return nil, fmt.Errorf("vkey %q: bad key hash", vkey)
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("vkey %q: bad key", vkey)
	}
	switch key[0] {
	case algEd25519:
		return note.NewVerifier(vkey)
	case algCosignatureV1:
		if len(key) != 1+ed25519.PublicKeySize {
			return nil, fmt.Errorf("vkey %q: cosignature key is %d bytes", vkey, len(key)-1)
		}
		if keyID(name, key) != uint32(id) {
			return nil, fmt.Errorf("vkey %q: key hash does not match the key", vkey)
		}
		return &cosigVerifier{name: name, id: uint32(id), pub: ed25519.PublicKey(key[1:])}, nil
	case 0x06:
		return nil, fmt.Errorf("vkey %q: ML-DSA-44 cosignatures are not verified yet; configure the witness's Ed25519 key", vkey)
	default:
		return nil, fmt.Errorf("vkey %q: unknown key type 0x%02x", vkey, key[0])
	}
}

// cosigVerifier checks cosignature/v1: an 8-byte big-endian timestamp followed
// by an Ed25519 signature over "cosignature/v1\ntime <t>\n" and the checkpoint
// text.
type cosigVerifier struct {
	name string
	id   uint32
	pub  ed25519.PublicKey
}

func (v *cosigVerifier) Name() string    { return v.name }
func (v *cosigVerifier) KeyHash() uint32 { return v.id }
func (v *cosigVerifier) Verify(msg, sig []byte) bool {
	if len(sig) != 8+ed25519.SignatureSize {
		return false
	}
	t := binary.BigEndian.Uint64(sig[:8])
	var m bytes.Buffer
	fmt.Fprintf(&m, "cosignature/v1\ntime %d\n", t)
	m.Write(msg)
	return ed25519.Verify(v.pub, m.Bytes(), sig[8:])
}

// CosignedAt reads the timestamp a witness put in a cosignature/v1 signature.
func CosignedAt(s note.Signature) (time.Time, bool) {
	raw, err := base64.StdEncoding.DecodeString(s.Base64)
	if err != nil || len(raw) != 4+8+ed25519.SignatureSize {
		return time.Time{}, false
	}
	return time.Unix(int64(binary.BigEndian.Uint64(raw[4:12])), 0).UTC(), true
}

// SigLine formats a verified signature as the note line that carries it.
func SigLine(s note.Signature) string {
	return "— " + s.Name + " " + s.Base64 + "\n"
}
