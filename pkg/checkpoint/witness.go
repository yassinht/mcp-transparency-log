package checkpoint

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// A Witness is one cosigner the log asks every night (c2sp.org/tlog-witness).
type Witness struct {
	VKey     string // name+hash+key, the key the witness cosigns with
	URL      string // submission prefix; requests go to URL + "/add-checkpoint"
	Verifier note.Verifier
}

func (w Witness) Name() string { return w.Verifier.Name() }

// ParseWitnesses reads the published witness list: one witness per line, its
// vkey then its submission prefix, '#' for comments. The list is public on
// purpose. A cosignature only means something to a reader who knows which
// keys to trust, so the trust policy ships beside the checkpoints it judges.
func ParseWitnesses(text string) ([]Witness, error) {
	var out []Witness
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || !strings.HasPrefix(f[1], "https://") {
			return nil, fmt.Errorf("witnesses line %d: want \"<vkey> https://<submission prefix>\"", n)
		}
		v, err := NewVerifier(f[0])
		if err != nil {
			return nil, fmt.Errorf("witnesses line %d: %w", n, err)
		}
		if seen[v.Name()] {
			return nil, fmt.Errorf("witnesses line %d: %s listed twice", n, v.Name())
		}
		seen[v.Name()] = true
		out = append(out, Witness{VKey: f[0], URL: strings.TrimSuffix(f[1], "/"), Verifier: v})
	}
	return out, sc.Err()
}

// Verifiers returns the witnesses' keys, for Open.
func Verifiers(ws []Witness) []note.Verifier {
	out := make([]note.Verifier, len(ws))
	for i, w := range ws {
		out[i] = w.Verifier
	}
	return out
}

// ProofFunc returns a consistency proof from oldSize to the checkpoint's size.
type ProofFunc func(oldSize int64) (tlog.TreeProof, error)

// Errors a caller may want to tell apart. The last two are the loud ones: a
// witness that refuses a consistency proof, or remembers a bigger tree than
// the log has, is either broken or has just caught the log rewriting history.
var (
	ErrUnknownLog   = errors.New("witness does not know this log yet")
	ErrRejectedSig  = errors.New("witness rejected the log signature")
	ErrInconsistent = errors.New("witness refused the consistency proof")
	ErrAhead        = errors.New("witness has cosigned a larger tree than this checkpoint")
)

// Cosign submits a log-signed checkpoint to one witness and returns the
// witness's verified cosignature lines and the size it now holds.
//
// oldSize is the size this log last had cosigned by that witness, 0 if
// unknown. A witness that disagrees answers 409 with the size it holds; the
// spec allows starting at 0 to learn it, so one retry with that size is the
// normal path for a first contact, not an error.
func Cosign(ctx context.Context, hc *http.Client, w Witness, signed []byte, size int64, oldSize int64, prove ProofFunc) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if oldSize > size {
			return nil, fmt.Errorf("%s: %w (%d > %d)", w.Name(), ErrAhead, oldSize, size)
		}
		var body bytes.Buffer
		fmt.Fprintf(&body, "old %d\n", oldSize)
		if oldSize > 0 && oldSize < size {
			proof, err := prove(oldSize)
			if err != nil {
				return nil, fmt.Errorf("%s: proof from %d: %w", w.Name(), oldSize, err)
			}
			if len(proof) > 63 {
				return nil, fmt.Errorf("%s: proof has %d hashes, the protocol allows 63", w.Name(), len(proof))
			}
			for _, h := range proof {
				body.WriteString(h.String() + "\n")
			}
		}
		body.WriteString("\n")
		body.Write(signed)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL+"/add-checkpoint", &body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", w.Name(), err)
		}
		reply, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			return verifyReply(w, signed, reply)
		case http.StatusConflict:
			held, err := strconv.ParseInt(strings.TrimSpace(string(reply)), 10, 64)
			if err != nil || held < 0 {
				return nil, fmt.Errorf("%s: 409 with an unreadable size %q", w.Name(), snippet(reply))
			}
			if held == oldSize {
				return nil, fmt.Errorf("%s: 409 but it holds the size we sent (%d)", w.Name(), held)
			}
			oldSize = held
			continue
		case http.StatusNotFound:
			return nil, fmt.Errorf("%s: %w", w.Name(), ErrUnknownLog)
		case http.StatusForbidden:
			return nil, fmt.Errorf("%s: %w", w.Name(), ErrRejectedSig)
		case http.StatusUnprocessableEntity:
			return nil, fmt.Errorf("%s: %w from size %d: %s", w.Name(), ErrInconsistent, oldSize, snippet(reply))
		default:
			return nil, fmt.Errorf("%s: HTTP %d: %s", w.Name(), resp.StatusCode, snippet(reply))
		}
	}
	return nil, fmt.Errorf("%s: still in conflict after learning its size", w.Name())
}

// verifyReply keeps only cosignature lines that verify under this witness's
// key. A reply is appended to the checkpoint and opened as one note, which is
// exactly how the spec suggests a client parse it.
func verifyReply(w Witness, signed, reply []byte) ([]byte, error) {
	if len(reply) == 0 || !bytes.HasPrefix(reply, []byte("— ")) || !bytes.HasSuffix(reply, []byte("\n")) {
		return nil, fmt.Errorf("%s: reply is not signature lines: %q", w.Name(), snippet(reply))
	}
	n, err := note.Open(append(append([]byte{}, signed...), reply...), note.VerifierList(w.Verifier))
	if err != nil {
		return nil, fmt.Errorf("%s: cosignature does not verify: %w", w.Name(), err)
	}
	var out bytes.Buffer
	for _, s := range n.Sigs {
		out.WriteString(SigLine(s))
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("%s: no cosignature from its configured key", w.Name())
	}
	return out.Bytes(), nil
}

// Merge appends cosignature lines to a checkpoint. A note may not carry two
// signatures with the same key name and key id, and a witness asked twice
// about the same tree answers with a fresh timestamp, so the first signature
// per key wins and later ones are dropped. Rerunning the nightly job is safe.
func Merge(signed []byte, lines ...[]byte) []byte {
	out := append([]byte{}, signed...)
	have := map[string]bool{}
	for _, l := range strings.SplitAfter(string(signed), "\n") {
		if k, ok := sigKey(l); ok {
			have[k] = true
		}
	}
	for _, block := range lines {
		for _, l := range strings.SplitAfter(string(block), "\n") {
			k, ok := sigKey(l)
			if !ok || have[k] {
				continue
			}
			have[k] = true
			out = append(out, l...)
		}
	}
	return out
}

// sigKey identifies a signature line by key name and key id.
func sigKey(line string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "— ")
	if !ok {
		return "", false
	}
	name, b64, ok := strings.Cut(rest, " ")
	if !ok {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 5 {
		return "", false
	}
	return name + "+" + hex.EncodeToString(raw[:4]), true
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
