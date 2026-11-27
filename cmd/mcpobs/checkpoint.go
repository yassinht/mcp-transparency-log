package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/yassinht/mcp-transparency-log/pkg/checkpoint"
	"github.com/yassinht/mcp-transparency-log/pkg/mlog"
)

// cmdCheckpoint derives a C2SP checkpoint from every signed head: same size,
// same root, same key. It refuses to sign a head that does not verify under
// key.pub, so a checkpoint can never claim more than the head it came from.
// Existing checkpoint files are kept as they are when their log-signed part
// matches, because they may already carry witness cosignatures.
func cmdCheckpoint(headsDir, pubPath, keyPath string) error {
	pub, err := mlog.LoadPublicKey(pubPath)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	priv, err := mlog.LoadKey(keyPath)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		return errors.New("checkpoint: the signing key does not match key.pub")
	}
	heads, err := loadHeads(headsDir)
	if err != nil {
		return err
	}
	if len(heads) == 0 {
		return fmt.Errorf("no signed heads in %s", headsDir)
	}
	dir := filepath.Join(headsDir, "checkpoints")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	vkey, err := checkpoint.VKey(pub)
	if err != nil {
		return err
	}
	if _, err := writeIfChanged(filepath.Join(headsDir, "key.vkey"), []byte(vkey+"\n")); err != nil {
		return err
	}

	wrote := 0
	var latest []byte
	for _, h := range heads {
		if err := h.head.Verify(pub); err != nil {
			return fmt.Errorf("%s: %w; refusing to derive a checkpoint from it", h.name, err)
		}
		cp, err := checkpoint.Sign(h.head.Size, h.head.Root, priv)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, h.name)
		if old, err := os.ReadFile(path); err == nil {
			if !bytes.HasPrefix(old, cp) {
				return fmt.Errorf("%s: an existing checkpoint names a different tree; leaving it for a human", path)
			}
			latest = old
			continue
		}
		if err := os.WriteFile(path, cp, 0o644); err != nil {
			return err
		}
		wrote++
		latest = cp
	}
	if _, err := writeIfChanged(filepath.Join(headsDir, "checkpoint"), latest); err != nil {
		return err
	}
	last := heads[len(heads)-1]
	fmt.Printf("checkpoints: %d heads, %d new, latest %s size %d\n", len(heads), wrote, last.name, last.head.Size)
	fmt.Printf("log key: %s\n", vkey)
	return nil
}

// witnessHTTPClient is a variable so tests can trust a local TLS witness.
var witnessHTTPClient = &http.Client{Timeout: 30 * time.Second}

// cmdWitness asks every listed witness to cosign the latest checkpoint and
// publishes the cosignatures that verify. A witness that fails tonight costs
// one night of its signature, never the head itself, so failures are reported
// and the run carries on; only "nobody cosigned" is an error.
func cmdWitness(dataDir, logDir, headsDir, pubPath, listPath, statePath string) error {
	list, err := os.ReadFile(listPath)
	if os.IsNotExist(err) {
		fmt.Println("witness: no witness list; nothing to do")
		return nil
	} else if err != nil {
		return err
	}
	ws, err := checkpoint.ParseWitnesses(string(list))
	if err != nil {
		return err
	}
	if len(ws) == 0 {
		fmt.Println("witness: the witness list is empty; nothing to do")
		return nil
	}
	pub, err := mlog.LoadPublicKey(pubPath)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	heads, err := loadHeads(headsDir)
	if err != nil || len(heads) == 0 {
		return fmt.Errorf("witness: no signed heads in %s (%v)", headsDir, err)
	}
	cpPath := filepath.Join(headsDir, "checkpoints", heads[len(heads)-1].name)
	cpBytes, err := os.ReadFile(cpPath)
	if err != nil {
		return fmt.Errorf("witness: %w (run mcpobs checkpoint first)", err)
	}
	c, err := checkpoint.Open(cpBytes, pub, checkpoint.Verifiers(ws)...)
	if err != nil {
		return err
	}

	// Never ask a stranger to vouch for a tree this log cannot rebuild itself.
	l, err := mlog.Open(logDir)
	if err != nil {
		return err
	}
	defer l.Close()
	if c.Size > l.Size() {
		return fmt.Errorf("witness: checkpoint size %d is beyond the local log (%d)", c.Size, l.Size())
	}
	if root, err := tlog.TreeHash(c.Size, l); err != nil || root != c.Root {
		return fmt.Errorf("witness: the local log does not reproduce the checkpoint root at size %d (%v)", c.Size, err)
	}

	state := map[string]int64{}
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, &state)
	}
	hc := witnessHTTPClient
	prove := func(old int64) (tlog.TreeProof, error) { return l.ProveTreeAt(c.Size, old) }

	var got [][]byte
	ok := 0
	for _, w := range ws {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		lines, err := checkpoint.Cosign(ctx, hc, w, cpBytes, c.Size, state[w.Name()], prove)
		cancel()
		if err != nil {
			fmt.Printf("witness %s: %v\n", w.Name(), err)
			continue
		}
		state[w.Name()] = c.Size
		got = append(got, lines)
		ok++
		fmt.Printf("witness %s: cosigned size %d\n", w.Name(), c.Size)
	}

	merged := checkpoint.Merge(cpBytes, got...)
	if _, err := checkpoint.Open(merged, pub, checkpoint.Verifiers(ws)...); err != nil {
		return fmt.Errorf("witness: merged checkpoint does not verify: %w", err)
	}
	for _, p := range []string{cpPath, filepath.Join(headsDir, "checkpoint")} {
		if _, err := writeIfChanged(p, merged); err != nil {
			return err
		}
	}
	if b, err := json.MarshalIndent(state, "", " "); err == nil {
		_ = os.WriteFile(statePath, append(b, '\n'), 0o644)
	}
	fmt.Printf("witness: %d of %d witnesses cosigned size %d\n", ok, len(ws), c.Size)
	if ok == 0 {
		return errors.New("witness: no witness cosigned tonight")
	}
	return nil
}

// cmdVerifyCheckpoint checks a checkpoint the way a stranger would: the log
// signature against key.pub, the tree against the signed head of the same
// size, and each cosignature against the published witness list.
func cmdVerifyCheckpoint(path, headsDir, pubPath, listPath string) error {
	pub, err := mlog.LoadPublicKey(pubPath)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	var ws []checkpoint.Witness
	if b, err := os.ReadFile(listPath); err == nil {
		if ws, err = checkpoint.ParseWitnesses(string(b)); err != nil {
			return err
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	c, err := checkpoint.Open(b, pub, checkpoint.Verifiers(ws)...)
	if err != nil {
		return err
	}
	fmt.Printf("origin   %s\nsize     %d\nroot     %s\n", checkpoint.Origin, c.Size, c.Root)
	fmt.Println("log      signature verifies under key.pub")

	if heads, err := loadHeads(headsDir); err != nil {
		// Say so rather than skip quietly: a check that silently does not run
		// reads exactly like one that passed.
		fmt.Printf("head     not checked: %v\n", err)
	} else {
		match := ""
		for _, h := range heads {
			if h.head.Size == c.Size && h.head.Root == c.Root {
				match = h.name
			}
		}
		if match == "" {
			return fmt.Errorf("no signed head in %s names this tree", headsDir)
		}
		fmt.Printf("head     matches %s\n", match)
	}

	cosigned := 0
	for _, s := range c.Note.Sigs {
		if s.Name == checkpoint.Origin {
			continue
		}
		if at, ok := checkpoint.CosignedAt(s); ok {
			fmt.Printf("witness  %s cosigned at %s\n", s.Name, at.Format(time.RFC3339))
		} else {
			fmt.Printf("witness  %s signed\n", s.Name)
		}
		cosigned++
	}
	names := make([]string, 0, len(c.Note.UnverifiedSigs))
	for _, s := range c.Note.UnverifiedSigs {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("unknown  %s signed, but its key is not in the witness list; not counted\n", n)
	}
	switch {
	case len(ws) == 0:
		fmt.Println("result   log signature only; no witnesses are listed yet")
	case cosigned == 0:
		fmt.Printf("result   no cosignature from the %d listed witness(es)\n", len(ws))
	default:
		fmt.Printf("result   cosigned by %d of %d listed witness(es)\n", cosigned, len(ws))
	}
	return nil
}

func writeIfChanged(path string, b []byte) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		return false, nil
	}
	return true, os.WriteFile(path, b, 0o644)
}
