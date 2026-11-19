package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/yassinht/mcp-transparency-log/pkg/evidence"
	"github.com/yassinht/mcp-transparency-log/pkg/mlog"
	"github.com/yassinht/mcp-transparency-log/pkg/pack"
)

// cmdEvidence is the operator side: it needs the archive. The output is the
// file a customer or auditor receives, and verify-evidence is what they run.
func cmdEvidence(dataDir, logDir, headsDir, endpoint, from, to, out string) error {
	if endpoint == "" {
		return fmt.Errorf("usage: mcpobs [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--out file] evidence <endpoint>")
	}
	fmt.Fprintf(os.Stderr, "collecting observations of %s ...\n", endpoint)
	b, err := evidence.Build(evidence.BuildOptions{DataDir: dataDir, LogDir: logDir, HeadsDir: headsDir, Endpoint: endpoint, From: from, To: to})
	if err != nil {
		return err
	}
	if out == "" {
		out = fmt.Sprintf("evidence-%s-%s-%s.json", b.Subject.Slug, b.Range.From, b.Range.To)
	}
	raw, err := json.MarshalIndent(b, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s\n", out)
	fmt.Printf("  server       %s\n  endpoint     %s\n", b.Subject.ServerName, b.Subject.Endpoint)
	fmt.Printf("  nights       %d  (%s → %s)\n", b.Range.Nights, b.Range.From, b.Range.To)
	fmt.Printf("  observations %d, each with an inclusion proof against %s\n", len(b.Observations), b.Log.HeadFile)
	fmt.Printf("  versions     %d distinct tool surfaces, %d changes\n", len(b.Versions), len(b.Changes))
	for _, c := range b.Changes {
		fmt.Printf("    %s  +%d −%d edited %d\n", c.At[:10], len(c.Added), len(c.Removed), len(c.Edited))
	}
	fmt.Printf("  size         %d KB\n\n", len(raw)/1024)
	fmt.Printf("verify with:  mcpobs --heads %s --pubkey %s/key.pub verify-evidence %s\n", headsDir, headsDir, out)
	for _, n := range b.Notes[4:] {
		fmt.Printf("note: %s\n", n)
	}
	return nil
}

// cmdVerifyEvidence is what the recipient runs. It needs the bundle and, to
// get the strongest result, a clone of the public repository for the heads
// and the key; without one it falls back to the key pinned in this build.
func cmdVerifyEvidence(path, pubPath, headsDir, servicePub string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Two shapes share the command: a log bundle (inclusion proofs) and a CI
	// check file (text and hashes). The format field says which.
	var peek struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		return fmt.Errorf("%s: not an evidence file: %w", path, err)
	}
	if peek.Format == evidence.CheckFormat {
		return verifyCheckFile(raw, pubPath, headsDir)
	}
	if peek.Format == pack.Format {
		return verifyPackFile(raw, pubPath, servicePub)
	}
	var b evidence.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("%s: not an evidence bundle: %w", path, err)
	}

	opt := evidence.Options{}
	if pub, kerr := mlog.LoadPublicKey(pubPath); kerr == nil {
		opt.TrustedKey = pub
		fmt.Printf("trusting the key in %s\n", pubPath)
	} else {
		fmt.Printf("trusting the key pinned in this build (%s not readable)\n", pubPath)
	}
	if heads, herr := evidence.LoadPublishedHeads(headsDir); herr == nil && len(heads) > 0 {
		opt.PublishedHeads = heads
		fmt.Printf("checking the head against %d published heads in %s\n", len(heads), headsDir)
	} else {
		fmt.Printf("no published heads at %s; the head is checked by signature only\n", headsDir)
	}
	fmt.Println()

	rep := evidence.Verify(&b, opt)
	okByName := map[string]int{}
	var order []string
	for _, c := range rep.Checks {
		if c.OK {
			if _, seen := okByName[c.Name]; !seen {
				order = append(order, c.Name)
			}
			okByName[c.Name]++
			continue
		}
		fmt.Printf("  FAIL  %-15s %s  %s\n", c.Name, c.Ref, c.Detail)
	}
	for _, name := range order {
		n := okByName[name]
		if n == 1 {
			fmt.Printf("  ok    %s\n", name)
		} else {
			fmt.Printf("  ok    %-15s %d checks\n", name, n)
		}
	}
	fmt.Println()
	if !rep.OK() {
		return fmt.Errorf("FAILED  %d check(s) did not pass; do not rely on this bundle", rep.Failed)
	}
	fmt.Printf("VERIFIED  %d observations of %s over %d nights (%s → %s), %d tool surfaces, %d changes, head %s\n",
		rep.Verified, b.Subject.Endpoint, b.Range.Nights, b.Range.From, b.Range.To, len(b.Versions), len(b.Changes), strings.TrimSuffix(b.Log.HeadFile, ".txt"))
	return nil
}

// verifyCheckFile handles the CI evidence shape. It is honest about what it
// proves: that the text in the file is the text the hashes were computed over.
func verifyCheckFile(raw []byte, pubPath, headsDir string) error {
	var ce evidence.CheckEvidence
	if err := json.Unmarshal(raw, &ce); err != nil {
		return err
	}
	opt := evidence.Options{}
	if pub, kerr := mlog.LoadPublicKey(pubPath); kerr == nil {
		opt.TrustedKey = pub
	}
	if heads, herr := evidence.LoadPublishedHeads(headsDir); herr == nil && len(heads) > 0 {
		opt.PublishedHeads = heads
	}
	fmt.Printf("CI check evidence from %s, lock %s (%d servers)\n\n", ce.CheckedAt, ce.Lock.Path, len(ce.Servers))
	rep := evidence.VerifyCheck(&ce, opt)
	for _, c := range rep.Checks {
		mark := "ok  "
		if !c.OK {
			mark = "FAIL"
		}
		fmt.Printf("  %s  %-13s %s  %s\n", mark, c.Name, c.Ref, c.Detail)
	}
	fmt.Println()
	if !rep.OK() {
		return fmt.Errorf("FAILED  %d check(s) did not pass; the text in this file is not what its hashes say", rep.Failed)
	}
	fmt.Printf("VERIFIED  the recorded text matches every hash; %d changed server(s) with their diff. This file is the CI runner's own record, not an observation of the public log.\n", rep.Verified)
	return nil
}

// verifyPackFile handles a hosted service's evidence pack. The service key
// is pinned with --service-pubkey; without it the key named in the pack is
// used and printed, for the reader to compare with the key the service
// publishes.
func verifyPackFile(raw []byte, pubPath, servicePub string) error {
	var p pack.Pack
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	opt := pack.Options{}
	if servicePub != "" {
		k, err := mlog.LoadPublicKey(servicePub)
		if err != nil {
			return fmt.Errorf("service key: %w", err)
		}
		opt.TrustedKey = k
		fmt.Printf("trusting the service key in %s\n", servicePub)
	} else {
		fmt.Printf("no --service-pubkey: the key named in the pack is used and shown below\n")
	}
	if k, err := mlog.LoadPublicKey(pubPath); err == nil {
		opt.OperatorKey = k
	}
	fmt.Printf("evidence pack for %s (%s), %s to %s, %d checks, generated %s by %s\n\n",
		p.Server.Name, p.Server.Endpoint, p.Range.From, p.Range.To, p.Range.Checks, p.GeneratedAt, p.GeneratedBy)
	rep := pack.Verify(&p, opt)
	okByName := map[string]int{}
	var order []string
	for _, c := range rep.Checks {
		if c.OK {
			if _, seen := okByName[c.Name]; !seen {
				order = append(order, c.Name)
			}
			okByName[c.Name]++
			if c.Name == "signature" {
				fmt.Printf("  ok    %-15s %s\n", c.Name, c.Detail)
			}
			continue
		}
		fmt.Printf("  FAIL  %-15s %s  %s\n", c.Name, c.Ref, c.Detail)
	}
	for _, name := range order {
		if name == "signature" {
			continue
		}
		fmt.Printf("  ok    %-15s %d checks\n", name, okByName[name])
	}
	fmt.Println()
	if !rep.OK() {
		return fmt.Errorf("FAILED  %d check(s) did not pass; do not rely on this pack", rep.Failed)
	}
	fmt.Printf("VERIFIED  %d checks of %s with %d versions and %d decisions; every hash, diff and grade recomputed from the text\n",
		rep.Verified, p.Server.Endpoint, len(p.Versions), len(p.Decisions))
	return nil
}
