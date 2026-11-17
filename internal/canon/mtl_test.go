package canon

import (
	"encoding/json"
	"testing"
)

// Vectors published by CrawlCheck at https://crawlcheck.io/spec/mcp-lockfile
// (checked 2026-11-17). HISTOR reports equal digests for the same lists, so
// matching these means matching both.
func TestJCSToolsDigestVectors(t *testing.T) {
	d, reason, err := JCSToolsDigest(nil)
	if err != nil || reason != "" {
		t.Fatalf("empty list: %v %q", err, reason)
	}
	if want := "sha256-T1PNoYwrqgwDVLtfmj7L5e0Sq02OEbqHPC8RFhICuUU="; d != want {
		t.Fatalf("empty list digest %s, want %s", d, want)
	}

	one := json.RawMessage(`{"name": "read_file", "title": "Read file", "description": "Read a file from disk.",
  "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
  "annotations": {"readOnlyHint": true}}`)
	d, reason, err = JCSToolsDigest([]json.RawMessage{one})
	if err != nil || reason != "" {
		t.Fatalf("one tool: %v %q", err, reason)
	}
	if want := "sha256-pUO5TdOtj4yR/mh2VDcu4y6axwVix4xgwST6cFkdd3g="; d != want {
		t.Fatalf("one-tool digest %s, want %s", d, want)
	}
}

func TestJCSToolsDigestOrderAndExtrasDoNotMatter(t *testing.T) {
	a := json.RawMessage(`{"name":"b","description":"x","inputSchema":{"type":"object"}}`)
	b := json.RawMessage(`{"name":"a","inputSchema":{"type":"object"},"description":"y","title":"ignored","annotations":{"readOnlyHint":true}}`)
	b2 := json.RawMessage(`{"description":"y","name":"a","inputSchema":{"type":"object"}}`)
	d1, _, _ := JCSToolsDigest([]json.RawMessage{a, b})
	d2, _, _ := JCSToolsDigest([]json.RawMessage{b2, a})
	if d1 != d2 {
		t.Fatalf("digest depends on order or extras: %s vs %s", d1, d2)
	}
}

func TestJCSToolsDigestNotDigestible(t *testing.T) {
	_, reason, err := JCSToolsDigest([]json.RawMessage{json.RawMessage(`{"description":"no name"}`)})
	if err != nil || reason == "" {
		t.Fatalf("nameless tool should be undigestible: %v %q", err, reason)
	}
	_, reason, err = JCSToolsDigest([]json.RawMessage{json.RawMessage(`{"name":"t","inputSchema":{"maximum":1e400}}`)})
	if err != nil || reason == "" {
		t.Fatalf("1e400 should be undigestible: %v %q", err, reason)
	}
}

func TestES6Number(t *testing.T) {
	cases := map[float64]string{
		0: "0", 1: "1", -1: "-1", 1.5: "1.5", 0.5: "0.5", 100: "100", 1e21: "1e+21",
		123456789012345680000: "123456789012345680000", 0.000001: "0.000001", 1e-7: "1e-7",
		1.25e-7: "1.25e-7", 2.5e22: "2.5e+22", 3.14159: "3.14159",
	}
	for f, want := range cases {
		if got := es6Number(f); got != want {
			t.Errorf("es6Number(%v) = %s, want %s", f, got, want)
		}
	}
}
