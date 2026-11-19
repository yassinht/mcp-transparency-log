package canon

import (
	"encoding/json"
	"testing"
)

// The vectors published in docs/spec/surface-hash.md. If this test changes,
// the specification changes, and every hash in the log before the change
// stops being reproducible from the document: do not edit casually.
func TestSurfaceHashVectors(t *testing.T) {
	cases := []struct {
		name  string
		tools []json.RawMessage
		want  string
	}{
		{"empty list", nil, "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"},
		{"one tool with extras", []json.RawMessage{json.RawMessage(`{"name": "read_file", "title": "Read file", "description": "Read a file from disk.",
  "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
  "annotations": {"readOnlyHint": true}}`)}, "e29fa88df23d924f560048fa68b071156e3386d5b047deaf94af55dc9ef0c757"},
		{"two tools, served out of order, literal numbers kept", []json.RawMessage{
			json.RawMessage(`{"name":"b","description":"second","inputSchema":{"type":"object","properties":{"n":{"type":"number","maximum":1.0}}}}`),
			json.RawMessage(`{"name":"a","description":"first","inputSchema":{"type":"object"}}`),
		}, "435ed6659b58d59d5506dbf8785244700b352424da1591f8db89697280d6c4a1"},
	}
	for _, c := range cases {
		s, err := SurfaceOf([][]json.RawMessage{c.tools})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		t.Logf("%-55s %s", c.name, s.SurfaceSHA256)
		for _, tool := range s.Tools {
			t.Logf("    canonical: %s", tool)
		}
		if c.want != "" && s.SurfaceSHA256 != c.want {
			t.Errorf("%s: got %s, want %s", c.name, s.SurfaceSHA256, c.want)
		}
	}
}
