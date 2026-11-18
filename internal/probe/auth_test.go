package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeMCP is the smallest streamable-http MCP server that satisfies the
// probe: initialize, the initialized notification, and one page of tools.
// With a token it answers 401 to anything that does not carry it, which is
// what every authenticated server in the registry looks like from outside.
func fakeMCP(token, tools string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%q,"capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"0"}}}`,
				req.ID, req.Params.ProtocolVersion)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`, req.ID, tools)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

const twoTools = `[{"name":"a","description":"first","inputSchema":{"type":"object"}},{"name":"b","description":"second","inputSchema":{"type":"object"}}]`

func TestProbeWithoutCredentialsIsAuthRequired(t *testing.T) {
	srv := fakeMCP("s3cret", twoTools)
	defer srv.Close()
	p := New(DefaultConfig("test"))
	r := p.Probe(context.Background(), srv.URL, "")
	if r.Outcome != OutcomeAuth {
		t.Fatalf("outcome %s (%s), want %s", r.Outcome, r.FailReason, OutcomeAuth)
	}
}

func TestProbeWithConfiguredHeadersEnumerates(t *testing.T) {
	srv := fakeMCP("s3cret", twoTools)
	defer srv.Close()
	cfg := DefaultConfig("test")
	cfg.Headers = http.Header{"Authorization": {"Bearer s3cret"}}
	r := New(cfg).Probe(context.Background(), srv.URL, "")
	if r.Outcome != OutcomeOK {
		t.Fatalf("outcome %s (%s), want ok", r.Outcome, r.FailReason)
	}
	if len(r.ToolPages) != 1 || len(r.ToolPages[0]) != 2 {
		t.Fatalf("tool pages %d, tools %v", len(r.ToolPages), r.ToolPages)
	}
	if r.Transport != "streamable-http" {
		t.Fatalf("transport %s", r.Transport)
	}
}

func TestExtraHeadersCannotOverrideProtocolHeaders(t *testing.T) {
	var seenAccept, seenCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAccept, seenCT = r.Header.Get("Accept"), r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	cfg := DefaultConfig("test")
	cfg.Headers = http.Header{"Accept": {"text/plain"}, "Content-Type": {"text/plain"}, "X-Team": {"blue"}}
	New(cfg).Probe(context.Background(), srv.URL, "")
	if seenAccept != "application/json, text/event-stream" || seenCT != "application/json" {
		t.Fatalf("protocol headers were overridden: Accept=%q Content-Type=%q", seenAccept, seenCT)
	}
}
