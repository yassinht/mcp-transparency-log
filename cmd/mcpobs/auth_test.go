package main

import "testing"

func TestEnvKeyFor(t *testing.T) {
	cases := []struct{ name, endpoint, want string }{
		{"context7", "https://mcp.context7.com/mcp", "MCPOBS_HEADER_CONTEXT7"},
		{"Salesforce Prod", "https://x", "MCPOBS_HEADER_SALESFORCE_PROD"},
		{"", "https://mcp.example.com/v1/mcp", "MCPOBS_HEADER_MCP_EXAMPLE_COM"},
		{"a--b__c", "https://x", "MCPOBS_HEADER_A_B_C"},
	}
	for _, c := range cases {
		if got := envKeyFor(c.name, c.endpoint); got != c.want {
			t.Errorf("envKeyFor(%q, %q) = %s, want %s", c.name, c.endpoint, got, c.want)
		}
	}
}

func TestHeadersForReadsMultilineAndNeverLeaks(t *testing.T) {
	t.Setenv("MCPOBS_HEADER_VENDOR", "Authorization: Bearer top-secret-token\n\nX-Org: acme\r\n")
	h, key, err := headersFor("vendor", "https://x")
	if err != nil || key != "MCPOBS_HEADER_VENDOR" {
		t.Fatalf("err %v key %s", err, key)
	}
	if h.Get("Authorization") != "Bearer top-secret-token" || h.Get("X-Org") != "acme" {
		t.Fatalf("headers %v", h)
	}
	if ref := authRef(key, h); ref != "env:MCPOBS_HEADER_VENDOR" {
		t.Fatalf("authRef %s", ref)
	}

	t.Setenv("MCPOBS_HEADER_BAD", "no colon here, and a secret-looking value")
	_, _, err = headersFor("bad", "https://x")
	if err == nil {
		t.Fatal("malformed value accepted")
	}
	if got := err.Error(); len(got) > 0 && (contains(got, "secret") || contains(got, "colon here")) {
		t.Fatalf("error quotes the secret: %s", got)
	}

	h, key, err = headersFor("unset", "https://x")
	if err != nil || h != nil || key != "MCPOBS_HEADER_UNSET" {
		t.Fatalf("unset: %v %v %s", h, err, key)
	}
}

func contains(s, sub string) bool {
	return len(sub) <= len(s) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
