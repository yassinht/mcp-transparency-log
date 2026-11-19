package lock

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Credentials for servers that need them come from the environment and go
// nowhere else: not into mcp.lock, not into the check report, not into an
// issue. The lockfile records only where to look ("auth": "env:NAME"), which
// is what a reviewer needs and nothing an attacker could use. In GitHub
// Actions the variable is set from a repository secret on the step that runs
// the Action, so the value is masked in logs as well.
//
//	MCPOBS_HEADER_SALESFORCE="Authorization: Bearer ..."   one header per line
//	mcpobs lock salesforce=https://mcp.salesforce.example/mcp

const HeaderEnvPrefix = "MCPOBS_HEADER_"

// EnvKeyFor names the variable for a lock entry: the entry's name, or the
// endpoint's host when it has none, upper-cased with every run of characters
// outside A-Z and 0-9 folded to one underscore.
func EnvKeyFor(name, endpoint string) string {
	base := name
	if base == "" {
		if u, err := url.Parse(endpoint); err == nil {
			base = u.Hostname()
		}
	}
	var b strings.Builder
	last := '_'
	for _, r := range strings.ToUpper(base) {
		switch {
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			last = r
		case last != '_':
			b.WriteByte('_')
			last = '_'
		}
	}
	return HeaderEnvPrefix + strings.Trim(b.String(), "_")
}

// HeadersFor reads the entry's variable. The key is returned even when the
// variable is unset so a caller can name it in a message without ever
// printing a value.
func HeadersFor(name, endpoint string) (http.Header, string, error) {
	key := EnvKeyFor(name, endpoint)
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, key, nil
	}
	h, err := ParseHeaderLines(raw)
	if err != nil {
		return nil, key, fmt.Errorf("%s: %w", key, err)
	}
	return h, key, nil
}

// EnvCredentials is the Credentials function the CLI and the Action use.
func EnvCredentials(e Entry) (http.Header, string, error) {
	return HeadersFor(e.Name, e.Endpoint)
}

// ParseHeaderLines accepts "Name: value" lines; blank lines are ignored. The
// error never quotes the input, because the input is a secret.
func ParseHeaderLines(raw string) (http.Header, error) {
	h := http.Header{}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("expected one \"Header-Name: value\" per line")
		}
		h.Add(k, v)
	}
	return h, nil
}

// AuthRef is what the lockfile records when headers were used.
func AuthRef(key string, h http.Header) string {
	if len(h) == 0 {
		return ""
	}
	return "env:" + key
}
