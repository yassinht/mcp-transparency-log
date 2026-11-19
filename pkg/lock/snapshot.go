package lock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/yassinht/mcp-transparency-log/pkg/evidence"
	"github.com/yassinht/mcp-transparency-log/pkg/mlog"
)

// A lockfile pins a hash; a snapshot keeps the text the hash was computed
// over. Without it, "the description changed" is all a check can say. With
// it, the check can show the sentence, and the pull request that accepts a
// change carries the exact diff of the tool text for review, the way a
// dependency bump carries a changelog.
//
// Snapshots live beside the lockfile in <lock>.d/, one file per server,
// indented so that git diffs of them read as text. They are derived from the
// lock and can be regenerated with `mcpobs lock`; a missing or stale snapshot
// is reported, never guessed around.

type Snapshot struct {
	Endpoint string            `json:"endpoint"`
	LockedAt string            `json:"locked_at"`
	Surface  string            `json:"surface_sha256"`
	ToolsSRI string            `json:"jcs_v1_tools_sha256,omitempty"`
	Tools    []json.RawMessage `json:"tools"`
}

func SnapshotDir(lockPath string) string { return lockPath + ".d" }

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Slug is the same sixteen hex characters the site uses to name a server's
// files: SHA-256 over the endpoint.
func Slug(endpoint string) string { return evidence.Slug(endpoint) }

// SnapshotFile names a server's snapshot: the entry name when it has one,
// otherwise the slug of the endpoint.
func SnapshotFile(lockPath string, e Entry) string {
	key := unsafeName.ReplaceAllString(e.Name, "-")
	if key == "" || key == "-" {
		key = Slug(e.Endpoint)
	}
	return filepath.Join(SnapshotDir(lockPath), key+".json")
}

func WriteSnapshot(lockPath string, e Entry, tools []json.RawMessage) (string, error) {
	if tools == nil {
		tools = []json.RawMessage{}
	}
	p := SnapshotFile(lockPath, e)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(Snapshot{Endpoint: e.Endpoint, LockedAt: e.LockedAt, Surface: e.Surface, ToolsSRI: e.ToolsSRI, Tools: tools}, "", "  ")
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(p), os.WriteFile(p, append(b, '\n'), 0o644)
}

// ReadSnapshot returns the snapshot for an entry if one exists and matches
// the locked surface. A snapshot whose hash differs from the lock is stale
// (someone edited one without the other) and is refused with a reason.
func ReadSnapshot(lockPath string, e Entry) (*Snapshot, string, error) {
	p := SnapshotFile(lockPath, e)
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", fmt.Errorf("no snapshot at %s: locked before snapshots existed; re-run `mcpobs lock` to record the text", filepath.ToSlash(p))
		}
		return nil, "", err
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, "", fmt.Errorf("%s: %w", filepath.ToSlash(p), err)
	}
	if s.Surface != e.Surface || s.Endpoint != e.Endpoint {
		return nil, "", fmt.Errorf("%s does not match the lockfile entry; re-run `mcpobs lock` for this server", filepath.ToSlash(p))
	}
	return &s, filepath.ToSlash(p), nil
}

// PublicHeadsBase is where the public log's signed heads are fetched from.
const PublicHeadsBase = "https://raw.githubusercontent.com/yassinht/mcp-transparency-log/main/heads/"

// FetchPublicHead gets the newest signed head of the public log, trying the
// last three dates. It is a freshness anchor for an evidence file and nothing
// more; failure to reach it is returned as a note, not an error, because a
// CI runner without egress to GitHub must still be able to check its servers.
func FetchPublicHead(ctx context.Context) (*evidence.PublicHead, string) {
	client := &http.Client{Timeout: 6 * time.Second}
	var lastErr string
	for back := 0; back < 3; back++ {
		name := time.Now().UTC().AddDate(0, 0, -back).Format("2006-01-02") + ".txt"
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, PublicHeadsBase+name, nil)
		req.Header.Set("User-Agent", UserAgent)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != 200 || rerr != nil {
			lastErr = fmt.Sprintf("%s: HTTP %d", name, resp.StatusCode)
			continue
		}
		if _, perr := mlog.ParseHead(body); perr != nil {
			lastErr = name + ": " + perr.Error()
			continue
		}
		return &evidence.PublicHead{HeadFile: name, Head: string(body), FetchedFrom: PublicHeadsBase + name}, ""
	}
	return nil, "public head not fetched: " + strings.TrimSpace(lastErr)
}
