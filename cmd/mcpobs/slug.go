package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"path/filepath"
)

// slugOf names a server's static files. It is a pure function of the
// endpoint URL so that anyone -- the site's JavaScript, the Action's issue
// text, a reader with sha256sum -- can find a server's page from its URL
// without an index: sixteen hex characters of SHA-256 over the endpoint.
//
// Registry names were the obvious alternative and were rejected: they are
// not unique per endpoint (one name can declare several remotes, and two
// names can point at one remote), and they can be renamed. An endpoint is
// what the crawler actually connected to.
func slugOf(endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:8])
}

// shardPath spreads tens of thousands of files over 256 directories. Git
// does not care, but file systems and directory listings do.
func shardPath(dir, slug, suffix string) string {
	return filepath.Join(dir, slug[:2], slug+suffix)
}

func urlQuery(s string) string { return url.QueryEscape(s) }
