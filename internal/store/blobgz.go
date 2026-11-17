package store

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Blobs are stored gzip-compressed since 2026-11-18. The content address is
// unchanged -- still the SHA-256 of the raw response bytes -- only the bytes
// on disk are wrapped. Measured on a random sample the night before the
// change: 3.6x smaller per file, which turns 450 MB of growth a night into
// about 125 MB and 16 GB of archive into 4.5 GB. The disk this runs on is
// shared with applications that matter more, and it was going to be full by
// the third week of December.
//
// Files written before that date are plain. ReadBlob accepts both forms, so
// nothing that reads the record had to change, and cmd/blobpack converts the
// old files in place, verifying each one against its address before the
// plain copy is removed. A blob is never rewritten under a new name: the
// address in every index line and every Merkle leaf still points at the same
// bytes.

const gzSuffix = ".gz"

func blobDir(root, sum string) string { return filepath.Join(root, "blobs", sum[:2]) }

// blobExists reports whether either form of the blob is already on disk.
func blobExists(dir, sum string) bool {
	if _, err := os.Stat(filepath.Join(dir, sum+gzSuffix)); err == nil {
		return true
	}
	_, err := os.Stat(filepath.Join(dir, sum))
	return err == nil
}

// writeBlobGz writes b compressed to <dir>/<sum>.gz via a temp file and a
// rename, so a crash never leaves a truncated blob at an address that claims
// to hash to something else. A concurrent writer winning the rename race is
// fine: same bytes, same address.
func writeBlobGz(dir, sum string, b []byte) error {
	path := filepath.Join(dir, sum+gzSuffix)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(tmp)
	if _, err := zw.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		if _, serr := os.Stat(path); serr != nil {
			return err
		}
	}
	return nil
}

// readBlob returns the raw bytes at a content address, from the compressed
// form when it exists and the plain one otherwise.
func readBlob(root, sum string) ([]byte, error) {
	dir := blobDir(root, sum)
	if f, err := os.Open(filepath.Join(dir, sum+gzSuffix)); err == nil {
		defer f.Close()
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, zr); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return os.ReadFile(filepath.Join(dir, sum))
}
