// Command blobpack converts plain blobs written before 2026-11-18 into the
// gzip form the store now writes, in place, one file at a time.
//
// It is a separate binary on purpose. mcpobs is the reader other people run
// and must never be able to change the archive; the crawler only appends.
// This is the one program allowed to rewrite a blob, and it is allowed only
// because it changes the encoding and not the bytes: for every file it
// re-reads what it wrote, decompresses it, and checks the SHA-256 against
// the file's own name before the plain copy is removed. A file that does not
// hash to its name is left exactly as it is and reported, never deleted.
//
//	blobpack --data /opt/mcp-observatory/data [--workers 2] [--limit N] [--dry-run]
//
// Safe to run while the crawler runs: the crawler writes only .gz files and
// reads either form; blobpack touches only plain files.
package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yassinht/mcp-transparency-log/pkg/canon"
)

func main() {
	dataDir := flag.String("data", "data", "observation directory")
	workers := flag.Int("workers", 2, "parallel compressors; keep low on a shared box")
	limit := flag.Int("limit", 0, "stop after this many files (0 = all)")
	dryRun := flag.Bool("dry-run", false, "count and measure, change nothing")
	flag.Parse()

	root := filepath.Join(*dataDir, "blobs")
	var (
		done, skipped, bad    atomic.Int64
		rawBytes, packedBytes atomic.Int64
		queue                 = make(chan string, 1024)
		wg                    sync.WaitGroup
		start                 = time.Now()
	)
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range queue {
				in, out, err := pack(path, *dryRun)
				switch {
				case err != nil:
					bad.Add(1)
					fmt.Fprintf(os.Stderr, "blobpack: %s: %v\n", path, err)
				default:
					rawBytes.Add(in)
					packedBytes.Add(out)
					if n := done.Add(1); n%20000 == 0 {
						fmt.Printf("%8d files  %6.0f MB -> %6.0f MB  %s\n", n,
							mb(rawBytes.Load()), mb(packedBytes.Load()), time.Since(start).Round(time.Second))
					}
				}
			}
		}()
	}

	var queued int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".gz") || strings.HasPrefix(name, ".tmp-") || len(name) != 64 {
			skipped.Add(1)
			return nil
		}
		queue <- path
		queued++
		if *limit > 0 && queued >= *limit {
			return fs.SkipAll
		}
		return nil
	})
	close(queue)
	wg.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "blobpack: walk: %v\n", err)
	}

	verb := "packed"
	if *dryRun {
		verb = "would pack"
	}
	fmt.Printf("\n%s %d files: %.0f MB -> %.0f MB (%.1fx) in %s; %d skipped (already .gz or not a blob), %d left untouched because of an error\n",
		verb, done.Load(), mb(rawBytes.Load()), mb(packedBytes.Load()),
		ratio(rawBytes.Load(), packedBytes.Load()), time.Since(start).Round(time.Second), skipped.Load(), bad.Load())
	if bad.Load() > 0 {
		os.Exit(1)
	}
}

// pack compresses one plain blob to <path>.gz and removes the plain file once
// the compressed copy has been read back and verified against the address.
func pack(path string, dryRun bool) (in, out int64, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	sum := filepath.Base(path)
	if canon.SHA256Hex(raw) != sum {
		return 0, 0, fmt.Errorf("content does not hash to its address; left as is")
	}
	in = int64(len(raw))
	if dryRun {
		var cw countWriter
		zw := gzip.NewWriter(&cw)
		zw.Write(raw)
		zw.Close()
		return in, cw.n, nil
	}

	dir := filepath.Dir(path)
	final := path + ".gz"
	if _, serr := os.Stat(final); serr == nil {
		// Already converted by an earlier run that died before removing the
		// plain file. Verify the existing .gz, then finish the job.
		if verr := verifyGz(final, sum); verr != nil {
			return 0, 0, fmt.Errorf("existing .gz is bad (%v); plain kept", verr)
		}
		st, _ := os.Stat(final)
		return in, st.Size(), os.Remove(path)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-pack-*")
	if err != nil {
		return 0, 0, err
	}
	zw := gzip.NewWriter(tmp)
	if _, err := zw.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return 0, 0, err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return 0, 0, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return 0, 0, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return 0, 0, err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		os.Remove(tmp.Name())
		return 0, 0, err
	}
	if err := verifyGz(final, sum); err != nil {
		os.Remove(final)
		return 0, 0, fmt.Errorf("verification failed (%v); plain kept, .gz removed", err)
	}
	st, err := os.Stat(final)
	if err != nil {
		return 0, 0, err
	}
	return in, st.Size(), os.Remove(path)
}

func verifyGz(path, sum string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer zr.Close()
	b, err := io.ReadAll(zr)
	if err != nil {
		return err
	}
	if canon.SHA256Hex(b) != sum {
		return fmt.Errorf("decompressed bytes hash to %s, not %s", canon.SHA256Hex(b)[:12], sum[:12])
	}
	return nil
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func mb(n int64) float64 { return float64(n) / (1 << 20) }

func ratio(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
