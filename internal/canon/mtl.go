package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// JCSToolsDigest computes the tool-set digest two other public observers of
// the MCP registry already compute -- HISTOR calls it the MTL/1 tool-set
// digest, CrawlCheck publishes it as jcs_v1.tools_sha256 -- so that a hash
// written by this project can be compared, byte for byte, with theirs.
//
// Our own SurfaceSHA256 stays what it is: it covers every member of every tool
// (title, annotations, icons included) and keeps numeric literals verbatim,
// which is the right change key for a log that must never miss an edit. This
// digest is narrower on purpose. It covers only the "contract" of a tool, the
// part the model reads and the call accepts:
//
//	{name, description, inputSchema, outputSchema?}
//
// with description "" and inputSchema {} when absent or of the wrong type,
// outputSchema only when the server sent an object, contracts sorted by name
// in UTF-16 code units (equal names by canonical bytes), the whole list as one
// RFC 8785 canonical JSON array, SHA-256, written as an SRI string.
//
// RFC 8785 writes numbers the way ECMAScript does (1.0 becomes 1), so this
// digest cannot share the verbatim-literal writer used for SurfaceSHA256.
// A tool with no string name, or a number that has no IEEE 754 double
// (1e400), makes the list not digestible: the result is "" with a reason,
// never a guess.
//
// Test vectors are CrawlCheck's published ones, in mtl_test.go.
func JCSToolsDigest(tools []json.RawMessage) (digest, reason string, err error) {
	type entry struct {
		name  string
		canon []byte
	}
	entries := make([]entry, 0, len(tools))
	for i, raw := range tools {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return "", "", fmt.Errorf("tool %d: %w", i, err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return "", "tool is not an object", nil
		}
		name, ok := m["name"].(string)
		if !ok {
			return "", "entry with no name", nil
		}
		contract := map[string]any{"name": name, "description": "", "inputSchema": map[string]any{}}
		if d, ok := m["description"].(string); ok {
			contract["description"] = d
		}
		if s, ok := m["inputSchema"].(map[string]any); ok {
			contract["inputSchema"] = s
		}
		if o, ok := m["outputSchema"].(map[string]any); ok {
			contract["outputSchema"] = o
		}
		var buf bytes.Buffer
		if err := writeJCS(&buf, contract); err != nil {
			var nd *noDoubleError
			if errors.As(err, &nd) {
				return "", "number with no double: " + nd.literal, nil
			}
			return "", "", err
		}
		entries = append(entries, entry{name: name, canon: buf.Bytes()})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].name != entries[j].name {
			return utf16Keys{entries[i].name, entries[j].name}.Less(0, 1)
		}
		return bytes.Compare(entries[i].canon, entries[j].canon) < 0
	})

	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, e := range entries {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(e.canon)
	}
	buf.WriteByte(']')
	sum := sha256.Sum256(buf.Bytes())
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:]), "", nil
}

type noDoubleError struct{ literal string }

func (e *noDoubleError) Error() string { return "number has no double: " + e.literal }

// writeJCS is RFC 8785 proper: like write, but numbers go through float64 and
// come out the way ECMAScript's Number.prototype.toString writes them, and a
// NUL in a string becomes U+FFFD (CrawlCheck's rule; HISTOR's digests agree
// on every list we have compared).
func writeJCS(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(t.String(), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return &noDoubleError{t.String()}
		}
		buf.WriteString(es6Number(f))
	case string:
		return writeString(buf, strings.ReplaceAll(t, "\x00", "�"))
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCS(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Sort(utf16Keys(keys))
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeJCS(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return write(buf, v) // nil, bool
	}
	return nil
}

// es6Number formats a finite float64 as ECMAScript Number::toString does,
// which is what RFC 8785 section 3.2.2.3 requires. The shortest digit string
// that round-trips comes from strconv; the layout rules (plain up to 1e21,
// decimals down to 1e-6, exponent form beyond) are ECMA-262's.
func es6Number(f float64) string {
	if f == 0 {
		return "0"
	}
	neg := f < 0
	if neg {
		f = -f
	}
	mant, expStr, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	if len(digits) > 1 {
		digits = strings.TrimRight(digits, "0")
	}
	k, n := len(digits), exp+1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		e, sign := n-1, "+"
		if e < 0 {
			e, sign = -e, "-"
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(e)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(e)
		}
	}
	if neg {
		return "-" + out
	}
	return out
}
