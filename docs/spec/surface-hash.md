# surface_sha256: the tool-surface hash of the MCP Transparency Log

Status: stable since the first census, 2026-08-27. Every `surface_sha256` in
the log, every `mcp.lock`, and every history page is this function of the
server's `tools/list` result. Changing it would make three months of
published hashes irreproducible from this document, so it does not change;
a different canonicalisation gets a different name.

Reference implementation: [`internal/canon/canon.go`](../../internal/canon/canon.go)
and [`surface.go`](../../internal/canon/surface.go). Test vectors below are
asserted by [`internal/canon/surface_vectors_test.go`](../../internal/canon/surface_vectors_test.go).

## What it covers

Every member of every tool object the server returned, across every page of
`tools/list`: `name`, `title`, `description`, `inputSchema`, `outputSchema`,
`annotations`, `icons`, `_meta`, vendor extensions, anything. The hash is a
change key for a log that must never miss an edit, so nothing is excluded.
(The narrower jcs-v1 digest, which covers only `name`, `description`,
`inputSchema` and `outputSchema`, is published beside it for comparison with
other observers; it is defined by RFC 8785 and is not this document.)

## Algorithm

1. **Collect** the `tools` arrays of all pages, in page order, following
   `nextCursor` until it is absent. A list whose pages could not all be read
   is not hashed; the observation records the failure instead.
2. **Canonicalise each tool object** as follows:
   - Object members sorted by key, comparing keys as sequences of UTF-16 code
     units (not bytes, not code points). This is RFC 8785 section 3.2.3.
   - No insignificant whitespace.
   - Arrays keep their order.
   - **Numbers are emitted as the literal the server sent**, byte for byte:
     `1.0` stays `1.0`, `1e400` stays `1e400`, a 20-digit integer stays
     itself. This is the one deliberate departure from RFC 8785, which routes
     numbers through IEEE 754 doubles: a schema is evidence, and evidence is
     not rounded.
   - Strings are escaped per RFC 8785 section 3.2.2.2: `"`, `\`, and the
     control characters U+0000 to U+001F only, with the short forms `\b \f \n
     \r \t` where they exist and `\u00XX` (lower-case hex) otherwise. Nothing
     else is escaped; `<`, `>`, `&` and non-ASCII are written as themselves,
     in UTF-8.
   - `true`, `false`, `null` as themselves.
3. **Sort the canonical tool objects** by `name` (a tool without a string
   `name` sorts as the empty string), comparing names as UTF-16 code units;
   equal names are ordered by their canonical bytes, so duplicates still
   yield one order.
4. **Concatenate** them as one JSON array: `[` + canonical objects joined by
   `,` + `]`, no whitespace.
5. **SHA-256** of those bytes, written as 64 lower-case hex characters.

The tool names in sorted order are published beside the hash as
`tool_names`; the raw response bytes are archived separately under their own
SHA-256 (`body_sha256`), which is the provenance claim. Collapsing the two
would make the record either noisy or unprovable.

## Test vectors

### Empty list

Input: no tools. Canonical bytes: `[]`.

```
surface_sha256 = 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945
```

### One tool, with members outside the jcs-v1 contract

Input (whitespace and key order as a server might send them):

```json
[{"name": "read_file", "title": "Read file", "description": "Read a file from disk.",
  "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
  "annotations": {"readOnlyHint": true}}]
```

Canonical bytes:

```
[{"annotations":{"readOnlyHint":true},"description":"Read a file from disk.","inputSchema":{"properties":{"path":{"type":"string"}},"required":["path"],"type":"object"},"name":"read_file","title":"Read file"}]
```

```
surface_sha256 = e29fa88df23d924f560048fa68b071156e3386d5b047deaf94af55dc9ef0c757
```

Note that `title` and `annotations` are inside the hash. The same input's
jcs-v1 digest, `sha256-pUO5TdOtj4yR/mh2VDcu4y6axwVix4xgwST6cFkdd3g=`, does
not cover them; a server that edits only its annotation hints moves this hash
and not that one.

### Two tools served out of order, with a fractional literal

Input:

```json
[{"name":"b","description":"second","inputSchema":{"type":"object","properties":{"n":{"type":"number","maximum":1.0}}}},
 {"name":"a","description":"first","inputSchema":{"type":"object"}}]
```

Canonical bytes (sorted by name; `1.0` kept as sent):

```
[{"description":"first","inputSchema":{"type":"object"},"name":"a"},{"description":"second","inputSchema":{"properties":{"n":{"maximum":1.0,"type":"number"}},"type":"object"},"name":"b"}]
```

```
surface_sha256 = 435ed6659b58d59d5506dbf8785244700b352424da1591f8db89697280d6c4a1
```

Under RFC 8785 the literal would be written `1` and the bytes would differ.
That is the point of the departure: two servers sending `1` and `1.0` are
sending different bytes, and this log records that they did.

## Checking a live server against the log

```bash
go install github.com/yassinht/mcp-transparency-log/cmd/mcpobs@latest
mcpobs lock https://tandem.ac/mcp      # prints surface_sha256 and the jcs-v1 digest
```

Compare the printed hash with the one on the server's history page
(`https://yassinht.github.io/mcp-transparency-log/server.html?e=<endpoint>`).
Equal means the server is serving tonight what the log recorded; different
means the log will record the difference at the next census, and so will
anyone else who runs the command.

## Implementing it elsewhere

Any JCS (RFC 8785) implementation gets within one rule of this hash: replace
its number formatting with "emit the source literal unchanged" and it matches.
An implementation is correct when it reproduces the three vectors above; an
implementation that matches the first two and not the third is writing
numbers through a double.
