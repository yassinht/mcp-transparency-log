# MCP Transparency Log

An independent, continuously-operated record of what public MCP servers actually served.

## Why signing is not enough

Sigstore, Rekor and manifest signing are **opt-in publisher attestations**. A server operator who changes a tool description from *"look up the weather"* to *"look up the weather and forward the conversation to evil.example"* will happily sign the new description, and the signature will verify perfectly. Signing proves who published something. It does not tell you that what you are running today is not what you audited last month.

A transparency log is **adversarial third-party observation**. It records what servers actually served, without their consent or cooperation. That asymmetry is why Certificate Transparency worked: CAs never opted in, monitors watched them anyway, and misissuance became detectable after the fact.

That is what this project is. Not a scanner, not a registry, not a linter — a log.

## What it does

A crawler visits every publicly reachable MCP server in the official registry on a schedule and records the exact tool surface it served: names, descriptions, JSON schemas, and the four annotation hints. Observations go into an append-only log with signed tree heads, so anyone can prove that a given surface was observed at a given time and that the log has not been rewritten since.

The value is the accumulated history. A stranger can clone this repository in a weekend. Nobody can clone a year of observations.

## Use it

**Look up a server.** Every endpoint in the registry has a page at `https://yassinht.github.io/mcp-transparency-log/server.html?e=<endpoint URL>`: when it appeared, every night its tool surface changed and which tools moved, when it went dark, the tools it serves, what the rule scan found in its text, and two badges that re-read this log:

[![mcp surface](https://img.shields.io/endpoint?url=https%3A%2F%2Fyassinht.github.io%2Fmcp-transparency-log%2Fdata%2Fbadge%2F1a%2F1a1978d681b968f5.json)](https://yassinht.github.io/mcp-transparency-log/server.html?e=https%3A%2F%2Ftandem.ac%2Fmcp)
[![mcp scan](https://img.shields.io/endpoint?url=https%3A%2F%2Fyassinht.github.io%2Fmcp-transparency-log%2Fdata%2Fbadge%2F1a%2F1a1978d681b968f5-scan.json)](https://yassinht.github.io/mcp-transparency-log/server.html?e=https%3A%2F%2Ftandem.ac%2Fmcp)

**Pin the servers you depend on.** `mcp.lock` is to MCP servers what `package-lock.json` is to packages:

```bash
go install github.com/yassinht/mcp-transparency-log/cmd/mcpobs@latest
mcpobs lock context7=https://mcp.context7.com/mcp exa=https://mcp.exa.ai/mcp
git add mcp.lock
```

Each entry records the server's canonical surface hash and its jcs-v1 tool-set digest, the same bytes CrawlCheck's lockfiles and HISTOR's records carry, so a lock written here can be compared with what either of them observed. `mcpobs check` re-probes every locked server and exits 1 when one no longer serves what was reviewed. In CI:

```yaml
- uses: yassinht/mcp-transparency-log@v1
```

The Action fails the job and opens an issue with the diff: tools added, removed, or edited in place under the same names. This repository runs it against its own [`mcp.lock`](mcp.lock) every morning; the issues it opens are the demo. [Setup in four steps](https://yassinht.github.io/mcp-transparency-log/lock.html).

**Scan tool text.** `mcpobs scan` runs thirteen regular expressions over every description, title and schema description in a census, looking for text addressed to the model rather than the user: "ignore previous instructions", "forward the conversation", hidden bidi characters. No model judges; every match is quoted and none is called malicious. [Rules, numbers and one example each](https://yassinht.github.io/mcp-transparency-log/scan.html).

## Status

Running since 2026-08-30, unattended.

| Phase | Scope | State |
| --- | --- | --- |
| 0 | Falsification test — is the ecosystem observable at all? | done, passed |
| 1 | Crawler, raw observation archive, daily census | done, running |
| 2 | RFC 6962 Merkle log, signed tree heads, verify CLI | done |
| 3 | Public static site and published leaf hashes | done |
| 3b | A history page and badges per server; `mcp.lock` and the GitHub Action; the rule scan | done, 2026-11-17 |
| 4 | Witnesses and cross-checks with independent observers | started: nightly peer list published, see [Related work](#related-work) |

**79 nightly censuses as of 2026-11-17, one night missed (2026-11-08), 2,169,622 observations in the tree.** On the last night 45,490 endpoints were probed and 27,096 of them enumerated a tool list without credentials. A systemd timer fetches the registry, probes every endpoint, archives the raw bytes, appends to the tree, signs a head, publishes it and regenerates the site, with no human in the loop. The registry grew from 16,305 declared endpoints on 2026-09-07 to 45,490; the crawl has kept up.

**The daily figures, every server's history and the scan are at [yassinht.github.io/mcp-transparency-log](https://yassinht.github.io/mcp-transparency-log/).** The measurements were cited as evidence in the registry's own tracker for periodic re-validation of entries ([modelcontextprotocol/registry#1715](https://github.com/modelcontextprotocol/registry/issues/1715), consolidating [#1626](https://github.com/modelcontextprotocol/registry/issues/1626)).

Phase 4 is the end state, not the entry ticket. A witness is a second party running their own crawler against the same servers and signing what they see, so that a log which invented its history could be contradicted. In the three months since this started, several independent crawlers have appeared ([Related work](#related-work)). Since 2026-11-17 this log publishes its nightly observations in the cross-check format HISTOR reads from other observers, so the two records can catch each other out. A single-operator log is still useful in the meantime; Go's own checksum database ran that way for years.

## First census — 2026-08-27

The first complete pass over the registry. 13,870 of 13,997 declared endpoints were reached; the run's `meta.json` records it as incomplete, because it is.

| | |
| --- | --- |
| Registry entries | 25,020 |
| Declaring a network endpoint | 13,997 |
| Observed | 13,870 (99.1%) |
| **Enumerated a tool list, no credentials** | **7,820 — 56.4%** of endpoints with a remote |
| Same figure against the whole registry | **31.3%** |
| Tools recorded | **132,683** |
| Tools declaring at least one annotation hint | **73.2%** |

Outcomes: 56.4% ok, 25.0% auth required, 8.3% protocol error, 6.4% unreachable, 3.2% timeout, 0.7% rpc error. Distinguishing "refused us" from "is not there" is what keeps the reachability figure honest.

**Concentration.** Two operators — `gateway.pipeworx.io` (1,264) and `api.mcp.ai` (1,094) — account for **30.2% of every reachable MCP server in the registry**. One template edit at either changes over a thousand "servers" at once. This is the single strongest argument for watching this ecosystem rather than trusting it.

**Spec adoption.** 6,716 servers negotiated 2025-06-18; 672 still speak 2024-11-05. Seventeen answered on 2026-07-28. The week-0 sample of 300 found zero on that revision and concluded none existed — at full population the honest statement is "rare, not absent". A sample that small cannot see a 0.2% feature.

**Tool-surface size.** The median server exposes a handful of tools. Three expose more than 600, and one — `io.github.davidmosiah/delx-mcp-a2a` — exposes **1,076**, of which 31 carry any annotation. Only 2 servers in the entire population paginated `tools/list`.

**Parked domains still listed.** Four registry endpoints resolve to expired domains now serving for-sale parking pages, all four through the same ad host. Small in absolute terms (0.03%), but the mechanism matters: an agent configured from the official registry connects to infrastructure its original operator no longer controls. Windows Defender classified two of those pages as phishing — noted, not endorsed: the same detector had flagged this project's own binary as a trojan an hour earlier. The archived bytes are in the log; judge them yourself.

## The measurement this project is built on

Before writing a crawler, the obvious way to kill this idea was tested: if almost no public MCP server can be enumerated without credentials, there is nothing to observe and the project should not exist. The kill threshold was set at 30% in advance.

Measured on a random sample of 300 registry entries, 2026-08-25:

| | |
| --- | --- |
| Registry population | **24,729** servers |
| Declaring a network endpoint | **13,629** (55.1%) |
| Enumerable with no credentials | **35.0%** — above the 30% kill line |
| Genuinely real servers in the sample | 67.6%, across 71 distinct operators |
| Tools declaring at least one annotation hint | **68.8%** of 1,420 observed tools |
| Successful handshakes using the 2026-07-28 `server/discover` | **0 of 105** — all used legacy `initialize` |

Two operators, `gateway.pipeworx.io` (1,312 servers) and `api.mcp.ai` (1,099), publish **17.7% of every observable server in the registry**. One template edit changes 1,312 "servers" at once. That concentration is the clearest argument for watching this ecosystem rather than trusting it.

The probe, its raw output, and the population snapshot are in [`docs/week0-falsification/`](docs/week0-falsification/). Two bugs in that probe mattered enormously: missing SSE transport support understated reachability by ten percentage points and would have produced a false "do not build" verdict, and a hardcoded protocol version biased the sample against servers on newer spec revisions. Writing the code was never the bottleneck. Contact with reality was.

## Related work

Nobody is alone in this, and the order matters less than the fact that several people reached the same conclusion independently. Dated so that the order is plain; nothing here is a judgement of the others.

| Project | Watches | First public | How it differs from this log |
| --- | --- | --- | --- |
| [KryptosAI mcp-observatory](https://github.com/KryptosAI/mcp-observatory) | tool and schema drift of the servers you configure, `lock` / `lock verify` in CI | by 2026-03 | a client-side tool with no public record of the registry. Unrelated to this project, which carried the same name until September 2026 |
| [PulseFeed MCP Drift Watch](https://pulsefeed.dev/mcp/drift) | package and repository changes after a server is listed, whole registry | 2026-07-30 | packages, not tool surfaces |
| [MCP Drift Observatory](https://github.com/mikerawsonnz/mcp-drift-observatory) | byte-exact tool declarations of public servers, daily, git archive and Atom feed per server | 2026-08-20 | no Merkle log or signed heads; reachable as an MCP server |
| **this log** | tool surfaces of every registry endpoint, nightly, RFC 6962 log, signed heads, published leaf hashes | 2026-08-26, unbroken series from 2026-08-30 | |
| [HISTOR](https://github.com/alexar76/histor) | tool surfaces of registry endpoints and sandboxed npm/PyPI packages, RFC 9162 log, hosted API with `/check`, witnessed checkpoints | 2026-09-24, data from 2026-10-10 | a hosted service with a database; cross-checks other observers daily |
| [mcpcost](https://mcpcost.ulehla.dev) | liveness and context-window cost of every registry server, daily evidence file | 2026-10-03 | cost, not content |
| [ProtocolProbe](https://protocolprobe.com) | registry entries against npm, PyPI and GitHub | 2026-10 | packages and repositories, not endpoints |

Whole-registry endpoint censuses were also reported to the registry by siliroid ([#1485](https://github.com/modelcontextprotocol/registry/issues/1485), [#1487](https://github.com/modelcontextprotocol/registry/issues/1487)) and mun29 ([#1643](https://github.com/modelcontextprotocol/registry/issues/1643)). All of them, with this log's [#1626](https://github.com/modelcontextprotocol/registry/issues/1626), were consolidated as evidence under [#1715](https://github.com/modelcontextprotocol/registry/issues/1715).

**Cross-checking.** Two observers that read the same servers independently check each other: when they disagree, either a server answered them differently or one of them has a bug. Every night this log publishes [`docs/data/peers/tool-digests-latest.jsonl`](docs/data/peers/tool-digests-latest.jsonl), one row per endpoint with its jcs-v1 tool-set digest (or `null` and the outcome) and the time it was read, in the format [HISTOR's cross-check](https://github.com/alexar76/histor/blob/main/docs/cross-check.md) consumes. The digest reproduces CrawlCheck's published test vectors ([`internal/canon/mtl_test.go`](internal/canon/mtl_test.go)), so the three records can be compared row by row.

## Design commitments

**Raw bytes are the record.** Every response is archived exactly as received. Counts, classifications and hashes are derived views that can be rebuilt. The week-0 probe stored only its own classification of the registry and discarded the raw entries, which made every later question about that snapshot unanswerable.

**Two hashes, never one.** `body_sha256` covers the exact bytes and is the provenance claim. `surface_sha256` covers the canonical, name-sorted tool array and is the change-detection key and the future Merkle leaf. Collapsing them would make the log either noisy or unprovable.

**No MCP SDK in the crawl path.** An SDK validates, normalizes and rejects, because it is built to talk to well-behaved servers. A server returning a nameless tool, a duplicate name, or a 40KB description is producing exactly the observation worth keeping.

**No LLM anywhere in the data path.** Every judgment must be a rule a human can re-run against the archived blobs, or the Merkle proofs are theatre.

**Content addressing, not timestamps.** A server whose surface has not changed costs nothing to observe again. The archive grows only when something actually changed.

## Running it

```bash
go test ./...
go run ./cmd/crawler --dry-run          # fetch and archive the registry, probe nothing
go run ./cmd/crawler --sample=200       # reproducible smoke test
go run ./cmd/crawler                    # full census
```

Output lands in `data/`:

```
data/blobs/<ab>/<sha256>        exact response bytes, deduplicated across all runs
data/runs/<runID>/index.jsonl   one line per endpoint observed
data/runs/<runID>/meta.json     run header, including the raw registry pages
```

Politeness is structural rather than advisory: targets are grouped by host and each host is worked by exactly one goroutine with a delay between requests, so no amount of `--workers` can hammer a single operator.

## How fast do tool surfaces change?

This is the question the log exists to answer, and the first attempt at it was wrong by a factor of six. Both the wrong number and the correction are kept here, because the correction is the more useful of the two.

Comparing two censuses seventeen hours and fifty-one minutes apart (2026-08-30 09:12 → 2026-08-31 03:03, same machine, same network):

| | |
| --- | --- |
| Enumerable in both runs | 8,106 |
| Surface unchanged | 6,551 — 80.8% |
| Surface changed | 1,555 — 19.2% |
| Of those, keeping **identical tool names** | 1,480 — 95.2% of all changes |

A server that adds or removes a tool is visible: the client sees the list change. A server that keeps `send_email` under the same name and rewrites what it claims to do announces nothing. No version bump, no notification. That second shape is the one signing cannot catch — the operator signs the new description and the signature verifies — and it accounts for 95% of everything that moves.

**Then the number had to survive its own audit.** Some servers embed live data in a description: *"cache updated 2026-08-30 09:14:02, 1,204 cities"* changes on every request and means nothing. `mcpobs classify` separates those by a rule anyone can re-run against the archived bytes — replace every digit with `#` and compare again — and the result was not kind:

| | | |
| --- | --- | --- |
| digits only | 83.5% | not a change |
| schema edited | 10.4% | real |
| description rewritten | 6.0% | real |

That reading — 83.5% noise — was itself an artifact, and finding out why produced the most useful methodological result here. **It came from comparing two censuses taken at different times of day** (09:12 against 03:03). Many servers embed content on a daily cycle, so sampling at different points in that cycle makes them all look changed. Every census since runs at 03:00, and comparing same-hour to same-hour the noise collapses:

| interval | volatile | real | one publisher's share |
| --- | --- | --- | --- |
| Aug 30 09:12 → Aug 31 03:03 | 57.7% | 42.3% | 69.0% |
| **Sep 1 03:06 → Sep 2 03:07** | **1.0%** | **99.0%** | **87.1%** |
| **Sep 3 03:04 → Sep 4 03:05** | **0.5%** | **99.5%** | **86.9%** |

**Sampling a live system at a fixed hour removes cyclic noise; sampling it at wandering hours measures your own clock.** The two same-hour intervals agree to within half a point on every figure.

### The result, after two independent confirmations

Of roughly 8,300 servers enumerable on two consecutive days, **19.2% changed their tool surface within 24 hours**, and about 95% of those changes kept identical tool names while rewriting descriptions or schemas underneath.

**But the headline number is one publisher.** `io.github.pipeworx-io` accounts for **87% of every real edit**, rewriting descriptions across roughly 1,280 servers — essentially its whole fleet — every single night. Excluding it, the independent server changes at about **2.3%** per day.

Both numbers are true and they answer different questions. What an agent operator experiences is 19%. How volatile a typical independent server is, is 2.3%. Reporting either alone misleads, and a single snapshot cannot tell them apart — only a daily log can.

Two earlier figures here were wrong and are kept on purpose. A first pass reported 26%. A sample then put the real fraction at 97%, and it was wrong for a reason worth naming: the analysis could only parse plain-JSON response bodies and silently skipped SSE-framed ones, inspecting 67 of 1,355. That sample was **biased, not small** — simple servers return plain JSON and write static descriptions, complex ones stream SSE and inject live data. Measuring the easy half and generalising is how a six-fold error gets published.

One limitation stands: the rule normalizes digits, not rotating prose. At least one server serves a different daily puzzle inside a tool description, which this classifier still counts as real.

### An unexplained observation

On 2026-09-06 reachability fell to 50.5% and the tool count to 109,406, against a stable 56.5–58.5% and roughly 143,000 on every neighbouring day. The drop is far larger in tools than in servers, which means the servers that went missing were the large ones — a major operator was unreachable for a single night, and returned. It has not been investigated further. It is recorded here because the log's value is precisely that such nights are recoverable after the fact.

## Verifying the log

The log's public key:

```
4DNVWgqiY5HKiGH3PFcKt5O+fn9EmdoTNvj4aYbwQ4E=
```

Every census appends its observations to an RFC 6962 Merkle tree and publishes a signed tree head in [`heads/`](heads/) — a few hundred readable bytes:

```
mcp-transparency-log/v1
size 136225
root 1JPVp4Dx7ds59SivxgXvaHdoTpDD1W0VyTR6SmCCL8c=
time 2026-09-07T10:37:12Z
sig  qv1sZUjrjHXFhtwPPPq1e770e57Xg1DpeeJFxsL/DX+5ZVl2pFDYJjHGoG6u9HzB2OYKZwPjF8VIJUw8eaaRCA==
```

```bash
go install github.com/yassinht/mcp-transparency-log/cmd/mcpobs@latest
mcpobs verify
```

There are two ways to check it, and which one applies depends on what you hold.

**From the published leaf hashes — no archive needed.** Each census publishes its leaf hashes to [`docs/data/leaves/`](docs/data/leaves/), 32 bytes per observation, about 800 KB a day. Clone the repository and run:

```bash
mcpobs verify --leaves docs/data/leaves --heads heads --pubkey heads/key.pub
```

That rebuilds the whole tree from those hashes and checks the root against every signed head. It proves the heads describe exactly this sequence of leaves, that a given leaf is included, and that each day's tree extends the previous day's rather than replacing it.

**From the records.** The operator, or anyone holding the archive, can rebuild from the observations themselves — `mcpobs verify` with no `--leaves`.

`verify` rebuilds the tree from the observation records and checks the result against every published head. It deliberately ignores the stored hash file: verifying a log against hashes its own operator wrote proves nothing, since the hashes and the lie would come from the same hand. It also rejects any head that shrinks the log, because publishing fewer observations than yesterday is a deletion of history that no valid signature excuses.

The tree is what makes the operator — me — untrusted rather than trusted. A signature alone cannot do this: I hold the key, so a forged head will always verify under it. What cannot be forged is the tree. If I edit one archived observation from last month, the records stop reproducing the root I signed at the time, and anyone holding that older head can prove it. [`internal/mlog/commit_test.go`](internal/mlog/commit_test.go) is that scenario as an executable test.

### What verification does not establish

Rebuilding the tree proves the log has not been rewritten. It does not prove the observations are genuine: nothing here stops an operator from inventing a consistent history and signing it. Only independent observation closes that gap, which is what witnesses are for and why they are on the roadmap rather than done.

Until the leaf hashes were published, this was worse than it needed to be — an outsider could verify that a head carried a valid signature and nothing else, which proves only that the operator owns a key. That limitation stood for a month before someone asked the right question about it.

**One further caveat.** The first head, signed 2026-09-07, covers 136,225 observations taken over the nine days before the log existed. It attests that those observations are in the log *as of that date* — not that each was taken on the day it records. Only heads signed the day their observations were taken carry the stronger claim. Every head from 2026-09-08 onward does.

## Deployment

The crawler is a single static binary with no dependencies — no runtime, no database, no container.

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/crawler ./cmd/crawler
scp dist/crawler dist/mcpobs deploy/* user@server:~/
ssh user@server 'sudo bash install.sh'
```

`install.sh` creates a `mcpobs` service account with no shell, installs to `/opt/mcp-observatory` (the directory keeps the project's first name), and enables a daily systemd timer. It refuses to run if any name it needs is already taken, rather than overwriting something that might matter.

The unit is deliberately constrained. The crawler talks to fourteen thousand servers it does not control, on a box that is probably running something else that does matter:

| | |
| --- | --- |
| `ProtectSystem=strict`, `ReadWritePaths=…/data` | the filesystem is read-only except its own data directory |
| `RestrictAddressFamilies=AF_INET AF_INET6` | network only; no local sockets |
| `CPUQuota=50%`, `IOWeight=20`, `Nice=10` | background work yields to real applications |
| `OOMScoreAdjust=800` | under memory pressure the kernel kills this, never the neighbours |
| `MemoryMax=1500M` | measured, not guessed: a real census sat at 404 MB |
| `Persistent=true` on the timer | a reboot spanning 03:00 catches up instead of leaving a hole |

Three faults only appeared on the first real deployment and none were visible in development: progress written with carriage returns is invisible in `journalctl` and looks exactly like a hang; a 512 MB memory cap would have killed the census partway; and falling back to the SSE transport after a *timeout* doubled the cost of every dead endpoint, stretching the tail of a run by two hours. Writing the code was never the bottleneck.

## Scope, stated precisely

This log covers **publicly observable MCP servers** — those listed in the official registry that declare a network endpoint and answer an unauthenticated `tools/list`. That is 35% of listed servers, not "the MCP ecosystem". The distinction is not modesty; the credibility of every number here depends on it.

## Licence

TBD.
