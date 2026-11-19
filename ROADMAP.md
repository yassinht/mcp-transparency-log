# Roadmap and backlog

Written 2026-11-18. Three epics, chosen from a longer list because each one is
buildable by one person on top of what already runs, needs little or no
infrastructure, and is something no other observer of the MCP registry offers.
Everything below stands on the record that exists: an unbroken signed series
since 2026-08-30, published leaf hashes, a specified surface hash, and a
cross-check list other observers can read.

Status marks: ✅ done · 🔄 in progress · ⏳ not started.

## What exists today ✅

| Piece | State |
| --- | --- |
| Nightly census of every registry endpoint, raw bytes archived (gzip), RFC 6962 log, signed heads, leaf hashes | ✅ 80 nights |
| Site: a history page and two badges per server, scan summary, verification page | ✅ |
| `mcpobs lock` / `check`, the GitHub Action, dogfooded daily | ✅ |
| Rule scan (13 rules, review and informational tiers) | ✅ |
| jcs-v1 digest and nightly peer list; surface-hash specification with vectors | ✅ |
| Registry community-projects PR; cross-check proposal to HISTOR | 🔄 awaiting replies |

## Epic A · Evidence packs and forensics

Goal: a compliance or security team can prove, to someone who does not trust
them, exactly what their agents' servers served and when, and who accepted
what. Sold first as a four-week audit through experteam.tn; no hosted
infrastructure.

| ID | Story | Acceptance | Est. | Requires |
| --- | --- | --- | --- | --- |
| A1 ✅ | Authenticated servers in `lock` and `check`: per-server headers read from environment variables (`MCPOBS_HEADER_<name>=Authorization: Bearer …`), never written to the lockfile | A private server locks and checks in CI with a secret from Actions or Vault; the lockfile diff shows no secret | 3 d | nothing |
| A2 ✅ 2026-11-19 | `mcpobs check --check-evidence out.json`: for every changed server, the full tool text before and after, the diff, timestamps, lock reference, and the public log head of that night | A reviewer reads one file and sees the exact sentence that changed | 3 d | nothing |
| A3 ✅ 2026-11-19 | `mcpobs evidence <endpoint> --from --to` (operator side): every surface version of a server between two dates, with the archived bytes and an inclusion proof per observation | Output verifies with A4 from a clean clone | 4 d | nothing |
| A4 ✅ 2026-11-19 | `mcpobs verify-evidence bundle.json`: checks every inclusion proof against the published leaves and heads, offline | An auditor runs one command and gets VERIFIED or the exact failing item | 3 d | nothing |
| A5 ⏳ | Retroactive rules: `mcpobs scan --since <date>` replays the rule set over history with a digest-keyed cache, reporting first appearance per rule and per publisher | "Pattern X first seen YYYY-MM-DD on N servers, M publishers" for every rule, from 80 nights, in under an hour | 5 d | a cache dir on the server (~100 MB) |
| A6 ⏳ | Compliance mapping document: each evidence field mapped to EU AI Act record-keeping and cybersecurity clauses, ISO/IEC 42001, SOC 2 change management, NIST AI RMF, OWASP MCP Top 10 | A GRC reader finds the clause they need in one page | 2 d | optional review by a GRC consultant |
| A7 ⏳ | Audit offer page (FR/EN) on experteam.tn and a one-page evidence sample | One real client signs a pilot | 2 d | experteam |

Budget: €0 infrastructure. Optional €300–600 for a GRC consultant to read A6.

## Epic B · Split-view detection

Goal: catch the server that shows scanners a clean tool list and real clients
a different one. Same server, several vantage points, several client
identities, same night; any disagreement that is not explained by known
volatility is a finding. Nobody observing the registry does this; every
current scanner probes from one place with one identity.

| ID | Story | Acceptance | Est. | Requires |
| --- | --- | --- | --- | --- |
| B1 ⏳ | Client identity profiles in the probe: at least four (generic, a desktop client, an IDE client, a browser-like client), each with its own User-Agent, Accept headers and protocol-version preference | Each identity recorded on the observation; a test server that keys on User-Agent is caught | 4 d | care with politeness: identities run serially per host |
| B2 ⏳ | Sampling plan so the crawl stays inside its window: all enumerable servers with the baseline identity nightly; the extra identities on a rotating stratified third nightly, so every server gets all identities weekly | Census still finishes in under 3 h | 2 d | nothing |
| B3 ⏳ | Two remote vantage points (North America, Asia) running the probe only, signing their observations with their own keys, shipping them to the main server nightly | Three observations per sampled server per night, each attributable to a vantage and key | 5 d | two small VPS, ~€6/month each |
| B4 ⏳ | Disagreement matrix: per server, digests by (vantage, identity); volatility excluded by the existing digit-normalising classifier and a same-night window; per-server split-view status on the history page and in the badge | A server that answers two identities differently shows `split view` with the two digests and dates | 5 d | nothing |
| B5 ⏳ | Customer vantage: the probe as a container a company runs from its own egress, results compared with the public vantages | Their IP is one more column in the matrix | 3 d | nothing beyond B3 |
| B6 ⏳ | Published study: first full matrix across the registry, whatever it finds, with method and raw data | A talk and a dated report | 3 d | nothing |

Budget: about €12–15 per month for two VPS, from the first week of B3.
Bandwidth is a few GB a month per vantage.

## Epic C · Witnessed private log

Goal: a company runs this log inside its own network for its internal and
authenticated servers; only signed tree heads leave; the public log co-signs
them, so a third party attests their history without seeing their data.
This is the recurring-revenue product and the one that turns the public log
into infrastructure others depend on.

| ID | Story | Acceptance | Est. | Requires |
| --- | --- | --- | --- | --- |
| C1 ⏳ | Deployable package: one container (crawler + mcpobs + static site served locally), a config file listing endpoints and header secrets, a data volume, retention setting, docker-compose and a Helm chart | A fresh VM runs a private log against three internal servers in under an hour | 6 d | nothing |
| C2 ⏳ | Heads in the standard checkpoint format (c2sp tlog-checkpoint with note signatures), dual-published beside the current format for the public log | Existing witness tooling parses our checkpoints | 4 d | reading the c2sp specs |
| C3 ⏳ | Witness client: a private log submits its checkpoint and consistency proof to a witness and stores the returned cosignature with the head | A private log's heads carry the public log's cosignature | 5 d | C2 |
| C4 ⏳ | The public log as a witness: a small endpoint that verifies consistency and cosigns, append-only record of everything it signed, key kept off the web box | Two private logs cosigned nightly for a month without a gap | 6 d | one more port on the OVH box, isolated; later its own host |
| C5 ⏳ | Reciprocity: ask existing witnesses (HISTOR's network, CrawlCheck) to cosign the public log's checkpoints | At least one external cosignature on our checkpoints | 2 d | their agreement |
| C6 ⏳ | Security model and data-flow document for the customer's security review: what leaves the network (heads only), key custody, what verification proves and does not | Passes one real customer's review | 2 d | nothing |
| C7 ⏳ | Pricing and contract template through experteam: annual subscription per private log, pilot credited | One signed pilot | 1 d | experteam, a lawyer's hour for the template |

Budget: €0–10 per month until the witness needs its own host; then one small
VPS (~€6/month). Optional domain for the witness endpoint, ~€15 a year.

## Cross-cutting

| Item | Status | Requirement |
| --- | --- | --- |
| Billing | ✅ resolved | experteam.tn invoices audits and subscriptions; no Stripe account needed from Tunisia |
| Credibility | ✅ | signed series since 2026-08-30, registry citation, published spec, cross-check with an independent observer |
| Licence | ✅ | Apache-2.0 |
| Time | ⏳ | one person, about 15–20 hours a week for 12 weeks; the estimates above total ~70 working days, so the three epics land in sequence A → B → C, not in parallel |
| Pilot customer | ⏳ | one experteam client with agents in production; the audit is the entry |
| Legal | ⏳ | one hour of a lawyer for the pilot contract and the witness terms; a DPA is unnecessary for the private log, since no customer data leaves |
| Events | ⏳ | a talk, not a booth: candidates Forum InCyber (Lille), Devoxx France, GITEX Africa, OWASP chapters; verify dates and CFP deadlines; budget below |

## Budget, total

| Line | Monthly | One-off |
| --- | --- | --- |
| Two vantage VPS (B3) | ~€12 | |
| Witness host, when needed (C4) | ~€6 | |
| Domain for the witness, optional | | ~€15 / year |
| GRC consultant review of A6, optional | | €300–600 |
| Lawyer, pilot contract and witness terms | | €150–300 |
| Events: one ticket, travel, two nights | | €800–1,500 per event |
| Hardware, licences, SaaS tooling | €0 | €0 |

Realistic cash need for the 90 days: about €40 of infrastructure plus one
event, under €2,000 in total. The binding constraint is hours, not money.

## 90-day sequence

| Weeks | Deliverable | Gate to the next |
| --- | --- | --- |
| 1–3 | Epic A complete; audit offer live on experteam.tn | one pilot audit agreed |
| 4–7 | Epic B through B4; first registry-wide split-view matrix published | the report exists, whatever it says |
| 8–12 | Epic C through C4 with one pilot private log; talk submitted; pricing page | one cosigned private log, one CFP accepted or one event booked |

Kill criteria, stated in advance: if by week 12 there is no paid audit and no
company willing to run a private log, the three epics stay free and open, the
nightly log keeps running, and no hosted service is built.
