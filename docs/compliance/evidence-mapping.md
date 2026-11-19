# What the evidence proves, clause by clause

A mapping of every field in the two evidence files `mcpobs` produces to the
record-keeping, change-management and supply-chain clauses a governance, risk
or compliance reader is asked about: the EU AI Act, ISO/IEC 42001, SOC 2,
the NIST AI Risk Management Framework and the OWASP MCP Top 10.

It is written so that one page answers "which clause does this file help me
with, and which does it not". It was prepared by the engineer who wrote the
tooling, not by a lawyer or a certified auditor; clause titles are quoted from
the public texts and should be confirmed against your own copy of each
standard before they go into an audit file. A review by a GRC practitioner is
open on the [roadmap](../../ROADMAP.md) (A6).

## The two files

| File | Produced by | What it is | What it proves | What it does not prove |
| --- | --- | --- | --- | --- |
| **Log bundle** `mcp-evidence/v1` | `mcpobs evidence <endpoint> --from --to`, on the operator's side | Every observation of one public server in a date range: the exact log line, an inclusion proof against a signed head, the archived bytes the server returned, the distinct tool surfaces and the diff between them | That these records were committed to the public log before the head was signed and have not been altered since; that the tool text in the file is the text those records hashed | That the operator really visited the server and wrote down what it served (a consistent lie is still consistent). Independent observers answer that; the log publishes digests for them to compare |
| **CI check file** `mcp-check-evidence/v1` | `mcpobs check --check-evidence`, in your CI, kept by the GitHub Action as an artifact | For every server in your `mcp.lock`: the tool text at lock time, the text at check time, the diff, the status, and the public log's newest head as a timestamp anchor | That the text in the file is the text the lockfile's hashes and the check's hashes were computed over; that the file was produced after the head it carries was published | Anything about the probe itself: it is your runner's own record. The public log never saw a private server |

Both are verified offline with one command:

```bash
mcpobs verify-evidence <file>                                   # key pinned in the binary
mcpobs --heads heads --pubkey heads/key.pub verify-evidence <file>   # from a clone: also checks the head is a published one
```

The verifier recomputes everything that can be recomputed (leaf hashes, proofs,
blob hashes, surface hashes, the diff, the summary) and never trusts a number
in the file. A one-byte change anywhere fails the check and names the item.

## Field by field

### Log bundle

| Field | What it is | What a reader can establish from it | Clauses it speaks to |
| --- | --- | --- | --- |
| `log.head`, `log.head_file`, `log.public_key` | The signed tree head the proofs are built against, verbatim, and the key that signed it | The commitment: tree size, root hash, signing time. Checkable against the head of the same name in the public repository | AI Act Art. 12 (integrity of automatically generated logs); ISO 42001 A.6.2.8; SOC 2 CC7.2 |
| `observations[].record` | One night's observation exactly as the crawler wrote it: time, endpoint, outcome, tool names, tool count, surface hash, content addresses of the bytes | What the server served that night, as recorded at the time | AI Act Art. 12(1)-(2) traceability, Art. 26(5) deployer monitoring; ISO 42001 A.6.2.6, A.6.2.8; SOC 2 CC7.1; NIST MANAGE 3.1, MANAGE 4.1 |
| `observations[].leaf_index`, `observations[].proof` | The record's position in the Merkle tree and the inclusion proof to the head's root | That the record was in the tree when the head was signed and has not been changed since | AI Act Art. 12 (logs that cannot be altered after the fact); SOC 2 CC7.2 (reliability of monitoring records) |
| `blobs` | The raw response bodies to `tools/list`, keyed by SHA-256 | The exact text the model was given about each tool, byte for byte. The verifier re-derives the surface hash from them | AI Act Annex IV §2 (description of components, including third-party ones); ISO 42001 A.4.4, A.6.2.7; OWASP MCP03 |
| `versions[]` | Each distinct tool surface, first and last night seen, nights served, tool names, the jcs-v1 digest other observers compute | The change history of a third-party component your agent depends on, with a digest an independent observer can confirm | SOC 2 CC8.1, CC9.2; ISO 42001 A.10.3; NIST MAP 4.1, MANAGE 3.1 |
| `changes[]` with `edited[].description_before` / `description_after`, `before` / `after` | The step between two versions down to the member that moved, with the old and new text | The sentence that changed in an instruction the model follows, and when | AI Act Art. 15 (resilience against attempts to manipulate the system through inputs), Art. 9 (risks identified and evaluated); OWASP MCP03, MCP06; SOC 2 CC7.1, CC7.3 |
| `range`, `subject`, `generated_at` | Scope of the bundle, the server, the slug of its public history page | What was asked for, and where the same history is published | Documentation hygiene for Art. 11 / Annex IV; ISO 42001 A.6.2.7 |
| `notes` | What the file proves and what it does not, in the file itself | That the limits travelled with the evidence | SOC 2 CC2.2 (information about the system communicated to those who need it) |

### CI check file

| Field | What it is | What a reader can establish from it | Clauses it speaks to |
| --- | --- | --- | --- |
| `lock.path`, `lock.generated`, `servers[].locked_at` | Which lockfile was checked and when its entries were last reviewed | The inventory of MCP servers the agent uses and the date each surface was accepted | OWASP MCP09; ISO 42001 A.4.4, A.10.3; NIST MAP 4.1; SOC 2 CC9.2 |
| `servers[].snapshot`, `servers[].tools_before`, `surface_locked`, `jcs_v1_locked` | The tool text that was reviewed when the server was locked, and its two digests | The approved baseline, recomputable from the text | SOC 2 CC8.1 (changes authorised and approved before implementation); ISO 42001 A.6.2.5; AI Act Art. 26(1) (use in accordance with instructions, with the instructions on record) |
| `servers[].tools_after`, `surface_now`, `jcs_v1_now` | The text served at check time and its digests | What the server served when your pipeline looked | SOC 2 CC7.1; NIST MANAGE 3.1 |
| `servers[].status`, `added`, `removed`, `edited[]` | `ok`, `changed`, `unreachable` or `misconfigured`, and for `changed` the exact diff | Whether the component changed since approval, and precisely how | SOC 2 CC7.1, CC7.2, CC8.1; OWASP MCP03, MCP04; AI Act Art. 26(5) |
| `servers[].auth` | Where the credential came from (an environment variable name), never its value | That private servers were checked and that secrets were kept out of the record | OWASP MCP01 hygiene; SOC 2 CC6.1 |
| `public_log.head`, `public_log.fetched_from` | The newest signed head of the public log at check time | A lower bound on when the file was produced, from a third party's signed clock | Freshness of the record for Art. 12 / A.6.2.8 retention; SOC 2 CC7.2 |
| `servers[].error`, `servers[].note` | Why a server could not be checked, or that no snapshot existed for it | That a gap is recorded as a gap, not hidden in a pass | SOC 2 CC7.3; honest-reporting expectations in every framework |
| `notes` | The limits of the file | See above | — |

## Framework by framework

### EU AI Act (Regulation (EU) 2024/1689)

Relevant where an agent is, or is a component of, a **high-risk AI system**
(Annex III, or Annex I products). Most agent deployments are not; where they
are not, the same evidence is still what a supervisor, a customer or an
insurer asks for after an incident.

| Clause | What it asks | What the evidence contributes |
| --- | --- | --- |
| Art. 12 Record-keeping | High-risk systems automatically record events over their lifetime, so that operation is traceable | The nightly observations and the CI check files are a record of what each external tool declared to the model and when, with integrity proofs for the public part |
| Art. 19 and Art. 26(6) Logs kept | Providers and deployers keep the automatically generated logs under their control for at least six months (longer if other law requires) | CI evidence artifacts expire after 90 days on GitHub by default: export them to your own retention store. Log bundles can be regenerated from the public log for any date the log has observed |
| Art. 26(5) Deployer monitoring | Deployers monitor the operation of the system on the basis of the instructions for use and inform the provider of risks | `mcpobs check` in CI and the drift issue are that monitoring for the MCP layer, with the text of each change |
| Art. 15 Accuracy, robustness and cybersecurity | Resilience against attempts by unauthorised third parties to alter use, outputs or performance by exploiting vulnerabilities, including attacks that manipulate inputs | A rewritten tool description is an input manipulation the model follows. The rule scan and the before/after diff detect and document it |
| Art. 9 Risk management | Known and reasonably foreseeable risks identified, estimated and evaluated, including from post-market monitoring | The published figures (share of servers changing per night, share of changes that keep the same tool names) are measured, not assumed, risk inputs |
| Art. 11 and Annex IV Technical documentation | Description of the system's elements, including third-party components and their versions | `mcp.lock` plus `mcp.lock.d/` is a versioned register of external tool interfaces; a bundle is the history of each |
| Art. 25 Value chain | Responsibilities of third-party suppliers of components, tools and services | The lock and the evidence make the supplier's interface changes visible and attributable by date |
| Art. 72 Post-market monitoring, Art. 73 Serious incidents | Systematic collection of operating data; incident reporting with the facts | A bundle for the affected server and date range is the factual annex to an incident report, verifiable by the recipient |

Timing: the obligations for Annex III high-risk systems were scheduled to
apply from 2 August 2026. A provisional agreement on the "AI Omnibus" of
7 May 2026 moves that to 2 December 2027 (Annex I products to 2 August 2028),
subject to formal adoption. Check the Official Journal for the state at the
time you read this; the record-keeping content of Art. 12 and the retention
periods were not reported as changed.

### ISO/IEC 42001:2023 (AI management systems)

Annex A control titles as commonly cited; confirm numbering against your
licensed copy.

| Control | What it asks | What the evidence contributes |
| --- | --- | --- |
| A.4.4 Tooling resources | Document the tools, frameworks and platforms the AI system uses | `mcp.lock` is that register for MCP servers, with a version (surface hash) per tool interface |
| A.6.2.6 AI system operation and monitoring | Monitor the system in operation, including components | Nightly checks, drift issues, CI evidence files |
| A.6.2.7 AI system technical documentation | Keep technical documentation of the system | Snapshots of the tool text; bundles as the history of each external component |
| A.6.2.8 AI system recording of event logs | Record event logs for traceability and incident analysis | The public log (signed, append-only) and the CI check files, with the diff per event |
| A.10.3 Suppliers | Manage risks from suppliers of components or services used in the AI system | Supplier-side interface changes are detected, dated and quoted; procurement can ask a vendor for its history page before onboarding |
| Clause 9.1 Monitoring, measurement, analysis and evaluation | Determine what to monitor and keep documented information as evidence | The per-server page, badges and the replayed rule history (`mcpobs scan --since`) are measurements with their method published |

### SOC 2 (AICPA Trust Services Criteria)

| Criterion | What it asks | What the evidence contributes |
| --- | --- | --- |
| CC7.1 | Detect changes to configurations that introduce new vulnerabilities, and susceptibilities to newly discovered ones | A changed tool surface is a configuration change in a dependency; the check detects it and the file documents it |
| CC7.2 | Monitor system components for anomalies indicative of malicious acts | The rule scan over tool text and the in-place edit detection, nightly for public servers and per run for yours |
| CC7.3 | Evaluate security events to determine whether they could or did result in a failure to meet objectives | The before/after text is what the evaluator reads |
| CC8.1 | Changes to infrastructure, data, software and procedures are authorised, designed, tested, approved and implemented | `mcpobs check --update` plus the commit of `mcp.lock` and `mcp.lock.d/` is the approval record for a change in a third-party tool interface, with the reviewed text in the diff |
| CC9.2 | Assess and manage risks associated with vendors and business partners | The vendor's server history and badges; the bundle as the periodic vendor review artefact |
| CC6.1, CC6.8 | Logical access controls; prevention and detection of unauthorised or malicious software | Credentials never in the lock or the evidence (`auth` names a variable); injected instructions in tool text are the closest MCP analogue to malicious software, and the scan reports them |

### NIST AI Risk Management Framework 1.0

| Subcategory | What it asks | What the evidence contributes |
| --- | --- | --- |
| GOVERN 6.1 | Policies and procedures for AI risks arising from third-party software and data, including supply chain | A lock-and-check policy with evidence files is an implementable procedure |
| GOVERN 6.2 | Contingency processes for failures or incidents in third-party components | The drift issue is the trigger; the bundle is the incident record |
| MAP 4.1, MAP 4.2 | Map and control the risks of third-party components | The inventory (`mcp.lock`) and the measured change rates |
| MEASURE 2.7 | Security and resilience assessed and documented | Rule scan results and change history per server |
| MANAGE 3.1 | Risks from third-party resources monitored, with response plans | Nightly monitoring and the accept flow |
| MANAGE 4.1 | Post-deployment monitoring plans implemented, including mechanisms for capturing and evaluating input | The CI check on a schedule and on lockfile changes |

The Generative AI Profile (NIST AI 600-1, 2024) names "Value Chain and
Component Integration" and "Information Security" among its risks; the same
rows apply.

### OWASP MCP Top 10 (2025, beta)

| Entry | What the evidence contributes |
| --- | --- |
| MCP03 Tool Poisoning | The rule scan reads descriptions and parameter descriptions for model-directed text; the nightly history and the CI diff catch poisoning that arrives after review, which is the form a scanner run once at install time misses |
| MCP04 Software Supply Chain Attacks & Dependency Tampering | `mcp.lock` pins the interface; `check` fails the build on tampering; the bundle proves what was served and when |
| MCP06 Prompt Injection via Contextual Payloads | Schema-level descriptions are scanned, which is where injected text most often sits |
| MCP08 Lack of Audit and Telemetry | The CI evidence artifact per run and the signed public record are audit trails that verify offline |
| MCP09 Shadow MCP Servers | A lockfile that must list every server the agent uses is an inventory; a server not in it is, by construction, unapproved. Partial: the lock does not discover servers configured outside it |
| MCP10 Context Injection & Over-Sharing | Partial: the exfiltration rules flag text that asks to move conversation content |
| MCP01, MCP02, MCP05, MCP07 | Not addressed. Token handling, privilege scope, command execution and authentication are properties of your deployment, not of the tool text; the only contribution here is that credentials never enter the lockfile or the evidence |

## Retention and custody

- Keep CI evidence files for at least as long as your longest applicable
  retention period (the AI Act's floor for logs is six months). The Action's
  artifact retention is 90 days by default (`evidence-retention-days`); copy
  the files to your own store from the workflow if you need longer.
- Log bundles are regenerable: anyone with the operator's archive can produce
  the same bundle for the same range, and anyone with a clone of the public
  repository can verify it. The signed heads and leaf hashes are in git and are
  not deleted.
- Keep the head files of the dates you rely on with the evidence. The
  verifier compares the bundle's head to the published one by name.

## What verification establishes, and what it does not

A passing `verify-evidence` on a log bundle establishes that the operator
committed to these exact records before signing the head, that the archived
bytes are the bytes those records hashed, and that nothing was altered since.
It does not establish that the operator observed the server honestly. That is
the single-operator limit of every transparency log, and the mitigation is
cross-checking: the log publishes nightly tool-set digests in a format other
observers read, so two independent records can be compared row by row.

A passing check on a CI file establishes that the text in the file is the
text the hashes were computed over and that the file postdates the head it
carries. It does not establish that the probe was performed as described; the
file is your own runner's record, the same way a CI log is.

Neither file contains a judgement. Every rule in the scan is a regular
expression published in the repository, every match is quoted, and none is
called malicious. The decision is the reader's.
