# Design brief: MCP Transparency Log

Written 2026-11-18, before any screen. A project rule wins over this brief
where they clash; the repository's rules are in README.md (no LLM in the
data path, raw bytes are the record, numbers always with denominators).

## 1. What this is

A public, signed, independently verifiable record of what every public MCP
server actually served, night after night since 30 August 2026, and the
tools that act on it: a history page and badges per server, a lockfile and
GitHub Action, a rule scan, evidence export. It is read by people who are
paid to be suspicious.

**Audience, in order.** Security and platform engineers who run agents;
CISOs and auditors who must prove what those agents consumed; MCP server
publishers who want to show they never changed their tools silently.

**The problem it solves.** A tool description is injected straight into a
model's context, and a server can rewrite it tonight with no version bump,
no signature failure, no notification. Nothing in a company's stack notices.
This log notices, and can prove what it saw.

**Business objective per surface.**
Overview: a stranger understands in ten seconds that this is a record, not a
scanner, and finds a server. Server page: a reviewer answers "is this still
what I approved" and copies a badge or a lock line. Lock page: an engineer
gets the Action running in four steps. Scan page: a sceptic sees the method
and one example per rule and believes the 3.1 %. Verify page: an auditor
reproduces the root. Plans: a buyer sees what is free, what a pilot is, and
the honest counter.

## 2. Brand strategy

**Positioning.** The record of what MCP servers served, kept so that nobody
has to take our word for it. Not a grade, not a gateway, not an opinion.

**Personality.** A court register, not a dashboard. Sober, exact, unhurried,
adversarially honest. Every number carries its denominator; every hash is
shown whole; corrections are published, not hidden. The product's charisma
comes from precision, not from motion or colour.

**Emotional tone.** Calm authority. The reader should feel the way they feel
in front of a well-kept archive: that someone has been paying attention
every night, and will still be paying attention next year.

**Differentiation.** The oldest unbroken series in its field, published leaf
hashes, a specified hash with test vectors, cross-checks with independent
observers. The design must make *time* and *verifiability* visible: the
nightly rhythm, the signed head, the proof, are first-class objects, not
footnotes.

**What it must never look like.** An AI-security landing page: purple
gradients, glass panels, shield icons, fake 99.9 % tiles, a hero
illustration of a robot. Nor a generic dark dashboard with twelve equal
cards. The Avoid list in the principal-designer brief applies in full.

## 3. Design principles

1. **Evidence before interface.** The signed head of the night is always on
   screen. Any figure can be clicked through to what it was computed from.
2. **Hashes are text, not decoration.** Full length, monospace, selectable,
   copyable. Truncation only where a column forces it, with the full value a
   hover away.
3. **Time is the primary axis.** Server pages are timelines. Quiet nights
   are shown as quiet, not hidden; a change is an event with a date.
4. **State colours mean state, nothing else.** One verified colour, one
   changed colour, one failure colour, one neutral. No colour is used for
   branding that is also used for state.
5. **Density is respect.** Readers are professionals; tables are allowed to
   be tables. Whitespace separates meaning, it does not pad.
6. **Two readers, two densities.** Marketing-level pages (overview, plans)
   breathe; operational pages (server, scan, lock) are dense.
7. **No illustration that is not data.** Charts are drawn from the log;
   there are no mascots, no stock art, no invented imagery. Icons, if any,
   come from one open set, approved before use.

## 4. Three directions to choose from

Same screen in each: the server page for `ac.tandem/docs-mcp` with real
data from the log, plus a strip of the overview. Rendered in
`design/directions/`. Pick one; the design system is then built for that
direction only.

| | A · Ledger | B · Console | C · Observatory |
| --- | --- | --- | --- |
| Metaphor | a printed register, kept nightly | a security operations console | an instrument that watches the sky every night |
| Surface | warm off-white paper, ink text, hairline rules | deep charcoal, high contrast, rails and panels | near-black indigo, one luminous accent, large numerals |
| Type | serif display + humanist mono | neutral grotesk + mono, tight | geometric grotesk + mono, editorial scale |
| Verified colour | verdigris green | signal green | phosphor green |
| Feels like | authority, archive, trust | tooling, operations, speed | brand, mission, memory |
| Risk | can read as academic | can read as any dashboard unless the evidence strip and timeline carry it | can drift towards marketing if the density slips |
| Best for | auditors, publishers, the long game | security engineers living in consoles all day | conferences, the landing page, recruiting believers |

Light and dark are both supported in every direction; the table names each
direction's *default* mood.

## 5. After the pick

Tokens (colour, type, space, radius, elevation, state), the component set
(top bar with evidence strip, status chip, hash, timeline, data table,
stat, code block, badge row, callout, form controls, empty/loading/error
states), then the six pages rebuilt on them, rendered and inspected at
desktop and mobile, then the quality gate in the brief.
