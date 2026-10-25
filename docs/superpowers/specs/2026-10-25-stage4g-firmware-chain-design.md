# Stage 4g Firmware Chain Design

**Date:** 2026-10-25  
**Status:** approved
**Consumes:** completed Stage 4f firmware static review  
**Produces:** complete, static-only firmware exploit-chain evidence

## Intent

Stage 4f turns two independent hunt lanes into canonical, static-reviewed
firmware findings. It intentionally stops before composing those primitives.
Stage 4g adds that missing cross-finding pass: it determines whether one
reviewed primitive produces a capability or device state that satisfies the
explicit precondition of another, records the evidence for every transition,
and accounts for every reviewed finding even when no chain is justified.

This is firmware security analysis, not prose similarity. Two findings do not
form a chain merely because they mention the same daemon, protocol, path, or
security noun. A valid directed edge states what the producer grants, what the
consumer requires, why those facts match, and which device state and unresolved
observations constrain the transition.

The phase remains static. It does not execute firmware, assign severity or
CVSS, estimate payout, claim runtime reachability, or write a disclosure report.
Its strongest evidence rung is `static-chained`. Later `dive` and `decide`
phases settle runtime and hardware questions and rank the resulting chains.

## Goals

1. Consume only a current, complete Stage 4f generation for one firmware image.
2. Freeze all reviewed findings plus current surface/state context into one
   immutable, content-addressed chain worklist.
3. Require a disposition for every reviewed finding: `chained`, `standalone`,
   `unchainable`, or `blocked`.
4. Record reusable findings in any number of distinct chains; coverage is by
   disposition, never by exclusive assignment.
5. Represent every chain as an ordered simple path of at least two findings and
   every adjacent transition as a separately evidenced edge.
6. Preserve current Stage 4d unknowns as blockers and allow the chain reviewer
   to create new, explicitly settleable chain blockers.
7. Retain Stage 4f false-positive pivots as investigative context only. A pivot
   can motivate follow-up work but can never be a node, edge, or evidence source.
8. Derive `pre_auth` as `yes`, `no`, or `unknown` from structured requirements;
   never accept it as a free reviewer conclusion.
9. Fail closed on stale roots, generations, artifacts, ownership, incomplete
   coverage, invalid transitions, and claims stronger than the weakest edge.
10. Preserve image isolation and atomically invalidate Stage 4g whenever its
    selected-image Stage 4f foundation changes.

## Non-goals

- Severity, CVSS, payout rank, exploit reliability, or report priority.
- Dynamic verification, emulation, weaponization, or hardware interaction.
- Treating a false-positive pivot as a resurrected finding.
- Finding new vulnerabilities. A newly suggested primitive returns to `hunt`
  and `fpcheck`; it does not enter a Stage 4g chain directly.
- Cross-image chains. Each generation belongs to exactly one target image.
- The later `dive`, `decide`, or `report` phases.
- Creating the separate `firmware-audit` skill tree or settling the monorepo
  question.
- Changing the existing generic `cba_findings` / `cba_chains` behavior.

## Anti-goals

- Keyword joins presented as exploit chains.
- “Pre-auth” inferred from the first finding while a later edge requires a
  session, administrator access, a local shell, UART, or an unresolved state.
- A complete-looking output that silently omitted hard-to-chain findings.
- A chain whose middle finding does not consume the preceding edge and produce
  the following one.
- Collapsing several alternative paths into one ambiguous unordered member set.
- Treating `complete` as equivalent to live exploitation.

## Constraints inherited from the repository

- The package remains Python standard-library only.
- SQLite and canonical artifacts are the durable sources of truth; agent return
  text is never authoritative.
- Raw findings and agent output stay file-backed and out of the orchestrator
  context.
- Public JSON preserves exact scalar identities and paths. Human diagnostics
  use the repository's bounded, escaped display rules.
- Expected SQL failures use a fixed diagnostic. Unexpected exceptions propagate
  after transaction cleanup.
- Content-addressed artifacts install before database publication. SQL changes
  are atomic; a failed publication may leave only an unreferenced immutable
  artifact.
- All selected-image operations preserve sibling images.
- `make all` is the final completion gate after documentation reconciliation;
  `make mutate` remains separate and opt-in.

## Approaches considered

### A. Dedicated provenance-bound evidence graph — selected

Add firmware-specific run, receipt, disposition, blocker, chain, and edge
records. Freeze the complete Stage 4f boundary, dispatch one global file-backed
review, validate strict result JSON, import it atomically, and reconstruct the
whole graph at completion.

This costs more schema and validation work, but it makes coverage, ownership,
staleness, and claim strength mechanically checkable. It also preserves the
firmware-specific state model without contaminating the generic source-code
chain tables.

### B. Extend generic token proposals and compose manually — rejected

The existing `audit_core.chains` mechanism compares generic finding impact and
precondition prose. Firmware chains often cross HTTP handlers, configuration
stores, init scripts, Unix sockets, privileged helpers, cloud callbacks, and
reboot boundaries without sharing three useful tokens. Extending that heuristic
would be cheap but would miss the semantic transitions this phase exists to
discover and would lose Stage 4f image/generation provenance.

### C. Accept one free-form global agent report — rejected

A free-form report can sound expert while omitting findings, relying on rejected
candidates, or overclaiming reachability. Without a strict result contract and a
reconstructing completion gate, those defects are not distinguishable from a
legitimate absence of chains.

## Security model

### Nodes

Only current `cba_firmware_findings` rows are nodes. Each node retains its Stage
4f finding ID and immutable candidate-snapshot ownership. A finding may appear
in multiple chains. A finding never changes identity or evidence rung because
it participates in a chain.

### Directed edges

For adjacent findings `A -> B`, the result must provide:

- one `capability_kind` from the frozen vocabulary below;
- a concrete `link_key` naming the exact resource, credential, state, endpoint,
  or authority both sides refer to;
- `produced_capability`: what A produces for that key;
- `required_precondition`: what B requires from that key;
- separate producer and consumer evidence-reference arrays, plus optional
  current surface/state evidence references;
- the state required before B and the state produced after B;
- an explicit transition kind when B crosses a reboot or other state boundary;
- existing surface-unknown IDs and/or new chain-blocker IDs; and
- a static confidence from 0 through 10.

The capability vocabulary is `credential-possession`, `session-possession`,
`file-read`, `file-write`, `config-read`, `config-write`, `command-execution`,
`code-execution`, `ipc-access`, `network-reachability`,
`firmware-update-control`, `persistent-execution`, `reboot-control`,
`physical-access`, and `other-specific`. Producer and consumer capability kinds
and `link_key` must match exactly. `other-specific` is permitted only with a
non-generic, namespace-like key. This deliberately rejects clever implicit
transformations: when one primitive converts a file write into reboot-time code
execution, the edge key names the controlled boot resource and the evidence
explains that exact conversion.

Evidence references are machine-addressable strings:

- `finding:<finding-id>#<field>` where field is one of `root_cause`,
  `attacker_position`, `data_flow`, `impact_hypothesis`, or `evidence_summary`;
- `surface:<surface-id>#reach_evidence`; or
- `unknown:<unknown-id>#evidence` for a current resolved Stage 4d unknown.

Producer evidence must include a field owned by A; consumer evidence must
include a field owned by B. Supplemental references must resolve to a current
surface or resolved unknown frozen in the worklist. Pivot references are never
valid evidence references. Validation can therefore prove ownership and exact
retained text even though the reviewer remains responsible for the semantic
judgment that the cited text supports the claim. Generic claims such as
“provides access,” “could help exploitation,” or “same component” are rejected
by the result contract and adversarial review; the completion gate also requires
matching typed capability and concrete link keys rather than attempting an
unreliable natural-language truth oracle.

Edges are chain-local and ordinal. Reusing the same two findings in a different
path is allowed because the required state or evidence may differ. Within one
chain, members are unique, edge ordinals are contiguous from zero, and there is
exactly one edge for each adjacent member pair.

### Chains

A chain is an ordered simple path containing at least two findings. Its stable
ID is derived from the image ID, Stage 4f candidate snapshot, ordered member IDs,
and the canonical edge projection. Reviewer-supplied labels are descriptive and
do not establish identity.

Alternative routes are separate chains. A shared prefix or suffix is not copied
into a synthetic super-chain. The result may submit each canonical path only
once; exact duplicates and conflicting descriptions of the same canonical path
are rejected rather than silently selected.

### Finding dispositions

Exactly one disposition is required for every Stage 4f finding:

- `chained`: references every accepted chain containing the finding;
- `standalone`: independently meaningful, but no second reviewed primitive is
  needed or currently composes with it;
- `unchainable`: no evidence-backed transition was found, with a specific
  explanation of what was examined; or
- `blocked`: a plausible transition depends on one or more named unresolved
  observations.

For a `chained` disposition, the declared chain set must exactly equal derived
membership. Non-chained dispositions cannot be referenced by a chain. A pivot
may be attached only as a follow-up hint to `unchainable` or `blocked`; it never
changes the disposition or supplies evidence.

A finding in either a complete or blocked materialized chain is `chained`.
`blocked` disposition is reserved for a finding not present in any materialized
chain where a plausible composition cannot yet be expressed as a coherent
ordered path. It references blockers directly, without inventing an edge.
Reviewer-created blockers therefore carry affected finding IDs and may carry
either materialized `(chain_key, edge_ordinal)` references or blocked-disposition
finding references. At least one affected reference is required.

### Blockers and unknowns

Current Stage 4d `cba_unknowns` rows are frozen into the worklist with their
status, settling observation, method, evidence, and artifact provenance. Open
ones may block an edge. Resolved ones may support an edge only when their
evidence remains part of the current verified surface generation.

The reviewer may define a new chain blocker when composition exposes a question
not represented by Stage 4d. Each new blocker requires:

- a stable result-local key;
- the exact question;
- the observation that would settle it;
- one method from `static`, `emulate`, or `hardware`;
- one or more affected axes from `authentication`, `lifecycle`, `posture`, or
  `reachability`;
- affected finding IDs; and
- optional affected materialized chain/edge references.

Imported chain blockers begin `open`. Stage 4g does not resolve them. Later
`dive` or `decide` work owns resolution and must trigger chain regeneration when
the input evidence changes.

### False-positive pivots

Stage 4f pivots are included in the worklist only to expose promising follow-up
directions. Result validation permits their IDs only in disposition follow-up
lists. Pivot IDs are forbidden from member lists, producer/consumer fields,
transition-evidence ownership, and blocker evidence. This prevents a rejected
candidate from being laundered back into a chain.

## Device-state and pre-auth derivation

The structured firmware state axes remain those of the parent design:

- lifecycle: `factory-fresh`, `provisioned`, `bound-to-owner`,
  `cloud-registered`, `post-reset`;
- posture: `SoftAP-setup`, `STA-LAN`, `WAN-exposed`, `BLE`,
  `cloud-tunnel-only`;
- authentication: `pre-auth`, `session`, `admin`, `local-shell`,
  `physical-UART`.

Each chain declares one exact initial lifecycle, posture, and authentication
state. Alternative initial states are alternative chains; this avoids hiding
several paths inside one permissive union.

It also declares an `initial_attacker_position` description and non-empty
`initial_evidence_refs`. Those references must resolve to the first finding's
retained attacker-position/evidence fields or to a current referenced surface.
Thus the initial structured state is not a bare reviewer assertion.

Each edge declares a `required_state` with one exact value or the literal `any`
for each axis, and a `result_state` with one exact value or `unchanged` for each
axis. The validator carries state forward in edge order. A requirement must be
`any` or equal the carried state; an exact result replaces that axis and
`unchanged` preserves it. Edge continuity is therefore mechanical.

The edge also declares one transition kind from `direct`, `reboot`,
`service-restart`, `factory-reset`, or `reprovision`. Anything except `direct`
requires producer and consumer evidence that explicitly supports the boundary.
A lifecycle or posture change with `direct` is invalid. This permits real
firmware chains such as persistent configuration write -> reboot -> privileged
startup execution without treating reboot as magic. State-independent behavior
uses `any` explicitly; an omitted or empty requirement is invalid.

`pre_auth` is derived, never submitted:

- `yes` when the exact initial authentication state is `pre-auth`, state
  continuity proves that every stronger later requirement was produced by an
  earlier edge, and the chain has no open blocker;
- `no` when the exact initial authentication state is `session`, `admin`,
  `local-shell`, or `physical-UART`; and
- `unknown` when an open existing or new blocker affects authentication,
  lifecycle, posture, or reachability.

An authentication bypass or credential primitive may legitimately move the
carried state from `pre-auth` to `session` or `admin`; consuming that internally
produced capability does not make the chain post-auth. The question is what the
attacker must possess before the first node, not which authority the chain earns.
For determinism, explicit stronger initial authentication yields `no`; otherwise
any relevant open blocker yields `unknown`; otherwise a `pre-auth` initial state
yields `yes`.

An edge references existing Stage 4d unknowns as objects containing the exact
unknown ID and one or more affected axes. The unknown must be in the frozen
relevant set. Open unknowns are blockers. Resolved unknowns may instead appear
as supplemental evidence and cannot be labeled open. The result's affected axes
must agree with the unknown's recorded field under a frozen field-to-axis map;
unrecognized Stage 4d fields conservatively map to `reachability`.

The chain's static confidence is the minimum of all member Stage 4f confidences
and all edge confidences. The chain's evidence rung is exactly
`static-chained`. Neither value is accepted from worker JSON.

## Persistence model

Stage 4g adds six dedicated tables; generic chain tables remain untouched.

### `cba_firmware_chain_runs`

One selected-image generation. It binds the manifest, surface snapshot, Stage
4f candidate snapshot, Stage 4f findings artifact, frozen chain worklist, counts,
and `pending|complete` status. Completion owns a canonical graph artifact and
timestamp.

### `cba_firmware_chain_receipts`

One canonical imported result for the generation. It records worklist/result
paths and hashes plus submitted and derived counts. Replacement is explicit.

### `cba_firmware_chain_dispositions`

One row per Stage 4f finding, keyed by image and finding ID. It stores the
classification, explanation, canonical chain-ID list, referenced blocker IDs,
pivot follow-up IDs, and result provenance.

### `cba_firmware_chain_unknowns`

Reviewer-created chain blockers, keyed by image and derived blocker ID. It stores
the question, settling observation, method, affected findings, affected chain
edges, open status, and result provenance. Existing Stage 4d unknowns remain in
`cba_unknowns` and are referenced, not copied.

### `cba_firmware_chains`

One canonical chain, keyed by image and derived chain ID. It stores ordered
member IDs, initial attacker position, derived `pre_auth`, derived confidence,
`complete|blocked` static completeness, referenced existing/new blockers,
`static-chained`, and canonical artifact provenance.

`complete` means that every static transition is evidenced and has no open
blocker. It does not mean the path ran on a device. `blocked` retains a coherent
candidate chain whose unsettled observations prevent that static conclusion.
Members of either form have the `chained` disposition.

### `cba_firmware_chain_edges`

One row per chain-local ordinal, keyed by image, chain ID, and ordinal. It stores
adjacent producer/consumer finding IDs, capability, precondition, transition
evidence, structured state requirements, confidence, blocker references, and
result provenance.

All JSON-array columns use canonical JSON: UTF-8, sorted unique values where
order is semantic-free, compact separators, and exact ordered arrays for chain
members and edge ordinals. Validators reject duplicate keys, invalid variants,
unsafe identifiers, unknown fields, non-finite numbers, boolean integers, and
noncanonical arrays.

## Immutable input boundary

`firmware_fpcheck.verified_findings_snapshot(...)` is added as a read-only
consumer boundary analogous to `hunt.verified_snapshot`. It:

1. verifies the selected image's complete Stage 4f run and canonical findings
   artifact;
2. revalidates its completed hunt, current surface evidence, and live root;
3. reconstructs every canonical Stage 4f finding without writes or timestamp
   changes; and
4. returns frozen findings, pivots, referenced surfaces, and current unknowns
   with run-relative canonical artifact provenance.

It works on read-only SQLite connections and inside a caller-owned transaction.
It has no display-row cap.

The frozen Stage 4d unknown set is exact: all current same-image unknowns whose
`surface_id` is one of a reviewed finding's `surface_ids`, plus all current
same-image unknowns whose `component_path` is one of a reviewed finding's
`component_paths`. This includes component-level unknowns with a NULL surface.
The union is deduplicated by unknown ID. No unrelated same-image unknown is
included, and no unknown from another image is accepted.

Stage 4g hashes a canonical projection containing:

- selected image and upstream manifest/surface/candidate identities;
- every Stage 4f finding and its exact evidence fields;
- every current surface referenced by those findings;
- every current Stage 4d unknown relevant to those surfaces/components; and
- every Stage 4f pivot, clearly tagged as context-only.

The absolute firmware root and timestamps are excluded. The resulting worklist
is installed beneath `files/firmware-chain/<worklist-sha256>/worklist.json`.

## Phase operations

The existing `chain` verb retains its generic default/proposal and `--compose`
behavior. Firmware modes are explicit and mutually exclusive:

```bash
python3 audit.py chain --run RUN --prepare --root ROOT [--image-id ID] [--json]
python3 audit.py chain --run RUN --record RESULT.json [--replace] [--json]
python3 audit.py chain --run RUN --check --root ROOT [--image-id ID] [--json]
```

Generic flags cannot be mixed with firmware modes. Syntax errors exit 2 before
database access. Expected semantic errors exit 1 with bounded diagnostics.

### Prepare

`prepare` obtains the verified Stage 4f snapshot, builds the complete global
worklist, installs it content-addressed, then takes `BEGIN IMMEDIATE`. Under the
lock it repeats upstream/root and installed-byte verification before publishing
one pending run.

An identical prepare preserves imported/completed state and timestamps. A
changed worklist replaces only the selected image's Stage 4g rows. Empty Stage
4f findings still produce a valid empty worklist and must later receive an empty
result; absence is evidence only when explicitly receipted.

The phase deliberately uses one global worklist. Cross-component composition is
the work. The worker reads it incrementally from disk and may checkpoint its own
scratch analysis, but only one final complete result is importable. No finding
count cap may silently truncate coverage.

### Agent review

One strongest-available worker receives the immutable worklist and the installed
firmware-chain brief. It analyzes the full finding graph, treats pivots as hints
only, writes strict result-only JSON, and returns the standard one-line contract.

The brief requires explicit adjacent-edge reasoning, middle-node continuity,
device-state constraints, full finding disposition, blocker settlement methods,
and adversarial checks against same-component correlation, reboot assumptions,
privilege discontinuities, confused-deputy claims, and pre-auth inflation.

### Record

`firmware_chain_results.load_and_validate(...)` parses bounded UTF-8 JSON,
rejects duplicate/unknown keys, checks exact generation ownership and complete
finding disposition, and derives canonical blocker, chain, and edge identities.
Validation performs no SQL or artifact writes and supports a read-only
connection.

Worker JSON uses unique safe result-local `blocker_key` and `chain_key` values
for references. Identity derivation is deliberately ordered and non-circular:

1. derive each blocker ID from image ID, Stage 4f candidate snapshot, question,
   settling observation, method, affected axes, and sorted affected finding
   IDs; `blocker_key` and materialized chain/edge references do not participate
   in blocker identity, and two local keys resolving to the same ID are rejected;
2. replace blocker keys in edges with derived blocker IDs;
3. derive each chain ID from image ID, Stage 4f candidate snapshot, exact
   initial state, ordered member IDs, and every canonical edge semantic field:
   ordinal, endpoints, capability kind, link key, capability/precondition text,
   producer/consumer/supplemental evidence references, required/result states,
   transition kind, confidence, existing unknown IDs, and derived blocker IDs;
4. key persisted edges by the derived chain ID and contiguous ordinal; and
5. resolve disposition and blocker affected references from local keys to the
   derived IDs.

Chain titles/summaries, local keys, SQL timestamps, artifact paths, and other
display-only text are excluded from chain identity. Edge capability and
precondition descriptions are semantic and remain included. Unknown or dangling
local references fail the import.

`record` installs canonical result bytes beneath
`artifacts/firmware-chain/<generation>/<result-sha256>/result.json`, then takes
`BEGIN IMMEDIATE`. Under the lock it repeats mutable upstream, assignment,
ownership, current-unknown, pivot-use, and installed-byte checks. It atomically
publishes one receipt plus dispositions, blockers, provisional chains, and
edges. The run remains pending and prior derived completion evidence is cleared.

Duplicate import fails unless `--replace` is explicit. Replacement is isolated
to the selected image and current generation. Sibling images survive. A failed
replacement preserves all prior SQL.

### Check

`check` re-reads the canonical result artifact and reconstructs all receipt-owned
rows. It requires:

- exact current Stage 4f and live-root provenance;
- one disposition per reviewed finding and no foreign finding;
- exact disposition-to-chain membership;
- at least two unique ordered members per chain;
- exactly `members - 1` contiguous adjacent edges;
- no repeated member or cyclic path;
- concrete capability/precondition/evidence on every edge;
- valid current surface unknown references;
- pivot references only in permitted follow-up fields;
- canonical chain/blocker identities and exact row ownership;
- derived confidence, completeness, `pre_auth`, and evidence rung; and
- a truthful empty result for an empty Stage 4f finding set.

It writes deterministic `chains.json` before taking the publication lock, then
repeats every mutable input, artifact, root, and derivation check under
`BEGIN IMMEDIATE`. Success replaces selected-image canonical chains/edges as one
unit and marks the run complete. A completed recheck performs the same work,
requires byte-identical canonical evidence and rows, and preserves timestamps
without writes.

Read, parse, install, SQL, lock, or commit failure preserves the prior durable
state. An unreferenced immutable artifact may remain.

## Invalidation

`firmware_chain.invalidate(con, image_id, commit=False)` deletes exactly one
image's six Stage 4g tables in dependency order and leaves transaction ownership
with the caller by default.

Every Stage 4f operation that truly changes the selected image's review run,
receipt, verdict, pivot, canonical finding, or completed status calls this local
invalidator inside its existing transaction. Byte-identical Stage 4f operations
preserve Stage 4g. Stage 4f rollback also restores Stage 4g.

Earlier acquisition, triage, surface, and hunt changes already invalidate Stage
4f; their transaction therefore reaches Stage 4g transitively through the Stage
4f invalidation boundary. Tests pin both direct and transitive behavior.

## CLI and machine-output contract

Prepare, record, and check human output contains bounded scalar summaries only.
Machine JSON exposes a fixed scalar whitelist plus reusable artifact paths and
preserves image IDs and paths losslessly with normal JSON escaping. It never
dumps findings, edges, blocker prose, or chain member lists into orchestrator
output.

Expected SQLite failures print exactly `chain: database operation failed`.
Other expected errors are root-redacted, ASCII-escaped, capped at 512 characters,
and newline-terminated. Successful commands write nothing to stderr.

## Installed workflow contract

A new `references/briefs/firmware-chain-brief.md` renders through the existing
brief mechanism. `SKILL.md` routes the firmware chain phase through explicit
prepare, one global worker over the immutable file, record, and check operations.
It preserves the existing generic source-code chain instructions.

The worker never writes SQL, installs canonical artifacts, selects identities,
or marks completion. Its output is data for hostile validation, not authority.

## Error and adversarial cases

Tests must cover at least:

- stale Stage 4f finding artifacts, changed live-root bytes, and same-size root
  changes;
- sibling images with overlapping finding IDs, surface IDs, pivot IDs, and
  blocker result keys;
- Unicode and delimiter-bearing image IDs without machine-output corruption;
- empty finding generations and all four disposition classes;
- a finding reused across multiple chains;
- exact duplicate chains, alternative paths with shared prefixes, repeated
  members, reversed edges, missing middle transitions, and cycles;
- unsupported capability/precondition matches and generic transition prose;
- existing open/resolved/foreign/stale surface unknowns;
- new blockers with invalid methods, missing settling observations, or dangling
  edge references;
- pivot laundering through members, edges, evidence, or blocker proof;
- `pre_auth=no` from a stronger initial authentication state, internally earned
  session/admin state remaining compatible with `pre_auth=yes`, and `unknown`
  from unresolved reachability/state blockers;
- confidence minima across reused members and chain-local edges;
- raw/canonical size boundaries, duplicate JSON keys, invalid UTF-8, non-finite
  values, booleans as integers, unknown keys, and unsafe paths;
- replace isolation, idempotent prepare/check, publication races, real
  two-connection lock contention, injected SQL/commit failures, and transitive
  upstream invalidation; and
- generic `audit.py chain` behavior remaining byte-for-byte compatible at its
  public CLI boundary.

## Documentation and completion

Stage completion reconciles `progress.md`, `SESSION_HANDOFF.md`,
`ARCHITECTURE.md`, and `feature_lists.json` with the actual tree. It removes
`chain` from next steps and names `dive` as the next firmware slice, while
retaining the Asus golden, paid milestone gate, separate skill tree, and
monorepo/submodule decision as unfinished.

After the final documentation changes, `make all` must pass from the repository
root and its measured test, selftest, schema, migration, line-ending, manifest,
install, coverage, and benchmark summaries must be recorded. `make mutate` is
not part of Stage 4g unless separately requested.

## Builder decisions intentionally left open

- Exact helper and dataclass decomposition between `firmware_chain.py` and
  `firmware_chain_results.py`, provided parsing/validation remains read-only and
  publication remains atomic.
- Exact canonical JSON field ordering, provided the schema version and semantic
  identities above are preserved and golden tests pin the chosen bytes.
- The internal SQL query strategy, provided it has no display-row cap and never
  weakens full-denominator verification.
- Human success wording within the bounded scalar-output contract.

