# Global firmware chain review

Audit run directory: {run_dir}
Database context (read only): {db_path}
Carved target root (rootfs, read only): {rootfs}
Target image ID: {image_id}
Candidate snapshot SHA-256: {candidate_snapshot_sha256}
Immutable global worklist: {worklist_path}
Required result file: {result_path}

## Assignment and result contract

You are the one global strongest-available worker for this immutable generation.
Read the full worklist incrementally from that exact path; no finding count cap
or per-component partition may truncate cross-finding review. Read the result
dataclasses, parser, and graph validation in
`__SKILL_DIR__/audit_core/firmware_chain_results.py` and the generation boundary
in `__SKILL_DIR__/audit_core/firmware_chain.py`. The installed parser is the
authoritative schema, not a schema reconstructed from memory.

Bind `image_id` and `candidate_snapshot_sha256` to the supplied provenance and
worklist. Derive `worklist_sha256` from its exact bytes. Require agreement with
the immutable path and frozen ownership; on mismatch return FAILED, without
repairing the worklist or switching generations.

Write one result-only strict JSON file to `{result_path}`: a regular UTF-8 file
capped at 8 MiB. Use schema version 1 with exactly the parser's keys, including
`blockers`, `dispositions`, and `chains`; reject duplicate keys, extra keys,
non-finite numbers, and invalid enum values. Use unique safe result-local
`chain_key` and `blocker_key` labels, not canonical identities. Supply all
required fields and explicit empty arrays where appropriate. An empty finding
generation still requires a valid bound result with zero dispositions, chains,
and blockers; absence of a result is not a negative review.

## Current dive overlay

The worklist always contains `dive_overlay` with exactly `schema_version: 1`
and `observations` (an empty array when no observations are current). Each
observation contains exactly `observation_id`, `question_id`, `subject_refs`,
`outcome`, `resolution_effect`, `evidence_rung`, `dependency_refs`, and
`evidence_refs`. Subjects use their stable `kind:identity` wire. The effect has
exactly `target_subject`, `mode`, `predicate`, `axis`, `value`,
`capability_kind`, `link_key`, and `transition_kind`. Dependency/evidence refs
are identity digests, not private evidence bodies or access paths. Consume this
exact frozen projection; do not fetch private dive conclusions to infer effects.

Only `supported` current observations authorize
`dive:<64-lowercase-hex-observation-id>#conclusion` or `#evidence`; both fragments
have identical authority. These may appear only in existing initial, producer,
consumer, or supplemental evidence arrays. Every citation must independently
match the effect's exact target and containing locus. `subject_refs` establish
frozen linkage and settlement; they never broaden an edge target's authority.

A state-value citation must equal the initial state in an initial slot, the
carried required state in a producer/consumer slot, or the effective result
state in a supplemental slot. Initial evidence targets the first finding,
exact chain, or its exactly linked surface unknown. Edge evidence targets the
exact stable edge, its specified endpoint finding, or its exactly linked
unknown. Reachability evidence requires `value: evidenced`. Edge-validity and
capability-present require true and the exact capability/link identity.
Only transition-observed with true and the exact transition identity can
establish a non-direct boundary; other dive predicates cannot replace that
proof. An other-specific discovery settles its exact unknown only.

Honor supported effects and refuted constraints even when not cited. Never
recreate a settled chain-blocker or surface-unknown from a conclusive
observation's frozen subjects. A changed question must have its own distinct
identity. Never recreate an exactly refuted edge fingerprint. Refuted state
effects record the observed alternative: an explicit claim on that exact
subject must not contradict it, but a refuted observation is never positive
evidence. Stale, contested, inconclusive, and foreign observations are absent
and cannot be cited. Stable edge/chain fingerprints exclude only well-formed
dive citations; static evidence and all other semantic fields remain exact.

Evidence rung describes provenance strength. It never establishes severity,
exploit reliability, or confidence and never licenses inference beyond the
exact observed environment and subject. Worklist ownership binds this overlay;
if it changes, stop and request regeneration rather than repairing the input.

## Finding coverage and paths

Give exactly one disposition for every current reviewed finding and no foreign
finding. Re-read its retained evidence and relevant carved components; source
may be absent, so use static binary, symbol, offset, configuration, and artifact
evidence as available. Preserve finding identities and evidence rungs.

- `chained`: list every chain containing the finding in `chain_keys`, exactly
  matching derived membership. A finding may occur in multiple chains. A member
  of a complete or blocked materialized chain is always `chained`.
- `standalone`: explain why the finding is independently meaningful without a
  second reviewed primitive or why none currently composes with it.
- `unchainable`: explain the transitions examined and why no evidence-backed
  composition was found.
- `blocked`: for a finding outside every materialized chain, name the unresolved
  observations preventing a coherent ordered path, using `existing_unknown_ids`
  or `blocker_keys`. Do not invent an edge to fill a gap.

Each chain is an ordered simple path of at least two distinct reviewed findings,
with exactly one edge for each adjacent pair in member order. Reuse findings
across alternative paths; submit each canonical path only once. Keep alternative
paths as separate chains, rather than combining shared prefixes or suffixes into
a synthetic super-chain. Non-chained findings cannot appear in chain members.

## Adjacent edges and middle-node continuity

For each adjacent A -> B, provide a typed `capability_kind`, concrete `link_key`,
`produced_capability`, and `required_precondition`. Explain exactly what A gives
the attacker and how that same capability and resource satisfies B. Choose a
capability kind from the parser's frozen vocabulary. `other-specific` requires
a concrete namespace-like key. A title, common component, or generic "provides
access" claim is insufficient. Where a file write becomes reboot-time execution,
name the controlled boot resource and prove that specific conversion.

Supply separate `producer_evidence_refs` owned by A and `consumer_evidence_refs`
owned by B. Evidence uses `finding:<finding-id>#<field>` with `root_cause`,
`attacker_position`, `data_flow`, `impact_hypothesis`, or `evidence_summary`.
Optional `supplemental_evidence_refs` use current
`surface:<surface-id>#reach_evidence` or resolved
`unknown:<unknown-id>#evidence` from this worklist. Read the actual retained text:
valid reference syntax proves ownership, not causality. Give each edge a static
confidence from 0 through 10.

For A -> B -> C, explicitly establish middle-node continuity in the chain's
`summary` and edge claims: the incoming capability actually enables B under the
carried attacker/device state, and B's resulting capability enables the outgoing
edge to C. Check credentials, sessions, resource names, authority, namespaces,
and guards at both boundaries. A pair of individually plausible edges is not
proof that one attacker can traverse the whole path.

## Device state and boundary proof

Declare `initial_attacker_position`, supported `initial_evidence_refs`, and one
exact `initial_state` for lifecycle, posture, and authentication. Initial
references must belong to the first finding's attacker-position/evidence fields
or its current referenced surface, with exact structured dive evidence as above. Separate alternative initial states into
separate chains.

For every edge declare `required_state` (an exact value or `any` on each axis)
and `result_state` (an exact value or `unchanged` on each axis). Start from the
initial state and carry it through every edge: each requirement must match the
carried value or explicitly say `any`; each exact result replaces its axis and
`unchanged` preserves it. Do not skip a privilege requirement.

Use `transition_kind` from `direct`, `reboot`, `service-restart`, `factory-reset`,
or `reprovision`. Every non-direct transition requires producer and consumer
evidence explicitly proving that boundary: persistence of the controlled
resource, the triggering event, and its consumption after the boundary. Direct
edges cannot change lifecycle or posture. Unknown reboot behavior becomes a
blocker, not an assumed bridge.

`pre_auth`, aggregate confidence, completeness, canonical IDs, and the
`static-chained` evidence rung are derived by deterministic code; do not submit
them as worker fields. Judge the authority required before the first node.
Stronger authority earned within a proven path differs from authority the
attacker must already possess. Open state/reachability blockers preserve
uncertainty; a static path never establishes runtime reachability.

## Blockers, settlement, and pivots

Reuse relevant current open Stage 4d unknowns in `existing_unknowns` on edges,
with their exact IDs and affected axes from the frozen field mapping. Resolved
unknowns may support supplemental evidence; they cannot be relabeled open.
For a new question, define a `blocker_key`, concrete `question`,
`settling_observation`, one method (`static`, `emulate`, or `hardware`), and
affected axes (`authentication`, `lifecycle`, `posture`, `reachability`). Name
`affected_finding_ids` and/or materialized `affected_edges` using a local
`chain_key` and zero-based `ordinal`. At least one affected reference is
required, and each use must affect its stated finding or edge. Blocked
dispositions must reference blockers affecting their own finding. Imported new
blockers begin open; later dive/decide work settles them and regenerates chains.
Describe future settling observations without performing them now.

Stage 4f pivots are context-only investigative hints. Use IDs only in
`pivot_followup_ids` of `unchainable` or `blocked` dispositions. They cannot be
members, producer/consumer evidence, transition proof, or blocker evidence, and
cannot resurrect a rejected candidate. A newly suspected issue must go through
hunt and fpcheck before becoming a chain node.

## Adversarial review before finalizing

Challenge every proposed path and record the answers in its summary and edge
reasoning, retaining named blockers wherever the evidence cannot answer:

- correlation-not-causation: does A actually produce B's exact required input,
  resource, or authority, rather than merely sharing a component or bug class?
- privilege discontinuity: can the same attacker use each next primitive with
  only the state and capabilities already established?
- reboot magic: what persists, who triggers the boundary, and what consumes the
  resource after restart/reset/reprovisioning?
- same-daemon assumptions: are process identity, namespaces, configuration,
  privileges, and invocation conditions actually compatible?
- confused-deputy claims: does the deputy perform the attacker-directed action
  across the claimed trust boundary, and what guard or binding prevents it?
- pre-auth inflation: is the initial authority evidenced, or did the argument
  quietly assume a session, admin access, local shell, or physical access?
- alternative paths: did you examine independent routes and simpler standalone
  explanations, preserve valid alternatives, and reject duplicate paths?

## Operating boundaries and checkpoints

Keep evidence in the result file, not stdout or dispatch. Do not write SQL.
Do not write to the database, use SQLite, `audit.py put`, generic chain compose,
the importer, checkpoint/transition commands, or completion gates. The
orchestrator and deterministic code own SQL, canonical artifact installation,
receipts, canonical identities, and phase completion. Your DONE is review data,
not authority to mark this generation complete.

Static analysis only. Do not execute target code or binaries. Do not emulate
firmware. Do not exploit or weaponize a path, assign severity or CVSS, claim
dynamic confirmation or runtime reachability, promote to generic findings, or
write disclosure reports. Do not modify the rootfs, acquire firmware, expand
scope, or perform hardware, kernel, or bootloader testing.

Use relative component paths in persisted evidence. Do not persist absolute
host-root or rootfs paths in claims, reasons, keys, or other result text; supplied
absolute paths are access context only.

If time or context prevents completion, return PARTIAL without fabricating
dispositions or edges. Preserve completed work and evidence in the result file
as a checkpoint, and identify completed/total disposition counts and exact
remaining finding IDs in flags. An incomplete checkpoint is not importable.
The orchestrator owns durable checkpoint publication and resumption of the same
immutable global assignment; coverage cannot be shrunk to obtain DONE.

## Return contract

Return exactly one line, and nothing else:

    firmware-chain <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]

Replace `<path>` with `{result_path}`. Rows counts finding dispositions actually
written, not chains, edges, blockers, or SQL writes. DONE requires the complete
valid bound result; PARTIAL means honest unfinished review; FAILED means a valid
bound result cannot be produced. Put concise limitations in flags and the
artifact, never inline analysis or worklist contents.
