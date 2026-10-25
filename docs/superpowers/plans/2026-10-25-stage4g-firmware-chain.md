# Stage 4g Firmware Chain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a provenance-bound firmware `chain` phase that turns completed Stage 4f findings into fully accounted, evidence-backed static attack paths without making severity or runtime claims.

**Architecture:** Add six firmware-only SQLite tables and two focused modules. `firmware_chain.py` owns the verified Stage 4f boundary, immutable worklist, derivation, completion gate, and invalidation; `firmware_chain_results.py` owns bounded hostile-result parsing, semantic validation, canonical identities, and atomic import. The existing `chain` CLI gains explicit firmware prepare/record/check modes while preserving its generic proposal/compose interface.

**Tech Stack:** Python 3 standard library, SQLite, canonical UTF-8 JSON, pytest, existing `audit_core` workspace/artifact helpers and `scripts/harness.py`.

**Spec:** `docs/superpowers/specs/2026-10-25-stage4g-firmware-chain-design.md`

## Global Constraints

- Only current, complete `cba_firmware_findings` rows may become chain nodes; pivots are context-only and never evidence.
- Every Stage 4f finding receives exactly one `chained|standalone|unchainable|blocked` disposition; findings may be reused across chains.
- A chain is an ordered simple path of at least two findings with exactly one evidenced edge per adjacent pair.
- Device-state continuity is mechanical across the frozen lifecycle, posture, authentication, and transition vocabularies.
- `pre_auth`, confidence, completeness, stable IDs, and evidence rung `static-chained` are derived, not trusted from worker JSON.
- All phase artifacts are content-addressed and installed before one atomic SQL publication; failures preserve prior SQL and may leave only unreferenced immutable files.
- Image IDs and machine JSON values remain lossless Unicode; only human output and diagnostics are escaped/capped.
- The package remains standard-library only; generic `cba_findings`, `cba_chains`, and source-code `audit.py chain` behavior remain untouched.
- No severity, CVSS, payout, dynamic reachability, emulation, exploit, or report claim enters Stage 4g.
- Final completion requires documentation reconciliation followed by a fresh repository-root `make all`; `make mutate` remains separate.

## Review Focus

1. **Evidence laundering:** an edge must cite producer-owned and consumer-owned retained fields; foreign findings, unrelated surfaces, open unknown evidence, and all pivot evidence must fail in Task 5.
2. **State/pre-auth inflation:** exact state carry, internally earned session/admin authority, reboot/reset boundaries, and blockers producing `unknown` must be pinned in Tasks 5 and 7.
3. **Coverage with reuse:** every finding gets one truthful disposition while a finding may appear in multiple complete or blocked chains; missing, extra, and contradictory membership must fail in Tasks 5 and 7.
4. **Staleness and isolation:** same-size root drift, changed Stage 4f artifacts, overlapping identifiers across images, and transitive upstream invalidation must fail without harming sibling images in Tasks 2, 3, 7, and 8.
5. **Canonical/atomic publication:** local-key reorder, duplicate semantic identities, Unicode/delimiter IDs, write-lock races, commit failures, and post-install input changes must preserve deterministic bytes and prior durable state in Tasks 4, 6, and 7.

---

### Task 1: Add the six Stage 4g tables and exact row contracts

**Files:**
- Modify: `audit_core/schema.sql`
- Modify: `audit_core/db.py`
- Create: `tests/test_firmware_chain_schema.py`
- Modify: `tests/test_migrate.py`
- Modify: `tests/test_workspace.py`
- Modify: `tests/test_harness.py`

**Interfaces:**
- Produces constants `FIRMWARE_CHAIN_RUN_STATES = ("pending", "complete")`, `FIRMWARE_CHAIN_DISPOSITIONS = ("chained", "standalone", "unchainable", "blocked")`, `FIRMWARE_CHAIN_COMPLETENESS = ("complete", "blocked")`, `FIRMWARE_CHAIN_PRE_AUTH = ("yes", "no", "unknown")`, `FIRMWARE_CHAIN_EVIDENCE_RUNGS = ("static-chained",)`, the frozen capability/state/transition/method/axis vocabularies from the spec, and validators for canonical JSON cells.
- Produces tables, exact columns, and primary keys:
  - `cba_firmware_chain_runs(image_id, manifest_sha256, surface_snapshot_sha256, candidate_snapshot_sha256, fpcheck_artifact_path, fpcheck_artifact_sha256, worklist_path, worklist_sha256, finding_count, surface_count, unknown_count, pivot_count, status, graph_path, graph_sha256, prepared_at, completed_at)`, primary key `(image_id)`.
  - `cba_firmware_chain_receipts(image_id, candidate_snapshot_sha256, worklist_sha256, result_path, result_sha256, disposition_count, blocker_count, chain_count, edge_count, recorded_at)`, primary key `(image_id, candidate_snapshot_sha256)`.
  - `cba_firmware_chain_dispositions(image_id, finding_id, candidate_snapshot_sha256, disposition, explanation, chain_ids, existing_unknown_ids, blocker_ids, pivot_followup_ids, artifact_path, artifact_sha256, recorded_at)`, primary key `(image_id, finding_id)`.
  - `cba_firmware_chain_unknowns(image_id, blocker_id, candidate_snapshot_sha256, question, settling_observation, method, axes, affected_finding_ids, affected_edges, status, artifact_path, artifact_sha256, recorded_at)`, primary key `(image_id, blocker_id)`.
  - `cba_firmware_chains(image_id, chain_id, candidate_snapshot_sha256, title, summary, member_ids, initial_attacker_position, initial_evidence_refs, initial_lifecycle, initial_posture, initial_authentication, pre_auth, confidence, completeness, existing_unknown_ids, blocker_ids, evidence_rung, artifact_path, artifact_sha256, derived_at)`, primary key `(image_id, chain_id)`.
  - `cba_firmware_chain_edges(image_id, chain_id, ordinal, candidate_snapshot_sha256, producer_finding_id, consumer_finding_id, capability_kind, link_key, produced_capability, required_precondition, producer_evidence_refs, consumer_evidence_refs, supplemental_evidence_refs, required_state, result_state, transition_kind, confidence, existing_unknowns, blocker_ids, artifact_path, artifact_sha256, derived_at)`, primary key `(image_id, chain_id, ordinal)`.
- Raises fresh schema totals from 32/31 to 38 SQLite/37 contracted tables; the existing four column migrations remain unchanged.

- [ ] **Step 1: Write fresh-schema and exact-key tests.** Assert every declared column, required column, primary key, and `TableSpec`; assert 38/37 inventory without hard-coding timestamp defaults.
- [ ] **Step 2: Write frozen-baseline tests.** Apply current schema twice to both `baseline-pre-stage3.sql` and `baseline-stage4b.sql`; assert all six tables appear, existing firmware rows survive, and `connect()` accepts the result.
- [ ] **Step 3: Write row-validator tests.** Pin one legal minimal row per table and reject invalid enum values, negative/boolean counts and ordinals, malformed digests, unsafe identifiers/paths, noncanonical or duplicate JSON arrays, missing variant fields, foreign evidence rung, and illegal pending/complete timestamp/provenance combinations.
- [ ] **Step 4: Run RED.** Run `python3 -m pytest tests/test_firmware_chain_schema.py tests/test_migrate.py tests/test_workspace.py tests/test_harness.py -q`; expect missing tables/contracts and old inventory totals.
- [ ] **Step 5: Add additive DDL and validators.** Do not add a column migration: these are new idempotent tables. Keep cross-row graph semantics out of `db.py`; row validators enforce only local shape.
- [ ] **Step 6: Run GREEN.** Run the Task 1 command; expect all tests pass and selftest-compatible 38/37 schema totals.
- [ ] **Step 7: Commit.** Commit as `feat: add firmware chain state`.

### Task 2: Expose a read-only verified Stage 4f finding snapshot

**Files:**
- Modify: `audit_core/firmware_fpcheck.py`
- Modify: `tests/test_firmware_fpcheck_gate.py`
- Create: `tests/test_firmware_chain_prepare.py`

**Interfaces:**
- Produces frozen records:
  - `VerifiedFirmwareFinding` containing every `cba_firmware_findings` semantic field and canonical run-relative artifact provenance.
  - `VerifiedFirmwareSurface` containing every field of a referenced current surface.
  - `VerifiedFirmwareUnknown` containing current relevant unknown status, settlement/evidence fields and provenance.
  - `VerifiedFirmwarePivot` containing current pivot context and provenance, explicitly tagged context-only by the worklist layer.
  - `VerifiedFirmwareFindingsSnapshot(image_id, manifest_sha256, surface_snapshot_sha256, candidate_snapshot_sha256, fpcheck_worklist_sha256, findings_artifact_path, findings_artifact_sha256, findings, surfaces, unknowns, pivots)`.
- Produces `firmware_fpcheck.verified_findings_snapshot(con, run_dir, root, *, image_id=None) -> VerifiedFirmwareFindingsSnapshot`.
- Preserves `firmware_fpcheck.check(...)` by refactoring both callers around one verifier; the snapshot helper never writes, changes timestamps, or completes a pending run.

- [ ] **Step 1: Write success tests.** Complete a real Stage 4f fixture, call the helper through a read-only connection and inside a caller transaction, and assert exact sorted frozen records, parsed canonical arrays, canonical run-relative paths, and zero SQL/timestamp changes.
- [ ] **Step 2: Pin the relevant-unknown union.** Include unknowns selected by referenced surface, component-only unknowns with NULL surface, an overlap selected both ways, unrelated same-image unknowns, and a foreign-image unknown; assert only the exact deduplicated same-image union is returned.
- [ ] **Step 3: Write refusal and scale tests.** Corrupt root bytes at the same size, manifest/surface/hunt/fpcheck worklists, result/finding artifacts, findings, surfaces, unknowns, pivots, ownership and complete status; assert refusal beyond 200 rows and no writes.
- [ ] **Step 4: Run RED.** Run `python3 -m pytest tests/test_firmware_fpcheck_gate.py tests/test_firmware_chain_prepare.py -q`; expect the helper/records to be absent.
- [ ] **Step 5: Refactor one complete Stage 4f verifier.** Reuse the existing reconstruction and live-root checks. Do not call public `check()` from the snapshot helper because it owns completion writes.
- [ ] **Step 6: Run GREEN and Stage 4e/4f regression.** Run `python3 -m pytest tests/test_hunt_gate.py tests/test_firmware_fpcheck_prepare.py tests/test_firmware_fpcheck_results.py tests/test_firmware_fpcheck_import.py tests/test_firmware_fpcheck_gate.py tests/test_firmware_chain_prepare.py -q`.
- [ ] **Step 7: Commit.** Commit as `refactor: expose verified firmware findings snapshot`.

### Task 3: Prepare one immutable global firmware-chain worklist

**Files:**
- Create: `audit_core/firmware_chain.py`
- Modify: `tests/test_firmware_chain_prepare.py`

**Interfaces:**
- Produces `FirmwareChainError`.
- Produces `PreparationSummary(image_id: str, manifest_sha256: str, surface_snapshot_sha256: str, candidate_snapshot_sha256: str, generation: str, worklist_path: str, worklist_sha256: str, finding_count: int, surface_count: int, unknown_count: int, pivot_count: int)`.
- Produces `prepare(con, run_dir, root, *, image_id=None) -> PreparationSummary` and `invalidate(con, image_id, *, commit=False) -> None`.
- Installs exactly `RUN/files/firmware-chain/<worklist-sha256>/worklist.json`, excluding timestamps and absolute host/root paths.

- [ ] **Step 1: Write literal canonical-worklist tests.** Independently construct expected bytes containing exact upstream identities, all finding fields, referenced surfaces, the exact relevant-unknown union, and context-only pivots; assert stable digest under reversed SQL insertion order and Unicode/delimiter image IDs.
- [ ] **Step 2: Write empty/global-scale tests.** Assert zero findings still creates a truthful global worklist; assert 201+ findings/unknowns are retained without a display cap or silent batching/truncation.
- [ ] **Step 3: Write publication/idempotence tests.** Require a complete verified Stage 4f snapshot and live root; assert explicit/unique image selection, same-input timestamp/state preservation, changed-input selected-image replacement, sibling-image survival, and active-transaction refusal.
- [ ] **Step 4: Write artifact/atomicity tests.** Pin parent symlink redirection, installed-byte drift, snapshot change between initial read and publication, SQL/commit failure, and real two-connection write contention; prior SQL survives and only an unreferenced worklist may remain.
- [ ] **Step 5: Run RED.** Run `python3 -m pytest tests/test_firmware_chain_prepare.py -q`; expect missing module/interfaces.
- [ ] **Step 6: Implement canonical projection, guarded content-addressed install, locked revalidation and pending-run publication.** `invalidate` deletes only the selected image's six tables in dependency order and defaults to caller-owned commit.
- [ ] **Step 7: Run GREEN.** Run the Task 3 command plus `tests/test_firmware_fpcheck_gate.py`; expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: prepare firmware chain worklist`.

### Task 4: Parse strict graph results and derive non-circular identities

**Files:**
- Create: `audit_core/firmware_chain_results.py`
- Create: `tests/test_firmware_chain_results.py`

**Interfaces:**
- Constants `RESULT_SCHEMA_VERSION = 1` and `MAX_RESULT_BYTES = 8 * 1024 * 1024`.
- Produces frozen result records:
  - `State(lifecycle: str, posture: str, authentication: str)`.
  - `ExistingUnknownRef(unknown_id: str, axes: tuple[str, ...])`.
  - `AffectedEdgeRef(chain_key: str, ordinal: int)`.
  - `NewBlocker(blocker_key: str, question: str, settling_observation: str, method: str, axes: tuple[str, ...], affected_finding_ids: tuple[str, ...], affected_edges: tuple[AffectedEdgeRef, ...])`.
  - `FindingDisposition(finding_id: str, disposition: str, explanation: str, chain_keys: tuple[str, ...], existing_unknown_ids: tuple[str, ...], blocker_keys: tuple[str, ...], pivot_followup_ids: tuple[str, ...])`.
  - `ChainEdge(producer_finding_id: str, consumer_finding_id: str, capability_kind: str, link_key: str, produced_capability: str, required_precondition: str, producer_evidence_refs: tuple[str, ...], consumer_evidence_refs: tuple[str, ...], supplemental_evidence_refs: tuple[str, ...], required_state: State, result_state: State, transition_kind: str, confidence: int, existing_unknowns: tuple[ExistingUnknownRef, ...], blocker_keys: tuple[str, ...])`.
  - `ChainResult(chain_key: str, title: str, summary: str, member_ids: tuple[str, ...], initial_attacker_position: str, initial_evidence_refs: tuple[str, ...], initial_state: State, edges: tuple[ChainEdge, ...])`.
  - `GraphResult(schema_version: int, image_id: str, candidate_snapshot_sha256: str, worklist_sha256: str, blockers: tuple[NewBlocker, ...], dispositions: tuple[FindingDisposition, ...], chains: tuple[ChainResult, ...])`.
- Produces `load(path) -> GraphResult` with duplicate-key rejection and structural variant validation.
- Produces pure helpers `canonical_blocker_id(...)`, `canonical_chain_id(...)`, and `canonical_bytes(validated) -> bytes`; local `blocker_key`/`chain_key` never enter stable identity.

- [ ] **Step 1: Write one independently serialized valid-result test.** Include reused findings, a blocked chain, a blocked disposition, an existing unknown, a new blocker, a reboot edge, and Unicode identity; assert every frozen record and literal canonical bytes.
- [ ] **Step 2: Write hostile parser tests.** Reject invalid UTF-8, duplicate JSON keys, non-object roots, missing/unknown keys, invalid enums/digests/identifiers/paths/evidence refs, duplicate arrays, non-finite values, boolean integers, raw oversize, and canonical output over 8 MiB.
- [ ] **Step 3: Write identity tests.** Reordering semantic-free arrays and changing local keys/title/summary preserve IDs; changing any semantic edge/state/evidence/blocker field changes the appropriate ID; duplicate semantic blockers/chains under different local keys are rejected; dangling/circular local references fail.
- [ ] **Step 4: Run RED.** Run `python3 -m pytest tests/test_firmware_chain_results.py -q`; expect missing module/types.
- [ ] **Step 5: Implement bounded load, exact typed parsing, ordered blocker-then-chain derivation, and canonical serialization.** Perform no SQL or artifact writes.
- [ ] **Step 6: Run GREEN.** Run the Task 4 command; expect pass.
- [ ] **Step 7: Commit.** Commit as `feat: parse firmware chain results`.

### Task 5: Validate evidence ownership, graph coverage, and state continuity

**Files:**
- Modify: `audit_core/firmware_chain_results.py`
- Modify: `tests/test_firmware_chain_results.py`
- Create: `tests/test_firmware_chain_validation.py`

**Interfaces:**
- Produces immutable SQL-ready semantic records `ValidatedDisposition`, `ValidatedBlocker`, `ValidatedChain`, and `ValidatedEdge`, whose fields are the corresponding Task 1 table columns except importer-owned artifact paths/hashes/timestamps.
- Produces `ValidatedGraph(result: GraphResult, blocker_ids: tuple[tuple[str, str], ...], chain_ids: tuple[tuple[str, str], ...], dispositions: tuple[ValidatedDisposition, ...], blockers: tuple[ValidatedBlocker, ...], chains: tuple[ValidatedChain, ...], edges: tuple[ValidatedEdge, ...])`; local-to-derived ID tuples sort by local key.
- Produces `validate(con, run_dir, result) -> ValidatedGraph`; it is read-only, works on a read-only connection/in caller transaction, and uses the prepared worklist plus current verified Stage 4f SQL/artifacts without live-root access.
- Frozen field-to-axis mapping: recognized Stage 4d state/auth/lifecycle/posture/reachability fields map to their exact axis; all other fields conservatively map to `reachability`.

- [ ] **Step 1: Pin exact finding coverage and reuse.** Accept one finding in multiple chains; reject omitted/extra/foreign findings, duplicate dispositions, non-chained members, incomplete `chained` membership lists, and chain members appearing in `standalone|unchainable|blocked` dispositions.
- [ ] **Step 2: Pin evidence addressing and pivot confinement.** Require producer-owned and consumer-owned finding refs, resolve supplemental surface/resolved-unknown refs, and reject swapped/foreign/unresolved evidence plus pivots in nodes, edges, evidence or blockers. Permit pivot IDs only in unchainable/blocked follow-up lists.
- [ ] **Step 3: Pin edge/path semantics.** Reject singleton paths, repeated members, noncontiguous/wrong endpoints, missing middle transitions, duplicate canonical paths, generic/invalid `other-specific` keys, mismatched capability kind/link key, and empty claim/evidence strings.
- [ ] **Step 4: Pin state carry and pre-auth derivation.** Cover exact/`any` requirements, `unchanged`/exact results, direct lifecycle/posture change refusal, reboot/restart/reset/reprovision evidence, initial evidence ownership, internally earned session/admin producing `yes`, stronger initial auth producing `no`, and any relevant open blocker producing `unknown`.
- [ ] **Step 5: Pin blocker semantics.** Require axes/method/settling observation/affected references; validate existing-unknown axis mapping and status; accept blocked-chain members as `chained`; accept nonmaterialized `blocked` dispositions; reject dangling edge/finding references.
- [ ] **Step 6: Pin ownership/staleness and conservative derivation.** Reject wrong image/snapshot/worklist, changed prepared artifact/current SQL, foreign image identifiers, and worker-supplied derived fields. Assert chain confidence is the minimum of all members/edges, completeness is blocker-derived, and rung is exactly `static-chained`.
- [ ] **Step 7: Run RED.** Run `python3 -m pytest tests/test_firmware_chain_results.py tests/test_firmware_chain_validation.py -q`; expect missing validation behavior.
- [ ] **Step 8: Implement read-only validation and canonical derivation.** Rebuild evidence maps from the immutable worklist/current verified snapshot; do not infer semantic truth from prose beyond frozen types, exact keys, ownership, and adversarially required evidence.
- [ ] **Step 9: Run GREEN.** Run the Task 5 command plus `tests/test_firmware_chain_prepare.py`; expect pass.
- [ ] **Step 10: Commit.** Commit as `feat: validate firmware chain evidence graph`.

### Task 6: Import the canonical graph atomically

**Files:**
- Modify: `audit_core/firmware_chain_results.py`
- Create: `tests/test_firmware_chain_import.py`

**Interfaces:**
- Produces `ImportSummary(image_id: str, finding_count: int, disposition_count: int, blocker_count: int, chain_count: int, edge_count: int, complete_chains: int, blocked_chains: int, artifact_path: str)`.
- Produces `record(con, run_dir, result_path, *, replace=False) -> ImportSummary`.
- Installs `RUN/artifacts/firmware-chain/<generation>/<result-sha256>/result.json`; all SQL timestamps and artifact provenance are importer-owned.

- [ ] **Step 1: Write first-import and empty-result tests.** Assert one receipt, exact disposition/blocker/chain/edge rows, canonical JSON cells, accurate counts and pending run; assert a receipted empty Stage 4f generation imports zero graph rows.
- [ ] **Step 2: Write identity/isolation tests.** Import Unicode/delimiter IDs and overlapping finding/surface/pivot/local keys in sibling images; assert lossless values and no cross-image collision.
- [ ] **Step 3: Write duplicate/replacement tests.** Refuse duplicate import without replace; replacement removes exactly the selected image/current generation graph and prior completion artifact/status while preserving siblings; changed local keys with identical semantic IDs remain deterministic.
- [ ] **Step 4: Write atomicity/race tests.** Inject source read, install, each delete/insert, and commit failure; mutate worklist/current Stage 4f evidence after initial validation; hold a real competing write lock. Assert prior SQL byte equivalence and caller/competitor transaction ownership.
- [ ] **Step 5: Run RED.** Run `python3 -m pytest tests/test_firmware_chain_import.py tests/test_firmware_chain_validation.py -q`; expect missing record behavior.
- [ ] **Step 6: Implement artifact-first publication.** Validate/canonicalize, install, take `BEGIN IMMEDIATE`, repeat mutable provenance/ownership/installed-byte checks, replace current selected-image rows, insert receipt and graph rows, leave run pending, commit once.
- [ ] **Step 7: Run GREEN.** Run Tasks 3–6 firmware-chain suites together; expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: persist firmware chain graph atomically`.

### Task 7: Reconstruct and complete canonical firmware chains

**Files:**
- Modify: `audit_core/firmware_chain.py`
- Create: `tests/test_firmware_chain_gate.py`

**Interfaces:**
- Produces `ChainSummary(chain_id: str, member_count: int, edge_count: int, completeness: str, pre_auth: str, confidence: int)`.
- Produces `FirmwareChainSummary(image_id: str, finding_count: int, disposition_count: int, blocker_count: int, complete_chains: int, blocked_chains: int, chains: tuple[ChainSummary, ...], artifact_path: str, complete: bool)`.
- Produces `check(con, run_dir, root, *, image_id=None) -> FirmwareChainSummary` and deterministic `RUN/artifacts/firmware-chain/<generation>/<graph-sha256>/chains.json`.

- [ ] **Step 1: Write successful completion tests.** Reconstruct all result bytes and receipt-owned rows, assert deterministic graph artifact, exact full finding coverage, reused memberships, edge order/state carry, derived pre-auth/confidence/completeness/rung, run completion and idempotent no-write recheck.
- [ ] **Step 2: Write blocked/empty tests.** A fully receipted empty generation completes with zero chains; a graph containing only standalone/unchainable/blocked dispositions completes; coherent blocked chains persist without becoming `complete`.
- [ ] **Step 3: Write corruption/refusal tests.** Independently corrupt every receipt/disposition/blocker/chain/edge field, count, canonical result/worklist/finding artifact, relevant surface/unknown/pivot, live root and upstream status; assert the check catches rows beyond 200 and preserves prior state.
- [ ] **Step 4: Write publication-race/atomicity tests.** Mutate Stage 4f evidence or imported graph under the completion lock; inject graph delete/insert/status/commit failure and real lock contention; assert previous SQL/timestamps/graph remain exact, with at most an orphan immutable artifact.
- [ ] **Step 5: Run RED.** Run `python3 -m pytest tests/test_firmware_chain_gate.py -q`; expect missing check/derivation behavior.
- [ ] **Step 6: Implement full reconstruction, graph installation, locked revalidation, and one-transaction completion.** Never trust a stored complete status without rebuilding current evidence and comparing canonical rows/artifacts.
- [ ] **Step 7: Run GREEN.** Run every `tests/test_firmware_chain_*.py` plus all Stage 4f suites; expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: complete static firmware chains`.

### Task 8: Invalidate Stage 4g from every Stage 4f ownership change

**Files:**
- Modify: `audit_core/firmware_fpcheck.py`
- Modify: `audit_core/firmware_fpcheck_results.py`
- Modify: `tests/test_firmware_chain_prepare.py`
- Modify: `tests/test_firmware_chain_import.py`
- Modify: `tests/test_firmware_chain_gate.py`
- Modify: selected existing Stage 4b–4f invalidation tests where transitive assertions belong

**Interfaces:**
- `firmware_fpcheck.invalidate(...)` locally imports and calls `firmware_chain.invalidate(..., commit=False)` in the same caller transaction.
- Stage 4f batch replacement and finding completion call the Stage 4g invalidator whenever durable selected-image review evidence truly changes.
- Byte-identical Stage 4f operations preserve Stage 4g; Stage 4f rollback restores Stage 4g; sibling images always survive.

- [ ] **Step 1: Write direct invalidation RED.** Complete Stage 4g, then change Stage 4f preparation, imported result/pivot/verdict, or canonical findings; assert all six selected-image Stage 4g tables clear atomically and sibling state survives.
- [ ] **Step 2: Write idempotence/rollback RED.** Same-input Stage 4f prepare/record/check preserves completed Stage 4g and timestamps. Inject Stage 4f failure after invalidation and assert both stages roll back together.
- [ ] **Step 3: Write transitive RED.** Change target acquisition, target triage, surface prepare/result, hunt prepare/result/completion and prove existing Stage 4f invalidation transitively clears Stage 4g; reference/supplemental or byte-identical changes preserve it.
- [ ] **Step 4: Run RED.** Run all Stage 4b–4g invalidation-focused suites; expect stale Stage 4g rows to survive incorrectly.
- [ ] **Step 5: Wire local imports at the narrow Stage 4f boundaries.** Avoid importing Stage 4g into every earlier phase; preserve existing transaction ownership and circular-import safety.
- [ ] **Step 6: Run GREEN.** Run all Stage 4b–4g suites; expect pass.
- [ ] **Step 7: Commit.** Commit as `feat: invalidate stale firmware chains atomically`.

### Task 9: Add bounded firmware modes to the existing `chain` CLI

**Files:**
- Modify: `audit.py`
- Create: `tests/test_cli_stage4g.py`
- Modify: `tests/test_chains.py`
- Modify: `tests/test_cli_stage3.py`

**Interfaces:**
- Preserves generic `audit.py chain --db DB [--json]` and `--compose ...` behavior.
- Adds firmware modes exactly:
  - `chain --run RUN --prepare --root ROOT [--image-id ID] [--json]`
  - `chain --run RUN --record RESULT [--replace] [--json]`
  - `chain --run RUN --check --root ROOT [--image-id ID] [--json]`
- Firmware handlers expose only fixed scalar provenance/count fields and reusable artifact paths; check adds `chain_count` without serializing per-chain details.

- [ ] **Step 1: Write parser/mode RED.** Pin generic compatibility; require exactly one firmware mode when `--run` is used; reject firmware/generic flag mixtures and invalid root/image/replace combinations before database access; preserve argparse syntax exit 2 versus semantic exit 1.
- [ ] **Step 2: Write delegation/output RED.** Mock prepare/record/check exact calls and scalar whitelists; assert successful stderr empty, human output root-redacted/ASCII/capped, JSON lossless for Unicode IDs/paths, and no findings/edges/blocker prose leaks.
- [ ] **Step 3: Write error RED.** Assert fixed `chain: database operation failed` for SQLite anywhere in the expected chain and bounded diagnostics for domain/filesystem errors; active transactions roll back; unexpected exceptions propagate after cleanup.
- [ ] **Step 4: Run RED.** Run `python3 -m pytest tests/test_cli_stage4g.py tests/test_chains.py tests/test_cli_stage3.py -q`; expect missing firmware modes.
- [ ] **Step 5: Refactor `cmd_chain` into an early validated firmware route plus unchanged generic route.** Add local module imports at file scope and reuse proven bounded-output helpers without lossy machine escaping.
- [ ] **Step 6: Run GREEN and selftest.** Run the Task 9 command and `python3 audit.py selftest`; expect 29 declared/dispatchable verbs and 38/37 tables.
- [ ] **Step 7: Commit.** Commit as `feat: expose firmware chain CLI`.

### Task 10: Ship the firmware-chain worker brief and installed routing

**Files:**
- Create: `references/briefs/firmware-chain-brief.md`
- Create: `tests/test_firmware_chain_brief.py`
- Modify: `tests/test_brief_templates.py`
- Modify: `tests/test_install.py`
- Modify: `SKILL.md`
- Modify: `ARCHITECTURE.md` only for durable interface documentation that becomes true in this task

**Interfaces:**
- Adds brief phase `firmware-chain` with required variables `run_dir`, `db_path`, `rootfs`, `image_id`, `candidate_snapshot_sha256`, `worklist_path`, and `result_path`.
- Worker returns exactly `firmware-chain <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`; rows count finding dispositions.
- Installed `SKILL.md` routes Stage 4g prepare -> one strongest global worker -> record -> check while preserving ordinary source-code chain instructions.

- [ ] **Step 1: Write template/routing RED.** Pin exact placeholder set, file-backed dispatch without evidence inlining, path binding, installed presence, rendered filename, and separate generic/firmware routes.
- [ ] **Step 2: Write methodology RED.** Require every disposition; reusable findings; adjacent typed link/evidence; middle-node continuity; state carry/reboot proof; blockers and settlement; pivot context-only language; no severity/runtime/exploit claims; strict result-only JSON and no worker SQL/artifact ownership.
- [ ] **Step 3: Write adversarial-review RED.** Require explicit challenges for correlation-not-causation, privilege discontinuity, reboot magic, same-daemon assumptions, confused-deputy claims, pre-auth inflation, and alternative paths.
- [ ] **Step 4: Run RED.** Run `python3 -m pytest tests/test_firmware_chain_brief.py tests/test_brief_templates.py tests/test_install.py -q`; expect missing template/routing.
- [ ] **Step 5: Write the brief and route.** Keep the brief complete but file-backed; the orchestrator prompt carries paths, not raw worklist content.
- [ ] **Step 6: Run GREEN plus workflow prose/install regressions.** Run the Task 10 command plus `tests/test_skill_lint.py tests/test_workflow_prose.py`; expect pass.
- [ ] **Step 7: Commit.** Commit as `feat: ship firmware chain agent brief`.

### Task 11: Reconcile the full stage, review it, and run the final harness

**Files:**
- Modify: `progress.md`
- Modify: `SESSION_HANDOFF.md`
- Modify: `ARCHITECTURE.md`
- Modify: `feature_lists.json`
- Modify: `docs/superpowers/specs/2026-10-25-stage4g-firmware-chain-design.md` only if implementation-approved refinements must be recorded
- Modify: `docs/superpowers/plans/2026-10-25-stage4g-firmware-chain.md` only to mark/report execution truth without rewriting history

**Interfaces:**
- Produces truthful present-state documentation: Stage 4g implemented on `stage4g-firmware-chain`, integration still pending until explicitly merged, no push, and firmware `dive` next.
- Preserves the Asus golden, paid Stage 4 gate, separate firmware skill tree, monorepo/submodule decision, triage upsert-only snapshots, and Stage 4d orphan-scan limitation.

- [ ] **Step 1: Run all focused Stage 4g and upstream regression suites.** Record exact commands and measured outcomes; fix failures before proceeding.
- [ ] **Step 2: Run an independent whole-branch review.** Review `main...HEAD` for Critical/Important correctness, provenance, atomicity, stale-evidence, output, installation, and generic-chain compatibility defects. Fix findings with focused RED/GREEN tests and re-review until no Critical/Important remains.
- [ ] **Step 3: Reconcile all four durable state documents.** Add Stage 4g feature/stage entries and exact paths/verbs; remove `chain` from next steps; name `dive`; preserve historical specs, plans, baselines, measurements and limitations.
- [ ] **Step 4: Validate structured documentation.** Run `python3 -m json.tool feature_lists.json >/dev/null`, manifest-focused tests, `git diff --check`, and stale-state searches; expect success and no contradictory present-state claims.
- [ ] **Step 5: Run the authoritative final harness after the final documentation edit.** Run `make all` from the worktree root; require all eight gates. Record only emitted test, verb, table, migration, EOL, manifest, install, coverage and benchmark values. Do not copy prior counts.
- [ ] **Step 6: State optional gates honestly.** Record that `make mutate`, the paid semantic audit/milestone rerun, Asus golden and indicator snapshot did not run unless they actually did.
- [ ] **Step 7: Commit final documentation.** Commit as `docs: record Stage 4g firmware chain`.
- [ ] **Step 8: Verify clean handoff.** Run `git status --short --branch`, `git log --oneline main..HEAD`, and `git diff --stat main...HEAD`; expect a clean unmerged feature branch containing only Stage 4g work.

## Completion Criteria

- Every current Stage 4f finding is truthfully disposed, reusable across chains, and never silently omitted.
- Every accepted adjacent transition has typed matching capability/link identity, producer/consumer-owned evidence, mechanically continuous state, and explicit blockers.
- Pivots cannot become nodes or evidence; current unknowns and new blockers remain settleable and provenance-bound.
- Derived chains are deterministic, image-isolated, static-only, and atomically invalidated with changed Stage 4f evidence.
- Generic source-code chain behavior remains compatible.
- A fresh whole-branch reviewer reports no Critical/Important issue.
- Final reconciled `make all` passes all eight gates; `make mutate` remains separately reported.

