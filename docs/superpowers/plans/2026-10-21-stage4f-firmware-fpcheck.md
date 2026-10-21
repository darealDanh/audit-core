# Stage 4f Firmware FP-check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a provenance-bound static firmware false-positive review phase that consumes completed Stage 4e candidates, preserves pivots, validates cross-lane deduplication, and publishes dedicated reviewed firmware findings.

**Architecture:** Add a dedicated `audit_core.firmware_fpcheck` prepare/check boundary and `audit_core.firmware_fpcheck_results` strict result importer. The phase snapshots a read-only verified Stage 4e generation, publishes deterministic review batches, stores batch-owned verdicts and pivots atomically, then derives canonical firmware findings only after exact global coverage and duplicate resolution pass.

**Tech Stack:** Python 3 standard library, SQLite, dataclasses, argparse, pytest, Markdown dispatch briefs, and the existing `scripts/harness.py` gates.

**Spec:** [`docs/superpowers/specs/2026-10-21-stage4f-firmware-fpcheck-design.md`](../specs/2026-10-21-stage4f-firmware-fpcheck-design.md)

## Global Constraints

- Stage 4f uses dedicated firmware tables and must not write `cba_findings` or `cba_fp_verdicts`.
- Review is static only: no execution, emulation, exploitation, weaponization, final severity, CVSS, live-PoC claim, chain composition, acquisition decision, or report generation.
- Agents read immutable files and write strict JSON only; deterministic code exclusively owns SQL, canonical artifact installation, and completion transitions.
- Both Stage 4e lanes must be complete against the same still-current image, manifest, surface snapshot, live carved root, and canonical hunt artifacts.
- Candidate identity is always `(image_id, lane, candidate_id)`; raw candidate IDs and raw component paths never imply cross-image or cross-lane ownership.
- `batch_size` is an integer from 1 through 200; an equal-signature cluster is indivisible, and no cluster or emitted batch may exceed 1,000 candidates.
- Result input and canonical output are each capped at exactly `8 * 1024 * 1024` bytes; duplicate JSON keys, invalid UTF-8, non-finite numbers, and booleans in integer positions are rejected.
- Exact `root_cause_key` equality is the only automatic true-positive grouping rule. Different keys remain separate; duplicate chains must terminate at a TRUE_POSITIVE in the same candidate snapshot.
- Every FALSE_POSITIVE owns exactly one evidence-backed pivot. A legitimate no-attacker-controlled-path observation is allowed; a blank pivot is not.
- Artifacts install before one immediate SQL transaction. Failure preserves prior SQL and may leave only an unreferenced immutable artifact.
- Expected domain/filesystem diagnostics are escaped and capped at 512 ASCII characters plus newline; SQLite details use one fixed message. Unexpected exceptions propagate in direct handler tests.
- Documentation reconciliation and a fresh final `make all` are part of completion. `make mutate` remains separate and is not run by this plan.

## File Structure

- `audit_core/schema.sql` — five Stage 4f tables.
- `audit_core/db.py` — Stage 4f enums and table validators.
- `audit_core/hunt.py` — public read-only verified Stage 4e snapshot and downstream invalidation hook.
- `audit_core/firmware_fpcheck.py` — candidate snapshotting, similarity batching, preparation, invalidation, completion, duplicate resolution, and finding derivation.
- `audit_core/firmware_fpcheck_results.py` — strict result records, parsing, semantic validation, canonicalization, and atomic batch import.
- `audit.py` — bounded `fpcheck` CLI.
- `references/briefs/firmware-fpcheck-brief.md` — installed firmware review worker contract.
- `SKILL.md` — firmware Stage 4f routing without changing ordinary source-code `fpcheck` semantics.
- `tests/test_firmware_fpcheck_schema.py` — schema and validator coverage.
- `tests/test_firmware_fpcheck_prepare.py` — verified snapshot and worklist preparation.
- `tests/test_firmware_fpcheck_results.py` — strict parser and semantic result validation.
- `tests/test_firmware_fpcheck_import.py` — atomic import, replacement, and rollback.
- `tests/test_firmware_fpcheck_gate.py` — exact completion, deduplication, pivots, and findings.
- `tests/test_firmware_fpcheck_brief.py` — brief, routing, and installed-tree contract.
- `tests/test_cli_stage4f.py` — CLI modes, summaries, and diagnostics.
- Existing upstream, migration, harness, install, and documentation tests change only where Stage 4f extends their contracts.

## Review Focus

1. **Exactly 8 MiB raw input whose canonical form expands past 8 MiB:** parsing must reject the canonical oversize before artifact installation; Task 5 pins it.
2. **The same `candidate_id` exists in both lanes:** preparation, verdict ownership, replacement, duplicate resolution, and finding contributors must remain distinct by lane; Tasks 3, 4, 6, and 7 pin it.
3. **A duplicate cycle crosses batches:** final check must detect the global cycle without recursion failure or partial finding publication; Task 7 pins it.
4. **Completed hunt SQL is unchanged but the live root drifts:** prepare and check must refuse same-size content changes while preserving Stage 4f state; Tasks 3, 4, and 7 pin it.
5. **Artifact installation succeeds and SQL publication then fails:** existing receipts/verdicts/pivots/findings must remain byte-for-byte equivalent; Tasks 6 and 7 pin it.

---

### Task 1: Reconcile the Stage 4e merge before extending the tree

**Files:**
- Modify: `progress.md`
- Modify: `SESSION_HANDOFF.md`
- Modify: `feature_lists.json`

**Interfaces:**
- Consumes: local `main` merge commit `8119af1` and the measured Stage 4e merged-tree `make all` result.
- Produces: truthful present-state prose saying Stage 4e is merged into local `main`, not pushed, and Stage 4f design/implementation is next; historical Stage 4e spec and plan remain untouched.

- [ ] **Step 1: Prove the stale state is present.** Run `rg -n "stage4e-firmware-hunt|integration (is )?pending|has not been integrated|awaits integration" progress.md SESSION_HANDOFF.md feature_lists.json`; expect current-state matches that contradict merged `main`.
- [ ] **Step 2: Reconcile only changed present-state claims.** Replace feature-branch/integration-pending statements with merge commit `8119af1`, preserve the prior measured 2,925-test/4,946-statement result, remove Stage 4e integration from next steps, and name Stage 4f firmware `fpcheck` with its inherited limitations.
- [ ] **Step 3: Validate structured documentation.** Run `python3 -m json.tool feature_lists.json >/dev/null && git diff --check`; expect exit 0.
- [ ] **Step 4: Run the required fresh merged-state harness.** Run `make all`; expect all eight gates pass. Record only values actually emitted if they differ from the existing Stage 4e measurements.
- [ ] **Step 5: Commit.** Commit as `docs: reconcile Stage 4e merge state`.

### Task 2: Add the dedicated Stage 4f schema and row contracts

**Files:**
- Modify: `audit_core/schema.sql`
- Modify: `audit_core/db.py`
- Create: `tests/test_firmware_fpcheck_schema.py`
- Modify: `tests/test_migrate.py`
- Modify: `tests/test_workspace.py`
- Modify: `tests/test_harness.py`

**Interfaces:**
- Consumes: existing `db.TableSpec`, canonical JSON validation, digest/path/identifier helpers, and idempotent `workspace.apply_schema`.
- Produces: constants `FIRMWARE_FP_RUN_STATES = ("pending", "complete")`, `FIRMWARE_FP_VERDICTS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE")`, and evidence rung `FIRMWARE_FP_EVIDENCE_RUNGS = ("static-reviewed",)`.
- Produces tables and keys:
  - `cba_firmware_fp_runs`, primary key `(image_id)`.
  - `cba_firmware_fp_receipts`, primary key `(image_id, candidate_snapshot_sha256, batch_path)`.
  - `cba_firmware_fp_verdicts`, primary key `(image_id, lane, candidate_id)`.
  - `cba_firmware_pivots`, primary key `(image_id, pivot_id)`.
  - `cba_firmware_findings`, primary key `(image_id, finding_id)`.

- [ ] **Step 1: Write failing fresh-schema tests.** Assert all five exact tables, declared columns, primary keys, required columns, and `TableSpec` registrations. Assert the schema inventory rises from 27/26 to 32 SQLite tables/31 contracted tables without hard-coding timestamps.
- [ ] **Step 2: Write failing baseline migration tests.** Apply the current schema to `baseline-pre-stage3.sql` and `baseline-stage4b.sql`, assert all five tables appear, and reapply twice to prove idempotence and preservation of existing rows.
- [ ] **Step 3: Write failing row-validation tests.** Pin legal minimal rows and reject invalid verdict/status/rung/lane, uppercase or malformed digests, negative/boolean counts, noncanonical JSON arrays, duplicate JSON entries where uniqueness is required, invalid identifiers, absolute/traversing paths in fields whose contract is run-relative, forbidden verdict-specific columns, and missing FALSE_POSITIVE pivot fields.
- [ ] **Step 4: Run schema tests to prove RED.** Run `python3 -m pytest tests/test_firmware_fpcheck_schema.py tests/test_migrate.py tests/test_workspace.py tests/test_harness.py -q`; expect missing-table/contract/count failures.
- [ ] **Step 5: Add the five idempotent DDL declarations and validators.** Keep new tables additive; do not add a column migration because no existing table changes. Use shared helpers where their contracts match and Stage 4f-specific validators where verdict-shape invariants differ.
- [ ] **Step 6: Run schema tests to prove GREEN.** Run the same pytest command; expect pass and 32/31 schema counts.
- [ ] **Step 7: Commit.** Commit as `feat: add firmware fpcheck state`.

### Task 3: Expose a read-only verified Stage 4e snapshot

**Files:**
- Modify: `audit_core/hunt.py`
- Modify: `tests/test_hunt_gate.py`
- Create: `tests/test_firmware_fpcheck_prepare.py`

**Interfaces:**
- Produces immutable records:
  - `hunt.VerifiedHuntLane(lane: str, worklist_path: str, worklist_sha256: str, unit_count: int, batch_count: int)`.
  - `hunt.VerifiedHuntCandidate(lane: str, candidate_id: str, component_path: str, title: str, bug_class: str, surface_ids: tuple[str, ...], surface_context: str, attacker_position: str, input_evidence: str, data_flow: str, dangerous_operation: str, operation_evidence: str, mitigations_checked: str, lifecycle_required: str, posture_required: str, auth_required: str, reachability: str, state_evidence: str, confidence: int, impact_hypothesis: str, blockers: tuple[dict[str, str], ...], artifact_path: str, artifact_sha256: str)`.
  - `hunt.VerifiedHuntSnapshot(image_id: str, manifest_sha256: str, surface_snapshot_sha256: str, lanes: tuple[VerifiedHuntLane, ...], candidates: tuple[VerifiedHuntCandidate, ...])`.
- Produces `hunt.verified_snapshot(con, run_dir, root, *, image_id=None) -> VerifiedHuntSnapshot`, which performs the complete current Stage 4e verification without changing status or timestamps. Candidate artifact paths are verified descendants of `run_dir` and exposed in canonical run-relative POSIX form.
- Preserves `hunt.check(...) -> HuntCheck` by refactoring it to consume the same internal verified inputs before its existing completion transition.

- [ ] **Step 1: Write failing snapshot success tests.** Complete both hunt lanes using canonical result artifacts, call `verified_snapshot`, and assert lane order, full candidate fields, parsed canonical arrays, same-ID candidates in opposite lanes remaining distinct, and zero SQL changes/status changes.
- [ ] **Step 2: Write failing refusal tests.** Independently corrupt the live root with a same-size change, manifest, surface snapshot, lane worklist, batch, receipt, result artifact, coverage, candidate row, status, and image ownership; assert refusal and no writes.
- [ ] **Step 3: Write the 201-unit and candidate-free regressions.** Prove snapshot reads are not capped by `db.MAX_ROWS`, unit 201 corruption is detected, and two completed candidate-free lanes return an empty candidate tuple.
- [ ] **Step 4: Run snapshot tests to prove RED.** Run `python3 -m pytest tests/test_hunt_gate.py tests/test_firmware_fpcheck_prepare.py -q`; expect missing records/helper.
- [ ] **Step 5: Refactor the existing Stage 4e gate around one verifier.** Reuse current canonical artifact, receipt, coverage, candidate, surface, manifest, and live-root checks. Keep the completion update exclusively in `hunt.check`; `verified_snapshot` must refuse pending lanes rather than promote them.
- [ ] **Step 6: Run all Stage 4e suites to prove GREEN.** Run `python3 -m pytest tests/test_hunt_prepare.py tests/test_hunt_results.py tests/test_hunt_import.py tests/test_hunt_gate.py tests/test_cli_stage4e.py -q`; expect unchanged behavior plus passing snapshot tests.
- [ ] **Step 7: Commit.** Commit as `refactor: expose verified firmware hunt snapshot`.

### Task 4: Prepare deterministic firmware review batches

**Files:**
- Create: `audit_core/firmware_fpcheck.py`
- Modify: `tests/test_firmware_fpcheck_prepare.py`

**Interfaces:**
- Produces immutable records:
  - `BatchDescriptor(path: str, sha256: str, candidate_count: int)`.
  - `PreparationSummary(image_id: str, manifest_sha256: str, surface_snapshot_sha256: str, candidate_snapshot_sha256: str, generation: str, worklist_path: str, worklist_sha256: str, candidate_count: int, batch_count: int)`.
- Produces `prepare(con, run_dir, root, *, image_id=None, batch_size=20) -> PreparationSummary` and `invalidate(con, image_id, *, commit=False) -> None`.
- Publishes `RUN/files/firmware-fpcheck/<generation>/index.json` plus `batch-NNNN.json`; artifacts contain no timestamps or absolute root.

- [ ] **Step 1: Write failing candidate-snapshot tests.** Hand-author candidates in reversed SQL insertion order and assert literal stable canonical bytes/digest, both hunt worklist digests, artifact provenance, lane-qualified identity, and exclusion of timestamps/absolute root.
- [ ] **Step 2: Write failing similarity/batching tests.** Assert whitespace/case normalization, sorted surface IDs, equal-signature cross-lane clustering, deterministic cluster and candidate order, target batch size behavior, no cluster splitting, and stable bytes under reversed input order.
- [ ] **Step 3: Write failing boundary tests.** Reject batch sizes 0/201 and booleans; permit an indivisible cluster to exceed the requested size; refuse a cluster or emitted batch above 1,000. Assert one canonical empty batch for zero candidates.
- [ ] **Step 4: Write failing provenance and publication tests.** Require a verified completed hunt and exact live root; assert unique/explicit target selection, same-input idempotence, selected-image replacement, sibling-image isolation with overlapping paths/IDs containing delimiters and Unicode, active-transaction refusal, and rollback on revalidation/SQL failure.
- [ ] **Step 5: Run preparation tests to prove RED.** Run `python3 -m pytest tests/test_firmware_fpcheck_prepare.py -q`; expect missing module/interfaces.
- [ ] **Step 6: Implement canonical snapshotting, clustering, batching, installation, and pending-run publication.** Install all worklist files, begin `BEGIN IMMEDIATE`, repeat the verified hunt/live-root snapshot, re-read installed bytes, invalidate only changed selected-image Stage 4f state, and publish one pending row.
- [ ] **Step 7: Run preparation and Stage 4e regression suites to prove GREEN.** Run `python3 -m pytest tests/test_firmware_fpcheck_prepare.py tests/test_hunt_prepare.py tests/test_hunt_gate.py -q`; expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: prepare firmware fpcheck batches`.

### Task 5: Parse and validate adversarial review results

**Files:**
- Create: `audit_core/firmware_fpcheck_results.py`
- Create: `tests/test_firmware_fpcheck_results.py`

**Interfaces:**
- Constants `RESULT_SCHEMA_VERSION = 1` and `MAX_RESULT_BYTES = 8 * 1024 * 1024`.
- Immutable records:
  - `TruePositive(root_cause_key: str, root_cause: str, dedup_evidence: str, attacker_position: str, data_flow: str, impact_hypothesis: str, component_paths: tuple[str, ...], surface_ids: tuple[str, ...])`.
  - `FalsePositive(refuting_mechanism: str, pivot_id: str, enabled_observation: str, pivot_evidence: str, component_path: str)`.
  - `Duplicate(target_lane: str, target_candidate_id: str, dedup_evidence: str)`.
  - `Decision(lane: str, candidate_id: str, verdict: str, reason: str, attacker_advantage: str, rules_applied: tuple[str, ...], mitigation_analysis: str, confidence: int, true_positive: TruePositive | None, false_positive: FalsePositive | None, duplicate: Duplicate | None)`.
  - `BatchResult(schema_version: int, image_id: str, candidate_snapshot_sha256: str, worklist_sha256: str, batch_path: str, batch_sha256: str, decisions: tuple[Decision, ...])`.
  - `ValidatedBatch(result: BatchResult, assigned_candidates: tuple[tuple[str, str], ...], index_path: str)`.
- Produces `load(path) -> BatchResult`, `validate(con, run_dir, result) -> ValidatedBatch`, and `canonical_bytes(validated) -> bytes`.

- [ ] **Step 1: Write a hand-authored valid-result test.** Include one verdict of each kind, cross-lane duplicate targeting, and literal expected canonical bytes built independently of production serialization. Assert validation is read-only.
- [ ] **Step 2: Write failing strict parser tests.** Pin malformed/non-object/non-UTF-8 JSON, duplicate keys, missing/extra keys, invalid enums/digests/identifiers/paths, duplicate decisions/rules/components/surfaces, non-finite values, integer booleans, raw oversize, and exactly-8-MiB raw input whose canonical bytes exceed 8 MiB.
- [ ] **Step 3: Write failing provenance tests.** Reject wrong image/snapshot/worklist/batch identities, stale pending run, canonical worklist drift, omitted/extra/duplicate assigned candidates, foreign lane/candidate/component/surface ownership, and a same raw candidate ID incorrectly resolved across lanes.
- [ ] **Step 4: Write failing common-verdict semantic tests.** Require non-empty adversarial reason, attacker-advantage conclusion, rules list, mitigation analysis, and confidence 0–10. Reject result timestamps and artifact provenance supplied by the worker.
- [ ] **Step 5: Write failing variant tests.** TRUE_POSITIVE requires only its exact nested fields and owned component/surface arrays; FALSE_POSITIVE requires exactly one complete pivot and no root-cause/duplicate data; DUPLICATE requires an in-snapshot non-self target and evidence but defers transitive/global resolution to final check. Reject multiple or mismatched variant objects.
- [ ] **Step 6: Run result tests to prove RED.** Run `python3 -m pytest tests/test_firmware_fpcheck_results.py -q`; expect missing module/interfaces.
- [ ] **Step 7: Implement bounded duplicate-rejecting loading, typed parsing, ownership validation, and canonicalization.** Reuse proven Stage 4d/4e parsing conventions without importing their phase-specific private records. Validate exact assignment membership before verdict semantics.
- [ ] **Step 8: Run result and preparation suites to prove GREEN.** Run `python3 -m pytest tests/test_firmware_fpcheck_results.py tests/test_firmware_fpcheck_prepare.py -q`; expect pass.
- [ ] **Step 9: Commit.** Commit as `feat: validate firmware fpcheck results`.

### Task 6: Import batch receipts, verdicts, and pivots atomically

**Files:**
- Modify: `audit_core/firmware_fpcheck_results.py`
- Modify: `tests/test_firmware_fpcheck_results.py`
- Create: `tests/test_firmware_fpcheck_import.py`

**Interfaces:**
- Produces `ImportSummary(image_id: str, batch_path: str, assigned_candidates: int, true_positives: int, false_positives: int, duplicates: int, pivots: int, artifact_path: str)`.
- Produces `record(con, run_dir, result_path, *, replace=False) -> ImportSummary`.
- Installs `RUN/artifacts/firmware-fpcheck/<generation>/<result-sha256>/result.json` and derives all SQL provenance/timestamps itself.

- [ ] **Step 1: Write failing first-import tests.** Assert one receipt, one verdict per assigned candidate, one pivot per FALSE_POSITIVE, exact importer-owned artifact provenance, canonical JSON cells, accurate counts, and pending run status.
- [ ] **Step 2: Write failing empty and identity-isolation tests.** Import the canonical empty batch and assert its receipt with zero verdicts. Import opposite-lane same-ID candidates and overlapping-path candidates from two images; assert independent ownership.
- [ ] **Step 3: Write failing duplicate/replacement tests.** Duplicate import refuses without replace. Replacement removes only its image/snapshot/batch receipt, verdicts, and pivots; it preserves sibling batches/images and returns a previously complete selected-image run to pending while removing its derived findings.
- [ ] **Step 4: Write failing atomicity/concurrency tests.** Inject source read, canonical install, each table insert/delete, and commit failures plus candidate snapshot/worklist changes between initial validation and publication. Assert existing SQL remains byte-for-byte equivalent; only an unreferenced canonical artifact may remain.
- [ ] **Step 5: Run import tests to prove RED.** Run `python3 -m pytest tests/test_firmware_fpcheck_import.py tests/test_firmware_fpcheck_results.py -q`; expect missing record/import behavior.
- [ ] **Step 6: Implement artifact-first one-transaction publication.** Validate/canonicalize, install, take `BEGIN IMMEDIATE`, repeat mutable provenance and installed-artifact checks, perform batch-scoped replacement, then insert receipt/verdict/pivot rows with `commit=False` and commit once.
- [ ] **Step 7: Run all preparation/result/import tests to prove GREEN.** Run `python3 -m pytest tests/test_firmware_fpcheck_prepare.py tests/test_firmware_fpcheck_results.py tests/test_firmware_fpcheck_import.py -q`; expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: persist firmware fpcheck batches atomically`.

### Task 7: Resolve duplicates and publish canonical reviewed findings

**Files:**
- Modify: `audit_core/firmware_fpcheck.py`
- Create: `tests/test_firmware_fpcheck_gate.py`

**Interfaces:**
- Produces `FindingSummary(finding_id: str, root_cause_key: str, canonical_lane: str, canonical_candidate_id: str, contributor_count: int)`.
- Produces `FpcheckSummary(image_id: str, candidate_count: int, true_positives: int, false_positives: int, duplicates: int, pivots: int, findings: tuple[FindingSummary, ...], artifact_path: str, complete: bool)`.
- Produces `check(con, run_dir, root, *, image_id=None) -> FpcheckSummary`.
- Derivation rule: resolve every duplicate to a terminal TRUE_POSITIVE; group terminals and direct TRUE_POSITIVEs by exact `root_cause_key`; select lexicographically first `(lane, candidate_id)` as canonical; take scalar title/bug class/root cause/attacker position/data flow/impact/evidence from that canonical reviewed verdict; union and sort contributors/components/surfaces; use the minimum group confidence; set evidence rung exactly `static-reviewed`; derive finding ID from image, candidate snapshot, and root-cause key.

- [ ] **Step 1: Write failing complete-generation tests.** Assert exact receipt/verdict/pivot coverage, deterministic `findings.json`, expected finding rows, conservative minimum confidence, canonical-candidate scalar selection, sorted unions, complete status/timestamp, and idempotent recheck.
- [ ] **Step 2: Write failing zero-finding and grouping tests.** A receipted empty batch completes with zero findings. Multiple TPs with the same exact root-cause key group; different keys remain separate even with equal similarity signatures; same candidate ID across lanes remains distinct.
- [ ] **Step 3: Write failing duplicate-graph tests.** Cover direct and transitive cross-batch/cross-lane duplicates, missing/foreign/self targets, chains ending at FALSE_POSITIVE, and cycles spanning batches. Assert iterative bounded resolution rather than recursion failure.
- [ ] **Step 4: Write failing refusal tests.** Independently pin pending/stale hunt, same-size live-root drift, manifest/surface/worklist/candidate snapshot drift, missing/extra/duplicate receipts or verdicts, result artifact drift, count mismatches, invalid pivots, invalid root-cause groups, active caller transaction, and read-side SQL/filesystem failures. Failed checks preserve prior status/timestamps/findings.
- [ ] **Step 5: Write failure-after-install and concurrency tests.** Change the hunt snapshot or imported verdict under the publication lock and inject finding deletion/insertion/status/commit failures after canonical artifact installation; assert prior SQL is byte-for-byte preserved and only an unreferenced finding artifact may remain.
- [ ] **Step 6: Run gate tests to prove RED.** Run `python3 -m pytest tests/test_firmware_fpcheck_gate.py -q`; expect missing check/derivation behavior.
- [ ] **Step 7: Implement exact global verification, iterative duplicate resolution, deterministic derivation, artifact installation, locked revalidation, and one-transaction completion.** Never trust an existing complete status without rechecking artifacts and derived rows.
- [ ] **Step 8: Run the complete Stage 4f core suite to prove GREEN.** Run `python3 -m pytest tests/test_firmware_fpcheck_schema.py tests/test_firmware_fpcheck_prepare.py tests/test_firmware_fpcheck_results.py tests/test_firmware_fpcheck_import.py tests/test_firmware_fpcheck_gate.py -q`; expect pass.
- [ ] **Step 9: Commit.** Commit as `feat: publish reviewed firmware findings`.

### Task 8: Invalidate Stage 4f at every upstream ownership boundary

**Files:**
- Modify: `audit_core/acquire.py`
- Modify: `audit_core/triage.py`
- Modify: `audit_core/surface.py`
- Modify: `audit_core/surface_results.py`
- Modify: `audit_core/hunt.py`
- Modify: `audit_core/hunt_results.py`
- Modify: `tests/test_acquire.py`
- Modify: `tests/test_triage.py`
- Modify: `tests/test_surface_prepare.py`
- Modify: `tests/test_surface_results.py`
- Modify: `tests/test_hunt_prepare.py`
- Modify: `tests/test_hunt_import.py`
- Modify: `tests/test_hunt_gate.py`

**Interfaces:**
- Consumes: `firmware_fpcheck.invalidate(con, image_id, commit=False)`.
- Produces: atomic same-image invalidation when acquisition, target triage, surface preparation/results, hunt preparation/results, or hunt completion evidence changes; byte-identical operations preserve Stage 4f.

- [ ] **Step 1: Write failing acquisition and triage invalidation tests.** Seed complete Stage 4f state for two images. Changed selected-target provenance/manifest clears only its Stage 4f rows inside the upstream transaction; reference-image changes and byte-identical target operations preserve them; injected delete failure rolls everything back.
- [ ] **Step 2: Write failing surface invalidation tests.** Changed surface preparation or result replacement clears selected-image Stage 4f with hunt invalidation; idempotent operations preserve it; overlapping raw paths and Unicode/delimiter image IDs remain isolated.
- [ ] **Step 3: Write failing hunt invalidation tests.** Changed hunt preparation, batch replacement, or completion evidence clears dependent Stage 4f in the same transaction; unchanged re-import/recheck preserves it. Assert same lane/candidate ID in another image survives.
- [ ] **Step 4: Run upstream suites to prove RED.** Run `python3 -m pytest tests/test_acquire.py tests/test_triage.py tests/test_surface_prepare.py tests/test_surface_results.py tests/test_hunt_prepare.py tests/test_hunt_import.py tests/test_hunt_gate.py -q`; expect Stage 4f rows to survive changed upstream state.
- [ ] **Step 5: Wire local imports at existing transaction boundaries.** Keep the Stage 4f invalidator SQL-only with respect to upstream modules to avoid import cycles. Invoke it only when durable selected-image state actually changes and never commit independently from the caller.
- [ ] **Step 6: Run all upstream and Stage 4f suites to prove GREEN.** Run the Step 4 command plus `tests/test_firmware_fpcheck_prepare.py tests/test_firmware_fpcheck_import.py tests/test_firmware_fpcheck_gate.py`; expect pass.
- [ ] **Step 7: Commit.** Commit as `feat: invalidate dependent firmware fpcheck`.

### Task 9: Expose the bounded firmware `fpcheck` CLI

**Files:**
- Modify: `audit.py`
- Create: `tests/test_cli_stage4f.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_harness.py`

**Interfaces:**
- Produces `cmd_fpcheck(args: argparse.Namespace) -> int` for explicit prepare, record, and check modes.
- Adds parser verb `fpcheck`, raising declared/dispatchable verbs from 28 to 29.
- Prepare accepts `--run`, `--prepare`, required `--root`, optional `--image-id`, `--batch-size`, and `--json`.
- Record accepts `--run`, `--record RESULT`, optional `--replace`, and `--json` only.
- Check accepts `--run`, `--check`, required `--root`, optional `--image-id`, and `--json`.

- [ ] **Step 1: Write failing parser/mode tests.** Pin all flags and reject no mode, multiple modes, missing root for prepare/check, root/image/batch-size with record, replace without record, batch size outside 1–200 or boolean-like malformed input, and mode-specific extras before database I/O. Usage syntax errors exit 2; semantic combinations exit 1 without creating a run.
- [ ] **Step 2: Write failing real subprocess tests.** Prepare, record literal canonical results, and check a real fixture. Assert exact bounded human summaries and JSON keys for candidate-bearing and empty generations, clean stderr on success, 29 dispatchable verbs, and no raw evidence/absolute root/private markers in output.
- [ ] **Step 3: Write failing error-translation tests.** Inject expected domain, filesystem, and SQLite failures; assert exit 1, no traceback, fixed `fpcheck: database operation failed`, and escaped/capped other diagnostics. Assert unexpected exceptions propagate through direct `cmd_fpcheck` calls.
- [ ] **Step 4: Run CLI tests to prove RED.** Run `python3 -m pytest tests/test_cli_stage4f.py tests/test_cli.py tests/test_harness.py -q`; expect missing handler/parser and verb-count failures.
- [ ] **Step 5: Implement imports, argument parser, early mode validation, handler dispatch, and aggregate-only renderers.** Do not change the existing prose workflow name or the generic `cba_fp_verdicts` commands.
- [ ] **Step 6: Run CLI and complete Stage 4f suites to prove GREEN.** Run Step 4 plus all `tests/test_firmware_fpcheck_*.py`; expect pass and 29 dispatchable verbs.
- [ ] **Step 7: Commit.** Commit as `feat: expose firmware fpcheck CLI`.

### Task 10: Ship the firmware review brief and route installed users

**Files:**
- Create: `references/briefs/firmware-fpcheck-brief.md`
- Create: `tests/test_firmware_fpcheck_brief.py`
- Modify: `tests/test_brief_templates.py`
- Modify: `tests/test_install.py`
- Modify: `SKILL.md`

**Interfaces:**
- Template variables: `run_dir`, `db_path`, `rootfs`, `image_id`, `candidate_snapshot_sha256`, `worklist_index`, `batch_path`, and `result_path`.
- Renders through `audit.py brief --phase firmware-fpcheck --unit batch-NNNN ...`; no new renderer implementation.
- Return contract: `firmware-fpcheck-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`.

- [ ] **Step 1: Write failing render/install tests.** Assert the eighth template exists, all eight variables are required, library/CLI rendering works, installed copies resolve `__SKILL_DIR__` and the shared FP-rule reference, and worklist evidence is not inlined in stdout.
- [ ] **Step 2: Write failing method-contract tests.** Pin attacker-advantage first; all 18 HE, 10 PR, 3 CV, and Marginal Gain references; source/evidence reread; cross-lane comparison; exact candidate coverage; true-positive/root-cause, false-positive/pivot, and duplicate-target requirements; and no silent merging.
- [ ] **Step 3: Write failing safety/return tests.** Pin strict result-only JSON, 8 MiB limit, no SQL writes, no execution/emulation/exploitation/weaponization/severity/generic promotion, PARTIAL checkpoint behavior without fabricated verdicts, no absolute-root persistence, and exactly one return-contract line.
- [ ] **Step 4: Run brief/install tests to prove RED.** Run `python3 -m pytest tests/test_firmware_fpcheck_brief.py tests/test_brief_templates.py tests/test_install.py -q`; expect missing template/count/routing failures.
- [ ] **Step 5: Write the brief and update `SKILL.md` routing.** Preserve ordinary source-code `fpcheck`; add an explicit Stage 4f firmware route using `audit.py fpcheck`, the immutable worklist, and the firmware-specific brief. Keep detailed schema in the parser module rather than duplicating every JSON field in prose.
- [ ] **Step 6: Run brief, lint, and install gates to prove GREEN.** Run `python3 -m pytest tests/test_firmware_fpcheck_brief.py tests/test_brief_templates.py tests/test_install.py -q && make lint && make install-smoke`; expect pass, eight templates, and zero sentinel survivors.
- [ ] **Step 7: Commit.** Commit as `feat: ship firmware fpcheck agent brief`.

### Task 11: Reconcile documentation, inventory, review, and the full harness

**Files:**
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `progress.md`
- Modify: `SESSION_HANDOFF.md`
- Modify: `feature_lists.json`
- Modify: `tests/test_harness.py` only for durable inventory/count assertions established by implementation.
- Modify the approved Stage 4f spec only if review proves a real design correction; never rewrite historical planned steps to match implementation after the fact.

**Interfaces:**
- Produces truthful present-state documentation for Stage 4f on its feature branch, including exact commands, ownership, invalidation, non-goals, inherited limits, measured verification, and the real next firmware slice `chain`.
- Produces a `feature_lists.json` Stage 4f stage/feature entry resolving every shipped module, test, brief, spec, and plan.

- [ ] **Step 1: Write failing documentation/inventory checks.** Add manifest assertions for the Stage 4f feature and paths; search for stale Stage 4e-next, 28-verb, seven-template, 27/26-schema, and firmware-fpcheck-unimplemented present-state claims.
- [ ] **Step 2: Update user and architecture documentation.** Document prepare/record/check commands, root requirement, completed-hunt prerequisite, candidate snapshot, batching, strict results, receipts/verdicts/pivots/findings, exact dedup rules, invalidation, diagnostics, dedicated-table boundary, and non-goals.
- [ ] **Step 3: Reconcile progress, handoff, and feature inventory.** Remove Stage 4f from next steps, name `chain` as next, retain triage upsert-only/Stage 4d orphan-scan limitations, preserve the Asus golden and restructure prerequisites, and distinguish deterministic contract verification from deferred paid semantic quality.
- [ ] **Step 4: Run structured documentation gates.** Run `python3 -m json.tool feature_lists.json >/dev/null && git diff --check && make selftest && make lint && make eol && python3 scripts/harness.py --only manifest && make install-smoke`; expect pass. Record measured values, never estimates from this plan.
- [ ] **Step 5: Run the full pytest suite.** Run `python3 -m pytest -q`; expect all tests pass without warnings/errors. Record the exact count but do not claim stage completion yet.
- [ ] **Step 6: Prepare and run an independent whole-branch review.** Review from `git merge-base main HEAD` through `HEAD` against the approved spec, this plan, image/lane/candidate ownership, exact coverage, duplicate graphs, false-positive pivots, transactional rollback, bounded parsing/output, installed behavior, and documentation truth.
- [ ] **Step 7: Address blocking review findings with TDD.** For every Critical/Important code defect, add a reproducing failing test, implement the minimum fix, rerun affected/full suites, and commit review fixes separately. Record nonblocking Minor findings honestly.
- [ ] **Step 8: Run the final measurement harness after all documentation and fixes.** Run `make all` from the feature worktree root and require all eight gates pass. Record exact tests, verbs, schema/contract counts, migrations/baselines, EOL, feature/stage/open-item counts, installed Markdown/sentinels, coverage statements, and benchmark recall/precision/cost in `progress.md` and `SESSION_HANDOFF.md` if changed.
- [ ] **Step 9: Re-run documentation-sensitive verification and commit.** Run `python3 -m json.tool feature_lists.json >/dev/null && git diff --check && make selftest && make lint && make eol && python3 scripts/harness.py --only manifest && make install-smoke`; then commit as `docs: record Stage 4f firmware fpcheck`.
- [ ] **Step 10: Verify the committed tree.** Run `make all` again after the documentation commit. Do not run `make mutate`. Record any measurement drift in a follow-up documentation commit and repeat `make all` until the committed tree and handoff agree.

## Execution Notes

- Work in `.worktrees/stage4f-firmware-fpcheck` on branch `stage4f-firmware-fpcheck`; never implement on `main`.
- Use strict RED → GREEN → REFACTOR cycles for every production behavior. Read [`writing-good-tests.md`](/Users/danhnguyen/.codex/plugins/cache/openai-curated-remote/superpowers/6.4.2/skills/test-driven-development/writing-good-tests.md) before Task 2.
- Maintain the plan-scoped execution ledger under `.superpowers/sdd/2026-10-21-stage4f-firmware-fpcheck/` so work survives compaction and executor changes.
- Preserve unrelated user changes. Never push or merge without explicit user instruction.
