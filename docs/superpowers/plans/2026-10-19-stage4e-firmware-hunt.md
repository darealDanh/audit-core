# Stage 4e Firmware Hunt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an evidence-bound firmware `hunt` command whose independent L-sink and L-dark lanes each cover every target firmware unit and produce provenance-checked candidates for later static FP review.

**Architecture:** Extend the Stage 4d prepare/record/check pattern with two immutable lane worklists bound to a canonical completed-surface snapshot. Agents write strict bounded JSON; deterministic modules verify provenance, install content-addressed results, publish batch receipts/coverage/candidates atomically, and own the only completion transitions. Acquisition, triage, and surface changes invalidate image-owned hunt state without affecting sibling images or unrelated phases.

**Tech Stack:** Python 3 standard library, SQLite, dataclasses, argparse, pytest, Markdown dispatch briefs, existing `scripts/harness.py` gates.

**Spec:** `docs/superpowers/specs/2026-10-19-stage4e-firmware-hunt-design.md`

## Global Constraints

- Work from an isolated `stage4e-firmware-hunt` worktree created from current local `main`; do not push or merge without an explicit user request.
- Follow strict TDD: add one failing behavioral test, observe the expected failure, implement the minimum behavior, and rerun the affected suite before each commit.
- Every target regular-file unit receives exactly one decision in both `l-sink` and `l-dark`; hints never reduce either denominator.
- The two lanes have separate worklists, receipts, coverage phases (`hunt-l-sink`, `hunt-l-dark`), pending/complete state, and completion timestamps. Neither lane may satisfy the other.
- `not_applicable` is a result disposition, not a new shared coverage state; publish it as `state='analyzed'` with its retained explanation.
- Result inputs are strict schema-version-1 UTF-8 JSON capped at `8 * 1024 * 1024` bytes; reject duplicate/extra keys and non-finite numbers.
- Do not execute target binaries, emulate firmware, develop exploits, assign final severity, or promote candidates into generic `cba_findings` in this stage.
- Preserve the frozen historical baselines. Applying current `schema.sql` may add the three Stage 4e tables to a baseline copy; never edit `baseline-pre-stage3.sql` or `baseline-stage4b.sql` to pretend they originally contained them.
- Expected SQLite errors render as exactly `hunt: database operation failed`; other expected diagnostics are escaped/capped at 512 ASCII characters plus newline; unexpected programming errors propagate after rollback.
- `make mutate` remains opt-in and outside this plan. Completion requires a fresh `make all` after the final documentation edit.

## Review Focus

1. **Same worklist, changed Stage 4d evidence:** replacing a surface result without changing the surface worklist must change `surface_snapshot_sha256` and invalidate both hunt lanes; Task 2 and Task 6 pin this.
2. **Candidate-free batch ownership:** an imported batch with zero candidates must still have a canonical receipt and pass without scanning retained artifact generations; Tasks 4 and 5 pin this.
3. **Overlapping raw paths across target images:** prepare, record, replacement, invalidation, and check must affect only the selected image-qualified denominator; Tasks 2, 4, 5, and 6 pin this.
4. **Live root changes after preparation:** lane and final checks must require `--root`, detect same-size content changes, and preserve pending/completed state on refusal; Tasks 5 and 7 pin this.
5. **Lane leakage:** a complete L-sink generation, receipt, candidate, or coverage row must never satisfy L-dark or the final two-lane gate; Tasks 4 and 5 pin this.

---

## Execution setup

- [ ] Read the approved spec and this plan from local `main`.
- [ ] Use `superpowers:using-git-worktrees` to create `.worktrees/stage4e-firmware-hunt` on branch `stage4e-firmware-hunt`; verify `.worktrees` is ignored before creation.
- [ ] Run `make all` in the new worktree. Expect the current eight-gate baseline: 2,081 tests, 27 verbs, 24 schema tables / 23 contracted tables, 4 migrations plus both baselines, 6 CRLF / 188 LF after this plan, 43 features / 12 stages / 21 open items, 104 Markdown installs, 0/4,074 uncovered statements, and benchmark 9/19 recall with 39/40 precision. If measured documentation-only counts differ, record the actual baseline instead of copying these estimates.

### Task 1: Add the durable hunt schema and row contracts

**Files:**
- Modify: `audit_core/schema.sql`
- Modify: `audit_core/db.py`
- Modify: `tests/test_firmware_schema.py`
- Modify: `tests/test_migrate.py`

**Interfaces:**
- Produces constants `HUNT_LANES = ("l-sink", "l-dark")`, `HUNT_RUN_STATES = ("pending", "complete")`, and `HUNT_DISPOSITIONS = ("analyzed", "not_applicable", "not_audited")`.
- Produces contracted tables `cba_hunt_runs`, `cba_hunt_receipts`, and `cba_hunt_candidates` with the exact column/key contracts below.
- Consumed by Tasks 2–7 through `db.TABLE_SPECS`, `db.put(..., commit=False)`, and ordinary parameterized SQL.

Exact table contracts:

- `cba_hunt_runs(image_id, lane, manifest_sha256, surface_snapshot_sha256, worklist_path, worklist_sha256, unit_count, batch_count, status, prepared_at, completed_at)`, primary key `(image_id, lane)`.
- `cba_hunt_receipts(image_id, lane, worklist_sha256, batch_path, batch_sha256, result_path, result_sha256, unit_count, candidate_count, recorded_at)`, primary key `(image_id, lane, worklist_sha256, batch_path)`.
- `cba_hunt_candidates(image_id, lane, candidate_id, component_path, title, bug_class, surface_ids, surface_context, attacker_position, input_evidence, data_flow, dangerous_operation, operation_evidence, mitigations_checked, lifecycle_required, posture_required, auth_required, reachability, state_evidence, confidence, impact_hypothesis, blockers, artifact_path, artifact_sha256, recorded_at)`, primary key `(image_id, lane, candidate_id)`.

- [ ] **Step 1: Write failing exact-schema and baseline-upgrade tests.** Assert 27 schema tables and 26 contracted tables; assert the exact ordered columns, required columns, and composite primary keys above. Apply current schema to copies of both frozen baselines, assert the new tables appear, historical rows/timestamps remain byte-for-byte equivalent at the row level, repeated application is idempotent, and `db.connect()` accepts the result.
- [ ] **Step 2: Run schema tests to prove RED.** Run `python3 -m pytest tests/test_firmware_schema.py tests/test_migrate.py -q`; expect missing-table/spec and count failures.
- [ ] **Step 3: Implement additive DDL and validators.** Add all three `CREATE TABLE IF NOT EXISTS` statements to `schema.sql`. Add `TableSpec` entries plus validators that enforce lanes/states, 64-lowercase-hex digests, non-negative SQLite integers, confidence 0–10, existing lifecycle/posture/auth/reachability enums, non-empty evidence fields, canonical `surface_ids` JSON string arrays, and canonical blocker object arrays. Do not add a column migration or edit either baseline: all three tables are additive.
- [ ] **Step 4: Add failing row-validation cases before each validator body.** Pin invalid lanes/states, booleans/nonintegers/overflow counts, malformed hashes, foreign enum values, empty required candidate evidence, confidence outside 0–10, duplicate/non-string surface IDs, malformed/noncanonical JSON, and blockers missing ID/question/settling observation/method. Assert rejected puts leave no row and no active transaction.
- [ ] **Step 5: Run schema and selftest suites to prove GREEN.** Run `python3 -m pytest tests/test_firmware_schema.py tests/test_migrate.py -q && python3 audit.py selftest`; expect exact schema/contract agreement and both baselines accepted.
- [ ] **Step 6: Commit.** Commit as `feat: add firmware hunt state`.

### Task 2: Bind a complete surface snapshot and prepare both lane worklists

**Files:**
- Create: `audit_core/hunt.py`
- Create: `tests/test_hunt_prepare.py`
- Modify: `audit_core/surface.py`
- Modify: `tests/test_surface_gate.py`

**Interfaces:**
- `surface.SurfaceSnapshot(image_id: str, manifest_sha256: str, worklist_sha256: str, snapshot_sha256: str, result_evidence: tuple[tuple[str, str], ...])`.
- `surface.verified_snapshot(con: sqlite3.Connection, run_dir: str | pathlib.Path, *, image_id: str | None = None, require_complete: bool = True) -> SurfaceSnapshot`; it verifies the current Stage 4d generation without changing status or completion time.
- `hunt.LanePreparation(lane: str, worklist_sha256: str, unit_count: int, batch_count: int, worklist_path: str)`.
- `hunt.PreparationSummary(image_id: str, manifest_sha256: str, surface_snapshot_sha256: str, generation: str, lanes: tuple[LanePreparation, ...])`.
- `hunt.prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path, *, image_id: str | None = None, sink_batch_size: int = 50, dark_batch_size: int = 50) -> PreparationSummary`.
- Worklist indexes carry `schema_version`, `image_id`, `lane`, `manifest_sha256`, `surface_snapshot_sha256`, `batch_size`, `unit_count`, and `batches`; batch files carry the same identity plus `batch_id` and `units`.

- [ ] **Step 1: Write failing read-only surface snapshot tests.** Starting from a completed Stage 4d run, assert deterministic digesting under reversed SQL row order, inclusion of canonical result path/hash evidence, exclusion of timestamps/host roots, refusal for pending/stale/noncanonical surface state, and no change to `status` or `completed_at`. Replace one surface result with different evidence but the same Stage 4d worklist and assert the snapshot digest changes after Stage 4d is rechecked.
- [ ] **Step 2: Run the snapshot tests to prove RED.** Run the new snapshot subset in `python3 -m pytest tests/test_surface_gate.py -q`; expect missing `SurfaceSnapshot`/`verified_snapshot`.
- [ ] **Step 3: Refactor Stage 4d verification into the public read-only helper.** Reuse the existing full-denominator, linkage, and canonical-artifact checks. Keep `surface.check` as the sole Stage 4d completion transition by having it consume the verified inputs and then update status; `verified_snapshot(require_complete=True)` must refuse rather than promote pending state.
- [ ] **Step 4: Run all Stage 4d tests to prove GREEN.** Run `python3 -m pytest tests/test_surface_prepare.py tests/test_surface_results.py tests/test_surface_gate.py tests/test_cli_stage4d.py -q`; expect unchanged Stage 4d behavior.
- [ ] **Step 5: Write failing hunt target/root/denominator tests.** Assert unique/explicit target selection, required completed surface state, exact current image-qualified inventory, exact live-root path/kind/size/SHA-256 agreement, active-transaction refusal, and preservation on added/removed/same-size-changed/unreadable files. For two targets sharing every raw path, assert selected-image ownership only.
- [ ] **Step 6: Write failing deterministic dual-lane worklist tests.** With 201 files and unequal batch sizes, assert every unit appears exactly once in each lane, path ordering, exact batch counts, stable canonical bytes under reversed input order, bounded image-scoped surface/diff/ELF/service/component hints, no absolute root/timestamp, independent lane hashes, and refusal for sizes 0/1001.
- [ ] **Step 7: Run prepare tests to prove RED.** Run `python3 -m pytest tests/test_hunt_prepare.py -q`; expect missing `hunt` module/interfaces.
- [ ] **Step 8: Implement canonical snapshot-bound preparation.** Reuse `firmware_tree.scan`, `surface.canonical_manifest`, `surface.atomic_install`, image-qualified inventory helpers, and strict full SQL reads rather than `db.rows` caps. Publish both lane directories beneath `RUN/files/hunt/<generation>/` before one transaction writes both pending `cba_hunt_runs`. Same inputs preserve the generation; changed inputs clear only that image's prior hunt SQL and hunt coverage before publication.
- [ ] **Step 9: Run preparation and Stage 4d regression suites to prove GREEN.** Run `python3 -m pytest tests/test_hunt_prepare.py tests/test_surface_prepare.py tests/test_surface_gate.py tests/test_triage.py -q`; expect pass.
- [ ] **Step 10: Commit.** Commit as `feat: prepare dual-lane firmware hunts`.

### Task 3: Parse and validate lane-specific agent results

**Files:**
- Create: `audit_core/hunt_results.py`
- Create: `tests/test_hunt_results.py`

**Interfaces:**
- Constants `RESULT_SCHEMA_VERSION = 1` and `MAX_RESULT_BYTES = 8 * 1024 * 1024`.
- Immutable records:
  - `Blocker(id: str, question: str, settling_observation: str, method: str)`.
  - `Candidate(candidate_id: str, component_path: str, title: str, bug_class: str, surface_ids: tuple[str, ...], surface_context: str, attacker_position: str, input_evidence: str, data_flow: str, dangerous_operation: str, operation_evidence: str, mitigations_checked: str, lifecycle_required: str, posture_required: str, auth_required: str, reachability: str, state_evidence: str, confidence: int, impact_hypothesis: str, blockers: tuple[Blocker, ...])`.
  - `UnitDecision(path: str, disposition: str, reason: str | None, candidates: tuple[Candidate, ...])`.
  - `BatchResult(schema_version: int, image_id: str, lane: str, manifest_sha256: str, surface_snapshot_sha256: str, worklist_sha256: str, batch_path: str, batch_sha256: str, decisions: tuple[UnitDecision, ...])`.
  - `ValidatedBatch(result: BatchResult, assigned_units: tuple[str, ...], index_path: str)`.
- Functions `load(path: str | pathlib.Path) -> BatchResult`, `validate(con: sqlite3.Connection, run_dir: pathlib.Path, result: BatchResult) -> ValidatedBatch`, and `canonical_bytes(validated: ValidatedBatch) -> bytes`.

- [ ] **Step 1: Write a hand-authored minimal valid result test.** Include one analyzed-clear decision, one evidence-backed not-applicable decision, and one lane-valid candidate with a blocker. Assert typed records and literal canonical JSON bytes without constructing expected output through production serializers.
- [ ] **Step 2: Write failing strict parsing tests.** Pin malformed/oversized/non-UTF-8 JSON, duplicate keys, non-object roots, extra/missing keys, booleans in integer positions, non-finite numbers, invalid schema/lane/digests/identifiers/paths, duplicate units/candidate IDs/surface IDs, and absolute or escaping paths.
- [ ] **Step 3: Write failing provenance and ownership tests.** Pin wrong image/lane/manifest/surface snapshot/worklist/batch digest, omitted/extra/duplicate assigned units, foreign image/component/surface ownership, and stale current run state.
- [ ] **Step 4: Write failing decision/candidate semantic tests.** Pin analyzed-clear without reason, not-applicable without evidence, not-audited without a permitted reason, candidates on not-applicable/not-audited decisions, empty trace/operation/mitigation/state/impact evidence, invalid confidence/enums/blockers, L-sink without attacker influence at a named sink, and L-dark without a named protocol/trust/OTA/heap mechanism.
- [ ] **Step 5: Run result tests to prove RED.** Run `python3 -m pytest tests/test_hunt_results.py -q`; expect missing module/interfaces.
- [ ] **Step 6: Implement strict loading, provenance validation, and canonicalization.** Follow `surface_results.py`'s bounded duplicate-rejecting parser without importing its surface-specific private records. Validate full batch membership before candidate semantics; never accept result-supplied timestamps or artifact provenance.
- [ ] **Step 7: Run result and preparation suites to prove GREEN.** Run `python3 -m pytest tests/test_hunt_results.py tests/test_hunt_prepare.py -q`; expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: validate firmware hunt results`.

### Task 4: Import receipts, coverage, and candidates atomically

**Files:**
- Modify: `audit_core/hunt_results.py`
- Modify: `tests/test_hunt_results.py`
- Create: `tests/test_hunt_import.py`

**Interfaces:**
- `hunt_results.ImportSummary(image_id: str, lane: str, batch_path: str, unit_count: int, candidate_count: int, blocker_count: int, artifact_path: str)`.
- `hunt_results.record(con: sqlite3.Connection, run_dir: str | pathlib.Path, result_path: str | pathlib.Path, *, replace: bool = False) -> ImportSummary`.
- Publishes coverage phase `hunt-l-sink` or `hunt-l-dark`, never plain `hunt`.

- [ ] **Step 1: Write failing first-import tests.** Assert content-addressed canonical installation under `RUN/artifacts/hunt/<generation>/<lane>/<result-sha256>/result.json`, one receipt, one image-qualified coverage row per assigned unit, exact candidate rows with importer-derived provenance, not-applicable mapped to analyzed coverage with retained reason, and only the imported lane set pending.
- [ ] **Step 2: Write failing candidate-free and lane-isolation tests.** Import a zero-candidate batch and assert its receipt exists. Import matching raw paths for two images and both lanes; assert every receipt, candidate, and coverage row remains independently owned.
- [ ] **Step 3: Write failing duplicate/replacement tests.** Duplicate import refuses without `--replace`. Replacement removes only that image/lane/generation/batch's receipt, coverage, and candidates, preserves sibling batches/lanes/images, and returns only that lane to pending.
- [ ] **Step 4: Write failing atomicity/concurrency tests.** Inject read, artifact-install, SQL insert, and commit failures plus a changed worklist/surface snapshot between initial validation and publication. Assert prior SQL remains byte-for-byte equivalent; artifact-first failure may leave only an unreferenced canonical directory.
- [ ] **Step 5: Run import tests to prove RED.** Run `python3 -m pytest tests/test_hunt_import.py tests/test_hunt_results.py -q`; expect missing `record`/receipt behavior.
- [ ] **Step 6: Implement one-transaction publication.** Validate and canonicalize before installation, revalidate current image/surface/worklist/batch under the publication lock, then replace only batch-owned rows and insert receipt/coverage/candidates with `commit=False`. Escape ambiguous legacy raw hunt coverage by refusing before and during publication; never infer image ownership from a raw path.
- [ ] **Step 7: Run all hunt result/import tests to prove GREEN.** Run `python3 -m pytest tests/test_hunt_results.py tests/test_hunt_import.py tests/test_hunt_prepare.py -q`; expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: persist firmware hunt batches atomically`.

### Task 5: Gate each lane and the final two-lane generation

**Files:**
- Modify: `audit_core/hunt.py`
- Create: `tests/test_hunt_gate.py`

**Interfaces:**
- `hunt.LaneCheck(image_id: str, lane: str, manifest_units: int, analyzed: int, not_applicable: int, not_audited: int, receipts: int, candidates: int, blockers: int, complete: bool)`.
- `hunt.HuntCheck(image_id: str, manifest_sha256: str, surface_snapshot_sha256: str, lanes: tuple[LaneCheck, ...], complete: bool)`.
- `hunt.check(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path, *, image_id: str | None = None, lane: str | None = None) -> HuntCheck`.

- [ ] **Step 1: Write failing lane-completion tests.** Assert a complete candidate-bearing lane and a candidate-free lane both pass using receipts, transition only the selected lane to complete, set `completed_at`, and recheck idempotently without scanning unrelated artifact directories.
- [ ] **Step 2: Write failing refusal tests.** Independently pin absent/pending/stale surface state, manifest/snapshot/worklist drift, live-root added/removed/same-size changes, missing/duplicate/foreign receipts, missing/extra coverage, invalid candidate provenance, count disagreement, budget skip, active caller transaction, and read-side SQLite/filesystem errors. Failed checks preserve all statuses/timestamps.
- [ ] **Step 3: Write the 201-unit and lane-leakage regressions.** Prove reads are not capped by `db.MAX_ROWS`; mutate unit 201 and expect refusal. Complete L-sink only and assert L-dark lane check/final check fail; add unrelated plain `hunt` or opposite-lane coverage and assert it is ignored.
- [ ] **Step 4: Write the overlapping-image regression.** Complete two targets with identical raw paths and delimiter/Unicode image IDs. Corrupt one target's receipt/coverage and assert the other target remains checkable and complete.
- [ ] **Step 5: Run gate tests to prove RED.** Run `python3 -m pytest tests/test_hunt_gate.py -q`; expect missing `check` behavior.
- [ ] **Step 6: Implement receipt-backed lane and final checks.** Reverify the live root and call `surface.verified_snapshot(require_complete=True)`. Validate canonical indexes/batches/results, exact receipt ownership, decision/coverage/candidate agreement, and absence of budget skips; repeat under the publication lock before setting completion. The final no-lane path requires both runs complete against identical manifest/surface snapshot identities.
- [ ] **Step 7: Run the complete hunt core suite to prove GREEN.** Run `python3 -m pytest tests/test_hunt_prepare.py tests/test_hunt_results.py tests/test_hunt_import.py tests/test_hunt_gate.py -q`; expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: gate dual-lane firmware hunts`.

### Task 6: Invalidate hunt state at every upstream ownership boundary

**Files:**
- Modify: `audit_core/hunt.py`
- Modify: `audit_core/acquire.py`
- Modify: `audit_core/triage.py`
- Modify: `audit_core/surface.py`
- Modify: `audit_core/surface_results.py`
- Modify: `tests/test_acquire.py`
- Modify: `tests/test_triage.py`
- Modify: `tests/test_surface_prepare.py`
- Modify: `tests/test_surface_results.py`
- Modify: `tests/test_hunt_prepare.py`

**Interfaces:**
- `hunt.invalidate(con: sqlite3.Connection, image_id: str, *, commit: bool = False) -> None` deletes only the selected image's hunt runs, receipts, candidates, and image-qualified `hunt-l-sink`/`hunt-l-dark` coverage.
- Upstream modules invoke `hunt.invalidate` inside their existing transaction only when their selected-image durable state changes.

- [ ] **Step 1: Write failing acquisition invalidation tests.** Seed two complete lanes plus sibling image/unrelated-phase rows. Assert changed target hash/version clears target hunt and surface state atomically; same-provenance replacement and diff-reference changes preserve target hunt. Inject hunt-delete failure and assert acquisition plus all dependent state roll back.
- [ ] **Step 2: Write failing triage invalidation tests.** A changed target manifest clears its surface and hunt state in the triage publication transaction; byte-identical retriage preserves both; reference or legacy-unscoped triage cannot clear the target. Inject failure and assert prior manifest/surface/hunt rows survive.
- [ ] **Step 3: Write failing surface invalidation tests.** Changed Stage 4d preparation or result replacement makes surface pending and clears both target hunt lanes in the same transaction. Same-input/idempotent surface operations preserve completed hunt. Corrupt or mutate only one image and assert sibling-image hunt survives.
- [ ] **Step 4: Run invalidation tests to prove RED.** Run `python3 -m pytest tests/test_acquire.py tests/test_triage.py tests/test_surface_prepare.py tests/test_surface_results.py tests/test_hunt_prepare.py -q`; expect hunt rows to survive upstream changes.
- [ ] **Step 5: Implement the shared image-scoped invalidator and wire upstream transactions.** Avoid circular imports by keeping the SQL-only helper in `hunt.py` free of surface/acquire/triage imports and importing it locally at ownership boundaries if necessary. Refuse ambiguous raw hunt coverage rather than deleting it.
- [ ] **Step 6: Run all upstream and hunt suites to prove GREEN.** Run `python3 -m pytest tests/test_acquire.py tests/test_triage.py tests/test_firmware_diff.py tests/test_surface_prepare.py tests/test_surface_results.py tests/test_surface_gate.py tests/test_hunt_prepare.py tests/test_hunt_results.py tests/test_hunt_import.py tests/test_hunt_gate.py -q`; expect pass.
- [ ] **Step 7: Commit.** Commit as `feat: invalidate dependent firmware hunts`.

### Task 7: Expose the bounded `hunt` CLI

**Files:**
- Modify: `audit.py`
- Create: `tests/test_cli_stage4e.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_harness.py`

**Interfaces:**
- `cmd_hunt(args: argparse.Namespace) -> int` dispatches prepare, record, lane check, or final check.
- Parser adds verb `hunt`, bringing the declared/dispatchable total from 27 to 28.
- Prepare accepts `--run`, required `--root`, optional `--image-id`, `--sink-batch-size`, `--dark-batch-size`, and `--json`.
- Record accepts `--run`, `--record RESULT`, optional `--replace`, and `--json` only.
- Check accepts `--run`, `--check`, required `--root`, optional `--image-id`, `--lane l-sink|l-dark`, and `--json`.

- [ ] **Step 1: Write failing help/mode validation tests.** Pin every flag and all invalid combinations before database I/O: missing root for prepare/check; root/image/lane/batch-size with record; replace without record; lane without check; batch sizes outside 1–1000; record/check mutual exclusion; malformed argparse values. Assert usage errors exit 2 and semantic mode errors exit 1 without creating a missing run.
- [ ] **Step 2: Write failing real prepare/record/check subprocess tests.** Use literal worker result JSON bound to real worklists. Assert exact bounded human lines/JSON keys, independent lane output, final two-lane output, clean stderr on success, and absence of candidate evidence, carved-root absolute paths, or private markers.
- [ ] **Step 3: Write failing error translation tests.** Inject domain, expected filesystem, and SQLite failures and assert exit 1, no traceback, exact database message, escaped/capped other diagnostics, and no partial status changes. Assert unexpected exceptions still propagate in direct `cmd_hunt` tests.
- [ ] **Step 4: Run CLI tests to prove RED.** Run `python3 -m pytest tests/test_cli_stage4e.py tests/test_cli.py tests/test_harness.py -q`; expect missing parser/handler and verb-count failures.
- [ ] **Step 5: Implement imports, parser, handler, and summaries.** Validate mode-specific arguments before `_open_db`, catch only expected `HuntError`/`DbError`, and render dataclasses with aggregate fields only.
- [ ] **Step 6: Run CLI and core suites to prove GREEN.** Run `python3 -m pytest tests/test_cli_stage4e.py tests/test_cli.py tests/test_harness.py tests/test_hunt_prepare.py tests/test_hunt_results.py tests/test_hunt_import.py tests/test_hunt_gate.py -q`; expect pass and 28 dispatchable verbs.
- [ ] **Step 7: Commit.** Commit as `feat: expose firmware hunt CLI`.

### Task 8: Ship the lane-aware worker brief and installed contract

**Files:**
- Create: `references/briefs/hunt-brief.md`
- Create: `tests/test_hunt_brief.py`
- Modify: `tests/test_brief_templates.py`
- Modify: `tests/test_install.py`
- Modify: `SKILL.md`

**Interfaces:**
- Template variables: `run_dir`, `db_path`, `rootfs`, `image_id`, `lane`, `manifest_sha256`, `surface_snapshot_sha256`, `worklist_index`, `batch_path`, and `result_path`.
- Render through existing `audit.py brief --phase hunt --unit <lane>-<batch> ...`; no new brief-renderer code.
- Return contract: `hunt-<lane>-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`.

- [ ] **Step 1: Write failing render/install tests.** Assert the seventh template exists, every variable is required and renders through library/CLI, installed copies resolve `__SKILL_DIR__`, schema references resolve from an installed tree, and no inline dispatch content is required.
- [ ] **Step 2: Write failing prose-contract tests.** For both lanes pin: every unit must be assessed; no hints means no omission; exact lane categories; full input-to-operation trace; mitigation/state evidence; strict result-only output; no SQL writes; no execution/emulation/exploitation/weaponization/severity; budget causes checkpoint/PARTIAL rather than omission; and the one-line return contract.
- [ ] **Step 3: Run brief/install tests to prove RED.** Run `python3 -m pytest tests/test_hunt_brief.py tests/test_brief_templates.py tests/test_install.py -q`; expect missing template/count/routing failures.
- [ ] **Step 4: Write the brief and add the firmware route to `SKILL.md`.** Keep raw evidence in the result artifact, reference `__SKILL_DIR__/audit_core/hunt_results.py` and the assigned paths, and explain lane-specific analysis without duplicating the parser schema field-by-field.
- [ ] **Step 5: Run brief, lint, and install gates to prove GREEN.** Run `python3 -m pytest tests/test_hunt_brief.py tests/test_brief_templates.py tests/test_install.py -q && make lint && make install-smoke`; expect pass and no sentinel survivors.
- [ ] **Step 6: Commit.** Commit as `feat: ship firmware hunt agent brief`.

### Task 9: Reconcile durable documentation, inventory, and final harness

**Files:**
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `progress.md`
- Modify: `SESSION_HANDOFF.md`
- Modify: `feature_lists.json`
- Modify: `docs/superpowers/specs/2026-10-19-stage4e-firmware-hunt-design.md` only if implementation review establishes an actual design correction
- Modify: `docs/superpowers/plans/2026-10-19-stage4e-firmware-hunt.md` only to mark factual execution notes, never to rewrite historical planned steps

**Interfaces:**
- Produces truthful branch-state documentation: Stage 4e implemented and reviewed on `stage4e-firmware-hunt`, integration still pending, no push, and firmware `fpcheck` next.
- Produces measured rather than predicted test, verb, schema, migration, EOL, manifest, install, coverage, and benchmark values.

- [ ] **Step 1: Write failing documentation/inventory checks.** Search for stale `27 verbs`, Stage 4e-next, Stage 4d integration-pending, and Stage 4d-only firmware-boundary claims. Add/adjust manifest assertions so `hunt`, its modules, tests, brief, spec, and plan must resolve from `feature_lists.json`.
- [ ] **Step 2: Update user and architecture documentation.** Document exact prepare/record/lane-check/final-check commands; root requirement; two denominators; result/receipt/candidate ownership; invalidation; not-applicable mapping; error behavior; limitations; and that this is firmware-audit functionality still shipped inside codebase-audit.
- [ ] **Step 3: Reconcile progress, handoff, and feature inventory.** Remove Stage 4e from next steps, name firmware `fpcheck` as next, preserve historical specs/baselines, record inherited triage upsert-only and Stage 4d performance limitations accurately, and retain the missing Asus golden/restructure prerequisites for the overall Stage 4 gate.
- [ ] **Step 4: Run structured documentation gates.** Run `python3 -m json.tool feature_lists.json >/dev/null`, `git diff --check`, `make selftest`, `make lint`, `make eol`, `python3 scripts/harness.py --only manifest`, and `make install-smoke`; expect pass.
- [ ] **Step 5: Run the full affected pytest suite.** Run `python3 -m pytest -q`; expect all tests pass with no warnings/errors. Record the exact count from this run but do not claim completion yet.
- [ ] **Step 6: Run independent review and address every blocking finding with TDD.** Review against the approved spec, this plan, image/lane ownership, transactional rollback, strict parsing, bounded output, and documentation truth. For each code defect, add a reproducing failing test before the fix and rerun the affected/full suites. Commit review fixes separately with specific messages.
- [ ] **Step 7: Run a measurement harness.** Run `make all` from the worktree root and require all eight gates to pass. Record the measured tests, 28 verbs, 27/26 schema counts, migrations/baselines, CRLF/LF, features/stages/open-items, installed Markdown, coverage statements, and benchmark recall/precision/cost in `progress.md` and `SESSION_HANDOFF.md`; never copy the estimates from this plan.
- [ ] **Step 8: Commit final documentation.** Run the structured documentation gates again, then commit as `docs: record Stage 4e firmware hunt`.
- [ ] **Step 9: Run the mandatory exact-committed-tree harness.** Run `make all` after the documentation commit. Require all eight gates to pass with the same recorded measurements; any edit made after this run invalidates it and requires another complete run.
- [ ] **Step 10: Verify clean handoff state.** Run `git status --short --branch`, `git log --oneline main..HEAD`, and `git diff --stat main...HEAD`; expect a clean feature branch containing only Stage 4e work. Do not merge or push.

## Completion and integration gate

Before asking to merge:

- every task commit exists and task-specific suites are green;
- a fresh whole-branch reviewer reports no Critical/Important findings;
- the final committed tree passes `make all` after the last documentation edit;
- `progress.md`, `SESSION_HANDOFF.md`, `ARCHITECTURE.md`, and `feature_lists.json` agree with the actual feature branch;
- Stage 4e remains described as firmware-audit functionality implemented inside the shared repository, not generic hardening and not yet a separately packaged skill;
- `make mutate` is reported as not run unless separately requested; and
- the branch/worktree remains available for explicit user-directed merge or further fixes.
