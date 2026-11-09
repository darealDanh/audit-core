# Stage 4j Firmware Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic firmware-report pipeline that converts the current verified Stage 4i package into a professional, evidence-cited six-heading Markdown report.

**Architecture:** Extend the Stage 4i verified-package return value with exact image and technical input, then add Stage 4j prepare/record/check/verified-report lifecycle modules. The core freezes one assignment per chain, validates structured worker prose against a versioned style contract, and alone renders and publishes canonical Markdown.

**Tech Stack:** Python 3.10+ standard library, SQLite, canonical JSON, pytest.

**Spec:** `docs/superpowers/specs/2026-11-09-stage4j-firmware-report-design.md`

## Global Constraints

- `audit_core` stays standard-library only and offline.
- `firmware_decide.verified_package` is the sole Stage 4j input boundary.
- Every current chain appears once in ascending Stage 4i rank; no truncation or fallback.
- Workers write strict result JSON only; canonical Markdown is core-owned.
- All immutable files are regular mode `0600`, descriptor-anchored and no-follow.
- Complete rechecks and `verified_report` are read-only and never repair.
- Expected diagnostics are bounded and root-redacted; database failures are exactly `firmware-report: database operation failed`.
- Existing ordinary report workflows remain unchanged.
- Permanent tests must exercise behavior, boundaries and rollback; repo coverage permits zero unexecuted statements.

## Review Focus

- A package with many chains must preserve full rank order without aggregate truncation: Task 3 tests 205 chains and ordinal continuity.
- Concurrent final item records must publish one exact result manifest: Task 6 adds the publication-race test.
- A complete report with a missing artifact must fail without repair: Task 7 tests before/after filesystem state.
- Unicode confusables and Markdown metacharacters must not bypass lint or alter headings: Task 4 tests NFC/casefold and every escaped character.
- An image identity change with unchanged Stage 4i package bytes must create a new report generation: Task 2 tests the sole-boundary extension and generation identity.

---

### Task 1: Verified package report input

**Files:**
- Modify: `audit_core/firmware_decide.py`
- Test: `tests/test_firmware_decide_package.py`
- Test: `tests/test_firmware_decide_coverage.py`

**Interfaces:**
- Produces: `VerifiedFirmwareImageIdentity(image_id, vendor, model, version, role, sha256)`.
- Changes: `VerifiedFirmwareDecisionPackage` adds `technical_input: VerifiedFirmwareDecisionInput` and `image: VerifiedFirmwareImageIdentity`.
- Preserves: Stage 4i canonical package bytes and SHA-256.

- [ ] **Step 1: Write failing package-extension tests**

Add tests that assert the two new fields exactly match the current graph/dive and `cba_images` row; malformed/missing/foreign image rows fail; changing image version changes the returned identity but not stored Stage 4i package bytes; read-only transaction behavior remains intact.

- [ ] **Step 2: Run the focused tests and observe missing fields**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_decide_package.py tests/test_firmware_decide_coverage.py`

- [ ] **Step 3: Implement the extension**

Inside the existing verified-package transaction, retain the `VerifiedFirmwareDecisionInput` used by `_capture_decision`, select and validate the exact image projection, and return both fields. Do not change `_package`, generation identity or installed bytes.

- [ ] **Step 4: Run focused tests**

Expected: both files pass.

- [ ] **Step 5: Commit**

`git commit -m "feat(report): expose verified firmware report input"`

### Task 2: Schema and contracts

**Files:**
- Modify: `audit_core/schema.sql`
- Modify: `audit_core/db.py`
- Test: `tests/test_firmware_report_schema.py`
- Modify: `tests/test_migrate.py`
- Modify: schema-count tests that pin migrations/contracts.

**Interfaces:**
- Produces: `cba_firmware_report_runs`, `cba_firmware_report_items` exactly as the spec.
- Produces constants: `FIRMWARE_REPORT_STATES`, `FIRMWARE_REPORT_SEVERITIES`.

- [ ] **Step 1: Write failing schema and migration tests**

Pin all columns, primary keys, item ordinal uniqueness, status variants, timestamps, result-count consistency, superseded pending/recorded variants, valid severity-independent storage and upgrade from pre-Stage-4j databases.

- [ ] **Step 2: Run tests and observe absent tables/contracts**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_report_schema.py tests/test_migrate.py tests/test_firmware_chain_schema.py tests/test_firmware_dive_schema.py tests/test_firmware_decide_schema.py`

- [ ] **Step 3: Add schema, `TableSpec` validators and two migrations**

Use existing Stage 4i lifecycle validation patterns. Migration only creates the empty tables; no row migration exists.

- [ ] **Step 4: Run focused tests and `audit.py selftest`**

Expected: tests pass and selftest reports two additional migrations, 47 schema tables and 46 contracts.

- [ ] **Step 5: Commit**

`git commit -m "feat(report): add firmware report lifecycle schema"`

### Task 3: Style contract, assignments and preparation

**Files:**
- Create: `audit_core/firmware_report.py`
- Test: `tests/test_firmware_report_input.py`
- Test: `tests/test_firmware_report_prepare.py`
- Test: `tests/test_firmware_report_style.py`

**Interfaces:**
- Produces dataclasses: `ReportPreparationSummary`, `VerifiedFirmwareReport`, `VerifiedFirmwareReportSection`.
- Produces: `prepare(con, run_dir, root, *, image_id=None) -> ReportPreparationSummary`.
- Internal stable helpers: `_style_contract()`, `_style_contract_sha256()`, `_assignment_seeds(package)`, `_generation(package, seeds)`, `_manifest(...)`.

- [ ] **Step 1: Write style-contract identity tests**

Assert the canonical object includes every bound/list/renderer/pre-auth/severity value from the spec and changes hash when any rule changes.

- [ ] **Step 2: Write assignment and generation tests**

Assert exact seed keys, no generation/storage paths in seeds, generation recomputation, exact evidence catalogs, ascending rank order, stable chain IDs, 205-chain continuity, image-identity sensitivity and zero-chain manifest.

- [ ] **Step 3: Write preparation lifecycle tests**

Cover immutable file bytes/mode, SQL publication after installation, rollback, identical re-rank, same-input conflict, stale active supersede, superseded terminal behavior, sibling isolation, current active policy/package behavior and publication race.

- [ ] **Step 4: Run tests and observe missing module**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_report_input.py tests/test_firmware_report_prepare.py tests/test_firmware_report_style.py`

- [ ] **Step 5: Implement style contract, evidence projection, seeds and prepare**

Reuse canonical bytes, stable-file reads, checked install, selector and transaction conventions from `firmware_decide.py`/`firmware_dive.py`. Do not copy helpers unless their existing ownership prevents reuse.

- [ ] **Step 6: Run focused tests**

Expected: all three files pass.

- [ ] **Step 7: Commit**

`git commit -m "feat(report): prepare immutable firmware report assignments"`

### Task 4: Strict result parser and professional prose lint

**Files:**
- Create: `audit_core/firmware_report_results.py`
- Test: `tests/test_firmware_report_results.py`
- Test: `tests/test_firmware_report_lint.py`

**Interfaces:**
- Produces dataclasses matching the exact worker-result schema: `CitedText`, `ReportAnswer`, `ReportResult`, `ValidatedReportResult`.
- Produces: `load(path) -> ReportResult`, `validate(result, assignment_bytes) -> ValidatedReportResult`, `_canonical(validated) -> bytes`.
- Later Task 6 adds `record` to this module.

- [ ] **Step 1: Write hostile JSON and exact-schema tests**

Cover duplicate/unknown/missing keys, invalid UTF-8, symlink, FIFO, nonregular files, huge integers, booleans as integers, result cap, each text/count/citation boundary and canonical retry bytes.

- [ ] **Step 2: Write lint tests for every versioned rule**

Parametrize every banned phrase/token, NFC/casefold bypass, ASCII token boundaries, runtime terms, URLs/paths, emoji ranges, repetition, sentence prefixes, vagueness and all Markdown metacharacters. Assert diagnostics name only item/field/rule.

- [ ] **Step 3: Write citation and severity tests**

Each structured entry needs a nonempty assignment-owned subset; foreign and unresolved refs fail; severity enum and justification are exact; open preconditions remain core-owned.

- [ ] **Step 4: Run tests and observe missing parser**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_report_results.py tests/test_firmware_report_lint.py`

- [ ] **Step 5: Implement parser, structured grammar and lint**

Reuse the Stage 4i bounded hostile reader and JSON hooks. Keep matching algorithms driven by the style-contract constants from Task 3.

- [ ] **Step 6: Run focused tests**

Expected: both files pass.

- [ ] **Step 7: Commit**

`git commit -m "feat(report): validate bounded professional report prose"`

### Task 5: Renderer and pure verification

**Files:**
- Modify: `audit_core/firmware_report.py`
- Test: `tests/test_firmware_report_render.py`
- Test: `tests/test_firmware_report_package.py`

**Interfaces:**
- Produces: `_render(package, assignments, results) -> tuple[bytes, bytes, tuple[VerifiedFirmwareReportSection, ...]]` for Markdown and index bytes.
- Produces: `_verify_complete_inputs(...)` pure helper.
- Produces: `verified_report(con, run_dir, root, *, image_id=None) -> VerifiedFirmwareReport`.

- [ ] **Step 1: Write exact renderer golden tests**

Assert metadata lines; one H1/five H2 per chain; ascending rank; deterministic citation rendering; source-level preamble; pre-auth mapping; severity/provisional line; escaping; no global H1/CVSS/extra heading/internal path. Add zero-chain exact bytes.

- [ ] **Step 2: Write pure verifier tests**

Assert current package, latest ordinal, exact assignments/results/artifacts, missing/differing file refusal, ambiguous ordinal refusal, no old-package fallback and zero writes/mtime changes under complete and read-only calls.

- [ ] **Step 3: Run tests and observe missing renderer/verifier**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_report_render.py tests/test_firmware_report_package.py`

- [ ] **Step 4: Implement renderer, index and pure verification**

Renderer alone writes Markdown syntax. `verified_report` invokes only the pure helper in a read transaction.

- [ ] **Step 5: Run focused tests**

Expected: both files pass.

- [ ] **Step 6: Commit**

`git commit -m "feat(report): render and verify canonical firmware reports"`

### Task 6: Per-item recording

**Files:**
- Modify: `audit_core/firmware_report_results.py`
- Test: `tests/test_firmware_report_import.py`
- Test: `tests/test_firmware_report_races.py`

**Interfaces:**
- Produces: `ReportRecordSummary` and `record(con, run_dir, result_path) -> ReportRecordSummary`.
- Consumes Task 3 assignments/style and Task 4 validation.

- [ ] **Step 1: Write recording state tests**

Cover first/partial/final item, exact item columns, result manifest bytes, zero-item state, idempotent retry, conflict, foreign/stale/superseded assignment, artifact-before-SQL rollback and sibling isolation.

- [ ] **Step 2: Write concurrency tests**

Two final items racing must produce one exact recorded run/results manifest; a record racing stale supersede loses safely; delete/update failures roll back.

- [ ] **Step 3: Run tests and observe missing record**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_report_import.py tests/test_firmware_report_races.py`

- [ ] **Step 4: Implement artifact-first per-item record**

Install canonical result, take `BEGIN IMMEDIATE`, reconstruct assignment/state/bytes, update one item with a guarded write, and transition/install manifest only when all items exist.

- [ ] **Step 5: Run focused tests**

Expected: both files pass.

- [ ] **Step 6: Commit**

`git commit -m "feat(report): record firmware report items atomically"`

### Task 7: Completion lifecycle

**Files:**
- Modify: `audit_core/firmware_report.py`
- Test: `tests/test_firmware_report_gate.py`
- Test: `tests/test_firmware_report_coverage.py`

**Interfaces:**
- Produces: `ReportSummary` and `check(con, run_dir, root, *, image_id=None) -> ReportSummary`.

- [ ] **Step 1: Write completion tests**

Cover pending refusal, recorded completion, exact report/results/index bytes, stale package refusal, latest pending no-fallback, publication rollback, complete pure recheck, missing artifact no-repair and sibling isolation.

- [ ] **Step 2: Write branch-completeness tests**

Exercise every expected exception branch, zero-item completion, timestamp guard, invalid stored rows and database errors; assert no unexecuted statements in both new modules with the repository coverage probe.

- [ ] **Step 3: Run tests and observe missing check**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_report_gate.py tests/test_firmware_report_coverage.py`

- [ ] **Step 4: Implement check**

Recorded path: pure reconstruction, immutable install, lock, repeat, guarded completion. Complete path: pure verification only.

- [ ] **Step 5: Run focused tests and coverage probe**

Expected: both files pass and new modules have zero unexecuted statements.

- [ ] **Step 6: Commit**

`git commit -m "feat(report): complete current firmware reports"`

### Task 8: CLI, brief and installed routing

**Files:**
- Modify: `audit.py`
- Create: `references/briefs/firmware-report-brief.md`
- Modify: `SKILL.md`
- Create: `tests/test_cli_stage4j.py`
- Create: `tests/test_firmware_report_brief.py`
- Modify: `tests/test_brief_templates.py`
- Modify: `tests/test_cli.py`
- Create first: `docs/superpowers/derivations/2026-11-09-stage4j-firmware-report-routing.md`

**Interfaces:**
- Produces CLI verb `firmware-report` with `--prepare|--record|--check` modes.
- Produces exact worker return line and installed route.

- [ ] **Step 1: Write the prose derivation before shipped prose edits**

List exact CLI, brief schema, route order, authority denials, incremental manifest reading and professional-prose rules.

- [ ] **Step 2: Write failing CLI tests**

Cover flag matrix, exit codes, fixed database diagnostic, bounded/root-redacted human and JSON summaries, manifest-only prepare output and no ordinary-report behavior change.

- [ ] **Step 3: Write brief/routing tests**

Derive field names/constants from parser types; assert exact return line, prepare -> fresh per-item writer -> record -> check order, no inline worklist/prose, and installed template rendering.

- [ ] **Step 4: Run tests and observe missing route**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_cli_stage4j.py tests/test_firmware_report_brief.py tests/test_brief_templates.py tests/test_cli.py`

- [ ] **Step 5: Implement CLI and write brief/routing**

Use existing Stage 4i CLI diagnostics/escaping. Reconcile shipped prose against `git diff -U0` in the derivation.

- [ ] **Step 6: Run focused tests**

Expected: all four files pass.

- [ ] **Step 7: Commit**

`git commit -m "feat(report): route bounded firmware report workers"`

### Task 9: Authority boundaries and independent review

**Files:**
- Create: `tests/test_firmware_report_boundary.py`
- Modify only files required by confirmed review findings.

**Interfaces:**
- Pins sole package input and table ownership.

- [ ] **Step 1: Add boundary tests**

Only `firmware_report.py`, `firmware_report_results.py`, `db.py` and `schema.sql` may reference report tables; only `firmware_decide.py` may construct the extended verified package; Stage 4j modules may not call Stage 4g/4h verified helpers directly.

- [ ] **Step 2: Run the complete Stage 4j selection**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_report*.py tests/test_cli_stage4j.py tests/test_firmware_decide_package.py tests/test_migrate.py tests/test_harness.py tests/test_install.py`

- [ ] **Step 3: Request whole-branch review**

Review `379a9d9..HEAD` against the design for Critical/Important correctness, authority, race, migration and professional-output defects.

- [ ] **Step 4: Fix confirmed findings test-first and re-review**

Each fix gets a focused commit and clean scoped re-review.

- [ ] **Step 5: Commit boundary tests**

`git commit -m "test: pin firmware report authority boundaries"`

### Task 10: Durable documentation and final harness

**Files:**
- Modify: `ARCHITECTURE.md`
- Modify: `README.md`
- Modify: `progress.md`
- Modify: `SESSION_HANDOFF.md`
- Modify: `feature_lists.json`

**Interfaces:**
- Records the implemented tree and measured gates; Stage 4j becomes complete.

- [ ] **Step 1: Reconcile present-state docs and inventory**

Record exact files, tables, migrations, CLI, lifecycle, limitations, review result and the real next stage/open prerequisites. Remove Stage 4j from next steps. Do not copy old gate counts.

- [ ] **Step 2: Run manifest/selftest checks**

Run: `python3 audit.py selftest && python3 scripts/harness.py --only manifest && python3 scripts/harness.py --only eol`

- [ ] **Step 3: Commit documentation**

`git commit -m "docs: record Stage 4j firmware report"`

- [ ] **Step 4: Run final full harness**

Run: `make all`

Expected: all eight gates pass; coverage has zero unexecuted statements; real install untouched.

- [ ] **Step 5: Record measured results and rerun affected document gates**

Update only measured counts that changed, commit `docs: record Stage 4j verification`, then rerun at least tests/selftest/lint/eol/manifest/install/coverage/bench through `make all` as required by `AGENTS.md` after final docs.
