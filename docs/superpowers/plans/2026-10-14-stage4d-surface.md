# Stage 4d Firmware Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an evidence-first firmware `surface` phase that maps dispatchers, handlers, authentication boundaries, device state, and reachability against a complete target manifest with durable unknowns and a hard completion gate.

**Architecture:** Deterministic code verifies the live carved root against the stored target manifest, writes content-addressed work-list batches, validates and atomically imports file-backed agent results, and certifies complete surface coverage. Agents perform the semantic handler and authentication analysis; SQLite stores image-scoped surfaces, unknowns, run provenance, and the existing `cba_coverage` denominator.

**Tech Stack:** Python 3.10+ standard library, SQLite, argparse, pytest, Markdown dispatch templates, existing `scripts/harness.py` gates.

**Spec:** [`../specs/2026-10-14-stage4d-surface-design.md`](../specs/2026-10-14-stage4d-surface-design.md)

## Global Constraints

- Work in an isolated `stage4d-surface` worktree created with `superpowers:using-git-worktrees`; start from the current clean `main` and run `make all` before implementation.
- Follow strict TDD for production behavior: write one real-behavior test, watch the expected failure, implement minimally, then run the focused suite and broader affected suite.
- Standard library only; do not add packages or network requirements.
- The target `cba_firmware_files` manifest is the full surface denominator; ELF, service, and component facts enrich ordering and metadata but never remove a unit.
- Surface preparation accepts only a real acquired image with role `target`; `legacy-unscoped` is never valid.
- Canonical JSON uses UTF-8, `sort_keys=True`, `ensure_ascii=False`, separators `(',', ':')`, and exactly one trailing newline. Host paths and timestamps never enter content identity.
- Preparation re-reads the complete carved root with Stage 4c's fail-closed `scandir` semantics and requires exact path/kind/size/SHA-256 agreement before publishing.
- Default work-list batch size is `50`; valid values are `1..1000`. Result files are capped at `8 * 1024 * 1024` bytes before JSON parsing.
- Work-list and result schema version is integer `1`. SHA-256 fields are exactly 64 lower-case hexadecimal characters. Surface and unknown IDs match `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`.
- Import installs the canonical artifact before opening the SQL transaction. An orphaned artifact is acceptable after SQL failure; a mixed SQL generation is not.
- Import never marks a run complete. Only `surface --check` may change `pending` to `complete`.
- A well-formed open unknown is valid output and does not fail completion; a missing settling question or budget skip does.
- Do not fetch, carve, execute, emulate, hunt vulnerabilities, assign severity, inspect kernels/bootloaders, or create the separate `firmware-audit` tree.
- Reconcile `progress.md`, `SESSION_HANDOFF.md`, `ARCHITECTURE.md`, `README.md`, and `feature_lists.json` when their present-state claims change. Preserve historical plans, derivations, and baselines.
- End with a fresh `make all` after the final documentation edit. `make mutate` remains opt-in and outside this stage.

## Review Focus

1. A root whose paths and sizes match while one file's bytes differ must refuse before replacing any prior work-list or SQL generation; Task 3 pins this with a same-size content mutation.
2. A crafted result that names a valid target component outside its assigned batch must refuse without changing another batch's rows; Task 5 pins batch ownership independently of manifest membership.
3. Replacing acquired target provenance after completed surface analysis must atomically clear the old manifest, run, surfaces, unknowns, and only the old units' `surface` coverage; Task 2 pins success and rollback.
4. Re-importing one batch with `--replace` must not delete surfaces, unknowns, or coverage from a sibling batch; Task 6 pins row ownership across two real batches.
5. Open unknowns must pass completion, while an `unknown` state field with no matching open unknown must fail; Tasks 5 and 7 pin both sides of this contract.

---

## File structure

| File | Responsibility |
|---|---|
| `audit_core/firmware_tree.py` | One fail-closed carved-tree scan that produces immutable regular-file facts for both triage and surface verification. |
| `audit_core/surface.py` | Target resolution, canonical manifest/work-list construction, preparation state, and completion gate. |
| `audit_core/surface_results.py` | Strict result parsing, cross-row validation, canonical artifact installation, and atomic batch import. |
| `audit_core/schema.sql`, `audit_core/db.py` | Three additive table contracts and row-level validation. |
| `audit_core/acquire.py` | Provenance-changing target replacement invalidates the dependent surface generation atomically. |
| `audit.py` | The mutually exclusive prepare/record/check CLI and bounded rendering. |
| `references/briefs/surface-brief.md` | File-backed semantic surface-mapping assignment and R2 return contract. |
| `tests/test_firmware_tree.py` | Shared traversal, hashing, classification, and failure-atomic scan behavior. |
| `tests/test_surface_prepare.py` | Target selection, live-root agreement, canonical batching, idempotence, and stale-generation invalidation. |
| `tests/test_surface_results.py` | Strict result schema, state/unknown linkage, atomic import, replacement isolation, and artifact failures. |
| `tests/test_surface_gate.py` | Complete denominator, budget, provenance, linkage, and completion-state behavior. |
| `tests/test_cli_stage4d.py` | argparse contract, bounded human/JSON output, exit codes, and error translation. |
| `tests/test_surface_brief.py` | Template rendering, dispatch variables, output contract, and phase boundaries. |

### Task 1: Reconcile the already-merged Stage 4c state

**Files:**
- Modify: `progress.md`
- Modify: `SESSION_HANDOFF.md`
- Modify: `feature_lists.json`
- Modify: `docs/superpowers/specs/2026-10-12-stage4c-firmware-diff-design.md`

**Interfaces:**
- Consumes: current `main` history, clean worktree, and the last verified Stage 4c counts already present in the documents.
- Produces: truthful current-state documents that say Stage 4c is merged locally, its worktree/branch is gone, nothing was pushed, and Stage 4d design/implementation is next.

- [ ] **Step 1: Capture the state that the prose must report.** Run `git branch --show-current`, `git rev-parse --short HEAD`, `git status --short`, `git worktree list`, and `git rev-list --left-right --count origin/main...main`; retain their literal results for the edits.
- [ ] **Step 2: Write a failing present-state check.** Run `rg -n "integration pending|remains in \\.worktrees/stage4c|Integrate Stage 4c|shipped on branch" progress.md SESSION_HANDOFF.md feature_lists.json docs/superpowers/specs/2026-10-12-stage4c-firmware-diff-design.md`; expect matches that contradict the captured merged state.
- [ ] **Step 3: Reconcile only present-state claims.** Change branch/head/integration/next-step text and the `main-unpushed` note. Preserve historical task counts, measured Stage 4c harness values, design decisions, and all baselines.
- [ ] **Step 4: Verify the stale claims are gone and structured docs still validate.** Re-run the `rg` command and expect no stale present-state match; run `python3 scripts/harness.py --only manifest --only lint --only eol` and expect all three gates to pass.
- [ ] **Step 5: Run the repository completion contract for the corrected merged state.** Run `make all`; expect all eight default gates to pass with the unchanged Stage 4c behavioral counts apart from the LF file count added by the Stage 4d spec/plan.
- [ ] **Step 6: Commit.** Commit the four documentation files as `docs: reconcile merged Stage 4c state`.

### Task 2: Add the durable surface schema and acquisition invalidation

**Files:**
- Modify: `audit_core/schema.sql`
- Modify: `audit_core/db.py`
- Modify: `audit_core/acquire.py`
- Modify: `tests/test_firmware_schema.py`
- Modify: `tests/test_migrate.py`
- Modify: `tests/test_acquire.py`

**Interfaces:**
- Consumes: `db.TableSpec`, `db.put(..., commit=False)`, `acquire.record(...)`, and the two frozen migration baselines.
- Produces: `cba_surface_runs`, `cba_firmware_surfaces`, and `cba_unknowns`; row validators for all spec enums; atomic invalidation when changed target provenance replaces an image.

- [ ] **Step 1: Write failing exact-schema tests.** Assert 24 schema tables and 23 contracted tables; assert the three tables' column order, required fields, and keys exactly match spec §5. Assert both frozen baselines gain the new tables, preserve their old rows/timestamps, pass `db.connect`, and remain idempotent.
- [ ] **Step 2: Write failing row-validation tests.** Use literal valid rows, then mutate each lifecycle, posture, auth, reachability, run status, unknown field/method/status, non-negative count, hash, and identifier input. Assert invalid writes raise `DbError` and leave no row; pin the signed SQLite integer boundary as existing diff tests do.
- [ ] **Step 3: Run the schema tests to prove RED.** Run `python3 -m pytest tests/test_firmware_schema.py tests/test_migrate.py -q`; expect missing-table/spec failures.
- [ ] **Step 4: Implement the additive DDL and independent `TABLE_SPECS`.** Add constants `SURFACE_RUN_STATES`, `LIFECYCLE_STATES`, `POSTURE_STATES`, `AUTH_STATES`, `REACHABILITY_STATES`, `UNKNOWN_FIELDS`, `UNKNOWN_METHODS`, and `UNKNOWN_STATES`; add `_validate_surface_run`, `_validate_firmware_surface`, and `_validate_unknown`. Reuse the strict SQLite non-negative-integer helper extracted from `_validate_diff` rather than duplicating it.
- [ ] **Step 5: Run schema and migration tests to prove GREEN.** Run `python3 -m pytest tests/test_firmware_schema.py tests/test_migrate.py -q` and `python3 audit.py selftest`; expect exact contract agreement and both baselines accepted.
- [ ] **Step 6: Write failing acquisition invalidation tests.** Seed a completed target surface run with two manifest units, surfaces, unknowns, and `surface` coverage plus unrelated phase/image rows. Assert changed target hash/version clears dependent target rows and only their surface coverage; same-provenance replacement preserves them; diff-reference replacement preserves target state; an injected delete failure rolls back the image replacement and every dependent row.
- [ ] **Step 7: Run the acquisition tests to prove RED.** Run `python3 -m pytest tests/test_acquire.py -q`; expect old surface state to survive changed target replacement.
- [ ] **Step 8: Implement invalidation in `acquire.record`.** Before deleting the changed target manifest, collect its unit paths and delete its `cba_firmware_surfaces`, `cba_unknowns`, `cba_surface_runs`, and `cba_coverage WHERE phase='surface' AND unit IN (...)` in the existing acquisition transaction. Do not touch another image or phase.
- [ ] **Step 9: Run the affected suite to prove GREEN.** Run `python3 -m pytest tests/test_acquire.py tests/test_firmware_schema.py tests/test_migrate.py -q`; expect pass.
- [ ] **Step 10: Commit.** Commit schema, database validation, invalidation, and tests as `feat: add firmware surface state`.

### Task 3: Share one fail-closed carved-tree scanner

**Files:**
- Create: `audit_core/firmware_tree.py`
- Create: `tests/test_firmware_tree.py`
- Modify: `audit_core/triage.py`
- Modify: `tests/test_triage.py`
- Modify: `tests/test_triage_corpus.py`

**Interfaces:**
- Produces: `FirmwareTreeError`; immutable `FileFact(path: pathlib.Path, relative: str, kind: str, size: int, sha256: str, elf: elf.ElfFacts | None)`; `scan(root: str | pathlib.Path) -> tuple[FileFact, ...]`.
- Consumes later: `surface.prepare` uses `scan`; `triage.run` publishes directly from the same facts so both phases agree on path, kind, size, and digest.

- [ ] **Step 1: Write failing scanner tests.** With literal binary/script/config/file fixtures, assert path ordering, classification, byte size, hand-derived SHA-256, and retained ELF facts. Name the production breaks: following symlinks, swallowing `scandir`/iteration/`is_dir`/`lstat`/open/stat races, accepting inconsistent classification, or returning a partial scan.
- [ ] **Step 2: Run the new tests to prove RED.** Run `python3 -m pytest tests/test_firmware_tree.py -q`; expect import failure for the missing module.
- [ ] **Step 3: Implement `firmware_tree.scan`.** Move the traversal, hashing, and kind logic from `triage.py` without changing behavior. Complete all reads before returning; sort only by POSIX relative path; exclude symlinks and nonregular entries; translate every filesystem failure into `FirmwareTreeError` naming the path.
- [ ] **Step 4: Run scanner tests to prove GREEN.** Run `python3 -m pytest tests/test_firmware_tree.py -q`; expect pass.
- [ ] **Step 5: Refactor triage to consume `FileFact`.** Preserve `TriageError` at the public boundary, existing service discovery behavior, one digest per file, atomic publication, and exact summary counts. Add a regression that scanner failure leaves fresh tables empty and retriage preserves prior timestamps and rows.
- [ ] **Step 6: Run all triage/scanner tests.** Run `python3 -m pytest tests/test_firmware_tree.py tests/test_triage.py tests/test_triage_corpus.py -q`; expect pass or only the documented absent-corpus skip.
- [ ] **Step 7: Commit.** Commit as `refactor: share fail-closed firmware tree scanning`.

### Task 4: Prepare deterministic content-addressed surface work lists

**Files:**
- Create: `audit_core/surface.py`
- Create: `tests/test_surface_prepare.py`

**Interfaces:**
- Consumes: `firmware_tree.scan`, `cba_images`, `cba_firmware_files`, `cba_inventory`, `cba_binfacts`, `cba_services`, and `cba_components`.
- Produces: `SurfaceError`; `PreparationSummary(image_id: str, manifest_sha256: str, worklist_sha256: str, unit_count: int, batch_count: int, worklist_path: str)`; `prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path, *, image_id: str | None = None, batch_size: int = 50) -> PreparationSummary`; internal canonical-manifest and atomic-install helpers used by Tasks 6–7.
- Work-list JSON: index keys are `schema_version`, `image_id`, `manifest_sha256`, `batch_size`, `unit_count`, and `batches`; each batch descriptor has `path`, `sha256`, and `unit_count`. Batch keys are `schema_version`, `image_id`, `manifest_sha256`, `batch_id`, and `units`. Paths inside JSON are relative to the work-list directory, avoiding a digest cycle and host-path identity.

- [ ] **Step 1: Write failing target-resolution tests.** Assert implicit unique-target selection; explicit target selection amid ambiguity; and named refusal for missing/ambiguous target, unknown ID, wrong role, `legacy-unscoped`, empty manifest, and active caller transaction. Assert every refusal creates no work-list file or run row.
- [ ] **Step 2: Write failing root-agreement tests.** Seed a stored literal manifest and assert exact success. Independently mutate added, removed, same-size changed content, kind, unreadable file, and target inventory mismatch; assert refusal preserves a prior prepared generation.
- [ ] **Step 3: Write failing canonical work-list tests.** For 201 literal units and `batch_size=50`, assert five ordered batches, every unit exactly once, deterministic byte-identical index/batches under reversed SQL/filesystem order, exact hand-derived hashes, bounded hint fields, absence of absolute root/timestamps, and rejection of batch sizes `0` and `1001`.
- [ ] **Step 4: Run preparation tests to prove RED.** Run `python3 -m pytest tests/test_surface_prepare.py -q`; expect missing module/interfaces.
- [ ] **Step 5: Implement pure target, manifest, hint, and canonical builders.** Convert SQLite rows to plain mappings before pure functions; use full stored manifest rather than bounded `db.rows`; let ELF/service/component hints annotate only matching paths.
- [ ] **Step 6: Implement content-addressed installation and preparation publication.** Install the complete generation under `RUN/files/surface/<worklist-sha256>/`; make same-input preparation idempotent. On a changed digest, clear only that image's surface/unknown rows and `surface` coverage for its prior manifest units, then replace `cba_surface_runs` with `pending` in one transaction.
- [ ] **Step 7: Run preparation and triage suites to prove GREEN.** Run `python3 -m pytest tests/test_surface_prepare.py tests/test_firmware_tree.py tests/test_triage.py -q`; expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: prepare deterministic firmware surface worklists`.

### Task 5: Parse and validate complete agent batch results

**Files:**
- Create: `audit_core/surface_results.py`
- Create: `tests/test_surface_results.py`

**Interfaces:**
- Consumes: a prepared index/batch generation from Task 4.
- Produces: `RESULT_SCHEMA_VERSION = 1`, `MAX_RESULT_BYTES = 8 * 1024 * 1024`, and these immutable records:
  - `SurfaceRecord(surface_id, component_path, entry_point, protocol, dispatch_path, handler, lifecycle_required, posture_required, auth_required, reachability, reach_evidence)` — all fields `str`.
  - `UnknownRecord(id, component_path, surface_id, field, question, settling_observation, method, status, resolution, evidence)` — `surface_id`, `resolution`, and `evidence` are `str | None`; the rest are `str`.
  - `UnitDecision(path: str, state: str, reason: str | None, surfaces: tuple[SurfaceRecord, ...], unknowns: tuple[UnknownRecord, ...])`.
  - `BatchResult(schema_version: int, image_id: str, manifest_sha256: str, worklist_sha256: str, batch_path: str, batch_sha256: str, decisions: tuple[UnitDecision, ...])`.
  - `ValidatedBatch(result: BatchResult, assigned_units: tuple[str, ...], index_path: str)`.
- Produces functions `load(path: str | pathlib.Path) -> BatchResult`, `validate(con: sqlite3.Connection, run_dir: pathlib.Path, result: BatchResult) -> ValidatedBatch`, and `canonical_bytes(validated: ValidatedBatch) -> bytes`.

- [ ] **Step 1: Write a minimal valid-result test.** Use one hand-written batch containing an analyzed no-surface config, an evidenced pre-auth handler, and an evidenced handler with one open posture unknown. Assert parsed typed values and canonical bytes without deriving expected JSON through production helpers.
- [ ] **Step 2: Write failing strict-shape tests.** Pin malformed UTF-8/JSON, non-object top level, unknown/missing keys, booleans where integers/strings are required, duplicate unit/surface/unknown IDs, oversized input, wrong schema version, and empty evidence. Each must raise `SurfaceError` before SQL mutation.
- [ ] **Step 3: Write failing provenance and ownership tests.** Pin wrong image/manifest/work-list/batch digest, omitted/extra/duplicate assigned units, a valid manifest component outside the assigned batch, `not_audited` with no reason, and a `not_audited` unit publishing a surface.
- [ ] **Step 4: Write failing state/unknown linkage tests.** Pin invalid enums, dangling image/surface/component references, incorrect open/resolved payloads, and each `unknown` lifecycle/posture/auth/reachability value without a matching open unknown for the same field. Assert a well-formed open unknown validates.
- [ ] **Step 5: Run parser tests to prove RED.** Run the parsing/validation subset of `python3 -m pytest tests/test_surface_results.py -q`; expect missing module/interfaces.
- [ ] **Step 6: Implement strict parsing and pure validation.** Reject extra keys instead of ignoring them; validate complete batch membership before row semantics; never trust result-supplied timestamps, artifact paths, or hashes.
- [ ] **Step 7: Run parser tests to prove GREEN.** Run the same test subset and expect pass.
- [ ] **Step 8: Commit.** Commit as `feat: validate firmware surface agent results`.

### Task 6: Import one surface batch atomically

**Files:**
- Modify: `audit_core/surface_results.py`
- Modify: `tests/test_surface_results.py`

**Interfaces:**
- Consumes: `ValidatedBatch` and canonical bytes from Task 5, `db.put(..., commit=False)`, and the prepared run from Task 4.
- Produces: `ImportSummary(image_id: str, batch_path: str, unit_count: int, surface_count: int, unknown_count: int, artifact_path: str)`; `record(con: sqlite3.Connection, run_dir: str | pathlib.Path, result_path: str | pathlib.Path, *, replace: bool = False) -> ImportSummary`.

- [ ] **Step 1: Write failing first-import tests.** Assert canonical content-addressed artifact installation, one coverage decision per assigned unit, exact surface/unknown rows with importer-derived artifact provenance, and `cba_surface_runs.status == 'pending'` even when the batch happens to cover every unit.
- [ ] **Step 2: Write failing duplicate/replacement isolation tests.** Import two real batches. Assert duplicate import refuses unchanged without `--replace`; replacing batch A removes/replaces only A's surfaces, unknowns, and coverage while batch B remains byte-for-byte unchanged.
- [ ] **Step 3: Write failing atomicity tests.** Inject artifact creation/write/replace failures and SQL insert/commit failures. Artifact failures create no SQL rows; SQL failures preserve the entire prior SQL generation and may leave only an unreferenced canonical artifact.
- [ ] **Step 4: Run import tests to prove RED.** Run `python3 -m pytest tests/test_surface_results.py -q`; expect missing `record` behavior.
- [ ] **Step 5: Implement artifact installation and one-transaction publication.** Derive artifact path/hash after validation; with `replace`, delete rows only where `component_path` belongs to assigned units and replace only matching `surface` coverage; set run status back to `pending`; rollback every exception and wrap expected SQLite/filesystem failures as `SurfaceError`.
- [ ] **Step 6: Run result and preparation suites to prove GREEN.** Run `python3 -m pytest tests/test_surface_results.py tests/test_surface_prepare.py -q`; expect pass.
- [ ] **Step 7: Commit.** Commit as `feat: persist firmware surface batches atomically`.

### Task 7: Enforce the surface completion gate

**Files:**
- Modify: `audit_core/surface.py`
- Create: `tests/test_surface_gate.py`

**Interfaces:**
- Consumes: current target manifest/run rows, surface coverage, surfaces, unknowns, and artifact provenance.
- Produces: `SurfaceCheck(image_id: str, manifest_units: int, analyzed: int, not_audited: int, surfaces: int, open_unknowns: int, resolved_unknowns: int, complete: bool)`; `check(con: sqlite3.Connection, *, image_id: str | None = None) -> SurfaceCheck`.

- [ ] **Step 1: Write failing completion tests.** Assert a complete two-batch run with an honest open unknown passes, returns literal aggregate counts, changes `pending` to `complete`, and sets `completed_at`; rechecking is idempotent.
- [ ] **Step 2: Write failing refusal tests.** Independently pin absent preparation, wrong target role, current/prepared manifest mismatch, inventory mismatch, missing unit decision, `not_audited(reason='budget')`, invalid/dangling unknown, unknown state without matching question, bad artifact provenance, and a read-side SQLite failure. Assert no failed check changes status or timestamp.
- [ ] **Step 3: Write the scale/bounded-read regression.** Complete 201 units and assert all are counted even though `db.MAX_ROWS` is 200; mutate the 201st unit to missing and assert the gate fails.
- [ ] **Step 4: Run gate tests to prove RED.** Run `python3 -m pytest tests/test_surface_gate.py -q`; expect missing `check` behavior.
- [ ] **Step 5: Implement aggregate validation and completion.** Use uncapped internal SQL for the full denominator, translate `sqlite3.Error` to `SurfaceError`, perform all validation before the transaction that marks complete, and accept well-formed open unknowns.
- [ ] **Step 6: Run all surface-core tests to prove GREEN.** Run `python3 -m pytest tests/test_surface_prepare.py tests/test_surface_results.py tests/test_surface_gate.py -q`; expect pass.
- [ ] **Step 7: Commit.** Commit as `feat: gate firmware surface completeness`.

### Task 8: Expose the bounded `surface` CLI

**Files:**
- Modify: `audit.py`
- Create: `tests/test_cli_stage4d.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_harness.py`

**Interfaces:**
- Consumes: `surface.prepare`, `surface_results.record`, `surface.check`, their summary dataclasses, and `_open_db`.
- Produces: `cmd_surface(args: argparse.Namespace) -> int`; `surface` parser and `HANDLERS['surface']`; 27 declared verbs.

- [ ] **Step 1: Write failing help and mode tests.** Assert help exposes `--run`, `--root`, `--image-id`, `--batch-size`, `--record`, `--check`, `--replace`, and `--json`. Assert prepare is the default; `--record` and `--check` are mutually exclusive; `--root` is required only for prepare; `--replace` is accepted only with record; invalid combinations refuse before opening a missing run.
- [ ] **Step 2: Write failing prepare/record/check subprocess tests.** Exercise real run directories and literal artifacts. Assert exact bounded human lines and JSON keys, stderr cleanliness on success, exit 0 on success, exit 1 with no traceback on named `SurfaceError`/`DbError`, and no raw SQLite error on read corruption.
- [ ] **Step 3: Run CLI tests to prove RED.** Run `python3 -m pytest tests/test_cli_stage4d.py tests/test_cli.py tests/test_harness.py -q`; expect missing verb/parser/handler failures.
- [ ] **Step 4: Implement parser, dispatcher, and rendering.** Validate mode-specific arguments before `_open_db`; use the run's `audit.db`; catch only expected domain/database errors; never print unit lists or agent evidence.
- [ ] **Step 5: Run CLI and selftest to prove GREEN.** Run `python3 -m pytest tests/test_cli_stage4d.py tests/test_cli.py tests/test_harness.py -q` and `python3 audit.py selftest`; expect 27 dispatchable verbs and the updated table counts.
- [ ] **Step 6: Commit.** Commit as `feat: expose firmware surface CLI`.

### Task 9: Ship the file-backed surface agent brief

**Files:**
- Create: `references/briefs/surface-brief.md`
- Create: `docs/superpowers/derivations/2026-10-14-stage4d-surface-brief.md`
- Create: `tests/test_surface_brief.py`
- Modify: `tests/test_brief_templates.py`

**Interfaces:**
- Consumes: `audit.py brief`, placeholders `run_dir`, `db_path`, `rootfs`, `image_id`, `manifest_sha256`, `worklist_index`, `batch_path`, and `result_path`.
- Produces: a renderable `surface` brief whose worker writes one strict JSON result and returns `surface-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`.

- [ ] **Step 1: Write failing render/contract tests.** Render through the real `briefs.render`/`write_brief` path and assert all values appear, no placeholder remains, the R2 line is accepted by `lint-skill`, and the assignment distinguishes evidence leads from conclusions, requires one decision per unit plus explicit unknowns, delegates SQL to the importer, and forbids hunting/execution/inferred listeners.
- [ ] **Step 2: Run brief tests to prove RED.** Run `python3 -m pytest tests/test_surface_brief.py tests/test_brief_templates.py -q`; expect missing-template failures.
- [ ] **Step 3: Derive and write the brief.** Keep the template bounded; reference the batch/result schema instead of duplicating it; make the anti-absence, auth-ordering, state-tuple, reachability-evidence, and open-unknown rules imperative.
- [ ] **Step 4: Run brief and lint tests to prove GREEN.** Run `python3 -m pytest tests/test_surface_brief.py tests/test_brief_templates.py -q` and `python3 scripts/harness.py --only lint`; expect pass.
- [ ] **Step 5: Commit.** Commit as `feat: ship firmware surface agent brief`.

### Task 10: Reconcile the full harness and durable documentation

**Files:**
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `progress.md`
- Modify: `SESSION_HANDOFF.md`
- Modify: `feature_lists.json`
- Modify: `docs/superpowers/specs/2026-10-14-stage4d-surface-design.md`
- Modify only if required by measured output: `scripts/eol-manifest.txt`, `scripts/coverage-allowlist.txt`

**Interfaces:**
- Consumes: the final reviewed implementation tree and fresh measured harness output.
- Produces: installed-user instructions, truthful architecture/state/feature inventory, implemented spec status, real gate measurements, and Stage 4e `hunt` as the next slice.

- [ ] **Step 1: Run the complete focused Stage 4d suite.** Run `python3 -m pytest tests/test_firmware_schema.py tests/test_migrate.py tests/test_acquire.py tests/test_firmware_tree.py tests/test_triage.py tests/test_triage_corpus.py tests/test_surface_prepare.py tests/test_surface_results.py tests/test_surface_gate.py tests/test_cli_stage4d.py tests/test_surface_brief.py tests/test_brief_templates.py -q`; expect pass or only the existing documented corpus skip.
- [ ] **Step 2: Perform the required whole-branch review.** Use `superpowers:requesting-code-review` against the Stage 4d base..HEAD diff. Resolve every Critical/Important issue with a new failing regression test and focused red–green cycle; re-review fixes that alter atomicity, provenance, traversal, or authorization semantics.
- [ ] **Step 3: Update installed-user and architecture documentation.** Document prepare/record/check usage, three tables, 27 verbs, complete denominator, state/unknown model, stale-root refusal, atomicity, invalidation, and explicit non-goals. Do not imply that an audit or benchmark was run.
- [ ] **Step 4: Reconcile present-state records.** Add the shipped Stage 4d feature and implementation paths to `feature_lists.json`; mark the design implemented with the real last implementation commit; update progress/handoff next steps to Stage 4e `hunt`; retain the asus-golden, restructure, mutation, and unpushed-main limitations.
- [ ] **Step 5: Run the full verification harness after the final documentation edit.** Run `make all`; expect all eight default gates to pass. Record the actual test count, verb/table/migration summary, EOL split, feature/stage/open-item counts, install Markdown count, statement coverage, and benchmark summary exactly as emitted.
- [ ] **Step 6: Investigate any gate failure before editing expectations.** A new executed line removes a stale coverage allowlist entry; a genuinely unreachable line needs a reason. Update EOL or manifest expectations only when the tree intentionally changed. Re-run `make all` after every correction until the final tree is green.
- [ ] **Step 7: Commit final reconciliation.** Commit the documentation, inventory, and only genuinely required harness-manifest edits as `docs: record Stage 4d firmware surface`.
- [ ] **Step 8: Verify the committed tree.** Run `git status --short`, `git log --oneline <base>..HEAD`, and one final `make all`; expect a clean worktree and all eight gates green from the exact committed tree.

## Out of scope after this plan

Stage 4e `hunt` owns separate L-sink and L-dark lanes and their non-transferable budgets. Later slices own firmware FP-check, chain, dive, decide, and report. The separate firmware skill tree, asus golden, monorepo/restructure decision, deferred paid benchmark, second indicator snapshot, and mutation-survivor policy remain open unless the operator explicitly starts them.
