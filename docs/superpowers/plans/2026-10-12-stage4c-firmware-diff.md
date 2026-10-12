# Stage 4c Firmware Diff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compare an acquired target firmware image with its CVE-affected reference, preserve both images' facts without key collisions, and turn the vendor's patch into evidence-backed sibling-sweep leads.

**Architecture:** Extend the validated SQLite contract with image-scoped firmware manifests, collision-free composite keys, and durable diff rows. `audit_core.firmware_diff` performs a deterministic hash-manifest comparison and writes a content-addressed artifact; a rendered agent brief performs semantic fix analysis and reuses the existing observation, pattern, and sweep machinery.

**Tech Stack:** Python 3.10+, stdlib only (`sqlite3`, `hashlib`, `json`, `pathlib`, `tempfile`, `os`, `dataclasses`); pytest.

**Spec:** [`2026-10-12-stage4c-firmware-diff-design.md`](../specs/2026-10-12-stage4c-firmware-diff-design.md)

## Global Constraints

- `audit_core` remains stdlib-only, has no network access, and keeps `pyproject.toml` at `dependencies = []` and `requires-python = ">=3.10"`.
- `~/Documents/Offsec/Opswat/Devices/` is read-only. Corpus tests may read it; every database and artifact they create belongs under pytest `tmp_path`.
- `diff` consumes acquired, already-carved and already-triaged images. It does not fetch, carve, emulate, map handlers, inspect kernels/bootloaders, or begin broad vulnerability hunting.
- `cba_inventory` remains the generic target coverage denominator. Diff-reference triage must not write, delete, or replace any of its rows.
- Existing Stage 4b rows survive migration. A NULL legacy `image_id` becomes the literal `legacy-unscoped`; migrations are idempotent and transactional.
- The orchestrator never receives an inline file-diff dump. It receives bounded counts and a file path; agents read the content-addressed manifest from disk.
- Do not run a paid audit or the deferred Stage 2/3 benchmark reruns. `make all` may score the existing benchmark database read-only.
- Never modify `tests/goldens/*/matches.json`, `tests/goldens/*/rejections.json`, or an existing `docs/baselines/` file.
- Write the diff-brief anti-absence derivation before the shipped brief and reconcile it with `git diff -U0`.
- Follow `AGENTS.md`: reconcile all current-state documents after the final code change, then run a fresh `make all`. `make mutate` remains opt-in and outside this plan.

## Review Focus

1. A Stage 4b database with NULL-scoped rows and original timestamps must migrate without data loss, and a failure rebuilding the second table must roll back the first. Task 1 pins both cases.
2. A diff-reference tree sharing every relative path with the target must add its own manifest/binfact/service rows while leaving `cba_inventory` byte-for-byte unchanged. Task 2 pins this.
3. A run with multiple target/reference pairs must refuse implicit selection; explicit IDs must be supplied together and must have the correct roles and matching vendor/model. Tasks 4 and 5 pin this.
4. A Unicode path and a corpus larger than `db.MAX_ROWS` must compare deterministically without truncation or locale-dependent ordering. Task 4 pins this.
5. If replacement fails after a prior diff exists, the prior database rows and referenced manifest must remain usable; an unreferenced content-addressed generation is acceptable. Task 5 pins this.

---

## File Structure

| File | Responsibility |
|---|---|
| `audit_core/schema.sql` | Final composite-key firmware tables plus `cba_firmware_files`, `cba_diffs`, and `cba_diff_entries`. |
| `audit_core/db.py` | Primary-key contract, Stage 4b rebuild migration, diff validators, and transaction-safe `put(..., commit=False)`. |
| `audit_core/baseline-stage4b.sql` | Frozen pre-Stage-4c schema used by installed selftest. |
| `audit_core/triage.py` | Image-scoped manifest hashing and role-aware target inventory behavior. |
| `audit_core/firmware_diff.py` | Pair resolution, deterministic comparison, content-addressed manifest, and atomic diff-row replacement. |
| `audit.py` | `diff` parser/handler and installed selftest extensions. |
| `references/briefs/diff-brief.md` | Semantic patch analysis and sibling-sweep assignment. |
| `docs/superpowers/derivations/2026-10-12-stage4c-diff-brief.md` | Anti-absence source for the brief. |
| `tests/test_migrate.py`, `tests/test_firmware_schema.py` | Key contract, old-database preservation, rollback, and new table validation. |
| `tests/test_triage.py`, `tests/test_triage_corpus.py` | Manifest hashing, image isolation, coverage behavior, and corpus consistency. |
| `tests/test_firmware_diff.py` | Pure comparison, persistence, refusal, replacement, and failure atomicity. |
| `tests/test_cli_stage4c.py`, `tests/test_diff_brief.py`, `tests/test_brief_templates.py` | CLI and agent-contract behavior. |
| `feature_lists.json`, `ARCHITECTURE.md`, `progress.md`, `SESSION_HANDOFF.md` | Machine inventory and durable current-state record. |

## Task 1: Primary-key contract and Stage 4b migration

**Files:** Modify `audit_core/schema.sql`, `audit_core/db.py`, `audit_core/workspace.py`, `audit.py`, `tests/test_migrate.py`, and `tests/test_firmware_schema.py`; create `audit_core/baseline-stage4b.sql`.

**Interfaces:** Extend `TableSpec` with `primary_key: tuple[str, ...]`; populate it for every registered table. Add `db.FIRMWARE_IMAGE_UNSCOPED = "legacy-unscoped"`. Preserve `db.primary_key(con, table) -> tuple[str, ...]`. `db.migrate(con) -> list[str]` additionally returns `cba_binfacts.primary_key` and `cba_services.primary_key` when it rebuilds those tables.

- [ ] **Step 1: Write failing key-contract tests.** Assert every fresh schema table's `PRAGMA table_info` key order equals `TABLE_SPECS[table].primary_key`; specifically require `("image_id", "path")` for `cba_binfacts` and `("image_id", "name")` for `cba_services`. Assert `connect()` rejects a database with current columns but the Stage 4b single-column keys.
- [ ] **Step 2: Add the frozen Stage 4b fixture and failing preservation tests.** Build it with one real-image row and one NULL-scoped row across the two firmware tables, migrate it, and assert values plus `recorded_at` survive while NULL becomes `legacy-unscoped`. Run migration twice and assert the second call returns `[]`.
- [ ] **Step 3: Add the rollback test.** Monkeypatch the private rebuild helper to fail while rebuilding `cba_services`; after `migrate()` raises, assert `cba_binfacts` still has its original Stage 4b key and both original tables/rows remain.
- [ ] **Step 4: Run** `python3 -m pytest tests/test_migrate.py tests/test_firmware_schema.py -q`; expect failures for the missing key contract, stale schema keys, and missing Stage 4b migration.
- [ ] **Step 5: Implement** the exact composite definitions from spec §4.2, `TableSpec.primary_key`, key validation in `connect()` and `cmd_selftest`, and one ordered Stage 4c rebuild inside `migrate()`. Use individual `execute` calls inside one explicit transaction; do not use an `executescript` that commits between the two rebuilds.
- [ ] **Step 6: Extend installed selftest** to apply both frozen baselines independently, verify representative Stage 4b rows and composite keys, and pass each upgraded database to `connect()`.
- [ ] **Step 7: Run** `python3 -m pytest tests/test_migrate.py tests/test_firmware_schema.py -q` and `python3 audit.py selftest`; expect both baseline upgrade paths, row preservation, rollback, and all key comparisons to pass.
- [ ] **Step 8: Commit** as `feat: migrate firmware facts to image-scoped keys`.

## Task 2: Image-scoped firmware file manifests

**Files:** Modify `audit_core/schema.sql`, `audit_core/db.py`, `audit_core/triage.py`, `tests/test_firmware_schema.py`, `tests/test_triage.py`, and `tests/test_triage_corpus.py`.

**Interfaces:** Register `cba_firmware_files` with columns and `("image_id", "path")` primary key from spec §4.1. Preserve `triage.run(con, root, *, image_id=None, allow_no_elf=False) -> TriageSummary`; use `legacy-unscoped` when `image_id` is omitted.

- [ ] **Step 1: Write failing manifest tests.** Triage a literal tree and assert every regular file has one row with effective image ID, root-relative POSIX path, kind, exact size, and a hand-computed SHA-256. Assert directories, in-root symlinks, and escaping symlinks are absent.
- [ ] **Step 2: Write failing image-isolation tests.** Record target and diff-reference image rows, triage trees sharing an ELF path and service name, and assert two manifest, binfact, and service rows survive. Snapshot all `cba_inventory` rows after target triage; assert reference triage leaves the snapshot identical.
- [ ] **Step 3: Add compatibility tests.** Omitted `image_id` writes `legacy-unscoped` to all three firmware tables and keeps Stage 4b's generic inventory behavior. Re-triage within one scope and assert stable counts rather than duplicates.
- [ ] **Step 4: Run** `python3 -m pytest tests/test_triage.py tests/test_firmware_schema.py -q`; expect missing-table and collision failures.
- [ ] **Step 5: Implement** `cba_firmware_files`, resolve image role before the filesystem walk, hash each regular file once, reuse the digest for binfacts, and use the effective image scope in every firmware row. Mirror files to `cba_inventory` only for target and `legacy-unscoped` scopes.
- [ ] **Step 6: Update the read-only corpus test** to assert every binfact has a same-image manifest row and every resolvable service executable has one. It must continue to skip only when the corpus is absent.
- [ ] **Step 7: Run** `python3 -m pytest tests/test_triage.py tests/test_triage_corpus.py tests/test_firmware_schema.py -q`; expect pass or the corpus test's documented SKIP.
- [ ] **Step 8: Commit** as `feat: record image-scoped firmware manifests`.

## Task 3: Durable diff table contract and deferred commits

**Files:** Modify `audit_core/schema.sql`, `audit_core/db.py`, `tests/test_db.py`, and `tests/test_firmware_schema.py`.

**Interfaces:** Add `db.DIFF_CHANGES = ("added", "removed", "modified")`; register `cba_diffs` and `cba_diff_entries` exactly as spec §4.4. Extend `db.put(con, table, row, *, replace=False, commit=True) -> None`; the default preserves all existing behavior, while `commit=False` leaves transaction ownership with the caller.

- [ ] **Step 1: Write failing schema tests.** Assert the exact columns, required fields, and primary keys for both diff tables. Assert summary counts reject negative and non-integer values.
- [ ] **Step 2: Write failing entry-validator tests.** `added` requires target kind/size/hash, `removed` requires reference kind/size/hash, `modified` requires both sides, and any other change value refuses. Literal valid rows for all three changes must pass.
- [ ] **Step 3: Write the deferred-commit regression test.** Against a file-backed database, call `db.put(..., commit=False)` and assert a second connection cannot see the row before `con.commit()` but can see it afterward; assert the default call remains immediately visible.
- [ ] **Step 4: Run** `python3 -m pytest tests/test_db.py tests/test_firmware_schema.py -q`; expect missing-table, validator, and signature failures.
- [ ] **Step 5: Implement** the schema/specs and narrow validators. Refactor only the final commit decision in `db.put`; do not change merge-on-replace, validation order, integrity-error translation, or callers that omit `commit`.
- [ ] **Step 6: Run** `python3 -m pytest tests/test_db.py tests/test_firmware_schema.py -q` and `python3 audit.py selftest`; expect 21 schema tables, 20 under contract, and unchanged default put semantics.
- [ ] **Step 7: Commit** as `feat: add durable firmware diff tables`.

## Task 4: Deterministic manifest comparison

**Files:** Create `audit_core/firmware_diff.py` and `tests/test_firmware_diff.py`.

**Interfaces:** Produce frozen dataclasses `DiffEntry(path, change, reference_kind, target_kind, reference_size, target_size, reference_sha256, target_sha256)` and `Comparison(entries, added_count, removed_count, modified_count, unchanged_count)`. Produce `compare(reference: Iterable[Mapping[str, object]], target: Iterable[Mapping[str, object]]) -> Comparison`.

- [ ] **Step 1: Write failing literal comparison tests.** Hand-build reference and target mappings that yield one added, one removed, one modified, and one unchanged path. Assert exact counts, exact optional-side values, and that unchanged paths are absent from `entries`.
- [ ] **Step 2: Add deterministic-scale tests.** Compare 250 paths, including non-ASCII names, supplied in opposite orders. Assert all 250 participate, output is sorted by Python string order, and reversing either input produces the identical `Comparison`.
- [ ] **Step 3: Add duplicate-path refusal tests.** Either input containing the same path twice must raise `FirmwareDiffError` rather than silently choosing one row.
- [ ] **Step 4: Run** `python3 -m pytest tests/test_firmware_diff.py -q`; expect missing module/interfaces.
- [ ] **Step 5: Implement** `compare` as an in-memory path map plus sorted union. Equality is SHA-256 equality; size and kind are evidence fields, not substitutes for content identity. Do not apply `db.MAX_ROWS` or read files here.
- [ ] **Step 6: Run** `python3 -m pytest tests/test_firmware_diff.py -q`; expect the pure comparison tests to pass.
- [ ] **Step 7: Commit** as `feat: compare firmware manifests deterministically`.

## Task 5: Pair resolution, persistence, and content-addressed manifests

**Files:** Modify `audit_core/firmware_diff.py` and `tests/test_firmware_diff.py`.

**Interfaces:** Add `FirmwareDiffError(Exception)`, frozen `DiffSummary(id, reference_image_id, target_image_id, added_count, removed_count, modified_count, unchanged_count, manifest_path)`, and `run(con: sqlite3.Connection, run_dir: str | pathlib.Path, *, target_image_id: str | None = None, reference_image_id: str | None = None, replace: bool = False) -> DiffSummary`.

- [ ] **Step 1: Write failing pair-resolution tests.** Cover the one-pair implicit path; multiple targets/references; only one explicit ID; missing explicit IDs; reversed roles; cross-vendor/model pairs; identical acquired-image hashes; and either empty manifest. Assert every refusal leaves both diff tables empty and creates no manifest.
- [ ] **Step 2: Write the successful persistence test.** Populate real image and manifest rows, call `run`, and assert the deterministic `diff-<16 hex>` ID, exact summary counts, only non-identical SQL entries, and a bounded `DiffSummary` without inline entries.
- [ ] **Step 3: Pin canonical artifact bytes.** Assert the manifest filename contains the first 16 hex characters of its own SHA-256, its JSON contains sorted entries and pair metadata, and two equivalent databases produce byte-identical manifests.
- [ ] **Step 4: Write replacement and atomicity tests.** A duplicate refuses without `replace`; replacement deletes stale entries. Patch manifest installation to fail and assert no database change. Patch a deferred `db.put` after a prior successful result and assert rollback preserves the old rows and old `manifest_path`; permit only an unreferenced new generation.
- [ ] **Step 5: Run** `python3 -m pytest tests/test_firmware_diff.py -q`; expect missing `run` behavior and persistence failures.
- [ ] **Step 6: Implement** pair resolution and direct unbounded manifest queries, call Task 4's `compare`, serialize canonical JSON, install it through a temporary sibling plus `os.replace`, then write summary and entries in one explicit SQLite transaction using `db.put(..., commit=False)`. Roll back on any database exception.
- [ ] **Step 7: Run** `python3 -m pytest tests/test_firmware_diff.py -q`; expect all selection, artifact, replacement, scale, and failure tests to pass.
- [ ] **Step 8: Commit** as `feat: persist content-addressed firmware diffs`.

## Task 6: Expose the `diff` CLI

**Files:** Modify `audit.py`, `tests/test_cli_stage4c.py`, `tests/test_harness.py`, and any exact verb-count assertion located by `rg '25 declared|25 verbs'`.

**Interfaces:** Add `audit.py diff --run DIR [--target-image-id ID --reference-image-id ID] [--replace] [--json]`. Success exits 0, a named refusal exits 1, and argparse usage errors exit 2.

- [ ] **Step 1: Write failing subprocess tests.** Cover help, implicit pair text output, explicit pair JSON output, half-explicit IDs, each library refusal class, duplicate without replace, and missing arguments. Assert stderr names the cause without a traceback.
- [ ] **Step 2: Assert bounded output.** Human output is exactly the summary plus manifest path; JSON has the summary fields and no `entries` array, even for a 250-file fixture.
- [ ] **Step 3: Run** `python3 -m pytest tests/test_cli_stage4c.py tests/test_harness.py -q`; expect missing verb and stale-count failures.
- [ ] **Step 4: Implement** the parser, handler, import, and `HANDLERS` entry. Enforce both-or-neither explicit IDs before calling `firmware_diff.run`; catch `FirmwareDiffError` and `DbError` at the CLI boundary.
- [ ] **Step 5: Run** `python3 -m pytest tests/test_cli_stage4c.py tests/test_harness.py -q` and `python3 audit.py selftest`; expect 26 declared dispatchable verbs and bounded outputs.
- [ ] **Step 6: Commit** as `feat: expose firmware diff CLI`.

## Task 7: Ship the semantic diff brief

**Files:** Create `docs/superpowers/derivations/2026-10-12-stage4c-diff-brief.md`, `references/briefs/diff-brief.md`, and `tests/test_diff_brief.py`; modify `tests/test_brief_templates.py`.

**Interfaces:** `audit.py brief --phase diff --unit <diff-id> --run <run> --var run_dir=<run> --var diff_id=<id> --var target_root=<path> --var reference_root=<path> --var manifest_path=<path> --var artifact_path=<path> --var known_advisory=<text> --var patched_component=<path>` renders the assignment.

- [ ] **Step 1: Write the anti-absence derivation** listing every instruction in spec §9 before creating the brief.
- [ ] **Step 2: Write failing brief tests.** Assert the template set gains `diff-brief.md`, every variable renders, the return contract is exact, and the brief names both roots, the manifest, known advisory, patched component, before/after evidence, build-noise exclusions, target-only sibling sweep, observation recording, conditional pattern registration, and the prohibition on turning every changed file into a finding.
- [ ] **Step 3: Run** `python3 -m pytest tests/test_diff_brief.py tests/test_brief_templates.py -q`; expect missing-template failures.
- [ ] **Step 4: Write** the brief from the derivation. Keep raw diff contents out of the dispatch and require the detailed artifact plus the one-line R2 return.
- [ ] **Step 5: Reconcile** `git diff -U0 -- references/briefs/diff-brief.md` against every derivation item; add a missing instruction rather than weakening its test.
- [ ] **Step 6: Run** `python3 -m pytest tests/test_diff_brief.py tests/test_brief_templates.py -q` and `python3 audit.py lint-skill`; expect pass.
- [ ] **Step 7: Commit** as `feat: ship firmware diff agent brief`.

## Task 8: Corpus proof, machine inventory, and durable handoff

**Files:** Modify `tests/test_triage_corpus.py`, `feature_lists.json`, `ARCHITECTURE.md`, `progress.md`, `SESSION_HANDOFF.md`, and `docs/superpowers/specs/2026-10-12-stage4c-firmware-diff-design.md`.

**Interfaces:** No new runtime interface. Record Stage 4c as shipped only after the reviewed tree passes the full harness.

- [ ] **Step 1: Run the focused Stage 4c suite** with `python3 -m pytest tests/test_migrate.py tests/test_firmware_schema.py tests/test_triage.py tests/test_triage_corpus.py tests/test_firmware_diff.py tests/test_cli_stage4c.py tests/test_diff_brief.py tests/test_brief_templates.py -q`; expect pass or only the documented absent-corpus SKIP.
- [ ] **Step 2: Update `feature_lists.json`.** Add the Stage 4c stage/feature with real modules, tests, and docs; mark `binfacts-path-key-collision` closed in Stage 4c; keep the newly discovered target-inventory rule in the feature notes. Update the recorded head only to the last implementation commit, not an invented future hash.
- [ ] **Step 3: Reconcile durable prose.** Add `firmware_diff.py`, three new tables, 26 verbs, migration behavior, and the Stage 4c/4d boundary to `ARCHITECTURE.md`. Update `progress.md` and `SESSION_HANDOFF.md` with measured counts, zero-audit status, remaining limitations, and Stage 4d `surface` as next. Mark the design status implemented only after review.
- [ ] **Step 4: Run** `make all`; expect all eight gates green, unchanged read-only tplink recall/precision/cost, zero unexecuted `audit_core` statements, no real-install modification, and current measured table/verb/test/file counts. If counts differ from planned values, record the measured values rather than editing code to match prose.
- [ ] **Step 5: Audit the final diff.** Run `git diff --check`, `git status --short`, and `git diff -- tests/goldens docs/baselines`; expect no whitespace errors and no golden/baseline edits. Confirm no code path writes under the read-only corpus.
- [ ] **Step 6: Commit** the corpus proof, feature inventory, design status, architecture, progress, and handoff as `docs: record Stage 4c firmware diff`.

## Whole-branch review

Review the complete Stage 4c branch against the design, not only each task's diff. Exercise all five Review Focus cases; verify the old Stage 4b database upgrade through the public `audit.py init --timestamp` remedy; confirm reference triage cannot alter target coverage; inspect transaction boundaries around rebuild and diff replacement; and follow the rendered brief as an operator would. Fix every Critical or Important finding with a failing regression test first. Reconcile the durable documents after the final fix, then run a fresh `make all` as required by `AGENTS.md` before integration.
