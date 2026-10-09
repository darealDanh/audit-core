# Stage 4b — Acquire and Triage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record firmware-image provenance and turn an already-carved root filesystem into an auditable file, ELF, and boot-service inventory.

**Architecture:** Extend the existing `cba_` database and `audit.py` CLI with two verbs. Keep image hashing, ELF parsing, and rootfs traversal in three focused stdlib modules; reuse `audit.py init`, `db.put`, and the existing inventory and coverage tables. Ship the `triage` dispatch brief with the CLI so the script and agent halves work together.

**Tech Stack:** Python 3.10+, stdlib only (`hashlib`, `pathlib`, `struct`, `sqlite3`, `dataclasses`); pytest.

**Spec:** [`2026-10-08-stage4b-acquire-triage-design.md`](../specs/2026-10-08-stage4b-acquire-triage-design.md), deriving from the audit-suite design §3.3–3.4, §4–5.

## Global Constraints

- `audit_core` remains stdlib-only with no network access; `pyproject.toml` keeps `dependencies = []` and `requires-python = ">=3.10"`.
- `~/Documents/Offsec/Opswat/Devices/` is read-only. Corpus tests may read it; all new databases and artifacts belong in pytest `tmp_path` or a run directory outside that tree.
- `acquire` records a local image; it never fetches. `triage` reads an already-carved rootfs; it never carves, invokes external tools, or asserts open ports.
- Do not run an audit or the deferred Stage 2/3 benchmark reruns. `make all` may score the existing database read-only.
- Never write `tests/goldens/*/matches.json` or `rejections.json`; never edit an existing `docs/baselines/` file in place.
- Before adding `references/briefs/triage-brief.md`, write its intended instructions to `docs/superpowers/derivations/`; reconcile the final prose with `git diff -U0`.
- `make all` must pass. It currently runs eight gates; the mutation sweep remains opt-in and outside it.

## Review Focus

1. A zero-ELF or empty root must refuse **before writing any inventory, binfacts, or service rows**; `--allow-no-elf` permits only the zero-ELF case. Task 5 pins this.
2. Symlinks, including links escaping the root, must not enter the inventory or be followed during the walk. Task 4 pins this.
3. A malformed ELF with a valid magic prefix must not abort the walk or acquire a confident mitigation value. Task 2 pins this.
4. A second `target` image for one vendor and model must refuse without `--replace`; with it, omitted optional data must retain the stored value. Task 3 pins this.
5. A service row needs the exact init line as evidence; a model-supplied `ports` claim without `ports_evidence` must fail. Tasks 1 and 6 pin this.

---

## File Structure

| File | Responsibility |
|---|---|
| `audit_core/schema.sql`, `audit_core/db.py` | Three tables and their validated row contracts. |
| `audit_core/elf.py` | Pure, bounded ELF reader; no database or phase knowledge. |
| `audit_core/acquire.py` | Local firmware-image provenance and SHA-256. |
| `audit_core/triage.py` | Rootfs walk, inventory, ELF facts, and boot-service discovery. |
| `audit.py` | `acquire` and `triage` handlers and parsers. |
| `references/briefs/triage-brief.md` | Instructions for the one triage agent, rendered by the existing `brief` verb. |
| `tests/test_firmware_schema.py`, `tests/test_elf.py`, `tests/test_acquire.py`, `tests/test_triage.py`, `tests/test_cli_stage4b.py` | Contract, parser, workflow, and CLI tests. |
| `tests/test_triage_corpus.py` | One read-only corpus consistency test, skipped when its corpus is absent. |
| `feature_lists.json`, `ARCHITECTURE.md`, `progress.md`, `SESSION_HANDOFF.md` | Inventory, architecture, progress, and resumption record. |

## Task 1: Database contract for firmware rows

**Files:** Modify `audit_core/schema.sql`, `audit_core/db.py`; create `tests/test_firmware_schema.py`.

**Interfaces:** Produce `db.IMAGE_ROLES = ("target", "diff-reference")`, `db.TRISTATE = ("yes", "no", "unknown")`, `db.RELRO_STATES = ("full", "partial", "none", "unknown")`, and append `"script"`, `"config"` to `db.INVENTORY_KINDS`. Register `cba_images`, `cba_binfacts`, and `cba_services` with the exact columns and primary keys in spec §5.

- [ ] **Step 1: Write failing contract tests.** Apply the schema to a temporary database and assert 18 tables, all three new `TABLE_SPECS`, and exact schema/spec column agreement. Assert valid image roles and tri-state values, rejection of an invalid role or mitigation value, rejection of `cba_services.ports` without nonblank `ports_evidence`, and acceptance of `script` and `config` inventory kinds.
- [ ] **Step 2: Run** `python3 -m pytest tests/test_firmware_schema.py -q`; expect failure for missing tables/contracts.
- [ ] **Step 3: Implement** the three `CREATE TABLE IF NOT EXISTS` definitions from spec §5, the constants, and validators in `db.py`. Make `cba_images` require `id`, `vendor`, `model`, `version`, `role`, `path`, and `sha256`; make `cba_binfacts` require `path`, `machine`, `bits`, `endian`, and `elf_type`; make `cba_services` require `name`, `start_source`, and `evidence`. Do not add a migration for wholly new tables.
- [ ] **Step 4: Run** the new tests and `python3 audit.py selftest`; expect 18 schema tables and 17 under contract, including repair of the frozen older database via `apply_schema`.
- [ ] **Step 5: Commit** schema, contract, and tests as `feat: add firmware provenance and triage tables`.

## Task 2: Pure ELF reader

**Files:** Create `audit_core/elf.py`, `tests/test_elf.py`.

**Interfaces:** Produce `ElfFacts` as a frozen dataclass with `machine`, `bits`, `endian`, `elf_type`, `interp`, `needed`, `runpath`, `nx`, `pie`, `relro`, `canary`, `stripped`, and `static`; produce `read(path: str | pathlib.Path) -> ElfFacts | None`. `None` means the header cannot establish an ELF. Unknown mitigation facts use the literal `"unknown"`.

- [ ] **Step 1: Write failing tests** using synthesized 32- and 64-bit ELF byte fixtures. Assert MIPS both endian orders, ARM, AArch64, x86-64, EXEC/DYN/REL, interpreter and `DT_NEEDED`, GNU stack NX, full/partial/no RELRO, stripped versus `.symtab`, and `__stack_chk_fail` canary evidence. Assert a DYN with `PT_INTERP` is PIE and DYN without it is a shared library.
- [ ] **Step 2: Add malformed-input tests** for empty/wrong magic, truncated headers, offsets beyond EOF, excessive program-header counts, and truncated tables. Assert `read` returns `None` or a partial `ElfFacts` with `unknown`, and never raises. Pin bounded reads rather than trusting file-declared sizes.
- [ ] **Step 3: Run** `python3 -m pytest tests/test_elf.py -q`; expect missing module/function failures.
- [ ] **Step 4: Implement** `read` with `struct` and explicit ELF class/endian decoding, checked offset arithmetic, bounded program and section table traversal, and the spec §4.1 mappings. Keep database, CLI, and phase imports out of this module.
- [ ] **Step 5: Run** `python3 -m pytest tests/test_elf.py -q`; expect all synthesized and malformed cases to pass. Commit as `feat: read ELF facts from carved firmware files`.

## Task 3: Acquire image provenance

**Files:** Create `audit_core/acquire.py`, `tests/test_acquire.py`.

**Interfaces:** Produce `AcquireError(Exception)` and `record(con: sqlite3.Connection, *, vendor: str, model: str, version: str, role: str, path: str | pathlib.Path, source: str, replace: bool = False) -> ImageRecord`. `ImageRecord` is a frozen dataclass with `id`, `path`, `sha256`, and `size`. ID is `vendor|model|role`.

- [ ] **Step 1: Write failing tests.** Hash a known byte vector, assert size and row fields, reject a missing/unreadable/nonregular image, reject an invalid role, and reject duplicate ID without `replace`. With `replace` and `source=""`, assert changed version/hash and preservation of the stored nonblank `source` through `db.put`'s merge semantics.
- [ ] **Step 2: Run** `python3 -m pytest tests/test_acquire.py -q`; expect missing module/function failures.
- [ ] **Step 3: Implement** `record` by validating the local file, reading SHA-256 in bounded chunks, then calling `db.put` once. Omit blank `source` from the row so replacement preserves a stored value. Do not fetch, copy, or alter the image.
- [ ] **Step 4: Run** `python3 -m pytest tests/test_acquire.py -q`; expect pass. Commit as `feat: record local firmware image provenance`.

## Task 4: Triage inventory and ELF facts

**Files:** Create `audit_core/triage.py`, `tests/test_triage.py`.

**Interfaces:** Produce `TriageError(Exception)`, `TriageSummary(inventory_count: int, elf_count: int, service_count: int)`, and `run(con: sqlite3.Connection, root: str | pathlib.Path, *, image_id: str | None = None, allow_no_elf: bool = False) -> TriageSummary`. Task 6 adds services to this function; this task returns `service_count=0`.

- [ ] **Step 1: Write failing tests** for a synthetic carved tree with ELF, shebang script, `/etc` configuration, ordinary file, directory, and symlink (including one pointing outside the root). Assert one `cba_inventory` row per regular file, root-relative POSIX paths, kinds `binary`/`script`/`config`/`file`, sizes, one `cba_binfacts` row per ELF, a matching SHA-256, and no rows for directories or symlinks. Rerun on the same root and assert stable counts.
- [ ] **Step 2: Write refusal tests** for a nonexistent/nondirectory root and an `image_id` absent from `cba_images`. Assert no rows were written. For a valid image ID, assert it is on each binfacts row.
- [ ] **Step 3: Run** `python3 -m pytest tests/test_triage.py -q`; expect missing module/function failures.
- [ ] **Step 4: Implement** `run` as one deterministic walk over regular files, calling `elf.read` and writing through validated `db.put(..., replace=True)` calls so a rerun is idempotent. Serialize `needed` as comma-joined names. Keep paths root-relative, avoid following symlinks, and check root and image provenance before the walk.
- [ ] **Step 5: Run** the tests from Steps 1–2; expect pass. Commit as `feat: inventory carved rootfs and ELF facts`.

## Task 5: Zero-ELF and empty-tree refusal

**Files:** Modify `audit_core/triage.py`, `tests/test_triage.py`.

**Interfaces:** Preserve Task 4's `run` signature and summary.

- [ ] **Step 1: Write failing tests** for an empty tree and a nonempty zero-ELF tree. Both refuse by default and leave all three firmware tables and `cba_inventory` untouched. `allow_no_elf=True` permits the nonempty zero-ELF tree and returns `elf_count=0`; it does not permit an empty tree.
- [ ] **Step 2: Run** `python3 -m pytest tests/test_triage.py -q`; expect the refusal assertions to fail.
- [ ] **Step 3: Implement** a pre-write discovery/counting pass: `db.put` commits per row, so a later rollback cannot undo rows already written. Refuse before the first write. Do not let an empty inventory make a later coverage gate look complete.
- [ ] **Step 4: Run** `python3 -m pytest tests/test_triage.py -q`; expect pass. Commit as `fix: refuse empty and unacknowledged zero-ELF trees`.

## Task 6: Boot-start services and agent evidence

**Files:** Modify `audit_core/triage.py`, `tests/test_triage.py`; create `docs/superpowers/derivations/2026-10-09-stage4b-triage-brief.md`, `references/briefs/triage-brief.md`, `tests/test_triage_brief.py`.

**Interfaces:** `triage.run` writes `cba_services` rows and returns their count. `audit.py brief --phase triage --unit <id> --run <run> --var run_dir=<run> --var rootfs=<path> --var image_id=<id>` renders the brief.

- [ ] **Step 1: Write failing tests** with boot entries under `/etc/init.d/`, `/etc/inittab`, `/etc/rc.d/`, and `/etc/rc.local`. Assert the service name, root-relative start source, resolved executable when determinable, exact nonblank matched line in `evidence`, image ID, and blank `ports`/`ports_evidence`. Assert ordinary comments and unproven service guesses do not make rows. When two start lines produce the same service name, retain the first in sorted path/line order and assert that rule.
- [ ] **Step 2: Run** `python3 -m pytest tests/test_triage.py -q`; expect no service rows.
- [ ] **Step 3: Implement** service extraction in `triage.py` without executing scripts. Resolve only paths that stay inside the root. Keep boot-start detection separate from open-port or handler inference.
- [ ] **Step 4: Write the brief derivation** listing every required instruction: carved root path; image provenance; what the script recorded; how the agent checks BusyBox applets, architecture, libc, service claims, and ports evidence; where it records `cba_components`, `cba_services`, and notes; bounded one-line return contract. Then write failing render tests and add `triage-brief.md` using only `run_dir`, `rootfs`, and `image_id` placeholders supplied by the planned command (`image_id=none` when omitted).
- [ ] **Step 5: Run** `python3 -m pytest tests/test_triage.py tests/test_triage_brief.py -q` and `git diff -U0 -- references/briefs/triage-brief.md`; expect pass and every derived instruction present. Commit as `feat: record boot services and ship triage brief`.

## Task 7: CLI verbs and user-visible refusals

**Files:** Modify `audit.py`; create `tests/test_cli_stage4b.py`.

**Interfaces:** Add `audit.py acquire --run DIR --vendor V --model M --version X --role {target,diff-reference} --file PATH --source TEXT [--replace] [--json]` and `audit.py triage --run DIR --root CARVED_ROOTFS [--image-id ID] [--allow-no-elf] [--json]`. Success exits 0, a named refusal exits 1, argparse usage errors exit 2.

- [ ] **Step 1: Write failing subprocess tests** for both help screens, valid JSON output, text output, each refusal class from Tasks 3–5, and invalid/missing arguments. Assert JSON has a machine-readable image ID or triage counts and that error text names the cause without a traceback.
- [ ] **Step 2: Run** `python3 -m pytest tests/test_cli_stage4b.py -q`; expect missing verb failures.
- [ ] **Step 3: Implement** handlers in `HANDLERS` and subparsers in `build_parser`, opening `<run>/audit.db` with `db.connect`. Catch `DbError`, `AcquireError`, and `TriageError` at the CLI boundary; keep library functions independently testable.
- [ ] **Step 4: Run** `python3 -m pytest tests/test_cli_stage4b.py -q` and `python3 audit.py selftest`; expect 25 declared dispatchable verbs and no parser/handler drift. Commit as `feat: expose acquire and triage CLI verbs`.

## Task 8: Corpus check, manifest, and handoff

**Files:** Create `tests/test_triage_corpus.py`; modify `feature_lists.json`, `ARCHITECTURE.md`, `progress.md`, `SESSION_HANDOFF.md` and any verb-count tests that now have stale expected values.

**Interfaces:** No new runtime interface. Record Stage 4b as shipped only after all gates pass.

- [ ] **Step 1: Write the corpus test** against the existing read-only `gl_inet/extracted/rootfs`, skipping only when absent. Run triage into a database under `tmp_path`; assert each binfacts path has an inventory row, the architecture is uniform across confidently classified ELFs, and each resolvable service executable points inside the root at a real file.
- [ ] **Step 2: Run** `python3 -m pytest tests/test_triage_corpus.py -q`; expect pass on the operator's corpus or an explicit SKIP elsewhere. Investigate a corpus contradiction; do not weaken the assertion merely to green it.
- [ ] **Step 3: Add** Stage 4b and feature entries to `feature_lists.json`, with real tests/modules/docs paths. Update architecture and handoff with the new tables, two verbs, zero-audit verification, the known two-image path-key collision, and the fact that the remaining firmware phases and the asus golden do not exist.
- [ ] **Step 4: Run** `make all`; expect all eight gates green, 18 schema tables, 17 under contract, 25 dispatchable verbs, and unchanged read-only tplink benchmark values. Check `git diff --check`, shipped-prose derivation reconciliation, and no diff under `tests/goldens/` or `docs/baselines/`.
- [ ] **Step 5: Commit** the tests, manifest, and record as `docs: record Stage 4b acquire and triage`.

## Whole-branch review

Review the full branch against the Stage 4b spec. In particular, exercise the five Review Focus cases, verify `acquire` and `triage` can be followed from their CLI/help and rendered brief without undocumented manual state, inspect all paths for writes into the read-only corpus, and confirm the new tables do not break an existing database after reapplying `audit.py init --timestamp`. Run `make all` once more on the reviewed tree before integration.
