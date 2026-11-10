# Firmware-audit skill split — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `firmware-audit` as its own installed skill over the shared vendored core, with `codebase-audit` behavior byte-identical.

**Architecture:** Flat source (approach B). Firmware phases stay in the shared `audit.py`/`audit_core`. A new `firmware-audit/` subtree holds the firmware SKILL.md, firmware worker briefs and launchers. The installer learns a `--skill` selector that vendors the shared core plus a chosen skill's surface. `codebase-audit/SKILL.md` drops firmware routing.

**Tech Stack:** Python 3.10+ stdlib, bash + PowerShell installers, pytest.

**Spec:** `docs/superpowers/specs/2026-11-10-firmware-audit-skill-split-design.md` (read its Builder-check resolutions R1–R5).

## Global Constraints

- `audit_core` stays stdlib-only; no behavior, schema, migration, table or verb change.
- Firmware verbs stay in the shared core; `audit.py selftest` stays green.
- `audit_core/` and `references/briefs/` (and `firmware-audit/references/briefs/`) resolve as the brief dirs; a firmware brief must render byte-identically before and after the move.
- Real install dirs are never touched; `make install-smoke` sandboxes `HOME`/`CODEX_HOME` and refuses if the sandbox resolves to the real one.
- Firmware brief set (move): `hunt`, `surface`, `diff`, `triage`, `firmware-fpcheck`, `firmware-chain`, `firmware-dive`, `firmware-decide`, `firmware-report`. Generic brief set (stays): `audit`, `recon`, `fpcheck`.
- `make all`'s eight gates must pass with zero unexecuted `audit_core` statements; `scripts/coverage-allowlist.txt` stays empty.

## Review Focus

- A `brief --phase <firmware>` call after the move must render identical bytes from the new location: Task 2 asserts byte-identity against a pre-move capture.
- The install smoke must still refuse a sandbox HOME that resolves to the real HOME, now for both skills: Task 5 asserts the refusal and real-dir mtime invariance for both skill roots.
- `codebase-audit`'s installed tree must still pass `selftest` and contain no `__SKILL_DIR__` survivor after the SKILL.md edit: Task 3/5 assert both.
- A firmware brief citing a generic doc (`phase5-fp-check.md`) must not dangle in the installed firmware tree: Task 2 ships it and Task 5 asserts it is present.
- Removing firmware sections from `codebase-audit/SKILL.md` must not strand a generic cross-reference: Task 3 greps the edited SKILL.md for dangling links.

---

### Task 1: Brief multi-directory resolver

**Files:**
- Modify: `audit_core/briefs.py`
- Test: `tests/test_brief_templates.py`

**Interfaces:**
- Produces: `BRIEF_DIRS: tuple[pathlib.Path, ...]` (root `references/briefs`, then `<repo>/firmware-audit/references/briefs`) and `template_path(phase: str) -> pathlib.Path` returning the first existing `<dir>/<phase>-brief.md` or raising `BriefError`.
- Produces: `iter_brief_templates() -> list[pathlib.Path]` enumerating `*-brief.md` across all existing `BRIEF_DIRS`.
- `TEMPLATE_DIR` stays as the root entry (back-compat); `write_brief` uses `template_path` when `template_dir` is None.

- [ ] **Step 1: Write failing resolver tests**

Assert `template_path("audit")` resolves under root; `template_path("firmware-report")` resolves under the firmware dir once it exists (create a temp file there in the test, or skip until Task 2 — use a tmp BRIEF_DIRS monkeypatch); unknown phase raises `BriefError`; `iter_brief_templates()` unions both dirs and tolerates a missing firmware dir.

- [ ] **Step 2: Run tests, observe failure**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_brief_templates.py`

- [ ] **Step 3: Implement `BRIEF_DIRS`, `template_path`, `iter_brief_templates`; route `write_brief` through them**

Existence-guard each dir. Keep rendered output identical.

- [ ] **Step 4: Run tests green**

- [ ] **Step 5: Commit** `feat(split): add multi-directory brief resolver`

### Task 2: Relocate firmware briefs

**Files:**
- Move: `references/briefs/{hunt,surface,diff,triage,firmware-fpcheck,firmware-chain,firmware-dive,firmware-decide,firmware-report}-brief.md` → `firmware-audit/references/briefs/`
- Create: `firmware-audit/references/phase5-fp-check.md` (copy of `references/phase5-fp-check.md`)
- Modify: `audit_core/skill_lint.py` (second brief-dir scan, existence-guarded)
- Modify: `feature_lists.json` (repoint ~10 firmware-brief path entries)
- Modify: `tests/test_harness.py` (hunt-brief, firmware-fpcheck-brief inventory asserts)
- Modify: `tests/test_hunt_brief.py`, `tests/test_firmware_chain_brief.py`, `tests/test_firmware_fpcheck_brief.py`, `tests/test_surface_brief.py`, `tests/test_diff_brief.py`, `tests/test_triage_brief.py` (migrate direct `TEMPLATE_DIR / name` reads and `TEMPLATE_DIR.glob` to `briefs.template_path`/`iter_brief_templates`)

**Interfaces:**
- Consumes: Task 1 resolver.

- [ ] **Step 1: Capture pre-move brief bytes**

Before moving, record `sha256` of each firmware brief (throwaway script) to prove byte-identity after.

- [ ] **Step 2: `git mv` the nine firmware briefs; copy `phase5-fp-check.md`**

Grep the moved briefs for `__SKILL_DIR__/references/` to confirm `phase5-fp-check.md` is the only generic doc cited; copy any other found.

- [ ] **Step 3: Migrate every direct `TEMPLATE_DIR` test read and the `skill_lint` scan**

Replace `briefs.TEMPLATE_DIR / "<phase>-brief.md"` with `briefs.template_path("<phase>")` and `TEMPLATE_DIR.glob("*-brief.md")` with `briefs.iter_brief_templates()`. In `skill_lint.py`, scan both brief dirs (guard the firmware dir with `.exists()`), keeping the DIVE/DECIDE/REPORT return-contract basenames.

- [ ] **Step 4: Repoint inventory paths**

Update the firmware-brief paths in `feature_lists.json` and the two asserts in `tests/test_harness.py` to the new location.

- [ ] **Step 5: Run the affected gates**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_brief_templates.py tests/test_hunt_brief.py tests/test_firmware_chain_brief.py tests/test_firmware_fpcheck_brief.py tests/test_surface_brief.py tests/test_diff_brief.py tests/test_triage_brief.py tests/test_firmware_dive_brief.py tests/test_firmware_decide_brief.py tests/test_firmware_report_brief.py tests/test_harness.py` and `python3 audit.py lint-skill` and `python3 scripts/harness.py --only manifest`. Assert the brief byte-hashes match Step 1.

- [ ] **Step 6: Commit** `refactor(split): relocate firmware worker briefs`

### Task 3: Firmware SKILL.md and codebase-audit SKILL.md split

**Files:**
- Create: `firmware-audit/SKILL.md`
- Create: `firmware-audit/claude/commands/firmware-audit.md` and per-phase launchers
- Modify: `SKILL.md` (remove firmware stage sections, tiering rows, router firmware line, brief-index count; add a one-line pointer)
- Modify: `scripts/eol-manifest.txt` (add `firmware-audit/SKILL.md` if CRLF)
- Modify: firmware brief tests that assert a `### Stage 4x firmware …` heading in the root SKILL.md (`tests/test_firmware_chain_brief.py`, `tests/test_firmware_fpcheck_brief.py`, and any sibling) — repoint to `firmware-audit/SKILL.md`

**Interfaces:**
- `firmware-audit/SKILL.md` frontmatter `name: firmware-audit`; router for stages 4a qualify → 4j report, each naming the exact verb (`qualify, acquire, triage, diff, surface, hunt, fpcheck, chain, dive, decide, firmware-report`) and its brief via `__SKILL_DIR__/audit.py brief --phase <p>`.

- [ ] **Step 1: Write failing routing tests**

New `tests/test_firmware_audit_skill.py`: `firmware-audit/SKILL.md` exists, frontmatter `name: firmware-audit`, contains every firmware stage verb and each referenced brief resolves via `briefs.template_path`; the root `SKILL.md` contains no `firmware` stage heading and no firmware `brief --phase` line.

- [ ] **Step 2: Run, observe failure**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_audit_skill.py`

- [ ] **Step 3: Author `firmware-audit/SKILL.md` and launchers; edit root `SKILL.md`**

Lift stages 4e–4j from the root SKILL.md; author 4a–4d router prose from the parent contract; copy worker-authority/economics prose, do not re-derive. Add the firmware-audit launchers mirroring the codebase-audit launcher pattern. In root SKILL.md remove firmware sections/rows/lines and add one pointer sentence to the firmware-audit skill. Preserve each file's CRLF/LF per the existing convention.

- [ ] **Step 4: Repoint SKILL.md-heading asserts; run gates**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_audit_skill.py tests/test_firmware_chain_brief.py tests/test_firmware_fpcheck_brief.py tests/test_brief_templates.py` and `python3 audit.py lint-skill` and `python3 scripts/harness.py --only eol --only manifest`. Grep edited root SKILL.md for dangling `firmware` links.

- [ ] **Step 5: Commit** `feat(split): route firmware stages from firmware-audit skill`

### Task 4: Installer source-split and `--skill` selector

**Files:**
- Modify: `install.sh`
- Modify: `install.ps1`

**Interfaces:**
- `install_skill_files(surface_dir, core_dir, skill_name, dest)` / `Install-SkillFiles -SurfaceDir -CoreDir -SkillName -Dest`: surface (SKILL.md, references/, workflows/, launchers) from `surface_dir`; `audit.py` + `audit_core/` always from `core_dir` (repo root); ends with installed-tree `selftest`.
- CLI: `--skill codebase-audit|firmware-audit|all` (default `all`); outer loop over selected skills × selected clients. `codebase-audit` surface = repo root; `firmware-audit` surface = `firmware-audit/`. Firmware launcher source = `firmware-audit/claude/commands/`. `--uninstall` loops skills.

- [ ] **Step 1: Author the derivation**

Write `docs/superpowers/derivations/2026-11-10-firmware-audit-install.md` with the intended install.sh/install.ps1 change list (surface/core split, `--skill`, per-skill loop, launcher source branch, uninstall loop), then reconcile against `git diff -U0` after the edit.

- [ ] **Step 2: Implement the sh and ps1 changes symmetrically**

Keep the clone-in-place guard (compare against the root checkout). Thread `skill_name` through destinations and echo strings.

- [ ] **Step 3: Smoke both skills into a throwaway HOME**

Run `install.sh --skill all` with `HOME`/`CODEX_HOME` set to a `mktemp -d`; assert both `~/.claude/skills/{codebase-audit,firmware-audit}/audit.py selftest` pass and no `__SKILL_DIR__` survives in either installed tree. Never run the installer against the real HOME.

- [ ] **Step 4: Commit** `feat(split): install codebase-audit and firmware-audit separately`

### Task 5: Install gate and self-containment tests

**Files:**
- Modify: `scripts/harness.py` (`gate_install`: `CLIENT_ROOTS` + `real_install_dirs` add firmware-audit roots; add a firmware-audit installed-`selftest` assertion)
- Create: `tests/test_firmware_audit_install.py`

**Interfaces:**
- Consumes Task 4 installer.

- [ ] **Step 1: Write failing install tests**

`tests/test_firmware_audit_install.py`: into a sandbox `HOME`, install both skills; assert each tree is self-contained (`audit.py`, `audit_core/`, `SKILL.md`, its briefs, and `firmware-audit`'s `references/phase5-fp-check.md` present), `selftest` passes inside each, no `__SKILL_DIR__` survivor, firmware briefs only under `firmware-audit/`, generic briefs under `codebase-audit/`, real install dirs' mtimes unchanged, and the sandbox-equals-real-HOME refusal still fires.

- [ ] **Step 2: Run, observe failure**

Run: `python3 -m pytest -q -p no:cacheprovider tests/test_firmware_audit_install.py`

- [ ] **Step 3: Extend `gate_install`; make the tests pass**

Add firmware-audit roots to `CLIENT_ROOTS`/`real_install_dirs`; add the firmware-audit installed-selftest assertion; ensure the default install path exercises both skills.

- [ ] **Step 4: Run the install gate**

Run: `python3 scripts/harness.py --only install` and the new test file.

- [ ] **Step 5: Commit** `test(split): gate both installed skills`

### Task 6: Docs, inventory, amendment, and final harness

**Files:**
- Modify: `ARCHITECTURE.md`, `README.md`, `progress.md`, `SESSION_HANDOFF.md`, `feature_lists.json`
- Modify: `docs/superpowers/specs/2026-10-04-audit-suite-design.md` (dated §3.1 amendment: approach B adopted)

- [ ] **Step 1: Reconcile present-state docs and inventory**

Record two installed skills over one shared core, the `--skill` install shape, `codebase-audit` unchanged in behavior, firmware briefs under `firmware-audit/`. Close `separate-firmware-skill-tree`. Append the dated §3.1 amendment. Keep feature/stage/open-item counts consistent, stating any change.

- [ ] **Step 2: Manifest/selftest checks**

Run: `python3 audit.py selftest && python3 scripts/harness.py --only manifest --only eol`

- [ ] **Step 3: Commit** `docs: record firmware-audit skill split`

- [ ] **Step 4: Final full harness**

Run: `make all`. Expected: all eight gates pass; coverage zero unexecuted; install gate covers both skills; real install untouched.

- [ ] **Step 5: Record measured results; rerun `make all` after the doc edit**

Commit `docs: record firmware-audit split verification`; rerun `make all` per AGENTS.md rule 3.
