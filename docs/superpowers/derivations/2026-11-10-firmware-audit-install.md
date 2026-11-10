# Derivation — installer source-split and `--skill` selector (Task 4)

**Date:** 2026-11-10
**Spec:** docs/superpowers/specs/2026-11-10-firmware-audit-skill-split-design.md (resolution R3)
**Files:** `install.sh`, `install.ps1`

Teaches both installers to install either skill (`codebase-audit`,
`firmware-audit`, or both). The per-skill install is parameterized so the
operator-facing **surface** (SKILL.md, references/, workflows/ if any,
launchers) comes from a per-skill *surface dir*, while the shared `audit.py` +
`audit_core/` always come from the repo-root *core dir*. The two scripts stay
symmetric.

## Intended change list

### 1. Surface / core split in the copy helper

- `install_skill_files` / `Install-SkillFiles` take `(surface_dir, core_dir,
  dest)` (ps1: `-SurfaceDir -CoreDir -Dest`).
  - Surface files — `SKILL.md`, `references/`, `workflows/` — copied from
    `surface_dir`. `workflows/` skipped gracefully when absent (firmware ships
    none).
  - `audit.py` and `audit_core/` copied **verbatim** from `core_dir` (always the
    repo root). Never `__SKILL_DIR__`-substituted.
  - `__SKILL_DIR__` substitution unchanged for the surface: installed
    `SKILL.md`, `references/**/*.md|.txt`, `workflows/**`, and launchers.
- Clone-in-place guard unchanged in intent: refuse when `dest` IS the repo-root
  checkout (compare `abs_target` against `core_dir`, i.e. the root).
- Each per-skill install still ends with `python3 <dest>/audit.py selftest` and
  aborts on nonzero.

### 2. `--skill` selector

- sh: new `--skill codebase-audit|firmware-audit|all` flag case in the arg loop
  (consumes the next token). Does NOT disturb the existing
  `copilot|claude|codex|all` client selectors, `--insiders`, `--uninstall`,
  `-h`. Default (no `--skill`) = `all` skills. Validation rejects unknown skill
  names.
- ps1: new real `[string]$Skill` named param (default `all`). Being named, it is
  not swallowed by the `ValueFromRemainingArguments` `$Targets`. Validation +
  expansion to `@('codebase-audit','firmware-audit')` for `all`.

### 3. Per-skill loop and destinations

- Outer loop over selected **skills**, inner loop over selected **clients**.
- Per skill `<s>`, surface dir:
  - `codebase-audit` → repo root (`SCRIPT_DIR` / `$ScriptDir`).
  - `firmware-audit` → `<root>/firmware-audit/`.
- Per-skill destinations (recomputed each skill from `<s>`):
  - Copilot: `~/.copilot/skills/<s>/`
  - Claude: `~/.claude/skills/<s>/` + `~/.claude/commands/<s>.md` +
    `~/.claude/commands/<s>/*.md`
  - Codex: BOTH `~/.agents/skills/<s>/` and
    `${CODEX_HOME:-~/.codex}/skills/<s>/`
- Launcher source is uniform: `<surface_dir>/claude/commands/<s>.md` plus
  `<surface_dir>/claude/commands/<s>/*.md`. Firmware launchers therefore come
  from `firmware-audit/claude/commands/`.

### 4. `--uninstall` loops skills

- Outer skill loop wraps the client uninstall switch so BOTH skills' install
  dirs (and Claude launcher files/dirs) are removed, never orphaned.

### 5. Post-install tips

- Tips move inside the per-skill loop and name `<s>`. Phase hint list branches
  per skill (codebase: recon/deploy/audit/fpcheck/verify/report; firmware:
  qualify/acquire/triage/diff/surface/hunt/fpcheck/chain/dive/decide/
  firmware-report).

## Reconciliation against `git diff -U0`

Reconciled after editing — see Task 4 report. Confirmed: surface/core params
threaded through both copy helpers; `--skill` flag (sh) and `[string]$Skill`
param (ps1) added without disturbing client selectors; outer skill × inner
client loops in install and uninstall; destinations and launcher source derive
from `<s>`; guard compares against the root core dir; each install ends in
`selftest`; `audit.py`/`audit_core` never substituted.
