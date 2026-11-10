# Firmware-audit skill split — design

**Date:** 2026-11-10
**Status:** proposed
**Parent spec:** docs/superpowers/specs/2026-10-04-audit-suite-design.md (§3.1 repository layout, §3.2 install, §10 + Amendment 2026-11-10)

## Intent

Ship `firmware-audit` as its own installed skill — its own name, SKILL.md, worker briefs and launchers — while `codebase-audit` keeps working unchanged at every step. This closes the `separate-firmware-skill-tree` open item and realizes the parent spec's two-sibling model.

The split is a packaging and routing change, not a Python refactor. The firmware phases are behavior on the shared `audit_core` spine; they stay there. What separates is the operator-facing surface: which SKILL.md a client installs, which briefs and launchers ship with it, and how phases are routed.

## Decisive constraint

`audit.py` registers every verb (generic and firmware) in one argparse table and one `HANDLERS` map; `audit.py selftest` cross-checks `HANDLERS` ↔ subparsers ↔ `schema.sql` `TABLE_SPECS` ↔ `MIGRATIONS`. `audit_core` is one package with dense cross-imports, and `briefs.TEMPLATE_DIR` is `audit_core/../references/briefs`, so `audit_core/` and `references/` must stay siblings in any installed tree. Removing firmware modules or verbs from the shared core would fail `selftest` and strand the briefs.

Therefore both skills vendor the **same** `audit.py` + `audit_core/` + `schema.sql`. The core is identical; the skills differ only in SKILL.md, the `references/` set they ship, and their launchers. `codebase-audit` retains the firmware verbs in its CLI (they stay dispatchable and `selftest` stays green); it simply stops *routing* them from its SKILL.md.

## Approaches considered

### A. Parent-spec `audit-suite/skills/<name>/` source reorg — rejected

Move every shipped file into `skills/codebase-audit/` and `skills/firmware-audit/`, keep one source `audit_core/` at repo root, vendor it into each skill at install. This matches §3.1 literally but breaks dev-time imports (`audit.py` assumes `audit_core` is a sibling; it would become `../../audit_core`), and forces rewrites across the harness, Makefile, `scripts/*manifest*`, every `tests/` path, `skill_lint._is_source_checkout`, and `gate_install` `CLIENT_ROOTS`. The only *installed* benefit over approach B — a self-contained per-skill tree — approach B already delivers, because the installer vendors the core into each skill's install dir regardless of source layout. Large blast radius for no installed difference.

### B. Flat source, second installable skill over the shared core — selected

Source stays flat: `audit_core/`, `audit.py`, `tests/`, `scripts/`, `Makefile` unchanged at repo root. Add a `firmware-audit/` source subtree holding only what differs: its SKILL.md, its `references/` (firmware briefs and firmware-facing reference docs), and its `claude/commands/` launchers. The installer learns a second skill name and, for `firmware-audit`, vendors the shared `audit.py` + `audit_core/` plus the firmware subtree's SKILL.md/references/launchers into `~/.<client>/skills/firmware-audit/`. `codebase-audit`'s SKILL.md drops the firmware stage subsections (they move to `firmware-audit/SKILL.md`); its code is untouched.

Installed outcome is identical to A (two self-contained skill trees sharing a vendored core); dev-time cost is a fraction.

### C. Keep interleaved, rename nothing — rejected

Does not close the open item; firmware stays a hidden set of subsections inside the generic skill with no discoverable `firmware-audit` entry point.

## Target source layout (approach B)

```
codebase-audit/                     # repo root (name unchanged this stage)
├── audit.py                        # shared, unchanged
├── audit_core/                     # shared, unchanged
├── SKILL.md                        # codebase-audit routing; firmware subsections removed
├── references/                     # codebase-audit briefs + generic reference docs
├── workflows/                      # codebase-audit workflows, unchanged
├── claude/commands/                # codebase-audit launchers, unchanged
├── firmware-audit/                 # NEW — firmware skill surface only
│   ├── SKILL.md                    # firmware routing (stages 4a–4j)
│   ├── references/
│   │   ├── briefs/                 # firmware briefs MOVED here
│   │   │   ├── triage-brief.md  diff-brief.md  surface-brief.md
│   │   │   ├── hunt-brief.md  firmware-fpcheck-brief.md  firmware-chain-brief.md
│   │   │   └── firmware-dive-brief.md  firmware-decide-brief.md  firmware-report-brief.md
│   │   └── *.md                    # firmware-facing reference docs (as needed)
│   └── claude/commands/            # firmware-audit launchers
├── install.sh  install.ps1         # learn the firmware-audit skill
├── tests/  scripts/  Makefile  docs/   # dev-only, unchanged locations
```

Briefs that are purely firmware move out of the root `references/briefs/` into `firmware-audit/references/briefs/`. Briefs shared by both surfaces (`audit-brief.md`, `recon-brief.md`, generic `fpcheck-brief.md`) stay at root; if a brief is needed by both, it is copied, not symlinked, so each installed skill is self-contained (the parent spec's rule).

## Install model

`install.sh [client...] [--skill codebase-audit|firmware-audit|all]` (default `all` skills, all clients). For each selected (skill, client):

- Destination `~/.<client>/skills/<skill>/` (Codex: both `~/.agents/skills/<skill>/` and `${CODEX_HOME:-~/.codex}/skills/<skill>/`), Claude launchers under `~/.claude/commands/<skill>/`.
- Vendored into every skill: `audit.py` (verbatim), whole `audit_core/` (minus `__pycache__`), and the skill's own `SKILL.md`, `references/`, `workflows/` (firmware-audit ships none initially), `claude/commands/`.
- `__SKILL_DIR__` substituted in the installed `SKILL.md`, `references/**/*.md`, `workflows/**/*.md` and launchers, pointing at that skill's own install dir, so every `python3 __SKILL_DIR__/audit.py` and `__SKILL_DIR__/audit_core/...` path resolves within the self-contained tree.
- Each install ends with `python3 <dest>/audit.py selftest`; both skills vendor the full core, so both pass.

The parent-spec "two installer defects" are fixed incidentally: the installer already copies `audit_core/` + `audit.py` (the scout confirmed; the spec's claim that it drops them is stale), and both Codex dirs are already written. No regression there; the new work is the second skill name and its destination set.

## Backward compatibility

- `codebase-audit` installs and runs exactly as before; only firmware stage prose leaves its SKILL.md. Its `audit.py`/`audit_core` are byte-identical, so its `selftest`, verbs and schema are unchanged.
- The firmware verbs remain in `codebase-audit`'s CLI (shared core); an operator who runs them there still works. The split makes `firmware-audit` the discoverable, documented home, not an exclusive one.
- No schema, migration, table, or Python-behavior change. `make all` test/selftest/coverage/bench results are unchanged except for the install and manifest gates.

## Routing surfaces

`codebase-audit/SKILL.md`: remove the Stage 4e–4j `###` subsections, the Stage-4e model-tiering rows, the firmware brief-index line and the 4b–4d firmware prose; keep generic recon/deploy/audit/fpcheck/verify/report/source routing. A one-line pointer notes that firmware auditing lives in the `firmware-audit` skill.

`firmware-audit/SKILL.md` (new): frontmatter `name: firmware-audit`, description triggers `$firmware-audit` / `/firmware-audit`; a router covering stages 4a qualify → 4j report with the exact verbs (`qualify, acquire, triage, diff, surface, hunt, fpcheck, chain, dive, decide, firmware-report`), each pointing at its brief under this skill's `references/briefs/` and the shared `audit.py` verb. Worker-authority and economics prose is copied from the parent contract, not re-derived.

Firmware launchers: add `firmware-audit/claude/commands/firmware-audit.md` plus per-phase launchers mirroring the codebase-audit launcher pattern, so Claude exposes `/firmware-audit`.

## Lint, harness and manifest

- `skill_lint.py`: `_is_source_checkout` still keys on `install.sh` presence (unchanged). The brief return-contract map must resolve firmware briefs at their new path; extend the lint to scan both `references/briefs/` and `firmware-audit/references/briefs/`, keeping the firmware-specific return contracts (DIVE/DECIDE/REPORT) mapped to the moved files. A firmware brief in neither location, or under the wrong contract, fails lint.
- `scripts/harness.py` `gate_install`: snapshot both skills' client roots in `CLIENT_ROOTS`; run the installer for both skills into the sandbox; assert zero `__SKILL_DIR__` survivors across both installed trees and real-install mtimes unchanged for both. `make install-smoke` covers both.
- Manifest gate (`scripts/*manifest*`, `eol-manifest.txt`): add `firmware-audit/**` shipped files with their line-ending class; firmware SKILL.md/briefs follow the existing CRLF/LF rules (briefs ship LF, SKILL.md may be CRLF — match the codebase-audit convention per file).
- Feature/stage inventory in `feature_lists.json`: record the split; `separate-firmware-skill-tree` moves to closed.

## Documentation and durable state

Update `ARCHITECTURE.md`, `README.md`, `progress.md`, `SESSION_HANDOFF.md`, `feature_lists.json` to describe two installed skills over one shared core, the install command shape, and that `codebase-audit` is unchanged in behavior. The parent spec's §3.1 is annotated (dated amendment) to record that the flat-source/second-skill model (approach B) is adopted in place of the `skills/` subdir reorg, with the same installed outcome.

## Testing strategy

- A new `tests/test_firmware_audit_install.py` (or an extension of the existing install test): installs both skills into a sandbox `HOME`, asserts each tree is self-contained (`audit.py`, `audit_core/`, SKILL.md, its briefs all present; `selftest` passes inside each), no `__SKILL_DIR__` survivors, firmware briefs present only under `firmware-audit/`, generic briefs present under `codebase-audit/`, real install untouched.
- A routing lint/test: `codebase-audit/SKILL.md` contains no firmware stage heading; `firmware-audit/SKILL.md` contains every firmware stage verb and each resolves to a shipped brief.
- `skill_lint` over both brief dirs stays clean; `make all` (eight gates) passes with install and manifest reflecting the second skill and every other gate unchanged.

## Builder-check resolutions (2026-11-10)

An independent builder check confirmed approach B is sound (installer copy-set
and `selftest`-stays-green claims verified) but found the brief relocation and
its test/manifest fallout understated. These five decisions are binding.

**R1 — Briefs physically move; `TEMPLATE_DIR` becomes a multi-dir resolver.**
Firmware briefs are `git mv`d into `firmware-audit/references/briefs/`. `briefs.py`
gains an ordered brief-directory list and a `template_path(phase)` helper that
searches root `references/briefs/` then `firmware-audit/references/briefs/`;
`TEMPLATE_DIR` stays as the root entry for back-compat. `write_brief` uses the
resolver. Every existing direct `briefs.TEMPLATE_DIR / "<phase>-brief.md"` read and
the `TEMPLATE_DIR.glob("*-brief.md")` enumeration in the tests migrates to the
resolver. Rendered brief bytes are identical; this is an enumerated test edit, not
a behavior change.

**R2 — The real split: firmware leaves `codebase-audit/SKILL.md`.** Stages 4e–4j
subsections, the Stage-4e model-tiering rows, the router intro firmware line and
the brief-index count drop to the three generic briefs. Firmware brief tests that
assert a `### Stage 4x firmware …` heading in the root SKILL.md are repointed to
`firmware-audit/SKILL.md`. `firmware-audit/SKILL.md` authors the full 4a–4j router;
4a–4d routing is net-new prose (it never had `###` headers), copied from the parent
contract, not invented.

**R3 — Installer is a source-split with a per-skill loop.** `install_skill_files`/
`Install-SkillFiles` take `(surface_dir, core_dir=root, skill_name)`: surface
(SKILL.md, references/, workflows/, launchers) from `surface_dir`, `audit.py` +
`audit_core/` always from `core_dir`. A `--skill codebase-audit|firmware-audit|all`
selector (default all) drives an outer loop; sh adds a flag case, ps1 adds a real
`[string]$Skill` param. Firmware launcher source is `firmware-audit/claude/commands/`.
`--uninstall` loops skills too. The clone-in-place guard is unchanged.

**R4 — Self-containment: enumerate generic docs a firmware brief cites.**
`firmware-fpcheck-brief.md` cites `__SKILL_DIR__/references/phase5-fp-check.md`; that
file (audited to be the only such case) is copied into `firmware-audit/references/`
so the installed firmware tree is self-contained. The build greps the moved briefs
for `__SKILL_DIR__/references/` to confirm the set is complete.

**R5 — Enumerated forced edits.** The relocation repoints the firmware-brief path
entries in `feature_lists.json` (~lines 170, 233, 478–479, 546, 607, 1339, 1369,
1412, 1539, 1579) and the two inventory asserts in `tests/test_harness.py`
(hunt-brief, firmware-fpcheck-brief), extends `gate_install` (`CLIENT_ROOTS` plus a
firmware-audit installed-`selftest` assertion), and existence-guards the second
`skill_lint` brief scan. These are listed, not incidental.

## Migration sequence (plan will expand)

1. Add the `briefs` multi-dir resolver and `template_path` helper (R1); `git mv` the firmware briefs into `firmware-audit/references/briefs/`; copy the cited generic docs (R4); migrate the direct `TEMPLATE_DIR` test reads.
2. Remove firmware subsections from `codebase-audit/SKILL.md`; add the pointer.
3. Teach `install.sh` / `install.ps1` the `--skill` selector and firmware destinations.
4. Extend `skill_lint`, `gate_install`, and the manifests for both skills.
5. Add install/routing tests; reconcile docs and inventory; run `make all`.

## Acceptance criteria

1. `firmware-audit` installs as a self-contained skill for all three clients, `selftest` green inside each installed tree.
2. `codebase-audit` installs and behaves exactly as before; its `audit.py`/`audit_core` are byte-identical to pre-split.
3. Firmware worker briefs ship under `firmware-audit/` and are discoverable via `audit.py brief` from that skill; no firmware brief is stranded.
4. `codebase-audit/SKILL.md` routes no firmware stage; `firmware-audit/SKILL.md` routes every firmware stage to a shipped brief and the shared verb.
5. `skill_lint`, the install smoke gate and the manifest gate cover both skills; real install dirs are never touched by the sandboxed smoke.
6. Behavior is unchanged — no schema, migration, table, verb-behavior or rendered-brief-output change; the only test edits are the enumerated relocation repoints (R1/R2/R5) plus new install/routing tests; `make all` passes all eight gates with zero unexecuted statements.
7. Docs and inventory record two skills over one shared core; the parent §3.1 amendment and the closed open item are in place.
8. Independent review finds no Critical or Important issue.
