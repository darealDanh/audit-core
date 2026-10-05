# Findings from Stage 1 that belong to later stages

Recorded 2026-10-05, at the end of Stage 1. These came out of building and
reviewing the economics work, not from the design that preceded it.

## 1. Rewriting shipped prose from scratch loses instructions, five times out of five

Stage 1 replaced inline subagent prompts with rendered brief templates. Every
template was written fresh rather than derived line by line from the prompt it
replaced, and every one lost something:

| Lost | Caught by |
|---|---|
| 18 Hard Exclusions, 10 Precedent rules, 3 Capability Validity checks | the implementer, who refused a literal instruction |
| 6 of 16 vulnerability hunt categories, including XXE and CSRF | task review |
| 2 of 9 false-positive method steps, including the confidence-threshold gate | task review |
| the patch-bypass probe instruction, while the phase exit still gated on it | whole-branch review |
| the live-PoC conduct prohibitions — no exfiltration, no permanent crash, no credential changes, no persistence | whole-branch review |

Plus eight smaller narrowings: IDOR, algorithmic-complexity DoS, a four-item
mitigations checklist, the zero-findings coverage statement, the
`artifact_path` instruction, the data-flow tracing step, cross-batch verdict
visibility, and the per-feature mapping output format.

All were restored and most are now pinned by guard tests. But the pattern is
the finding, not the individual losses: **five separate reviews each caught a
different subset, and none caught all of them.** A sixth narrowing surviving
into a stage with no whole-branch review is the realistic failure mode.

**Implication:** any later stage that rewrites shipped prose must produce an
explicit derivation — the old instruction set diffed against the new, with a
justification for every dropped line — as a reviewable artifact, rather than
relying on a reviewer to notice an absence. Absence is the hardest thing to
review for; a reviewer sees what is there.

## 2. A clean lint run is not a statement that the skill works

`audit.py lint-skill` checks four rules, soon five, and each is a literal
string match that pins a specific mistake this project has actually made. That
design is deliberate: a fuzzy linter over English prose produces false
positives on legitimate text and gets disabled.

The honest scope statement, which belongs anywhere the linter's output is
cited: **these rules pin specific past mistakes. A clean run means those five
mistakes are absent. It is not evidence the skill functions.**

This is not hypothetical. During Stage 1 the linter reported clean on a tree in
which every command it checks was unrunnable, because the defect — an
unsubstituted installer sentinel — was not among the things it looked for. The
fifth rule now covers that specific defect. It does not cover the sixth.

## 3. Two verification gaps are standing, not closed

- **`install.ps1` has never been executed.** No PowerShell exists on the
  development machine. Every change to it across Stage 0 and Stage 1 was
  verified by reading against the bash logic. It now carries non-trivial
  behaviour: sentinel substitution across every skill file, a remove-then-copy
  for `references/briefs/`, and a clone-in-place refusal. A Windows smoke test
  is the single highest-value verification this project does not have.
- **`audit.py preflight` is verified at config-content level only.** The
  generated `.audit-mcp.json` has never been handed to a client that then
  connected a real MCP server. R4's whole value is that the strict relaunch
  still has the servers the run needs.

## 4. Smaller items carried forward

- Batch identifiers still differ between files (`A, B, C` in `workflows/fpcheck.md`
  versus `B1, B2` in the references), even though the artifact *path pattern*
  is now uniform.
- `install.sh` does not remove `workflows/` or `references/` before copying,
  while `install.ps1` now does, so a file deleted from the repo lingers in a
  `.sh`-installed tree.
- `audit_core/briefs.py` reports missing placeholders before empty ones, so an
  operator fixing one class discovers the other only on the next run.
- `--server NAME=COMMAND` silently overwrites a `--keep`-copied server object
  of the same name with a bare `{"command": ...}`, which is the degradation
  that option exists to prevent. Untested.
