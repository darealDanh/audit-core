# Session handoff

**Written:** 2026-10-07 · **Branch:** `main` at `3eb2a93` (Stage 4a merged), working tree clean ·
**Tests:** 615 · **Gates:** 7/7 green

Read this first if you are picking the project up cold. It covers the rules
you can break expensively, the state you are inheriting, and what to do next.

| You want | Read |
|---|---|
| What has been built and what has not | [`progress.md`](progress.md) |
| How the pieces fit and why | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| A machine-readable inventory | [`feature_lists.json`](feature_lists.json) |
| The binding authority for any design question | [`docs/superpowers/specs/2026-10-04-audit-suite-design.md`](docs/superpowers/specs/2026-10-04-audit-suite-design.md) |

---

## 1. Rules you can break expensively

These are not style preferences. Each one has a specific, known cost.

1. **Never run `install.sh` or `install.ps1` without overriding `HOME`,
   `CLAUDE_CONFIG_DIR` and `CODEX_HOME`.** The installer resolves its four
   destinations from the environment at run time, and a real working
   installation lives at `~/.claude/skills/codebase-audit/` (mtime
   `Sep 22 14:24`). An unguarded run overwrites it.
   **Use `make install-smoke`** — it sandboxes, refuses to proceed if the
   sandbox HOME resolves to the real one, and asserts afterwards that none of
   the four real destinations moved.

2. **`~/Documents/Offsec/Opswat/Devices/` and `~/.claude/projects/` are
   read-only.** Readable, never written. They hold real audit corpora and real
   session transcripts, including the benchmark's `audit.db`.

3. **Never write `tests/goldens/*/matches.json` or `rejections.json`.** Both
   are human adjudications. A tool regenerating them destroys the only
   independent reference the benchmark has.

4. **Never edit a document under `docs/baselines/` in place.** A correction is
   a new dated file, or an appended and dated note. The superseded
   `2026-10-04-tplink-baseline.md` is kept and labelled rather than deleted,
   so the correction stays visible in git history.

5. **`audit_core` is stdlib-only and reaches no network.** `pyproject.toml`
   declares `dependencies = []` and `requires-python = ">=3.10"`. `pytest` is
   the only dev dependency.

6. **Derive before editing shipped prose.** Rewriting prose in
   `SKILL.md`, `workflows/` or `references/` lost instructions five times out
   of five in Stage 1. Write the intended change list to
   `docs/superpowers/derivations/` *first*, then reconcile it against
   `git diff -U0` after.

7. **A `>` blockquote in a workflow file is presented to the user, not
   executed.** A command placed in one ships inert. Stage 3 shipped its
   coverage gate into one; it never ran in either mode.

---

## 2. State you are inheriting

- **Branch:** `stage4a/qualify`, forked from `main` at `7f1de0d`.
  Stages 0-3 and 3b are merged to `main`; Stage 4a is complete on this branch, not yet merged.
- **`main` is 122 commits ahead of `origin/main` and has never been pushed.**
  `git pull` fails with an access-rights error; origin is unreachable from
  this machine. Everything exists only in this working copy — **take that
  seriously before any destructive git operation.**
- **Backups** of the Stage 3 SDD ledger and its deferred-minors list were
  copied to `/tmp/stage3-ledger-backup.md` and `/tmp/stage3-deferred-backup.md`.
  `/tmp` does not survive a reboot; if they still exist and you want them,
  move them somewhere durable.

### Verify the state yourself

```bash
cd ~/Documents/Offsec/Tools/codebase-audit
make all          # all seven gates, ~30s
```

Expected:

```
PASS  tests       615 passed
PASS  selftest    verbs 23 declared / tables 15 in schema.sql, 14 under contract / migrations 4
PASS  lint        skill lint: clean
PASS  eol         6 CRLF files, 134 LF
PASS  manifest    35 features ... all paths and verbs resolve
PASS  install     92 markdown files installed, 0 sentinel survivors, real install untouched
PASS  bench       recall 9/19, 45 findings, precision 39/40, $73.15 per match
```

If `bench` says SKIP, the measurement corpus is not on this machine. That is
expected on any machine but the operator's, and is not a failure.

---

## 3. Standing instruction: do not run a full audit

**Operator decision, 2026-10-07.** The benchmark gates are **deferred on
cost**. The tplink baseline run cost **$658.37**; the Stage 2 + Stage 3 gate
is two such runs and the tiering gate is four. Finish the skill work first;
spend the benchmark budget once, later, on a tree worth measuring.

Do not run a gate, a tplink re-run, or any full audit to close an open item
unless the operator asks for it in so many words. Everything in §4 below is
zero-audit-cost: it changes code, changes prose, or scores an `audit.db` that
already exists.

This matches spec §6.1, which runs the benchmark at milestones only and uses
**deterministic leading indicators** in between — indicators, now built in Stage 3b
(`audit.py indicators`). This stage did not run a benchmark and did not change
the deferral.

## 4. What to do next

Stage 3b (measurement hardening) is merged to `main`, and Stage 4a (`qualify`) is
done on branch `stage4a/qualify`; the leading indicators, severity agreement,
coverage in `bench`, `rerate` and the four parked defects are no longer options.
What remains:

### Merge and push

Merge `stage4a/qualify` to `main`. `main` is 122 commits ahead of origin (from
`git rev-list --count origin/main..main` when written) and has never been
pushed; pushing needs a reachable origin.

### Take a second indicator snapshot

The first snapshot reads `absent` for coverage, sweep hits and `not_audited`,
because the only `audit.db` that exists predates those tables. A comparison
needs a second datapoint, which needs an audit run, which the standing
instruction in §3 forbids until the operator asks.

### Decide what `rerate` is for

On the real corpus it flags 9 findings, recovers G1-F4 and G1-F7 (2 of the 4
known under-rated) without the golden set, and has one known negation false
positive (G4-F4). Nothing mutates severity; that waits on a benchmark run.

### Held, not forgotten — the tiering gate

[`docs/baselines/2026-10-05-stage3-tiering-gate.md`](docs/baselines/2026-10-05-stage3-tiering-gate.md)
carries the procedure *and the exact five-file diff*. It needs four audit
runs, so it stays held under the standing instruction above. Two guard tests
in `tests/test_skill_lint.py` fail deliberately if the diff is applied without
running the gate — that is the point of them; do not "fix" them.

### What exists of Stage 4

Stage 4 is built as vertical slices. The first, **`audit.py qualify`**
(`audit_core/qualify.py`, Stage 4a), is a GO/NO-GO gate that scores a
`vendor|model` against `_intel/target-scores.csv` and refuses a target that is
strip-mined, short of RCE CVEs, or not evidenced as still supported. It runs
at zero audit cost (`draytek/vigor3910` GO, `tenda/ac18` NO-GO). The remaining
ten `firmware-audit` phases do not exist yet. Stage 4a ran no benchmark and
did not change §3.

### Plan Stage 4

`firmware-audit` plus the monorepo restructure, spec §4 and §3.1. The gate
requires **two** targets: tplink >= 12/19 at <= $45 *and* the asus golden
passing, to guard against overfitting. The asus golden does not exist yet, so
building it is the real first task.

Stage 3b measured severity: `severity 5/9 agree`, 4 under-rated, `weighted
recall 0.382` against `recall 9/19`. Stage 4's target is a **recall** problem,
but a finding made and filed LOW is not a finding found, so watch both.

Spec §10 is still undecided and blocks the restructure, not the firmware phases.

---

## 5. How work is done here

The project follows the `superpowers` process, and the artifacts of it are on
disk:

```
docs/superpowers/specs/        the design spec — the binding authority
docs/superpowers/plans/        one implementation plan per stage
docs/superpowers/derivations/  anti-absence derivations for prose edits
docs/baselines/                measurements and gate procedures
```

A new stage goes: read the spec → `superpowers:writing-plans` → the user picks
an execution method → implement → whole-branch review →
`superpowers:finishing-a-development-branch`.

**Do not skip the whole-branch review.** In both Stage 2 and Stage 3 it found
Criticals that every task-scoped review was structurally blind to — a
per-task reviewer cannot see a writer that no task was assigned to build.
Stage 3's was exactly that: the coverage gate shipped with no writer side, so
following the shipped workflow exactly produced FAIL / exit 1 on a correct run.

### If you add a feature

1. Add it to `feature_lists.json` with its `tests`, `modules` and `docs`. The
   `manifest` gate fails if any path is wrong, any verb is not dispatchable,
   or a `shipped` feature names neither a test nor a doc.
2. If you change a file's line endings, update `scripts/eol-manifest.txt` in
   the **same commit** and say why in the message.
3. If you add a gate, put it in `scripts/harness.py`. `make`, `make list` and
   CI pick it up with no further edits.
4. Run `make all` before proposing a merge.

---

## 6. Things previously claimed that turned out to be wrong

Kept here so nobody re-trusts them:

- A Stage 3 fix-wave report claimed `chain --compose --replace` and
  `identify --replace` no longer blank optional columns. **They still did.**
  The claim was wrong when made; the defect was fixed for real in Stage 3b.
- A Stage 3 derivation miscounted its own hunks as 21 against an actual 15,
  and the wrong figure propagated into both an implementer report and a review
  brief.
- A task report cited "the brief" for an authorisation that had actually come
  from the dispatch message.

The general lesson: **subagent reports are evidence, not verdicts.** Verify
load-bearing claims against the tree.
