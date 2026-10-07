# Session handoff

**Written:** 2026-10-07 · **HEAD:** `3aaebb5` on `main`, working tree clean ·
**Tests:** 491 · **Gates:** 7/7 green

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

- **Branch:** `main` at `3aaebb5`, clean. Stages 0–3 merged. No open branches,
  no SDD workspace (deleted after the Stage 3 merge).
- **`main` is 84 commits ahead of `origin/main` and has never been pushed.**
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
PASS  tests       491 passed
PASS  selftest    verbs 20 declared / tables 15 in schema.sql, 14 under contract / migrations 4
PASS  lint        skill lint: clean
PASS  eol         6 CRLF files, 116 LF
PASS  manifest    29 features ... all paths and verbs resolve
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
**deterministic leading indicators** in between — indicators that have never
been built. Building them is therefore the first task.

## 4. What to do next

### Option A — build the deterministic leading indicators (recommended)

Spec §6.1 names four: coverage percentage, surfaces opened, sweep hit counts,
`not_audited` row count. Nothing emits them. They read an existing `audit.db`
and cost nothing per run, and until they exist, deferring the gate is blind
rather than merely deferred.

### Option B — close the `bench` measurement gaps

Two, both scoring an `audit.db` that already exists:

- **Severity agreement.** `bench` loads `severity` on both sides and compares
  neither. Four of the nine reference CRITICALs the audit found were rated
  below the reference, one of them a pre-authentication auth bypass filed as
  LOW. Until this is scored, Stage 4's ≥ 12/19 target can be hit while still
  mis-rating half of what it finds.
  See `docs/superpowers/specs/2026-10-05-stage0-findings-for-later-stages.md` §1.
- **Coverage.** §6.1 says `bench` reports recall, precision, **coverage** and
  cost per finding. It reports three of the four.

Then the pipeline change the same finding implies: a step that **re-derives
severity once reachability and chain composition are known**, rather than
fixing it at discovery time.

### Option C — close the parked defects

The preflight `--server` flatten, the briefs one-error-class-per-run, the
`--replace` column blanking, the fpcheck batch-id mismatch. All small, all
verified open on 2026-10-07.

### Option D — push `main`

84 commits are local-only. Needs a reachable origin.

### Held, not forgotten — the tiering gate

[`docs/baselines/2026-10-05-stage3-tiering-gate.md`](docs/baselines/2026-10-05-stage3-tiering-gate.md)
carries the procedure *and the exact five-file diff*. It needs four audit
runs, so it stays held under the standing instruction above. Two guard tests
in `tests/test_skill_lint.py` fail deliberately if the diff is applied without
running the gate — that is the point of them; do not "fix" them.

### Option E — plan Stage 4

`firmware-audit` plus the monorepo restructure, spec §4 and §3.1. Note the
gate requires **two** targets: tplink ≥ 12/19 at ≤ $45 *and* the asus golden
passing, to guard against overfitting. The asus golden does not exist yet, so
building it is the real first task.

Given the 97.5% precision against 47.4% recall, Stage 4's ≥ 12/19 target is a
**recall** problem. Spend the effort on breadth, not on filtering.

Spec §10 is still undecided — whether `grey-audit` joins the monorepo or
consumes the core as a submodule. It blocks the restructure, not the firmware
phases, so it can be decided alongside rather than first.

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
  `identify --replace` no longer blank optional columns. **They still do.**
  The behaviour is real, pre-existing, and parked with a ruling.
- A Stage 3 derivation miscounted its own hunks as 21 against an actual 15,
  and the wrong figure propagated into both an implementer report and a review
  brief.
- A task report cited "the brief" for an authorisation that had actually come
  from the dispatch message.

The general lesson: **subagent reports are evidence, not verdicts.** Verify
load-bearing claims against the tree.
