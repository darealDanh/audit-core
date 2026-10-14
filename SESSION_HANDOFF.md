# Session handoff

**Written:** 2026-10-14 · **Branch:** `stage4d-surface` at `deb3eed` (same as local `main`); Stage 4c merged locally, not pushed ·
**Tests:** 1,209 · **Gates:** 8/8 green (`make all`; mutation remains opt-in)

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

- **Branch:** `stage4d-surface` at `deb3eed`. Stage 4c is merged into local
  `main` at this same head; its feature branch and worktree have been removed.
- **`main` is local-only at this point.** It is at `deb3eed`, 31 commits ahead
  of `origin/main` (checked 2026-10-14; `git rev-list --left-right --count
  origin/main...main` reports `0 31`). Nothing has been pushed.
- **Stage 4c is firmware-audit behavior on the shared spine, not a separate
  skill tree.** The repository still ships the `codebase-audit` skill. The
  monorepo/submodule decision remains open and blocks the later restructure.
- **Image isolation is implemented:** firmware facts now use `(image_id,
  path/name)` keys. Only target and compatible unscoped triage mirror the
  unscoped `cba_inventory`; reference triage cannot change target coverage.
- **Existing Stage 4b runs need an upgrade:** rerun `audit.py init --timestamp
  <existing timestamp>` for the same project. The atomic, idempotent firmware
  rebuild preserves facts and maps missing image IDs to `legacy-unscoped`.
  Re-triage both acquired images to populate manifests; `diff` refuses
  unscoped provenance, missing manifests, ambiguous roles, mismatched
  vendor/models, and identical acquired-image hashes.
- **Snapshot limits:** triage upserts without pruning disappeared files, so
  use fresh image scopes/runs when changing carved tree contents. Diff reads
  stored manifests rather than verifying live files. SQL replacement is
  atomic; a failed SQL write can leave an unreferenced artifact generation.
- **Review fixes:** triage publication is atomic and scan, directory-entry
  classification, and stat failures abort before writes. Direct `scandir`
  traversal propagates errors that `os.walk` suppressed, refuses inconsistent
  directory classifications, and orders regular files by relative path while
  excluding symlinks and nonregular entries. A changed acquisition hash or
  version clears only that image's
  manifest in the same transaction; diff then requires retriage. Read-side
  SQLite errors in diff reach the CLI as named errors with exit 1.

### Verify the state yourself

```bash
cd /Users/danhnguyen/Documents/Offsec/Tools/codebase-audit/.worktrees/stage4d-surface
make all          # all eight gates
```

Measured gate summary (2026-10-14, after documentation reconciliation):

```
PASS  tests      1209 passed
PASS  selftest   verbs  26 declared, all dispatchable / tables 21 in schema.sql, 20 under contract, columns and primary keys agree / migrations 4 plus current schema applied to the pre-Stage-3 and Stage-4b baselines, firmware rows preserved, results accepted by connect()
PASS  lint       skill lint: clean
PASS  eol        6 CRLF files, 175 LF
PASS  manifest   42 features, 11 stages, 20 open items, all paths and verbs resolve
PASS  install    100 markdown files installed, 0 sentinel survivors, real install untouched
PASS  coverage   0 unexecuted / 3170 statements, 0 allowed
PASS  bench      recall 9/19, 45 findings, precision 39/40, $73.15 per match

all 8 gate(s) passed
```

The real output also prints a per-gate duration; the block omits variable times.
The residual-fix focused suite passes 133 tests; the full harness includes the
available GL.iNet corpus check. The final review regressions cover failed
fresh/retriage writes, acquisition replacement, unreadable traversal,
classification and scan-iteration errors with readable siblings, and read-side
SQLite errors. Fresh failures leave all four triage publication tables empty;
failed retriage preserves every prior row, including timestamps.

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
(`audit.py indicators`). Stage 4c only rescored the existing read-only
benchmark database; it ran no new audit and did not change the deferral.

## 4. What to do next

Stages 0 through 3c and Stages 4a-4b are merged to local `main`. Stage 4c adds
`firmware_diff.py`, the `diff` verb, image-scoped manifests, `cba_diffs` and
`cba_diff_entries`, composite firmware keys, and the diff dispatch brief.
Comparison stores every changed path in SQL and deterministic JSON while the
terminal result stays bounded. The agent brief requires evidence for the
vendor's fix and a target-only sibling search; changed bytes are not findings.
The read-only GL.iNet check proves inventory/manifest/ELF/service consistency.

### Design and implement Stage 4d (`surface`)

Stage 4c is integrated into local `main`; its whole-branch review fix wave and
residual classification fix are applied. Stage 4d design/implementation is
next. It inherits the need to preserve image scoping and the target-only
coverage rule, plus triage's upsert-only snapshot limitation. The asus golden
remains a prerequisite for the later Stage 4 milestone gate.

Stage 4d is dispatch/handler mapping, authentication boundaries, device state,
and reachability evidence. It inherits image scoping, the target-only coverage
rule, and triage's upsert-only snapshot limitation. Stage 4c does not fetch,
carve, infer ports, run emulation, inspect the kernel/bootloader, or create the
separate `firmware-audit` tree. Its semantic agent quality has not been measured
by an audit; benchmark gates remain deferred.

### Decide the remaining prose-string mutation survivors

`make mutate` (opt-in, about 54 minutes) is left failing on purpose: 360 of
1068 mutants survived the frozen sweep, Task 15 killed 32 logic survivors and
allowlisted 9 equivalent ones, and the rest are mostly prose-string constants
(`audit_core`'s tests assert behaviour, not message text). Either pin the
messages that matter or allowlist the rest with reasons. A post-fix sweep is
recorded as its own dated note; never edit
`docs/baselines/2026-10-08-mutation-sweep.md`.

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

Stage 4 is built as vertical slices. Stage 4a shipped `qualify`; Stage 4b shipped
`acquire` and `triage`; Stage 4c implements `diff` on its feature branch. These
four phases were built at zero audit cost. The remaining seven
firmware phases do not exist yet, nor does the separate firmware skill tree.

### Stage 4 milestone work

The milestone gate requires **two** targets: tplink >= 12/19 at <= $45 *and*
the asus golden passing, to guard against overfitting. The asus golden does not
exist yet. Spec §10 remains undecided and blocks the monorepo/submodule
restructure, not the next firmware phases.

Stage 3b measured severity: `severity 5/9 agree`, 4 under-rated, `weighted
recall 0.382` against `recall 9/19`. Stage 4's target is a **recall** problem,
but a finding made and filed LOW is not a finding found, so watch both.


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
4. A new unexecuted `audit_core` statement needs a test, or an allowlist
   entry with a reason: `python3 scripts/coverage_allowlist.py --add
   <module>.py:<line> "<reason>"` (the gate's FAIL output prints the exact
   command and a pasteable line). The coverage gate fails on an unlisted gap
   and on a stale entry. Prefer the test; a covered
   line can still be hollow, so assert on the value the line decides.
5. Run `make all` before proposing a merge.

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
