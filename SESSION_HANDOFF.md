# Session handoff

**Written:** 2026-10-16 · **Branch:** `stage4d-surface`; last implementation `b14b4fb`; Stage 4d integration pending; local `main` remains `deb3eed`, not pushed ·
**Tests:** 2,081 · **Gates:** 8/8 green (`make all`; mutation remains opt-in)

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

- **Branch:** `stage4d-surface` in `.worktrees/stage4d-surface`, implemented
  through `b14b4fb`; Stage 4d is not merged or pushed. Stage 4c is merged into
  local `main` at `deb3eed`; its feature branch and worktree have been removed.
- **`main` is local-only at this point.** It is at `deb3eed`, 31 commits ahead
  of `origin/main` (checked 2026-10-16; `git rev-list --left-right --count
  origin/main...main` reports `0 31`). Nothing has been pushed.
- **Stages 4a–4d are firmware-audit behavior on the shared spine, not a separate
  skill tree.** The repository still ships the `codebase-audit` skill. The
  monorepo/submodule decision remains open and blocks the later restructure.
- **Image isolation is implemented:** firmware facts now use `(image_id,
  path/name)` keys. Target triage mirrors inventory with
  `db.firmware_unit_key(image_id, path)`; legacy-unscoped triage retains raw
  keys. Reference triage cannot change target coverage. Surface coverage uses
  the same deterministic image-qualified database keys as inventory, preserving
  generic coverage joins without schema changes. Preparation/import/check,
  replacement, and acquisition invalidation isolate overlapping target paths.
  Worklists/results, surface/unknown component paths, and surface-facing output
  retain raw paths. ELF/service hints are image-scoped; component hints remain
  globally keyed by raw path and advisory.
- **No ownership guessing for old raw rows:** unqualified inventory cannot
  establish acquired-image agreement. Import refuses an overlapping old raw
  surface coverage row even with `--replace`, before installation and under
  the SQL lock. Preparation/acquisition invalidation preserves ambiguous rows;
  use a fresh run if they obstruct import. No automatic migration or retriage
  pruning was added.
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
- **Surface preparation/import/check are implemented:** all target manifest
  units remain in scope; live-root path/kind/size/SHA-256 and target inventory
  agreement precede preparation. Canonical worklist/batch and result hashes
  bind every imported decision. Three tables retain runs, surfaces and unknowns;
  every unknown state needs a settling question. Honest open unknowns pass;
  missing decisions, budget skips and broken provenance fail. Only check marks
  complete, after validating every batch artifact, including claim-free batches.
  Import resets pending; replacement is batch-owned; changed target acquisition
  or prepared generation invalidates dependent surface state atomically.
  Failed publication preserves prior SQL and may leave orphan artifacts.
- **Surface error behavior:** expected SQL errors print exactly
  `surface: database operation failed`; other expected diagnostics escape
  controls/non-ASCII and are capped at 512 ASCII characters plus a newline.
  Unexpected programming exceptions propagate after rollback. Human/JSON
  output contains bounded summaries and paths, never all units or evidence.
- **Accepted performance limitation:** completion discovers claim-free batch
  evidence by scanning retained orphan result candidates. Each result is
  individually bounded, but runtime grows with retained generations. A future
  durable batch receipt should avoid this scan without capping the denominator.
- **Review gate:** the controller reviewed `deb3eed..4394621` before Task 10.
  Both Important findings were fixed in `2550866` with regression evidence;
  the scoped re-review was clean. Task 10 Step 2 is satisfied. Final whole-branch
  review then found a cross-image inventory/coverage collision, fixed in
  `b14b4fb` with overlapping-target and rollback regressions; scoped re-review
  was clean. Reopened Task 10 reconciles that implemented ownership contract.

### Verify the state yourself

```bash
cd /Users/danhnguyen/Documents/Offsec/Tools/codebase-audit/.worktrees/stage4d-surface
make all          # all eight gates
```

Measured gate summary (2026-10-16, after Stage 4d documentation reconciliation):

```
PASS  tests      2081 passed
PASS  selftest   verbs  27 declared, all dispatchable / tables 24 in schema.sql, 23 under contract, columns and primary keys agree / migrations 4 plus current schema applied to the pre-Stage-3 and Stage-4b baselines, firmware rows preserved, results accepted by connect()
PASS  lint       skill lint: clean
PASS  eol        6 CRLF files, 186 LF
PASS  manifest   43 features, 12 stages, 21 open items, all paths and verbs resolve
PASS  install    104 markdown files installed, 0 sentinel survivors, real install untouched
PASS  coverage   0 unexecuted / 4074 statements, 0 allowed
PASS  bench      recall 9/19, 45 findings, precision 39/40, $73.15 per match

all 8 gate(s) passed
```

Variable per-gate durations are omitted; measured counts and summaries are
preserved. The manifest's 21 open-item records include historical closed records;
the new record names the retained-orphan candidate scan scaling limitation.

The exact reopened Task 10 focused command from the plan/brief passed **1,168
tests in 35.91s** after the ownership documentation edits, with no corpus skip.
It covers schema/migration/acquisition, shared
traversal and triage/corpus, surface prepare/results/gate/CLI, and rendered brief
contracts. Review regressions pin same-size byte changes, publication races,
batch ownership/replacement isolation, reverse artifact provenance, honest open
unknowns, rollback and unexpected exception identity, and bounded diagnostics.
The full harness includes the available GL.iNet consistency check. No paid
audit, milestone rerun, new indicator snapshot, or mutation sweep ran.

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
(`audit.py indicators`). Stage 4d only rescored the existing read-only
benchmark database; it ran no new audit and did not change the deferral.

## 4. What to do next

Stages 0 through 3c and Stages 4a-4c are merged to local `main`. Stage 4c adds
`firmware_diff.py`, the `diff` verb, image-scoped manifests, `cba_diffs` and
`cba_diff_entries`, composite firmware keys, and the diff dispatch brief.
Comparison stores every changed path in SQL and deterministic JSON while the
terminal result stays bounded. The agent brief requires evidence for the
vendor's fix and a target-only sibling search; changed bytes are not findings.
The read-only GL.iNet check proves inventory/manifest/ELF/service consistency.

Stage 4d adds `firmware_tree.py`, `surface.py`, `surface_results.py`, the
`surface` verb, three additive tables, and `references/briefs/surface-brief.md`.
Installed-user prepare/record/check commands, bounded output, state/unknown
rules, and provenance/invalidation contracts are documented in `README.md`;
`ARCHITECTURE.md` describes their implementation boundaries. The real last
implementation commit is `b14b4fb`, independent of the documentation commit.

### Design and implement Stage 4e (`hunt`)

Stage 4d is implemented and reviewed on its feature branch; integration into
local `main` is pending. Stage 4e is next and must consume verified surface
evidence and unknowns with separate, non-transferable L-sink and L-dark budgets.
It inherits image scoping, the complete target denominator, triage's upsert-only
snapshot limitation, and the retained-orphan candidate scan performance limit.
The asus golden remains a prerequisite for the later Stage 4 milestone gate.

Stage 4d does not fetch/carve/modify/execute firmware, infer listeners, hunt,
assign severity, emulate, inspect kernels/bootloaders, or create the separate
`firmware-audit` tree. Its semantic agent quality has not been measured by an
audit; paid benchmark gates remain deferred.

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
`acquire` and `triage`; Stage 4c shipped `diff` into local `main`; Stage 4d
implements `surface` on its feature branch. These five phases were built at
zero audit cost. The remaining six
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
