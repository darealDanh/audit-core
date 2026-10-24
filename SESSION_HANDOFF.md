# Session handoff

**Written:** 2026-10-25 · **Branch:** `stage4f-firmware-fpcheck`; Stage 4e merge reconciliation recorded ·
**Status:** Stage 4e merged into local `main` at `8119af1`, no push; Stage 4f
implementation and documentation/inventory complete on this feature branch;
controller-owned scoped re-review of the final JSON fix and integration pending. Next firmware
slice: `chain`. **Verification:** `make all` passed all 8 gates; 4,164 full-suite
tests passed, 0/5,933 unexecuted statements

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

- **Branch:** `stage4f-firmware-fpcheck`; Stage 4d's merge point remains
  `6eba6d6` and its last implementation remains `b14b4fb`. Stage 4e is
  merged into local `main` at `8119af1`. Nothing has been pushed.
- **Stage 4f design and plan are approved:** `b4f6e0f` and `61177ce` are
  committed on this feature branch; its five-table schema foundation and row
  contracts, the verified completed-hunt snapshot, deterministic review preparation,
  and image-scoped review invalidation helper are implemented.
  Strict result parsing/validation, atomic batch import and canonical reviewed finding
  derivation/completion, atomic upstream review invalidation and the bounded firmware
  `fpcheck` CLI are implemented, including the firmware review brief and installed-user
  routing. Implementation and documentation/inventory are complete on this branch;
  Final review found JSON identity/path corruption; the final fix preserves exact
  machine values and retains bounded human output. Controller-owned scoped
  re-review and integration remain pending.
  The historical synchronization observation for `main` was 50 commits ahead
  of `origin/main` (checked 2026-10-16; `git rev-list --left-right --count
  origin/main...main` reported `0 50`). Nothing has been pushed.
- **Stages 4a–4e are firmware-audit behavior on the shared spine, not a separate
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
- **Stage 4e hunt is implemented:** each of L-sink and L-dark assigns every
  selected target manifest unit exactly once. The separate lane worklists,
  receipts, coverage phases, pending/complete states, and completion gates bind
  to the current complete Stage 4d snapshot. Workers write strict bounded JSON;
  the importer installs canonical results and atomically publishes receipts,
  image-qualified coverage, and candidates. Candidate-free batches have
  receipts. `not_applicable` maps to shared `state='analyzed'` with its
  evidence-backed reason retained; `not_audited` remains distinct and budget
  skips fail the gate. Replacement is batch-owned. Changed acquisition,
  target triage, or surface evidence invalidates same-image hunt state.
  Expected SQLite errors print exactly `hunt: database operation failed`;
  other expected errors escape/cap at 512 ASCII characters plus newline.
- **Verified completed-hunt snapshot:** `hunt.verified_snapshot` shares the
  full Stage 4e verifier with `hunt.check`, requires both lanes already complete,
  and returns frozen lane/candidate/blocker records without SQL writes or status/
  timestamp transitions. Artifact paths are verified run descendants and exposed
  as canonical run-relative POSIX paths. It supports read-only SQLite and caller
  transactions; candidate-free lanes and denominators above 200 remain complete.
- **Deterministic review preparation:** immutable canonical batches preserve full
  lane-qualified candidate evidence and owning artifacts, bind both hunt worklists,
  and carry normalized priority-only similarity hints. Clusters never split; the
  requested 1..200 size is a target, with a 1,000-candidate hard limit. Empty hunts
  receive one empty batch. Installation precedes locked hunt/root/byte revalidation
  and pending-run publication. Same inputs preserve completed review state;
  replacement/invalidation isolates one image. Upstream callers now invalidate
  review state atomically when selected-image evidence changes.
- **Atomic upstream review invalidation:** changed selected-target acquisition
  identity/triage manifests, surface preparation/results, hunt preparation/results,
  and hunt lane completion remove the selected image's five Stage 4f tables in the
  same SQL transaction. Delete failures roll back all upstream and review state.
  Byte-identical operations and sibling images retain review content and timestamps;
  unchanged hunt replacements also preserve lane completion after comparing durable
  receipts, coverage and candidates. Reference acquisition/triage and supplemental
  source/path edits do not change target ownership.
- **Current next phase:** controller-owned scoped re-review of the final JSON fix and
  integration of Stage 4f, then firmware `chain`. Implementation, installed routing
  and documentation/inventory are complete on this branch. Ordinary source-code
  fpcheck retains its workflow; no merge/push is claimed.
  Stage 4e remains
  firmware functionality in the shared repository. Triage's upsert-only manifests
  and Stage 4d retained-orphan scan scaling persist. The Asus golden and
  monorepo/submodule decision remain prerequisites for the overall Stage 4
  milestone/restructure.
- **Review gate:** the controller reviewed `deb3eed..4394621` before Task 10.
  Both Important findings were fixed in `2550866` with regression evidence;
  the scoped re-review was clean. Task 10 Step 2 is satisfied. Final whole-branch
  review then found a cross-image inventory/coverage collision, fixed in
  `b14b4fb` with overlapping-target and rollback regressions; scoped re-review
  was clean. Reopened Task 10 reconciles that implemented ownership contract.

### Verify the state yourself

```bash
cd /Users/danhnguyen/Documents/Offsec/Tools/codebase-audit/.worktrees/stage4f-firmware-fpcheck
make all          # all eight gates
```

Historical Stage 4d gate summary (2026-10-16, after Stage 4d documentation
reconciliation; these values do not measure the Stage 4e branch):

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

The exact reopened Stage 4d Task 10 focused command from its plan/brief passed **1,168
tests in 35.91s** after the ownership documentation edits, with no corpus skip.
It covers schema/migration/acquisition, shared
traversal and triage/corpus, surface prepare/results/gate/CLI, and rendered brief
contracts. Review regressions pin same-size byte changes, publication races,
batch ownership/replacement isolation, reverse artifact provenance, honest open
unknowns, rollback and unexpected exception identity, and bounded diagnostics.
The full harness includes the available GL.iNet consistency check. No paid
audit, milestone rerun, new indicator snapshot, or mutation sweep ran.

### Historical Stage 4f schema foundation verification

The schema foundation adds five tables, bringing self-test to **32 SQLite
tables / 31 contracted**, with exact columns/keys agreeing. Existing generic
findings/verdicts and the four column migrations are unchanged. Both frozen
baselines gain the new tables; repeated application preserves old and new
rows. Conditional verdict fields, canonical unique JSON arrays, relative
batch/component paths, stored path spellings, UTF-8 text, identifiers,
digests, counts and confidence are validated through real database tests.

Current measured test evidence: **726 focused tests passed in 25.88s**;
the completed post-reconciliation `make all` passed **all eight gates** with
**3,614 tests passed** and **0 unexecuted / 5,071 statements, 0 allowed**.
The initial successful full run took **169.46s** for the test suite. Other measured
gates pass: **28 dispatchable verbs**; the existing four migrations plus
schema apply to both frozen baselines, preserving firmware rows and producing
databases accepted by `connect()`; clean lint; **6 CRLF / 200 LF**;
**45 features / 13 stages / 21 open-item records**; **108 Markdown files
installed**, zero sentinel survivors, real install untouched; existing
benchmark recall **9/19** over **45 findings**, precision **39/40**,
**$73.15 per match**.

The initial ordinary suite captured a stale CLI count assertion before its
correction (`test_selftest_cross_checks_the_table_contract_against_the_real_schema`);
its targeted corrected rerun and the later full instrumented suite pass.
Full-harness verification completed after the final documentation reconciliation.
No mutation sweep, paid audit/milestone rerun, or indicator snapshot ran.

At that point, next was the read-only completed-hunt snapshot helper; preparation,
parsing/import, completion, invalidation and CLI remained. Cross-row/run
containment and ownership belong to those modules, while schema validation
checks stored path spelling. Triage remains upsert-only and Stage 4d retains
its retained-orphan candidate scan limitation. The Asus golden and
monorepo/submodule decision remain overall Stage 4 prerequisites.

### Historical Stage 4f verified completed-hunt snapshot

The Stage 4e and snapshot suites pass **407 tests**. The RED run recorded
**50 expected missing-helper failures / 65 existing tests passed** before any
implementation. Real artifacts and SQLite verify full evidence preservation,
independent same-ID lane candidates, nested immutability, no SQL/status/time
changes, pending-lane refusal, independent input corruption, artifact containment,
read-only connections/caller transactions and unit-201/candidate-free regressions.
Full `make all` evidence: **all eight gates passed**, **3,663 tests passed**,
**0 unexecuted / 5,134 statements, 0 allowed**; **28 dispatchable verbs**;
**32 schema tables / 31 contracted** with columns/keys agreeing; four migrations
plus current schema apply to both frozen baselines, preserving firmware rows
and producing databases accepted by `connect()`; clean lint; **6 CRLF / 201
LF**; **46 features / 13 stages / 21 open-item records**; **108 Markdown files
installed**, zero sentinels, real install untouched; existing benchmark recall
**9/19** over **45 findings**, precision **39/40**, **$73.15 per match**.
Verification includes a fresh full harness after the final documentation
reconciliation. No mutation sweep, paid audit/milestone rerun or indicator
snapshot ran. At that point, next was Task 4: deterministic review-batch preparation,
consuming this verified snapshot and retaining the triage upsert-only and Stage 4d
orphan-scan limitations.

### Historical Stage 4f deterministic review-batch preparation

Task 4 adds `firmware_fpcheck.py` with frozen batch/summary records, full canonical
candidate snapshotting, both hunt worklist digests, normalized similarity routing,
stable no-split batches, and one canonical empty assignment. The index SHA-256 is
the generation identity, binding the candidate evidence and batch-size policy.
Installation rejects symlink parents before writes, then publication repeats the
verified hunt/live root and prior-run checks under `BEGIN IMMEDIATE`, re-reads all
installed bytes, invalidates only changed selected-image state, and inserts one
pending run. Same-input preparation preserves status/timestamps/claims. Explicit
invalidation touches only that image's five Stage 4f tables; commit is opt-in.

RED: **28 expected missing-module failures / 13 existing tests passed**. A later
adversarial RED exposed pre-install symlink-parent redirection; its guard passed
GREEN. A separate relative-run spelling RED exposed unnecessary invalidation;
normalizing the run path fixes it. Preparation plus Stage 4e regressions:
**204 tests passed in 28.98s**, including **54 preparation/snapshot tests**.
Full harness: `make all` passed **all 8 gates**, with **3,704 tests passed** and
**0/5,263 unexecuted statements** (zero allowed). Selftest: **28 verbs**,
**32 schema tables / 31 contracted tables**, and **4 migrations plus current
schema** passing both baselines. Skill lint is clean; line endings: **6 CRLF /
202 LF**; manifest: **47 features / 13 stages / 21 open items**; install:
**108 Markdown files**, zero sentinels, real install untouched. Existing benchmark:
recall **9/19** over **45 findings**, precision **39/40**, **$73.15 per match**.
At that boundary, next was Task 5 strict result parsing and ownership validation. Import, finding
derivation/completion, upstream invalidation wiring (Task 8), and CLI remain.
No mutation sweep, paid audit/milestone rerun or indicator snapshot ran; the
triage upsert-only and Stage 4d orphan-scan limitations remain.

### Historical Stage 4f strict adversarial review results

Task 5 adds `firmware_fpcheck_results.py` and frozen common/verdict/batch records.
Strict UTF-8 JSON loading rejects duplicate keys at every object level, unknown
keys, coercions, non-finite values, unsafe identifiers/paths, repeated arrays and
mismatched variants. Raw and canonical bytes each have an 8 MiB cap; an exactly
8 MiB compact raw result whose canonical newline overflows is rejected. The
canonical oracle is hand-authored independently of production serialization.
Rules require canonical HE-1..18, PR-1..10, CV-1..3 or MARGINAL-GAIN. Image IDs
retain the established non-empty UTF-8 text contract. Integer confidence is parsed
structurally; its 0..10 range is validated after exact assignment membership.

Read-only validation reuses current completed-hunt lane/artifact checks, rebuilds
the entire canonical review generation, and verifies run/index/batch identities,
counts and installed bytes. Lane-qualified membership precedes verdict semantics;
reviewed components/surfaces must belong to selected-image evidence. Current
pending and complete runs are accepted only with consistent completion timestamps,
supporting replacement and idempotent final verification. Cross-batch duplicate
targets must be in-snapshot and non-self; global resolution stays Task 7. No SQL
or artifact writes occur, including inside caller transactions and on read-only
SQLite. There is no live-root parameter; prepare and final check own root agreement.

RED: **142 missing-module failures**, then **8 canonical-rule failures**, **4
image-ID/confidence-precedence failures**, and **1 completed-generation failure**
before their production changes. Latest focused GREEN: **221 tests passed**.
Full harness: `make all` passed **all 8 gates**, with **3,871 tests passed** and
**0/5,546 unexecuted statements** (zero allowed). Selftest: **28 verbs**, **32
schema tables / 31 contracted tables**, **4 migrations plus current schema**
passing both baselines. Skill lint is clean; line endings: **6 CRLF / 204 LF**;
manifest: **48 features / 13 stages / 21 open items**; install: **108 Markdown
files**, zero sentinels, real install untouched. Existing benchmark: recall
**9/19** over **45 findings**, precision **39/40**, **$73.15 per match**.

At the Task 5 boundary, Task 6 artifact-first atomic batch import was next and had to repeat mutable
generation checks under the publication lock. Finding derivation/completion,
upstream invalidation wiring (Task 8), and CLI remain. No mutation sweep, paid
audit/milestone rerun or indicator snapshot ran. Triage's upsert-only manifests
and Stage 4d's retained-orphan scan scaling remain inherited limitations.

### Historical Stage 4f atomic batch import

Task 6 provides `ImportSummary` and artifact-first `record` publication.
The immutable canonical result path uses only verified generation/result digests,
including for Unicode/delimiter image IDs. One `BEGIN IMMEDIATE` transaction repeats
current hunt/snapshot/worklist/assignment validation, receipt ownership and installed
artifact checks before publishing one receipt, one lane-qualified verdict per
assigned candidate, and one pivot per false positive. Empty batches retain receipts.
SQL defaults supply timestamps; worker JSON supplies neither SQL paths nor timestamps.
Duplicate import requires replacement. Deletion scopes the selected image/current
snapshot/batch; pivots join lane-qualified source verdicts before verdict deletion.
Sibling batches/images and old-snapshot pivots survive. Selected-image derived
findings are cleared and the run returns to pending, including after complete runs.
Failures roll back all SQL; an unreferenced immutable result artifact may remain.

RED: **26 expected missing-record failures / 167 existing result tests passed
in 22.61s**. Latest focused GREEN: **254 tests passed in 62.07s**.
Review Fix Round 1 adds real two-connection write-lock contention with a 25ms busy
timeout: publication raises the domain error, durable SQL stays unchanged, and
the competing connection retains its transaction and uncommitted update.

Full suite: **3,904 tests passed in 247.08s**. Full harness: **all 8 gates passed**,
with **0/5,648 unexecuted statements** (zero allowed). Selftest: **28 verbs**,
**32 schema tables / 31 contracted tables**, and **4 migrations plus current schema**
passing both baselines. Skill lint is clean; line endings: **6 CRLF / 205 LF**;
manifest: **49 features / 13 stages / 21 open items**; install: **108 Markdown
files**, zero sentinels, real install untouched. Existing benchmark: recall
**9/19** over **45 findings**, precision **39/40**, **$73.15 per match**.
The complete post-reconciliation `make all` is the final completion gate.

At the Task 6 boundary, Task 7 finding derivation/completion was next: global duplicate
graph checks, root-cause grouping and final live-root revalidation. Upstream invalidation wiring
(Task 8) and CLI remain. Triage's upsert-only snapshots and Stage 4d retained-orphan
scan scaling persist; the Asus golden and restructure decision remain overall Stage 4
prerequisites. No mutation sweep, paid audit/milestone rerun or indicator snapshot ran.

### Historical Stage 4f canonical reviewed findings and completion

Task 7 adds frozen `FindingSummary` / `FpcheckSummary` and `firmware_fpcheck.check`.
The gate reconstructs every receipt-owned verdict and false-positive pivot from
current canonical result artifacts, requiring exact batch/candidate coverage,
counts, ownership and provenance. It revalidates the completed hunt, review
worklists and live root even when the review status is already complete.
Iterative path-compressed duplicate resolution works across lanes/batches and
rejects cycles, missing/foreign/self targets and non-TP terminals. Exact root-cause
keys group true positives and duplicate contributors; similarity hints never merge.
The first lexicographic direct/terminal TP supplies immutable candidate title/bug
class and its own reviewed scalar evidence. Sorted unions retain every contributor,
component and surface; minimum confidence includes duplicate contributors. IDs bind
image/snapshot/root key, and the evidence rung is exactly `static-reviewed`.

Deterministic `findings.json` installs before one immediate transaction, which
repeats all input/root/artifact checks under the publication lock before replacing
selected-image findings and marking the review complete. Complete rechecks require
existing canonical findings evidence and matching derived rows; they preserve rows
and timestamps. Empty receipted and fully false-positive generations complete with
zero findings. Trigger-injected delete/insert/status failures, commit failure,
read/install failures and publication races preserve prior SQL/status/timestamps;
only an unreferenced immutable artifact may remain. Real second-connection write
contention preserves both connections' transaction ownership and durable state.
Generic findings/verdicts remain untouched; no dynamic, severity or report claim
is made.

Inherited RED was **42 expected missing-check failures in 18.68s**; initial core
GREEN was **993 passed in 55.49s**. Original self-review added the missing canonical
artifact regression (**1 failed / 50 deselected in 14.11s**) and its implementation
fix. Takeover retained that fix, added zero-finding/lock-contention evidence, and
closed all seven new refusal branches reported by the initial full coverage gate
without adding a coverage allowance. Latest focused Stage 4f core GREEN:
**1,003 passed in 84.81s**; the gate suite passed **60 tests in 15.11s**.
Historical Task 6 measurements above remain unchanged.

Full suite: **3,964 tests passed in 270.25s**. Full harness: **all 8 gates passed**,
with **0/5,889 unexecuted statements** (zero allowed). Selftest: **28 verbs**,
**32 schema tables / 31 contracted tables**, and **4 migrations plus current schema**
passing both baselines. Skill lint is clean; line endings: **6 CRLF / 206 LF**;
manifest: **50 features / 13 stages / 21 open items**; install: **108 Markdown
files**, zero sentinels, real install untouched. Existing benchmark: recall
**9/19** over **45 findings**, precision **39/40**, **$73.15 per match**.
These measured totals are rechecked by the final post-documentation `make all`;
its timing and commit evidence are in the Task 7 report.

At the Task 7 boundary, upstream invalidation wiring (Task 8) was next; the
final gate refused stale evidence, while eager upstream removal remained unwired.
The historical Task 8 boundary is recorded below; the current Task 9 boundary
follows. Triage's upsert-only snapshots
and Stage 4d retained-orphan scan scaling
persist; the Asus golden and monorepo/submodule decision remain overall Stage 4
milestone/restructure prerequisites. No mutation sweep, paid audit/milestone rerun,
indicator snapshot, merge or push ran.

### Historical Stage 4f atomic upstream review invalidation

Task 8 joins the existing acquisition, target triage, surface prepare/results,
hunt prepare/results and lane completion transactions through local imports of
`firmware_fpcheck.invalidate(..., commit=False)`. Changed selected-image evidence
clears only that image's five dedicated review tables; any delete failure rolls
back upstream publication and review removal together. Reference changes,
supplemental acquisition metadata and unchanged operations preserve review state.
Hunt replacement compares durable receipts, qualified coverage and full
receipt-owned candidates: identical evidence preserves completion/timestamps,
while changed evidence or repaired durable rows invalidates review. Unicode and
delimiter image IDs and repeated lane-qualified candidate IDs remain isolated.

Tests-first RED: **57 failed / 621 passed**. Prescribed upstream plus Stage 4f
prepare/import/gate GREEN: **824 passed**. Real SQLite delete failures cover every
review table at every mutation boundary and restore complete database snapshots.
The full suite exposed two existing human/JSON CLI expectations that identical
replacement reset completion; the reconciled end-to-end test now checks exact
snapshot preservation, then changes evidence and verifies the affected lane resets.

Full suite: **4,032 tests passed**. Full harness: **all 8 gates passed**, with
**0/5,933 unexecuted statements** (zero allowed). Selftest: **28 verbs**,
**32 schema tables / 31 contracted tables**, and **4 migrations plus current schema**
passing both baselines. Skill lint is clean; line endings: **6 CRLF / 206 LF**;
manifest: **51 features / 13 stages / 21 open items**; install: **108 Markdown
files**, zero sentinels, real install untouched. Existing read-only benchmark:
recall **9/19** over **45 findings**, precision **39/40**, **$73.15 per match**.
The final post-documentation `make all` rechecks these measured totals; exact
run timings and commit evidence are recorded in the Task 8 report.

At the Task 8 boundary, the bounded firmware CLI was next; it is now implemented.
At upstream-invalidation completion, Task 10 was still pending; its implemented contract is recorded below.
Triage remains upsert-only;
Stage 4d retained-orphan scan scaling persists. The Asus golden and monorepo/submodule
decision remain prerequisites for the overall Stage 4 milestone/restructure.
No mutation sweep, paid audit/milestone rerun, indicator snapshot, merge or push ran.

### Historical Stage 4f bounded firmware review CLI

Task 9 exposes explicit `fpcheck --prepare`, `--record RESULT` and `--check`
modes beneath the existing prose workflow. All mode combinations and extras are
validated before opening the run database; syntax errors exit 2 and semantic
mode errors exit 1 without creating a run. Prepare defaults to 20 candidates per
batch and accepts integer targets 1–200; check requires the current live root.
The CLI delegates directly to the completed preparation, atomic importer and
completion gate. Source-code `cba_fp_verdicts` commands are unchanged.

Human and JSON success output select only scalar aggregate/provenance fields and
artifact paths. Success redaction uses absolute root spellings so `--root .`
preserves dots in usable artifact filenames. Check reports `finding_count`,
never the per-finding review records. Public text fields escape controls/non-ASCII, redact the supplied root,
and cap at 512 printable ASCII characters; unusually long image identifiers or
paths are displayed with a trailing `...`. Stored identities and artifacts retain
their full values. Expected diagnostics have the same 512-character cap plus
newline; SQLite anywhere in an expected exception chain produces exactly
`fpcheck: database operation failed`. Unexpected exceptions propagate from the
direct handler after rollback/connection release.

Tests-first RED: **97 failed / 17 passed**, from the missing parser/handler and
updated verb-count assertions. Real subprocess tests prepare, record hand-written
canonical results, replace receipts and complete both three-candidate and empty
generations in human and JSON formats. They pin exact summaries, clean success
stderr, private-evidence exclusion and generic-table isolation. Error tests cover
early no-I/O validation, real SQLite authorization failures, cause/context cycles,
escaping/capping, rollback and unexpected exception propagation.

Final focused CLI plus complete Stage 4f suites: **1,124 tests passed**. The
current full suite passes **4,134 tests**. Full measurement harness: **all 8 gates
passed**, with **0/5,933 unexecuted statements** (zero allowed). Selftest:
**29 dispatchable verbs**, **32 schema tables / 31 contracted tables**, and
**4 migrations plus current schema** passing both baselines. Skill lint is clean;
line endings: **6 CRLF / 207 LF**; manifest: **52 features / 13 stages / 21 open
items**; install: **108 Markdown files**, zero sentinels, real install untouched.
Existing read-only benchmark: recall **9/19** over **45 findings**, precision
**39/40**, **$73.15 per match**. The final post-documentation `make all` rechecks
these measured totals; run timings and commit evidence are in the Task 9 report.

At CLI completion, Task 10 was next; its implemented contract is recorded below.
Triage remains upsert-only; Stage 4d retained-orphan scan scaling persists. The
Asus golden and monorepo/submodule decision remain prerequisites for the overall
Stage 4 milestone/restructure. No mutation sweep, paid audit/milestone rerun,
indicator snapshot, merge or push ran.


### Historical Stage 4f firmware review worker brief and installed routing

The eighth template, `references/briefs/firmware-fpcheck-brief.md`, renders through
`audit.py brief --phase firmware-fpcheck --unit batch-NNNN` with eight required
variables. The firmware route prepares immutable completed-hunt candidate batches,
dispatches brief paths, records complete strict result-only JSON, and checks the
whole snapshot. Workers preserve lane-qualified identities and cross-lane evidence,
apply the shared FP rules with attacker advantage first, and supply reviewed roots,
mandatory false-positive pivots, and explicit duplicate targets. Deterministic code
exclusively owns SQL, canonical installation, and transitions. Static-only safety,
relative persisted evidence, honest non-importable PARTIAL checkpoints, and exactly
one return line are explicit. Ordinary source-code fpcheck retains its workflow.

Repository RED: **24 failed / 39 passed in 25.21s**, all missing-template,
firmware-route or installed-template failures. Focused GREEN: **66 passed in
26.73s**. `make lint`, sandboxed `make install-smoke`, and the skill creator's
quick validator passed. Installation tests render from Claude and both Codex
locations and resolve the installed parser and shared FP rules. The controller
captured behavioral RED before editing; independent behavioral GREEN remains its
post-commit gate. Static contract verification is not paid semantic audit evidence.

Task 10 full-harness measurements: **4,160 tests**, **all eight gates passed**;
**29 dispatchable verbs**; **32 schema tables / 31 contracted**, columns/keys agree;
**four migrations plus current schema** accepted by both frozen baselines;
clean skill lint; **6 CRLF / 210 LF files**; **53 features / 13 stages / 21 open
items**, all paths/verbs resolve; **112 installed Markdown files**, zero sentinel
survivors, real install untouched; **0/5,933 unexecuted statements**, zero allowed.
The read-only benchmark remains recall **9/19** over **45 findings**, precision
**39/40**, **$73.15 per match**. No paid audit, milestone rerun, indicator snapshot,
mutation sweep, merge, or push ran. The final post-documentation `make all`
rechecks these recorded measurements; exact logs and timing are in the Task 10 report.

At the Task 10 boundary, next was **Task 11**: reconcile the complete Stage 4f documentation/inventory,
perform independent whole-branch review, and run final verification before the
stage-completion decision. The subsequent firmware slice is `chain`. Triage's
upsert-only snapshots and Stage 4d retained-orphan scan scaling persist; the Asus
golden and monorepo/submodule decision remain overall milestone/restructure
prerequisites. Paid semantic quality measurement remains deferred.

### Stage 4f implementation and documentation verification

The following records the historical Task 11 boundary.

Stage 4f implementation, installed routing and documentation/inventory are
complete on the feature branch. Controller-owned independent final review of
`merge-base(main)..HEAD` and integration remain pending; no merge/push is claimed.
The next firmware slice is `chain`, consuming dedicated static-reviewed findings.

Task 11 added one durable complete-stage inventory regression. It first failed
on the missing `stage4f` entry, then passed with the complete stage/feature
inventory. Plain `python3 -m pytest -q` passed **4,161 tests in 254.90s**, without
warnings/errors. Structured JSON/whitespace/selftest/lint/EOL/manifest/install
gates passed. The full `make all` measurement was:

```text
PASS  tests      4161 passed
PASS  selftest   verbs  29 declared, all dispatchable / tables 32 in schema.sql, 31 under contract, columns and primary keys agree / migrations 4 plus current schema applied to the pre-Stage-3 and Stage-4b baselines, firmware rows preserved, results accepted by connect()
PASS  lint       skill lint: clean
PASS  eol        6 CRLF files, 210 LF
PASS  manifest   54 features, 14 stages, 21 open items, all paths and verbs resolve
PASS  install    112 markdown files installed, 0 sentinel survivors, real install untouched
PASS  coverage   0 unexecuted / 5933 statements, 0 allowed
PASS  bench      recall 9/19, 45 findings, precision 39/40, $73.15 per match

all 8 gate(s) passed
```

Variable harness elapsed times are omitted. The 21 open-item records include
historical closed entries. A fresh
committed-tree `make all` rechecks these totals after the documentation commit;
its exact result is recorded in the execution report. No mutation sweep, paid
audit/milestone rerun or indicator snapshot ran. Read-only benchmark scoring of
the existing corpus measures no change in semantic audit quality.

Triage remains upsert-only and the Stage 4d retained-orphan result scan scaling
limit is inherited. Reviewer-authored root-cause keys can under-deduplicate;
static review cannot settle runtime/hardware blockers. The Asus golden and
monorepo/submodule decision remain overall milestone/restructure prerequisites.
Paid semantic quality remains deferred. Controller final review remains required.

### Stage 4f final-review JSON fix verification

Final whole-branch review found one Important defect: success display formatting
changed JSON identities and artifact paths. The final fix applies escaping,
root redaction and the 512-character field cap only to human display. Machine
JSON preserves the fixed aggregate-only whitelist with exact identities and
usable full artifact paths through normal JSON escaping. Expected diagnostics,
early validation, raw-evidence exclusion and generic source-code commands retain
their contracts.

The corrected JSON identity expectation and three real subprocess workflows
cover Unicode/delimiter IDs, Unicode paths, paths longer than the display cap,
and run paths sharing the root's spelling prefix. They open returned worklist,
result and findings artifacts and reuse returned identity/path values through
record, replacement and check. RED measured **4 failed / 1 passed**; GREEN
measured **5 passed**. The complete focused CLI/Stage 4f suite passed **1,149
tests in 73.11s**. Fresh full-harness measurement after the final code/test edits:

```text
PASS  tests      4164 passed
PASS  selftest   verbs  29 declared, all dispatchable / tables 32 in schema.sql, 31 under contract, columns and primary keys agree / migrations 4 plus current schema applied to the pre-Stage-3 and Stage-4b baselines, firmware rows preserved, results accepted by connect()
PASS  lint       skill lint: clean
PASS  eol        6 CRLF files, 210 LF
PASS  manifest   54 features, 14 stages, 21 open items, all paths and verbs resolve
PASS  install    112 markdown files installed, 0 sentinel survivors, real install untouched
PASS  coverage   0 unexecuted / 5933 statements, 0 allowed
PASS  bench      recall 9/19, 45 findings, precision 39/40, $73.15 per match

all 8 gate(s) passed
```

The final execution report records the authoritative post-documentation
`make all` result. Historical Task 11 measurements above remain intact. The
single final-fix wave is implemented; controller-owned scoped re-review and
integration remain pending. No merge, push, mutation sweep, paid audit/milestone
rerun or indicator snapshot ran. The next firmware slice is `chain`, retaining
triage's upsert-only snapshots and Stage 4d orphan-scan scaling. The Asus golden
and monorepo/submodule decision remain overall milestone/restructure
prerequisites; static contracts do not establish semantic audit quality.

### Historical Stage 4e merged-state verification

The Stage 4f worktree includes local `main` at `8119af1` plus the approved
Stage 4f design and plan. Its full `make all` result is 8/8 gates: 2,925 tests;
28 dispatchable verbs; 27 schema tables / 26 contracted; four migrations plus
the current schema applied to both frozen baselines with firmware rows
preserved and results accepted by `connect()`; clean lint; 6 CRLF / 199 LF;
44 features / 13 stages / 21 open-item records; 108 Markdown files installed,
zero sentinel survivors, real install untouched; 0 unexecuted / 4,946
statements, 0 allowed; benchmark recall 9/19 over 45 findings, precision
39/40, $73.15 per matched finding. The two additional LF files are the
Stage 4f design and plan. No new audit, paid milestone run, indicator snapshot,
or mutation sweep ran.

At that reconciliation point, `ARCHITECTURE.md` described the implemented
Stage 4e boundary and named firmware `fpcheck` next.

### Historical Stage 4e Task 9 verification

The historical Stage 4e feature tree passed the full eight-gate harness. The
pre-documentation `make all` summary, used to reconcile this handoff, was:

```
PASS  tests      2925 passed in 168.94s
PASS  selftest   28 declared, all dispatchable / 27 schema tables, 26 contracted / four migrations plus current schema applied to the pre-Stage-3 and Stage-4b baselines; firmware rows preserved, results accepted by connect()
PASS  lint       skill lint: clean
PASS  eol        6 CRLF files, 197 LF
PASS  manifest   44 features, 13 stages, 21 open items, all paths and verbs resolve
PASS  install    108 markdown files installed, 0 sentinel survivors, real install untouched
PASS  coverage   0 unexecuted / 4946 statements, 0 allowed
PASS  bench      recall 9/19, 45 findings, precision 39/40, $73.15 per match

all 8 gate(s) passed
```

Plain `python3 -m pytest -q` passed 2,925 tests in 140.33 seconds. Review fixes
include canonical result-size enforcement before artifact/SQL publication,
replacement rollback coverage, clean-checkout manifest independence from
ignored `.superpowers` files, orchestrator-owned worker checkpoint publication,
and the lane-specific economical L-sink / strongest-tier L-dark dispatch policy.
The EOL gate confirms the edited `SKILL.md` remains CRLF. The Stage 4e
`feature_lists.json` record resolves only tracked, durable docs and files.

The structured Step 4 gates also passed: JSON parse, `git diff --check`,
selftest, lint, EOL, manifest, and install smoke. The Stage 4e manifest
regression was first run against the stale inventory and failed because its
docs listed ignored `.superpowers` artifacts; after removing that dependency,
the clean-checkout manifest passes. Historical Stage 4d measurements above
remain historical and are not substituted for these Stage 4e results. The
fresh merged-state verification is recorded above; historical measurements
remain unchanged.

No firmware audit, paid milestone run, new indicator snapshot, or mutation
sweep ran. Benchmark output is read-only scoring of the existing baseline;
no audit-quality improvement is claimed. `make mutate` remains opt-in and
outside `make all`.

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

Stages 0 through 3c and Stages 4a-4e are merged to local `main`; Stage 4e is
included at `8119af1`, not pushed. Stage 4c adds
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

### Review/integrate Stage 4f, then implement firmware `chain`

Stage 4f implementation and documentation/inventory reconciliation are complete
on `stage4f-firmware-fpcheck`. Independent whole-branch review found one Important
JSON identity/path corruption issue. The single final-fix wave is implemented;
controller-owned scoped re-review and integration remain pending.
No Stage 4f merge or push is claimed. The next firmware slice is
`chain`, consuming dedicated reviewed findings with canonical contributors and
static-reviewed evidence. Triage remains upsert-only; the Stage 4d retained-orphan
scan performance limit persists. The Asus golden and monorepo/submodule decision
remain prerequisites for the overall milestone/restructure. Paid semantic quality
remains unmeasured; the harness proves deterministic contracts only.

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
`acquire` and `triage`; Stage 4c shipped `diff`; Stage 4d shipped `surface` into
local `main`; Stage 4e merged `hunt` at `8119af1`. These phases and Stage 4f
firmware `fpcheck` were built at zero audit cost.
Stage 4f implementation/docs are complete on its feature branch; controller final
review and integration remain pending. The next firmware slice is `chain`.
The separate firmware skill tree does not exist yet.

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
