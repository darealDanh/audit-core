# Session handoff

**Written:** 2026-11-02 · **Branch:** `stage4h-firmware-dive`; local `main`
retains Stage 4g at `30ca3ba`, not pushed ·
**Status:** Stage 4h firmware `dive` is in progress, integration pending.
Tasks 1–8 implement schema, graph/question contracts, immutable preparation,
sealed acquisitions, strict results and exact immutable observation import;
Task 9 completion/journal/overlay validation is next. **Verification:** Task 8: 7,694 full-suite tests passed;
0/10,530 unexecuted statements (zero allowed); schema, lint, EOL, manifest, install
and benchmark gates pass.
Measured gate details and historical Stage 4g results are preserved below.

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

- **Branch:** local `main`; Stage 4d's merge point remains `6eba6d6`, Stage 4e
  remains merged at `8119af1`, and Stage 4f is merged by fast-forward at
  `303232e`. Stage 4g is merged by fast-forward at `30ca3ba`. Nothing has been
  pushed.
- **Stage 4f design and plan are approved:** `b4f6e0f` and `61177ce` were
  committed on the feature branch and are now in local `main`; its five-table schema foundation and row
  contracts, the verified completed-hunt snapshot, deterministic review preparation,
  and image-scoped review invalidation helper are implemented.
  Strict result parsing/validation, atomic batch import and canonical reviewed finding
  derivation/completion, atomic upstream review invalidation and the bounded firmware
  `fpcheck` CLI are implemented, including the firmware review brief and installed-user
  routing. Final review found JSON identity/path corruption; `303232e` preserves
  exact machine values and retains bounded human output. Scoped re-review was clean,
  and implementation/documentation/inventory are merged into local `main`.
  The historical synchronization observation for `main` was 50 commits ahead
  of `origin/main` (checked 2026-10-16; `git rev-list --left-right --count
  origin/main...main` reported `0 50`). Nothing has been pushed.
- **Stages 4a–4g are firmware-audit behavior on the shared spine, not a separate
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
- **Stage 4g chain is implemented:** a verified complete Stage 4f snapshot feeds
  one immutable global worklist; six dedicated tables retain exact dispositions,
  blockers, deterministic chains and ordered typed edges. Strict result parsing,
  semantic graph/state validation, canonical import, completion reconstruction,
  upstream invalidation, firmware CLI modes, the ninth worker brief and installed
  routing are complete. Ordinary source-code `chain` proposal/human composition
  behavior remains compatible. Static chains do not prove runtime reachability,
  severity, exploitability or semantic causality beyond retained evidence.
  Stage 4g is merged locally and unpushed; `dive` is next.
  Stage 4e remains
  firmware functionality in the shared repository. Triage's upsert-only manifests
  and Stage 4d retained-orphan scan scaling persist. The Asus golden and
  monorepo/submodule decision remain prerequisites for the overall Stage 4
  milestone/restructure.
- **Stage 4g review gate:** independent whole-branch review found two Important
  cross-layer invariant defects. Commit `661c3c9` unified `other-specific` link
  acceptance across semantic validation/persistence and rejected unresolved
  references on standalone/unchainable dispositions. Scoped re-review marked
  both addressed with no new Critical/Important issue. Final review found one
  further Important contradiction: a blocker could affect a nonmaterialized
  finding whose disposition omitted it. Commit `7dad245` requires a reciprocal
  blocked disposition and blocker reference and adds completion reconstruction
  coverage; the complete final fix wave passed scoped re-review.
  Historical Stage 4d
  review: the controller reviewed `deb3eed..4394621` before Task 10.
  Both Important findings were fixed in `2550866` with regression evidence;
  the scoped re-review was clean. Task 10 Step 2 is satisfied. Final whole-branch
  review then found a cross-image inventory/coverage collision, fixed in
  `b14b4fb` with overlapping-target and rollback regressions; scoped re-review
  was clean. Reopened Task 10 reconciles that implemented ownership contract.

### Verify the state yourself

```bash
cd /Users/danhnguyen/Documents/Offsec/Tools/codebase-audit
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
Paid semantic quality remains deferred. At this historical Task 11 boundary,
controller final review was still required.

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

The final execution report recorded the authoritative post-documentation
`make all` result. Historical Task 11 measurements above remain intact. The
single final-fix wave passed scoped re-review and Stage 4f is merged into local
`main` at `303232e`. No push, mutation sweep, paid audit/milestone rerun or
indicator snapshot ran. The next firmware slice is `chain`, retaining
triage's upsert-only snapshots and Stage 4d orphan-scan scaling. The Asus golden
and monorepo/submodule decision remain overall milestone/restructure
prerequisites; static contracts do not establish semantic audit quality.

### Stage 4g implementation and verification

Stage 4g is merged into local `main` by fast-forward at `30ca3ba`; it is not
pushed. Approved design `00edb44` and plan `380b075` define a
dedicated six-table evidence graph over current Stage 4f reviewed findings.
Preparation installs one immutable global worklist; every finding receives an
exact chained/standalone/unchainable/blocked disposition and may participate in
multiple chains. Typed ordered edges require matching capability/link identity,
producer/consumer-owned retained evidence, middle-node continuity and carried
lifecycle/posture/authentication state. Reboot and other device boundaries need
explicit evidence on both sides. Existing unknowns and new blockers remain
settleable; Stage 4f pivots are context-only and never graph nodes or evidence.

Canonical result publication is artifact-first and one-transaction. Final check
reconstructs every receipt-owned row, revalidates current live-root/Stage 4f
evidence, derives deterministic `static-chained` output, and can preserve older
SQL generations while completing only the current image/snapshot. Changed Stage
4f evidence invalidates every generation in all six selected-image chain tables
in the owning upstream transaction; immutable content-addressed artifacts remain.
The `chain` CLI adds firmware prepare/record/check without
changing generic proposal/composition behavior. The installed global worker owns
strict result JSON only; SQL, canonical artifacts, identities, receipts, derived
claims and completion stay deterministic.

The whole-branch reviewer found two Important validation/persistence mismatches;
`661c3c9` fixed both and scoped re-review was clean. Final review then found the
blocker/disposition reciprocity mismatch fixed in `7dad245`; focused Stage 4f/4g
regression passed 2,557 tests. The complete fix wave passed scoped re-review.
The authoritative post-documentation full-harness result is:

```text
PASS  tests      5902 passed
PASS  selftest   verbs 29 declared, all dispatchable / tables 38 in schema.sql, 37 under contract / migrations 4 plus current schema applied to both frozen baselines
PASS  lint       skill lint: clean
PASS  eol        6 CRLF files, 224 LF
PASS  manifest   55 features, 15 stages, 21 open items, all paths and verbs resolve
PASS  install    116 markdown files installed, 0 sentinel survivors, real install untouched
PASS  coverage   0 unexecuted / 7392 statements, 0 allowed
PASS  bench      recall 9/19, 45 findings, precision 39/40, $73.15 per match

all 8 gate(s) passed
```

Static chain evidence does not prove runtime reachability, semantic causality
beyond retained evidence, severity/CVSS, exploitability, or successful
exploitation. No mutation sweep, paid audit/milestone rerun, Asus golden, or
indicator snapshot ran. Triage remains upsert-only; Stage 4d orphan-result scan
scaling persists; the separate firmware skill tree and monorepo/submodule choice
remain open. Firmware `dive` is the next slice.

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

### Stage 4h Task 1–6 handoff (in progress)

Task 1 adds six dedicated dive tables with 44 SQLite tables and 43 TableSpec
contracts overall; the four migrations remain unchanged. Task 2 exposes frozen,
sorted Stage 4g graph records with canonical run-relative artifact provenance.
Current snapshots reconstruct completed SQL, receipts, graph bytes and live
Stage 4f/source evidence without writes, including read-only SQLite and caller
transactions. The explicit retained verifier selects one image/dive-generation
owner and verifies its graph after Stage 4g SQL and worker files are deleted;
the public current helper never falls back to retained history.

The retained worklist hash is historical provenance, not a freshness equality.
Retained verification rechecks current Stage 4f/source dependencies but cannot
identify an administratively replaced, internally valid findings artifact under
the same candidate identity: the owning dive row stores no findings-artifact
digest. Tasks 4/8/9 must bind and recheck exact per-question/per-observation
finding artifacts before conflict preparation or overlay use.

Task 2 verification: `make all` passes all eight gates with 6,908 tests;
29 dispatchable verbs; 44 SQLite tables / 43 contracts; four unchanged migrations;
57 features / 16 stages / 21 open items with all paths and verbs resolving;
clean skill lint; 6 CRLF / 228 LF files; 116 installed markdown files with zero
sentinel survivors and the real install untouched; 0/7,737 unexecuted statements
(zero allowed). The existing read-only benchmark remains recall 9/19, 45 findings,
precision 39/40 and $73.15 per match. This is deterministic verification, not a
new paid semantic audit. Stage 4h remains in progress;
Historical Task 3 verification: `make all` passed all eight gates with 7,030 tests;
29 dispatchable verbs; 44 SQLite tables / 43 contracts; 4 unchanged migrations;
58 features / 16 stages / 21 open items with all paths and verbs resolving;
clean skill lint; 6 CRLF / 230 LF files; 116 installed markdown files with 0
sentinel survivors and the real install untouched; 0/8,391 unexecuted
statements (0 allowed). The read-only benchmark remains recall 9/19, 45 findings, precision 39/40, $73.15 per match.
The focused Task 3 suite passes 122 tests; its pure module has 0/654
unexecuted statements. That Task 3 checkpoint preceded the immutable preparation implementation below.
These deterministic checks do not establish paid semantic quality or runtime truth.

Task 3 implements strict analyst manifests, stable semantic subjects, automatic
question contracts, explicit durable retries, complete conflict supersession and
bounded exact-reference packets. Manifest nesting is bounded before normalization;
parser and validation failures use the question-domain error. Durable history
retains validated immutable question fields, preventing mutable conflict aliases.
Tasks 4–6 implement immutable preparation, sealed hardware captures and bounded
isolated probes below. At that checkpoint results, completion, overlays, CLI and worker
integration were pending; Tasks 7–8 results/import are recorded below. No new runtime
claim, paid audit, mutation sweep, merge or push is claimed.

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

Stages 0 through 3c and Stages 4a-4g are merged to local `main`; Stage 4f is
included at `303232e` and Stage 4g at `30ca3ba`, not pushed. Stage 4c adds
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

Task 4 implements artifact-first immutable preparation through `firmware_dive.prepare`.
It freezes complete question denominators, preserves every prior generation and
sibling image, and repeats live source, graph, strict manifest, durable history,
extract provenance and installed-byte verification under `BEGIN IMMEDIATE`.
Ordinary preparation uses only the current completed graph; conflict-only
preparation selects an exact completed retained owner from the complete current
conflict family and rejects ambiguous graph chronology, unrelated questions and
ordinary retries. Retry validation follows retained-owner selection, so unrelated
older graphs cannot veto a valid conflict retry. Installation anchors creation,
file writes, fsync, rename and cleanup to verified directory descriptors with
no-follow traversal; a parent replacement cannot redirect writes through a
symlink. A rejected publication may retain an unreferenced immutable generation
inside the run. Preparation never invalidates Stage 4g.

The generation index retains scalar graph ownership, canonical analyst input,
complete authoritative accepted-input dependency digests and retry projection,
plus every packet identity, so its hash can be reconstructed independently of
the bounded informational journal. Identical generations reuse their frozen
journal/packets without writes after later inconclusive history. Opaque dependency
provenance is structurally bounded and rejects host/traversing path spellings;
private provenance bodies stay behind digests. Exact finding-artifact provenance
is bound separately from historical Stage 4g worklist/result hashes. New questions
authorize no extracts by default; historical exact selections are reconstructed
from canonical stable upstream manifest projections and rechecked under lock.

Task 5 adds strict question-owned hardware sealing through
`firmware_dive_acquisition.load_capture_spec` and `seal_capture`. It reconstructs
the owning prepared run, generation index, packet, exact hardware acquisition
contract and current retained-graph/source dependencies. Specs bind the recorded
device identifier, firmware version/full image digest, lifecycle/posture/authentication,
operator/source and hardware method. The recorded image digest is a device fact,
not an equality to the Stage 4f manifest or candidate digest. Sources resolve
relative to the spec parent; no source paths or timestamps enter sealed bytes
or identity. Sorted flat evidence names and stable regular bytes are bounded at
256 files and 64 MiB total, with strict keys, strings, states and digests.
Explicit run/spec selectors normalize to absolute lexical targets before
no-follow traversal; evidence source paths and installed basenames remain
canonical relative and traversal-free. Image IDs preserve bounded upstream
UTF-8 scalar identity, including escaped controls; other metadata stays strict.
Capture evidence follows raw-name order; SQL paths follow canonical JSON-element order.

The full SHA-256 capture ID binds canonical sealed spec semantics and every
ordered evidence name/hash/size with a capture discriminator. The exact layout is
`artifacts/firmware-dive-captures/<id>/{spec.json,manifest.json,evidence/...}`.
The shared installer and stable reader anchor all directory traversal, file reads,
creation, writes, fsync, rename and cleanup to no-follow descriptors. Installation
precedes `BEGIN IMMEDIATE`; authority, source identities/bytes and installed bytes
are checked again before one append-only acquisition receipt. Exact duplicates
perform no writes; conflicting duplicates refuse. Failure preserves prior SQL,
sibling questions and images, and may retain an unreferenced in-run artifact.
Captures create no observation, finding, evidence rung or denominator change and
never contact or control a device.

At the Task 4 boundary, result/journal and retained probe bodies were opaque;
retained history enforced exact SQL/byte and method/rung checks. Task 8 now
reconstructs canonical results and referenced sealed acquisition semantics;
legacy opaque history retains byte-exact checks, while journal/completion/overlay
reconstruction belongs to Task 9. Task 6 preserves descriptor, exact prepared-contract
and locked publication boundaries for bounded probes. Stage 4h remains in progress,
integration pending; no generic severity or exploit claim is made.

Historical Task 4 Fix Round 1 verification: `make all` passed all eight gates with 7,132 tests;
29 dispatchable verbs; 44 SQLite tables / 43 contracts; four unchanged migrations
with firmware baselines preserved; clean skill lint; 6 CRLF / 232 LF files;
59 features / 16 stages / 21 open items with all paths and verbs resolving;
116 installed markdown files / zero sentinel survivors, real install untouched;
0/8,918 unexecuted statements (zero allowed). The read-only benchmark remains
recall 9/19, 45 findings, precision 39/40, $73.15 per match. The combined Task 4
and upstream regression suite passes 506 tests. Fix Round 1 focused preparation
coverage passes 101 tests with 0/527 unexecuted module statements. These checks establish mechanical
preparation integrity at the Task 4 boundary; capture sealing is now implemented
and canonical result domain validation remains future work. `make mutate` was not run.

Task 5 focused verification: 103 capture tests pass, including all three
lexical-selector regressions. Final cold monitoring of the 204-test
capture/preparation suite reports pytest_rc=0, with 0/182 unexecuted acquisition
statements and 0/548 shared preparation statements. The measured package
executable denominator is 9,121; focused execution is not full-package coverage.
The final capture/preparation/snapshot/question/chain combined regression passes
609 tests.

Historical Task 5 full-harness verification: `make all` passed all eight gates with 7,235
tests; 29 dispatchable verbs; 44 SQLite tables / 43 contracts; four unchanged
migrations with both firmware baselines preserved; clean skill lint;
6 CRLF / 234 LF files; 60 features / 16 stages / 21 open items with all paths
and verbs resolving; 116 installed markdown files / zero sentinel survivors /
real install untouched; zero unexecuted statements out of 9,121 (zero allowed).
The existing golden benchmark remains recall 9/19, 45 findings, precision 39/40,
$73.15 per match. These checks establish capture publication integrity.
This historical Task 5 checkpoint precedes Task 6 probes; result/completion
gates remain pending.
`make mutate` was not run.

Task 6 implements frozen strict `ProbeSpec`/`ProbeTermination`, `load_probe_spec`
and `run_probe` in the acquisition module. Every probe reconstructs its exact
prepared emulate question, packet and no-network acquisition contract against
current upstream evidence. It stages only declared verified regular dependencies,
binds exact argv/environment and hashes before/after execution, and publishes
runtime facts without answering questions, choosing evidence rungs or findings.

The network policy is exactly none. Supported installed or explicit canonical
no-symlink `bwrap`/`sandbox-exec` programs must match the backend/platform, remain
hash-stable, and pass a fixed bounded readiness probe from an ordinary-permission private
copy; firmware invocation uses that same staged adapter copy. Special file bits
and capabilities are never copied; tools needing them fail closed. Both the
staged tool tree and original host tool are revalidated. These operator-trusted
host tools are checked for readiness/integrity, not attested as nonmalicious.
The manifest records their host runtime before isolation as trusted tooling.
Missing, unknown or unready isolation seals `executed=false` with
`reason=isolation-unavailable`; firmware never runs unsandboxed and no tool is
installed. Linux mounts only staged declared guest files plus an optional verified
static-ELF runner, isolated proc/dev and output. Both bwrap readiness and payload
require explicit `--unshare-user` and `--disable-userns`; nested user namespaces
cannot restore namespace-local mount capabilities. Unsupported options refuse
readiness without retry or fallback. This required namespace policy is sealed
into identity. Dynamic host runners are recorded
as unsupported. macOS denies network and process forks, permits process exec,
and records the fixed Apple system-runtime read roots and platform/version;
those system reads are not firmware library evidence.

Host adapter processes, including readiness, always receive a fixed empty
environment. Declared environment values and the explicit shim are injected only
inside isolation: bwrap uses `--setenv`; macOS uses a verified native copy of fixed
`/usr/bin/env`, staged as `_environment-launcher`, with `-i`, literal assignments
and an exact absolute firmware command. The launcher has a separate host-tool
role/hash/size, with original and staged checks; its host path never enters the
identity. Missing or incompatible helpers seal `unsupported-helper` without a
payload. Pre-payload original-helper drift may seal truthful distinct before/after
hashes only while every other dependency remains stable and the captured after
snapshot revalidates under lock. Staged-helper tampering and any dependency drift
after a real payload launch refuse publication. Host adapter startup never
receives user environment or loader injection variables.

Timeout is an integer 1–300 seconds; argv is at most 128 entries/4096 UTF-8 bytes
each; environment has at most 64 safe names/4096-byte values and rejects loader
variables except the explicit validated shim. Staged dependencies are bounded to
256 regular files/64 MiB total; the adapter and fixed environment launcher are separately verified host tools,
each bounded to 64 MiB.
Processes use argv lists, no shell, a new session, closed descriptors, minimal
environment and redirected descriptor-checked stdin. Both streams retain at most
1 MiB with explicit truncation. Timeout/errors kill and reap the entire process
group with bounded pipe cleanup. Exit codes, signals, timeouts, truncation and
unsupported tools remain facts. Native bwrap and sandbox-exec wait status is
recorded only as `adapter_exit_code`/`adapter_signal`, explicit `status_source`
and adapter-exited/adapter-signal reasons; payload exit/signal remain unknown.
Neither backend provides authenticated payload wait status. Codes such as 153
may encode SIGXFSZ or a voluntary matching exit; no 128+n decoding occurs.
Nonzero, signaled, timeout or other ambiguous native outcomes suppress all
declared generated files. Native exit 0 may retain checked files without a guest
semantic conclusion. Bounded stdout/stderr are labeled adapter-stream facts.
Direct-process status semantics are internal and test-only. This trades diagnostic
precision for non-misattribution. Darwin zombie-group behavior is handled without
repeated signals or masking live cleanup failures.

Payload children inherit fixed hard and soft Unix limits: 8 MiB file size,
64 processes per UID and 64 file descriptors. Missing or insufficient resource
support, setup failure and root UID (which can bypass process limits) refuse with
`executed=false,reason=unsupported-limits`. The per-UID process bound can also
make adapters unavailable on a busy host; it is never raised as a fallback.

Only declared output files and parent directories are precreated. Directories
are non-writable; macOS permits writes to exact file paths only, and bwrap drops
all capabilities, remounts guest root/proc/dev read-only and exposes only exact
output files as writable submounts. Payloads cannot create, unlink or rename
output entries. A bounded descriptor watchdog checks directory/file identity,
shape and aggregate size throughout execution, including after pipes close.
Exceeding 8 MiB total or changing the tree kills/reaps the group and records an
`output-limit` fact; over-limit generated files are excluded from publication.
The 8 MiB per-file hard limit bounds growth between watchdog checks; no separate
filesystem quota or strict zero-overshoot aggregate limit is claimed.

Immediately before payload launch, each placeholder's device/inode/size/mtime/
ctime is snapshotted. Untouched placeholders remain absent from evidence;
explicit zero-byte writes count as produced even if mtime is restored.
Declared captured outputs are at most 256 regular files/8 MiB total. Canonical nested paths
have at most 32 components, 255 bytes/component and 4096 bytes overall; prefix
collisions, traversal, links, special files and undeclared tree entries refuse.
Bounded descriptor enumeration and the generalized shared no-follow installer
preserve `outputs/<declared-path>` under
`artifacts/firmware-dive-probes/<id>/`, with separate `evidence/stdout` and
`evidence/stderr`. Canonical identity binds exact question/contract/spec, runtime,
termination, dependency and output hashes/sizes, excludes timestamps and local
host paths, and installs before locked exact revalidation and one acquisition
row. Exact duplicates make no writes; conflicts/failures preserve SQL and siblings.

Historical pre-runtime-bound Task 6 cold focused coverage passed 329 probe/capture/preparation tests,
with zero unexecuted statements in `firmware_dive.py` (569 executable) and
`firmware_dive_acquisition.py` (705 executable). The package executable denominator
is 9,665; focused execution is not full-package coverage.

Historical pre-runtime-bound Task 6 full-harness verification: `make all` passed all eight gates with 7,360
tests; 29 dispatchable verbs; 44 SQLite tables / 43 contracts; four unchanged
migrations with both firmware baselines preserved; clean skill lint;
6 CRLF / 235 LF files; 61 features / 16 stages / 21 open items with all paths
and verbs resolving; 116 installed markdown files / zero sentinel survivors /
real install untouched; zero unexecuted statements out of 9,665 (zero allowed).
The existing golden benchmark remains recall 9/19, 45 findings, precision 39/40,
$73.15 per match. These checks establish mechanical probe acquisition integrity
with purpose-built fixtures; real adapters and firmware are unverified.
`make mutate` was not run.

Historical pre-Fix-Round-1 Task 6 runtime-bound cold focused coverage passed 358 probe/capture/
preparation tests, with zero unexecuted statements in `firmware_dive.py` (569
executable) and `firmware_dive_acquisition.py` (802 executable). The package
executable denominator is 9,762; focused execution is not full-package coverage.
The broad dive/chain regression passes 3,020 tests.

Historical pre-Fix-Round-1 Task 6 runtime-bound full-harness verification: `make all` passed all eight gates
with 7,389 tests; 29 dispatchable verbs; 44 SQLite tables / 43 contracts; four
unchanged migrations with both firmware baselines preserved; clean skill lint;
6 CRLF / 235 LF files; 61 features / 16 stages / 21 open items with all paths
and verbs resolving; 116 installed markdown files / zero sentinel survivors /
real install untouched; zero unexecuted statements out of 9,762 (zero allowed).
The existing golden benchmark remains recall 9/19, 45 findings, precision 39/40,
$73.15 per match. These checks establish mechanical bounded acquisition integrity
with purpose-built fixtures; real tools, Linux and alternate Python remain
unverified. `make mutate` was not run.

Task 6 Fix Round 1 full-suite monitoring passes 7,405 tests with zero unexecuted
statements out of 9,778 (zero allowed). Cold focused coverage passes 374 probe/
capture/preparation tests with zero unexecuted shared-module statements (569
executable) and acquisition statements (818 executable).

The six remaining gates pass: 29 dispatchable verbs; 44 SQLite tables / 43
contracts; four unchanged migrations with both firmware baselines preserved;
clean skill lint; 6 CRLF / 235 LF files; 61 features / 16 stages / 21 open items
with all paths and verbs resolving; 116 installed markdown files / zero sentinel
survivors / real install untouched. The golden benchmark remains recall 9/19,
45 findings, precision 39/40, $73.15 per match. Controlled wrappers verify the
status projection and refusal rules; real tools and Linux remain unverified.
Native payload termination remains unknown. `make mutate` was not run.

Historical pre-framing Task 7 full-suite cold monitoring passed 7,565 tests with zero skips/failures
and zero unexecuted statements out of 10,089 (zero allowed). Cold focused
coverage passes 160 strict-result tests with zero unexecuted statements in
`firmware_dive_results.py` (311 executable).

The six ancillary gates pass: 29 dispatchable verbs; 44 SQLite tables / 43
contracts; four unchanged migrations with both firmware baselines preserved;
clean skill lint; 6 CRLF / 237 LF files; 62 features / 16 stages / 21 open items
with all paths and verbs resolving; 116 installed markdown files / zero sentinel
survivors / real install untouched. The golden benchmark remains recall 9/19,
45 findings, precision 39/40, $73.15 per match. These checks establish structural
result parsing and pure identities; prepared authority/publication belongs to
Task 8. `make mutate` was not run.

Historical Task 7 post-framing full-suite cold monitoring passed 7,578 tests with zero
skips/failures and zero unexecuted statements out of 10,093 (zero allowed).
Cold focused coverage passes 173 strict-result tests with zero unexecuted
statements in `firmware_dive_results.py` (315 executable). This includes exact
4096/4097-byte ASCII/Unicode probe/capture path boundaries and independent
32-component/255-byte limits, plus the separate 8192-byte reference cap.

The six ancillary gates pass with 29 dispatchable verbs; 44 SQLite tables / 43
contracts; four unchanged migrations and both firmware baselines preserved;
clean lint; 6 CRLF / 237 LF files; 62 features / 16 stages / 21 open items;
116 installed markdown files / zero sentinels / real install untouched. The
golden benchmark remains recall 9/19, 45 findings, precision 39/40, $73.15 per
match. At that boundary, Task 8 authority/publication was next; `make mutate` was not run.

Task 7 implements pure strict result parsing and canonical observation/receipt
identities in `firmware_dive_results.py`. Exact empty or single-answer envelopes
reject duplicate/extra/missing keys, unsafe prose, coercions, noncanonical sets
and worker-derived fields. Raw/canonical results are capped at 8 MiB. Evidence
references have a separate 8192-byte cap, preserving the full dynamic path
budget of 4096 UTF-8 bytes, 32 components and 255 bytes/component; prose remains
bounded at 4096 bytes. Frozen records retain no mutable container aliases. Pure contract comparison checks
structured effects, including boolean/refuted and bounded value discovery.
Observation IDs bind the caller-derived rung and candidate snapshot plus exact
effect/prose/reference projections; safe receipt keys bind exact assignment or
explicit-empty projections. At the Task 7 boundary, only bounded stable-file
`load` read files and the pure helpers made no SQL/filesystem writes. Task 8's
prepared authority and atomic publication implementation is recorded below;
completion and overlays remain later work.
CLI/worker routing, integration and full Stage 4h review remain pending. Tests execute only purpose
fixtures through injected adapters; real-tool integration is not claimed. Runtime
verification is macOS Python 3.14; Linux and alternate-interpreter execution remain
unverified. Triage upsert-only snapshots, Stage 4d retained-orphan scan scaling and
paid semantic quality limitations persist. `make mutate` remains separate.

### Continue firmware `dive` with Task 9 completion/journal/overlay validation

Task 8 implements read-only `validate` and immutable `record` in
`firmware_dive_results.py`. Validation reconstructs the exact pending generation,
index, packet/attempt, retained graph and current retained Stage 4f evidence
without a live root or caller transaction changes. Static dependencies require
packet authority and exact artifact owners; dynamic evidence reconstructs the
question-owned sealed capture/probe contract, identity, spec, manifest, evidence
hashes/counts and SQL projections. Provenance is derived from verified owners;
canonical reference arrays and contiguous semantic dependency ordinals are stored.
Only conclusive answers receive a method-derived rung; dynamic conclusions need
limitations and evidence from the corresponding acquisition, and a nonexecuted
probe cannot support a conclusion. Successors are validated proposals only.

Canonical bytes install descriptor-safely at
`artifacts/firmware-dive/<generation>/<question-id|empty>/<result-hash>/result.json`
before `BEGIN IMMEDIATE`. Source, authority, history, acquisitions and installed
bytes are repeated under lock before atomic receipt/observation/dependency rows.
Exact duplicates preserve SQL timestamps and artifact mtime; conflicting/global
ID reuse refuses, siblings survive failure, and the run remains pending.
Canonical history reconstructs each attempt's artifact and all stored rows.
Repeated observation identity compares exact semantics plus dependency provenance,
excluding assignment/result bytes and successors; distinct successors remain
attempt-local. Full typed refs adapt to digests only for pure history/overlay
contracts. Recomputed currentness does not change observation identity or let a
stale attempt enter the overlay. Legacy opaque history retains byte-exact checks;
malformed envelopes and the canonical publication namespace cannot fall back.
The Task 7 direct-constructor exception inconsistency is closed.

Task 8 full-suite cold monitoring passed 7,694 tests with zero skips/failures
and zero unexecuted statements out of 10,530 (zero allowed). The exact
Task 8 command passed 288 tests; acquisition regression passed 273. The frozen
785-test combined cold regression has 0/580 preparation/history, 0/654 question,
and 0/741 result/import statements unexecuted.

The measured ancillary gates pass: 29 dispatchable verbs; 44 SQLite tables / 43
contracts; four unchanged migrations with both firmware baselines preserved;
clean skill lint; 6 CRLF / 238 LF files; 63 features / 16 stages / 21 open items;
116 installed markdown files / zero sentinels / real install untouched. The golden
benchmark remains recall 9/19, 45 findings, precision 39/40 and $73.15 per match.
These are mechanical measurements; paid semantic quality and real-tool runtime
behavior remain unmeasured. `make mutate` was not run.

Task 9 completion/journal/overlay validation is next. It must independently
reconstruct the complete receipt denominator and each attempt's canonical result,
including successors, before any completion or overlay claim. CLI/worker behavior,
integration and whole-stage review remain pending. Tests use purpose fixtures;
Linux, alternate Python, real tools and paid semantic quality remain unverified.
No mutation sweep, merge or push was performed.

Stage 4g remains merged into local `main` at `30ca3ba`, not pushed.

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
local `main`; Stage 4e merged `hunt` at `8119af1`; Stage 4f merged firmware
`fpcheck` at `303232e`; Stage 4g merged firmware `chain` at `30ca3ba`.
These phases were built at zero audit cost. The next firmware slice is `dive`.
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
