# Project progress

**Last updated:** 2026-11-02 · **Branch:** `stage4h-firmware-dive`; Stage 4h in progress, integration pending; local `main` retains Stage 4g at `30ca3ba`, not pushed ·
**Current verification:** Task 7: 7,578 full-suite tests passed; 0/10,093 unexecuted statements (zero allowed); schema, lint, EOL, manifest, install and benchmark gates pass. Measured gate details are in the Stage 4h section. Historical merged Stage 4g results remain below. **Paid milestone benchmark: deferred on cost — see §7**

This file is the durable record of what has been built, what has deliberately
*not* been built, and what is known to be unverified. It is written for an
agent or engineer picking the project up cold.

- Architecture and the reasoning behind it → [`ARCHITECTURE.md`](ARCHITECTURE.md)
- Machine-readable inventory → [`feature_lists.json`](feature_lists.json)
- How to resume right now → [`SESSION_HANDOFF.md`](SESSION_HANDOFF.md)
- The binding authority → [`docs/superpowers/specs/2026-10-04-audit-suite-design.md`](docs/superpowers/specs/2026-10-04-audit-suite-design.md)

---

## 1. Where the project stands

The work is a staged improvement of the `codebase-audit` skill's **token
economics without losing audit quality**. That constraint is the binding one:
every cost win is measured, and anything that could cost recall or precision is
benchmark-gated before it ships.

**Stages 0 through 3c and Stages 4a-4g are merged to local `main`.** Stage 4f
firmware `fpcheck` is merged by fast-forward at `303232e`; nothing has been
pushed. Stage 4g firmware `chain` is merged by fast-forward at `30ca3ba`, from approved design
`00edb44` and plan `380b075`. The Stage 4f slice includes
five-table row contracts, verified completed-hunt snapshots, deterministic review
batches, strict results, atomic import, canonical reviewed findings, upstream
invalidation, bounded CLI, worker brief and installed routing. Final review found
JSON identity/path corruption; `303232e` preserves machine-readable values and
retains bounded human output. The scoped re-review was clean. Stage 4h firmware `dive` is now in progress
on `stage4h-firmware-dive`; schema, verified graph snapshots, strict questions,
immutable preparation, hardware captures, bounded isolated probes and pure strict result/identity contracts are implemented,
with integration and the remaining lifecycle tasks pending.
Stage 5 has not started.

| Stage | Name | Commits | Diff | Status |
|---|---|---:|---|---|
| 0 | Instrumentation and goldens | 25 | 28 files, +3,931 / −52 | **merged** (`dd53e56`) |
| 1 | Cost wins that cannot touch quality | 26 | 32 files, +4,055 / −361 | **merged** (`c7d5944`) |
| 2 | Structural change (`audit_core`, R1, R3) | 15 | 45 files, +9,074 / −70 | **merged** (`1f11f64`) — gate NOT run |
| 3 | Quality additions (five mechanisms) | 17 | 45 files, +8,154 / −67 | **merged** (`3aaebb5`) — gate NOT run |
| 3b | Measurement hardening and parked defects | 20 | see branch | **merged** — gate none, no audit run |
| 4a | `qualify` - the hard GO/NO-GO gate (first slice of Stage 4) | — | see branch `stage4a/qualify` | **merged** (`3eb2a93`) — gate *none — no audit run* |
| 3c | Core hardening: coverage gate and mutation harness | 41 | branch `stage3c/core-hardening` | **shipped** - gate *none - no audit run* |
| 4b | `acquire` + `triage` firmware provenance and inventory | 13 | 25 files, +2,087 / −105 | **merged** (`6bbb0e0`) — 8/8 gates, no audit run |
| 4c | `diff` — image-scoped firmware comparison and agent brief | 10 implementation commits | local `main` | **merged locally** (`deb3eed`) — 8/8 gates, review fixes applied, no audit run; not pushed |
| 4d | `surface` — exact-root preparation, atomic results, completion gate, agent brief | through `b14b4fb` | local `main` | **merged locally** (`6eba6d6`) — 8/8 gates, no audit run; not pushed |
| 4e | `hunt` — evidence-bound independent L-sink/L-dark candidate lanes | through `8119af1` | local `main` | **merged locally** (`8119af1`); `make all` 8/8 gates, 2,925 tests, 0/4,946 uncovered; not pushed |
| 4f | `fpcheck` — dedicated static firmware review | through `303232e` | local `main` | **merged locally** (`303232e`); scoped final re-review clean; 8/8 gates, no audit run; not pushed |
| 4g | `chain` — global static firmware evidence graphs | through `30ca3ba` | local `main` | **merged locally** (`30ca3ba`); final scoped re-review clean; merged-tree 8/8 gates, no audit run; not pushed |
| 4h | `dive` — runtime evidence settlement | through Task 6 | `stage4h-firmware-dive` | **in progress**; schema, graph snapshots, questions, immutable preparation, hardware captures and bounded probes implemented; integration pending |
| 4 | `firmware-audit` + monorepo (remaining firmware phases) | — | — | planned; Asus golden and monorepo decision remain prerequisites for milestone/restructure |
| 5 | Backport the core to `grey-audit` | — | — | not started |

Stage 3's figure includes its 3,730-line plan document, which was committed on
`main` before the branch forked; the branch's own diff was +4,424 / −67.

Test files grew 8 → 15 → 23 → 30 across the four stages, and 31 with the
harness added after Stage 3.

### Current measurements

Against the tplink DL110 v2 1.0.11 golden set (`make bench`):

| Metric | Value |
|---|---|
| Recall | **9 / 19** (47.4%) |
| Findings | 45 |
| Precision | **39 / 40** (97.5%) |
| Cost per matched finding | **$73.15** |

Read-only scoring of the existing audit remains unchanged through Stage 4g.
This does not measure the effect of new behavior: the Stage 2/3 audit reruns
remain deferred, so no recall, precision, or audit-cost improvement is claimed.

**The contrast between 97.5% precision and 47.4% recall is the most useful
number the project has produced.** It is the signature of a false-positive
check that is not filtering much: the audit is not drowning in noise, it is
simply not finding enough. That reframes Stage 4's target (≥ 12/19) as a
recall problem, not a precision one.

---

## 2. What each stage actually delivered

### Stage 0 — Instrumentation and goldens

Measurement before change, with `SKILL.md` and `workflows/` left
byte-identical on purpose.

- `audit.py budget --report` — parses a Claude Code JSONL session into epochs,
  prefix, growth and attribution.
- `tests/goldens/tplink-dl110v2-1.0.11/` — an adjudicated reference set of 19
  known CRITICALs, with `matches.json` and `rejections.json` as **human**
  adjudications.
- `audit.py bench` — recall and cost-per-match scoring.
- The first baseline, then a **correction**: the parser counted one turn per
  content block rather than per API call (Σ context 2.33× high) and charged
  attachments their whole JSONL envelope (≈7.8× high). Both fixed;
  `2026-10-04-tplink-baseline.md` is superseded and labelled, not deleted.

### Stage 1 — Cost wins that cannot touch quality

Shipped in measured order: tiering (18.0% of the thinking term), MCP preflight,
`audit.py` verbs replacing inline heredocs (~4.5%), dispatch briefs as files
(~3.2%), return contracts (1.4%).

Two things worth carrying forward:

- **The installer fix was a hard dependency, not an extra.** `install.sh`
  copied only prose, so the first workflow to invoke `audit.py` would have
  broken every installed copy. It now copies `audit.py` and `audit_core/` and
  sed-substitutes `__SKILL_DIR__` per client.
- **Rewriting shipped prose lost instructions five times out of five.** The
  control adopted in response is the **anti-absence derivation**: enumerate
  every intended change in a file *before* editing, then reconcile against
  `git diff -U0` afterwards. Four commits in Stage 1's history
  (`793eeed`, `7e63e04`, `beb0d62`, `f9c1a4f`) are restorations of instructions
  a rewrite silently dropped.

### Stage 2 — Structural change

`audit_core` extracted as a vendored, stdlib-only package; R1 (the orchestrator
never holds raw material) and R3 (context ceiling with checkpoint-restart)
landed; phase semantics unchanged.

Delivered: `db.py` with a validated table contract, `extract.py`,
`annotations.py`, `coverage.py`, `sweep.py`, `budget.py`, `ceiling.py`,
`skill_lint.py`, and a `selftest` that cross-checks the table contract against
the schema.

### Stage 3 — Quality additions

Five mechanisms, each traced to a **named cause of a missed CRITICAL** in the
tplink post-mortem, where an audit found 9 of 19:

1. **Pivot rule** — a `FALSE_POSITIVE` must record what refuted it *and* what
   that refutation enables.
2. **Sweep-on-confirm** — a confirmed bug becomes a registered pattern, and an
   unswept registered pattern is a reportable gap.
3. **Coverage denominator** — analyzed over inventoried, a reason for every
   gap, and a gate at phase exit.
4. **Identity discipline** — asserting what a component *is* requires evidence
   that is not its own filename.
5. **Chain composition** — cross-group finding pairs proposed as candidate
   chains, with findings never examined as enablers reported as such.

Plus **precision scoring** in `bench` (the "before" half of the held tiering
gate) and **in-place column migration** in `db.py`.

**Chain composition was measured on the real corpus for the first time and was
unusable as designed** — 100 candidates, capped, with 33 of 45 findings never
examined as enablers and nothing saying so. Retuned to 24 candidates,
uncapped, all 45 examined.

---

### Stage 3b — Measurement hardening and parked defects

No audit was run and no audit output changed; the benchmark gates stay
deferred (§7). Delivered:

- **Leading indicators** — `audit.py indicators` reports coverage percentage,
  surfaces opened, sweep hit counts and `not_audited` rows from an existing
  `audit.db`, with dated snapshots under `docs/indicators/` and `--compare`.
  The first snapshot (tplink) reads `surfaces opened 197` and `absent` for the
  other three, because that database predates the tables. That is the honest
  reading and is the reason it is committed.
- **`absent` is not `0`** — `audit_core/readings.py`; every new reader
  distinguishes a value, absent (no table) and empty (table, no rows).
- **Severity agreement in `bench`**, additive. On the real corpus:
  `severity 5/9 agree [4 under-rated, 0 over-rated, 0 unrankable]`, worst 3
  ladder steps. The pairs are REF-12~G1-F4 (MEDIUM), REF-14~G1-F2 (HIGH),
  REF-16~G3-F4 (HIGH) and REF-17~G1-F7 (LOW), all against CRITICAL references.
  `weighted recall 0.382` (7.25/19) sits alongside `recall 9/19`, which is
  unchanged.
- **Coverage in `bench`** — it now scores all four of the spec's figures.
- **`audit.py rerate`** — advisory, stores nothing, needs no golden set. On the
  real corpus it flags 9 findings and recovers G1-F4 and G1-F7, two of the four
  known under-rated, with one known negation false positive (G4-F4).
- **Four parked defects closed** — `--replace` column blanking, the preflight
  `--server` flatten, `briefs` one-error-class-per-run, and the fpcheck batch
  identifier mismatch.

Verbs went 20 to 22 (`indicators`, `rerate`); tests 491 to 569; `audit_core`
gained `readings.py`, `indicators.py` and `rerate.py`. No `indicators` harness
gate was added: it needs a database, the only one lives outside the repo, and a
gate that SKIPs everywhere but one machine is noise.

### Stage 3c - Core hardening

**This stage changed no audit behaviour and claims no movement in recall or
precision.** It added tests and tooling and touched no `audit_core` logic; it
cannot have moved either. No audit was run. `SKILL.md`, `workflows/` and
`references/` are untouched.

Two instruments, both shipped:

1. **Coverage gate** (`gate_coverage`, in `DEFAULT`). A `sys.monitoring` probe
   measures which `audit_core` statements no test executes; an allowlist names
   every permitted gap with a reason and a content digest, and the gate fails in
   both directions (unlisted gap, stale entry, moved line). **Start: 115
   unexecuted of 2,392 statements (95.2%). End: 0 of 2,392**, closed across 15
   modules.
2. **Mutation harness** (`gate_mutate`, opt-in, in neither `DEFAULT` nor
   `ALL_EXTRA`; the sweep takes about 54 minutes). Frozen in
   `docs/baselines/2026-10-08-mutation-sweep.md`: 1068 mutants, 708 killed, 360
   survived, 0 timeout, 0 error, **score 66.3%**. By class: logic not-removal
   89/89, logic compare+boolop 225/258 (87.2%), constants numeric/bool 160/216
   (74.1%), constants prose-string 234/505 (46.3%). The tests verify behaviour
   well and message text poorly. Task 15 then killed all 32 unallowlisted logic
   survivors; 9 equivalent mutants are allowlisted with proofs. **The gate is
   left failing** on the remaining prose-string survivors: an opt-in gate stating
   the true position beats a passing one made to pass. A post-fix sweep is
   recorded separately as its own dated note.

**Why the stage argues for itself.** `qualify.py:179` is `if score.rce_cves < 1:`,
the guard on a GO/NO-GO verdict branch. Task 4 wrote a test for it using
`rce_cves=0`, where `< 1` and `<= 1` agree, so it never pinned the boundary. The
line was covered, the coverage gate was green on it and the task review passed.
Only the mutation sweep found it. Three other hollow tests surfaced the same
way: `chains.py:162`'s same-group test shared one token (below threshold) so it
passed whether or not the rule worked; `pivot.py`'s `severity_hint`, `location`
and `rule_applied` were written by tests and never read back; `patterns.py`'s
NULL-name branch is unreachable under a `NOT NULL` column. Line coverage cannot
see this defect class.

Tests: 621 at stage start, 813 at end. `make all` runs 8 gates.

### Stage 4a - `qualify`, the first slice of `firmware-audit`

Stage 4 is being built as **vertical slices**, because eleven phases is not one
plan. `audit.py qualify` is the first: a hard GO/NO-GO gate that scores one
`vendor|model` against `_intel/target-scores.csv` (1,716 models) and refuses to
start a firmware audit on a target that cannot pay. It refuses three things,
each failing closed: a **strip-mined** target (too much already found, by
VulDB share), a target **without enough RCE-class CVEs**, and a target that is
**not still supported**. Filter 3 has no data behind it, so it is asserted with
evidence that must name something checkable (a date, a firmware version or a
vendor host); `db.check_identity_evidence` alone was measured accepting
`"Zyxel NWA50AX is supported"`, and 0 of 1,716 models can self-certify with
`"<vendor> <model> is supported"`. On real data `draytek/vigor3910` is GO (49
RCE CVEs at 0% VulDB) and `tenda/ac18` is NO-GO on `low-slop` (51 CVEs at 67%
VulDB). Verbs 22 to 23; tests 574 to 621. No audit and no benchmark was run;
the remaining phases follow in later slices.

### Stage 4b - `acquire` and `triage`

The second firmware slice owns the first firmware run data. `audit.py acquire`
records a local image's vendor, model, version, role, SHA-256, size, source, and
path; it never fetches or carves. `audit.py triage` walks an already-carved
rootfs without following symlinks, writes the file inventory and bounded ELF
facts, and records boot-start services only when it can retain the exact source
line as evidence. Empty trees and unacknowledged zero-ELF trees refuse before
the first write.

Three new tables (`cba_images`, `cba_binfacts`, `cba_services`) take the schema
to 18 tables, 17 under contract. The CLI has 25 verbs. The script and agent
halves ship together through `references/briefs/triage-brief.md`. A read-only
GL.iNet corpus check verifies that ELF rows have inventory rows, confident
architectures agree, and resolved service executables stay inside the root.

This is firmware-audit behavior built on the shared core, not a separate
`firmware-audit` skill tree. It does not fetch, carve, diff, infer ports, or
inspect the kernel or bootloader. Its simple firmware primary keys were a
known limitation, closed by Stage 4c below.

### Stage 4c - `diff`

The third firmware slice migrates `cba_binfacts` and `cba_services` to
image-scoped composite keys, preserving Stage 4b facts with an atomic,
idempotent rebuild. `audit.py init --timestamp <existing timestamp>` upgrades
the existing run; old unscoped facts become `legacy-unscoped`. Acquired images
must then be triaged to populate manifests before diffing.

`triage` now hashes every regular file into `cba_firmware_files`. Only target
and compatible unscoped triage mirror `cba_inventory`: diff-reference triage
cannot overwrite the target coverage denominator. `firmware_diff.py` compares
stored manifests by path and SHA-256, counts unchanged paths, and persists
every changed path in `cba_diff_entries` with a `cba_diffs` summary. The CLI
returns bounded counts and a content-addressed JSON path. Replacement installs
the artifact first, then commits all SQL rows together; a failed SQL write can
leave an unreferenced generation while preserving the previous result.
Triage publishes all file, ELF, service, and coverage rows in one transaction;
scan, directory-entry classification, and stat failures abort before publication.
Direct `scandir` traversal avoids `os.walk` silently suppressing classification
errors; inconsistent directory classifications also fail closed. Regular-file
paths are sorted relative to the root, excluding symlinks and nonregular entries.
Replacing an acquired image whose
hash or version changes atomically clears that image's manifest, so diff
requires retriage. Read-side SQLite errors in diff have a named CLI failure.

The diff brief assigns patch-specific semantic analysis: document the vendor
fix using both builds and search the target for surviving sibling sites,
reusing observations, patterns, and recorded sweeps. It does not turn binary
churn into findings or start general surface/hunt/emulation work.

At Stage 4c completion, the residual-fix focused suite passed 133 tests. Its full
harness, including the read-only GL.iNet manifest, ELF-hash, and service
consistency proof, measured 1,209 tests, 26 verbs, and 21 schema tables (20
under contract). All eight gates passed:
42 features, 11 stages, and 20 open-item records resolve; EOL is 6 CRLF/175 LF;
the sandbox installs 100 markdown files with zero sentinel survivors and the
real install untouched; coverage is 0 unexecuted / 3,170 statements, 0 allowed.
Read-only benchmark scoring remains recall 9/19, 45 findings, precision 39/40,
and $73.15 per match. These are historical Stage 4c measurements; current
Stage 4d measurements are in `SESSION_HANDOFF.md`.
No paid audit or mutation sweep ran. Task-scoped implementation reviews and
the whole-branch fix wave are complete; Stage 4c is integrated into local
`main`.

Remaining limits: triage upserts without pruning disappeared files (use fresh
image scopes/runs for changed carved trees), stored manifests are snapshots
rather than live filesystem verification, semantic patch-analysis quality has
not been measured by an audit, and there is still no separate firmware skill
tree. Stage 4d below adds live-root verification at its preparation boundary,
dispatch/handler mapping, authentication boundaries, device state, and
reachability evidence while preserving the target-only coverage rule.

### Stage 4d - `surface`

The fifth firmware phase adds prepare/record/check modes; Stage 4e later brings
the shared CLI to 28 verbs.
The shared `firmware_tree.py` scanner binds the complete target regular-file
manifest to the live carved root by path, kind, size, and SHA-256 before
publishing deterministic content-addressed batches. All target units remain
in the denominator; ELF/service/component hints annotate rather than filter.
Inventory disagreement and stale roots refuse; a final root rescan runs before
SQL publication. Same-input preparation is idempotent.

Three additive tables (`cba_surface_runs`, `cba_firmware_surfaces`, `cba_unknowns`)
take the schema to 24 tables, 23 under contract. They retain generation
provenance, dispatcher/handler and authentication ordering evidence, device
lifecycle/posture/auth state, reachability evidence, and durable settling
questions. Every unknown state needs its corresponding open question; honest
open unknowns pass completion. The file-backed surface brief requires an
evidence-backed decision for every assigned unit, including no-surface units,
and leaves SQL publication to the importer.

Strict result input is capped at 8 MiB and verifies image/manifest/worklist/batch
provenance and batch ownership. Canonical artifacts install before one SQL
transaction publishes claims and surface coverage. Duplicate imports require
`--replace`, scoped to the assigned batch; import resets pending. Only the
explicit gate can mark complete after checking every unit and every batch's
canonical result evidence, including claim-free batches. Missing decisions,
budget skips, stale provenance, and dangling unknowns refuse. Expected SQL
diagnostics are fixed; other expected CLI errors are escaped and capped at
512 ASCII characters plus a newline. Unexpected exceptions propagate after
rollback. Changed worklist generations and changed target acquisition
provenance invalidate dependent surface rows and only affected surface coverage
atomically. Failed SQL preserves prior state; orphan artifacts may remain.

The exact reopened Task 10 focused suite passed **1,168 tests** with no corpus
skip.
Task-scoped implementation reviews and the controller's whole-branch review
of `deb3eed..4394621` are complete. Its two Important findings (unexpected
exception hiding and unbounded diagnostics) were fixed in `2550866` and the
scoped re-review was clean. The final whole-branch review then found overlapping
explicit targets shared raw inventory/surface coverage keys. Fix `b14b4fb`
qualifies `cba_inventory.unit` and surface `cba_coverage.unit` through the single
`db.firmware_unit_key` encoding, preserving schemas and generic coverage joins.
Preparation/import/check, replacement, and acquisition invalidation now isolate
each target even with identical raw paths. Artifacts, surface/unknown component
paths, and surface-facing output remain raw; legacy-unscoped remains raw.
Old unqualified inventory is not accepted for acquired images; overlapping old
raw surface coverage refuses import even with replacement and is preserved by
invalidation. Use a fresh run rather than guessing ownership. ELF/service hints
are image-scoped; globally keyed component hints remain advisory. Retriage is
still upsert-only. The fix's scoped review was clean. Fresh post-documentation
`make all` passes all eight gates: **2,081 tests**, 27 dispatchable verbs, 24
schema tables / 23 contracted, with columns and primary keys agreeing. Four
migrations plus current schema apply to the frozen pre-Stage-3 and Stage-4b
baselines, preserve firmware rows, and are accepted by `connect()`. Lint is
clean; EOL is 6 CRLF / 186 LF; 43 features / 12 stages / 21 open-item records
resolve. The sandbox installs 104 Markdown files with zero sentinel survivors
and the real install untouched. Statement coverage is **0 unexecuted / 4,074
statements, 0 allowed**. Benchmark scoring remains recall 9/19, 45 findings,
precision 39/40, and $73.15 per match. These replace the superseded initial
closeout counts; the complete summary is in `SESSION_HANDOFF.md`.

No audit, new indicator snapshot, paid milestone benchmark, or mutation sweep
ran. The full harness's benchmark gate only scores the existing read-only
baseline. Stage 4d itself does not fetch/carve/modify/execute firmware, infer live
listeners, hunt vulnerabilities, assign severity, emulate, inspect the
kernel/bootloader, or create a separate firmware skill tree. Triage remains
upsert-only; changed carved trees need a fresh image scope/run and retriage.
The gate's scan of retained orphan result candidates scales with retained
generations, an accepted local-run performance limit; a future durable batch
receipt should remove that scan without capping completeness. Stage 4e `hunt`
is implemented below with separate, non-transferable L-sink and L-dark budgets.

### Stage 4e - `hunt`

Stage 4e implements evidence-bound firmware candidate analysis after a
complete, current Stage 4d surface generation. It remains firmware-audit
functionality housed in the shared `codebase-audit` repository; the separate
firmware skill tree and monorepo/submodule decision remain open. Preparation
and checking verify an acquired target's complete live regular-file root
against its image-scoped manifest. Both L-sink and L-dark assign every target
unit exactly once, with independent worklists, receipts, coverage phases, and
completion states. Hints never reduce either denominator.

Workers write strict bounded batch JSON. The importer validates image, lane,
manifest, surface snapshot, worklist, batch, and exact assigned-unit ownership,
installs canonical results, then atomically publishes a durable receipt,
image-qualified coverage decisions, and candidate rows. Receipts make
candidate-free batches auditable without scanning retained artifacts. A
`not_applicable` result maps to shared coverage `state='analyzed'`, with its
evidence-backed reason retained; `not_audited` stays distinct and budget skips
fail the lane gate. Changed batch replacement is ownership-scoped and resets
only its lane; byte-identical replacement preserves completion and timestamps. Acquisition, target triage, and changed surface evidence invalidate the
same image's hunt state in their publication transaction. Ambiguous raw legacy
coverage is preserved and refused because its image ownership is unknown.

Task-scoped implementation reviews through Task 8 were clean after recorded
fix rounds. Whole-branch review then found and closed the canonical result size
boundary, ignored inventory dependency, worker checkpoint ownership, and lane
dispatch tiering issues. The canonical-size regression proves an exactly 8 MiB
raw result that would serialize to 8 MiB + 1 is rejected before install or SQL,
including replacement rollback. Inventory and brief regressions protect
clean-checkout manifest resolution and orchestrator-owned checkpoint publication.

The historical Stage 4e final `make all` passed all eight gates: 2,925 tests in 168.94 seconds;
28 dispatchable verbs; 27 schema tables / 26 contracted; four migrations plus
the current schema applied to the frozen pre-Stage-3 and Stage-4b baselines,
firmware rows preserved and results accepted by `connect()`; clean lint; 6
CRLF / 197 LF; 44 features / 13 stages / 21 open-item records; 108 Markdown
files installed, zero sentinels, real install untouched; 0 unexecuted / 4,946
statements, 0 allowed; benchmark recall 9/19 over 45 findings, precision
39/40, $73.15 per matched finding. Plain `python3 -m pytest -q` passed 2,925
tests in 140.33 seconds. These benchmark figures score the existing baseline;
no firmware audit, paid milestone run, or quality improvement is claimed.

The historical merged-state `make all` verification on the Stage 4f worktree
preserved those counts and summaries, with 6 CRLF / 199 LF after adding the approved
Stage 4f design and plan. All eight gates passed; that summary is recorded
in `SESSION_HANDOFF.md` under Historical Stage 4e merged-state verification.

No new indicator snapshot or mutation sweep ran. Triage remains upsert-only
and Stage 4d retains its orphan-candidate scan scaling limitation. Stage 4f is
merged into local `main` at `303232e` after clean scoped final re-review. The
next firmware slice is `chain`.
The Asus golden and monorepo/submodule decision remain milestone/restructure
prerequisites.

### Historical Stage 4f schema foundation verification

Five additive firmware review tables and their exact row contracts are
implemented. The requested focused suite passes **726 tests**. The completed
post-reconciliation `make all` passed **all eight gates**, with **3,614 tests
passed** and **0 unexecuted / 5,071 statements, 0 allowed**. The initial
successful full run took **169.46s** for the test suite. Self-test reports 28
dispatchable verbs, **32 schema tables / 31 contracted**, and the existing
four column migrations plus current schema applied to both frozen baselines
with firmware rows preserved and results accepted by `connect()`.

Measured remaining gates: clean lint; **6 CRLF / 200 LF**; **45 features / 13
stages / 21 open-item records**; **108 Markdown files installed**, zero
sentinels, real install untouched; existing benchmark recall **9/19** over
**45 findings**, precision **39/40**, **$73.15 per match**. Full-harness
verification completed after the documentation reconciliation required by `AGENTS.md`.
The initial ordinary test process had collected an old CLI table-count
expectation before it was corrected; the corrected targeted test and later
instrumented full suite passed. No paid audit, mutation sweep or indicator
snapshot ran. At that point, remaining Stage 4f work started with the completed-hunt
snapshot helper and inherited the triage/upstream limitations stated above.

### Historical Stage 4f verified completed-hunt snapshot

`hunt.verified_snapshot` now shares the complete Stage 4e verifier with
`hunt.check`, requires two already-complete lanes, and performs no SQL writes
or completion transitions. Frozen lane/candidate/blocker records retain all
verified candidate evidence, lane-qualified identity and run-relative canonical
artifact provenance. It works on read-only SQLite connections and inside a
caller's transaction. Real artifact/SQLite regressions cover input corruption,
same-size live-root changes, pending lanes, escaping/symlink artifacts, nested
immutability, candidate-free lanes and corruption beyond the 200-row display cap.
The Stage 4e and snapshot suites pass **407 tests**. Full `make all` evidence:
**all eight gates passed**, **3,663 tests passed**, **0 unexecuted / 5,134
statements, 0 allowed**; **28 dispatchable verbs**; **32 schema tables / 31
contracted** with columns/keys agreeing; four migrations plus current schema
apply to both frozen baselines, preserving firmware rows and producing databases
accepted by `connect()`; clean lint; **6 CRLF / 201 LF**; **46 features / 13
stages / 21 open-item records**; **108 Markdown files installed**, zero
sentinels, real install untouched; existing benchmark recall **9/19** over
**45 findings**, precision **39/40**, **$73.15 per match**. Verification includes
a fresh full harness after the final documentation reconciliation. No mutation
sweep, paid audit/milestone rerun or indicator snapshot ran. At that point,
deterministic review-batch preparation was next; the inherited limitations remain.

### Historical Stage 4f deterministic review-batch preparation

`firmware_fpcheck.prepare` now consumes `hunt.verified_snapshot`, preserves all
lane-qualified evidence and owning artifact provenance, and binds the candidate
digest to both hunt worklists. Canonical index/batch artifacts exclude timestamps
and absolute root metadata. Normalized similarity signatures only route candidates
to reviewers; they never merge findings. Stable clusters never split, requested
size is 1..200, and no cluster or batch exceeds 1,000. Empty hunts receive one
canonical empty batch. Artifact installation precedes locked hunt/live-root and
installed-byte revalidation, followed by one pending run row. Identical preparation
preserves completed review state; changed preparation and explicit invalidation
clear only the selected image's five Stage 4f tables.

RED: **28 missing-module failures / 13 existing snapshot tests passed**. Additional
adversarial RED found symlink-parent redirection before installation; the parent
guard fixes it. A relative-run spelling RED also exposed unnecessary invalidation;
normalizing the run path preserves idempotence. GREEN: **204 focused tests passed**,
including **54 preparation/snapshot tests**. Full harness: `make all` passed
**all 8 gates**, with **3,704 tests passed** and **0/5,263 unexecuted statements**
(zero allowed). Selftest: **28 verbs**, **32 schema tables / 31 contracted tables**,
and **4 migrations plus current schema** passing both baselines. Skill lint is
clean; line endings: **6 CRLF / 202 LF**; manifest: **47 features / 13 stages /
21 open items**; install: **108 Markdown files**, zero sentinels, real install
untouched. Existing benchmark: recall **9/19** over **45 findings**, precision
**39/40**, **$73.15 per match**. No mutation sweep, paid audit/milestone rerun,
or indicator snapshot ran. Historical measurements above remain intact.
At that boundary Task 5 was next: strict review-result parsing and ownership validation. Result import,
completion, upstream invalidation wiring (Task 8), and CLI remain. Triage's upsert-only
snapshots and Stage 4d's retained-orphan scan scaling remain inherited limitations.

### Historical Stage 4f strict adversarial review results

Task 5 introduced frozen typed result/variant records in `firmware_fpcheck_results`,
strict bounded UTF-8 JSON loading, read-only assignment/ownership validation,
and canonical bytes containing only worker evidence. Both raw and canonical
results are capped at 8 MiB, including the newline expansion at the exact raw
boundary. Duplicate JSON keys, unknown/missing keys, non-finite values, boolean
integers, unsafe identifiers/paths, duplicate arrays, mismatched variants, and
missing adversarial evidence are rejected. Canonical rules are HE-1..18,
PR-1..10, CV-1..3 and MARGINAL-GAIN; image IDs preserve existing UTF-8 identity.
Validation rebuilds current completed-hunt evidence and every canonical review
assignment, checks exact lane-qualified membership before verdict semantics
(including confidence 0..10), and verifies selected-image component/surface
ownership. Pending and complete runs require consistent completion timestamps.
Cross-batch non-self duplicate targets are allowed; Task 7 resolves global chains.
No SQL/artifact writes occur, including on read-only SQLite or in caller-owned
transactions. The API has no live-root parameter: prepare and final check retain
that verification boundary.

RED: **142 missing-module failures**, then **8 canonical-rule failures**, **4
image-ID/confidence-precedence failures**, and **1 completed-generation failure**
before their respective changes. Latest focused GREEN: **221 tests passed**.
Full harness: `make all` passed **all 8 gates**, with **3,871 tests passed** and
**0/5,546 unexecuted statements** (zero allowed). Selftest: **28 verbs**, **32
schema tables / 31 contracted tables**, and **4 migrations plus current schema**
passing both baselines. Skill lint is clean; line endings: **6 CRLF / 204 LF**;
manifest: **48 features / 13 stages / 21 open items**; install: **108 Markdown
files**, zero sentinels, real install untouched. Existing benchmark: recall
**9/19** over **45 findings**, precision **39/40**, **$73.15 per match**.
No mutation sweep, paid audit/milestone rerun or indicator snapshot ran.

At the Task 5 boundary, Task 6 was next: artifact-first atomic batch import, with locked revalidation of
mutable generation evidence. Finding derivation/completion, upstream invalidation
wiring (Task 8), and CLI remain. Triage's upsert-only snapshots and Stage 4d's
retained-orphan scan scaling remain inherited limitations.

### Historical Stage 4f atomic batch import

Task 6 adds frozen `ImportSummary` and `record` to the strict result module.
Canonical immutable result artifacts install before one `BEGIN IMMEDIATE`
transaction; mutable hunt/snapshot/worklist/assignment provenance, receipt ownership
and installed bytes are rechecked under the lock. Each batch publishes one receipt,
one verdict per lane-qualified candidate, and one pivot per false positive.
SQL defaults own timestamps; the importer derives all SQL provenance.
Empty batches retain zero-count receipts. Duplicate imports require explicit
replacement. Replacement removes only selected-image/current-snapshot/batch claims;
pivot deletion joins lane-qualified source verdicts. Sibling images/batches and
old-snapshot pivots survive. Selected-image derived findings are cleared and the
run returns to pending. Rollback preserves prior SQL on read/install/SQL/commit
failures; an unreferenced immutable canonical artifact may remain.

RED: **26 expected missing-record failures / 167 existing result tests passed
in 22.61s**. Latest focused GREEN: **254 tests passed in 62.07s**, including the
preparation, strict result and import suites.
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

At the Task 6 boundary, Task 7 global duplicate graph checks, root-cause grouping,
reviewed finding derivation and completion with exact live-root revalidation were next. Upstream invalidation
wiring (Task 8) and CLI remain. Triage's upsert-only snapshots, Stage 4d retained-orphan
scan scaling, and the overall milestone's missing Asus golden/restructure decision
remain inherited limitations. No mutation sweep, paid audit or indicator snapshot ran.

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

The final execution report recorded the authoritative post-documentation
`make all` result. Historical Task 11 measurements above remain intact. The
single final-fix wave passed scoped re-review and Stage 4f is merged into local
`main` at `303232e`. No push, mutation sweep, paid audit/milestone rerun or
indicator snapshot ran. The next firmware slice is `chain`, retaining
triage's upsert-only snapshots and Stage 4d orphan-scan scaling. The Asus golden
and monorepo/submodule decision remain overall milestone/restructure
prerequisites; static contracts do not establish semantic audit quality.

### Stage 4g — global static firmware evidence graphs

Stage 4g is merged into local `main` by fast-forward at `30ca3ba`; no push ran.
Six dedicated tables retain one image/snapshot-owned chain run,
its immutable result receipt, one disposition for every current Stage 4f finding,
open blockers, deterministic chains, and ordered typed edges. The overloaded
`chain` CLI preserves ordinary source-code proposal/composition behavior while
adding explicit firmware `--prepare`, `--record`, and `--check` modes.

Preparation consumes a verified complete Stage 4f findings snapshot and installs
one immutable global worklist. Strict bounded JSON permits finding reuse across
multiple chains, requires exact dispositions, binds producer/consumer-owned
evidence to typed capability/link identities, and mechanically carries lifecycle,
posture, and authentication state across direct, reboot, service-restart,
factory-reset, and reprovision transitions. Unresolved Stage 4d unknowns and new
blockers remain explicit and settleable; pivots are context-only and can never be
nodes or evidence. Import installs canonical result bytes before one immediate
transaction; completion independently reconstructs all receipt-owned rows,
derives deterministic `static-chained` graphs, and revalidates live root plus
current Stage 4f evidence. Upstream Stage 4f changes invalidate all six selected-
image tables atomically while preserving sibling images. Record/check can retain
valid older SQL generations, but upstream invalidation clears every Stage 4g SQL
generation for the selected image; immutable content-addressed artifacts remain.

The ninth installed brief assigns the complete immutable worklist to one strongest
global worker and routes prepare → file-backed brief → record → check. Workers own
result JSON only, never SQL, artifacts, identities, receipts, derived claims, or
completion. Static chains do not establish runtime reachability, semantic
causality beyond retained evidence, severity/CVSS, exploitability, or successful
exploitation; those questions remain for `dive`/`decide` and live verification.

The independent whole-branch review found two Important cross-layer invariants:
`other-specific` link keys differed between semantic validation and persistence,
and nonmaterialized dispositions could retain unresolved references. Commit
`661c3c9` unified link validation and rejects contradictory standalone/
unchainable dispositions; scoped re-review marked both addressed with no new
Critical or Important issue. Final review then found that blocker-side affected
findings could contradict nonmaterialized dispositions. Commit `7dad245`
requires each such finding to carry a reciprocal blocked disposition and blocker
reference; focused Stage 4f/4g regression passed 2,557 tests. The complete fix
wave passed scoped re-review. Coverage passes 0/7,392 statements with
no allowances. The current full harness passes all eight gates: 5,902 tests; 29 verbs; 38 schema tables, 37 contracted;
four migrations plus current schema on both frozen baselines; 6 CRLF and 224 LF
files; 55 features, 15 stages, and 21 open-item records; 116 installed Markdown
files; 0/7,392 uncovered statements; benchmark recall 9/19, 45 findings,
precision 39/40, and $73.15 per match.

No mutation sweep, paid semantic audit/milestone rerun, Asus golden, or indicator
snapshot ran. Triage remains upsert-only and Stage 4d retains its orphan-result
scan scaling limit. The separate firmware skill tree and monorepo/submodule
decision remain open. The next firmware slice is `dive`.

---

### Stage 4h — preparation, captures and bounded probes (in progress)

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
isolated probes below; results, completion, overlays, CLI and worker integration remain pending. No new runtime
claim, paid audit, mutation sweep, merge or push is claimed.

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

Result/journal and retained probe bodies remain opaque to preparation; its retained
history boundary continues exact SQL/byte and method/rung checks. Later result,
completion and overlay gates must consume sealed capture/probe semantics and enforce
canonical observation identity. Task 6 now preserves these descriptor, exact
prepared-contract and locked publication boundaries for bounded isolated probes. Stage 4h remains in progress, integration pending; no runtime,
severity or exploit claim is made.

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

Task 7 post-framing full-suite cold monitoring passes 7,578 tests with zero
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
match. Task 8 authority/publication remains next; `make mutate` was not run.

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
explicit-empty projections. Only bounded stable-file `load` reads; no SQL or
filesystem writes occur. Task 8 must prove prepared empty/nonempty ownership,
packet-authorized dependencies/evidence and method-derived rungs before atomic
result publication. Preparation still treats retained result/journal bodies as
opaque despite exact byte/SQL checks; completion and overlays remain later work.
CLI/worker routing, integration and full Stage 4h review remain pending. Tests execute only purpose
fixtures through injected adapters; real-tool integration is not claimed. Runtime
verification is macOS Python 3.14; Linux and alternate-interpreter execution remain
unverified. Triage upsert-only snapshots, Stage 4d retained-orphan scan scaling and
paid semantic quality limitations persist. `make mutate` remains separate.

## 3. What was deliberately not done

| Item | Why | Where it is recorded |
|---|---|---|
| **Sonnet tiering for feature mapping and FP-check** | Spec-mandated, but no precision baseline exists on the current configuration, so there is no "before" to measure against. Two guard tests prevent accidental application. | `docs/baselines/2026-10-05-stage3-tiering-gate.md` — carries the exact five-file diff; applying it later is transcription |
| **Cross-target pattern library** (spec §3.5.2) | Out of Stage 3's scope; belongs with the second target | Destination Stage 4 |
| **Running the Stage 2 and Stage 3 gates** | A benchmark run now measures both stages together. That sequencing is the operator's call. | Both gate documents open with `**Status: NOT RUN.**` |

---

## 4. Known-unverified — read before trusting anything

These are recorded in the gate documents and in `feature_lists.json`'s
`open_items`, not implied:

1. **The Stage 2 gate has never been run.** Its document is a procedure, not a
   measurement.
2. **The Stage 3 gate has never been run.** Same.
3. **No precision baseline exists on the current configuration**, which is why
   the Sonnet tiering change is held.
4. **`install.ps1` has never been executed** — there is no PowerShell on this
   machine. The Bash installer is covered by tests and by the harness install
   gate; the PowerShell path is reviewed, not run.
5. **`preflight` output has never reached a client that actually connected a
   real MCP server.** The file is produced and its shape is tested; the end of
   the loop is unverified.
6. **`chain --compose --replace` and `identify --replace` blanked optional
   columns** when their flags were omitted. Fixed in Stage 3b (`--replace`
   now preserves columns the caller did not pass). The Stage 3 fix-wave report
   had claimed this earlier; that claim was wrong at the time and is kept in
   SESSION_HANDOFF §6 so it is not trusted.
7. **Local changes are not pushed.** `main` includes Stage 4f at `303232e` and
   Stage 4g at `30ca3ba`; the Stage 4g feature branch/worktree were removed
   after the clean merged-tree harness.
   The earlier observation of 50 commits ahead of `origin/main` was measured
   on 2026-10-16 and is historical, not the current synchronization count.
   The former Stage 4f feature branch/worktree were removed after the local
   fast-forward merge. Nothing has been pushed.

### Carried forward from Stage 0 and Stage 1, never actioned

Recorded at the time in
[`docs/superpowers/specs/2026-10-05-stage0-findings-for-later-stages.md`](docs/superpowers/specs/2026-10-05-stage0-findings-for-later-stages.md)
and
[`…stage1-findings-for-later-stages.md`](docs/superpowers/specs/2026-10-05-stage1-findings-for-later-stages.md).
Re-verified against the tree on 2026-10-07. Items 8, 10, 11 and 12 were closed
in Stage 3b (marked below); 9 and 13 remain open.

8. **[closed in Stage 3b]** **Severity agreement is not scored, and nothing re-rates a finding once its
   chain is known.** Of the nine reference CRITICALs the audit *did* find, four
   were rated below the reference — REF-17, a pre-authentication
   authentication bypass, was filed **LOW** because the overflow was scored on
   its own and never traced to the authentication gate it overwrites. `bench`
   loads `severity` on both sides and compares neither. **Recall therefore
   understates the problem**, and severity is fixed at discovery time, before
   chain composition runs.
9. **No asus golden set exists**, and the Stage 4 gate requires one. Building
   it is the first task of Stage 4, not a sub-step.
10. **[closed in Stage 3b]** **`audit.py preflight --server NAME=COMMAND` silently flattens a
    `--keep`-copied server** of the same name to `{"command": …}`, discarding
    `args` and `env` — the exact degradation `--keep` exists to prevent.
    Reproduced 2026-10-07; exits 0. Untested in either direction.
11. **[closed in Stage 3b]** **`briefs.render` reports one error class per run** — missing placeholders
    first, empty ones only after those are fixed.
12. **[closed in Stage 3b]** **Batch identifiers disagreed**: `workflows/fpcheck.md` letters them
    `A, B, C`; `references/phase5-fp-check.md`'s worked example uses `B1`.
13. **Spec §10 is undecided**: whether `grey-audit` joins the monorepo or
    consumes the core as a submodule. Blocks the Stage 4 restructure, not the
    firmware phases.

One item from that list *is* now fixed and is recorded here so it is not
re-opened: `install.sh` does remove `workflows/` and `references/` before
copying (`install.sh:126`), so a file deleted from the repo no longer lingers
in a `.sh`-installed tree.

---

## 5. The verification harness (added 2026-10-07)

Everything that must pass before a merge now runs from one entry point.

```bash
make check     # tests, selftest, lint, eol, manifest, install, coverage
make all       # the above plus bench
make mutate    # opt-in, ~1h, outside `make all`
make list      # what each gate checks
make json      # one JSON object, for CI and for agents
```

| Gate | Proves |
|---|---|
| `tests` | The full pytest suite; current measured totals are in `SESSION_HANDOFF.md` |
| `selftest` | Verbs vs parser, `TABLE_SPECS` vs `schema.sql`, `MIGRATIONS` vs a frozen pre-Stage-3 database |
| `lint` | Shipped prose against the economics contract |
| `eol` | The six-file CRLF set against `scripts/eol-manifest.txt` |
| `manifest` | `feature_lists.json` against the tree it describes |
| `install` | A sandboxed `install.sh`, no surviving `__SKILL_DIR__`, real install untouched |
| `coverage` | Every unexecuted `audit_core` statement is in `scripts/coverage-allowlist.txt` with a reason (SKIPs below Python 3.12) |
| `bench` | Recall, precision, cost per match (opt-in; SKIPs without the corpus) |
| `mutate` | Every surviving mutant of `audit_core` is allowlisted (opt-in, ~1h, NOT in `make all`) |

Why it exists: five of the original seven (tests, selftest, lint, install, bench) were run by hand at the end of every stage,
from memory, in an order nobody had written down. Two of them — the
line-ending contract and the real-install safety assertion — were not checked
by anything at all and depended on whoever was driving remembering they
mattered.

`.github/workflows/ci.yml` runs the same gates on Python 3.10, 3.12 and 3.13.
There is no separate CI script that can drift out of step with the harness.

---

## 6. Lessons that cost real time

Carry these into Stage 4.

**On prose.** Rewriting shipped prose loses instructions — five for five.
Derive before you edit, reconcile against `git diff -U0` after. And a command
inside a `>` blockquote in a workflow file is **presented to the user, not
executed**: Stage 3 shipped its coverage gate into one and it never ran in
either mode.

**On SQLite.** There is no `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, and
`CREATE TABLE IF NOT EXISTS` is a no-op against a table that already exists —
so adding a column to `schema.sql` repairs *nothing* on a database that already
exists. And `INSERT OR REPLACE` drops every column the caller did not pass;
that silently destroyed `final_id`, `merged_into` and `final_severity` on a
pivot, because a *different* workflow step writes them.

**On review.** The whole-branch review found two Criticals that nine
task-scoped reviews were structurally blind to — in both Stage 2 and Stage 3.
A per-task reviewer cannot see a writer that no task was assigned to build.
Stage 3's C2 was exactly that: the coverage gate shipped with **no writer
side**, so following the shipped workflow exactly produced FAIL / exit 1 on a
correct run.

**On scoping a skip.** "Add `reports` to `SKIP_DIRS`" excluded any `reports`
directory at any depth, and a real `strcpy` in `src/reports/export.c` was never
scanned. The fix is `ROOT_ONLY_SKIP_DIRS`, applied only at the walk root.

**On reports.** Several subagent reports asserted things that were not true —
a hunk count off by six that propagated into a review brief, a fix claimed as
applied that was not. Verify load-bearing claims independently rather than
accepting them.

---

## 7. Operator decision, 2026-10-07: the gates are deferred on cost

**Do not run a full audit to close a gate until the operator says otherwise.**
The tplink baseline run cost **$658.37**; the Stage 2 + Stage 3 gate is two
such runs, and the tiering gate is four. The decision is to finish the skill
work first and spend the benchmark budget once, later, on a tree worth
measuring.

This is the spec's own path, not a deviation. §6.1, acknowledged limitations:

> **Benchmark cost.** A full re-run is itself expensive, so the benchmark runs
> at milestones only, never per-commit. Between milestones, **deterministic
> leading indicators** are used instead: coverage percentage, surfaces opened,
> sweep hit counts, `not_audited` row count.

Those leading indicators were built in Stage 3b. A useful comparison still
needs the next audit run, so the first snapshot remains a one-point baseline.

## 8. Next steps, in the order they make sense

Everything below is zero-audit-cost. The five items that used to head this list
(leading indicators, severity agreement, coverage in `bench`, re-rating, the
parked defects) shipped as Stage 3b and are recorded in §2.

1. **Continue Stage 4h firmware `dive` with Task 8 result validation/publication.**
   Tasks 1–7 implement schema, verified graph snapshots, strict questions,
   immutable preparation, sealed acquisitions and pure strict result/identity
   contracts on `stage4h-firmware-dive`; integration remains pending. Task 8
   must prove prepared denominator/ownership, packet-authorized refs and derived
   evidence rungs before immutable result publication. Preparation still treats
   retained result/journal bodies as opaque; completion and overlays remain later work.
   Stage 4g remains merged into local `main` at `30ca3ba`, not pushed.
   `dive` must consume only completed, current `static-chained`
   graphs and explicitly settle blockers/runtime reachability rather than treating
   static correlation as causality. Triage's upsert-only snapshots and Stage 4d
   retained-orphan scan scaling persist. The Asus golden and monorepo/submodule
   decision remain prerequisites for the overall Stage 4 milestone/restructure;
   paid semantic quality remains unmeasured.
2. **Take a second indicator snapshot** after the next audit run. The first
   (`docs/indicators/2026-10-07-tplink-dl110v2-1.0.11.json`) reads `absent` for
   three of four indicators, so there is nothing to compare against yet.
3. **Decide what to do with `rerate`'s report** once a benchmark run exists to
   test it against. It is advisory and stores nothing; mutating severity is
   deliberately not done.
4. **Build the asus golden and settle the restructure** before the Stage 4
   milestone gate. The gate remains tplink >= 12/19 at <= $45, *and* the asus
   golden must pass. Spec §10 (monorepo vs submodule) still needs a decision
   before the separate firmware skill tree or Stage 5 alignment.
