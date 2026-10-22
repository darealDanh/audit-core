# Project progress

**Last updated:** 2026-10-22 · **Branch:** `stage4f-firmware-fpcheck`; Stage 4e merged into local `main` at `8119af1`, not pushed ·
**Current verification:** Stage 4f schema foundation: 726 focused tests pass; instrumented full suite passes (3,614 collected cases), 0/5,071 unexecuted statements; current gate measurements below · **Paid milestone benchmark: deferred on cost — see §7**

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

**Stages 0 through 3c and Stages 4a-4e are merged to local `main`.** Stage 4e
(`hunt`) is merged at `8119af1`; nothing has been pushed. Stage 4f firmware
`fpcheck` is in progress, with approved design and plan committed as `b4f6e0f`
and `61177ce` on this feature branch. Its five-table schema foundation and row
contracts are implemented; the next task is the read-only completed-hunt
snapshot helper. Preparation, parsing/import, completion, invalidation, and
CLI remain. Stage 5 has not started.

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
| 4 | `firmware-audit` + monorepo (remaining five firmware phases) | — | — | planned; Asus golden and monorepo decision remain prerequisites for milestone/restructure |
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

Read-only scoring of the existing audit remains unchanged through Stage 4e.
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
fail the lane gate. Batch replacement is ownership-scoped and resets only its
lane. Acquisition, target triage, and changed surface evidence invalidate the
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
and Stage 4d retains its orphan-candidate scan scaling limitation. Firmware
`fpcheck` is in progress with its schema foundation implemented; the
completed-hunt snapshot helper is next. The Asus golden remains required for the overall Stage 4
milestone, and the monorepo/submodule decision remains required for restructure.

### Stage 4f schema foundation verification

Five additive firmware review tables and their exact row contracts are
implemented. The requested focused suite passes **726 tests**; the
instrumented full suite passes, with **3,614 cases** in current collection and
**0 unexecuted / 5,071 statements, 0 allowed**. Self-test reports 28
dispatchable verbs, **32 schema tables / 31 contracted**, and the existing
four column migrations plus current schema applied to both frozen baselines
with firmware rows preserved and results accepted by `connect()`.

Measured remaining gates: clean lint; **6 CRLF / 200 LF**; **45 features / 13
stages / 21 open-item records**; **108 Markdown files installed**, zero
sentinels, real install untouched; existing benchmark recall **9/19** over
**45 findings**, precision **39/40**, **$73.15 per match**. A fresh `make all`
rechecks all eight gates after this reconciliation, as required by `AGENTS.md`.
The initial ordinary test process had collected an old CLI table-count
expectation before it was corrected; the corrected targeted test and later
instrumented full suite passed. No paid audit, mutation sweep or indicator
snapshot ran. Remaining Stage 4f work starts with the completed-hunt snapshot
helper and inherits the triage/upstream limitations stated above.

---

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
7. **Local changes are not pushed.** `main` includes Stage 4e at `8119af1`.
   The earlier observation of 50 commits ahead of `origin/main` was measured
   on 2026-10-16 and is historical, not the current synchronization count.
   Stage 4f design and plan are on `stage4f-firmware-fpcheck`. Nothing has
   been pushed.

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
| `tests` | The pytest suite — current implementation measured 2,925 tests; current harness summary is in `SESSION_HANDOFF.md` |
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

1. **Continue Stage 4f firmware `fpcheck` with the verified completed-hunt snapshot helper**;
   the five-table schema and row contracts are implemented. Then prepare batches,
   parse/import reviews, derive findings, add invalidation and expose the CLI,
   consuming Stage 4e candidates
   for static adversarial review, cross-lane/root-cause deduplication, pivot
   preservation, and promotion into a reviewed finding model. It inherits
   triage's upsert-only snapshots and Stage 4d's retained-orphan scan scaling.
   Stage 4e is merged into local `main` at `8119af1`; nothing has been pushed.
   The Asus golden and monorepo/submodule decision remain prerequisites for
   the overall Stage 4 milestone/restructure.
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
