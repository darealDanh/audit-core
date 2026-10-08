# Project progress

**Last updated:** 2026-10-08 · **HEAD:** branch `stage3c/core-hardening` (41 commits ahead of `main`, which is at `3eb2a93`, Stage 4a merged), working tree clean · **Tests:** 813 ·
**Gates:** 8/8 green (`make all`; `mutate` is opt-in and not counted) · **Benchmark gates: deferred on cost — see §7**

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

**Stages 0, 1, 2, 3 and 3b are merged to `main`; Stage 4a is complete on branch
`stage4a/qualify`, awaiting merge.** Stage 4a (`qualify`) is the first slice of Stage 4; the rest of Stages 4 and 5 have not been started.

| Stage | Name | Commits | Diff | Status |
|---|---|---:|---|---|
| 0 | Instrumentation and goldens | 25 | 28 files, +3,931 / −52 | **merged** (`dd53e56`) |
| 1 | Cost wins that cannot touch quality | 26 | 32 files, +4,055 / −361 | **merged** (`c7d5944`) |
| 2 | Structural change (`audit_core`, R1, R3) | 15 | 45 files, +9,074 / −70 | **merged** (`1f11f64`) — gate NOT run |
| 3 | Quality additions (five mechanisms) | 17 | 45 files, +8,154 / −67 | **merged** (`3aaebb5`) — gate NOT run |
| 3b | Measurement hardening and parked defects | 20 | see branch | **merged** — gate none, no audit run |
| 4a | `qualify` - the hard GO/NO-GO gate (first slice of Stage 4) | — | see branch `stage4a/qualify` | **merged** (`3eb2a93`) — gate *none — no audit run* |
| 3c | Core hardening: coverage gate and mutation harness | 41 | branch `stage3c/core-hardening` | **shipped** - gate *none - no audit run* |
| 4 | `firmware-audit` + monorepo (remaining ten phases) | — | — | not started |
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

The benchmark has not moved across Stage 2 or Stage 3 — which is the point.
Both stages were required to hold recall at or above 9/19, and both did.

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
the remaining ten phases follow in later slices.

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
7. **`main` was 124 commits ahead of `origin/main` before Stage 3c (this branch adds 41) and has never been pushed.**
   `git pull` fails with an access-rights error; origin is unreachable from
   this machine. All completed stages exist only in this working copy.

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
| `tests` | The pytest suite — 813 tests |
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

**Those leading indicators have never been built.** Until they exist, deferring
the gate is blind rather than merely deferred — which makes building them the
first task, not a nice-to-have. They read an existing `audit.db` and cost
nothing per run.

## 8. Next steps, in the order they make sense

Everything below is zero-audit-cost. The five items that used to head this list
(leading indicators, severity agreement, coverage in `bench`, re-rating, the
parked defects) shipped as Stage 3b and are recorded in §2.

1. **Push `main` to `origin` `main`** once origin is
   reachable. `main` was 124 commits ahead of `origin/main` before Stage 3c (as of writing, from
   `git rev-list --count origin/main..main`); this branch adds its own on top.
2. **Take a second indicator snapshot** after the next audit run. The first
   (`docs/indicators/2026-10-07-tplink-dl110v2-1.0.11.json`) reads `absent` for
   three of four indicators, so there is nothing to compare against yet.
3. **Decide what to do with `rerate`'s report** once a benchmark run exists to
   test it against. It is advisory and stores nothing; mutating severity is
   deliberately not done.
4. **Plan Stage 4** — `firmware-audit` plus the monorepo restructure. Gate:
   tplink >= 12/19 at <= $45, *and* the asus golden must pass, which means
   building a second golden set first. Spec §10 (monorepo vs submodule) needs
   deciding at the same time.
