# Project progress

**Last updated:** 2026-10-07 · **HEAD:** `3aaebb5` on `main` · **Tests:** 491 ·
**Gates:** 7/7 green (`make all`) · **Benchmark gates: deferred on cost — see §7**

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

**Stages 0, 1, 2 and 3 are complete and merged to `main`.** Stages 4 and 5 have
not been started.

| Stage | Name | Commits | Diff | Status |
|---|---|---:|---|---|
| 0 | Instrumentation and goldens | 25 | 28 files, +3,931 / −52 | **merged** (`dd53e56`) |
| 1 | Cost wins that cannot touch quality | 26 | 32 files, +4,055 / −361 | **merged** (`c7d5944`) |
| 2 | Structural change (`audit_core`, R1, R3) | 15 | 45 files, +9,074 / −70 | **merged** (`1f11f64`) — gate NOT run |
| 3 | Quality additions (five mechanisms) | 17 | 45 files, +8,154 / −67 | **merged** (`3aaebb5`) — gate NOT run |
| 4 | `firmware-audit` + monorepo | — | — | not started |
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
6. **`chain --compose --replace` and `identify --replace` still blank optional
   columns** when their flags are omitted. Real, pre-existing, parked with a
   ruling. The Stage 3 fix-wave report claimed otherwise — that claim is
   recorded as wrong so it is not trusted.
7. **`main` is 84 commits ahead of `origin/main` and has never been pushed.**
   `git pull` fails with an access-rights error; origin is unreachable from
   this machine. All four completed stages exist only in this working copy.

### Carried forward from Stage 0 and Stage 1, never actioned

Recorded at the time in
[`docs/superpowers/specs/2026-10-05-stage0-findings-for-later-stages.md`](docs/superpowers/specs/2026-10-05-stage0-findings-for-later-stages.md)
and
[`…stage1-findings-for-later-stages.md`](docs/superpowers/specs/2026-10-05-stage1-findings-for-later-stages.md).
Re-verified against the tree on 2026-10-07; the ones below are still open.

8. **Severity agreement is not scored, and nothing re-rates a finding once its
   chain is known.** Of the nine reference CRITICALs the audit *did* find, four
   were rated below the reference — REF-17, a pre-authentication
   authentication bypass, was filed **LOW** because the overflow was scored on
   its own and never traced to the authentication gate it overwrites. `bench`
   loads `severity` on both sides and compares neither. **Recall therefore
   understates the problem**, and severity is fixed at discovery time, before
   chain composition runs.
9. **No asus golden set exists**, and the Stage 4 gate requires one. Building
   it is the first task of Stage 4, not a sub-step.
10. **`audit.py preflight --server NAME=COMMAND` silently flattens a
    `--keep`-copied server** of the same name to `{"command": …}`, discarding
    `args` and `env` — the exact degradation `--keep` exists to prevent.
    Reproduced 2026-10-07; exits 0. Untested in either direction.
11. **`briefs.render` reports one error class per run** — missing placeholders
    first, empty ones only after those are fixed.
12. **Batch identifiers still disagree**: `workflows/fpcheck.md` letters them
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
make check     # tests, selftest, lint, eol, manifest, install
make all       # the above plus bench
make list      # what each gate checks
make json      # one JSON object, for CI and for agents
```

| Gate | Proves |
|---|---|
| `tests` | The pytest suite — 491 tests |
| `selftest` | Verbs vs parser, `TABLE_SPECS` vs `schema.sql`, `MIGRATIONS` vs a frozen pre-Stage-3 database |
| `lint` | Shipped prose against the economics contract |
| `eol` | The six-file CRLF set against `scripts/eol-manifest.txt` |
| `manifest` | `feature_lists.json` against the tree it describes |
| `install` | A sandboxed `install.sh`, no surviving `__SKILL_DIR__`, real install untouched |
| `bench` | Recall, precision, cost per match (opt-in; SKIPs without the corpus) |

Why it exists: five of these seven were run by hand at the end of every stage,
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

Items 1-5 are now **Stage 3b**: designed in
[`specs/2026-10-07-stage3b-measurement-hardening-design.md`](docs/superpowers/specs/2026-10-07-stage3b-measurement-hardening-design.md)
and planned in
[`plans/2026-10-07-stage3b-measurement-hardening.md`](docs/superpowers/plans/2026-10-07-stage3b-measurement-hardening.md)
— 10 tasks, 112 steps, awaiting execution.

Everything below is zero-audit-cost: it either changes code, changes prose, or
scores an `audit.db` that already exists.

1. **Build the deterministic leading indicators** (spec §6.1) — the
   between-milestone substitute for the expensive gate.
2. **Score severity agreement in `bench`** — four of the nine CRITICALs
   already found were under-rated, so the Stage 4 target of ≥ 12/19 is
   measured against a metric known to be wrong.
3. **Score coverage in `bench`** — §6.1 says `bench` reports recall,
   precision, **coverage** and cost per finding. It reports three of the four.
4. **Add a re-rating step to the pipeline** — severity is fixed at discovery
   time, before chain composition runs.
5. **Close the parked defects** — the preflight flatten, the briefs error
   ordering, the `--replace` blanking, the batch-id mismatch.
6. **Push `main`** once origin is reachable. 84 commits are local-only.
7. **Plan Stage 4** — `firmware-audit` plus the monorepo restructure. Gate:
   tplink ≥ 12/19 at ≤ $45, *and* the asus golden must pass, which means
   building a second golden set first. Spec §10 (monorepo vs submodule) needs
   deciding at the same time.
