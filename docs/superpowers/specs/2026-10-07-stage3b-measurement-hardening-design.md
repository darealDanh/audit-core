# Stage 3b — Measurement hardening, and the defects Stages 0 and 1 parked

**Status:** design approved 2026-10-07, not yet planned.
**Derives from:** [`2026-10-04-audit-suite-design.md`](2026-10-04-audit-suite-design.md)
§5.3, §6.1 and §7; [`2026-10-05-stage0-findings-for-later-stages.md`](2026-10-05-stage0-findings-for-later-stages.md)
§1; [`2026-10-05-stage1-findings-for-later-stages.md`](2026-10-05-stage1-findings-for-later-stages.md)
§3 and §4.

This is an addendum, not a replacement. The parent spec remains the binding
authority; where this document and the parent disagree, the parent wins and
the disagreement is a defect in this document.

---

## 1. Why this stage exists

Stages 0 through 3 are merged. The next spec stage is Stage 4, whose gate is
**tplink ≥ 12/19 at ≤ $45, plus the asus golden**. Two things make starting
Stage 4 now a mistake.

**The gate measures the wrong thing.** Of the nine reference CRITICALs the
audit did find, **four were rated below the reference** — and REF-17, a
pre-authentication authentication bypass, was filed **LOW**, because the
check-after-copy overrun was scored on its own and never traced to the
authentication gate it overwrites, even though our own finding names the
consumer branch (`klap_handshake1_handle@0x0E043264`). `bench` loads
`severity` on both the reference and the finding side and **compares
neither**. So ≥ 12/19 can be reached while still filing an auth bypass as a
low-severity overflow. Recorded at the end of Stage 0 as an input to later
stages; never actioned.

**There is no cheap signal between milestones.** The parent spec's §6.1
anticipates exactly this:

> **Benchmark cost.** A full re-run is itself expensive, so the benchmark runs
> at milestones only, never per-commit. Between milestones, deterministic
> leading indicators are used instead: coverage percentage, surfaces opened,
> sweep hit counts, `not_audited` row count.

**Those indicators have never been built.** The operator's decision of
2026-10-07 is to defer the benchmark gates on cost — the tplink baseline run
cost $658.37, a gate is two such runs, the tiering gate is four. Deferring is
the spec's own path, but without the leading indicators it is *blind*
deferral rather than deferral. Building them is what makes the decision safe.

A third, smaller reason: Stages 0 and 1 each recorded carried-forward defects
that no later stage picked up. They are cheap, they are verified still open as
of 2026-10-07, and they will not get cheaper.

## 2. Goals and non-goals

### Goals

1. Make a **cheap partial run** informative. Today a run is informative only if
   it is a full audit scored for recall; the indicators make one feature group
   or recon alone worth measuring.
2. Make `bench` score what §6.1 says it scores — recall, precision,
   **coverage**, and cost per finding — plus severity agreement.
3. Surface severity under-rating **without changing any stored severity**.
4. Close the four parked defects.

### Non-goals

- **No change to audit output.** Nothing in this stage alters what an audit
  records. That is what makes it shippable while the benchmark is deferred.
- **No new golden set.** The asus golden belongs to Stage 4.
- **The held tiering change stays held.** It is untouched here.
- **No audit runs.** Every deliverable reads an existing `audit.db`, changes
  code, or changes prose.

### Constraints taken as given

- `audit_core` is stdlib-only, no network, Python ≥ 3.10.
- `recall` keeps its present meaning; 9/19 and every citation of it stay valid.
- A measurement document is never edited in place; a correction is a new dated
  file.
- `tests/goldens/*/matches.json` and `rejections.json` are human adjudications
  and are never written by a tool.

## 3. The constraint that shapes everything

**The only `audit.db` in existence is pre-Stage-2.** Verified 2026-10-07
against `Devices/tplink/reports/audit-20260928-073457/audit.db`:

| Table | Rows |
|---|---|
| `cba_findings` | 45 — 6 CRITICAL, 26 HIGH, 12 MEDIUM, 1 LOW |
| `cba_attack_surface` | 197 |
| `cba_coverage` | **table does not exist** |
| `cba_inventory` | **table does not exist** |
| `cba_patterns` | **table does not exist** |
| `cba_pattern_hits` | **table does not exist** |

So **three of the four leading indicators have no data anywhere**, and
`bench`'s new coverage figure has nothing to read. Two consequences, both
binding on the plan:

1. Those three indicators are verified against **fixtures** in this stage.
   Their first real reading comes from a later run. This is instrumentation
   shipped ahead of its data, and the stage must say so rather than imply a
   measurement it did not take.
2. **Every new reader must degrade, not guess.** See §4.3.

Severity is the exception and is measurable today: the golden is 19 CRITICALs,
both sides draw from `db.SEVERITIES`, and re-scoring the stored database costs
nothing.

## 4. Design

### 4.1 `audit.py indicators`

Reads one run directory's database and emits the four figures §6.1 names.

| Indicator | Source | Shape |
|---|---|---|
| Coverage percentage | `cba_coverage` ÷ `cba_inventory`, per phase | analyzed, inventoried, percent |
| Surfaces opened | `cba_attack_surface` | count, and count by `group_id` |
| Sweep hit counts | `cba_pattern_hits` | total, and count by `pattern_id` |
| `not_audited` rows | `cba_coverage` where `state='not_audited'` | count, and count by reason |

Flags: `--db PATH`, `--json`, `--snapshot`, `--compare A B`.

*Corrected 2026-10-07:* this said `--db PATH (required)`. It is optional:
`--compare` needs no database. One of `--db` or `--compare` is required.

### 4.2 Snapshots and comparison

A bare indicator is not a signal. `coverage 72%` means nothing; `coverage 72%,
was 94%` means a regression.

`--snapshot` writes `docs/indicators/YYYY-MM-DD-<target>.json`. Tracked in git,
**never edited in place** — the `docs/baselines/` convention, for the same
reason: a superseded measurement that stays written is how a regression
remains visible in history.

`--compare A B` reads two snapshot files, prints each indicator's two values
and the delta, and names what moved. It **reports; it does not pass or fail.**
A threshold invented without data to calibrate it would be a number pulled from
nowhere, and the project has no second datapoint yet to calibrate against.

### 4.3 `absent` is not `0`

**The single most important rule in this stage.** A pre-Stage-2 database has
no `cba_coverage` table. Reporting `coverage 0%` claims total failure where
the truth is *no data was recorded*. One of those is a catastrophe and the
other is a database from before the feature existed, and a reader cannot tell
them apart from the number.

Every reader added here — in `indicators` and in `bench` — distinguishes three
states: a value, `absent` (the table does not exist), and `empty` (the table
exists and has no rows). `empty` is a real measurement and may legitimately be
`0`. `absent` never renders as a number, in human or JSON output.

This rule gets its own tests. It is exactly the class of defect that reads
correctly, ships, and misleads a reader months later — the same shape as the
unscoped coverage gate that reported PASS/100% on a run whose audited phase
never opened the only unit.

### 4.4 `bench` gains severity agreement

For each matched `(reference, finding)` pair, compare the reference's severity
to the finding's on the `db.SEVERITIES` ladder
(`CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL`).

Reported: agreement count; under-rated count; over-rated count; worst delta in
ladder steps; and the offending pairs by ID, so the figure is actionable rather
than merely alarming.

**Additive, by decision.** `recall` keeps its present definition — matched on
root cause and location — so 9/19 keeps its meaning and the ≥ 9/19 floor and
≥ 12/19 target stay written against the same quantity. A **severity-weighted
recall** is emitted *alongside*, never instead, crediting a match in full only
where severity agrees.

The alternative — making `recall` itself severity-aware — was considered and
rejected: it silently restates the floor and the target, and invalidates every
citation of 9/19 in two gate procedures and the parent spec's §5.3 table at
once.

The existing baseline is re-scored for free and the result **appended, dated**,
to `docs/baselines/`.

### 4.5 `bench` gains coverage

§6.1 defines `bench` as scoring recall, precision, **coverage (analyzed ÷
inventoried)** and cost per finding. It scores three of the four. Coverage is
added, reusing `audit_core.coverage`, and degrades per §4.3.

### 4.6 `audit.py rerate` — advisory, stores nothing

Reports findings whose recorded severity disagrees with what their own cited
evidence implies: a finding whose text names an authentication path, or
that is a member of a chain recorded in `cba_chains` as pre-auth, filed
below the severity that reachability implies.

*Corrected 2026-10-07:* this named three evidence classes, including "a
consumer branch". Only the authentication path and chain membership are
implemented; the module argues for deliberately few rules.

**It prints. It writes no row, and it changes no stored severity.** The
mutating version the Stage 0 finding implies remains available later, once a
benchmark run can validate it; this report is the evidence for whether it
would help, gathered at zero cost and zero risk.

**Why a separate verb rather than part of `bench`.** `rerate` needs **no
golden set** — it compares a finding against its own evidence. `bench`'s
severity agreement requires a reference set, which exists for exactly one
target. Folding them would make the check that works on *every real client
audit* reachable only on the one corpus that has a golden. They answer
different questions and have different prerequisites.

Precedent for the shape: `coverage --gate` reports and does not block.

### 4.7 The four parked defects

| Defect | Fix |
|---|---|
| `preflight --server NAME=COMMAND` flattens a `--keep`-copied server to `{"command": …}`, discarding `args` and `env` — the exact degradation `load_servers` exists to prevent. Reproduced 2026-10-07, exits 0. | `--server` **merges over** a kept definition rather than replacing it. Tested in both directions; neither direction is tested today. |
| `briefs.render` raises on missing placeholders and returns, so empty ones surface only on the next run. Reproduced 2026-10-07. | Report both classes in one pass. |
| `chain --compose --replace` and `identify --replace` blank optional columns when their flags are omitted. | `db.put` already merges; these callers are not using it. Make them. |
| `workflows/fpcheck.md` letters batches `A, B, C`; `references/phase5-fp-check.md` uses `B1`. | Unify on the workflow's form; the workflow is what the operator reads first. |

The prose change is subject to the anti-absence derivation rule: derive before
editing, reconcile against `git diff -U0` after.

## 5. Verification

No audit runs. Five layers:

1. **Fixtures** for the three indicators that have no real data, including a
   database with the tables absent and one with the tables present but empty —
   the `absent` / `empty` distinction of §4.3 is the point of the second.
2. **The real baseline database** for severity agreement, re-scored free. The
   expected result is known in advance: four under-rated matches, with REF-17
   the worst delta.
3. **`make all`** — the seven existing gates, including `manifest`, which will
   fail until `feature_lists.json` records the new verbs.
4. **A committed `indicators` snapshot** of the baseline database as the first
   datapoint, showing `absent` for three of four. It is the honest first
   reading, and it makes the §4.3 rule visible in a tracked artifact.
5. **Reproduction tests for the two defects reproduced on 2026-10-07**, written
   to fail against today's code first.

## 6. What this stage deliberately does not do

| Not done | Why | Where it goes |
|---|---|---|
| Mutate any finding's severity | Unmeasurable while the benchmark is deferred; it is a change to audit output | After a benchmark run, with `rerate`'s report as the evidence |
| Threshold or gate the indicators | No second datapoint exists to calibrate against; an invented threshold is a number from nowhere | Once snapshots accumulate |
| Build the asus or unifi goldens | Stage 4's gate owns them | Stage 4 |
| Apply the Sonnet tiering diff | Needs four audit runs | Held, `2026-10-05-stage3-tiering-gate.md` |
| Run any gate | Operator decision of 2026-10-07, on cost | Operator's call |
| Execute `install.ps1` | No PowerShell on this machine | Needs a Windows host |

## 7. Risks

| Risk | Mitigation |
|---|---|
| Instrumentation shipped ahead of its data is never read | The committed snapshot and the `manifest` gate make it visible; `progress.md` records that its first real reading is pending |
| `absent` renders as `0` somewhere and a reader concludes a catastrophe | §4.3 is a named rule with its own tests on both readers |
| Severity-weighted recall gets cited as "recall" and confuses the gate floor | Both figures are labelled in full in human and JSON output; the baseline append states which is which |
| `rerate` produces noise nobody acts on | It is advisory by design; if its output is not actionable on the one corpus available, that is itself the finding |
| The `bench` JSON shape changes and breaks a consumer | Additive keys only; no existing key changes meaning. The harness `bench` gate pins the existing figures and will fail if one moves |

## 8. Decisions taken

1. **The re-rating step reports rather than rewrites** — chosen over building
   the mutating step now, and over designing it and holding it. Holding adds a
   second parked spec-mandated change; building it ships an unmeasured change
   to audit output.
2. **Severity agreement is additive; `recall` is unchanged** — chosen over
   making `recall` severity-aware, which would restate the ≥ 9/19 floor and the
   ≥ 12/19 target without a run.
3. **Snapshots are tracked JSON under `docs/indicators/`** — chosen over a
   stateless report, which depends on somebody remembering the previous output,
   and over recording into the run's own `audit.db`, which lives under
   gitignored `reports/`.
4. **`rerate` is its own verb** — chosen over folding it into `bench`, because
   it needs no golden set and must work on every real client audit.

## 9. Open questions

None blocking. One to revisit after the first two snapshots exist: whether
`indicators --compare` should grow a failure threshold, and what calibrates it.
