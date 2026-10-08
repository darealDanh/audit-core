# Stage 3c — core hardening

**Status:** design approved 2026-10-08, not yet planned.
**Derives from:** [`2026-10-04-audit-suite-design.md`](2026-10-04-audit-suite-design.md)
§6.2 (machinery that must survive the refactor) and §6.1 (deterministic
leading indicators between benchmark runs); and the project's own record of
two named test defects, in `SESSION_HANDOFF.md` §6 and the `open_items` entry
`qualify-negative-rce-branch-untested`.

Numbered `3c` because it belongs with Stages 3 and 3b — the `codebase-audit`
improvement arc — and precedes Stage 4's firmware work. Stage 4b
(`acquire`/`triage`) is designed and shelved; its spec is
[`2026-10-08-stage4b-acquire-triage-design.md`](2026-10-08-stage4b-acquire-triage-design.md).

---

## 1. Why this, and why now

The three high-severity open items all require a benchmark run the operator
has deferred on cost (`SESSION_HANDOFF.md` §3). Nothing in this stage needs
one. It is the hardening that is available at zero audit cost, and it hardens
the thing every deferred measurement will eventually rest on.

The case is not a hunch. Measured on 2026-10-08 against `main` at `10ec9bd`,
with a throwaway `sys.monitoring` probe over the 621-test suite:

**`audit_core` has 115 statements that no test executes** — **94.9% statement
coverage of 2,249 executable statements**, counting both sides the same way.
The raw probe reported 171 missed of 2,474; discarding multi-line
function-signature continuation lines with `ast` brings that to 115 of 2,249.
Filtering only the numerator would have given a flattering 95.4%, which is the
kind of number this stage exists to stop the project telling itself — the gate
it ships applies the filter to both sides.

They are not evenly spread. Five categories, in descending order of how much
they should worry a reader:

**Fixes that were committed and never run.** `qualify.py:72-73` and `133-134`
are the `UnicodeDecodeError`/`csv.Error` handlers added by `c4d9021`
("truncated rows, NaN/Inf, ranges, **encoding**"). `qualify.py:256-262` and
`344-347` are the NO-GO messages rewritten by `65f6c07` ("qualify
support-evidence message and NO-GO footer name the real cause").
`goldens.py`'s loader validations are from `f423efa`. Each was written as a
fix, reviewed, merged — and no test has ever entered it. A fix nothing
exercises is a claim, not a fix.

**A GO/NO-GO verdict branch.** `qualify.py:180`, `"no RCE CVEs on record"`,
decides whether a target is worth a week of work.

**Contract enforcement.** `db.py:466` (`has no column(s)` — the error that
makes `put` a contract rather than an INSERT), `db.py:337-339` (`not a
readable SQLite database`), and all three `coverage.py` guards: missing
phase, illegal state, past the per-call unit bound.

**A safety mechanism.** `indicators.py:180-192` is the `open(path, "x")`
exclusive create and its refusal, *"Measurements are never edited in place"*.
That is `SESSION_HANDOFF.md` rule 4 enforced in code, and nothing tests that
it holds.

**Operator-facing renderers.** `identity.render` in full, the coverage gate
renderer, `db.status`'s group and verdict blocks, the indicators comparison
table. This project has shipped wrong operator-facing prose twice
(`SESSION_HANDOFF.md` §6).

## 2. Two defect classes, two detectors

The project's record names two distinct test defects, and they need different
instruments.

**Class A — the branch no test enters.** The `qualify` row whose `rce_cves`
value used a Unicode minus, so `int()` rejected it before the `rce_cves < 0`
branch could run. Line coverage finds this class; all 115 statements above are
instances of it.

**Class B — the branch a test enters while asserting too little.** Recorded as
*"the Task 2 test that substituted an easier input for the one its finding
named."* Line coverage is blind to it: the line runs, the test passes, and the
assertion would survive the code being wrong. Only mutation finds this class.

This stage ships a detector for each, and the Class B detector is also what
checks the work done for Class A — see §5.

## 3. Goals and non-goals

### Goals

1. Resolve all 115 unexecuted statements — by a real test, a deletion, or an
   allowlist entry carrying a reason.
2. Ship a coverage gate that makes the condition non-recurring.
3. Sweep all 647 mutable nodes in `audit_core` for Class B defects, and fix
   what it finds in the tests and, where a survivor exposes one, in the code.
4. Leave both gates' baselines checked in, reasoned, and self-invalidating
   when stale.

### Non-goals

- **No change to what an audit records or costs.** This stage cannot move
  recall or precision, by construction, and claims neither.
- No benchmark run. `stage2-gate-not-run`, `stage3-gate-not-run` and
  `no-precision-baseline` stay open.
- No firmware work. Stage 4b stays shelved.
- No shipped-prose edits. This is tests and tooling, so rule 6's derivation
  requirement does not bind — a genuine reduction in this stage's risk, stated
  rather than assumed.
- `install.ps1` stays unexecuted. There is still no `pwsh` on this machine, so
  `install-ps1-never-executed` cannot close here.

### Constraints taken as given

- `audit_core` stays stdlib-only. Both instruments are stdlib: `sys.monitoring`
  (3.12+) and `ast`. Neither lives in `audit_core`; both are dev tooling under
  `scripts/`.
- `pyproject.toml` declares `requires-python = ">=3.10"` and CI runs a 3.10 /
  3.12 / 3.13 matrix. `sys.monitoring` does not exist on 3.10, so the coverage
  gate must SKIP cleanly below 3.12 rather than fail. See §8.
- `main` is 124 commits ahead of an unreachable origin and has never been
  pushed. **CI has therefore never run.** Any cost added to CI is a debt that
  comes due the day origin returns, not a cost paid today.

## 4. The coverage gate

`scripts/coverage_probe.py` runs the suite under a `sys.monitoring` LINE
callback, records which `audit_core` lines executed, and uses `ast` to discard
function-signature continuation lines before reporting.

### Why an allowlist, not a percentage

A percentage floor lets a new untested refusal path hide behind new tested code
elsewhere, which is exactly how 115 statements accumulated while every stage
reported its tests passing. Instead, `scripts/coverage-allowlist.txt` names
every statement permitted to go unexecuted, **with a reason**, in the style of
`scripts/eol-manifest.txt`.

The gate fails in **both** directions:

- an unexecuted statement that is not on the list — the regression case;
- a listed statement that is now executed — so the file cannot rot into a
  stale blanket permission.

This is the discipline the codebase already enforces on itself. `cba_coverage`
refuses a `not_audited` row without a reason from a fixed list, because a gap
recorded without a reason makes the denominator look accounted for. The
allowlist applies that rule to the test suite.

When this stage closes, the list should hold only genuinely unreachable
defensive code, each entry arguing for itself.

### Registration

`gate_coverage` in `scripts/harness.py`'s `GATES`, added to `DEFAULT`. `make
all` goes 7 gates to 8. Cost is one extra suite run, ~28s.

## 5. The mutation harness

`scripts/mutate.py`. A tool and an opt-in gate, never part of `make check`.

It copies the tree to a temporary directory — **it never writes into
`audit_core`** — applies one AST mutation at a time, and runs only the tests
that exercise the mutated module. Operators: comparison flips (`<`↔`<=`, `==`↔
`!=`, `>`↔`>=`), `and`↔`or`, `not` insertion and removal on branch tests,
integer and string constant perturbation, and `True`/`False` return swaps.

A **surviving** mutant is the finding: the code changed and every test still
passed, so no assertion depends on that line being right.

### Which tests run for a mutant

By naming convention: `tests/test_<module>.py`. That file exists for 22 of the
23 modules — verified, not assumed. `budget` is the sole exception, exercised
by `test_budget_epochs.py`, `test_budget_attribution.py` and
`test_cli_budget.py` among others.

So the rule is: run `tests/test_<module>.py` when it exists, plus any test file
whose name starts `test_<module>`; fall back to the whole suite when neither
matches. A fallback costs ~28s per mutant instead of ~1s, so the harness
reports which modules took the fallback — a module that silently falls back
turns a 20-minute sweep into a 5-hour one, and the operator should see that
coming rather than discover it.

A narrowed test selection also risks a *false* survivor: a mutant killed only
by a test file the selection skipped is reported as surviving. The harness
therefore re-runs the full suite against each surviving mutant before
reporting it. Survivors are rare, so this costs little, and it means a reported
survivor is a real one.

### Measured cost

647 mutable nodes across `audit_core`; a targeted test file runs in ~1.0s wall
(`test_qualify.py` 39 tests / 0.71s, `test_db.py` 22 / 0.81s,
`test_coverage.py` 27 / 0.85s). The sweep proper is therefore roughly **11-20
minutes**, depending on how many test files a module needs and the timeout
margin for mutants that hang.

The full-suite confirmation re-run for each survivor (below) adds ~28s per
survivor on top. That term is unknown until the first run — it is what the
sweep exists to discover — so the honest statement of total cost is **20
minutes plus 28s per surviving mutant**, and if survivors turn out to be
numerous the first run will be long precisely because the problem is large.

An earlier estimate in conversation said two hours. That was a guess stated as
a measurement; it was wrong by an order of magnitude, and it changed a design
choice — at 20 minutes this is a gate you can actually run, not a tool you run
twice a year. It is recorded here because this project's standing rule is that
load-bearing claims get verified against the tree.

The run must be **resumable**. A 20-minute run that dies at minute 18 and
restarts from zero will never be run a second time.

### Registration

`gate_mutate`, reachable by `--only mutate` and a `make mutate` target, and
excluded from both `DEFAULT` **and** `--all`. `bench` is in `--all` only
because it SKIPs on a runner; a mutation gate would not skip, and `ci.yml` runs
`--all` across three Python versions, so inclusion would mean 60 minutes of CI
per push.

`scripts/mutation-allowlist.txt` records permitted survivors with a reason
each. Equivalent mutants are real — a constant change with no observable effect
is unkillable by any test — and mistaking one for a test defect wastes effort
and erodes trust in the report.

## 6. The ordering trap

A test written to touch `qualify.py:180` is itself a Class B defect — the thing
this stage exists to remove. The rule is therefore explicit: **every new test
asserts observable behaviour** — the message text, the exit code, the refusal,
the row that was or was not written — never merely that a line ran.

The mutation sweep is the check on that claim, which is why it runs **after**
the new tests are written rather than before. A test added to close a coverage
gap that fails to kill its mutants gets rewritten.

## 7. Three legitimate outcomes per gap

`qualify.py:72-73` catches `csv.Error`. If no input can reach it, the handler
is dead code and the honest resolution is to delete it, not to contort a test
into reaching it.

Each of the 115 resolves one of three ways:

| Outcome | When |
|---|---|
| A test asserting observable behaviour | the statement is reachable and matters |
| Deletion | nothing can reach it; it was defensive cargo |
| An allowlist entry with a reason | reachable only in conditions a test cannot create, and the reason says which |

What is not permitted is a test that exists to move the number.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Tests written to move the number | The central risk, and the reason §6 fixes the ordering. A test that touches a line without asserting its behaviour does not kill that line's mutants, and the sweep reports it |
| The harness mutates the real tree | It copies to a temp directory and never writes into `audit_core`. Rule 1's history with the installer, and 124 unpushed commits behind an unreachable origin, make an in-place source rewriter the wrong thing to be casual about |
| An equivalent mutant is misread as a weak test | `scripts/mutation-allowlist.txt`, with a reason per entry |
| `sys.monitoring` is 3.12+, and 3.10 is the declared floor | `gate_coverage` SKIPs below 3.12 with the reason printed, the way `bench` SKIPs without its corpus. A skip is reported, not swallowed. The gate is therefore advisory on the floor version and binding on the operator's 3.14 and on CI's 3.12 and 3.13 |
| The gate makes future stages slower to land | Intended, not incidental. Recorded here so nobody later removes it as friction |
| A 20-minute gate reaches CI by accident | Excluded from `--all` deliberately, with the reason in §5, because `--all` is what `ci.yml` runs |

## 9. Verification

- `make all` green at 8/8.
- `scripts/coverage-allowlist.txt` and `scripts/mutation-allowlist.txt` checked
  in, a reason on every entry, no stale entries — both gates enforce this in
  both directions.
- The sweep recorded as `docs/baselines/2026-10-08-mutation-sweep.md`. It is a
  measurement, so rule 4 binds: never edited in place.
- `feature_lists.json` gains the probe, the harness and both gates, with their
  `tests`, `modules` and `docs`, or `manifest` fails.
- The probe and the harness are themselves tested. An instrument that reports
  "0 gaps" because it is broken is worse than no instrument, so each gets
  fixtures with known-unexecuted lines and known-surviving mutants.

The closing number is not "115 resolved". It is **zero unexplained unexecuted
statements and zero unexplained surviving mutants** — every remaining one
carrying a written reason.

## 10. Decisions taken

1. **An allowlist, not a coverage percentage** — a percentage is how 115
   statements accumulated invisibly.
2. **Both allowlists fail in both directions** — a baseline that cannot go
   stale is the only kind worth checking in.
3. **The mutation sweep runs after the new tests, not before** — it is the
   quality check on them, and running it first would forfeit that.
4. **`mutate` is excluded from `--all`, not merely from `DEFAULT`** — `--all`
   is what CI runs, across three Python versions.
5. **Deletion is a legitimate outcome** — unreachable defensive code should go,
   not acquire a ceremonial test.
6. **The instruments are tested too** — a silent instrument is worse than none.

## 11. Open questions

None blocking.

- Whether `gate_coverage` should eventually extend past `audit_core` to
  `audit.py` itself (50,577 bytes, dispatch and argument parsing). Left out
  here to keep the stage scoped; the probe does not care which package it
  watches, so it is a one-line change when wanted.
- Whether the mutation baseline is re-measured every stage or only when
  `audit_core` changes shape. Deferred until there is a second measurement to
  compare against.
