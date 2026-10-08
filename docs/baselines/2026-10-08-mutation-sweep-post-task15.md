# Mutation sweep — audit_core, post-Task-15, 2026-10-08

**This is a second measurement, not a correction.** The first sweep is
[`2026-10-08-mutation-sweep.md`](2026-10-08-mutation-sweep.md) and is frozen
under `SESSION_HANDOFF.md` rule 4. Nothing in it is edited by this file.

**Measured against:** `stage3c/core-hardening` at `33897b2`, 807 tests.
**Instrument:** `scripts/mutate.py` via `make mutate`, 8 workers.
**Runtime:** ~70 minutes wall, run concurrently with other work — the first
sweep's 54 minutes on an idle machine is the honest figure for planning.
**Canary:** did not trip. Mutants provably reached the tests.

## Why this run exists

The first sweep measured the suite as it stood after Tasks 4-10 closed the 115
unexecuted statements. Task 15 then fixed the 32 unallowlisted **logic**
survivors it had found. This run measures the result rather than projecting it.

## Result

| | mutants | killed | survived | timeout | error |
|---|---|---|---|---|---|
| first sweep | 1068 | 708 | 360 | 0 | 0 |
| **post-Task-15** | **1068** | **761** | **307** | **0** | **0** |

**Mutation score: 71.3%** (761/1068), from 66.3%. **+53 killed.**

Zero timeouts and zero errors in both runs. Under the strict classification
added in Task 12 — `killed` means pytest rc 1 and nothing else — no crash,
signal or internal error was miscredited as a kill in either number.

## By kind, which is where the result actually lives

| kind | first sweep | post-Task-15 |
|---|---|---|
| logic: not-removal | 89/89 (100.0%) | **89/89 (100.0%)** |
| logic: compare + boolop | 225/258 (87.2%) | **257/258 (99.6%)** |
| constant: numeric/bool | 160/216 (74.1%) | 166/216 (76.9%) |
| constant: prose string | 234/505 (46.3%) | 249/505 (49.3%) |
| **all logic** | **314/347 (90.5%)** | **346/347 (99.7%)** |
| overall | 708/1068 (66.3%) | 761/1068 (71.3%) |

**Every killable logic mutant in `audit_core` is now dead.** The single
remaining logic survivor is `bench.py:119:11 compare[0] Gt->GtE`, which is
allowlisted with a proof: `steps = f_rank - r_rank` at line 117 is followed
immediately by `if steps == 0: agreed += 1; continue`, so at the comparison
`steps` is never 0 and `>` and `>=` select the same set. That proof was
verified independently during review.

**Task 15 targeted 32 mutants and 53 died.** The other 21 fell to the new
tests incidentally. That is the signature of tests that assert behaviour
rather than chase a target list — a test written only to kill its own mutant
kills exactly one.

## What remains, and why it is not being chased

307 survivors, of which **306 are constants and 249 of those are prose
strings** — unasserted message text. That is a real gap in places and a
defensible choice in others: not every error string should be pinned, and
pinning all of them makes rewording a message a test failure.

The `mutate` gate is **left failing** on these. It is opt-in, in neither
`DEFAULT` nor `ALL_EXTRA`, so a failing gate costs nobody a broken build and
states the true position. Allowlisting 306 survivors to turn it green would
be the self-flattery this stage was built to stop.

## What a future sweep compares against

Use **71.3% overall and 99.7% all-logic** as the figures to beat, and watch
the per-kind table rather than the aggregate — the aggregate is dominated by
how many prose strings exist, which changes whenever messages are added.

A drop in **all-logic** is the signal that matters. It means a branch's
behaviour has stopped being pinned, which is the defect class line coverage
cannot see and the one this instrument exists for.

Regenerate with `make mutate`. The sweep is resumable and discards its state
whenever `audit_core` or the tests change, so a figure here is only
comparable against the commit named above.

## Caveats, carried forward from the first sweep

- `test_the_eol_manifest_matches_the_tree` fails on the sweep's temp copy
  (no `.git`), so it is deselected. Mutants only that test would catch count
  as survivors.
- Attribute docstrings are not filtered by the operators; 7 are allowlisted
  as unkillable.
- 3 survivors sit on parameter defaults in multi-line `def`s, which the
  statement-line test map does not track.
