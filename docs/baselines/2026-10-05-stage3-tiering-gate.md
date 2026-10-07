# Stage 3 tiering gate — Sonnet downgrade for feature mapping and FP-check

**Status: NOT RUN.** This is the only record of why a spec-mandated change
was not made. If this file is ever deleted on the theory that the two guard
tests it backs are stale, the next reader has no way to know that the tests'
rule is still true — read [§1](#1-what-is-held-and-why) first.

This file is the procedure, not a measurement. No baseline file is created by
writing it. When the gate is actually run, its two before-runs and two
after-runs are recorded in a new dated baseline document; this file is not
edited in place.

## 1. What is held, and why

Spec §7, Stage 3, last sentence:

> Then, last and alone, Sonnet tiering for `surface`, L-sink and `fpcheck` —
> the one tiering change that can cost quality, with precision measured
> before and after.

`surface` and L-sink are `firmware-audit` phase names (§4); this skill's
analogues, per §5.1's tiering table, are **feature mapping** (recon's mapping
subagents) and **`fpcheck`** itself. So the change this gate concerns is: drop
feature mapping and FP-check from the strongest model tier to the mid tier,
keeping their already-tiered-down effort levels unchanged.

The spec conditions this change on "precision measured before and after".
`audit_core/bench.py` could not score precision at all until Stage 3 Task 7.
Before that task landed, there was no instrument to take a before-measurement
with — the condition the spec sets could not be satisfied no matter when in
the stage this change shipped. Task 7 landed; nobody has yet run the two
tplink audits a before-measurement requires. **There is no before-number, so
the change is held rather than applied.** This is Ruling S1 from the Stage 3
plan, and its stated cost if the ruling is wrong: the tiering change itself
is two table rows and two workflow lines, re-doing it once the baseline
exists is under an hour; the reverse error — shipping the model downgrade on
the phase that decides which findings survive, with no precision number on
either side of it — is undetectable until a gate run weeks later, by which
time §6.1's merge rule ("no change merges if recall drops") has no evidence
to act on. Spec §8's own risk table reaches the same conclusion from the
other direction: "Sonnet on `fpcheck` raises the false-positive rate" is
mitigated by "[ships] last and alone, precision-gated; reverting is one table
row" — the mitigation *is* the gate this document specifies, and skipping the
gate to ship the change anyway would discard the mitigation along with the
measurement.

### The one precision figure this repository holds, and what it is not

Task 7 gave this project its first precision figure ever, scored against the
pinned pre-Stage-2 tplink run at
`~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db`
(verdict mix: TRUE_POSITIVE 39, FALSE_POSITIVE 1, DUPLICATE 5):

```
recall     9/19 (47.4%)
findings   45
precision  39/40 (97.5%)  [+5 dup, 0 undecided]
cost per matched finding  $73.15
```

That contrast is worth stating plainly: **97.5% precision against 47.4%
recall is exactly the shape of a pipeline that kept almost everything it
proposed while missing more than half of what was there.** A FALSE_POSITIVE
rate this low says the FP-check on this run was not rejecting much — which is
either genuinely clean work, or a FP-check that is too lenient to be a useful
filter. Nothing in a single number distinguishes those two readings. That is
why `audit_core/bench.Precision`'s own docstring is explicit that the figure
"is only meaningful comparatively: same golden, same pipeline, one variable
changed" — precision read in isolation is not a quality score, and must never
be reported as one.

This figure is **not** this gate's before-measurement. It predates Stage 2
entirely, so it was not scored against the strongest-tier configuration this
gate needs to compare against — it was scored against whatever pipeline
produced that pinned run, before Stage 2's structural changes and before any
of Stage 3's five mechanisms existed. The before-measurement this gate
requires has to come from two runs **on the current configuration**, with the
mechanisms from Stage 3 Tasks 1-6 active and the model still at the strongest
tier for feature mapping and `fpcheck`. No such run has happened. Until one
has, there is no number this gate can compare an after-measurement against,
and the tiering change stays held regardless of how the pre-Stage-2 figure
above reads.

## 2. The procedure

Four full tplink audit runs, in this order:

1. **Precision-before, run 1 and run 2.** Two full tplink audits on the
   current (strongest-tier) configuration — i.e. with every one of Stage 3's
   five mechanisms active and `SKILL.md` / `workflows/recon.md` /
   `workflows/fpcheck.md` unchanged from what this commit ships. Score each
   with `audit.py bench --golden tests/goldens/tplink-dl110v2-1.0.11 --db
   <db> --cost <cost>` and record `recall`, `precision` and
   `cost per matched finding` for both.
2. **Apply the diff.** The exact change is in [§3](#3-the-exact-diff-to-apply)
   below, applied verbatim across the five files it names.
3. **Precision-after, run 1 and run 2.** Two more full tplink audits, same
   golden, same procedure, with the diff applied and nothing else changed
   between the before and after pairs.
4. **Compare.** Four numbers in, both runs of each pair reported — never the
   better run of a pair standing in for both, per §6.1's non-determinism
   clause, which this gate inherits from the Stage 2 and Stage 3 gates.

### The noise allowance, for precision

§6.1 allows a one-finding recall delta between two runs of a pair to be
treated as noise. Recall's denominator is the fixed 19-item reference set, so
"one finding" is a fixed ~5.3 points on that scale. Precision's denominator is
not fixed — it is however many verdicts a given run actually decided — so no
single-point allowance carries across runs the way it does for recall.

**There is no measured threshold for precision noise; stating one here would
be inventing a number this project has not taken.** What can be stated is the
scale: the one pinned figure this repository holds decided 40 verdicts out of
45 findings, and one verdict moving from TRUE_POSITIVE to FALSE_POSITIVE (or
back) at that denominator moves precision by about 2.5 points (1/40). A
tplink run of comparable size will have a comparable denominator, so **a
one-verdict move is the rough equivalent of recall's one-finding allowance,
at roughly 2 points per verdict** — but this is a judgment call for whoever
reads the four-run comparison, not a measured floor the way 9/19 is for
recall. Treat a one-verdict precision delta between two runs of the same
pair as plausible noise; treat a multi-verdict delta, or a precision drop
that survives averaging across the pair, as a real signal that the gate
should act on.

## 3. The exact diff to apply

Verbatim, so that applying it once the gate has run is transcription, not
redesign:

| File | From | To |
|---|---|---|
| `SKILL.md` → *Model and effort tiering* table | `\| Feature mapping, FP-check batches \| strongest tier, effort tiered down \| low to medium \|` | `\| Feature mapping, FP-check batches \| mid tier \| low to medium \|` |
| `SKILL.md` → *Model and effort tiering*, the paragraph beginning **"Feature mapping and FP-check keep the strongest model"** | the whole paragraph (*"Feature mapping and FP-check keep the strongest model and tier only their effort. Both decide what gets looked at and what survives, so a model downgrade there can cost recall and precision. That change is not free and is not Stage 1's to make: it waits until precision is measured before and after."*) | a replacement paragraph stating the measured precision before and after (both pair averages, both individual runs) and the date the gate was run |
| `SKILL.md` → *Subagent Configuration* table, row `recon (mapping)` | `strongest tier, low effort` | `mid tier, low effort` |
| `SKILL.md` → *Subagent Configuration* table, row `fpcheck` | `strongest tier, medium effort` | `mid tier, medium effort` |
| `workflows/recon.md` → Step 5 **Model:** line | `strongest tier, low effort` | `mid tier, low effort` |
| `workflows/fpcheck.md` → Step 4 **Model:** line | `strongest tier, medium effort` | `mid tier, medium effort` |
| `tests/test_workflow_prose.py` | `test_mapping_and_fpcheck_keep_the_strongest_model` and `test_skill_md_subagent_table_keeps_the_strongest_model_for_both` (the two tests re-aimed in Stage 3 Task 9) | inverted to assert `mid tier` is present and `strongest tier` is absent on those lines, with the gate's run date in each docstring |

`workflows/audit.md`'s deep-audit **Model:** line (`strongest tier, high
effort`) is **not** in this table, and applying this diff must not touch it.
Spec §5.1 keeps deep audit, chain composition and final severity calls on the
strongest tier **permanently**, not provisionally — the spec's own wording,
"Sonnet tiering for `surface`, L-sink and `fpcheck`", names the
`firmware-audit` phases whose `codebase-audit` analogues are feature mapping
and FP-check, not deep audit. A later reader applying this diff from memory
rather than from this table could plausibly "complete the pattern" by
tiering audit.md down too; that would be a different, larger change the spec
does not ask for and this gate does not measure.

## 4. What reverting costs

**One commit.** If this diff is applied and the after-measurement shows
precision or recall falling, the fix is to revert the single commit that
applied it — the diff above touches five files but is one unit of work,
landed as one commit, exactly as spec §8's risk table states for this exact
risk: "Sonnet on `fpcheck` raises the false-positive rate" is mitigated by
"[ships] last and alone, precision-gated; reverting is one table row." That
cheapness is also why this change is safe to hold rather than force through
on a stale justification: there is no sunk cost in applying it now that a
later, measured application would lose.
