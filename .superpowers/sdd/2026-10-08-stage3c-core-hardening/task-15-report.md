# Task 15 report: the 32 unallowlisted logic survivors

Status: DONE for the 32-mutant scope. 32 killed, 0 allowlisted, 0 outstanding.
Real defects found: none (no mutated behaviour was correct; every original is right).
Only tests changed. `audit_core` is untouched. `make all`: 8/8 PASS (807 tests).

## qualify.py:179 (the failure of this stage's own work)
`if score.rce_cves < 1:` - Task 4's test used `rce_cves=0`, where `< 1` and
`<= 1` agree, so it pinned the verdict text but not the boundary. Added
`test_exactly_one_rce_cve_is_enough_for_proven_bad` (rce_cves=1 must PASS).
Before: mutant `survived` (same harness, pre-fix tests). After: `killed`.

## Method
`mutate.run_sweep` discards the whole state file whenever any test changes
(verdict key), so narrowing the state file cannot work after editing tests.
Instead a scratch harness (scratchpad/verify.py, not committed) reuses
mutate.enumerate_mutations / apply_mutation / _baseline_failures / _run_suite
/ _classify on a temp copy of the repo, applies ONE labelled mutant, and runs
the WHOLE suite (minus test_mutate.py, known baseline failure deselected).
Sanity: qualify:179 reported `survived` before the fix, `killed` after.
No full sweep re-run; overall mutation score not recomputed.

## Per-mutant verdicts (all: weak/missing test, strengthened/added; all re-run = killed)
qualify.py (tests/test_qualify.py)
- 116:60 compare[0] and compare[1] (0<=max_cvss<=10): missing test; CVSS 0 and 10 kept, 10.01 and -0.01 dropped. killed, killed
- 179:7 Lt->LtE: weak test, see above. killed
- 185:24, 185:58 Or->And (missing date / reason text): missing test; each date missing alone, exact reason text. killed, killed
- 187:15, 187:49 (window edges): missing test; span touching WINDOW_END / WINDOW_START passes, one day outside fails. killed, killed
- 211:11 Or->And (top_source or 'unknown'): missing test; exact reason both ways. killed
- 321:7 Is->IsNot (render of missing score): missing test; exact "(not in the scored target set)" line present/absent. killed
- 350:7 In->NotIn (footer for `supported`): missing test. killed
- 90:38 Or->And ('(no header)'): missing test; empty file vs wrong header. killed
db.py (tests/test_db.py)
- 157:7 Lt->LtE: evidence of exactly MIN_EVIDENCE_CHARS accepted, 19 refused. killed
- 419:15 And->Or: stored NULL must not be bound over a column DEFAULT on replace (cba_findings.verified). killed
- 570:32 GtE->Gt: confidence tie keeps the earlier id. killed
pivot.py (tests/test_pivot.py)
- 62:25, 63:20, 77:8: severity_hint, location, rule_applied were never read back; now asserted, plus blank rule stays NULL. killed x3
ceiling.py (tests/test_ceiling.py)
- 92:11: epoch of exactly min_turns judged. killed
- 92:34: mean == 0 skipped (mutant raises ZeroDivisionError); Report stubbed with SimpleNamespace(epochs=...). killed
extract.py (tests/test_extract.py)
- 141:20: content of exactly MAX_UNIT_BYTES kept whole. killed
- 222:63: pre-check sees this unit's names only: earlier-run claim refuses the whole batch with nothing written; other unit's same flattened name from a different source is fine. killed
patterns.py (tests/test_patterns.py)
- 52:42, 53:40: name / origin_finding never asserted. (name is NOT NULL in schema, so its NULL branch is unreachable; the test pins the set value.) killed x2
sweep.py (tests/test_sweep.py)
- 94:19: file of exactly MAX_FILE_BYTES scanned (existing test sat at +1, which >= also skips). killed
- 171:20: headline names the pattern or "(unrecorded)". killed
transcript.py (tests/test_transcript.py)
- 139:21: session id = first non-empty one in the file. killed
- 167:30: thinking_tokens read through; absent details -> 0. killed
annotations.py:119:11 (tests/test_annotations.py): summary of exactly SUMMARY_CHARS not truncated. killed
chains.py:162:15 (tests/test_chains.py): the existing same-group test shared ONE token, under MIN_SHARED_TOKENS, so it passed with or without the group rule (a degenerate pass of exactly the kind the file's own docstring warns about). New test shares 3 tokens. killed
coverage.py:258:15 (tests/test_coverage.py): gate failure text names phase / `<phase>`. killed
indicators.py:232:11 (tests/test_indicators.py): one absent side is not comparable even if the absent entry carries a stray value. Note: with the data shapes the code itself writes (absent => no value) this mutant is NOT equivalent only for hand-edited or foreign snapshots; I pinned the stated contract ("absent is never compared") rather than allowlist it. killed
rerate.py:107:17 (tests/test_rerate.py): no ellipsis when the window ends exactly at end of text. killed

## Commit
See return message (SHA captured with `git rev-parse --short HEAD`).

## Fix round 1 (coordinator review)

1. patterns.py:52:42 - NOT allowlisted, and the proof offered does not hold.
   The dead part is the `""` FALLBACK (name is NOT NULL, schema.sql:80). The
   mutant `x and ""` changes the LIVE path: for every truthy name it returns
   "". So the mutant is observable and killable (it was killed). Allowlisting
   it with "dead code" as the proof would be a false proof. Kept the
   name assertion (a behaviour: the state reports the registered name);
   dropped only the unreachable NULL-name half. The origin_finding half is
   kept as asked. Open item for a later stage: `r["name"] or ""` could be
   `r["name"]` (fallback unreachable). NOT changed here.
2. indicators.py:232 - chose to KEEP the test, docstring now says it guards
   foreign / hand-edited snapshots, not this module's own output. Dropped the
   third assertion (absent 5 vs present 7), which passed under mutant too.
3. ceiling.py:92:34 - docstring now states the Epoch(mean=0) case is a
   defensive guard, hand-built, not an observed case.
4. Evidence. Committed: task-15-verify.py (harness), task-15-verify-run1.log
   (full output of the original 32 re-runs), task-15-verify-round1.log
   (re-runs after this round: patterns 52, patterns 53, indicators 232,
   ceiling 92:34, qualify 179 - all killed).
   What was actually observed: AFTER-fix "killed" for all 32. BEFORE-fix, I
   observed `survived` myself for qualify:179 only (same harness). For the
   other 31 the before-state is the first sweep's recorded `survived`
   (docs/baselines/2026-10-08-mutation-sweep.md; .mutate-state.json), not a
   before-run I took.
   The harness runs from the repo root: `python3 task-15-verify.py "<label>"...`
   or `@file` of labels; it needs scripts/mutate.py.
