# Stage 4c semantic diff brief derivation

Source: Stage 4c firmware diff design §9 and implementation-plan Task 7.
Written before the tests and shipped brief as the anti-absence checklist.

The shipped brief must preserve every input, instruction, and boundary in §9:

1. Name the run directory and diff ID, with the existing `{run_dir}/audit.db` as the structured output destination.
2. Name both carved roots separately: the target is the patched/current build; the reference is the vulnerable build.
3. Name the file-backed manifest path and read comparison entries from that file. Keep raw diff contents out of the dispatch and return; the manifest stays file-backed.
4. Name the detailed artifact path as the destination for analysis.
5. Carry the orchestrator-supplied known CVE/advisory and patched component without inventing either.
6. Start from the known patched component. File churn elsewhere is not a vulnerability signal.
7. Establish the actual before/after mechanism with evidence from both builds, citing exact locations and explaining how the change addresses the advisory.
8. Distinguish a security fix from compiler, packaging, timestamp, stripping, and configuration noise. Record uncertainty rather than interpreting unexplained churn as a fix.
9. Record the fix idiom as an evidence-backed `cba_security_observations` row under a diff-specific group ID derived from the supplied diff ID.
10. Search the target, not the vulnerable reference, for sibling sites that still match the unsafe side of the idiom.
11. Register an idiom in `cba_patterns` only when it has an honest mechanical expression, and use `audit.py sweep --record` on the target root only in that case.
12. Do not force a semantic condition into a misleading regex. Record a non-mechanical sibling analysis instead when a regex cannot honestly express the condition.
13. Record non-mechanical sibling analysis and each surviving lead as bounded observations, with exact locations and evidence, under the same diff-specific group ID.
14. Write the detailed analysis to the supplied artifact path. Keep it bounded to the mechanism, noise discrimination, sibling search, evidence, and unresolved limitations rather than dumping every changed file or raw diff.
15. Return exactly one line and nothing else: `diff <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`. The artifact slot is the supplied artifact path; rows counts the observations actually recorded, and flags communicate unresolved limitations.
16. Do not turn every changed component/file into a finding.
17. Do not begin broad hunting, map handler tables, or emulate firmware.
18. Do not modify either carved tree.

Reconciliation procedure: after creating the brief, inspect
`git diff -U0 -- references/briefs/diff-brief.md` against all 18 items above.
Add any missing instruction to the brief rather than weakening its test.
