# Stage 4i review fixes: decide brief and routing derivation

The Stage 4i review found that the firmware decision brief pointed the worker
at the installed parser but stated none of its exact result contract, so a
worker reconstructing the schema from memory could produce an unimportable
result. It also found the SKILL.md decide route thinner than the Stage 4g route
it mirrors: it never said where the worklist path comes from, who assigns the
result path, or that the worklist is read incrementally. The review fixes also
change result rules a worker must follow (casefold-unique script names, bench
tests covering a subset of a shared subject's owners) and the preparation
lifecycle (`superseded`, latest preparation is current).

Intended changes, written before editing:

`references/briefs/firmware-decide-brief.md`

1. Read the worklist incrementally from the exact path; never inline,
   partition, or cap the chain or precondition denominator.
2. Add the exact result JSON schema matching `firmware_decide_results._parse`:
   top-level keys, `decision_generation == worklist_sha256`, the two `answer`
   variants (`empty` only for a zero-chain graph), every chain assessment
   field with type and sort/uniqueness rule, copied-fact equality with the
   frozen graph, contiguous ranks, the per-chain open-precondition
   denominator, the disposition enum, and admitted evidence references.
3. Add the exact bench test contract: fields and types,
   `test_id = "firmware-decide-test-" + sha256(canonical JSON of the test
   without test_id)`, subject wires (`blocker:`/`unknown:` precondition IDs and
   `transition:<chain_id>:<edge_ordinal>`), `required_state.device == image_id`,
   `required_state.firmware == candidate_snapshot_sha256`, required state
   matching the listed chains' frozen state at each subject, and the
   subset-of-owners rule for shared preconditions.
4. Add proposed-script rules: safe basename pattern, unique under casefold,
   32 KiB each, 256 KiB total, at most 16, each referenced by a bench test.
5. State that a superseded or replaced generation is never resumed; on a
   changed generation return FAILED and let the orchestrator prepare again.

`SKILL.md` Stage 4i route

6. Take IMAGE_ID, DECISION_GENERATION and WORKLIST_PATH
   (`${AUDIT_DIR}/<worklist_path>`) from the prepare JSON; the orchestrator
   assigns RESULT_PATH to the worker's writable result file.
7. Dispatch only the rendered brief path plus context the template cannot
   know; do not inline the worklist; the worker reads incrementally.
8. Keep the prepare → brief → record → check order, and state that the latest
   preparation is current, changed technical input supersedes an active
   generation, and an identical re-prepare makes its generation current again.

Tests: `tests/test_firmware_decide_brief.py` pins the schema clauses above and
the SKILL.md command order; `tests/test_brief_templates.py` keeps rendering the
template with exactly five variables.

## Reconciliation

Checked against `git diff -U0 SKILL.md references/briefs/firmware-decide-brief.md`
after the edits. The brief hunks cover items 1-5: incremental reading and the
changed-generation FAILED rule under "Assignment and authority"; new "Chain
assessments", "Bench tests", and "Proposed scripts" sections restating the
parser; the former authority paragraphs moved unchanged under "Limits of
authority". The SKILL.md hunks are exactly items 6-8 in the Stage 4i route:
prepare-output paths and RESULT_PATH assignment, no-inline dispatch with
incremental reading, the return line, and the lifecycle paragraph after the
authority paragraph. The command sequence is unchanged. Nothing outside the
change list was edited. `tests/test_firmware_decide_brief.py` derives field
sets from the parser dataclasses and reproduces `test_id` with the parser's own
identity function, so later parser drift fails the brief tests.
