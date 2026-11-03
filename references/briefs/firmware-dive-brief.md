# Firmware dive question

Audit run directory: {run_dir}
Carved target root (read only): {rootfs}
Target image ID: {image_id}
Dive generation: {dive_generation}
Question ID: {question_id}
Immutable question packet: {packet_path}
Frozen journal index: {journal_index_path}
Required result file: {result_path}

## Assignment and authority

You are one fresh strongest-available worker assigned exactly one question. Read
only that immutable packet and the referenced frozen journal index. Read the
result parser and dataclasses in
`__SKILL_DIR__/audit_core/firmware_dive_results.py`, the question/effect model in
`__SKILL_DIR__/audit_core/firmware_dive_questions.py`, and acquisition contracts
in `__SKILL_DIR__/audit_core/firmware_dive_acquisition.py`. Those installed
copies are authoritative. Bind image ID, dive generation, question ID, packet
bytes, proposition, requested resolution effect, and environment exactly.

Examine at most three narrow extracts selected by the packet. Keep evidence
file-backed: relative component path, digest, offset/range, symbol or structured
fact as the parser requires. Do not copy broad firmware content. Separate direct
observation from inference. A plausible explanation is not an observation.

## Outcome and effect contract

Return exactly one answer for this question:

- `supported`: the observed evidence establishes the exact proposition in the
  supplied environment and authorizes only its exact resolution effect.
- `refuted`: direct evidence contradicts the proposition; record the observed
  alternative without turning refutation into positive evidence for another
  subject.
- `inconclusive`: evidence cannot settle the proposition. Crashes, timeouts,
  tool absence, inaccessible hardware, unsupported emulation, and environment
  mismatch are inconclusive, never refuted.

Bind device identifier, firmware version, lifecycle, posture, authentication,
and all other environmental facts from the packet. Challenge stale firmware,
wrong device, wrapper behavior, mocks, cached output, host contamination,
privilege mismatch, non-determinism, and correlation without causation.
Evidence outside the bound environment cannot inflate the conclusion.

A successor question is allowed only when new direct evidence exposes a new,
materially distinct proposition that the current question cannot settle. It
must carry its own exact subject, proposition, settling observation, method,
environment, and resolution effect. A successor never broadens this answer or
silently replaces the frozen assignment.

## Result artifact

Write one result-only strict JSON regular UTF-8 file to `{result_path}`, capped
as required by the installed parser. Use exactly schema version 1 and the
parser's keys. Reject duplicate keys, extra keys, non-finite numbers, malformed
identities, absolute evidence paths, and evidence not owned by this assignment.
Use relative paths in persisted evidence. Dynamic artifact ownership is limited
to this result file; probe/capture manifests and canonical evidence are owned by
deterministic acquisition/import code.

Do not write SQL or open the database. Do not install a canonical artifact,
receipt, observation, dependency, overlay, or journal. Do not claim completion,
regenerate chains, change severity/CVSS, promote findings, construct an exploit,
weaponize a probe, or write a report. The orchestrator owns acquisition,
validation, canonical identities, artifact installation, chain regeneration,
and every completion gate.

DONE requires a complete parser-valid answer. If interrupted, return PARTIAL;
PARTIAL is nonimportable and retains the same assignment for resume. Do not
shrink or replace the question. FAILED means the bound packet cannot be read or
a valid result cannot be produced; it does not settle the proposition.

## Return contract

Return exactly one line and nothing else:

    firmware-dive <DONE|PARTIAL|FAILED> question=<question-id> artifact=<path> [flags=<csv>]

Replace `<question-id>` with `{question_id}` and `<path>` with `{result_path}`.
Keep evidence and analysis in the JSON artifact, never stdout.
