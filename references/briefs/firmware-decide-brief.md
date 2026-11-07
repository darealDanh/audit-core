# Firmware acquisition decision

Audit run directory: {run_dir}
Target image ID: {image_id}
Decision generation: {decision_generation}
Immutable global worklist: {worklist_path}
Required result file: {result_path}

## Assignment and authority

You are one fresh strongest-available worker assigned the one global firmware
acquisition decision worklist. Read only that immutable worklist and its frozen
references. Read the result parser and dataclasses in
`__SKILL_DIR__/audit_core/firmware_decide_results.py`; that installed copy is
authoritative. Bind the image ID, decision generation, graph, dive overlay,
policy identity, every chain, and every open precondition exactly.

Assess every chain in the denominator. A complete result has exactly one
assessment for every chain, including blocked or ineligible chains. Rank only
within the frozen denominator. Use only evidence references admitted by the
worklist. State uncertainty explicitly; never turn missing evidence into a
positive conclusion.

Bench tests must name their frozen subjects and exact required device, firmware,
lifecycle, posture, and authentication state. Proposed scripts are inert text
for later operator review. Do not execute proposed scripts, probes, commands, or
captures. Do not claim that a script has run or that its output exists.

## Result artifact

Write one result-only strict JSON regular UTF-8 file to `{result_path}`, within
the installed parser limits and using exactly schema version 1 and its keys.
Reject duplicate keys, extra keys, non-finite numbers, malformed identities,
absolute evidence paths, foreign evidence, omitted chains, and invented policy
matches. Keep analysis in the artifact, never stdout.

Do not write SQL or open the database. Do not select or modify policy, compute
the final recommendation or payout, install a canonical artifact, publish
completion, regenerate chains, change severity/CVSS, construct an exploit,
execute proposed scripts, or write a report. Deterministic code owns validation,
policy projection, canonical identities, package installation, recommendation,
payout, and every completion gate.

DONE requires one complete parser-valid global answer. If interrupted, return
PARTIAL; PARTIAL is nonimportable and resumes the same immutable assignment.
Do not shrink the denominator or replace the worklist. FAILED means the frozen
assignment cannot be read or a valid complete result cannot be produced.

## Return contract

Return exactly one line and nothing else:

    firmware-decide <DONE|PARTIAL|FAILED> chains=<n> artifact=<path> [flags=<csv>]

Replace `<n>` with the number of chain assessments and `<path>` with
`{result_path}`.
