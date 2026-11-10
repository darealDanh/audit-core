# Firmware false-positive review batch

Audit run directory: {run_dir}
Database context (read only): {db_path}
Carved target root (rootfs, read only): {rootfs}
Target image ID: {image_id}
Candidate snapshot SHA-256: {candidate_snapshot_sha256}
Immutable worklist index: {worklist_index}
Assigned batch file: {batch_path}
Required result file: {result_path}

## Assignment and result contract

Read the immutable index and assigned batch at those exact paths. Read the
result dataclasses and validation rules in
`__SKILL_DIR__/audit_core/firmware_fpcheck_results.py`; that parser is the
authoritative schema, not a schema reconstructed from memory. Read the shared
FP rules in `__SKILL_DIR__/references/phase5-fp-check.md`.

Bind the result to the supplied image and candidate snapshot. Derive
`worklist_sha256` from the exact index bytes. Use the relative batch filename
and `batch_sha256` declared by the index, verifying the digest against the
assigned bytes. Require agreement among the index, batch, supplied provenance,
and assignment paths. On mismatch return FAILED; do not repair the worklist or
switch generations.

Write one result-only strict JSON file to `{result_path}` using the parser's
schema-version-1 contract: a regular UTF-8 file capped at 8 MiB. No duplicate
keys, extra keys, non-finite numbers, invalid values, or unmatched verdict
variants. A complete result contains exactly one decision for every assigned candidate
and no other candidate, including both lanes' observations of the same issue.
Identity is `(lane, candidate_id)` within the same image and candidate snapshot;
the same candidate ID in different lanes remains two decisions. An empty
assigned batch requires a valid result with zero decisions.

## Review method

1. Restate each candidate's claim and apply the attacker-advantage test FIRST:
   does the attacker's position already grant the claimed impact? Explain the
   answer before applying other rules.
2. Apply all 18 Hard Exclusions (HE-1 through HE-18), all
   10 Precedent rules (PR-1 through PR-10), Capability Validity checks
   CV-1 to CV-3, and the Marginal Gain Test. Record the applicable canonical
   rule IDs in `rules_applied`; the Marginal Gain ID is `MARGINAL-GAIN`.
   Explain relevance rather than listing unsupported rule names.
3. Re-read every cited source or evidence artifact and the relevant carved
   component. Source may be absent: use static binary, symbol, offset,
   configuration, and artifact evidence as available; do not assume source
   access. Trace the actual attacker-input-to-operation flow, guards, device
   state, authentication, and reachability. Check mitigations the hunt missed,
   the shared confidence threshold, and the devil's advocate argument.
   Retain uncertainty and settling observations rather than claim live proof.
4. Perform cross-lane comparison across the index's batches as needed, reading
   the original evidence from both L-sink and L-dark. Verify each compared
   batch's indexed digest and provenance. Comparison does not assign its
   candidates to you. A `similarity_signature` is a priority hint only:
   never silently merge, drop, or rewrite candidate identities or evidence.
   Similar titles, paths, signatures, or bug classes do not prove one root cause.
5. Issue TRUE_POSITIVE, FALSE_POSITIVE, or DUPLICATE with reason,
   attacker-advantage explanation, mitigation analysis, and confidence, using
   exactly the matching verdict variant from the parser.
   For TRUE_POSITIVE, provide an exact `root_cause_key`, concrete root cause,
   attacker position, traced flow, cautious impact hypothesis, owned relative
   component paths and surface IDs, and `dedup_evidence` explaining identity or
   independence. Reuse a root-cause key only when the evidence establishes the
   same cause; distinct causes retain distinct keys.
   For FALSE_POSITIVE, the pivot is mandatory: provide `refuting_mechanism`,
   `enabled_observation`, `pivot_evidence`, a pivot ID, and the owned component
   path. Explain what the refuting mechanism itself enables; an evidence-backed
   "no attacker-controlled path identified in this review" is valid, a blank
   is not. Keep the pivot in this JSON; the importer publishes it atomically.
   For DUPLICATE, name `target_lane` and `target_candidate_id` in the same
   current snapshot and give concrete `dedup_evidence`. Cross-lane and
   cross-batch targets are allowed; preserve both candidates' evidence. A
   duplicate chain must terminate at a TRUE_POSITIVE. Self-targets, missing or
   foreign targets, cycles, and FALSE_POSITIVE terminals are invalid. Do not
   invent another worker's verdict; the orchestrator's global check resolves
   the complete graph before completion.

## Operating boundaries and checkpoints

Keep evidence and reasoning in the result artifact, not stdout or dispatch.
Do not write SQL. Do not write to the database, use SQLite, `audit.py put`,
`audit.py pivot`, the result importer, or checkpoint/transition commands.
The deterministic importer owns SQL, canonical artifact installation, receipts,
verdicts, pivots, and transitions. Only the orchestrator records complete results
and runs the global check; worker DONE certifies this batch alone.

Static review only. Do not execute target code or binaries. Do not emulate
firmware. Do not exploit or weaponize a path, assign severity, promote to
generic findings or generic verdicts, or claim dynamic confirmation. Do not
alter the carved root, acquire firmware, expand scope, or perform hardware,
kernel, or bootloader testing. Blocker methods describe future observations,
not permission to perform them.

Use relative component paths and relative indexed batch filenames in persisted
JSON. Do not persist absolute host-root or rootfs paths in evidence, reasons,
keys, or other result text; the supplied absolute paths are access context only.

If time or context prevents completion, return PARTIAL without fabricating verdicts
for unfinished candidates. Preserve completed decisions and evidence in the
result file as a checkpoint, and identify completed/total decision counts and
the exact remaining lane-qualified candidate IDs in return flags. An incomplete
checkpoint is not importable as a complete result. The orchestrator owns durable
checkpoint publication and resumption of the same immutable assignment; it must
not shrink coverage or substitute fabricated decisions to pass the gate.

## Return contract

Return exactly one line, and nothing else:

    firmware-fpcheck-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]

Replace `<batch>` with the assigned batch ID (for example, batch-0001) and
`<path>` with `{result_path}`. Rows counts candidate decisions actually written,
not findings, pivots, or SQL writes. DONE requires a complete valid bound result;
PARTIAL means honest unfinished review; FAILED means a valid bound result cannot
be produced. Put concise limitations in flags and the artifact, never inline
analysis or worklist contents.
