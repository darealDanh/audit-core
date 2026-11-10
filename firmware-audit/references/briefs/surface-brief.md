# Firmware surface brief

Audit run directory: {run_dir}
Database context (read only): {db_path}
Carved target root: {rootfs}
Target image ID: {image_id}
Manifest SHA-256: {manifest_sha256}
Work-list index: {worklist_index}
Assigned batch file: {batch_path}
Required result file: {result_path}

## Assignment and schema

Read the index and assigned batch from disk; dispatch and return carry paths,
not pasted contents. Inspect the assigned units beneath the carved target
root. The batch is the complete assignment, including files without hints.
Use `audit_core/surface.py` for the prepared index/batch contract and
`audit_core/surface_results.py` for the strict version-1 result schema:
`BatchResult`, `UnitDecision`, `SurfaceRecord`, `UnknownRecord`, `_parse`,
and `_semantics`. Use the enums in `audit_core/db.py`; do not invent values.
Read these contracts before constructing the result, rather than copying SQL
rows or work-list hint objects into it.

Bind the result to the supplied image and manifest. Set `schema_version=1`;
derive `worklist_sha256` as the SHA-256 of the index bytes. In the result,
`batch_path` is the relative batch filename named by the index, not the host
path above. Copy `batch_sha256` from its descriptor and verify it against the
assigned batch bytes. Require agreement among the supplied provenance, index,
and batch. If they disagree, report FAILED; do not repair the assignment or
analyze a different generation.

## Required analysis

1. Emit exactly one decision for every assigned unit and no unassigned unit.
   Use `analyzed` or `not_audited` with the schema's required reason and arrays.
   Do not silently omit a unit, even when it has no hints or looks uninteresting.
   For an analyzed unit with no surface, retain an evidence-backed explanation
   in `reason`, or an explicit unknown explaining why mapping remains unsettled.
   Record a valid non-empty reason for `not_audited` and publish no surfaces for
   that decision. Do not hide unfinished analysis behind an analyzed empty row;
   reason='budget' fails the completion gate and requires a partial return.
2. Treat service, ELF, component, imports, strings, configuration, and caller
   evidence as leads, not conclusions. The absence of a hint is not evidence
   of absence. Read the actual files; trace each external entry point through
   its dispatcher to the concrete handler. Cite the relative path and symbol,
   offset, key, or configuration line in the dispatch/handler evidence.
3. Locate authentication or authorization enforcement relative to the handler.
   Prove whether it occurs before or after dispatch to that handler; record the
   ordering evidence. Use `unknown` when ordering cannot be proved, and create
   its settling question. Do not label a path pre-auth from intuition or a
   missing authentication string.
4. Record the full device-state tuple on every surface: `lifecycle_required`,
   `posture_required`, and `auth_required`, plus `reachability` and non-empty
   `reach_evidence`. Cite the static path supporting `evidenced` or `refuted`;
   for `unknown`, state exactly what static analysis cannot establish. Separate
   materially different protocols, entry points, or state tuples into distinct
   surfaces. Keep each surface and unknown's `component_path` equal to its
   containing decision's assigned path; never publish another batch's rows.
5. Create an explicit unknown for every unresolved field, including dispatch
   and handler questions. Name the question, exact `settling_observation`, and
   method (`static`, `emulate`, or `hardware`); the latter two describe future
   work, not authorization to perform it. For each `unknown` lifecycle,
   posture, auth, or reachability value, supply a matching open unknown for the
   same surface and field. Use `surface_id=null` only when the question prevents
   identifying a surface at all; otherwise link it to that component's surface.
   Use globally unique unknown IDs and stable image-scoped surface IDs within
   the validator's identifier limits. For open questions set `resolution=null`
   and `evidence=null`; mark a question `resolved` only with non-empty resolution
   and evidence. Do not turn an open unknown into a negative reachability claim.
   Honest open unknowns are valid output and do not alone require PARTIAL.

## Output and boundaries

Write only one strict JSON result to `{result_path}`: a regular UTF-8 file,
at most 8 MiB, matching the referenced result schema exactly. Include every
required key, using null for nullable values and empty arrays where appropriate.
Reject duplicate keys, extra keys, non-finite numbers, omitted decisions, and
duplicate unit/surface/unknown IDs. Do not supply timestamps, database metadata,
or importer-derived artifact paths and hashes. Keep detailed evidence and
no-surface explanations in the result, not in the return line.

The deterministic importer owns SQL, canonical artifact provenance, and coverage
publication. Do not write to the database or run the importer, `audit.py put`,
or coverage recording. Only the orchestrator imports the result and runs
`audit.py surface --check`; DONE does not certify the run.

Do not hunt vulnerabilities, assign severity, execute exploits, execute target
binaries, emulate firmware, infer listeners without evidence, expand scope,
modify the carved root, fetch or carve firmware, or inspect the kernel or
bootloader. A configured port or boot-start line does not prove a listener or
a reachable handler. If evidence or resources prevent completion, record the
limitation honestly and return PARTIAL or FAILED; never manufacture evidence
or omit assigned units to claim success.

## Return contract

Return exactly one line, and nothing else:

    surface-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]

Replace `<batch>` with the batch's `batch_id`, `<path>` with the required result
file path, and `<n>` with the number of decisions written: rows counts unit
decisions, not SQL writes or surface rows. Use DONE only for a complete valid
batch result; choose PARTIAL for explicit unfinished work and FAILED when a
valid bound result cannot be produced. Put concise limitations in optional
flags and the result; never return inline analysis or the batch contents.
