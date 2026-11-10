# Firmware hunt batch

Audit run directory: {run_dir}
Database context (read only): {db_path}
Carved target root: {rootfs}
Target image ID: {image_id}
Lane: {lane}
Manifest SHA-256: {manifest_sha256}
Surface snapshot SHA-256: {surface_snapshot_sha256}
Lane work-list index: {worklist_index}
Assigned batch file: {batch_path}
Required result file: {result_path}

## Assignment and result contract

Read the exact index and assigned batch at the supplied paths. Read the result
contract at `__SKILL_DIR__/audit_core/hunt_results.py` and the shared firmware
enums in `__SKILL_DIR__/audit_core/db.py`. These installed-tree paths resolve
from the installed skill directory. The index, batch, and result schema are
file-backed; dispatch carries their paths, not their contents. Analyze only the
assigned batch beneath the supplied carved target root.

Bind the result to the supplied image, lane, manifest, and surface snapshot.
Derive `worklist_sha256` from the exact index bytes. Use the relative batch
filename and batch digest declared by the index, and verify the digest against
the assigned batch bytes. Require agreement among the supplied provenance,
index, batch, and current assigned paths. If anything differs, do not repair the
assignment or switch generations; return FAILED.

Write only one strict JSON result to `{result_path}`. It must be a
schema-version-1 result containing exactly one decision for every assigned unit
and no other unit. It must be a regular UTF-8 file capped at 8 MiB. Reject
duplicate keys, extra keys, non-finite numbers, invalid values, and any mismatch
with the exact result schema.
Use the result dataclasses and validation rules in
`__SKILL_DIR__/audit_core/hunt_results.py`; do not recreate its schema from
memory. Preserve exact relative component paths and valid enum values. A
candidate needs its required provenance, complete evidence, and lane-specific
operation or mechanism. Record analyzed-clear decisions with an evidence-backed
reason. Use `not_applicable` only with evidence that the unit cannot participate
in this lane, and `not_audited` only with an explicit reason. Never attach a
candidate to either of those dispositions.

## Required assessment

Assess every assigned unit directly, including every file with no hints. No
hints means no omission: the absence of a hint is not evidence of absence.
Hints, imports, strings, changed call sites, mapped handlers, and configured
services are leads, not conclusions. Do not silently omit a unit or turn a lead
into a candidate without tracing and supporting evidence.

For every candidate, provide the full attacker-input-to-operation trace: identify
the external or cross-trust-boundary input, transformations, relevant guards,
and the exact dangerous operation. Cite relative paths and the exact symbol,
offset, key, configuration line, or other location at each material step. Record
the mitigations checked: validation, bounds, quoting, authentication, and
call-site constraints. Explain why they do not break the traced path. Include
device-state evidence for `lifecycle_required`, `posture_required`,
`auth_required`, and `reachability`. Distinguish evidenced, refuted, and unknown
states; keep uncertainty and exact settling observations in the result artifact.
For each candidate, include a cautious impact hypothesis and confidence; add
candidate blockers with the exact observation needed to settle each remaining
question. Do not claim confirmation or assign a final severity.

### L-sink categories

When `lane` is `l-sink`, assess complete flows into `system`, `popen`, `execve`,
vendor shell wrappers such as `doSystemCmd` and `twsystem`, and equivalent
wrappers discovered in the target. Also assess `strcpy`, `sprintf`, `memcpy`,
unbounded `%s` scanning, and equivalent unsafe memory operations where
attacker-controlled length or content reaches the operation; NVRAM or
configuration values that later reach a shell; and attacker-controlled format
strings. A sink or dangerous function name alone is not a finding.

### L-dark categories

When `lane` is `l-dark`, directly assess every unit for UPnP/SSDP and mDNS
responders; TR-069/CWMP clients; cloud tunnels and P2P pairing stacks;
proprietary LAN discovery over UDP or multicast; HTTP-daemon-to-helper IPC over
Unix sockets; OTA signature, downgrade, and trust verification; and heap
corruption of any kind. Stage 4d hints are starting points only. Files without
hints still require direct assessment because proprietary protocols and trust
boundaries can be missed by generic mapping. A candidate must name a concrete
protocol, trust boundary, OTA decision, or heap-corruption mechanism; a generic
"interesting binary" observation is not a candidate.

## Output and operating boundaries

Keep all raw evidence, traces, state support, clear-analysis reasons, and
limitations in the result artifact. Write only the one strict JSON result file;
do not return analysis or evidence inline. Do not write to the database or write
SQL. Do not use SQLite, run `audit.py put`, or run the result importer or
coverage commands. The
deterministic importer owns SQL, canonical artifact installation, receipts,
coverage, and candidate publication. Only the orchestrator imports the result
and runs the lane check; DONE does not certify lane or run completion.

Do not execute binaries or target code. Do not emulate firmware. Do not exploit
or weaponize a path or assign severity. Do not perform hardware testing, alter
the carved root, fetch or carve firmware, expand scope, or analyze kernel or
bootloader code. Do not infer a listener, reachability, or trust boundary
without evidence. The `emulate` and
`hardware` blocker methods describe possible later observations, not permission
to perform them.

The lane budgets are separate and non-transferable. A context or time budget
does not permit dropping units, shrinking the denominator, or marking work
complete. Do not turn a budget checkpoint into not_audited(reason='budget');
that decision fails the lane gate. If the budget prevents complete assessment,
do not manufacture clear decisions or publish a database checkpoint. Return
PARTIAL and include checkpoint information in the return flags: completed and
total row counts plus the exact remaining unit paths. Preserve completed
evidence in the result artifact without inventing decisions for unfinished
units. The orchestrator publishes the checkpoint and owns resumption of the
same lane; it alone may run the database-writing `audit.py checkpoint` command.

## Return contract

Return exactly one line, and nothing else:

    hunt-<lane>-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]

Replace `<lane>` and `<batch>` with the assigned lane and batch ID. Replace
`<path>` with `{result_path}` and `<n>` with the number of unit decisions
actually written. Rows counts unit decisions, not candidates or SQL writes. Use
DONE only when the complete assigned batch has a valid result; use PARTIAL for
honest unfinished work, including a budget checkpoint; use FAILED when a valid
bound result cannot be produced. Put concise limitations in optional flags and
the result artifact. Never return inline analysis or batch contents.
