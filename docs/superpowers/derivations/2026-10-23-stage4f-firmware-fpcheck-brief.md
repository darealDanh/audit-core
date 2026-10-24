# Stage 4f firmware review brief and routing derivation

The approved Task 10 contract is in
[the Stage 4f plan](../plans/2026-10-21-stage4f-firmware-fpcheck.md).
The controller's behavioral baseline found only the source-code fpcheck route:
it assumed generic findings/source access and could not identify firmware
candidate import, cross-lane duplicate preservation, or pivot handling.

The required correction adds one conditional firmware route after both hunt
lanes complete. The existing source-code workflow and fpcheck brief stay intact.
The route prepares immutable worklists, renders one firmware review brief per
batch through the existing renderer, and leaves record/check to the orchestrator.

The firmware brief must bind all eight supplied variables; read the parser-owned
schema and shared HE/PR/CV/Marginal Gain rules; preserve exact lane-qualified
coverage, evidence and identities; compare cross-lane causes without silent
merging; and require concrete TP roots, FP pivots, and duplicate targets.
The worker writes bounded strict result-only JSON and exactly one return line.
Static-only limits, relative persisted evidence, and honest non-importable PARTIAL
checkpoints keep publication and transitions under deterministic ownership.

Repository tests first demonstrated the missing template, install resolution,
and route. Contract tests protect the rendered assignment's method and safety
clauses; library/CLI/install tests exercise the real renderer and installed trees.
Independent behavioral GREEN remains a controller gate after the implementation
commit. Parser, schema, SQL, workflow and renderer implementations are unchanged.

This reconciliation was written during self-review after the skill edit, rather
than before it as the durable handoff requests. The pre-edit Task 10 brief and
tests supplied the intended change list; this file makes that mapping durable.
