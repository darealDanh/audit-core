# Repository instructions

## Completion contract

Whenever a stage or material feature is completed, merged, or otherwise
changes the repository's current state:

1. Reconcile `progress.md`, `SESSION_HANDOFF.md`, `ARCHITECTURE.md`, and
   `feature_lists.json` with the actual tree. Update only the files whose
   present-state claims changed; keep historical specs, plans, derivations,
   and baselines intact.
2. Remove completed work from "next steps" and name the real next stage,
   including any prerequisite or known limitation it inherits.
3. Run the full verification harness with `make all` from the repository root.
   Do not claim completion from a targeted test run or from a harness result
   captured before the final documentation changes.
4. Record the measured test, gate, schema, manifest, install, coverage, and
   benchmark summaries in the durable handoff documents when those values
   changed. Never invent or copy stale counts.
5. Keep `make mutate` separate: it is opt-in, long-running, and intentionally
   outside `make all` unless the task explicitly requires a mutation sweep.

Documentation reconciliation and a fresh full-harness result are part of the
deliverable, not optional cleanup after it.
