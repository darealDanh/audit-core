# Stage 4b triage brief derivation

Source: Stage 4b design §3–4, §7 and implementation-plan Task 6.

The shipped brief must preserve these instructions:

1. Name the run directory, carved rootfs, and image ID; `none` is explicit when provenance was not supplied.
2. State that the script already recorded regular-file inventory, ELF facts, and statically evidenced boot starts. The agent verifies and enriches those rows rather than rebuilding them.
3. Inspect BusyBox once, identify its applet set as component evidence, and do not turn its symlinks into inventory units.
4. Check architecture, endianness, dynamic loader/libc, dependencies, and mitigation facts against actual binaries. Record contradictions and unknowns; do not guess.
5. Review each boot-service row against its exact start line. Static boot evidence proves startup intent, not that a port listens or a handler is reachable.
6. Add or update `cba_components` with identity evidence read from the component itself.
7. Add a service `ports` claim only with `ports_evidence`; leave both blank when static evidence cannot establish a listener.
8. Record vendor-specific facts such as nvram defaults through `audit.py note`, with the source path and evidence.
9. Do not carve, execute firmware, infer dispatch/handler tables, audit kernel or bootloader, or begin vulnerability hunting in this phase.
10. Return exactly one bounded line: `triage DONE|PARTIAL|FAILED rows=<n> artifact=<path> [flags=<csv>]`.

Reconciliation: compare this list against `git diff -U0 -- references/briefs/triage-brief.md` after writing the brief; every item must have a corresponding instruction.
