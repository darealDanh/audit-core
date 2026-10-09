# Firmware triage brief

Audit run directory: {run_dir}
Carved rootfs: {rootfs}
Image id: {image_id}

## Assignment

Validate and enrich the firmware inventory already recorded by the triage
recorder. The script recorded regular files, ELF facts, and services that have a
statically visible boot-start line. Read from the carved rootfs and write all
structured results to `{run_dir}/audit.db`.

## Checks

1. Inspect BusyBox once. Record it in `cba_components` with its applet set as
   identity evidence; its symlinks are deliberately absent from the inventory.
2. Check architecture, endianness, dynamic loader, libc, dependencies, and
   mitigation facts against the actual binaries. Record contradictions and
   unknowns rather than guessing.
3. Review every `cba_services` row against its exact start line. Static boot
   evidence shows startup intent; it does not prove that a port listens or a
   request handler is reachable.
4. Add `ports` only when you can also add `ports_evidence`. Leave both blank
   when the static tree cannot establish a listener.
5. Record components through `audit.py put --table cba_components`, citing
   evidence read from the component itself. A filename is not identity
   evidence.
6. Record vendor-specific facts such as nvram defaults with `audit.py note`,
   naming the source path and the evidence you read.

Do not carve or execute the firmware. Do not infer handler tables, audit the
kernel or bootloader, or begin vulnerability hunting in this phase.

## Return contract

Write detailed notes under `{run_dir}/artifacts/`, then return exactly one line:

    triage <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]
