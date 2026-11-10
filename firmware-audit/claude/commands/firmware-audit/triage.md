---
description: "Firmware audit — Stage 4c firmware triage: carve the image; record arch/endian/libc, component ID + SBOM, init scripts, nvram defaults, listening services, mitigations, corpus."
argument-hint: "[optional: focus or notes]"
---

Run the **triage** stage of the firmware-audit skill.

Argument: $ARGUMENTS

Read @__SKILL_DIR__/SKILL.md and the current resume note at `/memories/session/<project>-firmware-audit-resume.md` (if present), then execute its **Stage 4c firmware triage** route: carve the image; record arch/endian/libc, component ID + SBOM, init scripts, nvram defaults, listening services, mitigations, corpus.

Stop at the user gate before the next stage.
