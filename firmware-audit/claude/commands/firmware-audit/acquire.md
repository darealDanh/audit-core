---
description: "Firmware audit — Stage 4b firmware acquire: record the latest build (target) plus the CVE-affected diff reference, with versions, hashes, and provenance."
argument-hint: "[optional: focus or notes]"
---

Run the **acquire** stage of the firmware-audit skill.

Argument: $ARGUMENTS

Read @__SKILL_DIR__/SKILL.md and the current resume note at `/memories/session/<project>-firmware-audit-resume.md` (if present), then execute its **Stage 4b firmware acquire** route: record the latest build (target) plus the CVE-affected diff reference, with versions, hashes, and provenance.

Stop at the user gate before the next stage.
