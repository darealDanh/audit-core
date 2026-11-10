---
description: Run the full firmware-audit pipeline (qualify → acquire → triage → diff → surface → hunt → fpcheck → chain → dive → decide → report).
argument-hint: "[optional: focus area or notes]"
---

Run the **full firmware-audit pipeline** against the target firmware image.

Optional user note: $ARGUMENTS

Read @__SKILL_DIR__/SKILL.md.

Execute the router stages in order, gating on user approval between each:

1. Stage 4a firmware **qualify** — GO/NO-GO gate on EOL/EOS and payout. A NO-GO ends the run.
2. Stage 4b firmware **acquire** — latest target build + CVE-affected diff reference.
3. Stage 4c firmware **triage** — carve the image; record arch/libc, components, SBOM, services, nvram, mitigations.
4. Stage 4d firmware **diff** and **surface** — patch-diff + sibling sweep, then map the dispatch/handler attack surface.
5. Stage 4e firmware **hunt** — two independent lanes (L-sink, L-dark) with separate, non-transferable budgets.
6. Stage 4f firmware **fpcheck** — static adversarial review plus the mandatory false-positive pivot.
7. Stage 4g firmware **chain** — compose reviewed findings into end-to-end chains.
8. Stage 4h firmware **dive** — settle frozen chain blockers and unknowns.
9. Stage 4i firmware **decide** — acquisition decision package (replaces live verify).
10. Stage 4j firmware **report** (`firmware-report`) — lean per-chain report with pre-auth status stated explicitly.

`deploy` and live-instance `verify` are not part of this pipeline — an image is not a deployed app; `decide` is the terminal deliverable.

Follow every Essential Principle and Rationalization-to-Reject in SKILL.md. Honor user gates between stages.
