# Golden: TP-Link Tapo DL110 v2

**Firmware under test:** `DL110V2_US_1.0.11_Build_260506_Rel.164323`

**Reference set source:** `reference.json` transcribes the 19 findings rated
CRITICAL in the independent third-party firmware security audit
`~/Documents/Offsec/Opswat/Devices/tplink/findings.txt` (section `# CRITICAL
(19)`, entries F-1 through F-19 of that document, renumbered here as
`REF-1`..`REF-19` in document order to avoid colliding with our own audit's
`F-N` / `G#-F#` finding ids). That document is itself the product of a
multi-cluster review process with its own false-positive and refutation
passes (see its `# Refuted claims` section); it is treated here as the
external ground truth our own audit's recall is measured against, not as a
claim that is itself beyond question.

**Date derived:** 2026-10-05

**Our audit's findings:** read from
`~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db`,
table `cba_findings` (45 rows, primary key format `G<group>-F<n>`, e.g.
`G1-F1`). Note that this primary key is *not* the same as the flat `F-N`
numbering used in that report's own `report.md` prose/summary table — the two
numbering schemes were cross-checked by title and location before any id was
written into `matches.json`.

## matches.json: the adjudication rule

`matches.json` maps a reference finding id to the id of the run finding judged
to be the same underlying defect. **A pair is appended to this file only
after a human has looked at both sides — the reference entry's root cause and
location, and the run finding's root cause and location — and confirmed they
describe the same defect mechanism, not merely a similar symptom or the same
file.** A scorer may *propose* candidate matches (e.g. by shared location
tokens or similar root_cause_key text); a proposal is not a match until a
human adjudicates it and it is added here. This file must never be
auto-populated by a scoring run.

The eight entries currently in `matches.json` were established by a prior
post-mortem review and independently re-confirmed against `audit.db` while
building this golden: each reference id's title/location was checked against
the candidate run finding's title/location in `cba_findings` before the pair
was recorded. See `task-6-report.md` for the per-pair justification and for
two cases where the two reports score the finding at very different
severities despite describing the same mechanism (this is expected and does
not disqualify the match — recall scoring is about root-cause identity, not
severity agreement).
