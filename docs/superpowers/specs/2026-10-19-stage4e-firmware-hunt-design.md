# Stage 4e design: evidence-bound two-lane firmware hunt

**Date:** 2026-10-19

**Parent:** [`2026-10-04-audit-suite-design.md`](2026-10-04-audit-suite-design.md), §4

**Predecessor:** [`2026-10-14-stage4d-surface-design.md`](2026-10-14-stage4d-surface-design.md)

## 1. Decision

Stage 4e implements the firmware `hunt` phase as two independently prepared,
dispatched, imported, and completed lanes over the same complete target
denominator:

- **L-sink** traces attacker-controlled data to command-execution, unsafe-memory,
  NVRAM-to-shell, and format-string sinks.
- **L-dark** searches the less visible protocol and trust surfaces named by the
  parent design: UPnP/SSDP, mDNS, TR-069/CWMP, cloud/P2P, proprietary discovery,
  Unix-socket IPC, OTA verification, and heap corruption.

Every target firmware unit receives a decision in both lanes. Hints prioritize
work but never reduce either denominator. The lanes have separate worklists,
receipts, coverage phases, checkpoints, and completion gates. Work or budget
from one lane cannot satisfy the other.

The phase follows Stage 4d's deterministic prepare/record/check split. Agents
read immutable assignments and write bounded JSON. Deterministic code verifies
the live carved root, binds the exact completed surface snapshot, owns SQL and
artifact installation, and performs the only completion transition.

Stage 4e remains in the shared `codebase-audit` tree. It implements another
vertical slice of the future `firmware-audit` skill; it does not create the
separate skill tree or settle the monorepo/submodule decision.

## 2. Why this slice exists

Stage 4d proves what externally reachable dispatch paths exist, where their
handlers are, what authentication ordering is evidenced, and what remains
unknown. That is necessary context, not vulnerability analysis. Stage 4e turns
that verified context into candidate security findings without confusing a
mapped handler or a dangerous function call with an exploitable path.

The two lanes are intentionally non-transferable. The prior tplink audit spent
discovery budget on weaponization and left dark surfaces unopened. A single
combined queue would recreate that failure: cheap sink matches would dominate
the work while complex protocol and trust analysis disappeared behind an
aggregate "complete" count.

## 3. Goals and non-goals

### Goals

1. Require a complete and still-canonical Stage 4d surface generation.
2. Bind hunt work to the exact image manifest and a canonical digest of the
   verified surface rows, unknowns, run metadata, and result evidence.
3. Assign every target regular-file unit exactly once per lane.
4. Preserve independent L-sink and L-dark coverage and completion.
5. Store only candidates supported by a complete attacker-input-to-operation
   trace, checked mitigations, and an honest impact hypothesis.
6. Retain evidence-backed analyzed-clear and not-applicable decisions rather
   than treating an absent finding as coverage.
7. Install canonical results before atomically publishing receipts, coverage,
   and candidates.
8. Make candidate-free batches cheap to prove with durable receipts rather than
   a scan over retained orphan artifacts.
9. Invalidate downstream hunt state when image, manifest, or surface evidence
   changes.

### Non-goals

- Fetching, carving, modifying, or executing firmware.
- Exploit development, weaponization, or live verification.
- Emulation, hardware testing, kernel analysis, or bootloader analysis.
- Assigning a final severity or declaring a candidate confirmed.
- Static false-positive adjudication; that belongs to firmware `fpcheck`.
- Cross-component chain composition; that belongs to `chain`.
- Interactive deep investigation; that belongs to `dive`.
- Migrating firmware candidates into generic `cba_findings`; the later
  firmware `fpcheck` design will define that boundary.
- Running the paid milestone audits, mutation sweep, or a new indicator
  snapshot.

## 4. Entry contract and snapshot binding

`hunt prepare` accepts a run directory, the live carved target root, an optional
explicit target image ID, and independent batch sizes for the two lanes. It
requires all of the following:

- an acquired image with `role='target'`;
- a stored `cba_firmware_files` manifest and image-qualified inventory;
- a `cba_surface_runs` row in `complete` state;
- a canonical Stage 4d worklist and canonical result evidence for every batch;
- valid surface/unknown linkage and complete `phase='surface'` coverage; and
- an exact live-root match by path, kind, size, and SHA-256, including a final
  rescan under the publication lock.

Preparation calls the Stage 4d checker as a library contract rather than
reimplementing a weaker surface gate. It then computes
`surface_snapshot_sha256` from canonical, length-framed data containing:

- image ID and firmware manifest digest;
- Stage 4d worklist digest and completion identity;
- every selected-image surface row in primary-key order;
- every selected-image unknown row in primary-key order; and
- every canonical Stage 4d batch result path and digest used by the checker.

Host paths, timestamps, and SQLite row order do not enter the digest. A
replacement Stage 4d result that changes evidence changes the snapshot digest
even if the Stage 4d worklist did not change.

## 5. Complete dual-lane denominator

Both lane worklists contain every selected-image `cba_firmware_files` regular
file, ordered by exact relative path. Each unit appears in exactly one batch in
L-sink and exactly one batch in L-dark. Reference images and globally keyed
component hints cannot change the target denominator.

Each unit carries bounded advisory hints derived from the selected image:

- ELF and boot-service facts;
- matching Stage 4d surfaces and unknowns;
- target-side diff entries and known vendor-fix observations; and
- component identity where its evidence is applicable.

Hints never authorize an automatic omission or not-applicable result. The
worker reads the assigned file and supplies evidence for its decision.

## 6. Lane semantics

### 6.1 L-sink

L-sink looks for complete flows into:

- `system`, `popen`, `execve`, vendor shell wrappers such as `doSystemCmd` and
  `twsystem`, and equivalent discovered wrappers;
- `strcpy`, `sprintf`, `memcpy`, unbounded `%s` scanning, and equivalent unsafe
  memory operations where attacker-controlled length or content reaches them;
- NVRAM/configuration values that later reach a shell; and
- attacker-controlled format strings.

A sink name, import, string, or changed call site is a lead only. A candidate
requires the external or cross-trust-boundary input, transformations, guards,
and dangerous operation to be cited as one data flow. The worker records which
validation, bounds, quoting, authentication, and call-site constraints it
checked.

### 6.2 L-dark

L-dark examines every unit for:

- UPnP/SSDP and mDNS responders;
- TR-069/CWMP clients;
- cloud tunnels and P2P pairing stacks;
- proprietary LAN discovery over UDP or multicast;
- HTTP-daemon-to-helper IPC over Unix sockets;
- OTA signature, downgrade, and trust verification; and
- heap corruption of any kind.

Stage 4d surface hints are starting points, not the definition of this lane.
Files without hints still require direct assessment because proprietary
protocols and trust boundaries are precisely the surfaces generic mapping may
miss.

### 6.3 Decisions

Every assigned unit emits one strict decision:

- `analyzed` with zero or more candidates and a retained clear-analysis reason
  when no candidate survives;
- `not_applicable` with evidence showing why the unit cannot participate in the
  lane; or
- `not_audited` with an explicit reason and no candidates.

The shared `cba_coverage` contract remains unchanged. `analyzed` and
`not_applicable` result decisions publish `state='analyzed'`; the latter's
evidence-backed explanation is retained in the canonical result and coverage
reason. `not_audited` publishes that state and reason. A `budget` reason is
representable for honest partial work but fails the lane gate.

## 7. Durable schema

Stage 4e adds three additive tables.

### 7.1 `cba_hunt_runs`

One row per `(image_id, lane)`:

| Column | Meaning |
|---|---|
| `image_id` | selected acquired target |
| `lane` | `l-sink` or `l-dark` |
| `manifest_sha256` | exact target manifest |
| `surface_snapshot_sha256` | exact completed Stage 4d evidence snapshot |
| `worklist_path` | canonical lane index path |
| `worklist_sha256` | SHA-256 of exact index bytes |
| `unit_count` | complete lane denominator |
| `batch_count` | prepared lane batches |
| `status` | `pending` or `complete` |
| `prepared_at` | generation publication time |
| `completed_at` | set only by the lane checker |

Primary key: `(image_id, lane)`.

### 7.2 `cba_hunt_receipts`

One row per imported batch in a particular generation:

| Column | Meaning |
|---|---|
| `image_id`, `lane` | ownership |
| `worklist_sha256` | generation ownership |
| `batch_path`, `batch_sha256` | exact assignment |
| `result_path`, `result_sha256` | canonical installed evidence |
| `unit_count` | decisions in the batch |
| `candidate_count` | candidates in the batch |
| `recorded_at` | import time |

Primary key: `(image_id, lane, worklist_sha256, batch_path)`. Receipts make
candidate-free results first-class and remove any need to discover them by
scanning artifact directories.

### 7.3 `cba_hunt_candidates`

One row per candidate, owned by `(image_id, lane, candidate_id)`:

| Field group | Required content |
|---|---|
| Identity | candidate ID, component path, title, bug class |
| Surface context | canonical JSON list of selected-image surface IDs; empty only with an explanation |
| Attacker path | attacker position, input/source evidence, complete data flow |
| Dangerous operation | sink/operation and exact operation evidence |
| Mitigations | checks performed and why they do not break the traced path |
| Device state | lifecycle, posture, auth, reachability, and supporting evidence |
| Assessment | confidence, impact hypothesis, and structured blockers |
| Provenance | canonical result path/hash and recorded time |

Confidence is an integer 0 through 10. Stage 4e does not store final severity.
Each blocker contains an ID, question, exact settling observation, and method
(`static`, `emulate`, or `hardware`). Blockers do not rewrite Stage 4d unknowns.
They state what remains before later adjudication.

All JSON-valued cells use canonical compact UTF-8 JSON with sorted keys,
duplicate rejection, and schema validation before SQL publication.

## 8. Worklists and results

Preparation publishes one shared generation directory with separate lane
subdirectories:

```text
RUN/files/hunt/<generation>/l-sink/index.json
RUN/files/hunt/<generation>/l-sink/batch-*.json
RUN/files/hunt/<generation>/l-dark/index.json
RUN/files/hunt/<generation>/l-dark/batch-*.json
```

`generation` is a deterministic digest over the image, manifest, surface
snapshot, and the two canonical lane definitions. Lane index bytes separately
determine each `worklist_sha256`. Defaults are 50 units per batch for both
lanes; `--sink-batch-size` and `--dark-batch-size` independently accept 1
through 1000. Batch size changes the worklist generation, not the denominator.

Agents write one strict schema-version-1 result per batch. A result binds:

- image, lane, manifest, surface snapshot, and worklist digests;
- relative batch path and batch digest; and
- exactly one decision for every assigned unit and no other unit.

Results are regular UTF-8 files capped at 8 MiB. Duplicate keys, extra keys,
non-finite numbers, absolute/escaping paths, invalid identifiers, duplicate
decisions or candidates, foreign surfaces, and malformed blocker/state data are
rejected before artifact installation.

Canonical results install at:

```text
RUN/artifacts/hunt/<generation>/<lane>/<result-sha256>/result.json
```

The deterministic importer revalidates the current image, live manifest,
surface snapshot, index, batch, and result. It installs the artifact, repeats
the validation under the publication lock, then atomically publishes its
receipt, decisions as coverage, and candidates. Artifact installation may
leave an orphan on later SQL failure; no SQL from the failed import survives.

## 9. Candidate validity

A candidate is valid only when:

1. its component is assigned to that result's image, lane, and batch;
2. every referenced surface belongs to that image and component;
3. attacker position and device-state values use the existing firmware enums;
4. input evidence, complete data flow, dangerous-operation evidence,
   mitigation checks, and impact hypothesis are non-empty;
5. confidence is 0 through 10 and the worker has not claimed confirmation;
6. blockers have exact settling observations and permitted methods; and
7. no candidate is published by a not-applicable or not-audited decision.

L-sink candidates additionally require a named dangerous operation and a trace
showing attacker influence at that operation. L-dark candidates require a
named protocol, trust boundary, OTA decision, or heap-corruption mechanism;
generic "interesting binary" observations are not candidates.

Finding IDs are stable, bounded identifiers and need only be unique within an
image and lane. Later firmware `fpcheck` is responsible for cross-lane/root-
cause deduplication and promotion into its reviewed finding model.

## 10. Separate budgets and checkpoints

Non-transferability is structural rather than an unverifiable prose promise:

- each lane has its own immutable assignments and coverage phase;
- each lane has its own receipts, pending/complete state, and completion time;
- lane-specific checking cannot count rows from the other lane;
- unused work allocation is never rewritten into the other lane's worklist;
- a context ceiling checkpoints and resumes the same lane with fresh workers;
  it never creates a budget skip or shrinks the denominator; and
- the final two-lane check requires both lane checks to pass.

L-sink dispatch uses the economical analysis tier established by the parent
design. L-dark uses the strongest analysis tier. The phase records coverage and
evidence, not provider-specific token telemetry. Existing `budget` and
`checkpoint` verbs remain the source for measured context use.

## 11. Completion gate

`hunt --check --lane <lane>` verifies, for the selected image:

- the image, manifest, live root, and surface snapshot remain current;
- the lane worklist is canonical and covers the complete denominator;
- every batch has exactly one matching canonical receipt and result;
- every unit has exactly one valid decision and coverage row;
- every candidate matches its owning result and current surface context;
- no not-audited row has reason `budget`; and
- aggregate receipt counts equal worklist, coverage, and candidate counts.

It repeats the checks under a publication lock before changing that lane from
`pending` to `complete`. Honest open blockers do not alone prevent completion;
they prevent later overstatement.

`hunt --check` without `--lane` runs both lane gates and succeeds only when
both are complete against the same manifest and surface snapshot. It is the
terminal Stage 4e gate.

## 12. Replacement and invalidation

Duplicate batch import refuses unless `--replace` is supplied. Replacement
removes only the selected batch's receipt, coverage decisions, and candidates,
then installs the new batch result atomically. It sets only that lane back to
pending. The sibling lane and other images remain untouched.

Same-input preparation preserves both generations. A changed manifest,
surface snapshot, or lane worklist atomically clears the affected image's old
hunt runs, receipts, candidates, and lane coverage before publishing the new
pair. Preparation publishes both lanes together so they cannot bind different
surface snapshots.

Acquisition, triage, and surface mutation paths gain downstream invalidation:

- changed target acquisition clears its manifest, surface state, and both hunt
  lanes in the existing transaction;
- a changed target triage manifest clears surface state and both hunt lanes in
  its triage publication transaction; and
- preparing or recording a changed Stage 4d generation clears both hunt lanes
  for that image in the same transaction that makes surface pending.

Invalidation uses image-qualified coverage prefixes and never guesses ownership
of legacy raw rows. Ambiguous old hunt coverage is refused and preserved, with
a fresh run required, matching Stage 4d's conservative policy.

## 13. CLI and errors

```text
python3 audit.py hunt --run RUN --root ROOT [--image-id ID]
    [--sink-batch-size N] [--dark-batch-size N] [--json]

python3 audit.py hunt --run RUN --record RESULT.json [--replace] [--json]

python3 audit.py hunt --run RUN --check [--image-id ID]
    [--lane l-sink|l-dark] [--json]
```

Prepare is the default mode and requires `--root`. `--record` and `--check`
are mutually exclusive with preparation-only arguments. Argparse usage errors
exit 2; expected domain/database errors exit 1; success exits 0.

Terminal and JSON output are bounded aggregates: image, lane/generation
identity, manifest/surface/worklist digests, paths, units, batches, receipts,
coverage counts, candidate counts, blockers, and completion status. Raw
candidate evidence never enters orchestrator output.

Expected SQLite failures render exactly `hunt: database operation failed`.
Other expected diagnostics escape control/non-ASCII characters, cap output at
512 ASCII characters plus newline, and never expose an absolute carved-root
path. Unexpected programming exceptions propagate after rollback.

## 14. Agent brief

`references/briefs/hunt-brief.md` is lane-aware and rendered from file. It:

1. names only immutable paths and required provenance;
2. requires the worker to read the exact index, batch, result schema, and lane
   rules from the installed skill directory;
3. requires direct assessment of every unit, including units without hints;
4. forbids treating a sink/import/string, changed binary, mapped handler, or
   configured service as a vulnerability by itself;
5. requires full trace, mitigation checks, state/reachability evidence, and
   honest blockers for every candidate;
6. forbids execution, emulation, exploitation, severity assignment, database
   writes, scope expansion, and omission for budget; and
7. returns one line only:

```text
hunt-<lane>-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]
```

The result artifact, not the return line, contains analysis.

## 15. Implementation boundaries

New focused modules:

- `audit_core/hunt.py`: snapshot binding, dual-lane preparation, invalidation,
  receipt-backed checking, and bounded summaries.
- `audit_core/hunt_results.py`: strict result parser, semantic validation,
  canonical installation, and atomic batch import/replacement.
- `references/briefs/hunt-brief.md`: semantic worker contract.

Existing files change only at their ownership boundaries:

- `audit_core/schema.sql`, baselines, and `audit_core/db.py` own schema and row
  validation;
- acquisition, triage, and surface modules own downstream invalidation when
  their state changes;
- `audit.py` owns CLI parsing and bounded presentation;
- installer/manifest tests own shipped-file completeness; and
- durable docs own user commands, architecture, present state, and handoff.

Stage 4e does not fold hunt behavior into the already large Stage 4d modules.

## 16. Verification

TDD covers at least:

- fresh schema plus migration from every supported baseline;
- entry refusal for absent, pending, stale, or noncanonical surface state;
- exact live-root and target-inventory agreement;
- deterministic two-lane preparation and independent batch sizes;
- every unit exactly once in both lanes, including hint-free files;
- strict bounded JSON, duplicate/extra key, identifier, path, and enum checks;
- candidate trace, mitigation, state, surface linkage, blocker, and lane rules;
- analyzed-clear, not-applicable, not-audited, and budget behavior;
- canonical installation, receipts, duplicate refusal, replacement, and
  rollback;
- candidate-free batches proven by receipts without artifact-directory scans;
- image isolation for targets with identical raw paths and unusual Unicode or
  delimiter-containing image IDs;
- atomic acquisition, triage, and surface invalidation;
- stale-generation and concurrent-modification refusal;
- independent lane check plus the final two-lane gate;
- CLI text/JSON/error behavior and secret/absolute-path hygiene;
- brief anti-inference and no-weaponization prose contracts;
- installer, lint, EOL, manifest, schema, coverage, and benchmark regressions;
  and
- a fresh `make all` after final documentation reconciliation.

`make mutate` remains opt-in and outside Stage 4e unless explicitly requested.
No audit or paid milestone benchmark is implied by deterministic harness
success.

## 17. Completion boundary and next stage

Stage 4e is complete only when the command, schema, two deterministic modules,
agent brief, tests, installer manifest, architecture/progress/handoff/inventory
documents, independent review, and fresh eight-gate `make all` result agree.

The next vertical slice is firmware `fpcheck`: static adversarial review of
hunt candidates, cross-lane/root-cause deduplication, pivot preservation, and
promotion into the reviewed finding model. The Asus golden and the
monorepo/submodule decision remain prerequisites for the later overall Stage 4
milestone gate, not for implementing Stage 4e.
