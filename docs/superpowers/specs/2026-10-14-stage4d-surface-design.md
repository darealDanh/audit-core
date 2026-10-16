# Stage 4d Firmware Surface Design

**Date:** 2026-10-14

**Status:** Implemented on `stage4d-surface`; integration into local `main` pending.
Last implementation commit: `2550866`. Documentation and measured verification:
[`../../../SESSION_HANDOFF.md`](../../../SESSION_HANDOFF.md). Historical design
requirements below are preserved.

**Parent:** [`2026-10-04-audit-suite-design.md`](2026-10-04-audit-suite-design.md), §3.4 and §4

**Predecessor:** [`2026-10-12-stage4c-firmware-diff-design.md`](2026-10-12-stage4c-firmware-diff-design.md)

## 1. Decision

Stage 4d adds the firmware `surface` phase as a hybrid. Deterministic code owns
the target image selection, carved-root validation, complete file-backed work
list, result validation, atomic persistence, and completion gate. Agents own
the semantic work: locating entry points, reconstructing dispatch paths and
handlers, deciding where authentication is enforced, and stating the device
state and reachability evidence for each surface.

The phase uses the complete target manifest as its denominator. Known boot
services and ELF facts are useful seeds, but neither is complete enough to
define the work: a dispatcher can be reached through an inetd configuration,
a shell wrapper, a web asset, a shared library, or a proprietary configuration
file. Every target manifest unit therefore receives either an `analyzed` or a
`not_audited` surface-coverage decision. The existing coverage gate remains
the authority; Stage 4d does not invent a weaker parallel denominator.

Stage 4d remains in the shared `codebase-audit` tree. It does not create the
separate `firmware-audit` skill, settle the monorepo decision, or begin broad
vulnerability hunting.

## 2. Why this slice exists

Stage 4b records what files, ELF objects, and statically evidenced boot
services exist. Stage 4c compares target and reference manifests and gives an
agent the vendor-fix question. Neither phase answers the questions that make a
potential defect security-relevant:

- Which external entry point reaches which dispatcher and handler?
- Does authentication happen before or after that handler?
- In which lifecycle, network posture, and authentication state is the path
  available?
- What static evidence supports reachability, and what remains unknown?

The parent design requires dispatch and handler tables per component, with
pre-auth versus post-auth stored as data. It also requires every surface to
carry a device-state tuple and every unresolved element to become a durable
unknown with a named settling observation. Stage 4d provides those contracts
before `hunt`, so later findings cannot acquire reachability claims merely from
their severity labels.

## 3. Goals and non-goals

### Goals

1. Build a deterministic, complete, image-scoped work list from the target's
   stored regular-file manifest.
2. Refuse analysis when the supplied carved root no longer matches the stored
   manifest, closing Stage 4c's upsert-only snapshot limitation at this phase
   boundary.
3. Persist dispatch path, handler, protocol, authentication boundary, device
   state, and reachability evidence as queryable data.
4. Persist every unresolved state or reachability question with the
   observation and method that would settle it.
5. Import each agent batch atomically and bind it to the exact manifest and
   work-list batch the agent received.
6. Use `cba_coverage` with `phase='surface'` so incomplete work and budget
   skips fail the existing coverage gate.
7. Support safe batch re-execution without deleting results belonging to
   other batches.
8. Keep terminal output and subagent returns bounded while detailed evidence
   remains file-backed.
9. Remain zero-audit-cost until the operator chooses to run the deferred
   firmware benchmark.

### Non-goals

- Fetching, carving, modifying, or executing firmware.
- Inferring that a configured port is listening without evidence.
- Treating a mapped handler or unauthenticated path as a vulnerability.
- L-sink or L-dark vulnerability hunting; those belong to Stage 4e `hunt`.
- FP-check, chain composition, interactive dive, acquisition decisions, or
  reporting.
- Emulation, hardware verification, kernel analysis, or bootloader analysis.
- Extending firmware state fields onto findings before firmware findings
  exist.
- A paid model audit, a new indicator snapshot, or a benchmark-gate claim.
- The separate `firmware-audit` skill tree or Stage 5 alignment.

## 4. Alternatives considered

### 4.1 Reuse `cba_attack_surface`

Rejected. That source-audit table has no image identity, dispatch path,
handler, device-state tuple, structured reachability evidence, artifact
provenance, or unknown linkage. Adding firmware-only columns would weaken the
generic recon contract and still leave batch provenance unsolved.

### 4.2 Fully automatic surface extraction

Rejected. Strings, imports, init scripts, and socket calls are useful leads,
but they cannot reliably establish a complete dispatcher, the ordering of an
authentication check, or runtime device posture. Automation may prepare
evidence; it may not turn hints into pre-auth reachability claims.

### 4.3 Agent-only analysis

Rejected. An agent can reason about handlers but cannot provide a reproducible
denominator, detect a stale carved root, atomically publish a batch, or prove
that every target unit received a decision.

### 4.4 Selected hybrid

Deterministic preparation and ingestion surround file-backed agent analysis.
This keeps semantic judgment where it belongs while making scope, provenance,
and completion mechanically enforceable.

## 5. Data model

Stage 4d adds three tables. All are image-scoped. No table relies on a foreign
key pragma that existing databases do not enable; cross-table integrity is
enforced by the `surface` importer and gate.

### 5.1 `cba_surface_runs`

One row binds the current surface phase to the exact target manifest and
content-addressed work-list generation:

```sql
CREATE TABLE IF NOT EXISTS cba_surface_runs (
    image_id TEXT PRIMARY KEY,
    manifest_sha256 TEXT NOT NULL,
    worklist_path TEXT NOT NULL,
    worklist_sha256 TEXT NOT NULL,
    unit_count INTEGER NOT NULL,
    batch_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    prepared_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT);
```

`status` is `pending` or `complete`. Counts are non-negative SQLite integers;
an empty target manifest is refused before a row is written. `complete` is
derived only by the gate after every current manifest unit has a valid
`cba_coverage` decision for `surface` and every stored unknown reference is
consistent.

The manifest digest is over a canonical JSON array of the target's stored
`path`, `kind`, `size`, and `sha256` values in path order. It does not include
timestamps or host paths.

### 5.2 `cba_firmware_surfaces`

```sql
CREATE TABLE IF NOT EXISTS cba_firmware_surfaces (
    image_id TEXT NOT NULL,
    surface_id TEXT NOT NULL,
    component_path TEXT NOT NULL,
    entry_point TEXT NOT NULL,
    protocol TEXT NOT NULL,
    dispatch_path TEXT NOT NULL,
    handler TEXT NOT NULL,
    lifecycle_required TEXT NOT NULL,
    posture_required TEXT NOT NULL,
    auth_required TEXT NOT NULL,
    reachability TEXT NOT NULL,
    reach_evidence TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, surface_id));
```

`component_path` must be a path in the current target manifest. One logical
handler reachable through two materially different protocols, entry points,
or state tuples is two surface rows. `surface_id` is stable within the image,
non-empty, and restricted to a conservative identifier alphabet so it remains
safe in commands and reports.

The device-state values are canonical lower-case forms of the parent design:

| Field | Allowed values |
|---|---|
| `lifecycle_required` | `factory-fresh`, `provisioned`, `bound-to-owner`, `cloud-registered`, `post-reset`, `unknown` |
| `posture_required` | `softap-setup`, `sta-lan`, `wan-exposed`, `ble`, `cloud-tunnel-only`, `unknown` |
| `auth_required` | `pre-auth`, `session`, `admin`, `local-shell`, `physical-uart`, `unknown` |
| `reachability` | `evidenced`, `refuted`, `unknown` |

`reach_evidence` is always non-empty. For `evidenced` or `refuted`, it cites
the static path that supports the verdict. For `unknown`, it states precisely
what the static tree cannot establish and the importer requires a linked open
unknown. An `unknown` value in any device-state field likewise requires a
linked unknown naming that field.

The artifact path and SHA-256 bind every row to the canonical imported result.
Host root paths and timestamps are excluded from artifact identity.

### 5.3 `cba_unknowns`

```sql
CREATE TABLE IF NOT EXISTS cba_unknowns (
    id TEXT PRIMARY KEY,
    image_id TEXT NOT NULL,
    component_path TEXT NOT NULL,
    surface_id TEXT,
    field TEXT NOT NULL,
    question TEXT NOT NULL,
    settling_observation TEXT NOT NULL,
    method TEXT NOT NULL,
    status TEXT NOT NULL,
    resolution TEXT,
    evidence TEXT,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')));
```

`field` is one of `dispatch`, `handler`, `lifecycle`, `posture`, `auth`, or
`reachability`. `method` is `static`, `emulate`, or `hardware`. `status` is
`open` or `resolved`.

An open unknown requires empty `resolution` and `evidence`. A resolved unknown
requires both. `surface_id` may be absent only when the question prevents the
agent from identifying a surface row at all, for example an unresolved service
wrapper. Otherwise it must resolve to a surface in the same image. The
component must exist in the current target manifest.

Unknown IDs are globally unique because later firmware phases will consume
them without always carrying the image in a human-facing reference.

### 5.4 Existing-table use

Stage 4d does not change the `cba_inventory` schema. Stage 4c already guarantees
that only target or legacy-unscoped triage populates it; explicit image-scoped
surface work refuses `legacy-unscoped`. The prepared target manifest and the
target inventory must agree path-for-path before dispatch.

Each imported unit writes one `cba_coverage` row with `phase='surface'`:

- `analyzed` covers both a mapped surface and an evidence-backed determination
  that the unit contributes no dispatch surface.
- `not_audited` requires a non-empty reason. `reason='budget'` retains the
  existing hard-gate behavior.

The detailed reason a unit has no surface remains in the canonical batch
artifact. The database coverage row is the bounded completion index, not a
second copy of agent prose.

`cba_services`, `cba_binfacts`, and `cba_components` are preparation hints.
They may prioritize work-list batches and enrich their metadata, but they do
not remove any target manifest unit from the denominator.

## 6. Preparation

The preparation mode is:

```text
audit.py surface --run RUN --root ROOT [--image-id ID]
                 [--batch-size N] [--json]
```

The command selects the unique acquired `target` image unless `--image-id` is
given. An explicit ID must still have role `target`. It refuses ambiguous
targets, `legacy-unscoped`, missing or empty manifests, and target inventory
that differs from the stored target manifest.

Preparation walks `ROOT` with the same fail-closed regular-file semantics as
triage and recomputes the complete path, size, kind, and SHA-256 manifest. The
live carved root must exactly match the stored manifest. Added, removed,
modified, unreadable, reclassified, symlinked, or nonregular paths cause a
named refusal before publication. This is deliberately stricter than Stage
4c's stored-manifest diff: an agent about to read a tree must be bound to the
bytes the database describes.

The work list contains every target manifest unit exactly once, ordered by
path and divided into deterministic bounded batches. Each unit carries only
bounded metadata: path, kind, size, SHA-256, matching ELF facts, matching
service evidence, and matching asserted component identity when present.
Missing hints remain absent; they are not guessed.

Preparation writes canonical JSON beneath a content-addressed directory such
as:

```text
RUN/files/surface/<worklist-sha256>/index.json
RUN/files/surface/<worklist-sha256>/batch-0001.json
```

The index names the image, manifest digest, batch size, unit count, ordered
batch paths, and batch SHA-256 values. Absolute carved-root paths and
timestamps are excluded from canonical identity. The human output is bounded
to image ID, unit and batch counts, digest, and index path.

Files are installed before the database transaction. If the current
`cba_surface_runs` row has the same manifest and work-list digest, preparation
is idempotent. If the manifest digest changed, preparation atomically clears
that image's old surface rows, unknowns, and `surface` coverage before replacing
the run row with `pending`. Failure preserves the prior database generation;
an unreferenced content-addressed work-list generation may remain.

## 7. Agent result contract

Each batch agent reads its rendered brief and batch file from disk and writes
one JSON result artifact. The dispatch message carries paths, not the batch
contents. A result contains:

- schema version, image ID, manifest digest, work-list digest, batch path, and
  batch digest;
- exactly one decision for every assigned unit and no unassigned unit;
- coverage state and reason per unit;
- zero or more surface rows rooted in assigned components; and
- zero or more unknown rows.

The result is invalid if a unit is omitted or duplicated, a surface names a
component outside the batch, a state value is invalid, evidence is blank, an
unknown link is dangling, or an `unknown` field lacks the corresponding open
unknown. A `not_audited` decision cannot publish surfaces.

Agent-written timestamps, database IDs, and artifact hashes are ignored or
rejected rather than trusted. The importer derives provenance and timestamps.

## 8. Atomic import

The record mode is:

```text
audit.py surface --run RUN --record RESULT.json [--replace] [--json]
```

The importer reads with a bounded file-size limit, parses strict JSON, checks
the result schema, verifies the referenced index and batch digests, confirms
the current `cba_surface_runs` manifest digest, and validates every row before
opening the publication transaction.

It canonicalizes the accepted result and installs it beneath
`RUN/artifacts/surface/` using its SHA-256. It then publishes, in one
transaction:

1. replacement or insertion of surfaces for the batch's assigned units;
2. replacement or insertion of unknowns for those units;
3. one `cba_coverage` decision per assigned unit; and
4. `cba_surface_runs.status='pending'`, because only the explicit completion
   gate may certify the whole current denominator.

Without `--replace`, any existing surface result for an assigned unit or an
existing `surface` coverage decision causes a refusal before mutation. With
`--replace`, only rows and coverage decisions belonging to the assigned batch
units are removed; other batches remain byte-for-byte unchanged.

Artifact installation precedes SQL publication. A database failure can leave
an unreferenced artifact but cannot leave mixed-generation SQL rows. A failed
replacement preserves all prior rows and run status.

## 9. Completion gate

The gate mode is:

```text
audit.py surface --run RUN --check [--image-id ID] [--json]
```

It fails when:

- no current prepared run exists for the target image;
- the current target manifest digest differs from the prepared digest;
- target manifest and target inventory paths disagree;
- a target unit has no `surface` coverage decision;
- any unit is `not_audited` because of budget;
- a surface has invalid state or artifact provenance;
- an unknown link is dangling or violates its open/resolved contract; or
- a surface contains `unknown` state without its linked settling question.

The gate does not fail merely because a well-formed unknown remains open.
Open unknowns are the honest output of static analysis and become inputs to
later `dive` and `decide` phases. Human output is aggregate and bounded:
manifest units, analyzed, not audited, surfaces, open unknowns, resolved
unknowns, and final status. `--json` emits the same bounded summary.

When all checks pass, the command atomically marks the run `complete` and sets
`completed_at`. A later manifest change makes the next check fail regardless
of that stored status.

## 10. Acquisition and retriage invalidation

Stage 4c makes acquisition replacement clear a changed image's manifest.
Stage 4d extends that same transaction for a changed target image: it also
clears that image's surface run, firmware surfaces, unknowns, and target
`surface` coverage. A failure rolls back both provenance replacement and all
invalidations.

Successful retriage remains upsert-only and cannot know that a file vanished.
Stage 4d does not silently repair that historical limitation. Preparation's
full live-root comparison refuses stale stored manifests and instructs the
operator to use a fresh image scope or run and retriage. This keeps stale rows
from becoming agent assignments.

## 11. Agent brief

`references/briefs/surface-brief.md` receives:

- run directory and database path;
- carved-root path;
- image ID and manifest digest;
- work-list index and one batch path;
- required result path; and
- the one-line R2 return contract.

The brief requires the agent to:

1. Decide every assigned unit; silence is not coverage.
2. Use service, ELF, component, imports, strings, configuration, and caller
   evidence as leads, not conclusions.
3. Trace each external entry point through its dispatcher to the concrete
   handler and cite the path and symbol, offset, key, or configuration line.
4. Locate authentication or authorization enforcement relative to the
   handler. Use `unknown`, never intuition, when ordering cannot be proved.
5. Record lifecycle, posture, authentication state, and reachability as data.
6. Create an unknown for every unresolved field, naming exactly what
   observation would settle it and whether that requires static work,
   emulation, or hardware.
7. Write only the result artifact; the deterministic importer owns SQL.

The brief explicitly forbids vulnerability hunting, severity assignment,
emulation, execution of target binaries, inferred listeners without evidence,
and turning an open unknown into a negative reachability claim.

## 12. CLI and error behavior

The `surface` verb has exactly one mode per invocation: prepare, record, or
check. Conflicting mode flags fail before opening the database. All expected
filesystem, JSON, schema, SQLite, provenance, and state errors become a named
`SurfaceError` or `DbError`, print once to stderr, and exit 1 without a
traceback. Success exits 0.

Read-side SQLite failures are translated at the module boundary so a corrupt
or incompatible database never escapes as an implementation traceback.
Filesystem traversal follows Stage 4c's direct `scandir` fail-closed behavior;
classification, iteration, stat, and read races are named and preserve the
prior durable generation.

No command prints all units, surfaces, or unknowns. Detailed content stays in
the work-list and result artifacts and is inspected through bounded database
reads.

## 13. Migration and compatibility

The three new tables are additive and use `CREATE TABLE IF NOT EXISTS`; no
existing primary key changes. They are added independently to `schema.sql` and
`db.TABLE_SPECS`, so `selftest` compares two independently built structures.

The frozen pre-Stage-3 and Stage-4b databases must still migrate, preserve all
existing rows and timestamps, accept the current schema, and pass a second
idempotent migration. Stage 4d adds no claim that an old unscoped firmware
database is a valid surface input; preparation requires a real acquired target
image and image-scoped manifest.

The importer performs cross-row semantic validation that generic
`audit.py put` cannot express. Generic writes still receive per-row enum and required
field validation, but the `surface --check` gate is authoritative for linkage
and completeness.

## 14. Verification

### Schema and validation

- Fresh schema contains all three tables with exact columns and primary keys.
- Both frozen baselines upgrade twice without row or timestamp loss.
- Every enum, required field, integer bound, artifact hash, and identifier
  rule has acceptance and refusal tests.
- `selftest` detects drift between SQL and `TABLE_SPECS`.

### Preparation

- A literal target tree produces deterministic manifest, index, and batches.
- Reordered filesystem enumeration produces byte-identical artifacts.
- Known ELF, service, and component hints enrich but never reduce the unit set.
- Ambiguous or wrong-role images, missing manifests, inventory disagreement,
  and empty trees refuse without mutation.
- Added, removed, modified, unreadable, reclassified, and raced paths fail
  before publication and preserve an existing surface generation.
- Same-input preparation is idempotent; a changed manifest invalidates only
  the affected target generation atomically.

### Import

- Complete literal results publish surfaces, unknowns, and coverage together.
- Missing, duplicate, or unassigned units and dangling links refuse.
- Every unknown state requires its corresponding open question.
- Open/resolved unknown contracts are enforced.
- Duplicate import refuses; `--replace` changes only assigned batch units.
- Injected artifact and SQL failures preserve the prior SQL generation.
- More than 200 units proves preparation and completion are not truncated by
  the bounded interactive read contract.

### Gate and CLI

- Partial batches, budget skips, stale manifests, bad provenance, and dangling
  unknowns fail the gate.
- A complete run with honest open unknowns passes.
- Human and JSON output are bounded and agree on counts and status.
- CLI failures print named errors with exit 1 and no traceback.

### Brief and integration

- Every placeholder renders, the R2 return contract is present, and each
  anti-inference instruction is pinned by a prose test.
- Installer, lint, EOL, manifest, statement-coverage, benchmark, and existing
  firmware corpus gates include the new files without weaker exclusions.
- Final documentation reconciles Stage 4c as merged, records measured Stage
  4d harness values, and names Stage 4e `hunt` as next.
- A fresh `make all` passes after the last documentation edit. `make mutate`
  remains opt-in and is not part of Stage 4d unless separately requested.

## 15. Documentation correction inherited from Stage 4c

The current merged `main` still contains present-state prose saying Stage 4c
is on `stage4c-firmware-diff` and awaiting integration. That contradicts HEAD
`bd4d4b9`. Stage 4d implementation begins by reconciling `progress.md`,
`SESSION_HANDOFF.md`, and `feature_lists.json` to the merged state. Historical
Stage 4c specifications, plans, derivations, and baselines remain intact except
where their own explicit status header is a present-state claim.

This correction is not credited as Stage 4d functionality and does not reuse
the pre-merge harness result as Stage 4d evidence.

## 16. Completion boundary

Stage 4d is complete when the three-table contract, deterministic preparation,
strict batch importer, completion gate, surface brief, CLI tests, feature
inventory, architecture/progress/handoff reconciliation, independent review,
and a fresh eight-gate `make all` result are present.

No recall, precision, or cost improvement is claimed until the deferred
milestone audit is deliberately run. The next vertical slice is Stage 4e
`hunt`, with separate non-transferable L-sink and L-dark budgets.
