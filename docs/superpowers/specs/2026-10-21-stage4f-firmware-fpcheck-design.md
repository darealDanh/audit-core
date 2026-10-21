# Stage 4f design: provenance-bound firmware false-positive review

**Date:** 2026-10-21

**Parent:** [`2026-10-04-audit-suite-design.md`](2026-10-04-audit-suite-design.md), §4

**Predecessor:** [`2026-10-19-stage4e-firmware-hunt-design.md`](2026-10-19-stage4e-firmware-hunt-design.md)

## 1. Decision

Stage 4f implements firmware `fpcheck` as a static, adversarial review of the
complete candidate set produced by a completed Stage 4e hunt generation. It
deduplicates candidates across L-sink and L-dark, preserves useful observations
found while refuting candidates, and publishes reviewed firmware findings.

The phase uses dedicated firmware tables. It does not write generic
`cba_findings` or `cba_fp_verdicts`. Those tables cannot preserve the image,
hunt-generation, lane, candidate, batch, and review provenance required here
without flattening or encoding firmware-specific state. Promotion into the
generic finding model is deferred to the later firmware `decide` boundary.

The deterministic core owns preparation, parsing, validation, artifact
installation, SQL publication, deduplication checks, finding derivation, and the
only completion transition. Review agents read immutable assignments and write
bounded JSON; they never write SQL.

Stage 4f remains in the shared `codebase-audit` tree. It is another vertical
slice of the future `firmware-audit` skill, not a separately packaged skill.

## 2. Why this slice exists

Stage 4e records candidate hypotheses with input-to-operation traces, checked
mitigations, state evidence, impact hypotheses, and blockers. A hunt candidate
is deliberately not yet a finding. It may misread attacker control, overlook a
guard, duplicate the same root cause through two lanes, or describe an impact
already granted by the stated attacker position.

The existing source-code `fpcheck` workflow supplies the right adversarial
method, including the attacker-advantage test, Hard Exclusions, Precedent rules,
Capability Validity rules, and the pivot rule. Firmware review needs the same
reasoning but a different ownership model: candidates are image- and
generation-scoped, two lanes may independently rediscover one root cause, and
refutations can expose protocol, trust, state, or memory mechanisms worth
retaining for later work.

## 3. Goals and non-goals

### Goals

1. Require both Stage 4e lanes to be complete against one still-current image,
   manifest, surface snapshot, and pair of hunt worklists.
2. Snapshot the exact union of L-sink and L-dark candidates, including their
   canonical Stage 4e artifact provenance.
3. Assign every candidate exactly once to a deterministic review batch.
4. Require exactly one adversarial verdict for every assigned candidate.
5. Apply the attacker-advantage test first and preserve the rule, mitigation,
   and source-evidence basis for every verdict.
6. Reject false positives unless they identify the refuting mechanism and the
   useful observation that mechanism enables, including an evidence-backed
   statement that no attacker-controlled path was found when that is the result.
7. Deduplicate across lanes and root causes without silently merging ambiguous
   reviewer output.
8. Publish canonical reviewed firmware findings only from surviving,
   fully-covered TRUE_POSITIVE groups.
9. Keep preparation, replacement, invalidation, and completion image-scoped,
   atomic, resumable, and independently checkable.
10. Preserve bounded output, deterministic artifacts, installed-skill behavior,
    and the repository's full harness contract.

### Non-goals

Stage 4f does not:

- execute, emulate, exploit, or weaponize firmware;
- fetch or carve images, inspect new kernel or bootloader surfaces, or change
  the Stage 4e hunt denominator;
- settle hardware- or runtime-only blockers;
- assign final severity or CVSS;
- claim live reachability or rung-4 proof;
- write generic `cba_findings` or generic `cba_fp_verdicts`;
- compose exploit chains, make acquisition decisions, or write disclosure
  reports;
- create the separate `firmware-audit` tree or settle the monorepo/submodule
  decision;
- run a paid audit benchmark or the opt-in mutation sweep.

## 4. Alternatives considered

### 4.1 Dedicated firmware review tables — selected

Dedicated run, receipt, verdict, pivot, and reviewed-finding tables preserve the
full ownership chain and let later firmware phases consume a coherent model.
The cost is additional schema and validation code, but it avoids migrations to
generic finding interfaces used by existing source audits.

### 4.2 Extend generic findings and verdicts — rejected

This reuses existing names but requires invasive migrations and encoded IDs for
image, lane, generation, and candidate ownership. It also invites generic
reporting code to treat statically reviewed firmware hypotheses as final
findings before the firmware `decide` phase.

### 4.3 Artifact-only review followed by one import — rejected

This minimizes schema work but makes partial progress, exact coverage,
replacement, invalidation, and crash recovery difficult to audit. Durable batch
receipts and SQL-owned verdicts are required.

## 5. Preconditions and identity

### 5.1 Repository-state prerequisite

The Stage 4e merge left branch-state prose in `progress.md`,
`SESSION_HANDOFF.md`, and `feature_lists.json` saying integration was pending.
Execution begins by reconciling those present-state claims on the Stage 4f
branch and then running a fresh `make all`. Historical Stage 4e specifications,
plans, derivations, and baselines remain unchanged.

### 5.2 Completed hunt prerequisite

Preparation selects one target image by the existing unique-target/explicit-ID
rules. It requires:

- both `cba_hunt_runs` rows, one for each lane;
- both rows marked complete;
- identical image, manifest, and surface snapshot identities;
- current canonical worklist indexes, batches, receipts, coverage, candidates,
  and result artifacts passing the Stage 4e completion verification;
- no active caller transaction.

The deterministic core exposes a read-only Stage 4e verified-snapshot helper
that also checks the live carved root. Stage 4f therefore does not reproduce
only part of the hunt gate, omit filesystem drift, or change Stage 4e state.

### 5.3 Candidate identity

A candidate is identified by `(image_id, lane, candidate_id)`. A raw
`candidate_id` is not globally unique and must never be used without its lane.
The Stage 4f candidate snapshot includes every current Stage 4e candidate in
canonical lane-and-ID order plus the Stage 4e artifact path and digest that own
it.

`candidate_snapshot_sha256` is the SHA-256 of canonical JSON containing:

- schema version;
- image ID;
- manifest and surface snapshot digests;
- both lane worklist digests;
- the complete canonical candidate projection;
- no timestamps, host roots, or mutable absolute paths.

The generation identity is derived from these same inputs. Candidate-free hunts
produce a valid, stable empty snapshot rather than an absent generation.

## 6. Deterministic preparation and batching

The public preparation interface is:

```python
fpcheck.prepare(
    con: sqlite3.Connection,
    run_dir: str | pathlib.Path,
    root: str | pathlib.Path,
    *,
    image_id: str | None = None,
    batch_size: int = 20,
) -> PreparationSummary
```

`batch_size` accepts integers from 1 through 200. Preparation writes immutable
canonical worklists beneath:

```text
RUN/files/firmware-fpcheck/<generation>/
├── index.json
├── batch-0001.json
└── ...
```

Each batch carries the assigned Stage 4e candidate records, their owning
artifacts, related surface context, unresolved blockers, and deterministic
similarity hints. The worker receives the verified carved root separately from
the worklist. Absolute carved-root paths and timestamps are excluded from
canonical artifacts.

### 6.1 Similarity hints

The core computes a priority-only signature from a canonical normalized
projection of:

- image ID and component path;
- bug class;
- dangerous operation;
- surface IDs;
- input-to-operation trace evidence.

Equal signatures form an indivisible cluster so obvious L-sink/L-dark
rediscoveries reach the same reviewer. Clusters are ordered by signature and
then `(lane, candidate_id)`. Requested batch size is a target, not permission to
split an equal-signature cluster; a batch may exceed it. A cluster or batch may
never exceed 1,000 candidates, and preparation refuses rather than emitting an
unreviewable assignment.

The signature is not a verdict and cannot merge findings. Reviewers may split a
suggested group or join candidates from different suggested groups by supplying
evidence-backed root-cause keys.

### 6.2 Empty generations

A candidate-free hunt produces one canonical empty batch. Its imported receipt
proves the reviewer saw the empty assignment and keeps the same prepare/record/
check state machine as candidate-bearing generations.

Preparation installs all artifacts first, revalidates the completed hunt while
holding the SQL publication lock, and then publishes one pending run row. The
same inputs are idempotent. Changed inputs invalidate only the selected image's
prior Stage 4f SQL state before the new pending row is written.

## 7. Agent result contract

Results are UTF-8 JSON objects with duplicate keys rejected. Raw input is
limited to 8 MiB; canonical output must also fit within 8 MiB. The top-level
identity binds:

- schema version;
- image ID;
- candidate snapshot digest;
- worklist and batch paths and digests;
- exactly one decision per assigned `(lane, candidate_id)`.

Every decision records:

- `lane` and `candidate_id`;
- `verdict`: `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `DUPLICATE`;
- an adversarial reason grounded in the candidate and source evidence;
- the attacker-advantage conclusion;
- canonical rule identifiers applied;
- mitigation analysis;
- review confidence from 0 through 10.

### 7.1 TRUE_POSITIVE

A true positive additionally requires:

- a non-empty `root_cause_key` using the bounded identifier grammar;
- a concise root-cause statement;
- deduplication evidence explaining why the candidate belongs to that key;
- reviewed attacker position, data flow, impact hypothesis, component paths,
  and surface IDs;
- no duplicate target and no false-positive pivot.

Exact `root_cause_key` equality is the only automatic grouping rule. Differing
keys remain separate findings even if similarity hints match. This favors a
visible under-merge over a silent false merge.

### 7.2 FALSE_POSITIVE

A false positive additionally requires:

- the specific refuting mechanism;
- a unique pivot ID;
- what that mechanism enables or an evidence-backed statement that no
  attacker-controlled path was identified;
- pivot evidence and the affected component path;
- no root-cause key and no duplicate target.

The pivot is durable review output, not an automatically promoted candidate or
finding.

### 7.3 DUPLICATE

A duplicate additionally requires:

- the target lane and candidate ID;
- evidence that both candidates share a root cause;
- no root-cause key of its own and no false-positive pivot.

The target may be in another batch but must belong to the same candidate
snapshot. Final validation resolves duplicate chains transitively. Every chain
must end at a TRUE_POSITIVE candidate. Missing targets, self-targets, cycles,
cross-image references, or chains ending at FALSE_POSITIVE are refused.

## 8. Durable state

### 8.1 `cba_firmware_fp_runs`

One current row per image:

- `image_id` primary key;
- manifest, surface snapshot, L-sink worklist, L-dark worklist, candidate
  snapshot, and fpcheck worklist SHA-256 values;
- worklist path;
- candidate and batch counts;
- `status` in `pending|complete`;
- prepared and completed timestamps.

### 8.2 `cba_firmware_fp_receipts`

One row per imported batch, keyed by image, candidate snapshot, and batch path:

- worklist and batch provenance;
- canonical result path and SHA-256;
- assigned-candidate, verdict, true-positive, false-positive, duplicate, and
  pivot counts;
- importer-owned timestamp.

An empty batch still produces a receipt.

### 8.3 `cba_firmware_fp_verdicts`

One row per candidate, keyed by image, lane, and candidate ID:

- candidate snapshot and batch ownership;
- verdict, reason, attacker-advantage conclusion, canonical rule list,
  mitigation analysis, and confidence;
- root-cause key, root-cause statement, and deduplication evidence for true
  positives;
- duplicate target lane and candidate ID for duplicates;
- refuting mechanism and pivot ID for false positives;
- reviewed attacker position, data flow, impact, components, and surfaces where
  applicable;
- canonical artifact path and digest;
- importer-owned timestamp.

Columns that do not apply to a verdict are NULL and are rejected if populated.

### 8.4 `cba_firmware_pivots`

One row per false-positive pivot, keyed by image and pivot ID:

- candidate snapshot, source lane, and source candidate ID;
- component path;
- refuting mechanism;
- enabled observation;
- evidence;
- canonical artifact path and digest;
- importer-owned timestamp.

Each false positive owns exactly one pivot and each pivot has exactly one source
verdict.

### 8.5 `cba_firmware_findings`

One row per completed true-positive root-cause group, keyed by image and finding
ID:

- candidate snapshot and root-cause key;
- deterministic canonical candidate lane and ID;
- canonical JSON arrays of every contributing candidate, lane, component path,
  and surface ID;
- reviewed title, bug class, root cause, attacker position, data flow, impact
  hypothesis, and evidence summary;
- review confidence and evidence rung;
- deterministic finding artifact path and SHA-256;
- derived timestamp.

The finding ID is derived deterministically from the image ID, candidate
snapshot, and root-cause key. No severity, CVSS, live-verification claim, PoC,
or generic finding ID is stored in Stage 4f.

All tables receive full `db.TableSpec` validation. Canonical JSON cells use
strict compact UTF-8 encoding. Counts are non-negative integers, booleans are
not accepted as integers, digests are lowercase SHA-256, paths are relative
where the contract says they are, and all bounded identifiers and text fields
use the existing defensive validation conventions.

## 9. Atomic record and replacement

The public import interface is:

```python
fpcheck_results.record(
    con: sqlite3.Connection,
    run_dir: str | pathlib.Path,
    result_path: str | pathlib.Path,
    *,
    replace: bool = False,
) -> ImportSummary
```

Recording performs this sequence:

1. bounded strict parse;
2. validate identity, exact batch membership, verdict semantics, Stage 4e
   candidate ownership, and current pending Stage 4f generation;
3. canonicalize and content-address the result;
4. install it beneath
   `RUN/artifacts/firmware-fpcheck/<generation>/<result-sha256>/result.json`;
5. begin an immediate transaction;
6. repeat all mutable provenance and ownership checks;
7. for replacement, delete only the selected image/generation/batch's receipt,
   verdicts, and pivots;
8. insert the receipt, verdicts, and pivots and leave the run pending;
9. commit.

A duplicate import refuses unless `replace=True`. Replacement never changes
sibling batches, images, retained immutable artifacts, or completed reviewed
findings from another image. Any failure preserves prior SQL byte-for-byte; an
artifact installed before a failed transaction may remain unreferenced.

## 10. Completion and finding derivation

The public completion interface is:

```python
fpcheck.check(
    con: sqlite3.Connection,
    run_dir: str | pathlib.Path,
    root: str | pathlib.Path,
    *,
    image_id: str | None = None,
) -> FpcheckSummary
```

Completion revalidates:

- the exact current completed Stage 4e snapshot;
- exact live-root path, kind, size, and SHA-256 agreement with the current
  selected-image manifest;
- canonical worklist index and every batch;
- one canonical receipt per batch;
- exact verdict coverage with no missing, extra, or duplicated candidate;
- receipt counts against canonical results and SQL rows;
- verdict semantics and artifact provenance;
- false-positive/pivot one-to-one ownership;
- valid transitive duplicate resolution;
- true-positive grouping by exact root-cause key;
- no batch or artifact drift.

For every true-positive group, deterministic code selects the lexicographically
first `(lane, candidate_id)` as the canonical candidate, derives the finding,
and writes a canonical `findings.json`. The artifact is installed before an
immediate transaction. While holding the lock, completion repeats all mutable
checks, replaces only the selected image's derived findings, and marks the run
complete with one commit.

An empty, fully receipted generation completes with zero findings. Rechecking a
complete unchanged generation is idempotent and verifies rather than blindly
trusting existing findings. Failed checks do not alter status, timestamps, or
findings.

## 11. Invalidation

`fpcheck.invalidate(con, image_id, commit=False)` deletes only the selected
image's Stage 4f run, receipts, verdicts, pivots, and reviewed findings inside
the caller's transaction.

It is invoked when selected-image state changes at any ownership boundary that
can change the reviewed candidate snapshot:

- acquisition provenance;
- target triage manifest;
- surface preparation or results;
- hunt preparation, imported results, or completion evidence.

Byte-identical/idempotent upstream operations preserve Stage 4f. Reference
image changes do not clear unrelated target review state. Overlapping raw paths
across images never transfer ownership. Invalidation failure rolls back the
upstream change and all dependent deletions.

## 12. CLI and installed worker contract

`audit.py fpcheck` is the deterministic firmware command beneath the existing
prose-level `fpcheck` workflow.

### Prepare

```text
audit.py fpcheck --run RUN --prepare --root ROOT [--image-id ID] [--batch-size N] [--json]
```

### Record

```text
audit.py fpcheck --run RUN --record RESULT [--replace] [--json]
```

### Check

```text
audit.py fpcheck --run RUN --check --root ROOT [--image-id ID] [--json]
```

Modes and their arguments are mutually validated before database I/O. Usage
errors exit 2. Expected domain, filesystem, and SQLite failures exit 1 without a
traceback. SQLite details are replaced by one fixed diagnostic; other expected
diagnostics escape control/non-ASCII text and are capped at 512 ASCII
characters plus a newline. Success exits 0 and prints only aggregate counts and
artifact paths, never raw candidate evidence.

The installed worker brief:

- applies the attacker-advantage test first;
- applies the existing Hard Exclusions, Precedent, Capability Validity, and
  Marginal Gain rules;
- rereads cited firmware/source evidence rather than trusting the hunt claim;
- receives the separately verified carved root and never persists its absolute
  host path in a result;
- compares the assigned similarity cluster across both lanes;
- emits only the strict result JSON;
- performs no SQL writes, execution, emulation, exploitation, severity call,
  or generic promotion;
- checkpoints as PARTIAL rather than omitting an assigned candidate when the
  budget is exhausted;
- returns one bounded status line.

The `SKILL.md` router distinguishes ordinary source-code `fpcheck` orchestration
from firmware Stage 4f and points firmware work at the new brief and CLI.

## 13. Testing and verification

Implementation follows test-driven development. Required coverage includes:

1. schema creation, migration from every maintained baseline, validators, and
   idempotent schema application;
2. completed-hunt snapshot extraction without mutating Stage 4e state;
3. deterministic candidate snapshots, similarity clusters, batches, empty
   generations, and overlapping image/path ownership;
4. strict JSON parsing, duplicate keys, invalid UTF-8, raw and canonical size
   limits, booleans-as-integers, non-finite numbers, path traversal, and
   canonical serialization;
5. every verdict-specific required/forbidden field combination;
6. missing/extra/duplicate candidates, stale provenance, artifact drift, and
   foreign image/lane/candidate references;
7. cross-lane duplicates, transitive duplicate chains, self-targets, missing
   targets, cycles, false-positive targets, and conflicting root-cause keys;
8. false-positive pivot ownership and useful no-attacker-path observations;
9. first import, duplicate refusal, batch-scoped replacement, candidate-free
   receipts, sibling preservation, and injected read/install/SQL/commit
   failures;
10. exact completion coverage, canonical finding derivation, zero-finding
    completion, idempotent recheck, concurrency changes, and rollback;
11. acquisition, triage, surface, and hunt invalidation with same-input
    preservation and cross-image isolation;
12. CLI modes, exit codes, bounded diagnostics, JSON/human summaries, worker
    brief rendering, installed copies, routing, and harness counts;
13. documentation and `feature_lists.json` reconciliation.

Before Stage 4f is called complete, the final tree must satisfy the repository
completion contract: reconcile present-state documentation and inventory, name
the real next stage and inherited limits, run a fresh `make all` after the final
documentation changes, and record measured summaries. `make mutate` remains an
explicit, separate long-running operation.

## 14. Known limitations and later boundaries

- Root-cause keys are reviewer judgments. Exact equality safely groups them;
  differing keys remain separate, so Stage 4f may visibly under-deduplicate but
  will not silently merge unrelated candidates.
- Static review cannot settle runtime, emulation, or hardware blockers. Those
  remain explicit evidence gaps for later work.
- Triage remains upsert-only, and Stage 4d's retained-orphan scan scaling
  limitation is inherited through the current hunt verification path.
- The Asus golden and the monorepo/submodule decision remain prerequisites for
  the overall Stage 4 milestone and restructure, not for implementing this
  slice.
- Paid semantic quality remains unmeasured until the deferred milestone
  benchmark. Deterministic harness success proves contracts, not audit recall.

## 15. Completion boundary

Stage 4f is complete when an installed user can prepare review work from a
verified completed hunt, dispatch the firmware fpcheck brief, atomically record
strict results, prove exact candidate coverage and valid deduplication, preserve
false-positive pivots, and complete a canonical set of dedicated reviewed
firmware findings with the full harness green.

The next firmware slice after Stage 4f is `chain`: compose reviewed primitives
into evidence-backed end-to-end exploit chains without promoting them into
generic findings prematurely.
