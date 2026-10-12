# Stage 4c Firmware Diff Design

**Date:** 2026-10-12

**Status:** Draft for written-spec review

**Parent:** [`2026-10-04-audit-suite-design.md`](2026-10-04-audit-suite-design.md), §4

**Predecessor:** [`2026-10-08-stage4b-acquire-triage-design.md`](2026-10-08-stage4b-acquire-triage-design.md)

## 1. Decision

Stage 4c adds the firmware `diff` phase as a hybrid: deterministic code owns
the image-scoped file manifest and exact comparison, while an agent owns the
semantic question of what a vendor changed, why that change fixes the known
defect, and which sibling sites remain unfixed.

This is the boundary required by the parent design's “script sweep + agents”
work location. A filesystem-only diff would be reproducible but too shallow;
an agent-only diff would be semantic but not reproducible. The hybrid retains
both properties.

Stage 4c remains part of the shared `codebase-audit` tree. It does not create
the separate `firmware-audit` skill, settle the monorepo decision, or begin
Stage 4d `surface`.

## 2. Why this slice exists

The target-hunting plan calls patch-diff the highest-yield step: compare the
CVE-affected build with the fixed/latest build, learn the vendor's fix idiom,
then sweep the latest target for sibling sites the vendor did not repair.
Stage 4b created the target/diff-reference pair and recorded an already-carved
tree, but it deliberately stopped before comparing two images.

Stage 4b also left a known data-model limit: `cba_binfacts.path` and
`cba_services.name` are simple primary keys. Triaging a second image can
replace rows belonging to the first. Review of the actual writer exposes a
third collision not named by the open item: `cba_inventory.unit` is also
unscoped, so reference triage can overwrite the target's coverage denominator.
Stage 4c must close all three paths before it claims that two trees can share a
run.

## 3. Goals and non-goals

### Goals

1. Preserve target and diff-reference file, ELF, and service facts in one
   database without cross-image replacement.
2. Compare complete, image-scoped regular-file manifests and classify every
   path as added, removed, modified, or unchanged.
3. Store a durable diff summary plus every non-identical path in SQL, and write
   a deterministic file-backed manifest for unbounded agent consumption.
4. Give the diff agent the exact changed-component set, both carved roots, and
   an evidence contract for extracting and sweeping the vendor's fix idiom.
5. Reuse `cba_security_observations`, `cba_patterns`, `cba_pattern_hits`, and
   `audit.py sweep` instead of inventing a parallel pattern system.
6. Upgrade Stage 4b databases in place without losing their existing rows.
7. Keep the phase deterministic and zero-audit-cost until the operator chooses
   to spend the deferred benchmark budget.

### Non-goals

- Fetching firmware or selecting a CVE-affected version.
- Carving images; both root filesystems already exist.
- Treating a changed binary as a vulnerability.
- General dispatch/handler discovery (`surface`).
- General sink or dark-surface hunting (`hunt`).
- Emulation, live verification, kernel analysis, or bootloader analysis.
- A paid model audit or a new benchmark run.
- The separate `firmware-audit` skill tree or the Stage 5 alignment.

## 4. Data model

### 4.1 Image-scoped file manifests

Stage 4c adds one table populated by `triage`:

```sql
CREATE TABLE IF NOT EXISTS cba_firmware_files (
    image_id TEXT NOT NULL,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, path));
```

`path` is relative to the carved root and uses POSIX separators. The table
contains regular files only, matching Stage 4b's symlink-safe walk. Every file
gets a SHA-256, not only ELF binaries. This table is the comparison source;
`diff` never re-reads mutable carved trees and never infers equality from size.

Stage 4b's optional `--image-id` remains compatible. An unscoped triage uses
the reserved image scope `legacy-unscoped`. Such a manifest can be inspected,
but `diff` refuses to use it because it has no acquired-image provenance.

### 4.2 Collision-free ELF and service facts

The two Stage 4b tables become image-scoped:

```sql
CREATE TABLE IF NOT EXISTS cba_binfacts (
    image_id TEXT NOT NULL,
    path TEXT NOT NULL,
    machine TEXT NOT NULL,
    bits INTEGER NOT NULL,
    endian TEXT NOT NULL,
    elf_type TEXT NOT NULL,
    interp TEXT,
    needed TEXT,
    runpath TEXT,
    nx TEXT,
    pie TEXT,
    relro TEXT,
    canary TEXT,
    stripped TEXT,
    static TEXT,
    sha256 TEXT,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, path));

CREATE TABLE IF NOT EXISTS cba_services (
    image_id TEXT NOT NULL,
    name TEXT NOT NULL,
    start_source TEXT NOT NULL,
    exec_path TEXT,
    evidence TEXT NOT NULL,
    ports TEXT,
    ports_evidence TEXT,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (image_id, name));
```

Service names remain deduplicated within one image, not across the run. Rows
from a Stage 4b database whose `image_id` is NULL migrate to
`legacy-unscoped`. A later triage with a real image ID adds a separate row; it
does not rewrite the legacy evidence.

### 4.3 Target coverage stays target-only

`cba_inventory` remains the shared coverage denominator and is not made
firmware-specific. Triage behavior becomes role-aware:

- a recorded `target` image writes `cba_firmware_files` and mirrors its files
  into `cba_inventory`;
- a recorded `diff-reference` writes `cba_firmware_files`, `cba_binfacts`, and
  `cba_services`, but does not touch `cba_inventory`;
- `legacy-unscoped` preserves Stage 4b's single-tree behavior and writes the
  generic inventory.

This prevents reference-only files from becoming target audit obligations.
The diff itself reads only `cba_firmware_files`, so an old unscoped inventory
cannot corrupt its result. Stage 4c does not delete old `cba_inventory` rows
implicitly; destructive reconciliation of an already-used coverage
denominator requires an explicit later operation, not a schema upgrade.

### 4.4 Durable diff records

Two new tables hold the comparison:

```sql
CREATE TABLE IF NOT EXISTS cba_diffs (
    id TEXT PRIMARY KEY,
    reference_image_id TEXT NOT NULL,
    target_image_id TEXT NOT NULL,
    added_count INTEGER NOT NULL,
    removed_count INTEGER NOT NULL,
    modified_count INTEGER NOT NULL,
    unchanged_count INTEGER NOT NULL,
    manifest_path TEXT NOT NULL,
    recorded_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_diff_entries (
    diff_id TEXT NOT NULL,
    path TEXT NOT NULL,
    change TEXT NOT NULL,
    reference_kind TEXT,
    target_kind TEXT,
    reference_size INTEGER,
    target_size INTEGER,
    reference_sha256 TEXT,
    target_sha256 TEXT,
    PRIMARY KEY (diff_id, path));
```

`change` is one of `added`, `removed`, or `modified`. Unchanged files are
counted in `cba_diffs` but not copied into `cba_diff_entries`; their full
identity remains available in both manifests. This keeps the action set small
without losing the comparison denominator.

The diff ID is deterministic:

```text
diff-<first 16 hex characters of sha256(reference_image_id NUL target_image_id)>
```

The file-backed manifest is content-addressed as
`files/<diff-id>-<manifest-sha256-prefix>.json`. It contains the pair metadata,
four counts, and the sorted non-identical entries. Agents read that path rather
than receiving its contents in the dispatch, preserving R1. A content-addressed
generation lets replacement preserve the last complete manifest until the new
database transaction commits.

### 4.5 Validation

The database contract adds:

- `FIRMWARE_IMAGE_UNSCOPED = "legacy-unscoped"`;
- `DIFF_CHANGES = ("added", "removed", "modified")`;
- a `cba_diff_entries` validator that requires the target fields for `added`,
  reference fields for `removed`, and both sides for `modified`;
- non-negative integer validation for the four summary counts;
- primary-key declarations in `TableSpec`.

`connect()` currently validates tables and columns but not keys. Stage 4c adds
primary-key shape to the contract and rejects a database whose columns match
while its keys remain at the collision-prone Stage 4b shape. `selftest`
compares the schema-built keys with the independent `TableSpec` declarations.

## 5. Migration design

Adding columns cannot change a SQLite primary key. Stage 4c therefore keeps
the existing append-only `MIGRATIONS` tuple for additive columns and adds an
ordered, idempotent table-rebuild migration for the two Stage 4b tables.

For each old table, the migration runs in one transaction:

1. Detect the old primary key (`path` or `name`). A table already using the
   composite key is a no-op.
2. Rename the old table to a private temporary name.
3. Create the current table shape.
4. Copy every row, using `COALESCE(image_id, 'legacy-unscoped')`.
5. Drop the private table only after the copy succeeds.
6. Commit both table rebuilds together; any failure rolls the entire migration
   back.

A frozen `audit_core/baseline-stage4b.sql` records the exact pre-Stage-4c
shape. The installed `audit.py selftest` upgrades it, checks both composite
keys, verifies representative legacy rows survived, and then hands the result
to `connect()`. The existing pre-Stage-3 baseline remains frozen and continues
to test the older additive upgrade path.

Fresh databases receive the final definitions directly from `schema.sql` and
need no rebuild. Reapplying `audit.py init --timestamp <existing-ts>` remains
the supported in-place upgrade command.

## 6. Triage changes

`triage.run` retains its existing filesystem safety rules. Before the first
write it resolves the image row, role, and effective image scope, walks the
tree, reads ELF facts, hashes every regular file, and discovers evidenced boot
services. All database mutations then use the effective scope.

For a real acquired image, every binfact and service row requires that image
ID. For an omitted `--image-id`, all three firmware tables use
`legacy-unscoped`. This keeps repeat runs idempotent under the new composite
keys.

The summary remains compatible (`inventory_count`, `elf_count`,
`service_count`). `inventory_count` means files discovered in the carved tree,
not rows added to the target-only generic denominator.

## 7. Deterministic diff behavior

New module: `audit_core/firmware_diff.py`.

Its public operation accepts a connection, run directory, optional explicit
image IDs, and `replace`. It performs these checks before writing:

1. Resolve exactly one `target` and one `diff-reference`, unless both IDs were
   supplied explicitly.
2. Both rows exist, have the required roles, and name the same normalized
   vendor and model.
3. The image IDs differ and the acquired image hashes differ.
4. Both images have non-empty `cba_firmware_files` manifests.
5. The computed diff ID does not already exist unless `replace` is true.

Comparison is a merge over path-sorted manifests and is not subject to
`db.MAX_ROWS`; that bound protects orchestrator output, not internal work.
Classification is exact:

- only target has the path: `added`;
- only reference has the path: `removed`;
- both have the path and SHA-256 differs: `modified`;
- both hashes match: `unchanged`.

Rows and the JSON manifest are sorted by path. A replacement rewrites the
summary and that diff's entries as one transaction. The canonical manifest is
first written through a temporary sibling and atomically renamed to its
content-addressed generation. Only then does the database transaction point at
that complete file. A database failure can leave an unreferenced generation,
but it cannot replace the prior row or make the prior manifest incomplete. A
manifest failure occurs before database mutation.

## 8. CLI

```text
audit.py diff --run DIR
              [--target-image-id ID --reference-image-id ID]
              [--replace] [--json]
```

The two explicit IDs are all-or-nothing. They exist for a run containing more
than one model pair; omission is the common one-pair path. Success exits 0, a
named refusal exits 1, and argparse usage errors exit 2.

Human output is bounded to one summary line and the manifest path:

```text
diff <id>: 3 added, 2 removed, 7 modified, 941 unchanged
<run>/files/<id>-<manifest-sha256-prefix>.json
```

JSON output contains the diff ID, image IDs, four counts, and manifest path;
it does not inline every entry.

## 9. Agent brief

Stage 4c adds `references/briefs/diff-brief.md` with variables for:

- run directory and diff ID;
- target and reference carved roots;
- the file-backed manifest path;
- the detailed artifact path;
- the known CVE/advisory and patched component supplied by the orchestrator.

The brief requires the agent to:

1. Start from the known patched component; file churn elsewhere is not a
   vulnerability signal.
2. Establish the actual before/after mechanism with evidence from both builds.
3. Distinguish a security fix from compiler, packaging, timestamp, stripping,
   or configuration noise.
4. Record the fix idiom as an evidence-backed `cba_security_observations` row
   under a diff-specific group ID.
5. Search the target, not the vulnerable reference, for sibling sites that
   still match the unsafe side of the idiom.
6. Register an idiom in `cba_patterns` and use `audit.py sweep --record` only
   when it has an honest mechanical expression. Do not force a semantic
   condition into a misleading regex.
7. Record non-mechanical sibling analysis and each surviving lead as bounded
   observations with exact locations and evidence.
8. Write the detailed analysis to the artifact path and return only:

   ```text
   diff <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]
   ```

The agent does not turn every changed component into a finding, begin broad
hunting, map handler tables, emulate firmware, or modify either carved tree.

As with Stage 4b, an anti-absence derivation is written before the brief and
reconciled against `git diff -U0` after it is created.

## 10. Error handling and fail-closed rules

The phase refuses without partial output when:

- either role is missing or ambiguous;
- only one explicit image ID is supplied;
- an explicit ID has the wrong role;
- vendor/model differs across the pair;
- the two acquired images have the same hash;
- either triage manifest is empty;
- a diff exists and `--replace` was omitted;
- the database has Stage 4b keys and the in-place migration was not applied;
- a manifest cannot be written or atomically installed.

An empty difference is valid only when the image hashes differ and both
manifests are non-empty. It records zero added/removed/modified and a positive
unchanged count; this distinguishes “comparison completed” from “phase never
ran.”

## 11. Verification

All verification is zero-audit-cost.

### Schema and migration

- Fresh schema exposes both new tables and the three composite firmware keys.
- A frozen Stage 4b database upgrades in place and preserves representative
  NULL-scoped and real-image rows.
- A second migration is a no-op.
- `connect()` rejects correct columns with stale primary keys.
- A forced failure during the second rebuild rolls back the first.
- Both frozen baselines pass the installed selftest.

### Triage

- Target and reference trees containing the same relative ELF/service names
  retain two rows.
- Every regular file receives a correct SHA-256 manifest row.
- Reference triage leaves `cba_inventory` byte-for-byte unchanged.
- Target and legacy-unscoped triage retain the Stage 4b coverage behavior.
- Repeat triage is idempotent within one image scope.
- Existing symlink, empty-tree, zero-ELF, malformed-ELF, and read-race tests
  remain green.

### Diff

- Literal fixtures prove added, removed, modified, and unchanged counts.
- More than 200 files proves comparison is not truncated by the bounded read
  contract.
- Output and manifest ordering are deterministic.
- Role ambiguity, half-explicit IDs, cross-model pairs, identical image
  hashes, missing manifests, and duplicate writes all fail before mutation.
- `--replace` removes stale entries belonging to the prior result.
- Injected database and manifest failures leave no mixed-generation result.
- Human and JSON CLI output remain bounded and exit codes follow the contract.

### Agent and integration contracts

- The brief renders every variable, carries the R2 return contract, and pins
  each anti-absence instruction.
- The manifest, installer, EOL, lint, and coverage gates include the new files
  without weakening their contracts.
- The read-only firmware corpus consistency test verifies image-scoped
  binfacts/services against their manifests where the corpus is available.
- `make all` passes after final documentation reconciliation. `make mutate`
  remains opt-in and is not part of Stage 4c unless separately requested.

## 12. Completion boundary

Stage 4c is complete when the collision-free migration, image-scoped manifest,
deterministic `diff` command, agent brief, tests, feature inventory,
architecture/progress/handoff updates, and a fresh eight-gate `make all` result
are present. No recall or cost improvement is claimed until the deferred
milestone audit is deliberately run.

The next vertical slice is Stage 4d `surface`: dispatch and handler tables,
authentication boundaries, device state, and reachability evidence.
