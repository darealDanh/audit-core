# Architecture

How this repository is put together, and why it is put together that way.
For *what has been built and what has not*, read [`progress.md`](progress.md).
For *how to pick the work back up*, read
[`SESSION_HANDOFF.md`](SESSION_HANDOFF.md).

---

## 1. The thing being built

This repository currently ships **one skill, made of two different kinds of
material**. Its shared core now also contains the first eight vertical phases
of the future `firmware-audit` skill (`qualify`, `acquire`, `triage`, `diff`,
`surface`, `hunt`, `fpcheck`, and `chain`); the separate firmware skill tree
does not exist yet.

| Material | What it is | Who executes it |
|---|---|---|
| **Prose** — `SKILL.md`, `workflows/`, `references/` | Instructions an LLM reads and follows | A model, at audit time |
| **Code** — `audit.py`, `audit_core/` | A stdlib-only Python CLI the prose calls | A shell, at audit time |

Everything hard about this project comes from that split. A bug in the code
fails loudly: a test goes red, a verb exits non-zero. A bug in the prose fails
*silently* — a model reads an instruction that is no longer there, does
something slightly worse, and the only evidence is a vulnerability nobody
found. The project's whole verification apparatus exists to make prose defects
as visible as code defects:

- `audit.py lint-skill` checks shipped prose against the economics contract.
- `tests/test_workflow_prose.py` and `tests/test_brief_templates.py` assert
  that specific instructions are present, by content, not by line number.
- **Anti-absence derivations** (`docs/superpowers/derivations/`) enumerate every
  intended prose change *before* it is made and reconcile against
  `git diff -U0` after. This exists because rewriting shipped prose lost
  instructions five times out of five in Stage 1.
- The **line-ending contract** (§7) keeps prose diffs small enough to read.

**Nothing in this repository is a web service, and nothing reaches the
network.** `audit_core` is stdlib-only by contract; `pyproject.toml` declares
`dependencies = []` and `requires-python = ">=3.10"`.

---

## 2. Repository layout

```
SKILL.md                  the skill's entry document (CRLF)
workflows/                one file per phase: recon, deploy, audit, fpcheck,
                          verify, report, source (+ an archived v1 pipeline)
references/               phase deep-dives, lessons learned, dispatch brief
                          templates under references/briefs/
claude/commands/          Claude Code launcher stubs

audit.py                  the CLI: 29 verbs, argparse, one cmd_* per verb
audit_core/               the logic the verbs are thin wrappers over
audit_core/schema.sql     the audit.db schema
audit_core/baseline-pre-stage3.sql
                          a frozen pre-Stage-3 database, used by selftest to
                          prove MIGRATIONS actually repairs an old run

install.sh / install.ps1  per-client installers
scripts/                  the verification harness (§8) - never installed
tests/                    pytest suite; tests/goldens/ holds adjudicated
                          reference finding sets
docs/superpowers/specs/   the design spec - the binding authority
docs/superpowers/plans/   one implementation plan per stage
docs/superpowers/derivations/
                          anti-absence derivations for prose edits
docs/baselines/           measurements and gate procedures, never edited in
                          place; a correction is a new dated file
.github/workflows/ci.yml  runs the same gates as `make check`
```

---

## 3. The phase pipeline

Seven phases, each a file in `workflows/`. The orchestrator runs them in order;
most transitions are user-gated.

```
recon ──> deploy ──> audit ──> fpcheck ──> (fork per finding) verify ──> report
  │                                                                        
  └── source: recon → audit → fpcheck → report, unattended, no live instance
```

- **recon** — detect the source, split it into feature groups, dispatch one
  mapping subagent per group, write a resume note.
- **deploy** — stand up a live instance. Skipped in source-only mode.
- **audit** — ingest prior CVEs to find patch-bypass surfaces, then one
  deep-audit subagent per group.
- **fpcheck** — static false-positive review. No live testing.
- **verify** — runs in a *forked* conversation, per finding, with a live PoC
  and an adversarial review. Refuses to run without explicit finding IDs.
- **report** — the lean maintainer format. Per-finding in the fork for live
  runs; one consolidated report for source-only runs.
- **source** — a composite that chains four phases unattended, auto-resolving
  every gate. Every finding it writes is `verified='source-only'`.

The orchestrator fans out to subagents in recon, audit and fpcheck. That
fan-out is where the money goes, and it is what the economics contract governs.

---

## 4. The economics contract (R1–R6)

The spec's §5 rules, enforced in `SKILL.md` and checked by `lint-skill`:

| Rule | What it requires | Where it lives |
|---|---|---|
| **R1** | The orchestrator never holds raw material — subagents read files, the orchestrator reads summaries | `audit_core/extract.py` |
| **R2** | Subagents return a fixed contract, not prose | `SKILL.md`, brief templates |
| **R3** | A context ceiling with checkpoint-restart, so a run survives its own length | `audit_core/ceiling.py` |
| **R4** | An MCP preflight that names only the servers a run needs | `audit_core/preflight.py` |
| **R5** | Reusable logic is an `audit.py` verb, never an inline heredoc | `audit.py` |
| **R6** | Dispatch briefs are files, not prose pasted into a prompt | `audit_core/briefs.py` |

R5's dependency is easy to miss and expensive to rediscover: `install.sh`
originally copied only the prose, so the moment a workflow invoked `audit.py`
every installed copy broke. The installer now copies `audit.py` and
`audit_core/` too, and substitutes `__SKILL_DIR__` so each client's copy calls
its own.

---

## 5. State model

One SQLite database per run, at `reports/audit-<timestamp>/audit.db`, created
by `audit.py init`.

**Thirty-one tables under contract**, all prefixed `cba_`:

| Group | Tables |
|---|---|
| Recon | `cba_sources`, `cba_feature_groups`, `cba_attack_surface`, `cba_security_observations` |
| Audit | `cba_known_findings`, `cba_findings` |
| FP-check | `cba_fp_verdicts` |
| Coverage | `cba_inventory`, `cba_coverage` |
| Sweep | `cba_patterns`, `cba_pattern_hits` |
| Control | `cba_checkpoints` |
| Stage 3 | `cba_components`, `cba_chains` |
| Firmware | `cba_images`, `cba_binfacts`, `cba_services` |
| Firmware diff | `cba_firmware_files`, `cba_diffs`, `cba_diff_entries` |
| Firmware surface | `cba_surface_runs`, `cba_firmware_surfaces`, `cba_unknowns` |
| Firmware hunt | `cba_hunt_runs`, `cba_hunt_receipts`, `cba_hunt_candidates` |
| Firmware review | `cba_firmware_fp_runs`, `cba_firmware_fp_receipts`, `cba_firmware_fp_verdicts`, `cba_firmware_pivots`, `cba_firmware_findings` |

> `selftest` reports **32** tables in `schema.sql` against **31** under
> contract. The extra table is `sqlite_sequence`, which SQLite creates by itself
> for `AUTOINCREMENT`. Nothing is missing.

**Access is validated and bounded.** `audit_core/db.py` holds the shared
`TABLE_SPECS` (columns, required columns, validators) and validated row helpers;
phase modules own transactional publication and invalidation SQL. The row helpers
refuse a row that does not satisfy its contract — a verdict outside the enum, a
component kind that is not a kind, a chain that claims completeness it has not earned, an
identity with fewer than `MIN_EVIDENCE_CHARS` of evidence.

**Migrations are first-class.** SQLite has no `ALTER TABLE … ADD COLUMN IF NOT
EXISTS`, and `CREATE TABLE IF NOT EXISTS` is a no-op against a table that
already exists — so adding a column to `schema.sql` repairs *nothing* on a
database that exists already. `db.MIGRATIONS` carries the four column
additions; Stage 4c also rebuilds legacy firmware tables together in one
transaction. `cba_binfacts` uses `(image_id, path)` and `cba_services` uses
`(image_id, name)`, with absent legacy image IDs mapped to `legacy-unscoped`.
`connect()` rejects stale columns or primary keys and names the public remedy:
rerun `audit.py init --timestamp <existing timestamp>` for the same project.
`selftest` proves both the frozen pre-Stage-3 upgrade and the Stage 4b key
rebuild, including acceptance by `connect()`. Existing facts survive; old
databases need triage of both acquired images to populate the new manifests.

**`put(replace=True)` merges; it does not replace.** A bare
`INSERT OR REPLACE` drops every column the caller did not pass. That destroyed
`final_id`, `merged_into` and `final_severity` on a pivot — columns a
*different* workflow step writes. `db.put` now reads the stored row and merges.

---

## 6. `audit_core` module map

| Module | Lines | Responsibility |
|---|---|---|
| `db.py` | 1401 | Validated, bounded access to a run's `audit.db`; schema contracts, migrations, merge-on-replace, image-qualified firmware-unit identity, and Stage 4f/4g review and chain row validation. |
| `coverage.py` | 275 | Coverage accounting: the denominator, not a feeling. Inventory vs analyzed, a reason for every gap, and a gate. |
| `chains.py` | 246 | Propose cross-group finding pairs that compose into an exploit chain; record composed ones. |
| `extract.py` | 231 | Extract once, fan out without a cap (R1). |
| `transcript.py` | 231 | Parse a Claude Code JSONL session into typed records. |
| `budget.py` | 172 | Session economics: epochs, prefix, growth, attribution. |
| `bench.py` | 341 | Score a run against a golden set: recall, severity agreement, weighted recall, precision, coverage, cost per match. |
| `readings.py` | 77 | A measurement that can be a value, `absent` (no table) or `empty` (table, no rows) - never a silent `0`. |
| `indicators.py` | 264 | The four deterministic leading indicators and their dated snapshots. |
| `rerate.py` | 191 | Advisory report of findings whose severity disagrees with their own evidence. Stores nothing. |
| `qualify.py` | 369 | The hard GO/NO-GO gate for a firmware target: three filters (not strip-mined, RCE-rich, still supported), each failing closed, scored against `_intel/target-scores.csv`. |
| `elf.py` | 265 | Pure, bounded ELF facts; strict I/O mode lets the shared scanner fail closed on read races. |
| `acquire.py` | 88 | Record local firmware provenance; atomically invalidate changed-image manifests and dependent target surface state. |
| `triage.py` | 206 | Inventory an already-carved rootfs, attach ELF facts, and record boot services with source-line evidence. |
| `firmware_diff.py` | 223 | Compare stored image-scoped manifests by path and SHA-256, persist all changed paths atomically, and install deterministic content-addressed JSON. |
| `firmware_tree.py` | 101 | Shared fail-closed regular-file traversal, hashing, classification, and retained ELF facts for triage and surface. |
| `surface.py` | 582 | Exact-root verification, deterministic content-addressed batches, image-owned generation invalidation, and the sole completion transition. |
| `surface_results.py` | 458 | Strict bounded parsing, qualified coverage ownership, conservative raw-row refusal, and atomic batch-owned import. |
| `hunt.py` | 455 | Bind two complete lane worklists to verified surface evidence, invalidate image-owned hunt state, gate receipts and full-denominator coverage, and expose immutable read-only completed-hunt snapshots. |
| `hunt_results.py` | 443 | Strict bounded lane-result parsing, candidate validation, canonical artifact installation, and atomic receipt/coverage/candidate publication. |
| `firmware_fpcheck.py` | 604 | Prepare immutable review batches, verify complete review evidence, resolve global duplicates, derive canonical reviewed findings, atomically complete a generation, and invalidate one image's review and derived chain state. |
| `firmware_fpcheck_results.py` | 531 | Parse bounded review results, validate assignments and ownership without writes, atomically import canonical batch receipts/verdicts/pivots, and preserve or invalidate derived chain state on exact replacement. |
| `firmware_chain.py` | 323 | Prepare one immutable global findings worklist, invalidate image-owned graphs, reconstruct exact receipt-owned graph state, derive the deterministic graph artifact, and atomically complete the current snapshot. |
| `firmware_chain_results.py` | 977 | Parse bounded hostile chain JSON, enforce complete dispositions/evidence ownership/typed links/device-state continuity, derive stable graph identities, and publish canonical receipts and rows atomically. |
| `sweep.py` | 184 | Sweep a confirmed bug pattern across the corpus. |
| `skill_lint.py` | 164 | The shipped skill against the economics contract. |
| `annotations.py` | 123 | An append-only journal: comprehension that survives a restart. |
| `ceiling.py` | 115 | The context ceiling and its checkpoint (R3). |
| `pivot.py` | 112 | Write a FALSE_POSITIVE verdict and the observation it pivots to, together. |
| `patterns.py` | 111 | Which registered bug patterns have been swept, and which have not. |
| `goldens.py` | 93 | Golden reference sets and adjudicated match records. |
| `workspace.py` | 83 | Create a run directory and apply its schema. |
| `briefs.py` | 81 | Render a subagent dispatch brief from a template (R6). |
| `preflight.py` | 84 | Write a project-scoped MCP config (R4). |
| `text.py` | 66 | Normalization shared by dedup, golden scoring and identity evidence. |
| `identity.py` | 54 | An asserted identity needs evidence that is not the component's own name. |

### The twenty-nine verbs

```
init  selftest  preflight  brief  lint-skill            setup and self-check
put   rows      status     note   checkpoint            state
extract  coverage  sweep    patterns                    breadth
dedup    chain    pivot     identify                    quality
budget   bench    indicators  rerate                  measurement
qualify  acquire  triage  diff  surface  hunt  fpcheck firmware phases
```

### The firmware boundary through Stage 4g

Stages 4b through 4g add firmware behavior to the shared core without pretending that the
separate `firmware-audit` skill exists. `acquire` records a local image and its
SHA-256; it does not fetch or carve. `triage` reads an already-carved rootfs and
writes file, ELF, and evidenced boot-service rows; it does not infer open ports
or inspect the kernel and bootloader. Its agent half ships as
`references/briefs/triage-brief.md`. Every regular file gets an image-scoped
manifest row. Only target and backward-compatible unscoped triage mirror rows
into `cba_inventory`; acquired targets use image-qualified unit keys while
legacy-unscoped triage keeps raw keys. Reference triage cannot change the
target coverage denominator. Triage upserts observed paths; it does not prune disappeared
files, so use fresh image scopes/runs when replacing carved tree contents.
It prepares filesystem facts before writing and publishes file, ELF, service,
and coverage rows together. Direct `scandir` traversal propagates scan,
directory-entry classification, and stat errors instead of relying on
`os.walk`, which suppresses classification errors. A mismatch between entry
classification and `lstat` also aborts. Regular files are ordered by relative
path; directory symlinks, file symlinks, and nonregular entries are excluded.
These failures occur before publication and preserve prior rows. When an
acquired image's hash or version changes, acquisition and same-image manifest
invalidation commit together; diff refuses that image until retriage.

`diff` compares stored manifests, never rereading carved trees. It requires
acquired target/reference images of the same vendor/model with distinct image
hashes, and rejects missing manifests, ambiguous roles, and legacy-unscoped
provenance. All non-identical paths enter `cba_diff_entries`; unchanged paths
are counted. The bounded terminal result points to the full JSON artifact.
Read-side SQLite failures become `FirmwareDiffError` and a named CLI exit 1.
Artifact installation precedes the SQL transaction; replacement commits the
summary and entries together. SQL failure can leave an unreferenced artifact
generation but preserves the prior durable result.

`references/briefs/diff-brief.md` assigns the semantic half: explain the known
vendor fix with evidence from both builds, then sweep the target for surviving
siblings using existing observation/pattern tables. Changed bytes alone are
not vulnerabilities.

`surface` adds prepare/record/check modes (the exact commands are in `README.md`).
Preparation accepts only an acquired target and compares the complete live
regular-file root against its stored manifest by path, kind, size, and SHA-256,
with a final rescan under the SQL publication lock. Target inventory must also
agree. Every `cba_firmware_files` target unit enters exactly one path-ordered
batch; ELF/service/component hints never filter the denominator. Internal reads
are uncapped, independent of the interactive 200-row limit. Batch size defaults
to 50 (1–1000). Canonical schema-version-1 UTF-8 JSON excludes host paths and
timestamps; index bytes determine the worklist digest. Worklists install under
`RUN/files/surface/<worklist-sha256>/` before SQL publication.

`db.firmware_unit_key(image_id, path)` encodes database units as
`/firmware/<image-ID Unicode character count>:<exact image ID>:<exact raw path>`.
Length framing is injective even with delimiters or Unicode in either value;
the leading slash separates qualified units from valid relative manifest paths.
An empty path gives the exact image prefix for inventory reads. Target triage's
`cba_inventory.unit` and surface import's `cba_coverage.unit` share this encoding,
so generic coverage joins/gates still work without schema changes. Preparation,
validation, replacement, completion, and acquisition invalidation address only
the selected image, including when two targets share every raw path. Check
maps selected keys back to raw paths before artifact matching and aggregation.
Manifests, worklists, results, surface/unknown component paths, and surface-facing
output remain raw. Legacy-unscoped keys and non-surface coverage writes remain
unchanged. ELF/service hints are image-scoped; `cba_components` is still globally
keyed by raw path and supplies advisory hints, never ownership or completeness.

Old raw inventory is not accepted as acquired-image inventory. Import refuses
overlapping unqualified surface coverage even with replacement, before artifact
installation and again under the SQL lock. Preparation/acquisition invalidation
preserves such ambiguous rows; there is no ownership-guessing migration. Use a
fresh run when these old rows obstruct import. This isolation does not add
pruning to upsert-only retriage.

`cba_surface_runs` binds one target's manifest/worklist hashes, counts, and
pending/complete status. `cba_firmware_surfaces` stores image-scoped surface IDs,
entry point, protocol, dispatch path, handler, lifecycle/posture/auth requirements,
reachability, evidence, and canonical result provenance. `cba_unknowns` stores
globally unique questions with component/surface linkage, settling observation,
method (`static`, `emulate`, `hardware`), open/resolved state, and provenance.
Lifecycle is factory-fresh/provisioned/bound-to-owner/cloud-registered/post-reset;
posture is softap-setup/sta-lan/wan-exposed/ble/cloud-tunnel-only; auth is
pre-auth/session/admin/local-shell/physical-uart. Each also permits `unknown`;
reachability is evidenced/refuted/unknown. Unknown state fields require a matching
open question for that surface and field. Open questions have no resolution or
evidence; resolved questions require both. Honest open unknowns pass completion.

The worker brief requires evidence from entry point through dispatcher to
handler and auth ordering, plus exactly one decision per assigned unit. A
no-surface analyzed unit needs a retained explanation or explanatory unknown.
The importer rejects extra/duplicate/missing units, foreign batch claims, extra
keys, invalid state/linkage, and results over 8 MiB. It verifies current image,
manifest, index, and batch provenance, installs canonical result bytes under
`RUN/artifacts/surface/<sha256>/result.json`, then revalidates and publishes
claims plus `phase='surface'` coverage in one transaction. Duplicate import
requires `--replace`, which removes only assigned-batch rows. Each import sets
pending and clears completion time; only check can certify complete.

Check verifies the entire denominator, canonical worklist and result evidence
for every batch (including claim-free ones), exact claim/coverage agreement,
unknown linkage, and absence of budget skips. It repeats validation under the
publication lock before setting complete. Generic per-row `put` validation
cannot substitute for this cross-row gate. Terminal/JSON output contains only
aggregate counts, identity/digests, and artifact paths. Expected SQL failures
render as `surface: database operation failed`; other expected messages escape
controls/non-ASCII and truncate to 512 ASCII characters plus a newline. Unexpected
exceptions propagate after rollback; expected domain/database errors exit 1
without a traceback (argparse usage errors exit 2; success exits 0).

Same-input preparation preserves the generation; a changed manifest or worklist
digest atomically clears that image's surface/unknown rows and prior-unit surface
coverage. Changed target acquisition provenance clears its manifest and dependent
surface state in the same transaction. Failed publication preserves prior SQL;
artifact installation may leave an orphan generation. Triage remains upsert-only:
stale-root disagreement requires fresh image scope/run and retriage.

To verify claim-free batches, check scans retained orphan result candidates;
each candidate is bounded, but runtime grows with retained generations. A future
durable batch receipt is the direction for eliminating this local-run performance
limit without capping evidence or the denominator.

Stage 4d does not fetch/carve/execute firmware, infer listeners, hunt, assign
severity, emulate, inspect kernel/bootloader, or create the separate skill tree.

`hunt` is Stage 4e, a firmware-audit phase still shipped inside
`codebase-audit`. Preparation and checking require an acquired target, its
image-scoped manifest, a complete canonical Stage 4d generation, and the live
carved root. The exact commands are:

```bash
python3 audit.py hunt --run RUN --root ROOT [--image-id ID] \
  [--sink-batch-size N] [--dark-batch-size N] [--json]
python3 audit.py hunt --run RUN --record RESULT.json [--replace] [--json]
python3 audit.py hunt --run RUN --check --root ROOT [--image-id ID] \
  [--lane l-sink|l-dark] [--json]
```

The target regular-file manifest is the denominator for both L-sink and
L-dark. Each unit appears once in each lane; each lane has its own immutable
worklist, coverage phase, receipt set, candidates, and pending/complete state.
Hints are advisory. Worklists are installed under
`RUN/files/hunt/<generation>/<lane>/`; results are canonicalized and stored at
`RUN/artifacts/hunt/<generation>/<lane>/<result-sha256>/result.json`. Durable
receipts own every imported batch, including candidate-free batches. Candidates
are image-, lane-, component-, result-, and batch-bound. Replacing a batch
requires `--replace`; changed evidence removes only that batch's rows and resets
only its lane. A byte-identical replacement with matching durable receipt, coverage
and candidates preserves completion and timestamps.

In shared `cba_coverage`, `not_applicable` maps to `state='analyzed'` with its
evidence-backed reason retained; `not_audited` keeps its state, and a budget
skip fails the gate. Changed acquisition provenance, target triage, or surface
evidence invalidates the selected image's hunt state atomically. Ambiguous
legacy unqualified hunt coverage is refused and preserved. Expected SQLite
errors render exactly `hunt: database operation failed`; other expected
diagnostics escape controls/non-ASCII and cap at 512 ASCII characters plus a
newline. Raw candidate evidence does not enter command output.

The phase records candidate evidence for the later firmware `fpcheck`; it does
not adjudicate false positives, assign final severity, fetch/carve/execute or
emulate firmware, inspect kernel/bootloader code, or promote candidates into
generic `cba_findings`. It inherits triage's upsert-only snapshots and the
Stage 4d check's retained-orphan result scan scaling. Firmware review is
implemented as Stage 4f below and merged into local `main` at `303232e` after
clean scoped final re-review. Stage 4g `chain` is merged into local `main` at
`30ca3ba`; the next firmware slice is `dive`.

### Stage 4f — dedicated firmware static review

The five dedicated tables are `cba_firmware_fp_runs`,
`cba_firmware_fp_receipts`, `cba_firmware_fp_verdicts`, `cba_firmware_pivots`,
and `cba_firmware_findings`. They retain image/generation/batch ownership;
generic `cba_findings` and `cba_fp_verdicts` remain untouched.

```bash
python3 audit.py fpcheck --run RUN --prepare --root ROOT [--image-id ID] [--batch-size N] [--json]
python3 audit.py fpcheck --run RUN --record RESULT.json [--replace] [--json]
python3 audit.py fpcheck --run RUN --check --root ROOT [--image-id ID] [--json]
```

The CLI whitelists scalar aggregates/provenance and artifact paths. JSON preserves
exact identities and usable paths with normal JSON escaping; its fixed field set
does not impose the human display's per-string size limit. Only human display
fields use root redaction and the 512-character ASCII cap. Expected diagnostics
retain their separate escaping/redaction/cap and fixed SQLite error message.

Table validation checks variant-specific evidence, canonical unique JSON arrays, relative batch and
component paths, lowercase digests, counts, and bounded identifiers. Stored
worklist/result/artifact paths also accept canonical absolute paths; phase
modules must enforce run containment and cross-row ownership.
`hunt.verified_snapshot` shares the full Stage 4e verifier with `hunt.check`;
it requires both lanes already complete and never changes SQL/status/timestamps.
Frozen lane/candidate/blocker records retain full verified evidence and
lane-qualified candidate identity; artifact paths are verified run descendants
and returned in canonical run-relative POSIX form. Reads support read-only
SQLite and caller-owned transactions, without the display-row cap.
`firmware_fpcheck.prepare` consumes that immutable boundary, hashes the full
lane-qualified candidate projection with both hunt worklist digests, and installs
canonical index/batch artifacts beneath `files/firmware-fpcheck/<index-sha256>`.
Artifacts preserve evidence and run-relative provenance without host-root metadata
or timestamps. Normalized similarity signatures only keep equal-signature
candidates with one reviewer; they never merge findings. Clusters sort by signature
and then lane/ID, never split, and may exceed the requested 1..200 target size;
clusters and batches cannot exceed 1,000. Empty hunts receive one empty batch.
Preparation installs all files before `BEGIN IMMEDIATE`, repeats verified hunt/live-root
and prior-run checks, re-reads installed artifacts, and publishes one pending row.
Same inputs preserve existing review state; changed preparation invalidates only
the selected image's five review tables, retaining sibling images and artifacts.
Public `invalidate` leaves commit ownership with the caller by default. Local
imports at acquisition, target triage, surface prepare/results, hunt prepare/results
and hunt lane completion boundaries invoke it with `commit=False` inside the
upstream SQL transaction. Selected-target hash/version or manifest changes, new
prepared generations, changed result evidence and real lane completion transitions
remove only that image's five review tables. Reference/supplemental acquisition
changes and byte-identical operations preserve review state. Hunt replacement
compares receipt provenance/counts, qualified coverage and complete receipt-owned
candidate rows before preserving review and lane completion; repairing damaged
durable rows invalidates review even if the submitted result bytes are unchanged.
Any deletion failure rolls back both upstream publication and review removal.
`firmware_fpcheck_results` rejects duplicate JSON
keys, invalid UTF-8, non-finite values, unknown keys and mismatched verdict variants.
Raw input and canonical output each have an 8 MiB bound. Frozen records preserve
all reviewer evidence. Validation rebuilds the current completed-hunt evidence and
canonical review generation, requires a consistent pending/complete run, checks exact lane-qualified
assignment membership before verdict semantics, and binds components/surfaces to
the selected image. Rules use exactly HE-1..18, PR-1..10, CV-1..3 and MARGINAL-GAIN.
Image IDs retain the existing non-empty UTF-8 text contract. Confidence typing is
structural; its 0..10 range is checked after assignment membership. Pending runs
require no completion timestamp; completed runs require a non-empty timestamp so
replacement and idempotent final checks can revalidate the same current evidence.
The load/validate/canonical boundary works on read-only SQLite and inside caller
transactions without SQL/artifact writes. This result API has no live-root parameter: preparation and the final
completion gate retain root verification. Duplicate targets may cross batches;
the final completion gate resolves their global chains. `record`
installs `artifacts/firmware-fpcheck/<generation>/<result-sha256>/result.json`
before taking one `BEGIN IMMEDIATE` transaction. It repeats mutable provenance,
receipt ownership and installed-byte checks under the lock, then publishes one
receipt, one verdict per lane-qualified candidate, and one pivot per false positive.
SQL defaults own timestamps; worker JSON never supplies SQL provenance. Replacement
isolates the selected image/snapshot/batch; pivot deletion joins lane-qualified
source verdicts. Sibling batches/images survive, selected-image derived findings
are cleared, and the review run returns to pending. SQL/commit failures roll back
all rows and may leave only an unreferenced immutable artifact. No live root is
accessed during import.
`firmware_fpcheck.check` rebuilds every receipt-owned verdict and pivot from the
current canonical result bytes, requires exact candidate coverage, and revalidates
the completed hunt, review worklists and live root. Duplicate resolution is iterative
with path compression and rejects cycles, missing targets and non-TP terminals.
Exact root-cause keys group direct/terminal true positives and their duplicate
contributors; similarity signatures never merge groups. The lexicographically first
true-positive `(lane, candidate_id)` supplies immutable candidate title/bug class and
its review scalar evidence. Contributors, lanes, components and surfaces form sorted
unions; confidence is the minimum across every contributor, including duplicates.
Finding IDs bind image, candidate snapshot and root-cause key; evidence is exactly
`static-reviewed`. The deterministic `findings.json` installs before one
`BEGIN IMMEDIATE` transaction. Under the lock the gate repeats all input/artifact
checks, then replaces selected-image derived rows and marks the run complete.
Read/install/SQL/commit failures preserve previous SQL/status/timestamps; an
unreferenced immutable artifact may remain. Completed rechecks require the existing
canonical findings artifact and matching derived rows, repeat all verification, and
preserve timestamps without SQL writes. Empty receipted generations and fully
false-positive generations complete with zero findings. Only dedicated Stage 4f
tables are written; generic finding/verdict tables are untouched. Atomic upstream
invalidation and the bounded firmware `fpcheck` CLI are implemented. The firmware
review brief, installed-user routing and full-phase documentation/inventory are
merged into local `main` at `303232e`; the scoped final re-review was clean.
The eighth dispatch template, `references/briefs/firmware-fpcheck-brief.md`,
uses the existing `brief` renderer with eight required path/provenance variables.
`SKILL.md` routes firmware review through explicit `fpcheck --prepare`, one
file-backed brief per immutable batch, orchestrator `--record`, and global `--check`.
Workers preserve lane-qualified identities, compare cross-lane evidence, apply
shared FP rules, and return strict bounded result-only JSON with mandatory
false-positive pivots and explicit duplicate targets. Workers never own SQL,
canonical installation, or transitions. PARTIAL checkpoints retain completed
work without fabricated decisions and cannot be imported as complete results.
Absolute host-root paths are access context, not persisted reviewer evidence.
Ordinary source-code fpcheck keeps its existing workflow and brief.
The final check also independently refuses stale upstream evidence.
`audit.py fpcheck` requires one explicit prepare/record/check mode and validates
all mode-specific flags before database I/O (syntax exit 2; semantic exit 1).
Prepare accepts batch targets 1–200, default 20. The handler delegates to the
phase boundaries and selects scalar counts/provenance plus artifact paths;
check reports a finding count, excluding per-finding identifiers and review
fields. Human success fields escape/cap public text at 512 ASCII characters and
redact the supplied root; machine JSON preserves the fixed scalar field set
losslessly so identities and artifact paths remain reusable. Success stderr is
empty. Expected diagnostics are capped at 512 ASCII characters plus newline; SQLite errors print exactly
`fpcheck: database operation failed`;
unexpected handler exceptions propagate after cleanup. No source-code generic
verdict behavior or prose workflow name changes.
Stage 4f does not execute/emulate/exploit firmware, settle runtime/hardware
blockers, assign severity/CVSS, claim live reachability, compose exploit chains,
write disclosure reports or create the separate firmware skill tree. Root-cause
keys remain reviewer judgments; differing keys can visibly under-deduplicate.
The Asus golden
remains required for the overall Stage 4
milestone, and the monorepo/submodule decision remains open for the restructure.
Audit quality remains unmeasured until the deferred paid milestone runs;
deterministic harness scoring only measures the existing baseline.

### Stage 4g — global static firmware evidence graphs

Stage 4g is merged into local `main` at `30ca3ba`, with no push. It consumes only
a verified complete Stage 4f findings snapshot
and writes six dedicated tables: `cba_firmware_chain_runs`,
`cba_firmware_chain_receipts`, `cba_firmware_chain_dispositions`,
`cba_firmware_chain_unknowns`, `cba_firmware_chains`, and
`cba_firmware_chain_edges`. Every row is image- and candidate-snapshot-owned;
generic `cba_chains` and source-code findings remain untouched.

```bash
python3 audit.py chain --run RUN --prepare --root ROOT [--image-id ID] [--json]
python3 audit.py chain --run RUN --record RESULT.json [--replace] [--json]
python3 audit.py chain --run RUN --check --root ROOT [--image-id ID] [--json]
```

`firmware_chain.prepare` reuses the Stage 4f verified snapshot boundary, installs
one canonical global worklist beneath `files/firmware-chain/<snapshot>`, then
takes `BEGIN IMMEDIATE`, repeats live-root/upstream/installed-byte checks, and
publishes one pending run. Same inputs preserve current chain state; changed
inputs invalidate only the selected image's six tables. Stage 4f prepare, import,
repair, completion, and invalidation paths call that SQL-only invalidator inside
their owning transaction, so stale derived graphs cannot survive changed review
evidence. Sibling images remain isolated. Record/check can preserve valid older
SQL generations, but upstream invalidation deletes every Stage 4g SQL generation
for the selected image; immutable content-addressed artifacts remain.

`firmware_chain_results` accepts bounded strict UTF-8 JSON with no duplicate or
unknown keys and no non-finite/coerced values. Exact disposition coverage is
mandatory even for an empty generation. Findings may participate in multiple
chains; chained membership must match graph membership, while standalone and
unchainable findings cannot carry unresolved blocker references. Each adjacent
edge binds a typed capability and semantic link identity to producer- and
consumer-owned retained evidence. Middle findings must both consume and produce
the carried state. Lifecycle, posture and authentication continuity is mechanical;
direct transitions cannot magically change lifecycle/posture, while reboot,
service-restart, factory-reset and reprovision require explicit retained evidence
on both sides. Stage 4d unknowns must remain open and carry frozen axes; new
blockers include a settling observation and static/emulate/hardware method.
Stage 4f pivots may guide follow-up only and cannot be graph nodes or evidence.

`record` validates against the immutable worklist and current retained Stage 4f
SQL/artifacts without live-root access, installs canonical result bytes beneath
`artifacts/firmware-chain/<snapshot>/<result-sha256>/result.json`, then takes one
immediate transaction and repeats mutable provenance, receipt ownership and
installed-byte checks. It replaces only the current selected-image generation,
publishes one receipt and exact disposition/blocker/chain/edge rows, and leaves
the run pending. SQL failures preserve prior state and may leave only an
unreferenced immutable artifact.

`firmware_chain.check` re-enters the live-root/Stage 4f verified boundary,
reparses the immutable result, and reconstructs every receipt-owned row rather
than trusting imported SQL. It derives stable image/snapshot-bound chain and
blocker IDs, `pre_auth` (`yes`, `no`, or `unknown`), completeness, minimum
confidence, and the sole evidence rung `static-chained`. A deterministic
`chains.json` installs before one locked final revalidation and completion update.
Completed rechecks never repair missing/corrupt artifacts or rows and preserve
timestamps without writes. Static graphs encode evidence-backed composition;
they do not prove runtime reachability, semantic causality beyond that evidence,
severity/CVSS, exploitability, or successful exploitation.

The firmware modes overload the existing `chain` verb without changing ordinary
source-code proposal and human composition. Semantic flag errors fail before DB
I/O; prepare/check require root, record alone accepts replace, output is a bounded
scalar whitelist, and expected diagnostics are escaped/root-redacted/capped while
unexpected exceptions propagate after cleanup.

#### Installed global chain worker interface

`references/briefs/firmware-chain-brief.md` renders through the existing `brief`
mechanism with exactly seven required variables: `run_dir`, `db_path`, `rootfs`,
`image_id`, `candidate_snapshot_sha256`, `worklist_path`, and `result_path`.
`--phase firmware-chain --unit global` writes
`briefs/firmware-chain-global-brief.md`. Dispatch carries that file's path;
reviewed evidence stays in the immutable global worklist, read incrementally by
one strongest-available worker. Coverage is never capped or split by component.

`SKILL.md` routes firmware chain work through orchestrator `chain --prepare`,
one worker, `chain --record`, and `chain --check`. The ordinary source-code
chain proposal/human composition route is preserved. Worker output is strict
bounded result-only JSON governed by `firmware_chain_results.py`, with a
single return line:
`firmware-chain <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`.
Rows counts finding dispositions, including zero for a truthful empty review.
PARTIAL checkpoints preserve the same immutable assignment and cannot be
imported as complete results.

The brief requires every finding's disposition, reusable path membership,
owned typed adjacent-edge evidence, middle-node continuity, carried device
state, explicit boundary proof, and blockers with settling observations. Stage
4f pivots remain follow-up context only. The worker owns neither SQL nor
canonical installation, identities, receipts, derived claims, or completion.
Static chain review authorizes no runtime, severity/CVSS, or exploit claims;
settlement remains later dive/decide work.

Whole-branch review found and fixed two cross-layer invariant mismatches in
`661c3c9`; scoped re-review reported no remaining Critical/Important issue.
Final review then found that blocker-side affected findings could contradict
nonmaterialized dispositions. Commit `7dad245` requires a reciprocal blocked
disposition and blocker reference and adds independent completion-gate coverage;
the complete fix wave passed scoped re-review. Stage 4g is merged locally but
unpushed. The next firmware slice is `dive`. Triage's upsert-only snapshots and Stage 4d's retained-
orphan scan scaling remain inherited limitations. The Asus golden, paid milestone
audit, separate firmware skill tree, and monorepo/submodule decision remain open.

### Stage 4h — partial dive foundation

Stage 4h is in progress on `stage4h-firmware-dive`; integration is pending.
Six additive tables retain dive runs, questions, receipts, observations,
dependencies and acquisitions. The schema now has 44 tables and 43 TableSpec
contracts; all four existing migrations are unchanged. Question contracts and
packet authority and hardware capture sealing are implemented below; probe/result
domain schemas and cross-row completion semantics belong to the remaining dive tasks.

`firmware_chain.verified_graph_snapshot` reconstructs only a current completed
Stage 4g publication, sharing canonical graph derivation with `check()` without
calling that writing gate. Frozen nested records expose sorted semantic rows and
canonical run-relative graph provenance. A single read transaction spans upstream
and graph verification; read-only SQLite and caller transactions are supported.

`verified_retained_graph_snapshot(..., image_id=..., dive_generation=...)`
requires the explicitly owning dive-run row, canonical graph path/hash/bytes,
and a verified current Stage 4f/source snapshot. It remains usable after Stage
4g SQL and worker files are removed; it is never a fallback for the public
current helper. Its embedded worklist hash is historical provenance. The dive
row does not store the Stage 4f findings-artifact digest, so a valid replacement
under the same candidate identity cannot be detected here; Tasks 4/8/9 must bind
exact per-question/per-observation artifacts before conflict preparation or
overlay use. Every returned graph row cites the verified `chains.json` artifact.

`firmware_dive_questions` defines frozen strict questions and resolution contracts.
Semantic edge/chain fingerprints exclude local IDs and presentation fields;
full SHA-256 question IDs bind the specified canonical subject/method/text/axis
projection. Automatic blockers split by exact edge or every affected state axis;
linked open surface unknowns retain upstream text and bounded value discovery.
Analyst entries require current graph subjects and exact frozen predicates.
Manifest depth is bounded before recursive normalization, and parser/validation
failures use `FirmwareDiveQuestionError`. History retains normalized immutable
question fields so conflicts cannot inherit mutable subject, axis or value arrays.
Explicit retry directives bind contiguous durable attempt ordinals. Only current
conclusive history can contest a subject; complete exact supersedes sets replace
conflicting observations without choosing by timestamps. Pure packets contain
exact retained artifact/evidence references, up to three named extract records,
a bounded journal index and question/subject/method-owned future acquisition
contracts with probe and capture byte/file limits. Exact extract-record digests
bind stable provenance while excluding timestamps; absolute source identities
are rejected and source text never enters packet bytes. Packets embed no evidence
bodies.

Task 4 implements artifact-first immutable preparation through `firmware_dive.prepare`.
It freezes complete question denominators, preserves every prior generation and
sibling image, and repeats live source, graph, strict manifest, durable history,
extract provenance and installed-byte verification under `BEGIN IMMEDIATE`.
Ordinary preparation uses only the current completed graph; conflict-only
preparation selects an exact completed retained owner from the complete current
conflict family and rejects ambiguous graph chronology, unrelated questions and
ordinary retries. Retry validation follows retained-owner selection, so unrelated
older graphs cannot veto a valid conflict retry. Installation anchors creation,
file writes, fsync, rename and cleanup to verified directory descriptors with
no-follow traversal; a parent replacement cannot redirect writes through a
symlink. A rejected publication may retain an unreferenced immutable generation
inside the run. Preparation never invalidates Stage 4g.

The generation index retains scalar graph ownership, canonical analyst input,
complete authoritative accepted-input dependency digests and retry projection,
plus every packet identity, so its hash can be reconstructed independently of
the bounded informational journal. Identical generations reuse their frozen
journal/packets without writes after later inconclusive history. Opaque dependency
provenance is structurally bounded and rejects host/traversing path spellings;
private provenance bodies stay behind digests. Exact finding-artifact provenance
is bound separately from historical Stage 4g worklist/result hashes. New questions
authorize no extracts by default; historical exact selections are reconstructed
from canonical stable upstream manifest projections and rechecked under lock.

Task 5 adds strict question-owned hardware sealing through
`firmware_dive_acquisition.load_capture_spec` and `seal_capture`. It reconstructs
the owning prepared run, generation index, packet, exact hardware acquisition
contract and current retained-graph/source dependencies. Specs bind the recorded
device identifier, firmware version/full image digest, lifecycle/posture/authentication,
operator/source and hardware method. The recorded image digest is a device fact,
not an equality to the Stage 4f manifest or candidate digest. Sources resolve
relative to the spec parent; no source paths or timestamps enter sealed bytes
or identity. Sorted flat evidence names and stable regular bytes are bounded at
256 files and 64 MiB total, with strict keys, strings, states and digests.
Explicit run/spec selectors normalize to absolute lexical targets before
no-follow traversal; evidence source paths and installed basenames remain
canonical relative and traversal-free. Image IDs preserve bounded upstream
UTF-8 scalar identity, including escaped controls; other metadata stays strict.
Capture evidence follows raw-name order; SQL paths follow canonical JSON-element order.

The full SHA-256 capture ID binds canonical sealed spec semantics and every
ordered evidence name/hash/size with a capture discriminator. The exact layout is
`artifacts/firmware-dive-captures/<id>/{spec.json,manifest.json,evidence/...}`.
The shared installer and stable reader anchor all directory traversal, file reads,
creation, writes, fsync, rename and cleanup to no-follow descriptors. Installation
precedes `BEGIN IMMEDIATE`; authority, source identities/bytes and installed bytes
are checked again before one append-only acquisition receipt. Exact duplicates
perform no writes; conflicting duplicates refuse. Failure preserves prior SQL,
sibling questions and images, and may retain an unreferenced in-run artifact.
Captures create no observation, finding, evidence rung or denominator change and
never contact or control a device.

Result/journal and retained probe bodies remain opaque to preparation; its retained
history boundary continues exact SQL/byte and method/rung checks. Later result,
completion and overlay gates must consume sealed capture/probe semantics and enforce
canonical observation identity. Task 6 now preserves these descriptor, exact
prepared-contract and locked publication boundaries for bounded isolated probes. Stage 4h remains in progress, integration pending; no runtime,
severity or exploit claim is made.

Results, completion, overlays, CLI and worker routing remain pending. These helpers make
no runtime, severity or exploit claim and inherit triage's upsert-only snapshots
and Stage 4d retained-orphan scan scaling.

Task 6 implements frozen strict `ProbeSpec`/`ProbeTermination`, `load_probe_spec`
and `run_probe` in the acquisition module. Every probe reconstructs its exact
prepared emulate question, packet and no-network acquisition contract against
current upstream evidence. It stages only declared verified regular dependencies,
binds exact argv/environment and hashes before/after execution, and publishes
runtime facts without answering questions, choosing evidence rungs or findings.

The network policy is exactly none. Supported installed or explicit canonical
no-symlink `bwrap`/`sandbox-exec` programs must match the backend/platform, remain
hash-stable, and pass a fixed bounded readiness probe from an ordinary-permission private
copy; firmware invocation uses that same staged adapter copy. Special file bits
and capabilities are never copied; tools needing them fail closed. Both the
staged tool tree and original host tool are revalidated. These operator-trusted
host tools are checked for readiness/integrity, not attested as nonmalicious.
The manifest records their host runtime before isolation as trusted tooling.
Missing, unknown or unready isolation seals `executed=false` with
`reason=isolation-unavailable`; firmware never runs unsandboxed and no tool is
installed. Linux mounts only staged declared guest files plus an optional verified
static-ELF runner, isolated proc/dev and output; dynamic host runners are recorded
as unsupported. macOS denies network and process forks, permits process exec,
and records the fixed Apple system-runtime read roots and platform/version;
those system reads are not firmware library evidence.

Host adapter processes, including readiness, always receive a fixed empty
environment. Declared environment values and the explicit shim are injected only
inside isolation: bwrap uses `--setenv`; macOS uses a verified native copy of fixed
`/usr/bin/env`, staged as `_environment-launcher`, with `-i`, literal assignments
and an exact absolute firmware command. The launcher has a separate host-tool
role/hash/size, with original and staged checks; its host path never enters the
identity. Missing or incompatible helpers seal `unsupported-helper` without a
payload. Pre-payload original-helper drift may seal truthful distinct before/after
hashes only while every other dependency remains stable and the captured after
snapshot revalidates under lock. Staged-helper tampering and any dependency drift
after a real payload launch refuse publication. Host adapter startup never
receives user environment or loader injection variables.

Timeout is an integer 1–300 seconds; argv is at most 128 entries/4096 UTF-8 bytes
each; environment has at most 64 safe names/4096-byte values and rejects loader
variables except the explicit validated shim. Staged dependencies are bounded to
256 regular files/64 MiB total; the adapter and fixed environment launcher are separately verified host tools,
each bounded to 64 MiB.
Processes use argv lists, no shell, a new session, closed descriptors, minimal
environment and redirected descriptor-checked stdin. Both streams retain at most
1 MiB with explicit truncation. Timeout/errors kill and reap the entire process
group with bounded pipe cleanup. Exit codes, signals, timeouts, truncation and
unsupported tools remain facts. Darwin zombie-group behavior is handled without
repeated signals or masking live cleanup failures.

Payload children inherit fixed hard and soft Unix limits: 8 MiB file size,
64 processes per UID and 64 file descriptors. Missing or insufficient resource
support, setup failure and root UID (which can bypass process limits) refuse with
`executed=false,reason=unsupported-limits`. The per-UID process bound can also
make adapters unavailable on a busy host; it is never raised as a fallback.

Only declared output files and parent directories are precreated. Directories
are non-writable; macOS permits writes to exact file paths only, and bwrap drops
all capabilities, remounts guest root/proc/dev read-only and exposes only exact
output files as writable submounts. Payloads cannot create, unlink or rename
output entries. A bounded descriptor watchdog checks directory/file identity,
shape and aggregate size throughout execution, including after pipes close.
Exceeding 8 MiB total or changing the tree kills/reaps the group and records an
`output-limit` fact; over-limit generated files are excluded from publication.
The 8 MiB per-file hard limit bounds growth between watchdog checks; no separate
filesystem quota or strict zero-overshoot aggregate limit is claimed.

Immediately before payload launch, each placeholder's device/inode/size/mtime/
ctime is snapshotted. Untouched placeholders remain absent from evidence;
explicit zero-byte writes count as produced even if mtime is restored.
Declared captured outputs are at most 256 regular files/8 MiB total. Canonical nested paths
have at most 32 components, 255 bytes/component and 4096 bytes overall; prefix
collisions, traversal, links, special files and undeclared tree entries refuse.
Bounded descriptor enumeration and the generalized shared no-follow installer
preserve `outputs/<declared-path>` under
`artifacts/firmware-dive-probes/<id>/`, with separate `evidence/stdout` and
`evidence/stderr`. Canonical identity binds exact question/contract/spec, runtime,
termination, dependency and output hashes/sizes, excludes timestamps and local
host paths, and installs before locked exact revalidation and one acquisition
row. Exact duplicates make no writes; conflicts/failures preserve SQL and siblings.

Task 7 strict result parsing is next, followed by canonical observation identity,
completion and overlay validation. Preparation still treats retained result and
journal bodies as opaque despite exact byte/SQL checks. CLI/worker routing,
integration and full Stage 4h review remain pending. Tests execute only purpose
fixtures through injected adapters; real-tool integration is not claimed. Runtime
verification is macOS Python 3.14; Linux and alternate-interpreter execution remain
unverified. Triage upsert-only snapshots, Stage 4d retained-orphan scan scaling and
paid semantic quality limitations persist. `make mutate` remains separate.

### Stage 3's five quality mechanisms

Each answers a named cause of a missed CRITICAL in the tplink post-mortem,
where an audit found 9 of 19 known criticals:

1. **Pivot rule** (`pivot.py`) — a FALSE_POSITIVE must record what refuted it
   *and* what that refutation enables. A dismissal that leaves no trail loses
   the observation underneath it.
2. **Sweep-on-confirm** (`patterns.py`, `sweep.py`) — a confirmed bug becomes
   a registered pattern, and a registered pattern that was never swept is a
   reportable gap. One instance of a bug class is rarely the only one.
3. **Coverage denominator** (`coverage.py`) — analyzed over inventoried, with
   a reason for every gap, and a gate at phase exit. Coverage you cannot
   divide is a feeling.
4. **Identity discipline** (`identity.py`) — asserting what a component *is*
   requires evidence that is not its own filename. `km0_boot_0C000020.elf` is
   not evidence that the file is a boot image.
5. **Chain composition** (`chains.py`) — cross-group finding pairs are
   proposed as candidate chains, and findings never examined as enablers are
   reported as such. Two mediums in different groups can be one critical.

---

## 7. Two contracts that are easy to break by accident

### The line-ending contract

Six files ship with **CRLF**; everything else ships with **LF**.

```
SKILL.md
references/phase0-source-detection.md
references/phase2-feature-mapping.md
references/phase4-deep-audit.md
references/phase5-fp-check.md
workflows/_audit-pipeline-v1-archive.md
```

This is not legacy mess. `install.sh` substitutes `__SKILL_DIR__` line by line
with `sed`; normalising one of these files rewrites **every line of its diff**,
and a diff where every line changed is a diff in which an accidental deletion
is invisible. The authoritative list is
[`scripts/eol-manifest.txt`](scripts/eol-manifest.txt); the `eol` gate and
`tests/test_harness.py` both enforce it.

### `>` blockquotes in workflow files are presented, not executed

A command placed inside a `>` blockquote in a workflow file is shown to the
user rather than run. Stage 3 shipped its coverage gate into one and it never
executed in either mode. When adding a command to a workflow, check what block
it lands in.

---

## 8. The verification harness

`scripts/harness.py` owns every gate; `make` and CI are thin wrappers over it.
Adding a gate there makes it appear in `make list` and in CI with no further
edits.

| Gate | Default | What it proves |
|---|---|---|
| `tests` | yes | The pytest suite; current measured counts are in `SESSION_HANDOFF.md`. |
| `selftest` | yes | Verbs vs parser, `TABLE_SPECS` vs `schema.sql`, `MIGRATIONS` vs the frozen baseline — each comparing two structures built independently. |
| `lint` | yes | Shipped prose against the economics contract. |
| `eol` | yes | The CRLF/LF split above, across tracked *and* newly added files. |
| `manifest` | yes | `feature_lists.json` against the tree it describes: every path exists, every verb is dispatchable, every status is in the enum. |
| `install` | yes | A sandboxed `install.sh` run, no surviving `__SKILL_DIR__`, and the real install's mtime unmoved. |
| `coverage` | yes | Every `audit_core` statement a test executes, or is named in `scripts/coverage-allowlist.txt` with a reason and a content digest. |
| `bench` | opt-in | Recall, precision and cost against the tplink golden set. SKIPs when the corpus is absent. |

```bash
make check          # the default gates (coverage included)
make all            # plus bench
make list           # every gate and what it checks
make json           # one JSON object, for CI and for agents
make eol            # any single gate
```

**The install gate is the reason the harness is Python and not a Makefile
recipe.** `install.sh` resolves its four destinations from `$HOME` and
`$CODEX_HOME` *at run time*, so an unguarded invocation overwrites the
operator's real working skill at `~/.claude/skills/codebase-audit/`. The gate
builds a throwaway `HOME`, **refuses to proceed if that HOME resolves to the
real one**, and asserts afterwards that all four real destinations' mtimes did
not move. A recipe that forgets one `env` assignment does the damage silently.

### Stage 3c: two instruments for what the tests do not see

**Coverage gate** (`scripts/coverage_probe.py`, `scripts/coverage_allowlist.py`,
`scripts/coverage-allowlist.txt`, `gate_coverage`; in `DEFAULT`). A
`sys.monitoring` probe reports which `audit_core` statements no test executes.
It catches *untested code*. Every permitted gap is named in the allowlist with a
reason and a content digest, and the gate fails in both directions: an unlisted
gap is a regression, a listed line that now runs is a stale entry, and a moved
line reports as stale rather than silently re-aiming its permission. Measured
start: 115 unexecuted of 2,392 statements (95.2%); end: 0 of 2,392.

**Mutation harness** (`scripts/mutate.py`, `scripts/mutation-verify.py`,
`scripts/mutation-allowlist.txt`, `gate_mutate`). It mutates `audit_core` and
reruns the tests. It catches *hollow tests*: a line that is executed while
nothing asserted depends on it, which line coverage cannot see. It is excluded
from both `DEFAULT` and `ALL_EXTRA` because the sweep takes about 54 minutes and
`ci.yml` runs `--all` across three Python versions. The frozen measurement is
`docs/baselines/2026-10-08-mutation-sweep.md` (1068 mutants, 66.3% killed).

---

## 9. Measurement

Quality is measured, not asserted. `audit.py bench` scores a run's `audit.db`
against an adjudicated golden set in `tests/goldens/`:

- **Recall** — matched references over the reference count (currently 9/19).
- **Precision** — true positives over adjudicated findings (currently 39/40).
- **Cost per match** — the number that makes a cost win and a quality loss
  comparable (currently $73.15).

`tests/goldens/*/matches.json` and `rejections.json` are **human
adjudications**. They are never written by a tool and never regenerated.

`docs/baselines/` holds the measurements. A baseline is never edited in place:
a correction is a new dated file, so the correction stays visible in git
history. `2026-10-04-tplink-baseline.md` is superseded and labelled as such
rather than deleted.

---

## 10. Constraints that are not negotiable

1. **`audit_core` is stdlib-only** and reaches no network. `pyproject.toml`
   declares `dependencies = []`.
2. **Python 3.10 is the floor.** CI runs 3.10, 3.12 and 3.13.
3. **Never run `install.sh` or `install.ps1` without overriding `HOME`,
   `CLAUDE_CONFIG_DIR` and `CODEX_HOME`.** Use `make install-smoke`.
4. **Never write `tests/goldens/*/matches.json` or `rejections.json`.**
5. **Never edit a baseline in place.** Append, or write a new dated file.
6. **`~/Documents/Offsec/Opswat/Devices/` and `~/.claude/projects/` are
   read-only.** They hold real audit corpora and real session transcripts.
