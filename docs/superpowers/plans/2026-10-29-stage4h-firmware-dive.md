# Stage 4h Firmware Dive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a provenance-bound firmware `dive` phase that gives every current chain question one fresh, bounded investigation and feeds only dependency-current conclusive observations back into chain regeneration.

**Architecture:** Add six append-only firmware-dive tables and four focused modules. `firmware_dive_questions.py` owns strict manifests, stable subjects, resolution contracts and packets; `firmware_dive_acquisition.py` owns sealed hardware captures and the no-network single-binary probe runner; `firmware_dive_results.py` owns bounded hostile-result parsing, semantic validation and atomic per-question import; `firmware_dive.py` owns verified graph snapshots, immutable generation preparation, completion, conflict/current-overlay derivation and Stage 4g invalidation. A new `dive` CLI exposes prepare/probe/capture/record/check, while Stage 4g consumes the read-only current overlay during regeneration.

**Tech Stack:** Python 3 standard library, SQLite, canonical UTF-8 JSON, `subprocess` process groups, existing content-addressed artifact/workspace helpers, pytest, and `scripts/harness.py`.

**Spec:** `docs/superpowers/specs/2026-10-29-stage4h-firmware-dive-design.md`

## Global Constraints

- Consume only a verified completed Stage 4g graph, except conflict-only preparation may use its exact retained graph artifact plus current Stage 4f/source dependencies.
- Freeze automatic blocker/unknown questions plus a strict linked analyst manifest; every question has stable subjects and a machine-readable resolution contract.
- Outcomes are exactly `supported|refuted|inconclusive`; `value-discovery` cannot be refuted, and only conclusive non-contested observations enter the overlay.
- A completed generation requires one canonical receipt per frozen question, or one exact empty receipt when the denominator is zero; inconclusive questions do not prevent completion.
- Historical dive rows/artifacts are append-only. Dependency changes make observations stale and excluded; they never delete history.
- Identical retries require explicit retry directives and positive attempt ordinals. Contradictory conclusive answers require a conflict-only superseding generation; timestamps never choose a winner.
- Dynamic evidence must be sealed by a question-owned acquisition receipt. Probe execution is no-shell, no-network, path-contained and resource-bounded; unavailable isolation is an observed inconclusive condition, never an unsandboxed fallback.
- Stage 4h never creates findings or claims severity, CVSS, payout, exploitability, exploit success, firmware-wide runtime equivalence or report authority.
- Content-addressed artifacts install before one atomic SQL publication. Expected failures preserve prior SQL and may leave only unreferenced immutable artifacts.
- Human output/diagnostics exclude private evidence and remain bounded/redacted; JSON preserves exact scalar identities and usable artifact paths.
- Generic source-code behavior and sibling images remain unchanged. Python remains standard-library only.
- Every task runs its focused tests plus the relevant upstream regression named below before commit. Final completion reconciles the four durable state documents and runs fresh repository-root `make all`; `make mutate` remains separate.

## Review Focus

1. **Feedback-cycle freshness:** accepted graph-N evidence must remain verifiable after graph-N SQL invalidation without becoming applicable to a semantically different graph-N+1 subject; Tasks 2, 9 and 10 pin this.
2. **Dynamic evidence authorization:** workers must not cite arbitrary new files, probes, captures, host paths or foreign-question artifacts; Tasks 5, 6, 7 and 8 pin acquisition contracts and ownership.
3. **Denominator and conflict truth:** empty, inconclusive, retry and contradictory-answer generations must complete or block exactly as specified without timestamp selection or silent question growth; Tasks 3, 4 and 9 pin this.
4. **Probe containment:** unavailable isolation, hostile paths/symlinks/special files, process-tree timeout, output floods and before/after file drift must never execute unsandboxed or escape the artifact root; Task 6 pins this.
5. **Atomicity and privacy:** artifact-first publication, write races, commit failures, corrupt completed rechecks, Unicode identities and long/private outputs must preserve prior state and bounded public output; Tasks 4, 5, 8, 9 and 11 pin this.

---

### Task 1: Add the six Stage 4h tables and exact row contracts

**Files:**
- Modify: `audit_core/schema.sql`
- Modify: `audit_core/db.py`
- Create: `tests/test_firmware_dive_schema.py`
- Modify: `tests/test_migrate.py`
- Modify: `tests/test_workspace.py`
- Modify: `tests/test_harness.py`

**Interfaces:**
- Produces constants `FIRMWARE_DIVE_RUN_STATES = ("pending", "complete")`, `FIRMWARE_DIVE_ORIGINS = ("chain-blocker", "surface-unknown", "analyst", "conflict")`, `FIRMWARE_DIVE_METHODS = ("static", "emulate", "hardware")`, `FIRMWARE_DIVE_OUTCOMES = ("supported", "refuted", "inconclusive", "empty")`, `FIRMWARE_DIVE_CONTRACT_MODES = ("boolean-claim", "value-discovery")`, `FIRMWARE_DIVE_PREDICATES = ("state-value", "reachability", "edge-validity", "capability-present", "transition-observed")`, `FIRMWARE_DIVE_EVIDENCE_RUNGS = ("static-resolved", "emulated-observed", "hardware-observed")`, `FIRMWARE_DIVE_DEPENDENCY_KINDS = ("finding-artifact", "surface-artifact", "chain-artifact", "extract-record", "probe-manifest", "hardware-capture")`, and `FIRMWARE_DIVE_ACQUISITION_KINDS = ("probe", "capture")`.
- Produces exact tables/keys:
  - `cba_firmware_dive_runs(image_id, dive_generation, manifest_sha256, surface_snapshot_sha256, candidate_snapshot_sha256, chain_graph_path, chain_graph_sha256, analyst_manifest_path, analyst_manifest_sha256, journal_input_path, journal_input_sha256, question_index_path, question_index_sha256, question_count, chain_blocker_count, surface_unknown_count, analyst_question_count, retry_count, conflict_count, status, journal_path, journal_sha256, supported_count, refuted_count, inconclusive_count, prepared_at, completed_at)`, primary key `(image_id, dive_generation)`.
  - `cba_firmware_dive_questions(image_id, dive_generation, question_id, attempt_ordinal, origin, method, question, settling_observation, subject_refs, resolution_contract, axes, prior_observation_id, supersedes_observation_ids, packet_path, packet_sha256, ordinal, recorded_at)`, primary key `(image_id, dive_generation, question_id)`.
  - `cba_firmware_dive_receipts(image_id, dive_generation, receipt_key, receipt_kind, question_id, attempt_ordinal, packet_sha256, result_path, result_sha256, outcome, dependency_count, evidence_count, successor_count, recorded_at)`, primary key `(image_id, dive_generation, receipt_key)`.
  - `cba_firmware_dive_observations(image_id, dive_generation, question_id, attempt_ordinal, observation_id, outcome, conclusion, limitations, resolution_effect, evidence_rung, dependency_refs, evidence_refs, successor_questions, artifact_path, artifact_sha256, recorded_at)`, primary key `(image_id, dive_generation, question_id)`.
  - `cba_firmware_dive_dependencies(image_id, dive_generation, question_id, ordinal, observation_id, kind, logical_id, relative_path, sha256, byte_count, source_provenance, recorded_at)`, primary key `(image_id, dive_generation, question_id, ordinal)`.
  - `cba_firmware_dive_acquisitions(image_id, dive_generation, question_id, acquisition_id, kind, contract_sha256, spec_path, spec_sha256, manifest_path, manifest_sha256, evidence_paths, details, recorded_at)`, primary key `(image_id, dive_generation, question_id, acquisition_id)`.
- Raises fresh schema totals from 38/37 to 44 SQLite/43 contracted tables; the existing four column migrations remain unchanged.

- [ ] **Step 1: Write exact fresh-schema and TableSpec tests.** Assert every column, required column, primary key, six-table total increase and timestamp behavior.
- [ ] **Step 2: Write both frozen-baseline migration tests.** Apply current schema twice to `baseline-pre-stage3.sql` and `baseline-stage4b.sql`; assert all prior firmware rows survive and `connect()` accepts 44/43 tables with four migrations.
- [ ] **Step 3: Write local row-contract tests.** Accept one legal row per variant; reject malformed digests/identifiers/paths, negative or boolean counts/ordinals, noncanonical JSON, invalid enums, illegal pending/complete provenance, question/empty receipt cross-fields, outcome/evidence-rung mismatches, and probe/capture detail variants.
- [ ] **Step 4: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_schema.py tests/test_migrate.py tests/test_workspace.py tests/test_harness.py -q`; expect missing tables/contracts and old totals.
- [ ] **Step 5: Implement additive DDL and row validators.** Keep cross-row question/evidence semantics out of `db.py`.
- [ ] **Step 6: Run GREEN and selftest.** Run the Task 1 command and `python3 audit.py selftest`; expect 44/43 tables and the existing verb count.
- [ ] **Step 7: Commit.** Commit as `feat: add firmware dive state`.

### Task 2: Expose a read-only verified Stage 4g graph snapshot

**Files:**
- Modify: `audit_core/firmware_chain.py`
- Modify: `tests/test_firmware_chain_gate.py`
- Create: `tests/test_firmware_dive_snapshot.py`

**Interfaces:**
- Produces frozen `VerifiedFirmwareGraphSnapshot(image_id, manifest_sha256, surface_snapshot_sha256, candidate_snapshot_sha256, chain_worklist_sha256, graph_path, graph_sha256, findings, dispositions, blockers, chains, edges, surfaces, unknowns)` with exact canonical run-relative provenance.
- Produces `firmware_chain.verified_graph_snapshot(con, run_dir, root, *, image_id=None) -> VerifiedFirmwareGraphSnapshot`; it reconstructs the completed graph without writes, works on a read-only connection/in a caller transaction, and supports the expected later absence of Stage 4g SQL only through an explicit retained-artifact verifier used by conflict preparation—not through the public current snapshot.

- [ ] **Step 1: Write current-graph success tests.** Complete a real Stage 4g fixture; assert exact sorted frozen rows/artifact bytes through read-only SQLite and a caller transaction with zero timestamp/write changes.
- [ ] **Step 2: Write retained-graph tests.** Verify an explicitly owned prior graph artifact plus its stored dive-run provenance after Stage 4g SQL deletion; reject foreign image/generation, missing/corrupt graph bytes and changed current Stage 4f/source dependencies.
- [ ] **Step 3: Write refusal/race tests.** Corrupt live root, upstream artifacts/rows, receipts, graph rows/status/timestamps or same-size bytes; assert no write and one coherent read snapshot under a concurrent change.
- [ ] **Step 4: Run RED.** Run `python3 -m pytest tests/test_firmware_chain_gate.py tests/test_firmware_dive_snapshot.py -q`; expect the snapshot records/helper to be absent.
- [ ] **Step 5: Refactor one internal graph verifier shared by `check()` and the snapshot helpers.** Preserve completed recheck behavior and avoid calling the public writing gate from read-only code.
- [ ] **Step 6: Run GREEN and Stage 4g regression.** Run `python3 -m pytest tests/test_firmware_chain_gate.py tests/test_firmware_dive_snapshot.py -q`.
- [ ] **Step 7: Commit.** Commit as `refactor: expose verified firmware chain snapshot`.

### Task 3: Define strict questions, stable subjects, retries and conflicts

**Files:**
- Create: `audit_core/firmware_dive_questions.py`
- Create: `tests/test_firmware_dive_questions.py`

**Interfaces:**
- Produces frozen `SubjectRef`, `ResolutionContract`, `AnalystQuestion`, `RetryDirective`, `DiveQuestion`, `QuestionPacket`, and `QuestionSet` records matching the spec.
- Produces `load_analyst_manifest(path | None)`, `parse_retry_directives(values)`, `edge_fingerprint(...)`, `chain_fingerprint(...)`, `canonical_question_id(...)`, `derive_questions(snapshot, analyst, history, retries) -> QuestionSet`, and `packet_bytes(question, snapshot, journal_index) -> bytes`.
- Freezes `MAX_ANALYST_MANIFEST_BYTES = 8 * 1024 * 1024`, at most three exact extract records per packet, attempt ordinals starting at one, and stable full SHA-256 subject/question identities.

- [ ] **Step 1: Write automatic-question tests.** Derive exact chain-blocker and referenced-open-surface-unknown questions with resolution contracts; reject unrelated/foreign/resolved unknowns and blockers not in the completed graph.
- [ ] **Step 2: Write analyst-manifest tests.** Accept linked chain/edge/finding/blocker/unknown subjects and both contract modes; reject duplicate keys/questions, unlinked/stale subjects, invalid predicates/values/axes/methods, unsafe text, noncanonical arrays and oversize input.
- [ ] **Step 3: Write stable-fingerprint tests.** Prove display text/blocker order/chain-local IDs do not affect semantic subjects; every endpoint/capability/link/state/evidence/member/initial-state semantic change does.
- [ ] **Step 4: Write retry/conflict tests.** Ordinary identical derivation stays identical; explicit retry increments from durable history and binds prior observation; gaps/foreign retries fail. Contradictory current observations derive one complete conflict question with exact supersedes set; identical conclusive projections do not.
- [ ] **Step 5: Write packet authorization tests.** Assert bounded journal index, exact retained refs, acquisition contract, maximum three named extract records and no full graph/root/private body embedding.
- [ ] **Step 6: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_questions.py -q`; expect the module/interfaces to be absent.
- [ ] **Step 7: Implement pure strict parsing/identity/derivation/serialization.** Perform no SQL, artifact, subprocess or live-root writes.
- [ ] **Step 8: Run GREEN.** Run the Task 3 command.
- [ ] **Step 9: Commit.** Commit as `feat: define firmware dive questions`.

### Task 4: Prepare immutable dive generations and packets

**Files:**
- Create: `audit_core/firmware_dive.py`
- Create: `tests/test_firmware_dive_prepare.py`
- Modify: `tests/test_firmware_dive_snapshot.py`

**Interfaces:**
- Produces `FirmwareDiveError` and `PreparationSummary(image_id, dive_generation, graph_sha256, analyst_manifest_sha256, journal_input_path, question_index_path, question_count, chain_blocker_count, surface_unknown_count, analyst_question_count, retry_count, conflict_count)`.
- Produces `prepare(con, run_dir, root, *, image_id=None, questions_path=None, retry=()) -> PreparationSummary`.
- Installs exactly `files/firmware-dive/<generation>/index.json`, `journal-input.json`, and `questions/<question-id>.json`; generation hashes graph projection, analyst manifest, current input-overlay identities, retry projection and exact questions.

- [ ] **Step 1: Write canonical packet/index tests.** Independently serialize literal expected bytes/digests, reverse SQL insertion order, include Unicode/delimiter image IDs, and prove absolute root/timestamps/private bodies are excluded.
- [ ] **Step 2: Write ordinary/empty/retry preparation tests.** Assert complete current graph requirement, canonical empty manifest/generation, explicit empty denominator, idempotent identical prepare, retry-created generation and immutable older generations.
- [ ] **Step 3: Write conflict-only tests.** After graph invalidation, accept only exact current contested observations plus retained verified graph/source dependencies; reject unrelated analyst questions/retries, incomplete conflict sets and stale retained evidence.
- [ ] **Step 4: Write isolation/scale tests.** Preserve sibling images and all historical generations; retain 201+ questions without display caps or silent truncation.
- [ ] **Step 5: Write artifact/atomicity tests.** Refuse redirected parents/symlinks/extra files/installed-byte drift, active transactions, post-install input/history races, SQL/commit failure and two-connection contention; prior SQL survives.
- [ ] **Step 6: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_snapshot.py tests/test_firmware_dive_questions.py tests/test_firmware_dive_prepare.py -q`; expect missing lifecycle behavior.
- [ ] **Step 7: Implement artifact-first install, locked revalidation and append-only run/question publication.** Never invalidate Stage 4g during prepare.
- [ ] **Step 8: Run GREEN and upstream regression.** Run the Task 4 command plus `tests/test_firmware_chain_prepare.py tests/test_firmware_chain_gate.py`.
- [ ] **Step 9: Commit.** Commit as `feat: prepare firmware dive questions`.

### Task 5: Seal question-owned hardware captures

**Files:**
- Create: `audit_core/firmware_dive_acquisition.py`
- Create: `tests/test_firmware_dive_capture.py`

**Interfaces:**
- Produces `AcquisitionError`, `AcquisitionContract`, `CaptureSpec`, and `AcquisitionSummary`.
- Produces `load_capture_spec(path) -> CaptureSpec` and `seal_capture(con, run_dir, root, spec_path) -> AcquisitionSummary`.
- Freezes maximum capture input at 64 MiB and 256 regular files; installs `artifacts/firmware-dive-captures/<capture-id>/{spec.json,manifest.json,evidence/...}` and publishes one `capture` acquisition row.

- [ ] **Step 1: Write strict spec/identity tests.** Pin exact question/generation/contract/device/firmware/state/operator/method ownership and literal manifest/capture ID; reject duplicate/unknown keys, foreign question, wrong method/contract, invalid states/digests and noncanonical arrays.
- [ ] **Step 2: Write filesystem refusal tests.** Reject absolute/escaping paths, symlinks at every level, directories where files belong, devices/FIFOs/sockets, file-count/byte overflow, duplicate flattened names and changed source bytes during copy.
- [ ] **Step 3: Write publication/idempotence tests.** Assert artifact-first copy, exact duplicate preservation, conflicting duplicate refusal, sibling question/image survival, installed-byte recheck, SQL/commit failure and write-lock race rollback.
- [ ] **Step 4: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_capture.py -q`; expect missing acquisition module.
- [ ] **Step 5: Implement bounded strict capture sealing and atomic acquisition receipt publication.** Never contact or control a device.
- [ ] **Step 6: Run GREEN.** Run the Task 5 command.
- [ ] **Step 7: Commit.** Commit as `feat: seal firmware dive captures`.

### Task 6: Run bounded no-network single-binary probes

**Files:**
- Modify: `audit_core/firmware_dive_acquisition.py`
- Create: `tests/test_firmware_dive_probe.py`

**Interfaces:**
- Produces frozen `ProbeSpec` and `ProbeTermination` plus `run_probe(con, run_dir, root, spec_path) -> AcquisitionSummary`.
- Supports known adapter implementations for an already installed `bwrap` or macOS `sandbox-exec`; a caller-supplied adapter path must identify one of those known programs. Internal adapter objects are injectable for deterministic tests. No adapter means a sealed `executed=false, reason=isolation-unavailable` probe manifest and no firmware process.
- Freezes timeout 1..300 seconds, argv <=128 entries/4096 UTF-8 bytes each, environment <=64 safe names/4096-byte values, stdout/stderr 1 MiB each, outputs <=8 MiB/256 regular files, `network_policy="none"`, no shell and no ambient PATH lookup.

- [ ] **Step 1: Write strict probe-spec and hashing tests.** Bind exact question contract, executable/runner/loader/library/shim/input/output paths, argv/environment/limits and before/after hashes; reject dangerous loader variables except the explicit shim field.
- [ ] **Step 2: Write isolation refusal tests.** Missing/not-ready/unknown/renamed adapter returns nonexecuted manifest; assert subprocess is never invoked and no acquisition conclusion is inferred.
- [ ] **Step 3: Write controlled execution tests.** With an injected fixture adapter, assert argv-list/no-shell invocation, minimal environment, new process group, closed descriptors, stdin/output containment and deterministic manifest.
- [ ] **Step 4: Write hostile runtime tests.** Cover timeout plus descendant cleanup, crash/signal/nonzero exit, stdout/stderr truncation, output count/size overflow, undeclared/escaping/symlink/special outputs, executable/input drift, adapter failure and cleanup failure; no host escape or partial SQL.
- [ ] **Step 5: Write publication/race tests.** Exact duplicate is idempotent; conflicting acquisition, concurrent write, SQL/commit failure and post-run dependency drift preserve prior state and may leave only unreferenced artifacts.
- [ ] **Step 6: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_capture.py tests/test_firmware_dive_probe.py -q`; expect missing probe behavior.
- [ ] **Step 7: Implement adapters, process-group lifecycle, bounded capture and atomic acquisition publication.** Do not run corpus firmware in tests.
- [ ] **Step 8: Run GREEN.** Run the Task 6 command.
- [ ] **Step 9: Commit.** Commit as `feat: add bounded firmware dive probes`.

### Task 7: Parse strict dive results and derive observations

**Files:**
- Create: `audit_core/firmware_dive_results.py`
- Create: `tests/test_firmware_dive_results.py`

**Interfaces:**
- Constants `RESULT_SCHEMA_VERSION = 1`, `MAX_RESULT_BYTES = 8 * 1024 * 1024`.
- Produces frozen `ResolutionEffect`, `DependencyRef`, `EvidenceRef`, `SuccessorQuestion`, `QuestionAnswer`, `EmptyAnswer`, and `DiveResult` variants.
- Produces `load(path) -> DiveResult`, `canonical_observation_id(...)`, `canonical_receipt_key(...)`, and `canonical_bytes(...)`; evidence rung is absent from worker JSON and derived later.

- [ ] **Step 1: Write literal valid question-answer tests.** Cover supported boolean, refuted boolean, supported value-discovery, inconclusive with partial evidence, dynamic acquisition refs, successor questions and Unicode identities.
- [ ] **Step 2: Write exact empty-result tests.** Accept only matching image/generation with `questions: []`; reject it for nonempty generation and reject observations/dependencies/evidence on the empty variant.
- [ ] **Step 3: Write hostile parser tests.** Reject invalid UTF-8, duplicate/extra/missing keys, invalid variants/enums/IDs/digests/paths, non-finite/coerced/boolean integers, duplicate/noncanonical arrays, unsafe text, raw/canonical oversize and worker-supplied rung/SQL/derived fields.
- [ ] **Step 4: Write contract/effect and receipt identity tests.** Reject refuted value-discovery and effects outside packet contract; prove prose/limitations/effect/dependency/evidence changes alter observation ID while labels/order of semantic-free sets do not. Prove question and empty receipt keys are safe `firmware-dive-receipt-<sha256>` identifiers over their exact canonical projections, change with every bound identity field, and exclude local paths/timestamps.
- [ ] **Step 5: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_results.py -q`; expect missing module/types.
- [ ] **Step 6: Implement bounded exact parsing, variants, canonical serialization and pure identity helpers.** Perform no SQL/filesystem writes.
- [ ] **Step 7: Run GREEN.** Run the Task 7 command.
- [ ] **Step 8: Commit.** Commit as `feat: parse firmware dive results`.

### Task 8: Validate and import one question result atomically

**Files:**
- Modify: `audit_core/firmware_dive_results.py`
- Create: `tests/test_firmware_dive_import.py`
- Modify: `tests/test_firmware_dive_results.py`

**Interfaces:**
- Produces SQL-ready `ValidatedDiveResult(receipt, observation | None, dependencies)` and `validate(con, run_dir, result) -> ValidatedDiveResult`; read-only, caller-transaction compatible and live-root free.
- Produces `record(con, run_dir, result_path) -> RecordSummary`; installs canonical result bytes and atomically publishes receipt/observation/dependencies. No replace mode.

- [ ] **Step 1: Pin exact assignment/variant coverage.** Require pending prepared generation, exact question packet/attempt ownership or exact empty denominator; reject missing/foreign/already-conflicting assignment and question/empty variant mismatch.
- [ ] **Step 2: Pin static/dynamic evidence authorization.** Accept only packet-enumerated static dependencies or exact question-owned sealed acquisitions satisfying the frozen contract; reject arbitrary paths, foreign/stale probes/captures, changed manifests and evidence not backed by a dependency.
- [ ] **Step 3: Pin semantic outcomes.** Derive exact rung from method/acquisition kind; require conclusive evidence/effect, inconclusive reason, limitations for dynamic rungs, authorized successors and complete dependency provenance.
- [ ] **Step 4: Pin artifact/SQL atomicity.** Test exact duplicate no-write idempotence, conflicting duplicate refusal, symlink/redirected result install, post-install packet/acquisition/history race, rollback at every table/commit and sibling question/generation/image preservation.
- [ ] **Step 5: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_results.py tests/test_firmware_dive_import.py -q`; expect missing validation/import.
- [ ] **Step 6: Implement read-only validation, canonical artifact install, locked revalidation and one transaction publication.** Leave run pending.
- [ ] **Step 7: Run GREEN and acquisition regression.** Run the Task 8 command plus `tests/test_firmware_dive_capture.py tests/test_firmware_dive_probe.py`.
- [ ] **Step 8: Commit.** Commit as `feat: import firmware dive observations`.

### Task 9: Complete generations, derive the journal and current overlay

**Files:**
- Modify: `audit_core/firmware_dive.py`
- Modify: `audit_core/firmware_dive_results.py`
- Create: `tests/test_firmware_dive_gate.py`

**Interfaces:**
- Produces `DiveQuestionSummary`, `FirmwareDiveSummary`, `CurrentDiveObservation`, and `CurrentDiveOverlay(schema_version=1, observations=...)`.
- Produces `check(con, run_dir, root, *, image_id=None) -> FirmwareDiveSummary` and `current_overlay(con, run_dir, root, verified_findings_snapshot) -> CurrentDiveOverlay`.
- Canonical overlay bytes are `{"observations":[],"schema_version":1}` before any current conclusive observation.

- [ ] **Step 1: Write complete supported/refuted/inconclusive tests.** Require exact receipt denominator and reconstruct every result/acquisition/dependency/row; derive outcome counts/rungs/journal bytes and allow full completion with inconclusive questions.
- [ ] **Step 2: Write truthful empty completion tests.** Require the empty receipt variant, publish empty journal/overlay and reject absent/extra question receipts.
- [ ] **Step 3: Write retry/conflict tests.** Retain all attempts; identical conclusions deduplicate overlay identity; contradictory conclusive answers become contested and yield no overlay entry; exact superseding conflict answer clears only its complete conflict set.
- [ ] **Step 4: Write freshness tests.** Retained graph bytes are historical provenance; current Stage 4f/source/extract/probe/capture hashes plus stable subjects determine currentness. Changed dependency makes history stale/excluded; missing current graph SQL after dive invalidation remains a valid completed recheck.
- [ ] **Step 5: Write corruption/foreign-row tests.** Reject missing/extra/changed receipts, observations, dependencies, acquisitions, timestamps, artifacts, outcome counts and journal bytes; completed check never repairs.
- [ ] **Step 6: Write atomic invalidation tests.** On changed accepted overlay, install journal then under one lock publish completion and call `firmware_chain.invalidate`; failures at every dive/chain table or commit preserve pending dive plus prior complete graph. No overlay change preserves graph.
- [ ] **Step 7: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_gate.py -q`; expect missing completion/overlay behavior.
- [ ] **Step 8: Implement independent reconstruction, journal/overlay derivation, historical recheck and transactional Stage 4g invalidation.** Keep history append-only.
- [ ] **Step 9: Run GREEN and Stage 4g gate regression.** Run the Task 9 command plus `tests/test_firmware_chain_gate.py`.
- [ ] **Step 10: Commit.** Commit as `feat: complete firmware dive journals`.

### Task 10: Feed current dive observations into Stage 4g regeneration

**Files:**
- Modify: `audit_core/firmware_chain.py`
- Modify: `audit_core/firmware_chain_results.py`
- Modify: `references/briefs/firmware-chain-brief.md`
- Modify: `tests/test_firmware_chain_prepare.py`
- Modify: `tests/test_firmware_chain_validation.py`
- Modify: `tests/test_firmware_chain_gate.py`
- Create: `tests/test_firmware_dive_overlay.py`

**Interfaces:**
- Stage 4g worklist projection gains `dive_overlay` with exact schema/version/observation identity and structured effects. Its worklist hash remains the sole stored overlay provenance; no Stage 4g schema migration is added.
- Stage 4g evidence refs gain `dive:<observation-id>#conclusion` and `#evidence`; only supported current observations may provide positive evidence. Refuted edge subjects are constraints and never positive evidence.

- [ ] **Step 1: Pin canonical empty-overlay compatibility.** With no dive history, assert Stage 4g literal worklist/result/check behavior and generic source-code chain behavior remain unchanged except the explicit empty overlay field/hash.
- [ ] **Step 2: Pin supported overlay behavior.** Regenerate from current supported state/capability/transition effects; require matching stable subject fingerprint and authorize exact dive refs only for the matching edge/finding/blocker/unknown.
- [ ] **Step 3: Pin refuted/contested/stale constraints.** Reject recreation of exactly refuted edge fingerprint or settled blocker; reject positive use of refuted, stale, contested, foreign-image or changed-dependency observations.
- [ ] **Step 4: Pin feedback races/atomicity.** Change overlay between Stage 4g initial read and lock, corrupt retained dive artifacts, fail publication/commit and overlap image IDs; prior chain/dive history and sibling images survive.
- [ ] **Step 5: Update the chain brief contract.** Require workers to consume supported effects, honor refuted constraints and never treat dive prose/rung as severity or exploit proof.
- [ ] **Step 6: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_overlay.py tests/test_firmware_chain_prepare.py tests/test_firmware_chain_validation.py tests/test_firmware_chain_gate.py -q`; expect overlay behavior absent.
- [ ] **Step 7: Implement local-import overlay selection, worklist projection, dive ref validation and completion reconstruction.** Avoid module-level circular imports.
- [ ] **Step 8: Run GREEN and full Stage 4f-4h regression.** Run `python3 -m pytest tests/test_firmware_fpcheck*.py tests/test_firmware_chain*.py tests/test_firmware_dive*.py -q`.
- [ ] **Step 9: Commit.** Commit as `feat: regenerate firmware chains from dive evidence`.

### Task 11: Expose the bounded `dive` CLI

**Files:**
- Modify: `audit.py`
- Create: `tests/test_cli_stage4h.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_cli_stage3.py`
- Modify: `tests/test_harness.py`

**Interfaces:**
- Adds verb `dive` with exactly one mode `--prepare|--probe SPEC|--capture SPEC|--record RESULT|--check`; all require `--run`; prepare/check require `--root` and optionally `--image-id`; probe/capture require root and prepared question; `--questions`/repeatable `--retry` belong only to prepare; `--json` works in every mode.
- Success JSON/human output uses fixed scalar summaries only. Expected database errors map to `dive: database operation failed`; other expected diagnostics are escaped/root-redacted/capped at 512 ASCII characters plus newline.
- Raises verb count from 29 to 30; schema remains 44/43.

- [ ] **Step 1: Write parser/flag-matrix tests.** Pin syntax exit 2 before DB access, semantic exit 1, mode-specific flags, required root/run, repeatable retry syntax and no interaction with existing verbs.
- [ ] **Step 2: Write delegation/cleanup tests.** Assert exact module calls/arguments, connection closure, expected exception mapping and unexpected exception propagation after cleanup for all five modes.
- [ ] **Step 3: Write output privacy tests.** Human and JSON expose only whitelisted counts/IDs/paths/outcomes; never question/conclusion/stdout/stderr/capture/code/environment evidence. Pin Unicode/long/control/root-prefix identity/path round-trips and bounded diagnostics.
- [ ] **Step 4: Write real subprocess workflows.** Cover empty prepare/record/check, one static answer, unavailable isolation probe, sealed capture, inconclusive completion, retry/conflict and post-dive Stage 4g regeneration.
- [ ] **Step 5: Run RED.** Run `python3 -m pytest tests/test_cli_stage4h.py tests/test_cli.py tests/test_cli_stage3.py tests/test_harness.py -q`; expect missing verb/old count.
- [ ] **Step 6: Implement parser, handler, fixed renderers and exception boundaries.** Keep private result/evidence bodies out of output.
- [ ] **Step 7: Run GREEN and selftest.** Run the Task 11 command and `python3 audit.py selftest`; expect 30 verbs and 44/43 tables.
- [ ] **Step 8: Commit.** Commit as `feat: expose firmware dive CLI`.

### Task 12: Ship the per-question worker brief and installed routing

**Files:**
- Create: `references/briefs/firmware-dive-brief.md`
- Create: `tests/test_firmware_dive_brief.py`
- Modify: `tests/test_brief_templates.py`
- Modify: `tests/test_install.py`
- Modify: `SKILL.md`
- Modify: `ARCHITECTURE.md`

**Interfaces:**
- Brief variables are exactly `run_dir`, `rootfs`, `image_id`, `dive_generation`, `question_id`, `packet_path`, `journal_index_path`, and `result_path`.
- Exact return: `firmware-dive <DONE|PARTIAL|FAILED> question=<question-id> artifact=<path> [flags=<csv>]`.
- Installed routing is prepare -> render one brief/fresh strongest worker per indexed question -> optional probe/capture -> record each DONE -> check after every frozen assignment terminates. Workers own result JSON only.

- [ ] **Step 1: Write RED prose/render/install tests.** Pin exact variables/return, one-question assignment, at most three extracts, proposition/effect contract, observation-vs-inference, adversarial environment checks, dynamic artifact ownership, supported/refuted/inconclusive variants, successor semantics and strict JSON-only output.
- [ ] **Step 2: Pin authority/non-goals.** Require no SQL/artifact/completion/chain-regeneration/severity/exploit/report authority; crashes/timeouts/tool absence are inconclusive; PARTIAL is nonimportable and retains the same assignment.
- [ ] **Step 3: Pin installed Claude/Codex rendering and routing.** Assert the tenth template installs, every parser/schema/acquisition reference resolves in installed copies, evidence stays file-backed, fresh workers receive only brief paths/scalars and existing generic/firmware routes remain intact.
- [ ] **Step 4: Run RED.** Run `python3 -m pytest tests/test_firmware_dive_brief.py tests/test_brief_templates.py tests/test_install.py tests/test_skill_lint.py tests/test_workflow_prose.py -q`; expect missing template/route.
- [ ] **Step 5: Implement brief, Stage 4h SKILL route and durable architecture interface.** Preserve required CRLF in `SKILL.md`; all new files use LF.
- [ ] **Step 6: Run GREEN.** Run the Task 12 command and `git -c core.whitespace=cr-at-eol diff --check`.
- [ ] **Step 7: Commit.** Commit as `feat: ship firmware dive agent brief`.

### Task 13: Close coverage, review the whole branch and reconcile Stage 4h

**Files:**
- Create only if needed for real uncovered behavior: `tests/test_firmware_dive_coverage.py`
- Modify: `progress.md`
- Modify: `SESSION_HANDOFF.md`
- Modify: `ARCHITECTURE.md`
- Modify: `feature_lists.json`
- Modify approved spec/plan only to record implementation-approved refinements/execution truth without rewriting history.

**Interfaces:**
- Produces truthful present state: Stage 4h implemented on `stage4h-firmware-dive`, integration pending until explicit merge, no push, and Stage 4i `decide` next.
- Preserves Asus golden, paid milestone, second indicator snapshot, mutation sweep, separate firmware skill tree, monorepo/submodule decision, triage upsert-only behavior and Stage 4d orphan-scan limitation.

- [ ] **Step 1: Run focused Stage 4h and upstream regressions.** Run all `tests/test_firmware_dive*.py`, Stage 4f/4g suites, CLI/brief/install/migration/workspace/harness tests; fix failures before review.
- [ ] **Step 2: Close real coverage gaps without allowlisting.** Run the coverage probe, add meaningful branch assertions for every new unexecuted statement, preserve zero allowed entries, and rerun affected suites.
- [ ] **Step 3: Run an independent whole-branch firmware-security review.** Review `main...HEAD` for provenance, stale-overlay/cycle safety, denominator/conflict truth, acquisition authorization, process containment, atomicity, privacy, installed routing and generic compatibility. Fix every Critical/Important with focused RED/GREEN and scoped re-review.
- [ ] **Step 4: Reconcile all four durable state documents.** Add Stage 4h stage/feature paths/verb/tables, final reviewed implementation commit and measured focused results; remove `dive` from next steps and name `decide` with inherited limitations.
- [ ] **Step 5: Validate structured documentation.** Run `python3 -m json.tool feature_lists.json >/dev/null`, manifest-focused tests, CRLF-aware diff check and targeted stale-state searches.
- [ ] **Step 6: Run authoritative final harness after the final documentation edit.** Run repository-root `make all`; require all eight gates and record only emitted test, verb, schema/contract, migration, EOL, manifest, install, coverage and benchmark values. If any recorded value changes, edit docs and rerun after that edit.
- [ ] **Step 7: State optional gates honestly.** Record that mutation, paid audit/milestone, Asus golden, second indicator snapshot and real corpus probe/hardware work did not run unless they actually did.
- [ ] **Step 8: Commit final reconciliation.** Commit as `docs: record Stage 4h firmware dive`.
- [ ] **Step 9: Run final whole-branch review procedure and clean handoff.** Require no remaining Critical/Important finding, clean `git status`, exact `main..HEAD` log/stat and an unmerged/unpushed feature branch ready for the operator's integration choice.

## Completion Criteria

- Every frozen question is explicitly receipted, including truthful empty and inconclusive generations; no worker can silently grow the denominator.
- Every conclusive resolution has an exact packet contract, structured effect, authorized evidence, immutable dependencies and independently reconstructed receipt.
- Retries preserve history; contradictory answers become contested until an exact superseding generation resolves the complete conflict set.
- Probe execution never falls back to unsandboxed/networked operation and every dynamic artifact belongs to one prepared question.
- Historical observations survive source changes but stale/contested evidence cannot enter Stage 4g or `decide`.
- Stage 4g regeneration consumes only the current overlay, honors refuted constraints and matching stable semantic subjects, and remains compatible with an empty overlay and generic chain behavior.
- A fresh whole-branch reviewer reports no Critical/Important issue.
- Final reconciled `make all` passes all eight gates; `make mutate` remains separately reported.
