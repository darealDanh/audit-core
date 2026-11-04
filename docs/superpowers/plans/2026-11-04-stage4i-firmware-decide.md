# Stage 4i Firmware Decide Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a provenance-bound firmware `decide` phase that ranks every current chain, preserves every open precondition, applies a separately hashed operator policy, and publishes one deterministic immutable acquisition package.

**Architecture:** Add one Stage 4i lifecycle table and two focused modules. `firmware_decide.py` owns strict policy, current technical authority, immutable preparation, deterministic policy matching, completion, package publication and the verified current-package boundary; `firmware_decide_results.py` owns bounded hostile worker JSON, complete chain coverage, open-precondition/bench/script validation and atomic result import. One global worker proposes ranking and bench work; deterministic code owns payout projections and `acquire|defer|pass`.

**Tech Stack:** Python 3 standard library, SQLite, canonical UTF-8 JSON, existing descriptor-anchored immutable artifact helpers, argparse, pytest, Markdown briefs, and `scripts/harness.py`.

**Spec:** `docs/superpowers/specs/2026-11-04-stage4i-firmware-decide-design.md`

## Global Constraints

- Consume only one current completed Stage 4g graph whose frozen overlay equals the independently reconstructed current non-contested Stage 4h overlay.
- Refuse preparation while a selected-image dive generation is pending; require an explicit completed denominator, including the canonical empty-receipt case.
- Operator policy is a separately hashed assertion snapshot, never technical evidence.
- Every current chain is assessed exactly once and ranked by the exact contiguous set `1..chain_count`; empty graphs require explicit empty-result coverage.
- Current graph blocker/unknown references are the complete open-precondition denominator. Stage 4i cannot settle or omit them.
- Workers cannot assign payout, final recommendation, severity, CVSS, exploit reliability/success, disclosure language, or currentness.
- Proposed scripts are embedded bounded UTF-8, installed mode `0600`, marked unreviewed, and never executed by core, CLI, tests, or routing.
- Historical packages remain immutable. Currentness is proved through `verified_package`; no Stage 4a–4h invalidation cascade is added.
- Content-addressed artifacts install before atomic SQL publication. Expected failures preserve prior SQL and may leave only unreferenced immutable artifacts.
- Generic source-code behavior, sibling images, and all Stage 4a–4h history remain unchanged.
- Python remains standard-library only.
- Per-task verification is focused. Repository-wide pytest, full coverage, installer and benchmark gates MUST NOT run before Task 6.
- Final completion performs one planned repository-root `make all` after code review and after implementation paths/routing/deterministic metadata are reconciled. Exact harness status/metrics are then recorded through status-only durable-doc edits followed by every doc-sensitive gate; rerun `make all` only if code, tests, routing, manifest paths or executable behavior changes.
- `make mutate`, paid audit/milestone, Asus golden, second indicator snapshot, real hardware work and Linux/alternate-interpreter execution remain separate.

## Review Focus

1. **Historical-row confusion:** direct SQL history must never be returned as a current decision after graph, dive or policy changes; Task 4 tests `verified_package` and no historical fallback.
2. **Observation/policy authority bleed:** support/payout assertions and worker prose must not become technical evidence or vice versa; Tasks 1, 3 and 4 test copied facts, derived fields and policy-only projection.
3. **Incomplete denominator:** blocked/deprioritized chains and open blocker/unknown subjects must not disappear from a persuasive result; Task 3 tests exact complete coverage and rank/precondition sets.
4. **Recommendation edge precedence:** simultaneous unsupported/unknown/cost/no-match/bench-incomplete conditions must produce the spec's exact primary and ordered secondary reasons; Task 4 tests every overlap.
5. **Script execution or filesystem escape:** embedded script names/bytes must remain bounded inert regular files and no subprocess path may run; Tasks 3 and 4 test hostile names, modes, sentinels and descriptor-safe publication.

---

### Task 1: Add the one-row lifecycle and strict operator policy

**Files:**
- Modify: `audit_core/schema.sql`
- Modify: `audit_core/db.py`
- Create: `audit_core/firmware_decide.py`
- Create: `tests/test_firmware_decide_schema.py`
- Create: `tests/test_firmware_decide_policy.py`
- Modify: `tests/test_migrate.py`
- Modify: `tests/test_workspace.py`
- Modify: `tests/test_harness.py`

**Interfaces:**
- Produces constants `FIRMWARE_DECIDE_STATES = ("pending", "recorded", "complete")`, `FIRMWARE_DECISIONS = ("acquire", "defer", "pass")`, `FIRMWARE_DECIDE_SUPPORT = ("supported", "unsupported", "unknown")`, `FIRMWARE_DECIDE_PAYOUT_STATUS = ("eligible", "ineligible", "unknown")`, and the ordered reason-code tuple from the spec.
- Produces one table `cba_firmware_decide_runs` with primary key `(image_id, decision_generation)` and exact columns: `image_id`, `decision_generation`, `manifest_sha256`, `surface_snapshot_sha256`, `candidate_snapshot_sha256`, `chain_worklist_sha256`, `graph_path`, `graph_sha256`, `dive_generation`, `journal_path`, `journal_sha256`, `overlay_sha256`, `policy_id`, `policy_path`, `policy_sha256`, `worklist_path`, `worklist_sha256`, `status`, `result_path`, `result_sha256`, `package_path`, `package_sha256`, `decision`, `primary_reason`, `reason_codes`, `chain_count`, `bench_test_count`, `script_count`, `policy_match_count`, `prepared_at`, `recorded_at`, `completed_at`.
- Produces frozen `PayoutPath(path_id, status, basis)`, `PolicyTier(tier_id, payout_path_id, ordinal, minimum_minor, maximum_minor, accepted_pre_auth, minimum_confidence, accepted_completeness, accepted_evidence_rungs, physical_access_allowed)`, and `DecisionPolicy(schema_version, policy_id, currency, acquisition_cost_minor, max_acquisition_cost_minor, support_status, support_basis, payout_paths, tiers, notes)`.
- Produces `load_policy(path: str | pathlib.Path) -> DecisionPolicy` and `policy_bytes(policy: DecisionPolicy) -> bytes` in `firmware_decide.py`.
- Raises fresh totals from 44/43 to 45 SQLite tables / 44 TableSpecs; all four existing migrations remain unchanged.

- [ ] **Step 1: Write schema RED.** Assert exact columns/key/required fields, legal pending/recorded/complete variants, canonical JSON cells, timestamp progression, enum/digest/path/count bounds, sibling-image keys, 45/44 totals, and both frozen baseline migrations.
- [ ] **Step 2: Run schema RED.** Run `python3 -m pytest tests/test_firmware_decide_schema.py tests/test_migrate.py tests/test_workspace.py tests/test_harness.py -q`; expect the table/spec and totals to be absent.
- [ ] **Step 3: Implement additive DDL and local row validation.** Keep graph/dive/policy cross-row semantics out of `db.py`.
- [ ] **Step 4: Write policy RED.** Pin literal canonical bytes; accept the spec's bounded legal policy; reject invalid UTF-8, duplicate/extra/missing keys, noncanonical arrays, booleans as integers, non-finite/coerced values, invalid currency/IDs/status, missing/duplicate path/tier references, ordinal gaps, nonmonotonic ranges, invalid vocabularies, overlong prose and input over 1 MiB.
- [ ] **Step 5: Run policy RED.** Run `python3 -m pytest tests/test_firmware_decide_policy.py -q`; expect `firmware_decide` policy interfaces to be absent.
- [ ] **Step 6: Implement frozen strict policy parsing.** Reuse existing canonical/strict primitives where their exception and bounds semantics match; do not import result code or touch SQL.
- [ ] **Step 7: Run Task 1 GREEN.** Run the two Task 1 commands plus `python3 audit.py selftest`; require all focused tests and 45/44 schema agreement.
- [ ] **Step 8: Commit.** Commit as `feat: add firmware decision policy state`.

### Task 2: Verify current decision authority and prepare immutable worklists

**Files:**
- Modify: `audit_core/firmware_dive.py`
- Modify: `audit_core/firmware_decide.py`
- Create: `tests/test_firmware_decide_input.py`
- Create: `tests/test_firmware_decide_prepare.py`
- Modify: `tests/test_firmware_dive_gate.py`
- Modify: `tests/test_firmware_dive_overlay.py`

**Interfaces:**
- Produces frozen `VerifiedDiveDecisionInput(image_id, dive_generation, journal_path, journal_sha256, overlay_sha256, overlay)` and `firmware_dive.verified_decision_input(con, run_dir, root, graph_snapshot) -> VerifiedDiveDecisionInput`.
- The helper requires one current completed `VerifiedFirmwareGraphSnapshot`, no selected-image pending dive generation, one explicit latest completed denominator, exact journal/result/acquisition/dependency reconstruction, and graph-frozen/current-overlay equality; supports read-only SQLite and caller transactions with no write/repair.
- Produces frozen `VerifiedFirmwareDecisionInput(graph, dive)` and `DecisionPreparationSummary(image_id, decision_generation, graph_sha256, dive_generation, overlay_sha256, policy_id, policy_path, policy_sha256, worklist_path, worklist_sha256, chain_count, open_precondition_count)`.
- Produces `verified_input(con, run_dir, root, *, image_id=None) -> VerifiedFirmwareDecisionInput` and `prepare(con, run_dir, root, policy_path, *, image_id=None) -> DecisionPreparationSummary`.
- Installs exactly `files/firmware-decide/<decision-generation>/{policy.json,worklist.json}`; `policy.json` is the canonical policy snapshot and owns the row's run-relative policy path/hash; `decision_generation == sha256(worklist_bytes)`.

- [ ] **Step 1: Write decision-input RED.** Complete real Stage 4g/4h fixtures; assert exact graph/dive/journal/overlay fields, completed empty-dive acceptance, graph-frozen/current-overlay equality, zero writes under read-only/caller transactions, and selected-image isolation.
- [ ] **Step 2: Write refusal RED.** Reject missing/incomplete graph, absent explicit dive denominator, pending dive, stale/corrupt journal/results/acquisitions/dependencies, stale/contested overlay, changed source/root, foreign image, and graph built from a different overlay.
- [ ] **Step 3: Run input RED.** Run `python3 -m pytest tests/test_firmware_decide_input.py tests/test_firmware_dive_gate.py tests/test_firmware_dive_overlay.py -q`; expect the verified boundary to be absent.
- [ ] **Step 4: Implement `verified_decision_input` and `verified_input`.** Share existing independent Stage 4h reconstruction; do not trust status/hash columns without re-derivation and do not expose historical fallback.
- [ ] **Step 5: Write prepare RED.** Pin literal worklist bytes/generation, exact complete graph/overlay/policy projection, current blocker/unknown denominator, Unicode/delimiter image identity, idempotent identical preparation, changed-policy/new generation, preserved history/sibling image, active-generation ambiguity, installed-byte drift, symlink/parent replacement, concurrent input change, SQL/commit failure and write-lock rollback.
- [ ] **Step 6: Run prepare RED.** Run `python3 -m pytest tests/test_firmware_decide_prepare.py -q`; expect preparation interfaces to be absent.
- [ ] **Step 7: Implement descriptor-safe artifact-first prepare.** Verify before install, reverify under `BEGIN IMMEDIATE`, publish one pending row, and preserve exact completed identical state/timestamps.
- [ ] **Step 8: Run Task 2 GREEN.** Run the Task 2 input and prepare commands; do not run unrelated suites.
- [ ] **Step 9: Commit.** Commit as `feat: prepare firmware acquisition decisions`.

### Task 3: Parse, validate and import complete global decision results

**Files:**
- Create: `audit_core/firmware_decide_results.py`
- Create: `tests/test_firmware_decide_results.py`
- Create: `tests/test_firmware_decide_import.py`
- Modify: `audit_core/firmware_decide.py`

**Interfaces:**
- Produces frozen `OpenPrecondition`, `ChainAssessment`, `BenchTest`, `ProposedScript`, `DecisionAnswer`, `EmptyDecisionAnswer`, and `DecisionResult` variants matching the spec.
- Produces `load(path) -> DecisionResult`, `canonical_bytes(result) -> bytes`, `validate(con, run_dir, result) -> ValidatedDecisionResult`, and `record(con, run_dir, result_path) -> DecisionRecordSummary`.
- `ValidatedDecisionResult` contains the exact canonical result bytes/digest, complete sorted chain assessments, exact open-precondition denominator, validated bench tests and script bytes; it contains no policy match, payout projection or final recommendation.
- Result raw and canonical bytes are capped at 8 MiB. Script count/size limits are exactly 16 / 32 KiB each / 256 KiB total.
- Installs `artifacts/firmware-decide-results/<generation>/<result-sha256>/result.json` before atomically moving the selected row from `pending` to `recorded`.

- [ ] **Step 1: Write strict parser RED.** Cover a literal nonempty result and explicit empty result; reject invalid UTF-8, duplicate/unknown/missing keys, wrong variants, non-finite/coerced values, unsafe text, invalid IDs/paths/enums, raw/canonical oversize, worker-supplied policy matches/payout/recommendation/derived currentness, mutable aliases, and noncanonical arrays.
- [ ] **Step 2: Write complete coverage/rank RED.** Require exact current chain IDs once each and ranks exactly `1..N`; reject omitted/duplicate/foreign chains, copied graph-field drift, duplicate/gapped ranks, nonempty assessment on an empty graph, and empty variant on a nonempty graph.
- [ ] **Step 3: Write open-precondition/evidence RED.** Require the exact union of chain/edge blocker IDs and open unknown IDs with copied question/text/settling/method/axes/location; reject omission, settled/foreign/invented subjects, observations not current/applicable to the chain, private bodies, and successor questions absent from the current graph.
- [ ] **Step 4: Write bench/script RED.** Accept shared tests and optional scripts; reject tests without exact current chain/precondition/transition ownership, inconsistent required state, missing control/stop conditions, duplicate semantic test IDs, missing script refs, unsafe/duplicate/traversing names, invalid UTF-8/NUL, every count/byte overflow and any external-file variant.
- [ ] **Step 5: Run parser RED.** Run `python3 -m pytest tests/test_firmware_decide_results.py -q`; expect the result module to be absent.
- [ ] **Step 6: Implement pure parsing, identities and semantic validation.** Keep policy matching and recommendation out of this module; no SQL/filesystem writes in `load`/`validate`.
- [ ] **Step 7: Write import RED.** Require exact pending assignment/worklist and artifact-first canonical install; test idempotent duplicate, conflicting result, recorded/complete refusal, foreign image/generation, installed-byte drift, sibling preservation, concurrent change, SQL/commit failure and lock rollback.
- [ ] **Step 8: Run import RED.** Run `python3 -m pytest tests/test_firmware_decide_import.py -q`; expect missing publication behavior.
- [ ] **Step 9: Implement atomic `record`.** Reconstruct assignment without a live root, install canonical result, take `BEGIN IMMEDIATE`, repeat worklist/row/file validation, and update exactly one active row.
- [ ] **Step 10: Run Task 3 GREEN.** Run both Task 3 test files only.
- [ ] **Step 11: Commit.** Commit as `feat: import firmware decision reviews`.

### Task 4: Derive policy projections and publish verified current packages

**Files:**
- Modify: `audit_core/firmware_decide.py`
- Modify: `audit_core/firmware_decide_results.py`
- Create: `tests/test_firmware_decide_gate.py`
- Create: `tests/test_firmware_decide_package.py`
- Modify: `tests/test_firmware_decide_import.py`

**Interfaces:**
- Produces frozen `PolicyMatch`, `PayoutProjection`, `DecisionSummary(image_id, decision_generation, decision, primary_reason, reason_codes, chain_count, bench_test_count, script_count, policy_match_count, package_path, package_sha256, complete)` and `VerifiedFirmwareDecisionPackage` containing the exact canonical package projection plus immutable proposed script descriptors/bytes.
- Produces `check(con, run_dir, root, *, image_id=None) -> DecisionSummary` and `verified_package(con, run_dir, root, *, image_id=None) -> VerifiedFirmwareDecisionPackage`.
- Technical matching, eligible/unknown-path matching, `requires_physical_settlement`, bench completeness, top eligible ranked chain, primary reason and ordered secondary codes follow the exact spec precedence.
- Installs `artifacts/firmware-decide/<generation>/<package-sha256>/decision.json` and `bench/<name>` with regular mode `0600`; no code path invokes a script/interpreter/subprocess.

- [ ] **Step 1: Write policy matching RED.** Pin all technical predicates, physical-settlement derivation from exact open `method == "hardware"` preconditions, tier order, eligible/unknown/ineligible path behavior, range projection and no worker influence.
- [ ] **Step 2: Write recommendation precedence RED.** Cover every decision branch and overlaps: no chain; unsupported; cost exceeded; eligible+supported+complete bench; eligible+unknown support; eligible+incomplete bench; unknown-path technical match; no match. Assert exact `primary_reason` and all applicable reason codes in fixed order.
- [ ] **Step 3: Write bench completeness RED.** Require at least one top-chain test, coverage of every hardware-method open precondition and existing referenced scripts; allow shared tests; prove nonhardware preconditions remain visible without blocking completeness.
- [ ] **Step 4: Write package/publication RED.** Pin literal decision bytes/hash/script projection; assert mode `0600`, descriptor-safe layout, idempotence, exact row/count/timestamp update, sibling/history preservation, concurrent graph/dive/policy/result drift, symlink/special-file/extra-file refusal, SQL/commit failure and subprocess sentinel untouched.
- [ ] **Step 5: Write complete recheck/currentness RED.** Reconstruct every input/result/package byte and row; reject changed graph/overlay/policy, missing/corrupt rows/files, direct historical fallback and attempted repair; support read-only/caller transactions through `verified_package`.
- [ ] **Step 6: Run Task 4 RED.** Run `python3 -m pytest tests/test_firmware_decide_gate.py tests/test_firmware_decide_package.py tests/test_firmware_decide_import.py -q`; expect completion/package interfaces to be absent.
- [ ] **Step 7: Implement pure derivation, package install, check and verified helper.** Keep one canonical derivation shared by `check` and `verified_package`; complete rechecks perform no writes.
- [ ] **Step 8: Run Task 4 GREEN and directly affected regressions.** Run the Task 4 command plus `python3 -m pytest tests/test_firmware_chain_gate.py tests/test_firmware_dive_gate.py tests/test_firmware_dive_overlay.py -q`.
- [ ] **Step 9: Commit authority kernel.** Commit as `feat: publish firmware acquisition decisions`.
- [ ] **Step 10: Run one fresh authority-kernel security review.** Review only Tasks 1–4 for historical fallback, observation/policy bleed, denominator truth, recommendation precedence, artifact/SQL atomicity and script inertness. Fix every Critical/Important issue with focused failing tests and rerun only affected Task 1–4 files plus scoped re-review.

### Task 5: Expose the bounded CLI and one-global-worker route

**Files:**
- Modify: `audit.py`
- Create: `tests/test_cli_stage4i.py`
- Create: `references/briefs/firmware-decide-brief.md`
- Create: `tests/test_firmware_decide_brief.py`
- Modify: `tests/test_brief_templates.py`
- Modify: `tests/test_install.py`
- Modify: `tests/test_cli.py`
- Modify: `SKILL.md`

**Interfaces:**
- Adds verb `decide` with exactly one mode `--prepare|--record RESULT|--check`; all require `--run`; prepare/check require `--root`; prepare alone requires `--policy`; prepare/check optionally accept `--image-id`; `--json` works in every mode.
- Success output is bounded scalar `DecisionPreparationSummary`, `DecisionRecordSummary`, or `DecisionSummary`; no policy prose, evidence/script bodies, absolute roots, private paths or traceback enters expected output.
- Expected database errors map to `decide: database operation failed`; other expected diagnostics are escaped, root-redacted and capped at 512 ASCII characters plus newline; unexpected exceptions propagate after cleanup.
- Raises verb count from 30 to 31 and schema totals from 44/43 to 45/44.
- Brief variables are exactly `run_dir`, `image_id`, `decision_generation`, `worklist_path`, `result_path`; exact return is `firmware-decide <DONE|PARTIAL|FAILED> chains=<n> artifact=<path> [flags=<csv>]`.

- [ ] **Step 1: Write CLI mode-matrix RED.** Cover each success mode in human/JSON output, semantic flag refusal before DB I/O, root/policy/image rules, selected-image isolation, expected diagnostics, root/private/script redaction, output caps and generic verb compatibility.
- [ ] **Step 2: Run CLI RED.** Run `python3 -m pytest tests/test_cli_stage4i.py tests/test_cli.py -q`; expect `decide` to be absent.
- [ ] **Step 3: Implement parser, command dispatch and bounded presenters.** Reuse the established firmware CLI exception/cleanup pattern; do not duplicate core derivation.
- [ ] **Step 4: Write brief/routing RED.** Assert exact variables, one global strongest worker, complete-chain result requirement, worker authority exclusions, inert proposed scripts, PARTIAL nonimportability, exact return line, prepare → brief → record → check sequence, and generic routing preservation.
- [ ] **Step 5: Run brief RED.** Run `python3 -m pytest tests/test_firmware_decide_brief.py tests/test_brief_templates.py tests/test_install.py tests/test_skill_lint.py -q`; expect missing brief/install/route.
- [ ] **Step 6: Add brief and installed `SKILL.md` route.** Workers own only result JSON; the route never executes proposed scripts.
- [ ] **Step 7: Run Task 5 GREEN.** Run the two Task 5 commands plus `python3 audit.py selftest`; require 31 dispatchable verbs and 45/44 schema agreement.
- [ ] **Step 8: Commit.** Commit as `feat: expose firmware acquisition decisions`.

### Task 6: Review once, reconcile durable state and run one authoritative harness

**Files:**
- Modify only as required by real uncovered behavior: `tests/test_firmware_decide_*.py`
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `progress.md`
- Modify: `SESSION_HANDOFF.md`
- Modify: `feature_lists.json`
- Modify: `SKILL.md` only for review corrections not already completed in Task 5

**Interfaces:**
- Produces truthful present state: Stage 4i implemented on its feature branch, integration pending until explicit merge, nothing pushed, Stage 4j `report` next.
- Preserves every deferred gate/limitation named in the spec.
- Does not add a second implementation feature, schema mirror, test-only fallback, compatibility shim, or mutation/paid/hardware gate.

- [ ] **Step 1: Run the focused Stage 4i suite and direct Stage 4g/4h regressions.** Run `python3 -m pytest tests/test_firmware_decide_*.py tests/test_cli_stage4i.py tests/test_firmware_chain_gate.py tests/test_firmware_dive_gate.py tests/test_firmware_dive_overlay.py tests/test_install.py tests/test_skill_lint.py -q`. Fix only real behavior failures with focused RED/GREEN.
- [ ] **Step 2: Run one independent whole-branch review.** Review `main...HEAD` for exact currentness, policy/evidence separation, denominator/rank truth, recommendation precedence, script inertness, artifact/SQL atomicity, privacy, routing and generic compatibility. Fix every Critical/Important issue with focused tests and scoped re-review; do not rerun broad suites.
- [ ] **Step 3: Precompute deterministic final metadata cheaply.** Run pytest collection count, `audit.py selftest`, JSON validation, skill lint, manifest/install-focused tests and CRLF-aware diff check. Do not run full pytest/coverage/benchmark here.
- [ ] **Step 4: Reconcile implementation docs before the broad gate.** Add Stage 4i stage/features/verb/table/package/brief paths; remove `decide` from next steps and name Stage 4j `report`; record reviewed implementation commits and deterministic metadata; mark the final broad harness pending without guessing its values. Preserve historical measurements as historical.
- [ ] **Step 5: Validate documentation without broad gates.** Run `python3 -m json.tool feature_lists.json >/dev/null`, manifest/install/skill-lint focused tests, targeted stale-state searches and `git -c core.whitespace=cr-at-eol diff --check`.
- [ ] **Step 6: Run the one authoritative full harness.** Run repository-root `make all` once on the reviewed implementation and fully enumerated docs. Require all eight gates, zero unexecuted statements and zero allowance. If code, tests, routing, manifest paths or executable behavior changes to fix a failure, rerun on that changed tree. Do not run a separate full coverage probe unless the coverage gate reports a concrete gap.
- [ ] **Step 7: Record exact final evidence with status-only doc edits.** Replace only pending verification status/metrics in `ARCHITECTURE.md`, `progress.md`, `SESSION_HANDOFF.md` and `feature_lists.json`; do not change code, tests, routing, feature paths or behavior.
- [ ] **Step 8: Re-run every doc-sensitive gate, not the expensive code gates.** Run JSON validation, targeted stale-state searches, CRLF-aware diff check, manifest/install/skill-lint focused tests, and harness gates `lint`, `eol`, `manifest`, and `install`. Any non-status change that can affect code/test/coverage/benchmark requires returning to Step 6.
- [ ] **Step 9: State optional gates honestly and commit reconciliation.** Mutation, paid audit/milestone, Asus golden, second indicator snapshot, real hardware execution and Linux/alternate-interpreter checks remain not run unless actually exercised. Commit as `docs: record Stage 4i firmware decide`.
- [ ] **Step 10: Clean handoff.** Require clean `git status`, exact `main..HEAD` log/stat, no remaining Critical/Important review issue, and an unmerged/unpushed feature branch ready for the operator's integration choice.

## Acceptance criteria

- Only one current completed graph with an exact completed non-contested dive input can produce a decision package.
- Operator policy remains separately hashed and labeled; no policy assertion is presented as observed technical truth.
- Every current chain and open precondition is represented exactly once; rank and empty coverage are mechanical.
- Policy matches, payout ranges, primary/secondary reasons and `acquire|defer|pass` reproduce exactly from frozen inputs.
- Proposed scripts remain bounded, regular, mode `0600`, visibly unreviewed and never executed.
- Historical packages survive changes but `verified_package` never returns them as current.
- One-table SQL and immutable artifact publication are atomic/idempotent and preserve siblings and Stage 4a–4h history.
- Generic source-code behavior and existing firmware phases remain compatible.
- Fresh whole-branch review reports no Critical/Important issue.
- One authoritative `make all` passes all eight gates with zero unexecuted statements on the reviewed implementation and fully enumerated docs; subsequent status/metric-only documentation edits pass all doc-sensitive harness gates. Mutation and paid/hardware gates remain separate.
