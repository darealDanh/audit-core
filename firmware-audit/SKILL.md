---
name: firmware-audit
description: >-
  Runs the structured multi-stage security audit of a device firmware image over
  the shared audit.py spine: qualify the SKU as worth the spend, acquire the latest
  build plus a CVE-affected diff reference, triage the carved image, patch-diff and
  sweep unfixed siblings, map the attack surface, hunt two parallel lanes, verify
  false positives statically, compose cross-component chains, settle blockers in a
  bounded deep dive, and end in an acquisition decision and lean report. Use for
  router/IoT/embedded firmware audits, patch-diff hunting on device images, and
  scan-before-buy acquisition decisions. Triggers on 'audit this firmware', 'firmware
  security audit', 'find vulnerabilities in this firmware image', 'run the firmware
  audit', '$firmware-audit', '/firmware-audit', and firmware stage requests like
  qualify/acquire/triage/diff/surface/hunt/fpcheck/chain/dive/decide/firmware-report.
  NOT for source-code application audits (use codebase-audit), single-file review, or
  quick pattern scans.
---

# Firmware Audit — Patch-Diff-Led Vulnerability Hunting on Device Images

A methodology for auditing a device firmware image at scale. It qualifies the SKU as
worth the spend, acquires the latest build plus a CVE-affected diff reference, triages
the carved image into ground-truth data, learns the vendor's fix idiom and sweeps
unfixed siblings, maps the attack surface, hunts two independent lanes, eliminates
false positives statically, composes cross-component chains, settles blockers in a
bounded deep dive, and ends in an acquisition decision and lean report. It shares the
`audit.py` + `audit_core/` spine with `codebase-audit`; only the operator surface and
the firmware stages differ.

## Essential Principles

Firmware auditing inherits `codebase-audit`'s discipline — snapshot raw material to
files before fan-out, return one line per worker, tier the model and effort against the
*Model and effort tiering* table — and adds the firmware-specific gates below.

1. **Qualify is a hard gate.** An EOL SKU pays zero and costs thousands of tokens;
   `qualify` can and does refuse to start the pipeline. GO/NO-GO is recorded, not
   assumed.
2. **`diff` runs before `hunt`.** Patch-diff is the highest-yield firmware step: learn
   the vendor's fix idiom once, then sweep every unfixed sibling call site.
3. **`hunt` has two lanes with separate, non-transferable budgets** (L-sink and
   L-dark). A budget checkpoint resumes the same assignments and returns PARTIAL; a
   lane budget is never transferred to the other lane or spent on weaponization — that
   belongs to `dive`, after coverage closes.
4. **`decide` replaces `verify`.** There is no live instance to deploy; the terminal
   scan-before-buy deliverable is a ranked acquisition decision with open preconditions
   as `unknowns` rows and a day-1 bench plan. `deploy` and live-instance `verify` are
   not carried over.
5. **Chains cross groups, so something must look across them.**
   `audit.py chain` proposes; a human composes.
6. **Every finding and surface row carries the device-state tuple it requires**
   (lifecycle / posture / auth). Every unresolved element becomes an `unknowns` row
   with its settling observation.
## Economics Contract

Measured across nine real audits: 449.9M context tokens re-read for $2,053.64.
Cost follows `Σ over turns of context(turn)`, so **a token admitted to the
orchestrator's context at turn N is paid for on every remaining turn**. The
orchestrator's context is a budget, not a buffer. The rules below are the
economics contract in full: R1 and R3 govern what enters the orchestrator's
context and for how long; R2, R4, R5 and R6 govern each of the ways it gets
in.

### R1 — The orchestrator never holds raw material

Banned from the orchestrator's context: decompiler pseudocode, disassembly,
hexdumps, strings dumps, file reads over ~100 lines, and subagent prose.

Snapshot the material once, then read paths:

    python3 __SKILL_DIR__/audit.py extract --run ${AUDIT_DIR} --root . \
      --unit G1 --from-file ${AUDIT_DIR}/files/G1-paths.txt

Everything downstream reads files out of `${AUDIT_DIR}/extract/`, so fan-out
is bounded by nothing. This is the one rule where the cost argument and the
quality argument are the same argument: work that stays in the orchestrator
is serial, and serial work is why surfaces went unopened.

The orchestrator's own reads are bounded too. `audit.py rows` caps at 200
rows; `audit.py status` and `audit.py coverage` return aggregate counts
rather than rows; comprehension comes from `audit.py note`, which returns
one line per key, not the analysis behind it.

### R3 — Context ceiling with checkpoint-restart

Ceiling **100k**, checkpoint at 80%. On a trip, write the resume note and the
journal, record the checkpoint, and end the phase; the next phase starts
fresh at a ~45k prefix.

    python3 __SKILL_DIR__/audit.py checkpoint --db ${AUDIT_DIR}/audit.db \
      --phase audit --reason ceiling --turns <n> \
      --resume-note /memories/session/<project>-audit-resume.md

Compaction is not the mechanism: it costs a full-context read plus a summary,
lands at 60k-80k of lossy summary rather than 45k of real prefix, and discards
the technical state the next step needs.
`audit.py budget --project --report <session.jsonl>` reports the measured
prefix and growth and how many turns they leave.

**The budget governs where tokens are spent, never whether a surface is
opened.** A group skipped for budget is a `not_audited(reason='budget')` row.
That row is excluded from the analyzed total, raises a WARNING from
`audit.py coverage`, and **fails** `audit.py coverage --gate`: the audit
phase runs that gate at its exit and a budget skip is one of the
three things that fails it. The answer is
`audit.py checkpoint` and a restart, never a surface left unopened.

### Model and effort tiering

| Work | Model | Reasoning effort |
|---|---|---|
| Workspace setup, CVE ingest, pattern sweeps, SQL bookkeeping | script or cheapest tier | low |
| Report drafting | mid tier | low to medium |
| Feature mapping, FP-check batches | strongest tier, effort tiered down | low to medium |
| Deep audit, chain reasoning, final severity calls, adversarial review | strongest tier | high |
| Broad Stage 4e L-sink batches | economical tier | low to medium |
| Stage 4e L-dark batches | strongest available tier | medium to high |

For Stage 4e dispatch, use the economical tier for broad L-sink coverage and
reserve the strongest available tier for L-dark's proprietary protocol, trust,
OTA, and heap reasoning. Keep the two lane budgets independent.

Reasoning effort is tiered with the model: retained thinking is the largest
single component of accumulated context, so only the strongest-tier work runs
at high effort. Effort is the lever that is safe to pull on its own — it cuts
retained thinking without changing which model reads the code.

**Feature mapping and FP-check keep the strongest model and tier only their
effort.** Both decide what gets looked at and what survives, so a model
downgrade there can cost recall and precision. That change is not free and is
not Stage 1's to make: it waits until precision is measured before and after.

### R2 — Return contracts

A subagent writes its work to SQL and an artifact, then returns **one line**:

    <unit_id> <DONE|PARTIAL|FAILED> rows=<n> artifact=<relpath> [flags=<csv>]

The orchestrator never acts on the return text. Its next action is an
`audit.py` verb or a bounded SQL query. Prose returned anyway is dead weight
for one turn instead of permanently resident.

### R4 — MCP preflight

Before a run, write a project-scoped MCP config naming only what the run
needs, and relaunch against it:

    python3 __SKILL_DIR__/audit.py preflight --server autorev=<command>
    claude --strict-mcp-config --mcp-config .audit-mcp.json

The resident prefix is 20.9% of measured cost, and unused MCP tool schemas are
a large part of it: the prefix floor grows by 11.5k-25.1k tokens mid-session as
servers load, which on the largest measured session is 38% of the peak prefix.
Those schemas are then charged a second time in accumulation, as deferred-tool
records.

### R5 — Reusable logic is an `audit.py` verb, never an inline heredoc

Workspace creation and schema are `audit.py init`. MCP config is
`audit.py preflight`. Dispatch briefs are `audit.py brief`. A target-specific
script longer than ~10 lines is written once into the run's `files/`
directory and invoked by path thereafter — never retyped.

### R6 — Dispatch briefs are files

A subagent's task is rendered to a file with `audit.py brief`; the dispatch
carries the path plus only what the brief cannot know (where the task fits,
interfaces from earlier phases, the report-file path). Never paste prior
phases' summaries into a dispatch.


## Sub-Command Router

`firmware-audit` runs ten gated stages, 4a qualify through 4j report, over the shared
`audit.py` spine. Invoke a stage only after the prior stage's gate passes. `deploy` and
live-instance `verify` are not carried over — an image is not a deployed app; `decide`
replaces `verify` as the terminal deliverable. Each stage names its exact verb and,
where it fans out, renders a file-backed worker brief with
`python3 __SKILL_DIR__/audit.py brief --phase <p>`. The orchestrator never holds raw
material or worker prose; it acts on `audit.py` verbs and bounded SQL (see the
Economics Contract).

### Stage 4a firmware qualify

`qualify` is the pipeline's hard GO/NO-GO gate and runs first. It is deterministic
script work against the intel already in `_intel/target-scores.csv`: EOL/EOS status,
the latest-firmware date, the slop index, and the payout path. An EOL SKU pays zero and
costs thousands of tokens, so this stage can refuse to start the pipeline — a NO-GO
ends the run here. It renders no worker brief; run the verb directly:

    python3 __SKILL_DIR__/audit.py qualify --scores ${TARGET_SCORES_CSV} \
      --vendor ${VENDOR} --model ${MODEL} --supported yes \
      --support-evidence ${SUPPORT_EVIDENCE}

### Stage 4b firmware acquire

After a GO, `acquire` records the two images the run compares: the latest build as the
`target`, and the CVE-affected build as the `diff-reference`. It captures each image's
version, hashes, and provenance. This is orchestrator bookkeeping, not a fan-out, and
renders no worker brief; record each image with:

    python3 __SKILL_DIR__/audit.py acquire --run ${AUDIT_DIR} \
      --vendor ${VENDOR} --model ${MODEL} --version ${VERSION} \
      --role target --file ${IMAGE} --source ${SOURCE}

Repeat with `--role diff-reference` for the CVE-affected build.

### Stage 4c firmware triage

`triage` carves the image and records the ground truth every later stage reads as data:
architecture/endianness/libc, evidence-based component identity and SBOM, init scripts,
nvram defaults, every listening service, mitigations, and the corpus inventory. Prepare
the carved root, then dispatch one agent with the file-backed brief:

    python3 __SKILL_DIR__/audit.py triage --run ${AUDIT_DIR} --root ${ROOTFS}

    python3 __SKILL_DIR__/audit.py brief --phase triage \
      --unit ${IMAGE_ID} --run ${AUDIT_DIR} \
      --var run_dir=${AUDIT_DIR} --var rootfs=${ROOTFS} --var image_id=${IMAGE_ID}

The worker writes one result artifact and returns only
`triage <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`. Component
identity is evidence-based: a filename is an assertion, never a fact.

### Stage 4d firmware diff and surface

`diff` runs before `hunt` because patch-diff is the highest-yield firmware step: learn
the vendor's fix idiom once from the CVE-affected `diff-reference` against the latest
`target`, then sweep every unfixed sibling call site. Prepare the pair, then dispatch
the sweep workers with the file-backed brief:

    python3 __SKILL_DIR__/audit.py diff --run ${AUDIT_DIR}

    python3 __SKILL_DIR__/audit.py brief --phase diff \
      --unit ${DIFF_ID} --run ${AUDIT_DIR} \
      --var run_dir=${AUDIT_DIR} --var diff_id=${DIFF_ID} \
      --var target_root=${TARGET_ROOT} --var reference_root=${REFERENCE_ROOT} \
      --var patched_component=${PATCHED_COMPONENT} \
      --var known_advisory=${KNOWN_ADVISORY} \
      --var manifest_path=${MANIFEST_PATH} --var artifact_path=${ARTIFACT_PATH}

`surface` then maps the dispatch/handler tables per component, recording pre-auth vs
post-auth reachability as data, not prose. It prepares, records, and checks like
`hunt`; dispatch one file-backed worker per indexed batch:

    python3 __SKILL_DIR__/audit.py surface --run ${AUDIT_DIR} --root ${ROOTFS}

    python3 __SKILL_DIR__/audit.py brief --phase surface \
      --unit surface-batch-0001 --run ${AUDIT_DIR} \
      --var run_dir=${AUDIT_DIR} --var db_path=${AUDIT_DIR}/audit.db \
      --var rootfs=${ROOTFS} --var image_id=${IMAGE_ID} \
      --var manifest_sha256=${MANIFEST_SHA256} \
      --var worklist_index=${INDEX_PATH} --var batch_path=${BATCH_PATH} \
      --var result_path=${RESULT_PATH}

    python3 __SKILL_DIR__/audit.py surface --run ${AUDIT_DIR} --record ${RESULT_PATH}
    python3 __SKILL_DIR__/audit.py surface --run ${AUDIT_DIR} --check

A complete Stage 4d surface check is the precondition for Stage 4e hunt.
### Stage 4e firmware hunt

After acquisition, triage, and a complete Stage 4d surface check, `hunt` prepares
two complete, independent worklists for the selected target image. L-sink traces
attacker-controlled data into shell, memory, configuration, and format-string
operations. L-dark directly assesses proprietary protocols, helper IPC, OTA
trust decisions, and heap corruption. Each lane assesses every assigned file,
including files without hints. The lane budgets cannot be transferred; a budget
checkpoint resumes the same assignments and returns PARTIAL. See the rendered
worker contract in `references/briefs/hunt-brief.md` for the exact categories,
evidence, result schema, and boundaries.

Prepare the two lane worklists with the required run and carved-root paths:

    python3 __SKILL_DIR__/audit.py hunt --run ${AUDIT_DIR} --root ${ROOTFS}

Record each result and check each lane through the same verb. Render one
file-backed assignment with the existing brief command, supplying all ten
required variables. The dispatched task carries the resulting brief path plus
only context the template cannot know:

    python3 __SKILL_DIR__/audit.py brief --phase hunt \
      --unit l-sink-batch-0001 --run ${AUDIT_DIR} \
      --var run_dir=${AUDIT_DIR} --var db_path=${AUDIT_DIR}/audit.db \
      --var rootfs=${ROOTFS} --var image_id=${IMAGE_ID} --var lane=l-sink \
      --var manifest_sha256=${MANIFEST_SHA256} \
      --var surface_snapshot_sha256=${SURFACE_SNAPSHOT_SHA256} \
      --var worklist_index=${INDEX_PATH} --var batch_path=${BATCH_PATH} \
      --var result_path=${RESULT_PATH}

Repeat independently for each `l-sink` and `l-dark` batch. The worker writes
one strict result artifact and returns only
`hunt-<lane>-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`.
The orchestrator records results and checks each lane. After both pass, run the
final two-lane gate with:

    python3 __SKILL_DIR__/audit.py hunt --run ${AUDIT_DIR} --root ${ROOTFS} --check

This command certifies Stage 4e completion.

### Stage 4f firmware fpcheck

For firmware candidate review after both Stage 4e hunt lanes pass, use this
route. The ordinary source-code `fpcheck` route lives in the
codebase-audit skill; it reviews source findings.
Firmware review uses immutable lane-qualified hunt candidates and dedicated
firmware verdicts, pivots, and reviewed findings. Read
[references/briefs/firmware-fpcheck-brief.md](references/briefs/firmware-fpcheck-brief.md)
for cross-lane comparison, duplicate targets, mandatory false-positive pivots,
static-only limits, and the parser-owned result contract.

The orchestrator prepares the current candidate snapshot and worklists:

    python3 __SKILL_DIR__/audit.py fpcheck --run ${AUDIT_DIR} --root ${ROOTFS} --prepare

Use the returned index path, image ID, and candidate snapshot digest. Render
one brief per indexed batch with the existing renderer and all eight variables;
dispatch only its path plus context the template cannot know:

    python3 __SKILL_DIR__/audit.py brief --phase firmware-fpcheck \
      --unit batch-0001 --run ${AUDIT_DIR} \
      --var run_dir=${AUDIT_DIR} --var db_path=${AUDIT_DIR}/audit.db \
      --var rootfs=${ROOTFS} --var image_id=${IMAGE_ID} \
      --var candidate_snapshot_sha256=${CANDIDATE_SNAPSHOT_SHA256} \
      --var worklist_index=${INDEX_PATH} --var batch_path=${BATCH_PATH} \
      --var result_path=${RESULT_PATH}

Workers read immutable artifacts and write result-only JSON. They return
`firmware-fpcheck-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`.
The orchestrator preserves PARTIAL checkpoints for resumption of the same
assignment. Record only complete results, then check the whole current snapshot:

    python3 __SKILL_DIR__/audit.py fpcheck --run ${AUDIT_DIR} --record ${RESULT_PATH}
    python3 __SKILL_DIR__/audit.py fpcheck --run ${AUDIT_DIR} --root ${ROOTFS} --check

Deterministic code owns SQL, canonical artifact installation, and transitions;
the final check resolves duplicates across lanes and batches. Worker DONE alone
cannot certify Stage 4f completion. These static-reviewed firmware outputs carry
no dynamic verification, severity, or generic finding promotion.

### Stage 4g firmware chain

After Stage 4f's global check passes, compose the current reviewed firmware
findings with this dedicated route. The ordinary source-code `chain` proposal
and human composition instructions remain in force for source findings; firmware
uses a separate global worklist and dedicated tables. Read
[references/briefs/firmware-chain-brief.md](references/briefs/firmware-chain-brief.md)
for full finding dispositions, typed adjacent edges, middle-node continuity,
state/reboot proof, blocker settlement, and adversarial review. Pivots are
context-only follow-up hints, never chain nodes or proof.

The orchestrator prepares the immutable global worklist:

    python3 __SKILL_DIR__/audit.py chain --run ${AUDIT_DIR} --root ${ROOTFS} --prepare --json

Use the returned worklist path, exact image ID, and candidate snapshot digest.
Assign RESULT_PATH to the worker's writable result file. Render all seven
variables, then dispatch only its path plus context the template cannot know
to one global worker using the strongest available tier with high reasoning.
Do not inline the worklist or evidence in the dispatch. Read incrementally;
never partition by component or cap finding coverage.

    python3 __SKILL_DIR__/audit.py brief --phase firmware-chain \
      --unit global --run ${AUDIT_DIR} \
      --var run_dir=${AUDIT_DIR} --var db_path=${AUDIT_DIR}/audit.db \
      --var rootfs=${ROOTFS} --var image_id=${IMAGE_ID} \
      --var candidate_snapshot_sha256=${CANDIDATE_SNAPSHOT_SHA256} \
      --var worklist_path=${WORKLIST_PATH} --var result_path=${RESULT_PATH}

The worker writes strict result-only JSON and returns exactly
`firmware-chain <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]`;
rows counts finding dispositions. Preserve PARTIAL checkpoints and resume the
same immutable global assignment without fabricated dispositions. Import only
a complete result, including a truthful empty result when there are no findings:

    python3 __SKILL_DIR__/audit.py chain --run ${AUDIT_DIR} --root ${ROOTFS} --record ${RESULT_PATH}
    python3 __SKILL_DIR__/audit.py chain --run ${AUDIT_DIR} --root ${ROOTFS} --check

Deterministic code owns SQL, canonical identities, artifact installation, and
completion. Worker DONE alone cannot certify Stage 4g completion. The final
check independently revalidates current provenance, exact result bytes, full
coverage, evidence ownership, and state continuity. Outputs are static-chained;
no severity/CVSS, dynamic confirmation, runtime reachability, or exploit claim
is authorized. Unsettled observations remain blockers for later dive/decide.

### Stage 4h firmware dive

After Stage 4g check, use the bounded dive route to settle frozen chain blockers,
surface unknowns, and analyst questions. Read
[references/briefs/firmware-dive-brief.md](references/briefs/firmware-dive-brief.md).
Prepare one immutable denominator and index:

    python3 __SKILL_DIR__/audit.py dive --run ${AUDIT_DIR} --root ${ROOTFS} --prepare --json

For every indexed question, render one brief with exactly the eight variables
below. Dispatch only the rendered brief path and necessary scalars to one fresh strongest
worker. Never inline packets or evidence in dispatch.

    python3 __SKILL_DIR__/audit.py brief --phase firmware-dive \
      --unit ${QUESTION_ID} --run ${AUDIT_DIR} \
      --var run_dir=${AUDIT_DIR} --var rootfs=${ROOTFS} \
      --var image_id=${IMAGE_ID} --var dive_generation=${DIVE_GENERATION} \
      --var question_id=${QUESTION_ID} --var packet_path=${PACKET_PATH} \
      --var journal_index_path=${JOURNAL_INDEX_PATH} \
      --var result_path=${RESULT_PATH}

Workers own result JSON only. When the packet authorizes deterministic
acquisition, the orchestrator optionally runs exactly one prepared operation:

    python3 __SKILL_DIR__/audit.py dive --run ${AUDIT_DIR} --root ${ROOTFS} --probe ${PROBE_SPEC}
    python3 __SKILL_DIR__/audit.py dive --run ${AUDIT_DIR} --root ${ROOTFS} --capture ${CAPTURE_SPEC}

Record each DONE result; PARTIAL is nonimportable and resumes the same frozen
assignment. After every assignment terminates, run the completion gate:

    python3 __SKILL_DIR__/audit.py dive --run ${AUDIT_DIR} --record ${RESULT_PATH}
    python3 __SKILL_DIR__/audit.py dive --run ${AUDIT_DIR} --root ${ROOTFS} --check

Fresh workers have no SQL, canonical artifact, completion, chain-regeneration,
severity, exploit, or report authority. The final check owns dive publication
and invalidates Stage 4g when the current overlay changes; it cannot regenerate
worker-reviewed chains itself. After invalidation, repeat the complete Stage 4g
prepare, one-global-worker brief, root-bound record, and check route above.

### Stage 4i firmware decision

After the current Stage 4g chain and Stage 4h dive gates pass, prepare one
immutable global decision assignment from the operator policy:

    python3 __SKILL_DIR__/audit.py decide --run ${AUDIT_DIR} --root ${ROOTFS} \
      --policy ${DECISION_POLICY} --prepare --json

Use the returned `image_id` and `decision_generation`, and set WORKLIST_PATH to
`${AUDIT_DIR}/` plus the returned run-relative `worklist_path`. Assign
RESULT_PATH to the worker's writable result file. Read
[references/briefs/firmware-decide-brief.md](references/briefs/firmware-decide-brief.md)
for the exact result schema, bench-test identity and subject rules, and inert
proposed-script limits. Render exactly one global brief with the five frozen
variables, then dispatch only its path plus context the template cannot know
to one fresh strongest worker with high reasoning. Do not inline the worklist,
policy, or evidence in the dispatch. The worker reads the worklist
incrementally; never partition by chain or cap chain coverage.

    python3 __SKILL_DIR__/audit.py brief --phase firmware-decide \
      --unit global --run ${AUDIT_DIR} \
      --var run_dir=${AUDIT_DIR} --var image_id=${IMAGE_ID} \
      --var decision_generation=${DECISION_GENERATION} \
      --var worklist_path=${WORKLIST_PATH} --var result_path=${RESULT_PATH}

The worker must assess every chain in the complete frozen denominator and
returns exactly
`firmware-decide <DONE|PARTIAL|FAILED> chains=<n> artifact=<path> [flags=<csv>]`.
Workers own result JSON only. Import only DONE; PARTIAL is nonimportable and
resumes the same immutable assignment:

    python3 __SKILL_DIR__/audit.py decide --run ${AUDIT_DIR} --record ${RESULT_PATH}
    python3 __SKILL_DIR__/audit.py decide --run ${AUDIT_DIR} --root ${ROOTFS} --check

Deterministic code owns policy evaluation, recommendation, payout, SQL,
canonical package installation, and completion. Proposed scripts remain inert:
never execute them during dispatch, record, or check. The final check publishes
the verified acquisition decision package; worker output alone has no decision
authority.

The latest preparation is current. When the verified graph or dive input
changes, prepare again: it marks the stale active generation `superseded`,
which can never be recorded or become current, and creates a new one. A changed
policy over unchanged input is refused while a generation is active. An
identical re-prepare makes its generation current again; `--check` and the
verified package never fall back to an older completed generation. A superseded
generation can never be prepared again; change the policy bytes to create a new
generation. Upgrading a run ranks its existing decision rows so the generation
selected before the upgrade stays current.

### Stage 4j firmware report

After the Stage 4i acquisition decision package is complete and current,
prepare one immutable report generation from it:

    python3 __SKILL_DIR__/audit.py firmware-report --run ${AUDIT_DIR} --root ${ROOTFS} \
      --prepare --json

Prepare prints only scalars: image, report generation, manifest path, item
count and state. Read the N per-chain item paths from that bounded manifest at
`${AUDIT_DIR}/` plus the returned `manifest_path`; the CLI never prints them.
Each manifest item carries its `chain_id`, `assignment_path` and `result_path`.
Set ASSIGNMENT_PATH and RESULT_PATH to `${AUDIT_DIR}/` plus the item's
run-relative `assignment_path` and `result_path`.

Dispatch one fresh strongest worker with high reasoning per item. Read
[references/briefs/firmware-report-brief.md](references/briefs/firmware-report-brief.md)
for the exact result schema, bounds, citation rules and prose contract. Render
one brief per item with the five frozen variables and dispatch only its path
plus context the template cannot know. Do not inline the assignment, the
evidence catalog or any prose in the dispatch.

    python3 __SKILL_DIR__/audit.py brief --phase firmware-report \
      --unit ${CHAIN_ID} --run ${AUDIT_DIR} \
      --var run_dir=${AUDIT_DIR} --var image_id=${IMAGE_ID} \
      --var report_generation=${REPORT_GENERATION} \
      --var assignment_path=${ASSIGNMENT_PATH} --var result_path=${RESULT_PATH}

Each worker owns one chain and returns exactly
`firmware-report <DONE|FAILED> chain=<id> artifact=<path> [flags=<csv>]`.
Record each DONE result; FAILED is never recorded, and no script is executed
at any point in this stage. When every item is recorded, run the completion
gate:

    python3 __SKILL_DIR__/audit.py firmware-report --run ${AUDIT_DIR} --record ${RESULT_PATH}
    python3 __SKILL_DIR__/audit.py firmware-report --run ${AUDIT_DIR} --root ${ROOTFS} --check

Deterministic code owns chain selection, section ordering, pre-authentication
statements, provisional labeling, document layout, the result manifest, SQL and
publication. Workers own result JSON only; worker output alone publishes
nothing. A generation that is already complete refuses every further record,
and the refusal is an error, not a silent no-op.

The latest preparation is current. When the decision package changes, prepare
again: the stale active generation is superseded and can never be recorded,
while completed history stays immutable and is never returned. Reads never
fall back to an older generation. A second generation over the same unchanged
decision package is refused while one is still active, so a corrected image row
or a changed style contract needs a fresh Stage 4i decision preparation before
this stage can prepare again.

### Cross-client tool mapping

The workflows name **capabilities**, not one client's tool IDs. Use your client's equivalent:

| Capability | Copilot Chat | Claude Code CLI | OpenAI Codex CLI |
|---|---|---|---|
| Ask the user to choose | `vscode_askQuestions` | `AskUserQuestion` | present the options in text and wait for the reply |
| Spawn a subagent | `runSubagent` (or `task`) | `Task` | `spawn_agent` (+ `wait_agent` / `close_agent`) |
| Run a command in a subagent | `execution_subagent` | a `general-purpose` `Task` | `spawn_agent` |
| **Writable** subagent (writes files/SQL) vs read-only | `general-purpose` vs read-only `explore` | `general-purpose` vs read-only `Explore` | `spawn_agent` (writable by default — no read-only type) |
| Read / search files | `view` / `grep` / `glob` | `Read` / `Grep` / `Glob` | your native file tools |
| Semantic / codebase search | `semantic_search` | agentic search (`Grep`/`Glob` + exploration) | native code search |
| Manual context compaction | Compact action | `/compact` | `/compact` |

**Two rules hold on every client:** (1) any subagent that writes artifacts, runs SQL inserts, or hits the live instance MUST be a **writable** agent — a read-only agent silently produces nothing; (2) choose the model and reasoning effort from the *Model and effort tiering* table below — not the strongest available for everything. Retained thinking is 18.0% of measured context cost, and lower tiers emit far less of it.


## Rationalizations to Reject

| Rationalization | Required Action |
|---|---|
| "Each group's findings are independent" | Chains cross groups, and per-group subagents cannot see across them. Run `audit.py chain` before the audit phase exits. |
