# Stage 4h Firmware Dive Design

**Date:** 2026-10-29  
**Status:** proposed  
**Consumes:** completed Stage 4g firmware chain graph  
**Produces:** provenance-bound question coverage and current dive-resolution evidence

## Intent

Stage 4g composes static-reviewed firmware findings into evidence-backed static
chains. It deliberately stops at `static-chained`: an edge may still depend on
an unresolved bind address, daemon authority, reboot effect, provisioning state,
or hardware-only observation. Stage 4h adds the interactive investigation layer
that asks those questions without returning to one ever-growing audit context.

`dive` freezes a complete question denominator over one current Stage 4g graph,
dispatches one fresh strongest-available worker per question, retains immutable
answer and probe evidence, and completes when every frozen question has a
canonical receipt. A conclusive answer may settle the exact question it was
asked. An inconclusive answer closes investigation coverage for that generation
without pretending the uncertainty disappeared.

The phase also accepts analyst-created questions, but every question must link
to a current chain, edge, finding, Stage 4g blocker, or Stage 4d unknown. An
analyst question can add evidence or expose a successor question; it cannot
create a finding, rewrite chain history, assign severity, or claim exploit
success.

## Goals

1. Consume only a current, completed and reconstructable Stage 4g graph for one
   firmware image.
2. Freeze all current chain blockers and referenced open Stage 4d unknowns plus
   an explicit linked analyst-question manifest into one immutable denominator.
3. Give each question a stable identity and one file-backed packet containing
   only the evidence needed for that question.
4. Dispatch one fresh worker per question with the journal index and at most
   three extracted functions, keeping per-question context flat.
5. Record exactly one canonical answer receipt for every frozen question and
   preserve retries as later immutable generations.
6. Distinguish `supported`, `refuted`, and `inconclusive` without equating any
   answer with severity, exploitability, or successful exploitation.
7. Bind every conclusion to content-addressed dependencies and evidence
   artifacts; fail closed on missing, foreign, redirected, changed, or
   over-broad evidence.
8. Publish a deterministic journal and current resolution overlay only after
   independent reconstruction of every question, receipt, answer, dependency,
   and probe.
9. Retain stale historical evidence while excluding it from current chain
   regeneration and later acquisition decisions.
10. Feed current conclusive observations back into Stage 4g through a versioned
    overlay, invalidating rather than editing the prior graph in place.
11. Provide a narrow opt-in single-binary probe runner for userland emulation,
    with fail-closed network isolation, bounded resources, and captured
    provenance.
12. Preserve sibling images, generic source-code audit behavior, and all prior
    immutable firmware artifacts.

## Non-goals

- Discovering or publishing new findings. New vulnerability hypotheses return
  to `hunt` and `fpcheck`.
- Assigning severity, CVSS, payout, acquisition priority, exploit reliability,
  or disclosure language. Those belong to `decide` and `report`.
- Treating emulation as proof of device behavior or hardware observation as
  proof beyond the exact captured device, firmware, state, and procedure.
- Whole-system emulation, automatic firmware flashing, remote-device control,
  automatic network scanning, or an unrestricted command runner.
- Automatically installing QEMU, binfmt handlers, containers, isolation tools,
  loaders, libraries, or NVRAM shims.
- Mutating historical Stage 4d unknown rows or Stage 4g chain rows to make later
  evidence appear contemporaneous.
- Silently selecting one of two contradictory conclusive observations.
- Expanding a prepared question denominator when a worker suggests follow-up.
- Creating the separate firmware skill tree, settling the monorepo decision, or
  running the paid milestone/Asus golden.

## Anti-goals

- One long-lived “deep dive” worker whose context and conclusions drift.
- A journal entry that cannot be traced to exact graph and file bytes.
- Counting “question attempted” as “question resolved.”
- Treating a crash, timeout, missing loader, unsupported architecture, or
  absent hardware capture as refutation.
- Letting an analyst free-form note become machine-authoritative evidence.
- Deleting inconvenient historical answers when source facts change.
- Reusing a resolution after any dependency it examined changes.
- Executing a firmware binary directly on the host or with ambient network
  access, credentials, home-directory state, or inherited environment.
- Allowing probe stdout, stderr, generated files, or process trees to grow
  without bounds.

## Constraints inherited from the repository

- Python remains standard-library only.
- SQLite plus canonical immutable artifacts are the durable sources of truth;
  worker return text and the generic annotation journal are not authoritative.
- Raw evidence remains file-backed and out of orchestrator context.
- Public JSON preserves exact identities and paths. Human diagnostics remain
  escaped, root-redacted, ASCII-bounded, and free of private evidence.
- Expected database failures use a fixed diagnostic. Unexpected exceptions
  propagate after cleanup.
- Content-addressed artifacts install before SQL publication. A failed
  transaction may leave only an unreferenced immutable artifact.
- All selected-image operations preserve sibling images.
- Complete rechecks never repair missing artifacts or rows.
- `make all` runs after final documentation reconciliation. `make mutate`
  remains separate and opt-in.
- Triage remains upsert-only, and the Stage 4d retained-orphan scan scaling
  limitation remains inherited.

## Approaches considered

### A. Dedicated provenance-bound dive journal — selected

Add firmware-specific runs, questions, receipts, observations, dependencies,
and acquisition receipts. Freeze a complete question set, dispatch fresh workers,
validate strict result JSON, publish an immutable journal, and expose only a
dependency-current conclusive overlay to Stage 4g.

This adds schema and reconstruction work, but makes coverage, provenance,
staleness, conflict handling, and resolution authority mechanical. It also
preserves the distinction between scratch notes, attempted investigation, and
accepted evidence.

### B. Extend the generic annotation journal — rejected

`journal.jsonl` and `audit.py note` are useful restart-safe analyst memory, but
they have no image/snapshot ownership, question denominator, artifact receipts,
atomic publication, dependency validation, or completion gate. Conventions in
free-form text would not make blocker resolution trustworthy.

The generic journal remains available for non-authoritative notes and may link
to Stage 4h question IDs, but Stage 4h never derives truth from it.

### C. One global dive worker — rejected

A single worker could see all chains at once, but it recreates the growing
context and answer drift that the parent design assigns Stage 4h to eliminate.
It also makes one failure lose the entire investigation batch and encourages
unrelated evidence to leak between questions.

## Security and trust model

### Question authority

Questions originate from exactly three sources:

- `chain-blocker`: every current Stage 4g blocker referenced by a completed
  graph;
- `surface-unknown`: every open Stage 4d unknown referenced by a current chain
  or chain disposition; or
- `analyst`: a strict manifest entry linked to at least one current graph
  subject.

An automatically derived question preserves the upstream question, settling
observation, method, affected axes, and affected subjects. An analyst question
adds those fields explicitly. Exact duplicate questions are rejected; the tool
does not silently merge origins or choose one wording.

Every question has one or more canonical subject references:

- `finding:<finding-id>`;
- `surface-unknown:<unknown-id>`;
- `chain-blocker:<blocker-id>`;
- `edge:<edge-semantic-sha256>`; or
- `chain:<chain-semantic-sha256>`.

Finding and unknown identities are their upstream stable IDs. Edge fingerprints
hash the candidate snapshot plus endpoints, capability/link identity, evidence
references, required/result state, transition kind, and initial/member context,
but exclude chain-local IDs, blocker lists, timestamps, and display prose.
Chain fingerprints hash the candidate snapshot, exact initial state, ordered
members, and ordered edge fingerprints, excluding blocker-resolution state.
This lets a relevant observation survive graph regeneration without claiming it
applies to a semantically different path.

`question_id` is the full lowercase SHA-256 of a canonical projection containing
image ID, Stage 4f candidate snapshot, sorted subject references, method,
question, settling observation, and sorted affected axes. Display labels,
generation, timestamps, and worker identity do not establish question identity.

Every question also carries a machine-readable `resolution_contract`. The
contract names one exact target subject and one of two modes:

- `boolean-claim`: an exact predicate and expected value that may be supported
  or refuted; or
- `value-discovery`: an exact predicate plus an allowed value vocabulary (or a
  bounded `other-specific` namespace) that may be supported with one observed
  value or remain inconclusive.

Frozen predicates are `state-value`, `reachability`, `edge-validity`,
`capability-present`, and `transition-observed`. State predicates name one of
the lifecycle, posture, authentication, or reachability axes and use its frozen
vocabulary. Edge/capability/transition predicates name the stable subject
fingerprint and exact capability/link or transition identity. Automatically
derived questions obtain their contract from the upstream unknown field,
affected axes, and linked graph semantics. Analyst questions must declare it.
An open-ended upstream question such as “Which authority?” therefore becomes a
`value-discovery` contract rather than an unstructured proposition.

### Answer authority

One worker result has exactly one outcome:

- `supported`: the requested proposition is supported by the cited evidence;
- `refuted`: the requested proposition is contradicted by the cited evidence;
  or
- `inconclusive`: the evidence cannot settle the proposition.

Every answer includes a bounded conclusion, limitations, one exact
`resolution_effect` satisfying the packet's contract when conclusive, exact dependency
references, exact evidence references, and optional successor questions.
`supported` and `refuted` require non-empty evidence and dependency sets that
meet the question's method contract. `inconclusive` requires an explicit reason
and may cite partial evidence, but never enters the resolution overlay.
`refuted` is invalid for `value-discovery`; a worker that cannot establish an
allowed value must return `inconclusive`. Stage 4g consumes the structured
resolution effect, never attempts to infer an effect from conclusion prose.

`record` proves structure, ownership, hashes, and question assignment, then
publishes an immutable receipt and provisional observation. It does not complete
the generation. `check` independently reconstructs the current/frozen inputs,
canonical result bytes, dependencies, evidence, probes, receipts, and all SQL
rows. Only that gate accepts conclusive observations into the journal overlay.
No separate manual acceptance action exists.

### Conflicts and retries

Questions are immutable. Repeating the identical question requires an explicit
retry directive supplied to prepare. The directive names the prior question ID
and optional prior observation ID; prepare derives the next positive
`attempt_ordinal` from one coherent durable-history snapshot and requires that
same history under its publication lock. The canonical
retry projection `(question_id, attempt_ordinal, prior_observation_id)` enters
the generation hash, so an ordinary identical prepare remains idempotent while
`--retry` creates a later generation and preserves the older receipt.

If multiple dependency-current
conclusive observations for one question disagree, the question becomes
`contested`: neither answer enters the current overlay, Stage 4g regeneration
remains blocked on that subject, and the next preparation automatically includes
a canonical conflict-resolution question. A conflict question is permitted even
when no current Stage 4g SQL publication exists: it binds the most recent
verified retained graph artifact plus current Stage 4f/source dependencies. It
names the complete conflicting observation-ID set in `supersedes`, uses the same
stable subject and resolution contract, and produces a new observation that
supersedes the whole set. Only an accepted conclusive superseding observation
clears the contest. Timestamps and generation order never choose a winner.

An identical conclusive answer with an identical dependency/evidence projection
is redundant history, not a conflict. It may remain stored, while the overlay
contains one content-addressed observation identity.

### Evidence strength

Stage 4h uses three evidence rungs:

- `static-resolved`: a bounded static reread settles the exact question but
  makes no runtime claim;
- `emulated-observed`: a bounded userland probe observed the exact recorded
  behavior in the captured emulation environment; and
- `hardware-observed`: an imported capture observed the exact recorded behavior
  on the identified device and firmware state.

The rung is derived from the question method and validated evidence type, never
chosen freely by the worker. No rung means “exploitable,” “reliable,” or “works
on all devices.” Limitations are mandatory for both dynamic rungs.

## Persistence model

Stage 4h adds six dedicated tables. Historical rows are retained; “current” and
“stale” are derived by dependency verification rather than destructive cleanup.

### `cba_firmware_dive_runs`

One immutable question generation, keyed by image ID and `dive_generation`.
It binds the candidate snapshot, Stage 4g graph path/hash, analyst manifest
path/hash (including the canonical empty manifest), journal-input index
path/hash, question packet index path/hash, question/origin counts, pending or
complete status, canonical journal path/hash, preparation/completion timestamps,
and result counts by outcome.

`dive_generation` is the SHA-256 of the exact verified graph projection,
canonical analyst manifest, current accepted input-overlay identities, and all
canonical question projections. Absolute root paths and timestamps are excluded.

### `cba_firmware_dive_questions`

One frozen assignment per generation and question. It stores origin, canonical
subject references, method, question, settling observation, affected axes,
resolution contract, retry attempt ordinal, prior/superseded observation IDs,
packet path/hash, and ordinal. Ordinals are contiguous over questions sorted by
question ID plus attempt ordinal; they are dispatch order only and do not
establish identity.

### `cba_firmware_dive_receipts`

One canonical result receipt per generation assignment, with two exact variants.
A `question` receipt uses a `question:<question-id>:<attempt-ordinal>` receipt
key, non-null question ID, packet/result paths and hashes, outcome, submitted
dependency/evidence/successor counts, and recorded timestamp. An `empty` receipt
uses the derived `empty:<dive-generation>` key, null question/packet fields, the
canonical empty-result path/hash, zero counts, and no observation. Empty receipts
are valid only when the prepared question count is zero; question receipts are
required otherwise. Duplicate import is idempotent only when canonical bytes and
every stored row are already exact; otherwise it is refused. There is no replace
mode.

### `cba_firmware_dive_observations`

One canonical observation per receipted question. It stores the derived
observation ID, outcome, conclusion, limitations, derived evidence rung,
canonical dependency/evidence reference arrays, successor question projections,
artifact provenance, and recorded timestamp. `inconclusive` observations remain
durable but never enter the resolution overlay.

`observation_id` hashes image ID, candidate snapshot, question ID, outcome,
conclusion, limitations, derived rung, and canonical dependency/evidence
projections. Worker labels and timestamps are excluded.

### `cba_firmware_dive_dependencies`

One row per observation-local dependency ordinal. It stores dependency kind,
canonical logical identity, exact artifact-relative path where applicable,
SHA-256, byte count, and source provenance. Supported kinds are frozen:
`finding-artifact`, `surface-artifact`, `chain-artifact`, `extract-record`,
`probe-manifest`, and `hardware-capture`. Dependencies are unique by logical
identity within an observation and contiguous by sorted canonical projection.

### `cba_firmware_dive_acquisitions`

One immutable acquisition receipt per `probe|capture` acquisition ID. Both
variants bind the owning question and dive generation, specification and
manifest paths/hashes, acquisition contract, evidence paths/hashes, and creation
timestamp. Probe rows additionally retain executable/runner/loader/library/shim
hashes, exact argv/environment, isolation backend, limits, termination result,
and stdout/stderr/output manifests. Capture rows retain device/firmware/state/
operator/method provenance plus the copied evidence manifest. An acquisition
receipt alone is not a conclusion.

All JSON cells are canonical UTF-8 with exact keys, compact separators, no
duplicate members, no non-finite values, no boolean integers, and sorted unique
arrays wherever order has no semantic meaning.

## Immutable artifacts and worklists

Preparation installs:

```text
files/firmware-dive/<dive-generation>/
  index.json
  journal-input.json
  questions/<question-id>.json
```

`index.json` contains scalar generation ownership and the complete ordered
question packet manifest. `journal-input.json` is a bounded index of historical
current/stale/contested observations; evidence bodies remain behind paths.
Each question packet contains its exact subjects, retained upstream evidence
references, current resolution context, allowed dependency identities, and at
most three explicit `extract/` manifest records. For future dynamic evidence it
contains a strict acquisition contract rather than a nonexistent hash: permitted
method, artifact kinds, subject/question ownership, expected probe/capture class,
and byte/file limits. A later probe or capture is authorized only when its sealed
manifest satisfies that contract. The packet never embeds unrestricted firmware
files or the complete graph.

Worker results install beneath:

```text
artifacts/firmware-dive/<dive-generation>/<question-id>/<result-sha256>/
  result.json
```

Probe artifacts install beneath:

```text
artifacts/firmware-dive-probes/<probe-id>/
  spec.json
  manifest.json
  stdout.bin
  stderr.bin
  outputs/...
```

Externally acquired hardware evidence installs beneath:

```text
artifacts/firmware-dive-captures/<capture-id>/
  spec.json
  manifest.json
  evidence/...
```

The completed canonical journal installs at:

```text
artifacts/firmware-dive/<dive-generation>/<journal-sha256>/journal.json
```

Artifact paths are run-relative in worker packets and persisted provenance where
existing firmware phases require that convention. CLI JSON returns exact usable
paths. No absolute firmware root enters canonical identity material.

## Phase lifecycle

### Prepare

Public preparation is:

```bash
python3 audit.py dive --run RUN --prepare --root ROOT \
  [--image-id ID] [--questions QUESTIONS.json] \
  [--retry QUESTION_ID[:OBSERVATION_ID] ...] [--json]
```

Preparation requires one current completed Stage 4g graph and reconstructs its
canonical `chains.json`. It derives the complete automatic question set, parses
the strict analyst manifest (or canonical empty manifest), validates every
subject, freezes the current dive-history index, builds packets, installs them
content-addressed, then takes `BEGIN IMMEDIATE`. Under the lock it repeats the
live root, Stage 4f, Stage 4g, manifest, historical dependency, and installed-byte
checks before publishing one pending immutable generation.

An identical prepare without retry directives is idempotent and preserves
receipts/completion/timestamps. A changed question manifest, upstream graph, or
canonical retry projection creates a new generation; it never deletes older dive
rows. Normal preparation requires a completed current graph and rejects foreign
or stale analyst subjects. When the overlay is contested and Stage 4g has been
invalidated, a conflict-only preparation instead verifies the most recent
retained graph artifact, current Stage 4f/source dependencies, and the complete
conflict set, then freezes the automatically derived conflict questions. It may
not add unrelated analyst questions or ordinary retries.

The denominator is fixed at publication. Worker-proposed successors cannot
enter it. An empty automatic and analyst set still requires import of one strict
run-level empty result, represented by the `empty` receipt variant, before it can
complete.

### Worker review

The installed `firmware-dive` brief receives exactly one packet, the bounded
journal-input index, the result path, and no SQL authority. One fresh strongest-
available worker owns the question from reread through result JSON. It may use
only packet-authorized dependencies and at most three exact extract records.

The brief requires the worker to:

- state the proposition being tested before analyzing it;
- distinguish observation from inference;
- challenge environment mismatch, unreachable setup, wrong daemon authority,
  reboot assumptions, instrumentation effects, partial-state capture, and
  alternative explanations;
- treat crashes/timeouts/tool absence as inconclusive;
- state what exact fact remains unproved;
- propose successor questions without claiming they ran; and
- emit strict result-only JSON plus one bounded return line.

The worker cannot run SQL, publish canonical artifacts, alter question state,
select an evidence rung, regenerate chains, assign severity, or make acquisition
or report decisions.

### Probe

Public bounded probing is:

```bash
python3 audit.py dive --run RUN --probe PROBE.json --root ROOT [--json]
```

The strict probe specification names one prepared question, one executable
inside the verified firmware root, optional loader/libraries, an optional NVRAM
shim, exact argv, an allowlisted environment, declared stdin/input files,
declared output paths, an isolation backend, and limits.

The runner uses `subprocess` without a shell, starts a new process group, closes
unneeded file descriptors, supplies a minimal environment, redirects all three
standard streams, and kills the process group on timeout. It never resolves
executables through ambient `PATH`. Firmware executables, libraries, runner,
loader, shim, and inputs are regular-file checked and hashed before and after
execution.

Network policy is exactly `none` in Stage 4h. Execution requires a verified
isolation adapter capable of creating a no-network namespace/sandbox. The tool
may use an already installed supported adapter or a user-supplied explicit
adapter path, but never installs one and never falls back to an unsandboxed
process. If no adapter is ready, probing returns an inconclusive probe manifest
and does not execute the firmware binary.

Frozen limits are:

- timeout: integer 1 through 300 seconds;
- argv: at most 128 entries, each at most 4096 UTF-8 bytes;
- environment: at most 64 names matching `[A-Z_][A-Z0-9_]*`, values at most
  4096 UTF-8 bytes, with dangerous loader variables rejected except the one
  explicit validated shim mechanism;
- stdout and stderr: 1 MiB each, with truncation explicitly recorded;
- declared captured outputs: 8 MiB total and 256 regular files;
- no symlinks, devices, sockets, FIFOs, parent traversal, absolute output paths,
  undeclared output collection, or writes outside the isolated output root.

Exit, signal, crash, timeout, truncation, and unsupported-tool results are facts
in the manifest, not conclusions. Probe publication is artifact-first and
receipt-atomic; a failure may leave only an unreferenced immutable directory.

### Capture

External hardware evidence is sealed before a worker may cite it:

```bash
python3 audit.py dive --run RUN --capture CAPTURE.json --root ROOT [--json]
```

The strict capture specification names one prepared question, the exact packet
acquisition contract, device identifier, firmware version and image hash,
lifecycle/posture/authentication state, operator/source, capture method, and
one or more regular evidence files. Capture import refuses symlinks, devices,
sockets, FIFOs, escaping paths, changed files, or more than 64 MiB/256 files. It
copies and rehashes evidence into a content-addressed directory, writes a
canonical manifest, and atomically publishes a question-owned capture receipt.
It makes no conclusion and never contacts or controls the device.

Probe and capture manifests are the only dynamic artifact identities a worker
may add after packet preparation. They are authorized by question ownership plus
the frozen acquisition contract, not by arbitrary worker-selected paths.

### Record

Public result import is:

```bash
python3 audit.py dive --run RUN --record RESULT.json [--json]
```

The parser enforces strict UTF-8 JSON, exact keys, duplicate rejection, an 8 MiB
raw and canonical cap, correct generation/question ownership, one valid outcome,
bounded prose, canonical successor questions, and only packet-authorized
dependencies/evidence. Static references must be enumerated by the packet;
dynamic references must be exact question-owned probe or capture IDs whose
sealed manifests satisfy the packet acquisition contract. Hardware captures
require device identifier, firmware version/hash, lifecycle/posture/
authentication state, operator/source, capture method, and content hash.

For a nonempty generation, result JSON is the question-answer variant described
above. For an empty generation, the only accepted result is the exact empty
variant containing image/generation ownership and `questions: []`; it creates
the run-level empty receipt and no observation/dependency/acquisition row.

Validation is read-only and produces exact SQL-ready rows. Import installs
canonical result bytes, takes `BEGIN IMMEDIATE`, repeats question/upstream/
dependency/probe/installed-byte checks, then publishes receipt, observation, and
dependency rows atomically. The dive run remains pending. Exact duplicate import
is idempotent only when bytes and all rows already match; conflicting duplicates
fail. Sibling questions, generations, and images survive every failure.

### Check

Public completion is:

```bash
python3 audit.py dive --run RUN --check --root ROOT [--image-id ID] [--json]
```

`check` reconstructs the frozen graph artifact, question packets, every result,
probe/capture manifest, receipt, observation, dependency, and acquisition row. It requires
exact coverage of the prepared denominator, including a truthful empty result.
Every dependency is rehashed or verified against its immutable owning artifact.
It derives evidence rungs, outcome counts, current/stale/contested state, and the
canonical journal without trusting stored derived fields.

The generation may complete with inconclusive observations when every frozen
question is receipted. Success installs `journal.json`, then takes
`BEGIN IMMEDIATE` and repeats all mutable and installed-byte checks. It publishes
the exact completed run and journal provenance. If any newly accepted conclusive
observation changes the current overlay, the same transaction invalidates the
selected image's six Stage 4g tables after preserving the verified graph artifact
reference in the dive run. Dive history is never deleted.

A completed recheck reconstructs from immutable artifacts, supports the expected
absence of the invalidated Stage 4g SQL publication, requires byte-identical
journal and rows, and performs no writes or timestamp changes. Missing or changed
historical artifacts are corruption, not repaired state.

## Stage 4g feedback loop

Stage 4g gains one read-only overlay boundary that selects conclusive,
non-contested Stage 4h observations whose full dependencies remain current.
Before any dive exists the overlay is canonically empty, preserving Stage 4g
behavior.

Freshness does not require the invalidated Stage 4g SQL rows to remain current.
The originating `chain-artifact` is immutable historical provenance: its bytes
and hash must remain exact, but it is not compared to the replacement graph.
Currentness is derived from the still-current Stage 4f candidate snapshot,
finding/surface/unknown artifacts, extract records, probe inputs, capture
identity, and the stable subject fingerprint. This breaks the apparent cycle:
an observation can be current while graph N is absent, and graph N+1 may consume
it before graph N+1 exists.

After regeneration, positive edge evidence is usable only on an edge whose
recomputed stable semantic fingerprint matches the observation's target.
Refuted edge evidence remains a constraint against recreating that fingerprint.
Finding, blocker, and unknown effects use their stable IDs/contracts. If graph
N+1 has no matching subject, the observation remains valid history but is not
attached to any current graph subject or decision input.

`firmware_chain.prepare` includes the overlay projection in its worklist and
worklist hash. The chain brief receives supported observations as additional
evidence context and refuted observations as constraints. Result validation may
accept a `dive:<observation-id>#conclusion` or `#evidence` reference only when it
belongs to the current overlay and outcome/rung permits that use. Refuted
observations cannot supply positive edge evidence.

Chain composition must not recreate a blocker already conclusively settled by
the current overlay without a distinct changed question or dependency. It must
not retain an edge directly refuted for the same stable subject fingerprint.
The Stage 4g completion gate repeats those rules and exact overlay ownership.

If an upstream manifest, surface, finding, graph semantic dependency, extract
record, probe input, or hardware capture changes, the observation remains in
history but becomes stale. Stale observations are absent from the overlay and
cannot support Stage 4g or `decide`. The next complete graph may make a stale
question relevant again only through a new dive generation and new evidence.

This is a versioned feedback loop, not a circular mutable dependency:

```text
completed static graph N
  -> immutable dive generation and observations
  -> invalidate graph N publication
  -> graph N+1 composed from static inputs + current dive overlay
  -> later dive generation if graph N+1 still has questions
```

## CLI and output contract

Stage 4h adds the `dive` verb with exactly one of `--prepare`, `--probe`,
`--capture`, `--record`, or `--check`. All modes require `--run`;
prepare/probe/capture/check require `--root`; probe/capture require a prepared
question; record needs no live root but revalidates retained immutable ownership.
`--image-id` is valid only for prepare/check. `--retry` belongs only to prepare.
Generic source-code verbs remain unchanged.

Human success output exposes only bounded scalar counts, identities, outcomes,
and artifact paths. It never prints question bodies, conclusions, stdout,
stderr, hardware captures, extracted code, environment values, or private
evidence. JSON uses a fixed scalar whitelist and preserves exact usable paths
and identities.

Expected semantic errors exit 1 with escaped, root-redacted, capped diagnostics.
Syntax errors exit 2 before database access. SQLite cause/context chains map to
the fixed `dive: database operation failed` diagnostic. Unexpected exceptions
propagate after resource and transaction cleanup.

## Invalidation and retention

No upstream phase destructively deletes Stage 4h history. Current overlay
selection always verifies dependencies against live/current provenance, so an
upstream change makes affected observations stale automatically.

Explicit `dive --prepare` never changes Stage 4g. Only successful completion of
a generation with a changed accepted overlay invalidates the selected image's
current Stage 4g publication. Invalidation uses the existing SQL-only Stage 4g
invalidator inside the dive completion transaction. Failure rolls back both the
completed dive publication and Stage 4g deletion.

An explicit administrative purge is outside Stage 4h. Historical evidence is
ordinary repository/run data and follows the operator's existing run-retention
policy.

## Installation and agent routing

Add one installed `references/briefs/firmware-dive-brief.md` template and a
separate Stage 4h route in `SKILL.md`. After prepare, the orchestrator reads only
the scalar packet index, dispatches one fresh strongest-available worker per
question, collects the exact one-line return, imports completed result paths,
and runs check after all assignments terminate.

Workers may run concurrently only when the harness has independent worker slots;
question/result/probe directories and SQL primary keys are disjoint. The
orchestrator does not inline packets or journal bodies and does not retain worker
analysis. PARTIAL preserves worker scratch only and is not importable. FAILED
leaves the question uncovered until a later worker result or generation.

The exact worker return is:

```text
firmware-dive <DONE|PARTIAL|FAILED> question=<question-id> artifact=<path> [flags=<csv>]
```

## Verification strategy

Stage 4h requires tests for:

- six table contracts, migration from both frozen baselines, and preservation of
  all Stage 4b-4g rows;
- strict analyst manifests, automatic question coverage, stable subject
  fingerprints, duplicate/conflict handling, and canonical empty generations;
- packet installation, symlink/redirected-parent refusal, locked revalidation,
  idempotent prepare, sibling isolation, and historical retention;
- strict result parsing, outcome variants, canonical identities, dependency and
  evidence authorization, dynamic artifact requirements, and successor bounds;
- atomic per-question import, duplicate idempotence, rollback at every table,
  and private-output exclusion;
- complete/inconclusive/empty completion, contested answers, stale dependency
  derivation, immutable completed recheck, artifact corruption, and atomic Stage
  4g invalidation;
- Stage 4g overlay consumption, positive/refuted evidence rules, regeneration,
  stale-overlay exclusion, generic-chain compatibility, and rollback;
- probe path containment, regular-file checks, before/after hashes, no-shell
  invocation, isolation-backend refusal, process-group timeout cleanup, byte and
  file caps, output traversal/symlink/device refusal, and manifest determinism;
- CLI flag matrix, exit codes, bounded/redacted human and diagnostic output,
  fixed JSON scalar shapes, exact path/identity round-trips, and unexpected
  exception propagation;
- installed Claude/Codex brief rendering, one-fresh-worker routing, no inline
  evidence, no worker SQL/completion authority, and generic workflow retention;
  and
- final documentation, manifest, install, coverage, benchmark, and full harness
  reconciliation after the last edit.

Real probe tests execute only purpose-built fixture binaries under a fake or
verified local isolation adapter. They never execute corpus firmware, access the
network, or require root. Optional real-tool integration is reported separately
and cannot gate the deterministic suite.

## Documentation and completion

Completion reconciles `progress.md`, `SESSION_HANDOFF.md`, `ARCHITECTURE.md`, and
`feature_lists.json` with the actual Stage 4h tree. It records exact emitted
harness values, preserves historical baselines/plans, removes `dive` from next
steps, and names Stage 4i `decide` with the limitations it inherits.

The durable handoff must state that static, emulated, and hardware observations
prove only their exact recorded facts. The Asus golden, paid milestone audit,
second indicator snapshot, mutation sweep, separate firmware skill tree, and
monorepo/submodule decision remain open unless explicitly run or settled.

## Builder-check resolutions

The builder check found six decisions that the conversational design had not
made explicit. This document resolves them as follows:

1. Identical retries require explicit retry directives and a durable attempt
   ordinal in generation identity; ordinary repeated prepare stays idempotent.
2. Contested answers create an automatic conflict-only generation over retained
   graph evidence, and only a conclusive superseding observation clears the
   complete conflict set.
3. Every question carries a machine-readable resolution contract and every
   conclusive answer carries an exact structured effect; Stage 4g never infers
   state changes from prose.
4. Retained graph bytes establish historical provenance, while current Stage
   4f/source dependencies and stable semantic subjects establish freshness after
   graph invalidation.
5. Frozen packets authorize dynamic acquisition contracts; only sealed,
   question-owned probe or capture manifests may introduce later artifacts.
6. The ordinary receipts table has an exact empty variant keyed by generation,
   so an empty denominator still requires explicit result import without a
   synthetic question.

## Builder calls deliberately left open

- Exact internal helper names and file splits may follow adjacent Stage 4g
  conventions as long as the public CLI, table ownership, identities, and phase
  boundaries above remain exact.
- The supported no-network isolation adapter registry may start with the tools
  available on the development platform plus a test adapter; unsupported hosts
  must refuse execution rather than weaken isolation.
- SQL indexes that do not change row identity or ownership may be selected from
  measured query plans.
- Worker dispatch concurrency is an orchestrator resource choice; correctness
  cannot depend on dispatch order or concurrency.
