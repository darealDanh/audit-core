# Stage 4i Firmware Decide Design

**Date:** 2026-11-04  
**Status:** approved  
**Consumes:** one current completed Stage 4g graph, its exact current non-contested Stage 4h overlay, and one explicit operator policy snapshot  
**Produces:** one provenance-bound acquisition decision package

## Intent

Stage 4g establishes evidence-backed firmware chains. Stage 4h asks and settles
specific static, emulated, and hardware questions without granting those
observations severity, exploit-reliability, acquisition, or disclosure
authority. Stage 4i is the terminal scan-before-buy decision boundary. It turns
one current graph plus its exact current dive evidence into a reviewable policy
package that answers a narrower question: should the operator acquire this
device under the supplied cost and payout policy, and what should happen on the
first bench day?

`decide` does not discover new facts. It freezes current verified facts and a
separate operator policy, gives one global worker a bounded file-backed view,
requires a disposition and rank for every current chain, and deterministically
publishes an acquisition recommendation. The worker supplies analysis and a
bench proposal. The deterministic core owns provenance, policy matching,
payout-range projection, the final `acquire|defer|pass` recommendation, package
identity, publication, and every currentness check.

The package is advice under a named policy snapshot. It is not a severity,
CVSS, exploit-reliability, exploit-success, vendor-eligibility, or disclosure
claim.

## Goals

1. Consume only one current, completed and reconstructable Stage 4g graph whose
   frozen dive overlay equals the independently reconstructed current,
   non-contested Stage 4h overlay.
2. Refuse preparation while a Stage 4h generation for the selected image is
   pending; require an explicit completed dive denominator, including its
   canonical empty-receipt case.
3. Freeze an explicit operator policy independently from technical evidence.
4. Require one bounded assessment for every current graph chain, including a
   unique contiguous rank, current attacker position, pre-auth state, residual
   preconditions, and cited evidence identities.
5. Preserve open blockers and unknowns as open preconditions with their exact
   settling observations; never convert absence of evidence into settlement.
6. Produce a Day-1 bench plan that names setup, procedure, expected signal,
   control, stop conditions, exact chain/subject ownership, and any proposed
   script.
7. Treat proposed scripts as bounded, inert package content: store them as
   non-executable regular files, never execute them, and label them for manual
   review.
8. Project payout ranges mechanically from policy tiers and current chain facts;
   workers cannot invent payout tiers or amounts.
9. Derive `acquire|defer|pass` mechanically from the frozen policy, policy
   matches, acquisition cost, support/payout status, and completeness of the
   top matching chain's bench proposal.
10. Publish one canonical immutable package and expose a read-only verified
    current-package helper for the later `report` phase.
11. Preserve historical packages when evidence or policy changes while refusing
    to return them as current.
12. Preserve sibling images, generic source-code behavior, and all Stage 4a–4h
    history.

## Non-goals

- Creating, promoting, suppressing, deduplicating, or re-rating findings.
- Assigning severity, CVSS, exploitability, exploit reliability, exploit
  success, or disclosure language.
- Claiming that emulation proves device behavior or that one hardware capture
  generalizes beyond its recorded device, firmware, state, and procedure.
- Running a probe, script, network request, hardware operation, exploit, or
  proof of concept.
- Automatically buying hardware, contacting a vendor, choosing a disclosure
  channel, or filing a report.
- Fetching live support, EOL, bounty, marketplace, or program data. Those are
  explicit operator policy inputs whose truth remains the operator's
  responsibility.
- Mutating Stage 4d unknowns, Stage 4g chains/blockers, or Stage 4h observations.
- Choosing between contested observations. Contested observations are absent
  from the current overlay and cannot enter a decision input.
- Replacing `qualify`. Stage 4a says whether an audit is worth starting; Stage
  4i says whether hardware acquisition is justified by the completed audit.
- Building the later `report` phase, the separate firmware skill tree, the Asus
  golden, or the monorepo/submodule restructure.

## Anti-goals

- A recommendation that cannot be reproduced from exact graph, dive, policy,
  result, and package bytes.
- A worker-authored `buy` verdict treated as authoritative.
- A payout number inferred from severity prose or model intuition.
- Ranking only promising chains and silently omitting weak or blocked chains.
- Calling a blocker closed because the worker did not mention it.
- Executing worker-authored scripts during import, check, installation, tests,
  or normal CLI use.
- Mirroring every package field into mutable SQL tables.
- Wiring Stage 4i deletion into every upstream mutation path.
- Repeating the full repository harness after every implementation task.

## Constraints inherited from the repository

- Python remains standard-library only.
- SQLite plus canonical immutable artifacts are durable authority; worker return
  text and the generic annotation journal are not authoritative.
- Raw findings, evidence, and script bodies remain file-backed and out of the
  orchestrator context.
- Public JSON preserves exact scalar identities and usable paths. Human output
  and expected diagnostics remain escaped, root-redacted, ASCII-bounded, and
  free of private evidence.
- Content-addressed artifacts install before SQL publication. A rejected
  transaction may leave only an unreferenced immutable artifact.
- Selected-image operations preserve sibling images.
- Complete rechecks never repair missing/corrupt artifacts or rows.
- Triage remains upsert-only and Stage 4d retains its orphan-scan scaling
  limitation.
- `make mutate`, the paid audit/milestone, Asus golden, second indicator
  snapshot, real hardware work, and Linux/alternate-interpreter execution remain
  separately reported.

## Approaches considered

### A. One immutable decision package with one run row — selected

Freeze a verified graph/dive/policy worklist, validate one global result, derive
policy matches and the final recommendation deterministically, and publish one
canonical package. SQL stores one lifecycle/provenance row; the package owns the
ranked chain assessments, preconditions, bench plan, scripts, and policy
projections.

This minimizes duplicated state and cross-row invariants. Later `report` reads a
verified package helper rather than joining a second graph model. Historical
packages survive naturally, and currentness is checked instead of enforced by a
large deletion cascade.

### B. Normalize decisions, ranks, tests, scripts, and projections into tables — rejected

This makes ad-hoc SQL easier but recreates Stage 4g/4h's reconstruction burden,
adds ordering and denominator invariants to every table, and gives later code two
sources of truth. Stage 4i is terminal advice, not a feedback source, so the
cost is not justified.

### C. A deterministic package with no worker — rejected

Policy matching can be deterministic, but chain prioritization and a useful
bench procedure still require bounded expert judgment. Removing the worker
would produce a mechanically sorted inventory rather than an acquisition
package.

### D. Accept a free-form decision report — rejected

A free-form report cannot prove complete chain coverage, exact evidence
ownership, currentness, policy provenance, payout derivation, or bench-test
ownership. It would also let persuasive prose become an authoritative buy
verdict.

## Trust and authority model

### Technical facts

The technical input is a new frozen `VerifiedDecisionInput` containing:

- the exact `VerifiedFirmwareGraphSnapshot`;
- the exact `CurrentDiveOverlay` used by that graph;
- the selected completed dive generation, journal path/hash, and overlay hash;
- the complete current blocker/unknown settlement view; and
- no contested, stale, pending, or historical-only observation.

`firmware_dive.verified_decision_input(...)` reconstructs this value under one
read transaction. It requires a current completed Stage 4g graph, no selected
pending dive generation, one explicit latest completed denominator, exact
journal/result/acquisition/dependency reconstruction, and equality between the
graph's frozen overlay and the independently rebuilt current overlay. It works
with read-only SQLite and caller-owned transactions and performs no repair.

A chain's `initial_attacker_position`, `pre_auth`, confidence, completeness,
evidence rung, blocker IDs, unknown IDs, members, and edges are facts copied
from this verified input. The worker may cite and discuss them but cannot replace
them.

### Operator policy

Policy is not evidence. A strict canonical policy manifest supplies:

- `schema_version = 1`;
- `policy_id`: a stable bounded identifier;
- `currency`: exactly three uppercase ASCII letters;
- `acquisition_cost_minor` and `max_acquisition_cost_minor`: non-boolean
  integers from 0 through 1,000,000,000;
- `support_status`: `supported|unsupported|unknown`;
- `support_basis`: bounded operator prose naming a checkable source/date/version;
- one or more payout paths with stable ID, `eligible|ineligible|unknown`, and a
  bounded basis;
- one or more ordered payout tiers with stable ID, payout-path ID, minimum and
  maximum minor-unit values, accepted `pre_auth` values, minimum confidence,
  accepted completeness values, accepted evidence rungs, and whether physical
  access may remain required; and
- `notes`: bounded policy limitations, never technical evidence.

Tier order is explicit and unique. Amount ranges must be monotonic within each
path and `minimum <= maximum`. Every tier references one declared payout path.
The manifest is capped at 1 MiB, duplicate keys are rejected, arrays are
canonical and bounded, and unknown fields fail closed.

The core does not prove the policy's support or payout assertions. It records
the exact bytes/hash and labels projections as policy-derived. `unknown` produces
`defer`, never an optimistic default.

### Worker authority

One strongest-available global worker receives only the immutable worklist and a
result path. It returns strict JSON containing:

- exact image/generation/worklist ownership;
- exactly one assessment for every chain;
- one unique contiguous rank from 1 through the chain count;
- bounded rationale and limitations;
- only exact graph/dive evidence references;
- every residual blocker/unknown relevant to that chain;
- a disposition `bench-priority|retain|deprioritize`;
- zero or more structured bench tests; and
- zero or more bounded proposed scripts embedded as text.

The worker does not return a final acquisition recommendation, payout amount,
severity, CVSS, exploit reliability, exploit success, or report prose. It cannot
write SQL, install artifacts, mutate upstream state, execute a script, or choose
which observations are current.

### Core authority

The deterministic core exclusively owns:

- policy parsing and hashing;
- worklist generation and identity;
- result parsing and complete-chain coverage;
- graph/dive/policy evidence-reference validation;
- open-precondition completeness;
- policy-tier matching and payout-range projection;
- final `acquire|defer|pass` derivation;
- canonical script/package installation;
- SQL lifecycle publication;
- completion and currentness checks; and
- the read-only verified package returned to `report`.

## Policy matching and final recommendation

Each chain first receives **technical tier matches** using only exact structured
fields:

1. the chain's `pre_auth` is accepted by the tier;
2. chain confidence is at least the tier minimum;
3. chain completeness is accepted;
4. chain evidence rung is accepted; and
5. when any exact open precondition for the chain has `method == "hardware"`,
   the tier permits physical access to remain required.

`requires_physical_settlement` is therefore derived, never worker supplied: it
is true exactly when the chain's open-precondition denominator contains at least
one Stage 4g blocker or Stage 4d unknown whose verified method is `hardware`.
An **eligible policy match** is a technical match whose referenced payout path
is `eligible`. An **unknown-path match** is a technical match whose referenced
payout path is `unknown`. Tiers on `ineligible` paths never match.

The package records every technical, eligible and unknown-path match and selects
the first eligible tier by explicit tier order for each chain. This is a policy
projection, not a factual payout promise. A chain with no eligible match has no
payout-range projection.

The top matching chain is the lowest worker-supplied rank among chains with an
eligible policy match. Its Day-1 bench plan is complete exactly when:

- at least one structurally valid bench test references that chain;
- every open `method == "hardware"` precondition for that chain is referenced
  by at least one of those tests; and
- every script named by those tests exists in the validated script set.

A test may cover more than one chain or precondition. Non-hardware open
preconditions remain visible but do not make the hardware-acquisition plan
incomplete.

The final recommendation uses this precedence:

1. `pass / no-current-chain` when no current chain exists;
2. `pass / support-unsupported` when policy says support is unsupported;
3. `pass / cost-exceeds-policy` when acquisition cost exceeds the maximum;
4. when an eligible policy match exists, `acquire / eligible-chain` only if
   support is `supported` and the top matching chain's bench plan is complete;
   otherwise `defer / support-unknown` or `defer / bench-plan-incomplete`;
5. with no eligible match, `defer / payout-path-unknown` only when at least one
   unknown-path match exists; and
6. otherwise `pass / no-policy-match`.

The package stores one `primary_reason` from that precedence plus every
applicable code from the fixed order `no-current-chain`,
`support-unsupported`, `support-unknown`, `cost-exceeds-policy`,
`eligible-policy-match`, `unknown-policy-path-match`, `no-policy-match`,
`bench-plan-complete`, `bench-plan-incomplete`. Secondary codes never change the
primary recommendation. The worker's rank chooses the top eligible matching
chain; it never changes matching or recommendation rules.

## Complete coverage and open preconditions

Every graph chain appears exactly once. Rank values are the exact set
`1..chain_count`. Chain IDs, copied facts, and evidence references must resolve
to the frozen input. Empty graphs require an explicit empty-result variant and
produce `pass` with `no-current-chain`.

For each chain, the result must list every blocker ID on the verified chain or
its edges and every open unknown ID on the chain or its edges. That exact graph
projection is the open-precondition denominator. Stage 4g regeneration already
rejects recreation of an unchanged `settled_subject_ref`; therefore Stage 4i
does not reapply observations to close graph rows, and no worker omission can
settle one. Each precondition copies its exact subject ID, question/unknown
text, settling observation, method/axes, and affected chain location from the
verified input. Worker prose may explain priority but cannot alter these fields.

Current conclusive dive observations may be cited only by exact observation ID
and only when their subject applies to the chain. They provide evidence/context,
not an additional Stage 4i settlement mechanism. Stale and contested
observations are unreachable through the input. Hardware evidence remains scoped
to its recorded device/firmware/state/procedure. Successor questions have no
decision authority unless a later completed dive and regenerated graph
materialize them as current graph preconditions.

## Day-1 bench plan and proposed scripts

A bench test contains:

- stable `test_id` derived from its semantic content;
- one or more current chain IDs and subject refs;
- title and purpose;
- required device/firmware/lifecycle/posture/authentication state;
- setup steps;
- action steps;
- expected signal;
- one control observation;
- stop conditions;
- limitations; and
- an optional proposed-script name.

A bench test must settle or inspect an exact current precondition or validate an
exact current chain transition. It cannot introduce a new finding, claim
weaponization, or silently broaden a hardware observation.

Proposed scripts are UTF-8 text embedded in result JSON. Names are unique safe
relative basenames. At most 16 scripts are accepted, each at most 32 KiB and at
most 256 KiB total. NUL, invalid UTF-8, absolute/traversing names, symlinks,
devices, sockets, FIFOs, and external file references are impossible because
installation is generated only from validated embedded bytes. Package files are
installed mode `0600`, not executable. Neither import nor check invokes an
interpreter. The package prominently marks scripts `proposed_unreviewed` and
requires manual inspection before use.

## Durable model

Stage 4i adds exactly one table:

### `cba_firmware_decide_runs`

Primary key: `(image_id, decision_generation)`.

The row retains:

- exact Stage 4f/4g ownership: manifest, surface snapshot, candidate snapshot,
  chain worklist, graph path/hash;
- exact Stage 4h ownership: dive generation, journal path/hash, overlay hash;
- policy path/hash and `policy_id`;
- worklist path/hash;
- status `pending|recorded|complete`;
- result path/hash after record;
- package path/hash, final recommendation, primary reason, ordered reason codes,
  chain/test/script/match counts after completion; and
- prepared, recorded, and completed timestamps.

Variant validation requires null later-phase fields while pending, exact result
fields while recorded, and all derived fields while complete. Historical rows
are append-only after completion. Only one pending/recorded generation per image
may exist. A new preparation with changed current input or policy creates a new
generation; it does not delete an old package.

The fresh schema becomes 45 SQLite tables and 44 TableSpec contracts. Existing
migrations remain unchanged and both frozen baselines accept the additive table.
No per-chain, precondition, test, script, or payout table is added.

## Immutable artifacts and identities

Preparation installs:

- `files/firmware-decide/<decision-generation>/policy.json`
- `files/firmware-decide/<decision-generation>/worklist.json`

`policy.json` is the exact canonical policy snapshot and owns the row's
run-relative `policy_path`/hash. The worklist contains schema version, exact
technical provenance, complete current graph facts, applicable current dive
observations, the same strict policy projection/path/hash, and no private
evidence bodies. `decision_generation` is the full SHA-256 of canonical
worklist bytes.

Recording installs canonical worker JSON at:

`artifacts/firmware-decide-results/<decision-generation>/<result-sha256>/result.json`

Completion installs:

- `artifacts/firmware-decide/<decision-generation>/<package-sha256>/decision.json`
- `artifacts/firmware-decide/<decision-generation>/<package-sha256>/bench/<name>`

`package_sha256` binds the canonical decision projection and every ordered script
name/hash/size. Absolute paths, timestamps, worker identity, local SQL IDs, and
presentation-only formatting do not establish semantic identity. Canonical
package bytes contain run-relative artifact paths.

Installation is descriptor-anchored/no-follow, content-addressed, bounded, and
verified before SQL publication. Exact retries are idempotent. Conflicting bytes
at an existing identity fail closed. SQL/commit failure preserves prior state and
may leave only unreferenced immutable files.

## Lifecycle

### Prepare

`firmware_decide.prepare(con, run_dir, root, policy_path, *, image_id=None)`:

1. verifies the current graph and exact complete decision input under one read;
2. parses and freezes the policy;
3. builds canonical worklist bytes;
4. installs or verifies the immutable worklist;
5. takes `BEGIN IMMEDIATE`;
6. repeats all graph/dive/policy/file checks; and
7. publishes one pending run row atomically.

Identical preparation preserves imported/completed state and timestamps. Changed
input or policy creates a new generation only when no other active generation is
ambiguous. Sibling images and historical rows remain untouched.

### Record

`firmware_decide_results.record(con, run_dir, result_path)`:

1. parses bounded hostile JSON;
2. reconstructs the exact pending assignment and worklist;
3. requires exact complete chain coverage or the explicit empty variant;
4. validates copied facts, evidence refs, open preconditions, bench tests, and
   embedded scripts without a live root;
5. installs canonical result bytes; and
6. atomically moves the row from pending to recorded.

The result cap is 8 MiB before and after canonicalization. Duplicate keys,
unknown fields, invalid UTF-8, non-finite/coerced values, unbounded prose,
foreign/stale IDs, omitted chains, duplicate ranks, invented observations, and
worker-supplied derived fields are rejected.

### Check

`firmware_decide.check(con, run_dir, root, *, image_id=None)`:

1. independently reconstructs current graph, complete dive input, policy,
   worklist, recorded result, and installed bytes;
2. derives policy matches, payout projections, recommendation, reason codes,
   bench/script projection, and package bytes;
3. installs or verifies the immutable package;
4. takes `BEGIN IMMEDIATE` and repeats currentness and byte checks; and
5. atomically marks the row complete.

A complete recheck is read-only and byte/row exact. It never repairs. Any current
technical-input or policy difference means the historical package is not current
and a new prepare is required.

### Verified current package

`firmware_decide.verified_package(con, run_dir, root, *, image_id=None)` returns
one frozen `VerifiedFirmwareDecisionPackage` only after independently repeating
the complete check in a read transaction. It is the sole Stage 4j/report input.
It never falls back to historical packages.

## CLI and worker routing

The CLI adds one firmware-specific verb:

```text
python3 audit.py decide --run RUN --root ROOT --prepare --policy POLICY [--image-id ID]
python3 audit.py decide --run RUN --record RESULT
python3 audit.py decide --run RUN --root ROOT --check [--image-id ID]
```

Exactly one mode is required. `--policy` belongs only to prepare. `--root` belongs
only to prepare/check. `--json` emits bounded scalar summaries. Human output
contains no policy prose, evidence bodies, script bodies, absolute roots, or
private paths. Expected database errors map to a fixed diagnostic; other
expected diagnostics are escaped, root-redacted, and capped.

`references/briefs/firmware-decide-brief.md` renders one global assignment with
exact variables `run_dir`, `image_id`, `decision_generation`, `worklist_path`,
and `result_path`. The worker reads the immutable worklist incrementally and owns
only result JSON. Its exact return line is:

`firmware-decide <DONE|PARTIAL|FAILED> chains=<n> artifact=<path> [flags=<csv>]`

PARTIAL output is a checkpoint only and cannot be recorded. Installed `SKILL.md`
routing is prepare → one strongest global worker → record DONE → check. No
script is executed by this route.

## Currentness without an invalidation web

Stage 4i does not feed Stage 4g or Stage 4h and therefore does not add deletion
calls to acquisition, triage, surface, hunt, fpcheck, chain, or dive modules.
Instead, every prepare/check/verified-package call reconstructs current upstream
authority and compares exact digests. Changed upstream state makes a historical
package non-current but preserves it.

This is safe because no ordinary caller may read a decision row directly as a
current decision; `verified_package` is the public boundary. Tests pin that
later `report` code must use this helper. A direct SQL row is history, not
current authority.

## Performance and implementation-plan optimization

Stage 4h took too long because broad tasks accumulated many authority classes,
large tests, late cross-layer review findings, and repeated full harness runs.
Stage 4i changes the execution shape:

1. **One table, two focused modules.** Avoid six-table mirrors and per-row
   reconstruction where an immutable package is the better source of truth.
2. **Six implementation tasks maximum.** Split at reviewable authority
   boundaries: decision input/policy, prepare, result import, completion/package,
   CLI/worker route, final reconciliation.
3. **Authority tests first.** Currentness, policy/evidence separation, complete
   chain coverage, deterministic recommendation, and inert scripts are pinned
   before CLI/docs work.
4. **Focused RED/GREEN only per task.** Each task runs its own test module and
   directly affected Stage 4g/4h tests. It does not run repository-wide pytest,
   coverage, installer, or benchmark gates.
5. **One early kernel review.** After the completion/package task, review the
   authority core before adding CLI/prose. This catches provenance mistakes while
   fixes are still local.
6. **One final whole-branch review.** Review the completed branch once; fixes use
   focused tests and scoped re-review.
7. **One planned `make all`.** Reconcile implementation paths and deterministic
   metadata first, run one authoritative repository-root `make all`, then record
   its exact status/metrics with status-only durable-document edits. Re-run only
   the doc-sensitive lint/EOL/manifest/install gates after those edits; rerun
   `make all` only when code, tests, routing, manifest paths or executable
   behavior changed.
8. **No routine duplicate coverage run.** The final harness owns full coverage.
   A separate coverage probe is used only if that gate reports a real gap.
9. **No mutation or paid gates.** They remain explicit operator decisions and
   are not hidden inside Stage 4i completion.
10. **Native implementation recommended.** The six tasks share a narrow serial
    interface; fresh implementer/reviewer pairs per task would add handoff cost.
    Use one implementation context plus the early authority review and final
    independent whole-branch review.

## Testing strategy

Focused permanent tests cover consumer-visible authority and failure behavior:

1. strict one-table schema variants, additive baselines, and sibling-image
   isolation;
2. exact current graph/dive input, explicit completed empty dive, pending/stale/
   contested refusal, read-only/caller transaction behavior;
3. strict policy parser, tier references/order/ranges, money bounds, unknown
   support/payout semantics, and canonical identity;
4. canonical prepare/idempotence, descriptor-safe installation, concurrent input
   change, lock/commit rollback, and historical preservation;
5. hostile result parsing, every-chain/rank coverage, copied-fact equality,
   evidence/precondition ownership, bench completeness, script bounds, and no
   execution;
6. deterministic tier matches and every `acquire|defer|pass` branch;
7. canonical package bytes, complete recheck immutability, changed-input refusal,
   verified-package behavior, and no historical fallback;
8. CLI mode matrix, bounded human/JSON output, diagnostics, brief rendering,
   installed copy, routing, and generic behavior compatibility; and
9. final full harness with zero unexecuted statements and no allowlist.

Tests never run corpus firmware, network requests, hardware commands, or embedded
scripts. Script tests inspect installed mode and bytes and inject a subprocess
sentinel that must remain untouched.

## Documentation and durable state

Implementation completion updates `ARCHITECTURE.md`, `progress.md`,
`SESSION_HANDOFF.md`, `feature_lists.json`, `README.md`, and `SKILL.md`. The
current Stage 4h merge state is corrected before Stage 4i execution begins.
Historical task narratives remain historical rather than being rewritten as
current state.

The handoff preserves the open Asus golden, paid milestone audit, mutation
sweep, second indicator snapshot, separate firmware skill tree,
monorepo/submodule decision, triage upsert-only behavior, Stage 4d orphan-scan
scaling limitation, real hardware execution, and Linux/alternate-interpreter
verification.

## Acceptance criteria

1. Only a current completed graph with an exact complete, non-contested dive
   input can produce a decision worklist.
2. Policy facts remain a separately hashed operator snapshot and are never
   presented as observed technical truth.
3. Every current chain is assessed and uniquely ranked, including blocked and
   deprioritized chains; empty graphs require explicit empty coverage.
4. Every open precondition is preserved with its exact settling observation; no
   stale, contested, foreign, or omitted evidence gains authority.
5. Policy-tier matches, payout ranges, reason codes, and
   `acquire|defer|pass` are deterministic and independently reconstructable.
6. Proposed scripts are bounded, inert, non-executable, never run by the tool,
   and visibly require manual review.
7. Historical packages survive changed evidence/policy but
   `verified_package` refuses them as current.
8. SQL and artifact publication are atomic/idempotent and preserve sibling
   images and all Stage 4a–4h history.
9. Generic source-code audit and all existing firmware phases remain compatible.
10. Independent whole-branch review reports no remaining Critical/Important
    issue.
11. Final reconciled `make all` passes all eight gates; mutation and paid/hardware
    gates remain separately reported.
