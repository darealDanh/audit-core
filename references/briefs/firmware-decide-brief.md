# Firmware acquisition decision

Audit run directory: {run_dir}
Target image ID: {image_id}
Decision generation: {decision_generation}
Immutable global worklist: {worklist_path}
Required result file: {result_path}

## Assignment and authority

You are one fresh strongest-available worker assigned the one global firmware
acquisition decision worklist. Read only that immutable worklist and its frozen
references. Read the worklist incrementally from that exact path; never
partition it by chain or component, and never cap the chain or open
precondition denominator. Read the result parser and dataclasses in
`__SKILL_DIR__/audit_core/firmware_decide_results.py`; that installed copy is
authoritative, and the schema below restates it. Bind the image ID, decision
generation, graph, dive overlay, policy identity, every chain, and every open
precondition exactly.

The decision generation is the SHA-256 of the exact worklist bytes. If the
worklist bytes, image, or generation differ from the values above, return
FAILED; do not repair the worklist or switch to another generation. A newer
preparation can supersede this one; the orchestrator then prepares and
dispatches again.

Assess every chain in the denominator. A complete result has exactly one
assessment for every chain, including blocked or ineligible chains. Rank only
within the frozen denominator. Use only evidence references admitted by the
worklist. State uncertainty explicitly; never turn missing evidence into a
positive conclusion.

Bench tests must name their frozen subjects and exact required device, firmware,
lifecycle, posture, and authentication state. Proposed scripts are inert text
for later operator review. Do not execute proposed scripts, probes, commands, or
captures. Do not claim that a script has run or that its output exists.

## Result artifact

Write one result-only strict JSON regular UTF-8 file to `{result_path}`, at most
8 MiB, using exactly schema version 1 and its keys. Reject duplicate keys,
extra keys, non-finite numbers, malformed identities, absolute evidence paths,
foreign evidence, omitted chains, and invented policy matches. Keep analysis in
the artifact, never stdout. "Sorted" below means ascending Python string or integer
order with no duplicates; "text" means a nonempty string without NUL or control
characters other than newline and tab, at most 16 KiB UTF-8.

The top level has exactly these keys:

- `schema_version`: the integer `1`.
- `image_id`: the target image ID above.
- `decision_generation` and `worklist_sha256`: both the decision generation
  above, as lowercase SHA-256 hex; they must be equal.
- `answer`: one of two variants. When the frozen graph has zero chains, use
  exactly `{"kind": "empty"}`. Otherwise use an object with exactly `kind`
  (`"decision"`), `chain_assessments`, `bench_tests`, and `proposed_scripts`.

## Chain assessments

`chain_assessments` is nonempty, sorted by `chain_id`, and covers exactly the
graph's chains. Each assessment has exactly:

- `chain_id`: the frozen chain ID.
- `rank`: integer; ranks across all assessments are exactly 1 through the
  chain count, 1 being the strongest acquisition candidate.
- `initial_attacker_position`, `pre_auth`, `confidence`, `completeness`,
  `evidence_rung`: copied exactly from the frozen chain.
- `member_ids`: the frozen chain's member IDs in graph order.
- `edge_ordinals`: the sorted ordinals of that chain's frozen edges.
- `open_preconditions`: exactly the worklist `open_preconditions` objects whose
  `locations` include this chain, copied whole (all keys and every location)
  and sorted by `precondition_id`; an empty array when none apply.
- `disposition`: `bench-priority`, `retain`, or `deprioritize`.
- `rationale`: text.
- `limitations`: sorted text entries; may be empty.
- `evidence_refs`: nonempty sorted references, each one of this chain's frozen
  `initial_evidence_refs` or its edges' producer, consumer, or supplemental
  evidence refs, or `dive:<observation_id>#conclusion` or `#evidence` for a
  frozen overlay observation whose subject or settled-subject refs name this
  chain, its edges, its member findings, or its open preconditions.

## Bench tests

`bench_tests` is sorted by `test_id` and may be empty. Each test has exactly:

- `test_id`: `firmware-decide-test-` followed by the lowercase SHA-256 of the
  test object without `test_id`, serialized as UTF-8 JSON with sorted keys,
  `(",", ":")` separators, and non-ASCII characters left unescaped.
- `chain_ids`: nonempty sorted frozen chain IDs this test exercises.
- `subject_refs`: nonempty sorted subjects. A subject is either a worklist
  `precondition_id` (`blocker:<source_id>` or `unknown:<source_id>`) or
  `transition:<chain_id>:<edge_ordinal>` naming one frozen edge.
- `title`, `purpose`, `expected_signal`, `control_observation`: text.
- `required_state`: exactly `device`, `firmware`, `lifecycle`, `posture`, and
  `authentication`. `device` equals the image ID and `firmware` equals the
  graph's `candidate_snapshot_sha256`.
- `setup_steps`, `action_steps`, `stop_conditions`: nonempty ordered arrays of
  unique text steps.
- `limitations`: sorted text entries; may be empty.
- `script_name`: `null` or the name of one proposed script.

Every subject must be owned by at least one listed chain, and every listed
chain must own at least one subject. A precondition located on several chains
may be covered by tests that each list only a subset of its owner chains.
Required lifecycle, posture, and authentication are checked only against the
listed chains. For each subject and each listed chain that owns it, they must
match at least one of the subject's edge locations on that chain: the edge's
required state, or the carried incoming state where the edge requires `any`.
A subject with no edge location on that chain uses the chain's initial state.

Deterministic code calls a bench plan complete only when the top eligible chain
has at least one test listing it, every hardware open precondition located on
that chain is a subject of such a test, and every named script exists. Plan
hardware preconditions accordingly; never claim a test has run.

## Proposed scripts

`proposed_scripts` is sorted by `name`, holds at most 16 scripts, and may be
empty. Each has exactly `name` and `content`. A name matches
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}` and is not `.` or `..`; names must stay
unique after case folding, so `Probe.sh` and `probe.sh` cannot coexist.
`content` is UTF-8 text without NUL, at most 32 KiB per script and 256 KiB in
total. Every script is referenced by at least one bench test.

## Limits of authority

Do not write SQL or open the database. Do not select or modify policy, compute
the final recommendation or payout, install a canonical artifact, publish
completion, regenerate chains, change severity/CVSS, construct an exploit,
execute proposed scripts, or write a report. Deterministic code owns validation,
policy projection, canonical identities, package installation, recommendation,
payout, and every completion gate.

DONE requires one complete parser-valid global answer. If interrupted, return
PARTIAL; PARTIAL is nonimportable and resumes the same immutable assignment.
Do not shrink the denominator or replace the worklist. FAILED means the frozen
assignment cannot be read or a valid complete result cannot be produced.

## Return contract

Return exactly one line and nothing else:

    firmware-decide <DONE|PARTIAL|FAILED> chains=<n> artifact=<path> [flags=<csv>]

Replace `<n>` with the number of chain assessments and `<path>` with
`{result_path}`.
