# Stage 4j Firmware Report Design

**Date:** 2026-11-09  
**Status:** approved for planning

## Intent

Stage 4j turns one current, completed Stage 4i decision package into one lean, maintainer-facing firmware report. The report is a delivery artifact, not a new source of chain, evidence, policy or recommendation authority.

The document must read like careful technical work: concrete, restrained and traceable to retained evidence. Deterministic code owns coverage, facts, ordering, identifiers, citations, headings and Markdown assembly. One fresh worker per chain supplies bounded explanatory prose and the final severity judgment through strict JSON. The core rejects generic, unsupported or structurally unsafe prose before publication.

## Goals

1. Consume only `firmware_decide.verified_package`; never select decision rows directly or fall back to history.
2. Publish one immutable Markdown report for the latest report preparation of an image.
3. Give every current chain exactly one six-heading section, ordered by Stage 4i rank.
4. State pre-authentication reachability explicitly for every chain.
5. Preserve exact member order, evidence references, open preconditions, decision facts and package identity.
6. Let a fresh worker make only the irreducibly human calls: explanation and final severity.
7. Reject filler, unsupported absolutes, invented runtime claims, internal paths and unbounded prose mechanically.
8. Keep the report source-level. Stage 4h observations may settle facts, but worker prose cannot claim runtime confirmation.
9. Remain standard-library only, offline and compatible with the repository's six-heading report format.
10. Retain historical generations while exposing only the latest prepared current report.

## Non-goals

- Changing findings, chains, dive observations, policy matches, payout projections or the Stage 4i recommendation.
- Assigning CVSS, executing proposed scripts or creating proof-of-concept programs.
- Producing an executive summary, disclosure timeline, methodology appendix, coverage matrix or vendor communication.
- Automatically disclosing, filing or sending the report.
- Replacing the ordinary source-code report workflow.

## Anti-goals

- Free-form Markdown from a global worker.
- Claims that cannot be mapped to exact retained evidence.
- Boilerplate such as "it is important to note", "could potentially" or "robust security posture".
- Unsupported words such as `always`, `never`, `infinite`, `guaranteed` or `fully compromised`.
- A worker choosing chain coverage, changing order, inventing runtime state or rewriting copied facts.
- Internal artifact paths, absolute roots, SQL details, policy prose or worker commentary in final Markdown.

## Constraints inherited from the repository

- `audit_core` is standard-library only and reaches no network.
- SQLite plus immutable canonical artifacts are durable authority.
- Expected diagnostics are escaped, root-redacted and capped; database failures use a fixed diagnostic.
- Artifact installation is descriptor-anchored, no-follow, regular-file-only and mode `0600`.
- Workers write result JSON only. They never write SQL or canonical Markdown.
- The report uses the content contract in `references/phase6-report.md`: title plus Affected Version, Summary, Root Cause, Steps to reproduce and Impact. Firmware sections omit source code blocks because most inputs are binary-only; this is a documented content exception, not a heading change.

## Approaches considered

### A. Deterministic report with structured per-chain prose — selected

The core freezes one assignment per chain. A fresh worker returns structured text and citations. The core validates them and assembles canonical Markdown. This preserves human judgment without granting layout or factual authority.

### B. One global worker writes complete Markdown — rejected

It can reorder or omit chains, mutate facts, invent observations and add boilerplate. Markdown is not a safe machine-validation boundary.

### C. Fully deterministic prose — rejected

The package fixes technical authority but concise root-cause and impact explanations still require expert judgment. Templates alone produce repetitive, low-value prose.

### D. One file per chain — rejected

Stage 4j represents one acquisition decision over one image. A single document keeps that context and avoids inconsistent headers. Each chain remains independently structured.

## Trust and authority

### Sole input boundary

`firmware_decide.verified_package(con, run_dir, root, image_id=...)` is the only Stage 4j input. Stage 4j never queries `cba_firmware_decide_runs` or independently calls Stage 4g/4h helpers.

Stage 4j extends the in-memory return type, not the Stage 4i package bytes, with:

```text
VerifiedFirmwareImageIdentity(
  image_id, vendor, model, version, role, sha256
)
VerifiedFirmwareDecisionPackage(
  ...existing fields,
  technical_input: VerifiedFirmwareDecisionInput,
  image: VerifiedFirmwareImageIdentity
)
```

`verified_package` newly reads the exact `cba_images` row under its existing transaction, validates all six fields with existing image contracts and confirms that `image_id` equals the graph/package owner. `source`, `path`, `size` and `acquired_at` are not returned or rendered. The report generation hashes this projection. Any changed image identity changes the report generation even when Stage 4i package bytes are unchanged.

The technical input supplies the verified graph, findings, chains, edges and dive overlay already reconstructed by Stage 4i. The report never broadens that scope.

### Core authority

The core owns:

- generation, currentness and lifecycle;
- complete chain coverage and ascending `ChainAssessment.rank` order;
- item ordinals, exact `chain_id` display IDs and copied factual fields;
- image identity, pre-authentication statement and source-level label;
- assignment evidence catalogs and safe display citations;
- Markdown headings, escaping, formatting and canonical bytes;
- prose grammar, lint, citation validation and completion;
- artifact installation and the public verified-report boundary.

Every assessment in a nonempty package receives one section, including `deprioritize`. A Stage 4i disposition prioritizes acquisition work; it cannot suppress a technical chain. The empty decision variant yields a zero-item report.

Pre-authentication maps exactly: `yes` to `established`; `no` to `not established`; `unknown` to `not established: blocked by <sorted chain-local precondition IDs>`.

### Worker authority

One fresh strongest-available worker receives one item. It may choose only:

- title detail;
- structured Summary, Root Cause, Steps to reproduce and Impact text;
- final severity: `critical`, `high`, `medium`, `low` or `informational`;
- cited severity justification;
- optional cited fix direction.

Severity is a human technical judgment, not mechanically derived. The core validates its enum, citation coverage and prose but does not pretend to prove semantic correctness from unstructured impact hypotheses. Open chain-local preconditions cause the core to append `Provisional: unresolved preconditions <IDs>.` after the severity line. The worker cannot suppress that label.

The worker cannot return headings, affected-version fields, CVSS, recommendation, payout, pre-auth state, runtime status, ordering, storage paths, scripts or extra sections. It may mention only assignment-owned firmware-relative paths, symbols, states and identifiers.

## Exact data model

All JSON is UTF-8, LF-only, canonical compact JSON with sorted object keys and one final newline. Unknown keys, duplicate keys, invalid UTF-8, lone surrogates, non-finite/coerced numbers and values beyond the stated bounds fail. Arrays preserve the order specified below; set-like arrays are sorted unique.

### Evidence catalog entry

Each assignment entry has exact keys:

```json
{
  "ref": "finding:F-1#root_cause",
  "kind": "finding|edge|observation|precondition",
  "owner_id": "F-1",
  "component_path": "usr/sbin/service",
  "location": "symbol-or-offset-or-null",
  "field": "root_cause",
  "evidence_rung": "rung-2",
  "excerpt": "bounded retained text"
}
```

`ref` must be one exact reference already owned by the chain assessment, member finding, edge, dive overlay or open precondition. `component_path` is a firmware-relative path or null. `location` is a retained symbol/offset/line label or null; the core never infers one. `excerpt` is copied from an upstream verified field, at most 4 KiB, and never written verbatim to Markdown. Catalog entries sort by `ref` and are unique.

The renderer separates internal identity from display citation:

- path plus location: ``component_path:location [ref]``;
- path only: ``component_path [ref]``;
- no safe location: `evidence ref`.

It never renders run-relative `files/` or `artifacts/` paths. Worker runtime verbs are prohibited; the core does not render claims such as "crashed" from the untyped overlay. Stage 4h evidence may support source-level statements only.

### Assignment seed and generation

The core first builds an ordered assignment **seed** per chain with exact keys:

```json
{
  "schema_version": 1,
  "image": {"image_id":"...","vendor":"...","model":"...","version":"...","role":"target","sha256":"..."},
  "decision": {"generation":"...","package_sha256":"...","decision":"...","primary_reason":"..."},
  "ordinal": 1,
  "chain": {"chain_id":"...","rank":1,"title":"...","summary":"...","member_ids":[],"pre_auth":"yes","confidence":0,"completeness":"...","evidence_rung":"...","disposition":"...","rationale":"...","limitations":[]},
  "members": [],
  "edges": [],
  "open_preconditions": [],
  "evidence_catalog": [],
  "style_contract_sha256": "..."
}
```

`members`, `edges` and `open_preconditions` are exact `dataclasses.asdict` projections of verified upstream objects in chain/member/edge order. Storage paths, report generation and expected result path are absent from seeds.

`report_generation = sha256(canonical({schema_version:1, decision_package_sha256, image, style_contract_sha256, assignment_seed_sha256s}))`.

Installed item assignments add exact envelope keys `report_generation`, `assignment_sha256` and `result_path` around the unchanged seed. This removes any hash cycle.

### Manifest

`manifest.json` has exact keys:

```json
{
  "schema_version": 1,
  "image_id": "...",
  "report_generation": "...",
  "decision_generation": "...",
  "decision_package_sha256": "...",
  "style_contract_sha256": "...",
  "item_count": 1,
  "items": [{"ordinal":1,"chain_id":"...","assignment_path":"...","assignment_sha256":"...","result_path":"..."}]
}
```

Items are in ascending rank/ordinal order. Manifest and each assignment are at most 8 MiB. There is no aggregate worker-result cap; each expected result is at most 16 KiB, so total accepted bytes are bounded by the already verified chain count and per-file cap without omitting valid chains.

### Worker result

The envelope has exact keys:

```json
{
  "schema_version": 1,
  "image_id": "...",
  "report_generation": "...",
  "chain_id": "...",
  "assignment_sha256": "...",
  "answer": {
    "title_detail": "...",
    "summary": [{"text":"...","citation_refs":[]}],
    "root_cause": [{"text":"...","citation_refs":[]}],
    "reproduction_steps": [{"text":"...","citation_refs":[]}],
    "impact": [{"text":"...","citation_refs":[]}],
    "severity": "high",
    "severity_justification": {"text":"...","citation_refs":[]},
    "fix_direction": null
  }
}
```

`fix_direction`, when present, is the same `{text,citation_refs}` shape. Citation arrays are sorted unique, nonempty subsets of the assignment catalog. Every paragraph, step, justification and fix direction requires at least one citation.

Bounds: title 12–160 bytes; each text 20–1,200 bytes; Summary 1–2 paragraphs; Root Cause 1–4; reproduction 1–8 steps; Impact 1–2 paragraphs; severity justification 40–400 bytes; fix direction 20–400 bytes; at most 16 citations per entry; canonical result at most 16 KiB.

### Result manifest and report index

At completion the core builds `results.json`:

```json
{"schema_version":1,"report_generation":"...","results":[{"ordinal":1,"chain_id":"...","result_path":"...","result_sha256":"..."}]}
```

The list is ordinal order. `report.json` has exact keys:

```json
{
  "schema_version": 1,
  "image_id": "...",
  "report_generation": "...",
  "decision_generation": "...",
  "decision_package_sha256": "...",
  "report_sha256": "...",
  "sections": [{"ordinal":1,"chain_id":"...","severity":"high","pre_auth":"established","citation_refs":[]}]
}
```

Section citation refs are the sorted union used by that result. The index is at most 8 MiB.

### Public return type

```text
VerifiedFirmwareReport(
  image_id, report_generation, decision_generation,
  decision_package_sha256, report_path, report_sha256,
  report_bytes, index_path, index_sha256, sections
)
VerifiedFirmwareReportSection(
  ordinal, chain_id, severity, pre_auth, citation_refs
)
```

All tuples are immutable and already ordered.

## Professional prose contract

### Structured plain text

Worker text is plain UTF-8, not Markdown. The core escapes `\`, backticks, `<`, `>`, `&`, `*`, `_`, `[`, `]`, `#`, `|` and leading list markers before rendering. Inline code is not worker-controlled. The core wraps assignment-owned identifiers and paths as code spans after escaping. Reproduction is an array rendered as an ordered list. This excludes headings, blockquotes, thematic breaks, HTML, links, images, autolinks, tables, indented/fenced code and unbalanced backticks by construction.

Validation applies NFC normalization, then rejects NUL, CR, controls other than LF, and non-ASCII whitespace. Bounds are UTF-8 byte counts. Paragraphs are separate JSON entries, not parsed from blank lines. Text entries cannot contain LF.

### Versioned style contract

One canonical style-contract object, hashed into every generation, contains schema version; all byte/count bounds; NFC and escaping versions; the banned token/phrase lists; sentence-boundary algorithm; citation rules; renderer version; heading template; pre-auth mapping and severity enum.

Case-insensitive matching uses NFC plus Unicode `casefold()`. Phrase matches require ASCII-alphanumeric token boundaries after punctuation is replaced with spaces. Sentence boundaries are `.`, `?` or `!` followed by whitespace/end, excluding periods inside assignment-owned identifiers copied by the renderer.

Reject:

1. phrases: `it is important to note`, `it should be noted`, `it is worth noting`, `in today's`, `in the ever-evolving`, `robust security posture`, `significant concern`, `serious implications`, `potentially`, `could potentially`, `may potentially`, `this highlights`, `this underscores`, `overall`, `in conclusion`, `in summary`, `delve`, `leverage`, `utilize`, `crucial`, `vital`, `paramount`;
2. absolute tokens: `always`, `never`, `infinite`, `unlimited`, `guaranteed`, `impossible`, `unexploitable`, and phrase `fully compromised`;
3. meta phrases: `as an ai`, `the provided context`, `the prompt`, `the model`, `the worker`, `we recommend`, `best practices`, `industry standard`;
4. runtime tokens: `confirmed`, `observed`, `reproduced`, `crashed`, `executed`, `returned`, `runtime-verified`, `live-verified`;
5. formatting: em dash, emoji code points from the fixed style-contract ranges, repeated `!`/`?`, raw URL schemes, absolute POSIX/Windows paths, `reports/audit-`, `files/firmware-`, `artifacts/firmware-`, or SQL table names;
6. duplicate normalized sentences across any entry;
7. three consecutive sentences beginning with the same first three casefolded tokens;
8. an entry containing none of its cited catalog entries' `owner_id`, safe `component_path`, safe `location`, chain ID, member ID, state or precondition ID. Citation metadata alone does not satisfy this rule.

Diagnostics report item, field and rule code without echoing rejected prose.

## Canonical Markdown

The document header is metadata, not a heading:

```markdown
Firmware assessment report
Image: `<vendor> <model> <version>` (`<sha256>`)
Decision: `<decision>` (`<primary_reason>`)
Assessment basis: source-level; not runtime-verified.
```

Each nonempty chain repeats exactly one H1 and five H2 headings:

```markdown
# <chain_id>: <escaped title detail>

## Affected Version
...

## Summary
...

## Root Cause
...

## Steps to reproduce
Source-level verification guide; no runtime execution is claimed.
1. ...

## Impact
...
Pre-authentication path: <fixed mapping>.
Severity: HIGH. <cited justification>
[optional provisional sentence]
```

The sole order is ascending Stage 4i rank. Assignment ordinal, manifest order, item rows, result manifest, Markdown sections and report index all use that order. No global H1, CVSS table or extra section exists. A zero-chain report contains only metadata plus `No technical chain is present in the current completed decision package.`

## Durable model

Stage 4j adds two tables.

### `cba_firmware_report_runs`

Primary key `(image_id, report_generation)`. Exact columns:

```text
image_id, report_generation, preparation_ordinal, status,
decision_generation, decision_package_sha256, style_contract_sha256,
manifest_path, manifest_sha256, item_count,
results_path, results_sha256, result_count,
report_path, report_sha256, report_bytes,
index_path, index_sha256,
prepared_at, recorded_at, completed_at, superseded_at
```

Statuses: `pending`, `recorded`, `complete`, `superseded`. Pending requires zero results and null result/report/index/completion fields. Recorded requires every item result, result manifest and `recorded_at`, with report/index/completion null. Complete requires all fields except `superseded_at`. Superseded retains the pending or recorded variant and adds only `superseded_at`. Timestamp order is prepared <= recorded <= completed/superseded as applicable. `preparation_ordinal >= 1`; the maximum per image is current and ties are refused.

### `cba_firmware_report_items`

Primary key `(image_id, report_generation, chain_id)` and unique `(image_id, report_generation, ordinal)`. Exact columns:

```text
image_id, report_generation, chain_id, ordinal,
assignment_path, assignment_sha256, result_path, result_sha256, recorded_at
```

Prepared items require null `result_sha256` and `recorded_at`; recorded items require both. `result_path` is the expected run-relative destination and is nonnull from prepare. Code validates run ownership under the same transaction; repository convention does not require a SQL foreign key.

Two migrations add the tables. Existing databases contain no report rows, so no data migration is needed.

## Immutable artifacts

Preparation installs:

- `files/firmware-report/<generation>/manifest.json`;
- `files/firmware-report/<generation>/items/<ordinal>-<chain-id>.json`.

Recording installs:

- `artifacts/firmware-report-results/<generation>/<chain-id>/<result-sha256>/result.json`.

Completion installs:

- `artifacts/firmware-report/<generation>/<report-sha256>/results.json`;
- `artifacts/firmware-report/<generation>/<report-sha256>/report.md`;
- `artifacts/firmware-report/<generation>/<report-sha256>/report.json`.

Existing differing bytes are an error; matching bytes are verified. All files are regular mode `0600`.

## Lifecycle

### Prepare

`firmware_report.prepare(con, run_dir, root, *, image_id=None)` performs an optimistic read through `verified_package`, builds seeds/generation/files, installs immutable assignments, then takes `BEGIN IMMEDIATE` and calls the same sole boundary again. Under the lock it repeats identities and bytes, supersedes stale pending/recorded runs, assigns `max(preparation_ordinal)+1`, and atomically publishes the run/items. An identical prepare re-ranks the generation. Same-input conflicting active bytes are refused. Superseded runs are terminal.

A zero-item prepare publishes a `recorded` run, zero item rows and canonical empty `results.json` in the same transaction.

### Record

`firmware_report_results.record(con, run_dir, result_path)` uses the repository's bounded regular-file/no-follow/nonblocking reader, parses exact hostile JSON, validates assignment identity, citations, structured prose and style, installs canonical result bytes, then repeats checks under `BEGIN IMMEDIATE`. It fills one item result atomically. The run remains pending until every item is recorded, then installs/verifies `results.json` and transitions to recorded. Identical retry is idempotent; conflicting bytes fail.

### Check

A pure `_verify_complete_inputs` helper selects the unique highest preparation ordinal, reconstructs the current package, assignments and recorded results, reruns lint/citations, builds Markdown/index bytes and verifies any existing complete artifacts without writing.

For a recorded run, `check` calls the pure helper, installs immutable report/index files, takes `BEGIN IMMEDIATE`, repeats pure reconstruction and byte checks, and atomically marks complete. For a complete run it invokes only the pure verifier; missing or differing files fail and nothing is installed or repaired.

### Verified current report

`verified_report` opens/reuses a read transaction, invokes only the pure complete verifier and returns `VerifiedFirmwareReport`. It never writes, repairs or falls back to history.

## CLI and worker routing

The ordinary report is a skill workflow, not an `audit.py` verb. Firmware gets a dedicated verb:

```text
python3 audit.py firmware-report --run RUN --root ROOT --prepare [--image-id ID]
python3 audit.py firmware-report --run RUN --record RESULT
python3 audit.py firmware-report --run RUN --root ROOT --check [--image-id ID]
```

Exactly one mode is required. Prepare prints bounded scalar fields: generation, manifest path, item count and state. Consumers read item paths from the bounded manifest; the CLI never prints N paths. JSON and human outputs contain no prose or evidence bodies.

The orchestrator dispatches one fresh strongest-available writer per manifest item. Each reads one assignment and writes one expected result. The exact return line is:

`firmware-report <DONE|FAILED> chain=<id> artifact=<path> [flags=<csv>]`

`references/briefs/firmware-report-brief.md` carries the exact schema and prose contract. Installed `SKILL.md` routing is prepare, fresh writers, record each DONE result, then check. FAILED is never recorded. No script is executed.

## Currentness and error behavior

A report is current only when its exact Stage 4i package remains current and its run has the highest preparation ordinal. Earlier stages do not delete report history. The next prepare supersedes stale active reports. Completed history remains immutable but is never returned.

Expected SQLite errors print exactly `firmware-report: database operation failed`. Other expected diagnostics are escaped, root-redacted and capped at 512 ASCII characters plus newline. Unexpected programming exceptions propagate after rollback. Rejected prose and private paths are never echoed.

## Performance and implementation-plan optimization

- Separate schema/package-extension, assignments, parser/lint, lifecycle/renderer and CLI tasks.
- Test deterministic helpers directly before end-to-end lifecycle tests.
- Use two-chain fixtures for ordering, citation isolation and repetition.
- Add focused coverage while modules are small; zero unexecuted statements remain required.
- Review trust boundaries after parser/renderer completion, then once at branch end.
- Run final `make all` after documentation reconciliation; mutation remains separate.

Rendering is linear in verified input bytes. Per-file caps avoid a false aggregate limit; complete chain coverage is never truncated.

## Testing strategy

Permanent tests cover:

1. package extension and sole-boundary enforcement;
2. generation seed without hash cycles and exact manifest schemas;
3. complete rank ordering, item ordinals and zero-chain behavior;
4. exact hostile result JSON and every field/count/byte boundary;
5. structured per-entry citations and foreign/unresolved-reference refusal;
6. every style-contract rule, boundary and escaping case;
7. source-level wording and fixed pre-auth mapping;
8. severity enum, cited justification and provisional labeling;
9. exact repeated six headings, no global H1, CVSS or extra section;
10. symlink/FIFO/huge-number input refusal;
11. partial item recording, final transition, idempotency and conflicts;
12. rollback, publication races and sibling-image isolation;
13. stale supersede, latest-preparation selection and no fallback;
14. complete read-only recheck and missing-file refusal;
15. CLI flag matrix, bounded output and fixed diagnostics;
16. authority-boundary tests for report tables and `verified_package`;
17. deliberate faults removing each lint, citation, ordering and currentness check;
18. full compatibility through `make all`.

## Documentation

Completion updates `ARCHITECTURE.md`, `progress.md`, `SESSION_HANDOFF.md`, `feature_lists.json`, `README.md`, `SKILL.md`, the worker brief and installed routing. Historical specifications and baselines remain intact.

## Acceptance criteria

1. Preparation uses only a current `firmware_decide.verified_package` with exact technical input and image identity.
2. Generation identity is acyclic and binds image, package, style contract and ordered assignment seeds.
3. Every chain appears exactly once in ascending Stage 4i rank; empty input yields an honest zero-item report.
4. Workers receive one chain each and cannot alter facts, ordering, pre-auth status, runtime status or layout.
5. Every prose entry and severity justification cites assignment-owned evidence.
6. The canonical style contract deterministically rejects every listed filler, absolute, meta, runtime, formatting, repetition and vagueness rule.
7. Each chain has exactly one H1 and the five H2 headings; there is no global H1, CVSS table or extra section.
8. Reports are explicitly source-level; the core never promotes untyped evidence into a runtime claim.
9. Pre-authentication status is exact and mechanical; severity is explicit, cited worker judgment.
10. Prepare, per-item record, check and verified-report are atomic, immutable, image-isolated and latest-preparation current.
11. Stale active runs supersede without deleting history; reads never fall back.
12. Complete rechecks and `verified_report` are pure and never repair.
13. CLI output and errors are bounded and private-path safe.
14. Focused tests cover every branch and catch deliberate faults.
15. Independent review finds no Critical or Important issue.
16. Final reconciled tree passes `make all`; mutation remains opt-in.

## Amendment 2026-11-09: result manifest and completion directory

The "Immutable artifacts" list above contradicts the "Record" lifecycle section about
`results.json`. The lifecycle section governs, and the implementation follows it:

- `results.json` is installed at record time, content-addressed at
  `artifacts/firmware-report-results/<generation>/<results-sha256>/results.json`. A
  zero-chain preparation installs it with an empty `results` array in the same
  transaction that publishes the recorded run.
- Each recorded worker result stays at
  `artifacts/firmware-report-results/<generation>/<chain-id>/<result-sha256>/result.json`.
- The completion directory `artifacts/firmware-report/<generation>/<report-sha256>/`
  contains exactly `report.md` and `report.json`.

Additionally, `VerifiedFirmwareReportSection.pre_auth` and the `pre_auth` field of each
`report.json` section carry the mapped pre-authentication statement from
`pre_auth_mapping` (for example `established`), not the raw chain enum.

Every displayed value the core copies from upstream authority (image identity, catalog
component paths and locations, identifiers) is refused when it carries a control
character (`ord < 0x20`, `0x7F`, or Unicode category `Cc`/`Cf`); such a value is never
degraded or escaped into the document.
