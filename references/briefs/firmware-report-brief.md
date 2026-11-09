# Firmware report chain section

Audit run directory: {run_dir}
Target image ID: {image_id}
Report generation: {report_generation}
Immutable assignment: {assignment_path}
Required result file: {result_path}

## Assignment and authority

You are one fresh strongest-available worker assigned exactly one chain of the
firmware report. Read only that immutable assignment and its frozen references.
Read the assignment incrementally from that exact path; never partition it,
never cap its evidence catalog, and never read another chain's assignment. Read
the result parser and dataclasses in
`__SKILL_DIR__/audit_core/firmware_report_results.py`; that installed copy is
authoritative, and the schema below restates it.

The assignment envelope has exactly `report_generation`, `assignment_sha256`,
`result_path` and `seed`. Bind `report_generation` and `assignment_sha256`
into your result exactly; `result_path` is where you write, and `seed` is the
frozen assignment content you reason from. If the assignment bytes, image,
chain or generation differ from the values above, return FAILED; do not repair
the assignment or switch to another generation. A newer preparation can
supersede this one; the orchestrator then prepares and dispatches again.

Your assignment carries the frozen chain, its members, its edges, its open
preconditions and its evidence catalog. Every statement you write must rest on
that assignment. The report is explicitly source-level: describe what the code
shows, never what a run showed. State uncertainty explicitly; never turn
missing evidence into a positive conclusion.

## Result artifact

Write one result-only strict JSON regular UTF-8 file to `{result_path}`, at
most 16 KiB, using exactly schema version 1 and its keys.
Reject duplicate keys, extra keys, non-finite numbers, malformed identities
and foreign citations. Keep analysis in the artifact, never stdout.

The top level has exactly these keys:

- `schema_version`: the integer `1`.
- `image_id`: the target image ID above.
- `report_generation`: the report generation above, as lowercase SHA-256 hex.
- `chain_id`: the assigned chain's frozen ID.
- `assignment_sha256`: the envelope `assignment_sha256` above.
- `answer`: an object with exactly `title_detail`, `summary`, `root_cause`,
  `reproduction_steps`, `impact`, `severity`, `severity_justification` and
  `fix_direction`.

Every text value is plain NFC text: no control characters, no zero-width or
format characters, and no whitespace other than the ASCII space.

## Answer fields

`summary`, `root_cause`, `reproduction_steps` and `impact` are arrays of
entries. Each entry is an object with exactly `text` and `citation_refs`.

- `title_detail`: 12 to 160 UTF-8 bytes of text. The renderer owns the heading
  around it; write the specific defect, not a heading.
- `summary`: 1 to 2 entries. `root_cause`: 1 to 4 entries.
  `reproduction_steps`: 1 to 8 entries, in execution order.
  `impact`: 1 to 2 entries.
- Each entry `text` is 20 to 1200 UTF-8 bytes.
- `severity`: exactly one of `critical`, `high`, `medium`, `low` or
  `informational`. It is your explicit judgment, not a copied field.
- `severity_justification`: one entry whose `text` is 40 to 400 UTF-8 bytes.
- `fix_direction`: `null`, or one entry whose `text` is 20 to 400 UTF-8 bytes.

`citation_refs` holds 1 to 16 references, sorted ascending, unique, and each
one copied exactly from the assignment evidence catalog. An entry that cites a
reference outside that catalog is rejected whole. Each entry's prose must name
something its own citations own: the chain ID, one of its member IDs, one of
its edge states, one of its open precondition IDs or their source IDs, or the
catalog owner, component path or location of a reference that entry cites.
Naming another entry's subject does not support this one.

## Prose contract

Deterministic code rejects the whole result on any of these, naming the item,
the field and the rule, never your text:

- filler phrases, including hedging and summarizing openers;
- absolute claims such as always, never, unlimited, guaranteed or impossible;
- meta phrases about the model, the prompt, the context or industry practice;
- runtime terms such as confirmed, observed, reproduced, crashed or executed;
  the assessment is source-level and claims no execution;
- the em dash, repeated `!!` or `??`, emoji, and any raw url;
- any absolute path, Windows drive path, internal `files/`, `artifacts/` or
  `reports/` path, or `cba_` table name;
- one duplicate sentence anywhere in the answer, or four sentences in a row
  that share the same three-token prefix.

Write plain declarative prose. Prefer one concrete mechanism over three vague
sentences.

## Limits of authority

Do not write SQL or open the database. Deterministic code owns chain selection,
section ordering, the pre-authentication statement, provisional labeling,
headings and layout, the affected-version line, citation rendering, the result
manifest, publication and every completion gate. Do not install an artifact,
publish completion, change the chain's facts, rank or pre-authentication
state, construct an exploit, or write any file other than `{result_path}`.
Do not execute probes, scripts, commands or captures, and never claim any ran.

DONE requires one complete parser-valid result for your one chain. FAILED means
the frozen assignment cannot be read or a valid result cannot be produced.
There is no partial state: one chain is one result, and a rejected result is
rewritten against the same immutable assignment.

## Return contract

Return exactly one line and nothing else:

    firmware-report <DONE|FAILED> chain=<id> artifact=<path> [flags=<csv>]

Replace `<id>` with the assigned chain ID and `<path>` with `{result_path}`.
