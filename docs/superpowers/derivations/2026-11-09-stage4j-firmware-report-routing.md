# Stage 4j firmware report: CLI, worker brief and installed routing

Written before any shipped-prose edit, per the repository rule for `SKILL.md`
and `references/briefs/*`. The reconciliation against `git diff -U0` is at the
end of this file.

## 1. CLI surface (binding spec section "CLI and worker routing")

```text
python3 audit.py firmware-report --run RUN --root ROOT --prepare [--image-id ID]
python3 audit.py firmware-report --run RUN --record RESULT
python3 audit.py firmware-report --run RUN --root ROOT --check [--image-id ID]
```

- `--run` is required. The three modes form one required mutually exclusive
  group, so zero or two modes is an argparse error (exit 2) before any database
  access.
- Semantic errors print one line to stderr and exit 1 before the database is
  opened: `--root` is required for prepare and check; `--root` and `--image-id`
  are not valid with `--record`.
- Delegation is exact: `firmware_report.prepare(con, run_dir, root,
  image_id=...)`, `firmware_report_results.record(con, run_dir, result_path)`,
  `firmware_report.check(con, run_dir, root, image_id=...)`.
- Expected errors are `FirmwareReportError`, `FirmwareReportResultError`,
  `db.DbError`, `OSError` and `sqlite3.Error`. Both module error types are
  caught because prepare/check and record raise different classes.
- Every expected SQLite failure prints exactly
  `firmware-report: database operation failed`. Other expected diagnostics go
  through the Stage 4i escaping/redaction helper (`_bounded_cli_text`): the root
  is redacted, output is ASCII and capped at 512 characters plus newline.
  Unexpected exceptions propagate after rollback and close.
- Output is bounded scalars only. Prepare prints the report generation, the
  manifest path, the item count and the state; it never prints N item paths or
  any prose. Record prints the recorded result path; check prints the report
  path. `--json` prints the summary dataclass fields, which are all scalars.

## 2. Worker brief (`references/briefs/firmware-report-brief.md`)

Five placeholders, matching the per-item dispatch: `run_dir`, `image_id`,
`report_generation`, `assignment_path`, `result_path`.

Schema restated from `audit_core/firmware_report_results.py` (installed copy is
authoritative):

- Envelope keys the assignment carries: `report_generation`,
  `assignment_sha256`, `result_path`, `seed`.
- Result keys: `schema_version` (integer 1), `image_id`, `report_generation`,
  `chain_id`, `assignment_sha256`, `answer`.
- Answer keys: `title_detail`, `summary`, `root_cause`, `reproduction_steps`,
  `impact`, `severity`, `severity_justification`, `fix_direction`.
- Each entry is `{"text", "citation_refs"}`; citations are sorted, unique,
  1-16 per entry, and every ref must exist in the assignment evidence catalog.
- Bounds copied from the style contract: text 20-1200 bytes, title 12-160,
  severity justification 40-400, fix direction 20-400 or `null`, summary 1-2
  paragraphs, root cause 1-4, reproduction steps 1-8, impact 1-2, result file
  at most 16 KiB.
- Severity enum: critical, high, medium, low, informational.
- Prose rules named as rules, not as a retyped literal list: banned filler
  phrases, absolute claims, meta phrases, runtime terms, em dash, repeated
  punctuation, raw URLs, internal `files/`, `artifacts/` and `reports/` paths,
  `cba_` table names, emoji, absolute POSIX and Windows paths, duplicate
  sentences, more than three consecutive same-prefix sentences, and entries
  that name nothing their own citations own.
- The brief must state: one fresh strongest-available worker per item; read the
  one assignment incrementally from its exact path; never partition or cap it;
  no inline worklist or evidence in the dispatch; source-level only; no SQL, no
  completion, no ordering, no pre-auth, no layout, no script execution.
- Return contract, exactly:
  `firmware-report <DONE|FAILED> chain=<id> artifact=<path> [flags=<csv>]`
  (no PARTIAL: one item is one result).

## 3. Installed routing (`SKILL.md`, new `### Stage 4j firmware report`)

Order: prepare -> one fresh writer per manifest item -> record each DONE result
-> check. FAILED is never recorded. No script is executed. The section is placed
after Stage 4i and before "Cross-client tool mapping", and carries:

1. the prepare command with `--json`;
2. reading item paths from the returned bounded manifest, never from CLI output;
3. the `brief --phase firmware-report --unit <chain-id>` render with the five
   variables;
4. the exact return line;
5. the record and check commands;
6. the authority denial sentence and the supersede/latest-preparation note;
7. the refusal that a `complete` generation accepts no further `--record`.

`SKILL.md` is CRLF; every inserted line keeps CRLF endings.

## 4. Test modifications

- `tests/test_brief_templates.py`: the template-set assertion grows from eleven
  to twelve names, and the per-template return-contract map gains
  `firmware-report-brief.md` -> `chain=<id> artifact=`.
- `tests/test_cli.py`: the selftest dispatch count moves from 31 to 32 declared
  verbs.

## 5. Reconciliation against `git diff -U0`

Checked after the edits landed; the shipped prose diff contains exactly:

- `references/briefs/firmware-report-brief.md`: new file, the brief described in
  section 2 (five placeholders, result schema, bounds, severity enum, prose
  rules, authority denials, return contract).
- `SKILL.md`: one added `### Stage 4j firmware report` section as described in
  section 3, inserted before `### Cross-client tool mapping`, CRLF preserved
  (`git diff --stat` shows no other `SKILL.md` hunk, and no line endings
  changed).

No other shipped-prose file changed. One non-prose consequence of the new
return line: `audit_core/skill_lint.py` gains `REPORT_RETURN_CONTRACT` and its
brief-table entry, because `audit.py lint-skill` otherwise reports the new
template as missing the R2 contract.

## 6. Review fix round 1: intended shipped-prose changes

Written before the edits, as the rule requires.

1. `references/briefs/firmware-report-brief.md`, the envelope paragraph: the
   sentence "Copy all four identity values into your result exactly"
   contradicts the brief's own result key set and `_RESULT_KEYS`, where
   `result_path` and `seed` are not result keys and `_object` refuses any
   key-set difference. Replace it with: bind `report_generation` and
   `assignment_sha256` into the result exactly; `result_path` is where the
   worker writes; `seed` is the frozen assignment content it reasons from. All
   four names stay in backticks.
2. `references/briefs/firmware-report-brief.md`, the entry-anchor list: add the
   open precondition `source_id` anchor, which
   `firmware_report_results._seed_anchors` also admits.
3. `SKILL.md`, Stage 4j: one added sentence after the manifest-item sentence —
   set `ASSIGNMENT_PATH` and `RESULT_PATH` to `${AUDIT_DIR}/` plus the item's
   run-relative `assignment_path` and `result_path`, matching how Stage 4i
   states the join for its worklist. CRLF preserved.

Reconciled against `git diff -U0` after the edits: the shipped-prose diff
contains exactly one `SKILL.md` hunk (the added sentence) and two
`firmware-report-brief.md` hunks (the envelope paragraph and the anchor list),
with no other prose file touched and no line endings changed.
