# Stage 2 prose derivation — hand-typed SQL replaced by `audit.py` verbs

**Why this file exists.** Stage 1 closed with finding #1: *rewriting shipped
prose from scratch lost instructions five times out of five* — 18 Hard
Exclusion rules, 6 of 16 vulnerability hunt categories, 2 of 9 false-positive
method steps, a patch-bypass probe instruction, and the live-PoC conduct
prohibitions. Five separate reviews each caught a different subset and **none
caught all of them**. Absence is the hardest thing to review for: a reviewer
sees what is there. The finding's implication was binding:

> any later stage that rewrites shipped prose must produce an explicit
> derivation — the old instruction set diffed against the new, with a
> justification for every dropped line — as a reviewable artifact, rather than
> relying on a reviewer to notice an absence.

This is that artifact. It was written **before** the edits, as the plan for
them, not afterwards as a report about them. The rule it enforces is
**replacement, never rewriting**: each row below swaps one hand-typed SQL
block for the verb invocation that produces the same rows, and the surrounding
instructions — what to do with the result, when, and why — are not touched,
not reworded, not tightened.

The reviewer's first job is to check this table against `git diff`, not the
diff against their memory. A hunk with no row here is a change made without a
justification.

Line numbers are against `d2b4173` (the pre-edit tree).

---

## Evidence that the verbs return the retired queries' rows

Run against a fixture database (2 groups, 4 findings, 3 verdicts), before the
prose was edited. This is the comparison Step 4b asks for.

The four retired **read** queries, executed directly:

```
fpcheck Step 5 five-subquery SELECT
  {'findings': 4, 'verdicts': 3, 'tp': 1, 'fp': 1, 'dup': 1}
SELECT id,name,status FROM cba_feature_groups
  -> [('G1', 'auth', 'audited'), ('G2', 'api', 'mapped')]
SELECT group_id,severity,COUNT(*) FROM cba_findings GROUP BY 1,2 ORDER BY 1,2
  -> [('G1', 'HIGH', 2), ('G1', 'MEDIUM', 1), ('G2', 'CRITICAL', 1)]
SELECT verdict,COUNT(*) FROM cba_fp_verdicts GROUP BY verdict
  -> [('DUPLICATE', 1), ('FALSE_POSITIVE', 1), ('TRUE_POSITIVE', 1)]
SELECT finding_id, final_severity FROM cba_fp_verdicts WHERE verdict = 'TRUE_POSITIVE'
  -> [('G1-F1', 'HIGH')]
```

`python3 audit.py status --db <db>`:

```
groups 2   findings 4   verdicts 3   unverdicted 1
  groups:
    G1     auth                           audited
    G2     api                            mapped
  findings by group and severity:
    G1     HIGH           2
    G1     MEDIUM         1
    G2     CRITICAL       1
  verdicts:
    DUPLICATE            1
    FALSE_POSITIVE       1
    TRUE_POSITIVE        1
```

`python3 audit.py rows --db <db> --table cba_fp_verdicts --where verdict=TRUE_POSITIVE --columns finding_id,final_severity`:

```
(1 row(s), capped at 200)
G1-F1	HIGH
```

Row-for-row: the `groups:` block is query 2, the `findings by group and
severity:` block is query 3, the `verdicts:` block is query 4 **and** the
`tp`/`fp`/`dup` columns of query 1, and the header line's `findings`,
`verdicts` and `unverdicted` are query 1's `findings`, `verdicts` and their
difference. `rows` is query 5. Nothing in any retired read query is
unavailable from the verbs.

All five documented `put` invocations below were executed against the same
fixture database before being written into the prose; each returned
`<table>: 1 row` and exit 0. The five verbs' flag spellings were checked
against `python3 audit.py <verb> --help`.

---

## Table A — the read-side blocks

| File:line | Old text (verbatim) | New text (verbatim) | What the new form does that the old did — and anything the old stated that the new does not, with why |
|---|---|---|---|
| `references/resume-note-template.md:33-38` | `## SQL re-orient queries (paste-and-run)` then a `bash` fence containing `sqlite3 reports/audit-<ts>/audit.db "SELECT id,name,status FROM cba_feature_groups;"`, `sqlite3 reports/audit-<ts>/audit.db "SELECT group_id,severity,COUNT(*) FROM cba_findings GROUP BY 1,2 ORDER BY 1,2;"`, `sqlite3 reports/audit-<ts>/audit.db "SELECT verdict,COUNT(*) FROM cba_fp_verdicts GROUP BY verdict;"` | `## Re-orient after a restart (paste-and-run)` then a `bash` fence containing `python3 __SKILL_DIR__/audit.py status --db reports/audit-<ts>/audit.db` and `python3 __SKILL_DIR__/audit.py coverage --db reports/audit-<ts>/audit.db` | `status` prints all three replaced queries' results in one call (evidence above): groups with id/name/status, findings by group × severity, and verdicts by verdict. `coverage` is **additive** — it is the reason a restart can tell whether anything was *skipped*, which the three SELECTs could not say. **Dropped:** the word "SQL" from the heading, because the commands are no longer SQL. The rename is cosmetic; the heading's promise ("paste-and-run") and its position in the template are unchanged, and no instruction sat in the heading. Nothing else dropped. |
| `workflows/fpcheck.md:77-84` | A `sql` fence containing `SELECT` / `(SELECT COUNT(*) FROM cba_findings) AS findings,` / `(SELECT COUNT(*) FROM cba_fp_verdicts) AS verdicts,` / `(SELECT COUNT(*) FROM cba_fp_verdicts WHERE verdict='TRUE_POSITIVE') AS tp,` / `(SELECT COUNT(*) FROM cba_fp_verdicts WHERE verdict='FALSE_POSITIVE') AS fp,` / `(SELECT COUNT(*) FROM cba_fp_verdicts WHERE verdict='DUPLICATE') AS dup;` | A `bash` fence containing `python3 __SKILL_DIR__/audit.py status --db ${AUDIT_DIR}/audit.db`, followed by the new sentence "`status` prints `unverdicted`, which is that difference." | `status`'s header line carries `findings`, `verdicts` and `unverdicted`; its verdict table carries the TRUE_POSITIVE / FALSE_POSITIVE / DUPLICATE counts the `tp`/`fp`/`dup` aliases produced (evidence above). **Not touched:** the sentence after the block — "If `findings != verdicts`, identify the missing batch and re-spawn just that one." — and its "(Common cause: agent stalled — see lessons-learned.md)" parenthetical, both verbatim. The one added sentence names where the number now comes from; it adds, it does not replace. **Dropped:** the five SQL aliases as literal text; each is reproduced by `status`, named. |
| `workflows/audit.md:144-146` | A `sql` fence containing `SELECT group_id, severity, COUNT(*) FROM cba_findings GROUP BY 1,2 ORDER BY 1,2;` | A `bash` fence containing `python3 __SKILL_DIR__/audit.py status --db ${AUDIT_DIR}/audit.db` | `status`'s "findings by group and severity" block is exactly this query's rows (evidence above). **Not touched:** the heading "## Step 7 — Summary + resume note rewrite", the lead-in "Present a finding-count table by group × severity:", and every one of the five resume-note bullets that follow — phase status, Phase-4 finding counts table, **Top patch-bypass discoveries**, Live-PoC status, Updated "Quirks to remember". Nothing dropped. |
| `workflows/report.md:66-68` | A `sql` fence inside Mode B step 1 containing `SELECT finding_id, final_severity FROM cba_fp_verdicts WHERE verdict = 'TRUE_POSITIVE';` | A `bash` fence containing `python3 __SKILL_DIR__/audit.py rows --db ${AUDIT_DIR}/audit.db \` / `  --table cba_fp_verdicts --where verdict=TRUE_POSITIVE \` / `  --columns finding_id,final_severity` | Same table, same filter, same two columns (evidence above); `rows` additionally caps the result at 200 rows, which is R1's bound on what the orchestrator may hold. **Not touched:** step 1's lead-in "Pull the TPs:" and its trailing "Read each finding's detail from `artifacts/G<n>-findings.md` + `cba_findings`."; Mode B steps 2, 3 and 4 in full, including "**Steps to reproduce is a reproduction GUIDE only**", "do NOT run a PoC and do NOT paste captured output", and the "NOT live-verified" statement. Nothing dropped. |
| `references/workflow-orchestration.md:95` | Inside a JavaScript agent-prompt template literal: `` const tps = await agent(`${ref} SELECT finding_id FROM cba_fp_verdicts WHERE verdict='TRUE_POSITIVE' in ${AUDIT}/audit.db. Return the ids.`, { phase:'Verify', schema: IDS }) `` | `` const tps = await agent(`${ref} Run: python3 ${SK}/audit.py rows --db ${AUDIT}/audit.db --table cba_fp_verdicts --where verdict=TRUE_POSITIVE --columns finding_id. Return the ids.`, { phase:'Verify', schema: IDS }) `` | Covered by Ruling 1, not by the brief's own list: the brief's guard test normalizes whitespace away before matching, so `verdict='TRUE_POSITIVE'` here matches the retired shape `FROM cba_fp_verdicts WHERE verdict = 'TRUE_POSITIVE'` and the task would otherwise fail its own test. Same table, same filter, same column, same returned ids. `${SK}` is already bound in this script to the skill directory (used on the lines above and below), so the template literal stays valid JavaScript and the agent prompt's meaning is identical. **Not touched:** the `{ phase:'Verify', schema: IDS }` options, the `phase('Verify')` and "STRICTLY SERIAL — one finding at a time" comments above, and the `for (const id of tps.ids)` loop with its "plain for-await => concurrency 1; do NOT wrap in parallel()" comment below. Nothing dropped. |

## Table B — the write-side blocks

| File:line | Old text (verbatim) | New text (verbatim) | What the new form does that the old did — and anything the old stated that the new does not, with why |
|---|---|---|---|
| `references/phase4-deep-audit.md:67-73` | `3. **Insert into SQL**:` then a `sql` fence containing `INSERT INTO cba_findings (id, group_id, title, severity, confidence,` / `    location, root_cause, impact, verified, boundary_crossed,` / `    attacker_position, cwe)` / `VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);` | `3. **Insert into SQL**:` then a `bash` fence containing the 10-line `python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_findings` invocation with `--set` for `id`, `group_id`, `title`, `severity`, `confidence`, `location`, `root_cause`, `impact`, `attacker_position`, `boundary_crossed`, `cwe`, `artifact_path` | Every column the old block named is still named, with a placeholder value, so a subagent copying it cannot produce a row the contract rejects — the old `VALUES (?, ?, …)` form showed no value at all. **Added:** `artifact_path`, which `cba_findings` has carried since Stage 1 and which SKILL.md's table already documents. **Dropped:** `verified`. Justification: the schema declares `verified TEXT DEFAULT 'source-only'`, so an omitted `verified` is correct for every source-mode row; and the instruction that sets it non-default is not in this block at all — it is `workflows/audit.md:116`, "mark `verified='live-poc'` if reproduced, otherwise `verified='source-only'`", which is untouched. The instruction survives; only its duplicate mention in a column list is gone. |
| `references/phase4-deep-audit.md:74` | `4. **Dedup quick-check**: If two findings from different groups describe the same vulnerability at the same code location, keep the one with higher confidence and note the duplicate.` | The same sentence verbatim, followed by a `bash` fence containing `python3 __SKILL_DIR__/audit.py dedup --db ${AUDIT_DIR}/audit.db` and the sentence "These are proposals. Keep the one with higher confidence and record the other as `verdict=DUPLICATE` with `merged_into` set." | Pure addition: the original sentence is byte-identical, and "keep the one with higher confidence" survives verbatim (a guard test asserts it). The command performs by machine what the sentence asked the orchestrator to do by eye — across 45 findings that is 990 pairwise comparisons. The added sentence states that `dedup` proposes and never merges or deletes, so the orchestrator still owns the verdict. Nothing dropped. |
| `references/phase5-fp-check.md:86-89` | `### 2. Insert into SQL` then a `sql` fence containing `INSERT INTO cba_fp_verdicts (finding_id, verdict, reason, final_severity, final_id, merged_into)` / `VALUES (?, ?, ?, ?, ?, ?);` | `### 2. Insert into SQL` then a `bash` fence containing the 4-line `python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_fp_verdicts` invocation with `--set` for `finding_id`, `verdict`, `reason`, `final_severity`, `final_id`, `rule_applied` | Every required column is shown with a placeholder value. **Added:** `rule_applied`, so the verdict records which Hard Exclusion / Precedent / Capability-Validity rule was applied — the rules this file spends 60 lines defining. **Dropped:** `merged_into`. Justification: it is nullable, it applies only to DUPLICATE verdicts, and the instruction that sets it is four lines below in this same file — "### 4. Deduplication … Set `merged_into` to the primary's final ID" — which is untouched. The instruction survives; only its mention in a column list is gone. **Not touched:** sections 1, 3, 4 and 5 of Verdict Processing, and the Quality Gates below them. |
| `references/phase5-fp-check.md:20-23` | A bare fence containing `total_findings = SELECT COUNT(*) FROM cba_findings` / `batch_count = CEILING(total_findings / 10)` | A bare fence containing ``total_findings = the `findings` count from `audit.py status` `` / `batch_count    = CEILING(total_findings / 10)` | The same arithmetic, with the input named as a verb output rather than as pseudo-SQL that was never runnable as written. **Not touched:** the three Batch Formation Rules above it — group affinity, "**Severity mixing**: Mix severities within batches (don't put all CRITICALs in one batch — spread them for independent verification)", and "**No cross-dependencies**: If Finding A's truth value depends on Finding B, put them in the same batch" — nor the Batch Size targets above those. Nothing dropped. |
| `references/phase2-feature-mapping.md:104-108` | `2. **SQL attack surface**:` then a `sql` fence containing `INSERT INTO cba_attack_surface (group_id, endpoint, method, auth_required, description)` / `VALUES (?, ?, ?, ?, ?);` | `2. **SQL attack surface**:` then a `bash` fence containing the 4-line `python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_attack_surface` invocation with `--set` for `group_id`, `endpoint`, `method`, `auth_required`, `description` | Identical column set, now each with a placeholder that says what belongs there (`'<route or entry point>'`, `'<yes\|no\|partial>'`). **Not touched:** item 1 of the same list, "**Session files**: Save each group's full output to `files/{group_id}-mapping.md`". Nothing dropped. |
| `references/phase2-feature-mapping.md:109-113` | `3. **SQL observations**:` then a `sql` fence containing `INSERT INTO cba_security_observations (group_id, observation, severity_hint, location)` / `VALUES (?, ?, ?, ?);` | `3. **SQL observations**:` then a `bash` fence containing the 3-line `python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_security_observations` invocation with `--set` for `group_id`, `observation`, `severity_hint`, `location` | Identical column set with placeholders. **Not touched:** the five Quality Checks below, including "At least 1 security observation exists per group (if zero, the mapping was too shallow)". Nothing dropped. |
| `workflows/audit.md:36-39` | `For each advisory, record:` then a `sql` fence containing `INSERT INTO cba_known_findings(id, title, location, source, patched_in, severity, raw)` / `VALUES (?,?,?,?,?,?,?);` | `For each advisory, record:` then a `bash` fence containing the 4-line `python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_known_findings` invocation with `--set` for `id`, `title`, `location`, `source`, `patched_in`, `severity` | Same table, same advisory fields, with `GHSA-xxxx-yyyy-zzzz` and `GHSA` showing the id and source shapes Step 1a actually produces. **Dropped:** `raw`. Justification: it is nullable, nothing in any workflow or reference ever instructed anyone to populate it, and it appeared only as a column name in this one list — there is no instruction attached to it to lose. **Not touched:** Step 1a-1d above it, and **Step 2 — Patch-bypass mining (HIGH-VALUE STEP)** below it in full, including "were they the ONLY sites of the vulnerable pattern, or are there sibling files that have the same root cause untouched?", the three patch-bypass example classes, and the instruction to save the intel to `<AUDIT_DIR>/files/known-findings.md`. That step was lost once already, in Stage 1, and is now guard-tested. |

## Table C — `SKILL.md`

One replacement and five additions. `SKILL.md` is CRLF; the endings were
checked after editing (Step 7).

| File:line | Old text (verbatim) | New text (verbatim) | What the new form does that the old did — and anything the old stated that the new does not, with why |
|---|---|---|---|
| `SKILL.md:48-50` (Economics Contract preamble) | "The rules below are R2, R4, R5 and R6 of the economics contract; R1 (extract-then-fan-out) and R3 (the context ceiling) are enforced in the audit workflows rather than here." | "The rules below are the economics contract in full: R1 and R3 govern what enters the orchestrator's context and for how long; R2, R4, R5 and R6 govern each of the ways it gets in." | **Dropped:** the clause "R1 (extract-then-fan-out) and R3 (the context ceiling) are enforced in the audit workflows rather than here." Justification: it is the one sentence this task makes false. R1 and R3 are now stated here, immediately below, so leaving the clause would point a reader away from the rules they are standing on. **Not touched:** the two sentences above it — the 449.9M-tokens/$2,053.64 measurement and "a token admitted to the orchestrator's context at turn N is paid for on every remaining turn" / "The orchestrator's context is a budget, not a buffer". |
| `SKILL.md`, new `### R1 — The orchestrator never holds raw material`, inserted before `### Model and effort tiering` | — (addition) | The R1 section: the banned-material list (decompiler pseudocode, disassembly, hexdumps, strings dumps, file reads over ~100 lines, subagent prose), the `audit.py extract --run ${AUDIT_DIR} --root . --unit G1 --from-file ${AUDIT_DIR}/files/G1-paths.txt` snapshot command, the fan-out rationale, and the bound on the orchestrator's own reads (`rows`/`status`/`coverage` cap at 200 rows; `note` returns one line per key) | Addition, not replacement: no existing text is removed or reworded, and the section is inserted as the first rule so R1-R6 read in order. Flags verified against `audit.py extract --help` (`--run`, `--root`, `--unit`, `--from-file` all exist with these spellings). Nothing dropped. |
| `SKILL.md`, new `### R3 — Context ceiling with checkpoint-restart`, inserted after R1 | — (addition) | The R3 section: ceiling **100k** and checkpoint at 80%, the `audit.py checkpoint --db ${AUDIT_DIR}/audit.db --phase audit --reason ceiling --turns <n> --resume-note …` command, why compaction is not the mechanism, and "**The budget governs where tokens are spent, never whether a surface is opened.** A group skipped for budget is a `not_audited(reason='budget')` row and fails the quality gate." | Addition. Flags verified against `audit.py checkpoint --help`; `--reason ceiling` is one of the three values its `choices` accepts. Nothing dropped. |
| `SKILL.md`, `### SQL Tables` table | — (addition of five rows after `cba_fp_verdicts`) | Rows for `cba_inventory`, `cba_coverage`, `cba_patterns`, `cba_pattern_hits`, `cba_checkpoints` | Addition. The seven existing rows are untouched, in order. These five tables already exist in `audit_core/schema.sql` as of Tasks 4-6; the table was simply out of date. Nothing dropped. |
| `SKILL.md`, `### Artifact Layout` tree | — (addition of four lines after the `briefs/` subtree) | `├── extract/` with `manifest.json` and `G<n>/<flattened-path>`, and `├── journal.jsonl` | Addition inside the existing tree. Every existing line of the tree — `audit.db`, `briefs/`, `files/`, `artifacts/`, `archived-poc/`, `report.md` — and the `poc/` paragraph below it are untouched. Nothing dropped. |
| `SKILL.md`, `## Rationalizations to Reject` table | — (addition of three rows at the end) | "Near the ceiling — skip this group" → checkpoint and restart; "I'll just read the file into my own context to check one thing" → R1; "We confirmed the pattern here; the other call sites are probably fine" → register the pattern and sweep | Addition at the end of the table. All 19 existing rows are untouched, in order. Nothing dropped. |

---

## Files touched with no row here

`workflows/recon.md` is listed in the brief's Files block but carries no
retired query and no R1/R3 text, so it is **not modified**. If `git diff
--stat` shows it, that is a hunk without a justification and must be reverted.

`tests/test_workflow_prose.py` is extended with the six guard tests and the
`live_markdown()` / `normalize_ws()` helpers. It is test code, not shipped
prose, so it is outside this table's scope; the pre-existing tests in it are
unmodified.

`tests/test_skill_lint.py` has one consequential change, found by running the
full suite after the edits: its `KNOWN` verb set was a hand-copied literal of
seven Stage 1 verbs, while the shipped `audit.py lint-skill` command passes
`set(HANDLERS)` — all sixteen. The moment the prose above started naming
`put`, `rows`, `status`, `dedup`, `coverage`, `extract` and `checkpoint`, the
test reported 19 real verbs as "not a real verb" while the shipped command
accepted every one of them. `KNOWN` is now `set(audit.HANDLERS)`, which is
what the shipped command lints with. No lint rule and no other test changed.

---

## Reconciliation against `git diff -U0`

Every hunk, and the row that covers it:

| Hunk | Row |
|---|---|
| `SKILL.md @@ -48,3 +48,43` | Table C rows 1-3 (the 6a preamble swap and the R1 and R3 insertions are adjacent and git emits them as one hunk) |
| `SKILL.md @@ -206,0 +247,5` | Table C row 4 (SQL Tables) |
| `SKILL.md @@ -214,0 +260,4` | Table C row 5 (Artifact Layout) |
| `SKILL.md @@ -268,0 +318,3` | Table C row 6 (Rationalizations to Reject) |
| `references/phase2-feature-mapping.md @@ -105,3 +105,5` | Table B row 5 |
| `references/phase2-feature-mapping.md @@ -110,3 +112,4` | Table B row 6 |
| `references/phase4-deep-audit.md @@ -68,5 +68,8` | Table B row 1 |
| `references/phase4-deep-audit.md @@ -75,0 +79,6` | Table B row 2 |
| `references/phase5-fp-check.md @@ -21,2 +21,2` | Table B row 4 |
| `references/phase5-fp-check.md @@ -86,3 +86,5` | Table B row 3 |
| `references/resume-note-template.md @@ -33 +33` | Table A row 1 (the heading rename) |
| `references/resume-note-template.md @@ -35,3 +35,2` | Table A row 1 (the fence) |
| `references/workflow-orchestration.md @@ -95 +95` | Table A row 5 |
| `workflows/audit.md @@ -36,3 +36,5` | Table B row 7 |
| `workflows/audit.md @@ -144,2 +146,2` | Table A row 3 |
| `workflows/fpcheck.md @@ -77,7 +77,2` | Table A row 2 (the fence) |
| `workflows/fpcheck.md @@ -87,0 +83,2` | Table A row 2 (the one added sentence) |
| `workflows/report.md @@ -66,2 +66,4` | Table A row 4 |
| `tests/test_workflow_prose.py @@ -207,0 +208,116` | "Files touched with no row here" — the guard tests |
| `tests/test_skill_lint.py @@ -6,0 +7` and `@@ -10 +11,5` | "Files touched with no row here" — the stale `KNOWN` set |

No hunk is uncovered, and `workflows/recon.md` does not appear in the diff.

---

## Count

**13 blocks replaced** (12 in the workflows and references, 1 in `SKILL.md`),
**5 blocks added** to `SKILL.md`, **4 lines dropped, each justified above.**

The four dropped lines, each with its own justification:

1. `verified` from the `cba_findings` example column list
   (`references/phase4-deep-audit.md`) — schema default is `'source-only'`,
   and the instruction that sets it otherwise lives untouched at
   `workflows/audit.md:116`.
2. `merged_into` from the `cba_fp_verdicts` example column list
   (`references/phase5-fp-check.md`) — nullable, DUPLICATE-only, and the
   instruction that sets it lives untouched four lines below in the same file.
3. `raw` from the `cba_known_findings` example column list
   (`workflows/audit.md`) — nullable, and no instruction anywhere ever told
   anyone to populate it.
4. "R1 (extract-then-fan-out) and R3 (the context ceiling) are enforced in the
   audit workflows rather than here." (`SKILL.md`) — this task makes the
   statement false; R1 and R3 are now stated in that very section.

The heading rename at `references/resume-note-template.md:33` drops the word
"SQL" and nothing else; it carried no instruction.
