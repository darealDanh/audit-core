# Stage 3 — Quality Additions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the five mechanisms the tplink post-mortem named as the causes of ten missed CRITICALs — the pivot rule, sweep-on-confirm, coverage as a gate, identity discipline and chain composition — plus the precision metric that the one remaining tiering change is conditioned on.

**Architecture:** Each mechanism is a small `audit_core` module with one `audit.py` verb, writing to the SQLite tables the spec's §3.4 state model already names. Three of the five extend tables that already exist, which Stage 2 could not do in place, so the stage opens with a real column-level migration spine and closes with the shipped-prose change that makes the orchestrator actually use them. The mechanisms propose and gate; they never decide — every one of them hands a bounded candidate list or a pass/fail to a human or an agent, in the same discipline `dedup` and `bench` already follow.

**Tech Stack:** Python 3.10+, standard library only, SQLite via `sqlite3`, pytest.

**Spec:** [docs/superpowers/specs/2026-10-04-audit-suite-design.md](../specs/2026-10-04-audit-suite-design.md) — §3.4 (state model), §3.5 (the three new mechanisms), §5.1 (model tiering), §5.3 (measurement), §6.1 (golden benchmark), §6.2 (machinery that must survive), §7 (build stages, Stage 3).

**Prior stages:** [Stage 0](2026-10-04-stage0-instrumentation-and-goldens.md), [Stage 1](2026-10-05-stage1-economics.md), [Stage 2](2026-10-05-stage2-core-and-r1-r3.md). Stage 1's carried findings are in [specs/2026-10-05-stage1-findings-for-later-stages.md](../specs/2026-10-05-stage1-findings-for-later-stages.md); Stage 2's open gate is [docs/baselines/2026-10-05-stage2-gate.md](../../baselines/2026-10-05-stage2-gate.md).

---

## Scope Rulings

The spec assigns six things to Stage 3. Four rulings decide how much of each is in this plan. Each carries what it costs if the ruling is wrong.

### S1 — The Sonnet tiering change ships as a *measurement and a procedure*, not as an applied prose edit

Spec §7: "Then, last and alone, Sonnet tiering for `surface`, L-sink and `fpcheck` — the one tiering change that can cost quality, **with precision measured before and after**."

The before-measurement does not exist. `audit_core/bench.py` scores recall, candidates and cost per match; it does not score precision, and no run in this repository has ever reported a precision figure. Applying the model downgrade now means shipping the one change the spec explicitly conditioned on a measurement, without the measurement.

So Task 7 **builds** precision into `bench`, Task 9 **writes** the gate procedure that consumes it, and the two guard tests that currently quarantine the change (`test_mapping_and_fpcheck_keep_the_strongest_model`, `test_skill_md_subagent_table_keeps_the_strongest_model_for_both`) are **kept and re-aimed** at the new reason rather than deleted. The exact prose diff to apply once the baseline exists is written out verbatim in Task 9, Step 6, so applying it later is a transcription, not a redesign.

**Cost if wrong:** the stage ships without its measured cost win. The tiering change is two table rows and two workflow lines; re-doing it after the baseline exists is under an hour. The reverse error — shipping a model downgrade on the phase that decides which findings survive, with no precision number on either side of it — is undetectable until a gate run weeks later, and §6.1's merge rule ("no change merges if recall drops") would have no evidence to act on.

### S2 — Column migration is a first-class task, not a line in each mechanism's task

Three of the five mechanisms add columns to tables that already exist: `cba_fp_verdicts` gains `refuting_mechanism` and `enabled_observation`, `cba_patterns` gains `swept_at` and `hit_count`. `schema.sql` is entirely `CREATE TABLE IF NOT EXISTS`, which does nothing to a table that is already there, and SQLite has no `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.

Stage 2's whole-branch review found this same defect one level up — six verbs tracebacked against a pre-Stage-2 database, on the normal upgrade path — and fixed it for missing *tables*. Missing *columns* is the identical failure at a finer grain, and it arrives the moment Task 2 lands. Task 1 therefore builds `db.MIGRATIONS` / `db.migrate()`, extends the `connect()` gate from tables to columns, and wires `workspace.apply_schema` to run it, before any mechanism needs it.

**Cost if wrong:** if migration were folded into Task 2, the fix would arrive written by whoever happened to need it first, scoped to one table, and Tasks 3-7 would each re-derive it. If it were skipped entirely, every user with an in-flight audit gets `sqlite3.OperationalError: no such column: refuting_mechanism` and a raw traceback from six verbs.

### S3 — Coverage gates; it does not block

Spec §3.5.3 makes `not_audited` rows with reasons mandatory and §R3's anti-rationalization rule says a group skipped for budget "**fails the quality gate**". Stage 2 shipped coverage as recording and reporting only, deliberately, so that Stage 3 could benchmark the gate on its own.

The gate is `audit.py coverage --gate`, which exits non-zero and names every failure. It is a command a workflow step and a quality checklist call; it is **not** wired into `put`, `init` or any other verb, and nothing in `audit_core` refuses to run because coverage is incomplete. A gate that silently blocks writes mid-phase would strand a run with no way to record the very `not_audited` rows that clear it.

**Cost if wrong:** an orchestrator that ignores the workflow step passes a phase with gaps. That is detectable after the fact from `cba_coverage` and is exactly what §6.1's "deterministic leading indicators" are for. The reverse error — a hard block — can deadlock a real audit.

### S4 — `cba_components` and `cba_chains` are added under the `cba_` prefix, additively

Spec §3.4 names the shared-core tables without a prefix (`components`, `chains`). Every table in this repository carries `cba_`, and `db.TABLE_SPECS`, `skill_lint`, `selftest` and the whole test suite key on that. The two new tables are `cba_components` and `cba_chains`; no existing table is renamed, dropped or re-typed.

**Cost if wrong:** the eventual monorepo extraction (Stage 4, §3.1) renames all fifteen tables at once rather than fourteen. That is a mechanical rename against `TABLE_SPECS`, which is the single source of truth precisely so that it is mechanical.

---

## Global Constraints

Copied from the spec and from the constraints Stages 0-2 established. Every task's requirements implicitly include this section.

- **Python 3.10+, standard library only.** `pyproject.toml` declares `requires-python = ">=3.10"` and `dependencies = []`. No new dependency, in the package or in the tests.
- **No network access** in any module or any test.
- **Line endings are load-bearing and are checked by nothing — get them right by inspection.** CRLF: `SKILL.md`, `references/phase0-source-detection.md`, `references/phase2-feature-mapping.md`, `references/phase4-deep-audit.md`, `references/phase5-fp-check.md`. LF: everything else, including all of `workflows/`, `references/briefs/`, `references/lessons-learned.md`, `references/workflow-orchestration.md`, `references/resume-note-template.md`, `references/phase6-report.md`, `audit_core/*.py`, `tests/*.py`, `audit.py`, `install.sh`, `docs/**`. Before editing a markdown file, run `grep -c $'\r' <file>` and match what you find. A whole-file rewrite that flips line endings produces a diff in which every line is changed and the real edit is unreviewable.
- **`~/Documents/Offsec/Opswat/Devices/` and `~/.claude/projects/` are READ-ONLY.** Read them freely; never write to either.
- **Never run `install.sh` or `install.ps1` without overriding `HOME`, `CLAUDE_CONFIG_DIR` *and* `CODEX_HOME`.** A real installation exists at `~/.claude/skills/codebase-audit/` and an unguarded run overwrites it. All three variables, every time — Stage 2 found four tests that overrode two of the three and were safe only by accident.
- **Never write `tests/goldens/*/matches.json` or `tests/goldens/*/rejections.json` from code.** Both are human adjudications. `bench` proposes candidates; a human records the decision.
- **Never edit a baseline document in place.** A correction is appended, dated, and says what it corrects.
- **Every new `audit.py` verb goes in `HANDLERS` and in `build_parser`.** `cmd_selftest` cross-checks the two and `skill_lint` reads `HANDLERS`; a verb in one and not the other fails `selftest`.
- **Bounded output.** Anything that can return a list returns a capped list and says it capped — R1 applies to this toolchain's own output, not only to subagents.
- **Commit messages end with:** `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`

## Review Focus

Five conditions the spec implies that no task's happy path exercises. Each one's test is added to the task that owns the code, named in that task's steps.

1. **A run directory created before Stage 3.** `cba_fp_verdicts` exists without `refuting_mechanism`. This is the normal upgrade path — a user upgrades the installed skill mid-audit — and it is the exact defect Stage 2's whole-branch review found at table granularity. Every verb must give the remedy, never a traceback. *(Task 1, Steps 7-9.)*
2. **A `FALSE_POSITIVE` written by a path that predates the pivot rule.** The validator makes every such call fail, including `audit.py put --table cba_fp_verdicts --set verdict=FALSE_POSITIVE`, which is what `references/phase5-fp-check.md` documents today. The error must name the two missing fields *and* the verb that supplies them, or the operator's next move is to work around the rule. *(Task 2, Steps 7-8.)*
3. **A sweep that hit its cap.** 500 hits with more behind them. Recording that pattern as swept is a false coverage claim about the one mechanism whose entire value is breadth. *(Task 3, Steps 7-8.)*
4. **`coverage --gate` against an empty inventory.** `CoverageReport.fraction` returns `0.0` when nothing is inventoried, and Stage 2's `render` says "there is no denominator to report". A gate that reads `0 budget skips, 0 unrecorded` and passes is a gate that passes hardest on the run that did the least. *(Task 4, Steps 1-4.)*
5. **Chain proposal over a realistic finding set.** 45 findings is 1,980 ordered pairs, matched on English impact prose where "user", "remote" and "file" appear everywhere. Without a noise floor and a cap this dumps hundreds of candidates into the orchestrator's context — the precise R1 failure the mechanism is meant to serve. *(Task 6, Steps 1-4 and 9-10.)*

---

## File Structure

### Created

| File | Responsibility |
|---|---|
| `audit_core/pivot.py` | Write a `FALSE_POSITIVE` verdict and its enabled observation as one act; find verdicts whose observation does not resolve. |
| `audit_core/patterns.py` | Sweep state per registered pattern: which are swept, which are not, how many hits each found. |
| `audit_core/identity.py` | Assert a component's identity with evidence that is not its own filename. |
| `audit_core/chains.py` | Propose cross-group enabler→consumer finding pairs; compose an approved chain. |
| `tests/test_migrate.py` | The column migration spine, including a database built from the Stage 2 schema. |
| `tests/test_pivot.py` | Pivot rule validation and the atomic write. |
| `tests/test_patterns.py` | Sweep state, the unswept gate, the truncated-sweep refusal. |
| `tests/test_identity.py` | Evidence rules. |
| `tests/test_chains.py` | Proposal noise floor, cap, composition validation. |
| `tests/test_cli_stage3.py` | Every new verb as a subprocess, the idiom `tests/test_cli_stage2.py` uses. |
| `docs/superpowers/derivations/2026-10-05-stage3-prose-derivation.md` | Every shipped-prose hunk mapped to the rule that justifies it, written **before** the prose edits. |
| `docs/baselines/2026-10-05-stage3-gate.md` | How the five additions are benchmarked, separately, so attribution is possible. |
| `docs/baselines/2026-10-05-stage3-tiering-gate.md` | The precision-before/precision-after procedure for the held tiering change, and the exact diff it unlocks. |

### Modified

| File | Change |
|---|---|
| `audit_core/schema.sql` | Two new tables; four new columns on two existing tables. |
| `audit_core/db.py` | `MIGRATIONS`, `migrate`, `table_columns`; column-aware `connect()` gate; `_validate_verdict`, `_validate_component`, `_validate_chain`; two new `TABLE_SPECS` entries; `COMPONENT_KINDS`, `CHAIN_COMPLETENESS`. |
| `audit_core/workspace.py` | `apply_schema` returns `SchemaResult(tables, migrated)` and runs the migration. |
| `audit_core/coverage.py` | `GateResult`, `gate()`, `render_gate()`. |
| `audit_core/sweep.py` | `record()` marks the pattern swept, and refuses a truncated result. |
| `audit_core/bench.py` | `Precision`, `precision_from_db()`, `BenchResult.precision`. |
| `audit_core/skill_lint.py` | Two rules: an FP verdict documented without the pivot fields, and a `cba_patterns` insert documented without a sweep. |
| `audit.py` | Four verbs (`pivot`, `patterns`, `identify`, `chain`); `coverage --gate`; `bench` prints precision; `init` reports migrations; `cmd_sweep` drops its duplicated truncation check. |
| `SKILL.md` *(CRLF)* | Two table rows, five rationalization rows, the pivot/sweep/coverage/identity/chain mechanisms in Essential Principles. |
| `workflows/fpcheck.md`, `workflows/audit.md`, `workflows/recon.md` | The steps that invoke the five mechanisms. |
| `references/phase0-source-detection.md` *(CRLF)* | Identity evidence at source confirmation. |
| `references/phase4-deep-audit.md` *(CRLF)* | Pattern registration and the chain pass. |
| `references/phase5-fp-check.md` *(CRLF)* | The pivot rule in verdict processing and in the quality gates. |
| `references/briefs/fpcheck-brief.md` | The pivot step in the method. |
| `references/briefs/audit-brief.md` | Pattern registration in the return path. |
| `tests/test_workspace.py` | `SchemaResult`; two new table names. |
| `tests/test_db.py`, `tests/test_sweep.py`, `tests/test_coverage.py`, `tests/test_bench.py` | Extended for the new columns, gate and metric. |
| `tests/test_workflow_prose.py`, `tests/test_skill_lint.py`, `tests/test_cli.py` | Guard tests for the new prose and the two re-aimed tiering quarantines. |

---

## Task 1: Column migration spine, and the two new tables

Every other task in this stage either adds a column to a table that already exists or adds a table. `CREATE TABLE IF NOT EXISTS` handles the second case and is silently useless for the first. This task makes an existing run directory upgradeable in place, and declares the two new tables while it is in the schema.

**Files:**
- Modify: `audit_core/schema.sql`
- Modify: `audit_core/db.py`
- Modify: `audit_core/workspace.py`
- Modify: `audit.py` (`cmd_selftest` line 58, `cmd_init`)
- Modify: `tests/test_workspace.py`
- Create: `tests/test_migrate.py`

**Interfaces:**
- Consumes: `db.TABLE_SPECS`, `db.TableSpec`, `db.DbError`, `db.connect`, `workspace.SCHEMA_PATH` (all existing).
- Produces:
  - `db.MIGRATIONS: tuple[tuple[str, str, str], ...]` — `(table, column, sql_type)`.
  - `db.table_columns(con, table) -> tuple[str, ...]`
  - `db.migrate(con) -> list[str]` — returns `"table.column"` for each column added.
  - `db.COMPONENT_KINDS: tuple[str, ...]`, `db.CHAIN_COMPLETENESS: tuple[str, ...]`
  - `db.TABLE_SPECS["cba_components"]`, `db.TABLE_SPECS["cba_chains"]`
  - `workspace.SchemaResult` — frozen dataclass with `.tables: list[str]` and `.migrated: list[str]`; `workspace.apply_schema` now returns it.

- [ ] **Step 1: Write the failing migration test**

Create `tests/test_migrate.py`. The first test is the one that matters: a database built from the **Stage 2** schema, migrated, must end up with the same columns as a database built fresh from today's `schema.sql`. The Stage 2 text is embedded as a fixture rather than read from git, so the test keeps meaning after the history is rewritten or the file moves.

```python
import pathlib
import sqlite3

import pytest

from audit_core import db, workspace

# The two Stage 2 tables this stage adds columns to, exactly as Stage 2
# shipped them. Embedded rather than read from git history: this fixture is
# the definition of "the database an upgrading user actually has".
STAGE2_SQL = """
CREATE TABLE IF NOT EXISTS cba_fp_verdicts (
    finding_id TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    reason TEXT,
    final_severity TEXT,
    final_id TEXT,
    merged_into TEXT,
    rule_applied TEXT,
    reviewed_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    regex TEXT NOT NULL,
    origin_finding TEXT,
    language TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')));
"""


def columns(con, table):
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


def test_a_stage2_database_migrates_to_the_current_column_set(tmp_path):
    old = tmp_path / "old.db"
    con = sqlite3.connect(old)
    con.executescript(STAGE2_SQL)
    con.execute("INSERT INTO cba_fp_verdicts (finding_id, verdict) "
                "VALUES ('G1-F1', 'TRUE_POSITIVE')")
    con.commit()

    applied = db.migrate(con)

    assert "cba_fp_verdicts.refuting_mechanism" in applied
    assert "cba_patterns.hit_count" in applied
    for table in ("cba_fp_verdicts", "cba_patterns"):
        assert columns(con, table) >= set(db.TABLE_SPECS[table].columns)
    # The row an upgrading user already had is still there.
    assert con.execute("SELECT COUNT(*) FROM cba_fp_verdicts").fetchone()[0] == 1
    con.close()


def test_migrate_is_idempotent(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    assert db.migrate(con) == []
    con.close()


def test_migrate_skips_a_table_that_is_not_there(tmp_path):
    """An empty database is not an error; it is a database `init` has not
    touched yet. Reporting it as a failed migration would make `init` loud
    on the one path where it has nothing to do."""
    con = sqlite3.connect(tmp_path / "empty.db")
    assert db.migrate(con) == []
    con.close()


def test_every_migration_names_a_column_its_table_spec_declares():
    """The guard that keeps MIGRATIONS and TABLE_SPECS from drifting. A
    migration for a column no spec declares adds a column `put` will reject;
    a spec column with no migration is a column an upgraded database lacks."""
    for table, column, _type in db.MIGRATIONS:
        assert table in db.TABLE_SPECS, table
        assert column in db.TABLE_SPECS[table].columns, f"{table}.{column}"


def test_a_fresh_database_needs_no_migration_for_any_spec_column(tmp_path):
    """schema.sql and TABLE_SPECS agree on a fresh build, so MIGRATIONS only
    ever has work to do on an older database."""
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    for table, spec in db.TABLE_SPECS.items():
        assert columns(con, table) >= set(spec.columns), table
    con.close()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_migrate.py -q`
Expected: FAIL — `AttributeError: module 'audit_core.db' has no attribute 'migrate'`.

- [ ] **Step 3: Add the new columns and the two new tables to `schema.sql`**

`audit_core/schema.sql` is LF. Edit the two existing `CREATE TABLE` bodies in place, adding the columns before `reviewed_at` / `created_at` so the declaration reads in the order the row is written:

In `cba_fp_verdicts`, after the `rule_applied TEXT,` line:

```sql
    refuting_mechanism TEXT,
    enabled_observation TEXT,
```

In `cba_patterns`, after the `notes TEXT,` line:

```sql
    swept_at TEXT,
    hit_count INTEGER,
```

Then append at the end of the file:

```sql
-- Stage 3 additions. IF NOT EXISTS for the same reason as every statement
-- above. New COLUMNS on the tables above cannot be declared this way --
-- SQLite has no ADD COLUMN IF NOT EXISTS, and CREATE TABLE IF NOT EXISTS is
-- a no-op against a table that already exists -- so those columns are
-- declared inline above for fresh databases and added to existing ones by
-- audit_core.db.migrate, which workspace.apply_schema runs after this file.

CREATE TABLE IF NOT EXISTS cba_components (
    path TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    asserted_identity TEXT NOT NULL,
    identity_evidence TEXT NOT NULL,
    confidence INTEGER,
    version TEXT,
    recorded_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_chains (
    id TEXT PRIMARY KEY,
    finding_ids TEXT NOT NULL,
    attacker_position TEXT NOT NULL,
    pre_auth TEXT,
    completeness TEXT NOT NULL,
    blocking_unknowns TEXT,
    created_at TEXT DEFAULT (datetime('now')));
```

- [ ] **Step 4: Add `MIGRATIONS`, `table_columns` and `migrate` to `db.py`**

Place `MIGRATIONS` immediately after the `CHECKPOINT_REASONS` line, and the two functions immediately after `TABLE_SPECS`, before `connect()`.

```python
# Columns added to tables that already existed when an earlier stage shipped.
# `CREATE TABLE IF NOT EXISTS` adds a table; it does nothing to a table that
# is already there, and SQLite has no `ALTER TABLE ... ADD COLUMN IF NOT
# EXISTS`. So the list is explicit and ordered, and a reviewer can read
# exactly what will be run against a user's database.
#
# Append to this tuple; never reorder it and never remove an entry. A removed
# entry is a column that stops being added to the databases that still lack
# it, and nothing reports that - the column simply is not there.
MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("cba_fp_verdicts", "refuting_mechanism", "TEXT"),
    ("cba_fp_verdicts", "enabled_observation", "TEXT"),
    ("cba_patterns", "swept_at", "TEXT"),
    ("cba_patterns", "hit_count", "INTEGER"),
)
```

```python
def table_columns(con: sqlite3.Connection, table: str) -> tuple[str, ...]:
    """The columns a database actually has for `table`, in declared order.

    `table` is interpolated into the PRAGMA, which takes no bound parameters.
    It is checked against TABLE_SPECS first, so the only strings that reach
    the statement are the fourteen literals this module declares.
    """
    _spec(table)
    return tuple(r[1] for r in con.execute(f"PRAGMA table_info({table})"))


def migrate(con: sqlite3.Connection) -> list[str]:
    """Add every MIGRATIONS column the database lacks. Returns what it added.

    Idempotent, and safe against a database that has none of the tables yet:
    a table that is not there is skipped rather than reported, because that
    is what `init` sees on a fresh run before schema.sql has been applied.
    """
    present = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    applied: list[str] = []
    for table, column, decl in MIGRATIONS:
        if table not in present:
            continue
        if column in table_columns(con, table):
            continue
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        applied.append(f"{table}.{column}")
    if applied:
        con.commit()
    return applied
```

- [ ] **Step 5: Add the two new table specs and their vocabularies to `db.py`**

Vocabularies go beside `CHECKPOINT_REASONS`:

```python
COMPONENT_KINDS = ("source-tree", "binary", "library", "firmware-image",
                   "service", "config")
CHAIN_COMPLETENESS = ("complete", "partial", "blocked")
```

Validators go beside `_validate_pattern`. `_validate_component`'s identity rule belongs to Task 5 and is added there; here it checks only the vocabulary and the confidence range, so Task 1 ships a table that is usable and Task 5 tightens it.

```python
def _validate_component(row: dict[str, str]) -> None:
    kind = row.get("kind")
    if kind not in COMPONENT_KINDS:
        raise DbError(f"kind={kind!r} is not one of {', '.join(COMPONENT_KINDS)}")
    raw = str(row.get("confidence", "") or "").strip()
    if not raw:
        return
    try:
        value = int(raw)
    except ValueError:
        raise DbError(f"confidence={raw!r} is not an integer 1-10") from None
    if not 1 <= value <= 10:
        raise DbError(f"confidence={value} is outside 1-10")


def _validate_chain(row: dict[str, str]) -> None:
    """A chain is an ordered list of findings, and two is the minimum.

    A one-finding chain is a finding. Recording it as a chain hides it from
    the finding tally and inflates the chain tally, which is the one thing
    this table exists to count honestly.
    """
    completeness = row.get("completeness")
    if completeness not in CHAIN_COMPLETENESS:
        raise DbError(f"completeness={completeness!r} is not one of "
                      + ", ".join(CHAIN_COMPLETENESS))
    ids = [part.strip() for part in str(row.get("finding_ids", "")).split(",")]
    ids = [i for i in ids if i]
    if len(ids) < 2:
        raise DbError("finding_ids needs at least two comma-separated finding "
                      "ids, in attack order; a one-finding chain is a finding")
    if len(set(ids)) != len(ids):
        raise DbError(f"finding_ids repeats an id: {', '.join(ids)}")
```

Specs go at the end of `TABLE_SPECS`:

```python
    "cba_components": TableSpec(
        columns=("path", "kind", "asserted_identity", "identity_evidence",
                 "confidence", "version", "recorded_at"),
        required=("path", "kind", "asserted_identity", "identity_evidence"),
        validate=_validate_component),
    "cba_chains": TableSpec(
        columns=("id", "finding_ids", "attacker_position", "pre_auth",
                 "completeness", "blocking_unknowns", "created_at"),
        required=("id", "finding_ids", "attacker_position", "completeness"),
        validate=_validate_chain),
```

Also add the four new columns to the two existing specs: `cba_fp_verdicts` gains `"refuting_mechanism", "enabled_observation"` in `columns` (not in `required` — Task 2 enforces them conditionally, through the validator); `cba_patterns` gains `"swept_at", "hit_count"` in `columns`.

- [ ] **Step 6: Run the migration tests**

Run: `python3 -m pytest tests/test_migrate.py -q`
Expected: PASS, 5 tests.

- [ ] **Step 7: Write the failing test for the column-level `connect()` gate**

Review Focus 1. Append to `tests/test_migrate.py`:

```python
def test_connect_names_a_missing_column_and_gives_the_remedy(tmp_path):
    """Review Focus 1: the normal upgrade path. A run directory created
    before this stage has every table and is missing four columns. Stage 2
    closed this at table granularity; a missing column produced
    `sqlite3.OperationalError: no such column` from six verbs."""
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    # Rebuild cba_patterns without the Stage 3 columns, which is what a
    # pre-Stage-3 database holds.
    con.executescript(
        "DROP TABLE cba_patterns;"
        "CREATE TABLE cba_patterns (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " regex TEXT NOT NULL, origin_finding TEXT, language TEXT,"
        " notes TEXT, created_at TEXT);")
    con.commit()
    con.close()

    with pytest.raises(db.DbError) as exc:
        db.connect(run / "audit.db")
    message = str(exc.value)
    assert "cba_patterns.swept_at" in message
    assert "audit.py init" in message
    assert "--timestamp" in message


def test_connect_succeeds_once_the_missing_columns_are_migrated(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    con.executescript(
        "DROP TABLE cba_patterns;"
        "CREATE TABLE cba_patterns (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " regex TEXT NOT NULL, origin_finding TEXT, language TEXT,"
        " notes TEXT, created_at TEXT);")
    con.commit()
    db.migrate(con)
    con.close()
    db.connect(run / "audit.db").close()
```

Run: `python3 -m pytest tests/test_migrate.py -q`
Expected: FAIL — `connect()` opens the database without complaint.

- [ ] **Step 8: Extend the `connect()` gate from tables to columns**

In `audit_core/db.py`, replace the `missing = sorted(set(TABLE_SPECS) - present)` block and the `if missing:` that follows it. Keep the remedy text verbatim; only the noun and the list change.

```python
    missing_tables = sorted(set(TABLE_SPECS) - present)
    missing_columns: list[str] = []
    if not missing_tables:
        # Only when every table is there: naming a column of a table that
        # does not exist is noise on top of the real problem.
        for table, spec in sorted(TABLE_SPECS.items()):
            have = set(table_columns(con, table))
            missing_columns.extend(
                f"{table}.{c}" for c in spec.columns if c not in have)
    if missing_tables or missing_columns:
        con.close()
        noun = "table(s)" if missing_tables else "column(s)"
        names = ", ".join(missing_tables or missing_columns)
        raise DbError(
            f"{path} is missing {noun}: {names}. This run "
            f"directory predates the current schema. Re-apply it in place "
            f"with `audit.py init --root <project> --timestamp <ts>`, where "
            f"<ts> is the timestamp already in the run directory name - "
            f"every statement in schema.sql is CREATE TABLE IF NOT EXISTS "
            f"and every column added since is applied by an idempotent "
            f"ALTER TABLE, so this adds what is missing and destroys no "
            f"rows. Without --timestamp, `init` creates a new run directory "
            f"instead.")
    return con
```

Note the one sentence of the remedy that changed: it now claims the ALTER TABLE path as well, which is true only because Step 10 wires `apply_schema` to run `migrate`. Do Step 10 before claiming it works.

- [ ] **Step 9: Run the gate tests**

Run: `python3 -m pytest tests/test_migrate.py -q`
Expected: PASS, 7 tests.

- [ ] **Step 10: Make `apply_schema` run the migration and report it**

`audit_core/workspace.py`. Add the import and the result type, and change `apply_schema`:

```python
from dataclasses import dataclass

from audit_core import db


@dataclass(frozen=True, slots=True)
class SchemaResult:
    tables: list[str]
    migrated: list[str]


def apply_schema(db_path: str | pathlib.Path) -> SchemaResult:
    """Apply schema.sql, then add any columns an older database lacks.

    Both halves are idempotent and neither destroys a row. The second half
    is what makes `audit.py init --timestamp <existing-ts>` a real in-place
    upgrade rather than a no-op on everything but new tables.
    """
    con = sqlite3.connect(pathlib.Path(db_path))
    try:
        con.executescript(SCHEMA_PATH.read_text())
        con.commit()
        migrated = db.migrate(con)
        rows = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    finally:
        con.close()
    return SchemaResult(tables=[r[0] for r in rows], migrated=migrated)
```

`init_run`'s call site needs no change — it discards the return.

- [ ] **Step 11: Fix the three `apply_schema` call sites**

`audit.py` line 58, inside `cmd_selftest`: `tables = list(workspace_mod.apply_schema(db_path))` becomes

```python
            tables = workspace_mod.apply_schema(db_path).tables
```

`audit.py` `cmd_init`:

```python
def cmd_init(args: argparse.Namespace) -> int:
    run = workspace_mod.init_run(args.root, timestamp=args.timestamp)
    result = workspace_mod.apply_schema(run / "audit.db")
    print(f"tables: {', '.join(result.tables)}")
    if result.migrated:
        print(f"migrated: {', '.join(result.migrated)}")
    # The run directory is printed LAST and nothing may follow it:
    # workflows/recon.md does `AUDIT_DIR=$(audit.py init | tail -1)`.
    print(run)
    return 0
```

`tests/test_workspace.py` line 28:

```python
    tables = workspace.apply_schema(run / "audit.db").tables
```

and extend `EXPECTED_TABLES` with `"cba_chains", "cba_components"`, keeping the list alphabetical.

- [ ] **Step 12: Write the test that pins `init`'s last-line contract**

Append to `tests/test_workspace.py`:

```python
def test_init_prints_the_run_directory_as_its_last_stdout_line(tmp_path):
    """workflows/recon.md reads `AUDIT_DIR=$(audit.py init | tail -1)`. Any
    line printed after the path silently sets AUDIT_DIR to that line."""
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "init",
         "--root", str(tmp_path), "--timestamp", "20260105-120000"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    last = r.stdout.strip().splitlines()[-1]
    assert pathlib.Path(last) == tmp_path / "reports" / "audit-20260105-120000"


def test_init_against_an_older_database_reports_what_it_migrated(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    con.executescript(
        "DROP TABLE cba_patterns;"
        "CREATE TABLE cba_patterns (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " regex TEXT NOT NULL, origin_finding TEXT, language TEXT,"
        " notes TEXT, created_at TEXT);")
    con.commit()
    con.close()
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "init",
         "--root", str(tmp_path), "--timestamp", "20260105-120000"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "cba_patterns.swept_at" in r.stdout
    assert pathlib.Path(r.stdout.strip().splitlines()[-1]).name == "audit-20260105-120000"
```

- [ ] **Step 13: Run the whole suite**

Run: `python3 -m pytest -q`
Expected: PASS. `tests/test_workspace.py` and `tests/test_db.py` both build databases through `apply_schema`; if either fails, the cause is the `SchemaResult` change, not the schema.

- [ ] **Step 14: Run selftest**

Run: `python3 audit.py selftest`
Expected: exit 0, reporting `tables 15 in schema.sql, 14 under contract, columns agree`. The table count rises by two (`cba_components`, `cba_chains`); `sqlite_sequence` continues to account for the one-table difference between the two numbers.

- [ ] **Step 15: Commit**

```bash
git add audit_core/schema.sql audit_core/db.py audit_core/workspace.py audit.py \
        tests/test_migrate.py tests/test_workspace.py
git commit -m "$(cat <<'MSG'
feat: migrate columns in place, and declare components and chains

CREATE TABLE IF NOT EXISTS adds a table and does nothing to one that is
already there, so every column this stage adds to cba_fp_verdicts and
cba_patterns was invisible to an existing run directory. SQLite has no ADD
COLUMN IF NOT EXISTS, so MIGRATIONS is an explicit ordered list and migrate()
applies what is missing.

connect()'s schema gate now covers columns as well as tables, with the same
remedy -- which is honest only because apply_schema runs the migration, so
`init --timestamp <existing-ts>` is a real in-place upgrade.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 2: The pivot rule

Spec §3.5.1: "A `FALSE_POSITIVE` verdict is invalid unless it records `refuting_mechanism` and what that mechanism enables, and the latter is written back as a rung-1 observation."

The tplink miss this comes from: a finding was correctly refuted by a 300-byte sliding-window flush, and that same flush is the attack surface for a reference-set CRITICAL. The analyst stopped at "refuted" and never asked what the refuting mechanism *is*. The rule forces the question on every false positive.

**The rule is unconditional, and the honest answer is sometimes "nothing yet".** A refuting mechanism is code; code does something. The observation may legitimately read "a 300-byte sliding-window flush in `recv_loop` bounds the write; no attacker-controlled path to the window size identified in this review" — that is a rung-1 observation, and it is exactly the kind that was never written down. What the rule forbids is a `FALSE_POSITIVE` with the mechanism left blank. Implementers and prose must not soften this into "where applicable".

**Files:**
- Create: `audit_core/pivot.py`
- Create: `tests/test_pivot.py`
- Modify: `audit_core/db.py` (`_validate_verdict`, replacing `one_of("verdict", VERDICTS)` on `cba_fp_verdicts`)
- Modify: `audit.py` (`cmd_pivot`, `HANDLERS`, `build_parser`)
- Modify: `tests/test_cli_stage3.py` (created in this task)

**Interfaces:**
- Consumes: `db.put`, `db.rows`, `db.DbError`, `db.VERDICTS`, `db.connect`.
- Produces:
  - `pivot.Pivot` — frozen dataclass: `finding_id: str`, `observation_id: int`, `mechanism: str`.
  - `pivot.record(con, *, finding_id, group_id, mechanism, enables, reason="", rule_applied="", severity_hint="", location="", replace=False) -> Pivot`
  - `pivot.dangling(con) -> list[tuple[str, str]]` — `(finding_id, enabled_observation)` for verdicts whose observation id does not resolve.
  - `pivot.render(p: Pivot) -> str`

- [ ] **Step 1: Write the failing validator tests**

Create `tests/test_pivot.py`:

```python
import sqlite3

import pytest

from audit_core import db, pivot, workspace


def fresh(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = db.connect(run / "audit.db")
    db.put(con, "cba_feature_groups", {"id": "G1", "name": "auth"})
    db.put(con, "cba_findings", {
        "id": "G1-F1", "group_id": "G1", "title": "t", "severity": "HIGH",
        "confidence": "9", "location": "src/recv.c:120",
        "root_cause": "unbounded copy", "impact": "overflow"})
    return con


def test_a_false_positive_without_a_refuting_mechanism_is_rejected(tmp_path):
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_fp_verdicts",
               {"finding_id": "G1-F1", "verdict": "FALSE_POSITIVE",
                "reason": "bounded by the window"})
    message = str(exc.value)
    assert "refuting_mechanism" in message
    assert "audit.py pivot" in message, (
        "the error must name the verb that supplies the fields, or the "
        "operator's next move is to work around the rule")


def test_a_false_positive_without_an_enabled_observation_is_rejected(tmp_path):
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_fp_verdicts",
               {"finding_id": "G1-F1", "verdict": "FALSE_POSITIVE",
                "refuting_mechanism": "300-byte sliding-window flush"})
    assert "enabled_observation" in str(exc.value)


def test_a_true_positive_needs_neither(tmp_path):
    """The rule is about false positives. A true positive that carried the
    same requirement would make every verdict cost an observation."""
    con = fresh(tmp_path)
    db.put(con, "cba_fp_verdicts",
           {"finding_id": "G1-F1", "verdict": "TRUE_POSITIVE"})


def test_an_unknown_verdict_is_still_rejected(tmp_path):
    """The vocabulary check that one_of() used to do must survive its
    replacement -- this is the regression the swap can silently cause."""
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_fp_verdicts",
               {"finding_id": "G1-F1", "verdict": "PROBABLY"})
    assert "PROBABLY" in str(exc.value)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_pivot.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.pivot'`.

- [ ] **Step 3: Replace the verdict validator in `db.py`**

Add beside `_validate_pattern`:

```python
def _validate_verdict(row: dict[str, str]) -> None:
    """Spec section 3.5: a FALSE_POSITIVE must say what refuted it, and what
    that mechanism enables.

    From the tplink post-mortem: a finding was correctly refuted by a
    300-byte sliding-window flush, and that flush is the attack surface for a
    reference-set CRITICAL. The verdict schema recorded the refutation and
    nothing else, so the pivot was never taken.

    The requirement is unconditional. A refuting mechanism is code, and code
    does something; "no attacker-controlled path identified in this review"
    is a legitimate answer and a useful rung-1 observation. A blank is not.
    """
    verdict = row.get("verdict")
    if verdict not in VERDICTS:
        raise DbError(f"verdict={verdict!r} is not one of {', '.join(VERDICTS)}")
    if verdict != "FALSE_POSITIVE":
        return
    missing = [c for c in ("refuting_mechanism", "enabled_observation")
               if not str(row.get(c, "") or "").strip()]
    if missing:
        raise DbError(
            f"a FALSE_POSITIVE verdict requires {', '.join(missing)}: what "
            f"refuted the finding, and the id of the observation recording "
            f"what that mechanism enables. Write both with "
            f"`audit.py pivot --db <db> --finding {row.get('finding_id', '<id>')} "
            f"--group <group> --mechanism '<what refuted it>' "
            f"--enables '<what it enables, or what was ruled out>'`, which "
            f"records the observation and the verdict together.")
```

Then change `cba_fp_verdicts`'s spec:

```python
    "cba_fp_verdicts": TableSpec(
        columns=("finding_id", "verdict", "reason", "final_severity", "final_id",
                 "merged_into", "rule_applied", "refuting_mechanism",
                 "enabled_observation", "reviewed_at"),
        required=("finding_id", "verdict"),
        validate=_validate_verdict),
```

- [ ] **Step 4: Run the validator tests**

Run: `python3 -m pytest tests/test_pivot.py -q`
Expected: the four validator tests PASS; the module import at the top still fails. Remove the `pivot` import temporarily if you want a clean run, or go straight to Step 5.

- [ ] **Step 5: Write the failing tests for `pivot.record`**

Append to `tests/test_pivot.py`:

```python
def test_record_writes_the_observation_and_the_verdict_together(tmp_path):
    con = fresh(tmp_path)
    p = pivot.record(
        con, finding_id="G1-F1", group_id="G1",
        mechanism="300-byte sliding-window flush in recv_loop",
        enables="the flush itself takes an attacker-sized length at recv.c:214",
        reason="the copy is bounded by the window", rule_applied="HE-1")
    assert p.finding_id == "G1-F1"
    assert p.observation_id > 0

    verdict = db.rows(con, "cba_fp_verdicts", where={"finding_id": "G1-F1"})[0]
    assert verdict["verdict"] == "FALSE_POSITIVE"
    assert verdict["refuting_mechanism"].startswith("300-byte")
    assert verdict["enabled_observation"] == str(p.observation_id)

    obs = db.rows(con, "cba_security_observations",
                  where={"id": str(p.observation_id)})[0]
    assert "attacker-sized length" in obs["observation"]
    assert obs["group_id"] == "G1"


def test_record_refuses_a_finding_that_already_has_a_verdict(tmp_path):
    """Checked before anything is written. db.put commits, so an observation
    written ahead of a verdict that then fails would be orphaned."""
    con = fresh(tmp_path)
    db.put(con, "cba_fp_verdicts",
           {"finding_id": "G1-F1", "verdict": "TRUE_POSITIVE"})
    before = len(db.rows(con, "cba_security_observations"))
    with pytest.raises(db.DbError) as exc:
        pivot.record(con, finding_id="G1-F1", group_id="G1",
                     mechanism="m", enables="e")
    assert "--replace" in str(exc.value)
    assert len(db.rows(con, "cba_security_observations")) == before


def test_record_rejects_an_empty_mechanism_before_writing_anything(tmp_path):
    con = fresh(tmp_path)
    before = len(db.rows(con, "cba_security_observations"))
    with pytest.raises(db.DbError):
        pivot.record(con, finding_id="G1-F1", group_id="G1",
                     mechanism="   ", enables="e")
    assert len(db.rows(con, "cba_security_observations")) == before


def test_record_rejects_a_finding_that_does_not_exist(tmp_path):
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        pivot.record(con, finding_id="G9-F9", group_id="G1",
                     mechanism="m", enables="e")
    assert "G9-F9" in str(exc.value)


def test_dangling_finds_a_verdict_whose_observation_was_deleted(tmp_path):
    con = fresh(tmp_path)
    p = pivot.record(con, finding_id="G1-F1", group_id="G1",
                     mechanism="m", enables="e")
    assert pivot.dangling(con) == []
    con.execute("DELETE FROM cba_security_observations WHERE id = ?",
                (p.observation_id,))
    con.commit()
    assert pivot.dangling(con) == [("G1-F1", str(p.observation_id))]
```

- [ ] **Step 6: Write `audit_core/pivot.py`**

```python
"""Write a FALSE_POSITIVE verdict and the observation it pivots to, together.

Spec section 3.5: a FALSE_POSITIVE verdict is invalid unless it records what
refuted the finding and what that mechanism enables, and the latter is
written back as a rung-1 observation.

The two writes are one act because separating them is how the pivot gets
lost: the verdict is the thing the phase gate counts, so a verdict written
first and an observation "to follow" is an observation nobody writes. The
validator in db.py refuses the verdict without the observation id, and this
module is what produces one.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from audit_core import db


@dataclass(frozen=True, slots=True)
class Pivot:
    finding_id: str
    observation_id: int
    mechanism: str


def record(con: sqlite3.Connection, *, finding_id: str, group_id: str,
           mechanism: str, enables: str, reason: str = "",
           rule_applied: str = "", severity_hint: str = "",
           location: str = "", replace: bool = False) -> Pivot:
    """Record the observation, then the verdict that points at it.

    Everything that can fail is checked before the first write. `db.put`
    commits each row on its own, so a verdict that failed after the
    observation landed would leave an observation referenced by nothing -
    recoverable, but it would make `dangling()` report a problem that is not
    one. Checking first costs two queries and removes the case.
    """
    mechanism = (mechanism or "").strip()
    enables = (enables or "").strip()
    if not mechanism:
        raise db.DbError("a pivot needs --mechanism: what refuted the finding")
    if not enables:
        raise db.DbError(
            "a pivot needs --enables: what the refuting mechanism makes "
            "possible, or what this review ruled out about it. "
            "'no attacker-controlled path identified in this review' is a "
            "legitimate answer; a blank is not.")
    if not db.rows(con, "cba_findings", where={"id": finding_id},
                   columns=("id",)):
        raise db.DbError(f"no finding {finding_id!r} to pivot from")
    if not replace and db.rows(con, "cba_fp_verdicts",
                               where={"finding_id": finding_id},
                               columns=("finding_id",)):
        raise db.DbError(f"{finding_id} already has a verdict; "
                         f"pass --replace to overwrite it")

    db.put(con, "cba_security_observations", {
        "group_id": group_id,
        "observation": f"Pivot from {finding_id}: {mechanism} -- {enables}",
        "severity_hint": severity_hint or "",
        "location": location or ""})
    observation_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])

    db.put(con, "cba_fp_verdicts", {
        "finding_id": finding_id, "verdict": "FALSE_POSITIVE",
        "reason": reason or "", "rule_applied": rule_applied or "",
        "refuting_mechanism": mechanism,
        "enabled_observation": str(observation_id)}, replace=replace)

    return Pivot(finding_id=finding_id, observation_id=observation_id,
                 mechanism=mechanism)


def dangling(con: sqlite3.Connection) -> list[tuple[str, str]]:
    """FALSE_POSITIVE verdicts whose enabled_observation resolves to nothing.

    The validator checks that the field is non-empty; it has no connection,
    so it cannot check that the id exists. This is that check, run on demand
    rather than on every write.
    """
    return [(r[0], str(r[1])) for r in con.execute(
        "SELECT v.finding_id, v.enabled_observation FROM cba_fp_verdicts v "
        "LEFT JOIN cba_security_observations o "
        "  ON CAST(o.id AS TEXT) = CAST(v.enabled_observation AS TEXT) "
        "WHERE v.verdict = 'FALSE_POSITIVE' AND o.id IS NULL "
        "ORDER BY v.finding_id")]


def render(p: Pivot) -> str:
    return (f"pivot {p.finding_id}: FALSE_POSITIVE recorded, "
            f"observation {p.observation_id} written.\n"
            f"  refuting mechanism: {p.mechanism}\n"
            f"  The observation is a lead, not a finding. Read it with "
            f"`audit.py rows --table cba_security_observations "
            f"--where id={p.observation_id}`.")
```

- [ ] **Step 7: Run the pivot tests**

Run: `python3 -m pytest tests/test_pivot.py -q`
Expected: PASS, 9 tests.

- [ ] **Step 8: Add the `pivot` verb and its CLI tests**

Create `tests/test_cli_stage3.py` with the `tests/test_cli_stage2.py` idiom — `subprocess.run` against `audit.py`, a `new_run` helper, exit codes and stderr asserted:

```python
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FINDING_ARGS = [
    "--set", "id=G1-F1", "--set", "group_id=G1", "--set", "title=t",
    "--set", "severity=HIGH", "--set", "confidence=9",
    "--set", "location=src/recv.c:120", "--set", "root_cause=rc",
    "--set", "impact=im",
]


def run(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), *args],
        capture_output=True, text=True,
    )


def new_run(tmp_path):
    r = run("init", "--root", str(tmp_path), "--timestamp", "20260105-120000")
    assert r.returncode == 0, r.stderr
    return pathlib.Path(r.stdout.strip().splitlines()[-1])


def seeded(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    assert run("put", "--db", db, "--table", "cba_findings",
               *FINDING_ARGS).returncode == 0
    return db


def test_pivot_writes_the_verdict_and_the_observation(tmp_path):
    db = seeded(tmp_path)
    r = run("pivot", "--db", db, "--finding", "G1-F1", "--group", "G1",
            "--mechanism", "300-byte sliding-window flush",
            "--enables", "the flush takes an attacker-sized length")
    assert r.returncode == 0, r.stderr
    assert "FALSE_POSITIVE recorded" in r.stdout

    rows = run("rows", "--db", db, "--table", "cba_fp_verdicts", "--json")
    assert "300-byte sliding-window flush" in rows.stdout
    obs = run("rows", "--db", db, "--table", "cba_security_observations", "--json")
    assert "attacker-sized length" in obs.stdout


def test_put_rejects_a_bare_false_positive_and_points_at_pivot(tmp_path):
    """Review Focus 2: the path references/phase5-fp-check.md documents."""
    db = seeded(tmp_path)
    r = run("put", "--db", db, "--table", "cba_fp_verdicts",
            "--set", "finding_id=G1-F1", "--set", "verdict=FALSE_POSITIVE")
    assert r.returncode == 1
    assert "refuting_mechanism" in r.stderr
    assert "audit.py pivot" in r.stderr


def test_pivot_check_reports_a_dangling_observation(tmp_path):
    db = seeded(tmp_path)
    assert run("pivot", "--db", db, "--finding", "G1-F1", "--group", "G1",
               "--mechanism", "m", "--enables", "e").returncode == 0
    r = run("pivot", "--db", db, "--check")
    assert r.returncode == 0, r.stderr
    assert "0 dangling" in r.stdout


def test_pivot_on_an_unknown_finding_exits_one(tmp_path):
    db = seeded(tmp_path)
    r = run("pivot", "--db", db, "--finding", "G9-F9", "--group", "G1",
            "--mechanism", "m", "--enables", "e")
    assert r.returncode == 1
    assert "G9-F9" in r.stderr
```

In `audit.py`, add the import `from audit_core import pivot as pivot_mod  # noqa: E402` beside the others, then the handler:

```python
def cmd_pivot(args: argparse.Namespace) -> int:
    con = _open_db(args.db)
    if con is None:
        return 1
    try:
        if args.check:
            bad = pivot_mod.dangling(con)
            for finding_id, obs in bad:
                print(f"  {finding_id}: enabled_observation={obs} resolves to "
                      f"no row in cba_security_observations")
            print(f"pivot: {len(bad)} dangling observation reference(s)")
            return 1 if bad else 0
        for name in ("finding", "group", "mechanism", "enables"):
            if not (getattr(args, name) or "").strip():
                print(f"--{name} is required unless --check is given",
                      file=sys.stderr)
                return 1
        p = pivot_mod.record(
            con, finding_id=args.finding, group_id=args.group,
            mechanism=args.mechanism, enables=args.enables,
            reason=args.reason or "", rule_applied=args.rule or "",
            severity_hint=args.severity_hint or "",
            location=args.location or "", replace=args.replace)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    print(pivot_mod.render(p))
    return 0
```

`HANDLERS` gains `"pivot": cmd_pivot,`. `build_parser` gains:

```python
    pv = sub.add_parser("pivot", help="record a FALSE_POSITIVE and the observation it pivots to")
    pv.add_argument("--db", required=True, metavar="AUDIT_DB")
    pv.add_argument("--finding", default=None, metavar="FINDING_ID")
    pv.add_argument("--group", default=None, metavar="GROUP_ID")
    pv.add_argument("--mechanism", default=None,
                    help="what refuted the finding")
    pv.add_argument("--enables", default=None,
                    help="what that mechanism makes possible, or what this "
                         "review ruled out about it")
    pv.add_argument("--reason", default=None)
    pv.add_argument("--rule", default=None, metavar="HE-n/PR-n/CV-n")
    pv.add_argument("--severity-hint", default=None)
    pv.add_argument("--location", default=None)
    pv.add_argument("--replace", action="store_true")
    pv.add_argument("--check", action="store_true",
                    help="list verdicts whose enabled_observation does not resolve")
```

- [ ] **Step 9: Run the CLI tests and the whole suite**

Run: `python3 -m pytest tests/test_cli_stage3.py -q && python3 -m pytest -q && python3 audit.py selftest`
Expected: all PASS; `selftest` reports 17 verbs.

- [ ] **Step 10: Commit**

```bash
git add audit_core/pivot.py audit_core/db.py audit.py \
        tests/test_pivot.py tests/test_cli_stage3.py
git commit -m "$(cat <<'MSG'
feat: a FALSE_POSITIVE must say what refuted it and what that enables

Spec 3.5. From the tplink post-mortem: a finding was correctly refuted by a
300-byte sliding-window flush, and that flush is the attack surface for a
reference-set CRITICAL. The verdict schema recorded the refutation and
nothing else.

The requirement is unconditional -- a refuting mechanism is code, and code
does something. "No attacker-controlled path identified in this review" is a
legitimate observation; a blank is not. `audit.py pivot` writes the
observation and the verdict together, because a verdict written first and an
observation to follow is an observation nobody writes.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 3: Sweep-on-confirm

Spec §3.5.2: "Confirming a bug pattern registers it in `patterns` and triggers a corpus-wide sweep by a cheap model."

The tplink miss: `strncpy(dst, src, strlen(src))` was found twice, recognised as a pattern, and never grepped for. Two reference CRITICALs are that pattern elsewhere.

Stage 2 shipped the mechanism — `cba_patterns`, `cba_pattern_hits`, `audit.py sweep`. What it did not ship is any way to tell whether a registered pattern was ever swept. This task adds that, and makes the unswept set a gate a phase can check.

**The gate is per-pattern, not per-finding.** "Is this finding's root cause a pattern?" is a judgment a script cannot make, and a rule that guessed would fire on every finding and be switched off. "This pattern is registered and has never been swept" is a fact, and it is the fact that was true of `strncpy(dst, src, strlen(src))` for the whole tplink run.

**Files:**
- Create: `audit_core/patterns.py`
- Create: `tests/test_patterns.py`
- Modify: `audit_core/sweep.py` (`record`)
- Modify: `audit.py` (`cmd_patterns`, `cmd_sweep`, `HANDLERS`, `build_parser`)
- Modify: `tests/test_sweep.py`
- Modify: `tests/test_cli_stage3.py`

**Interfaces:**
- Consumes: `db.put`, `db.rows`, `db.DbError`, `sweep.SweepResult`.
- Produces:
  - `patterns.PatternState` — frozen dataclass: `id`, `name`, `origin_finding`, `swept_at`, `hit_count`; property `swept -> bool`.
  - `patterns.MAX_PATTERNS = 200`
  - `patterns.states(con) -> list[PatternState]`
  - `patterns.unswept(con) -> list[PatternState]`
  - `patterns.mark_swept(con, pattern_id: str, *, hit_count: int, when: str | None = None) -> None`
  - `patterns.render(states: list[PatternState]) -> str`
- `sweep.record(con, result)` now also calls `patterns.mark_swept`, and raises `db.DbError` on a truncated result.

- [ ] **Step 1: Write the failing tests for pattern state**

Create `tests/test_patterns.py`:

```python
import pytest

from audit_core import db, patterns, workspace


def fresh(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = db.connect(run / "audit.db")
    db.put(con, "cba_patterns", {
        "id": "P1", "name": "strncpy with strlen of source",
        "regex": r"strncpy\s*\([^,]+,\s*([^,]+),\s*strlen\(\s*\1\s*\)",
        "origin_finding": "G1-F1"})
    return con


def test_a_newly_registered_pattern_is_unswept(tmp_path):
    con = fresh(tmp_path)
    states = patterns.states(con)
    assert len(states) == 1
    assert states[0].id == "P1"
    assert states[0].swept is False
    assert states[0].hit_count == 0
    assert [s.id for s in patterns.unswept(con)] == ["P1"]


def test_mark_swept_records_the_time_and_the_count(tmp_path):
    con = fresh(tmp_path)
    patterns.mark_swept(con, "P1", hit_count=7, when="2026-10-05 12:00:00")
    state = patterns.states(con)[0]
    assert state.swept is True
    assert state.swept_at == "2026-10-05 12:00:00"
    assert state.hit_count == 7
    assert patterns.unswept(con) == []


def test_a_sweep_that_found_nothing_still_counts_as_swept(tmp_path):
    """Zero hits is a result. Treating it as unswept would make the gate
    unclearable for exactly the patterns that turned out to be isolated --
    and would push an operator to narrow a pattern until it matched
    something, which is the opposite of what a sweep is for."""
    con = fresh(tmp_path)
    patterns.mark_swept(con, "P1", hit_count=0)
    assert patterns.unswept(con) == []
    assert patterns.states(con)[0].hit_count == 0


def test_mark_swept_on_an_unknown_pattern_is_an_error(tmp_path):
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        patterns.mark_swept(con, "P9", hit_count=1)
    assert "P9" in str(exc.value)


def test_render_names_the_sweep_command_for_each_unswept_pattern(tmp_path):
    con = fresh(tmp_path)
    out = patterns.render(patterns.states(con))
    assert "P1" in out
    assert "audit.py sweep" in out
    assert "1 unswept" in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_patterns.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.patterns'`.

- [ ] **Step 3: Write `audit_core/patterns.py`**

```python
"""Which registered bug patterns have been swept, and which have not.

A confirmed finding is evidence about one call site and a hypothesis about
every other one. The tplink run confirmed `strncpy(dst, src, strlen(src))`
twice, named it as a pattern, and never grepped for it; two reference-set
CRITICALs are that pattern elsewhere.

Stage 2 shipped the sweep. This is the accounting that makes "we swept the
patterns we confirmed" a checkable claim instead of a recollection. The unit
is the pattern, not the finding: whether a given finding's root cause
generalises is a judgment, and a rule that guessed would fire on everything.
Whether a registered pattern has ever been swept is a fact.
"""
from __future__ import annotations

import datetime
import sqlite3
from dataclasses import dataclass

from audit_core import db

MAX_PATTERNS = 200


@dataclass(frozen=True, slots=True)
class PatternState:
    id: str
    name: str
    origin_finding: str
    swept_at: str
    hit_count: int

    @property
    def swept(self) -> bool:
        """Swept means a sweep ran, not that it found something. Zero hits is
        a result: the pattern was isolated."""
        return bool(self.swept_at)


def states(con: sqlite3.Connection) -> list[PatternState]:
    rows = db.rows(con, "cba_patterns",
                   columns=("id", "name", "origin_finding", "swept_at",
                            "hit_count"),
                   limit=MAX_PATTERNS)
    return [PatternState(id=r["id"], name=r["name"] or "",
                         origin_finding=r["origin_finding"] or "",
                         swept_at=r["swept_at"] or "",
                         hit_count=int(r["hit_count"] or 0))
            for r in rows]


def unswept(con: sqlite3.Connection) -> list[PatternState]:
    return [s for s in states(con) if not s.swept]


def mark_swept(con: sqlite3.Connection, pattern_id: str, *,
               hit_count: int, when: str | None = None) -> None:
    """Record that `pattern_id` was swept, and how many hits it produced.

    A partial UPDATE, which `db.put` cannot express - `put` writes whole
    rows. Writing it here rather than in a workflow is the point of R5: this
    is the only place the statement exists, and the column names are
    literals in this module rather than something an orchestrator retypes.
    """
    if not db.rows(con, "cba_patterns", where={"id": pattern_id},
                   columns=("id",)):
        raise db.DbError(
            f"no pattern {pattern_id!r} to mark swept; register one with "
            f"`audit.py put --table cba_patterns --set id=... --set name=... "
            f"--set regex=...`")
    stamp = when or datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    con.execute("UPDATE cba_patterns SET swept_at = ?, hit_count = ? "
                "WHERE id = ?", (stamp, int(hit_count), pattern_id))
    con.commit()


def render(items: list[PatternState]) -> str:
    if not items:
        return ("patterns: none registered.\n"
                "  A confirmed finding whose root cause could appear "
                "elsewhere is a pattern. Register it with `audit.py put "
                "--table cba_patterns --set id=P1 --set name=... "
                "--set regex=... --set origin_finding=<finding-id>`.")
    gaps = [s for s in items if not s.swept]
    out = [f"patterns: {len(items)} registered, {len(gaps)} unswept"]
    for s in items:
        mark = "swept" if s.swept else "NEVER SWEPT"
        origin = f" from {s.origin_finding}" if s.origin_finding else ""
        out.append(f"  {s.id:6s} {s.name:40.40s} {mark:11s} "
                   f"{s.hit_count} hit(s){origin}")
    if gaps:
        out.append("  Sweep each one before the phase exits:")
        out.extend(f"    audit.py sweep --db <db> --pattern {s.id} "
                   f"--root <src> --record" for s in gaps)
        out.append("  A confirmed pattern that was never swept is the tplink "
                   "miss exactly: strncpy(dst, src, strlen(src)) was found "
                   "twice, named, and never grepped for.")
    return "\n".join(out)
```

- [ ] **Step 4: Run the pattern tests**

Run: `python3 -m pytest tests/test_patterns.py -q`
Expected: PASS, 5 tests.

- [ ] **Step 5: Write the failing tests for sweep integration**

Review Focus 3 lives here. `tests/test_sweep.py` already has a `con` pytest fixture (a run database with pattern `P1` registered, built under `tmp_path / "ws"`) and a `tree(root, **files)` helper. Use both; add `patterns` to that file's `from audit_core import ...` line. Append:

```python
REGEX = r"strncpy\([^,]+,[^,]+,\s*strlen\("


def test_record_marks_the_pattern_swept(con, tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "strncpy(dst, src, strlen(src));\n",
        "b.c": "strncpy(d2, s2, strlen(s2));\n",
    })
    result = sweep.run(root, REGEX, pattern_id="P1")
    assert sweep.record(con, result) == 2
    state = patterns.states(con)[0]
    assert state.swept is True
    assert state.hit_count == 2


def test_record_refuses_a_truncated_sweep(con, tmp_path):
    """Review Focus 3. A sweep that stopped at its cap does not know what it
    did not see. Marking that pattern swept is a false coverage claim about
    the one mechanism whose whole value is breadth -- and the pattern would
    then never appear in `patterns.unswept` again."""
    root = tree(tmp_path / "src", **{
        "a.c": "strncpy(dst, src, strlen(src));\n",
        "b.c": "strncpy(d2, s2, strlen(s2));\n",
    })
    result = sweep.run(root, REGEX, pattern_id="P1", max_hits=1)
    assert result.truncated is True
    with pytest.raises(db.DbError) as exc:
        sweep.record(con, result)
    assert "truncated" in str(exc.value).lower()
    assert patterns.states(con)[0].swept is False
    assert db.rows(con, "cba_pattern_hits") == []
```

The second assertion of the last test is the important one: a refused record must write **no** hits either, so the implementer must check before the write loop, not inside it.

- [ ] **Step 6: Run to verify they fail**

Run: `python3 -m pytest tests/test_sweep.py -q`
Expected: FAIL — `record` neither marks swept nor refuses.

- [ ] **Step 7: Change `sweep.record`**

In `audit_core/sweep.py`, add `from audit_core import patterns` beside the `db` import — `patterns` imports `db` and nothing else, so there is no cycle — and replace `record`:

```python
def record(con: sqlite3.Connection, result: SweepResult) -> int:
    """Write one `cba_pattern_hits` row per hit, and mark the pattern swept.

    A truncated sweep is refused outright, before any hit is written. The
    sweep stopped at its cap, so it does not know what it did not see;
    recording it would both store a partial hit list and set `swept_at`,
    after which the pattern never appears in `patterns.unswept` again. The
    bad outcome is silent and permanent, so the check is a refusal.
    """
    if not result.pattern_id:
        raise db.DbError("a sweep result with no pattern_id cannot be "
                         "recorded; pass pattern_id= to sweep.run()")
    if result.truncated:
        raise db.DbError(
            f"refusing to record a truncated sweep of {result.pattern_id}: it "
            f"stopped at {len(result.hits)} hits and does not know what it "
            f"did not see. Narrow the pattern, or sweep a subtree, and run "
            f"it again.")
    for hit in result.hits:
        db.put(con, "cba_pattern_hits", {
            "pattern_id": result.pattern_id, "path": hit.path,
            "line": str(hit.line), "excerpt": hit.excerpt})
    patterns.mark_swept(con, result.pattern_id, hit_count=len(result.hits))
    return len(result.hits)
```

- [ ] **Step 8: Remove the duplicated truncation check from `cmd_sweep`**

`audit.py`'s `cmd_sweep` currently carries its own pre-check. Two copies of one rule is how they drift. Delete these three lines:

```python
            if result.truncated:
                print("refusing to record a truncated sweep; narrow the "
                      "pattern first", file=sys.stderr)
                return 1
```

leaving:

```python
        if args.record:
            print(f"recorded {sweep_mod.record(con, result)} hit(s)")
```

The `except db_mod.DbError` already in the function prints the library's message and returns 1, which is strictly more informative than the line removed — it names the pattern and the hit count.

- [ ] **Step 9: Add the `patterns` verb**

In `audit.py`, import `from audit_core import patterns as patterns_mod  # noqa: E402`, then:

```python
def cmd_patterns(args: argparse.Namespace) -> int:
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        items = patterns_mod.states(con)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    if args.json:
        print(json.dumps([dataclasses.asdict(s) | {"swept": s.swept}
                          for s in items], indent=2))
    else:
        print(patterns_mod.render(items))
    if args.gate:
        gaps = [s for s in items if not s.swept]
        return 1 if gaps else 0
    return 0
```

`HANDLERS` gains `"patterns": cmd_patterns,`. `build_parser` gains:

```python
    pt = sub.add_parser("patterns", help="sweep state for every registered bug pattern")
    pt.add_argument("--db", required=True, metavar="AUDIT_DB")
    pt.add_argument("--gate", action="store_true",
                    help="exit 1 if any registered pattern has never been swept")
    pt.add_argument("--json", action="store_true")
```

- [ ] **Step 10: Write the CLI tests**

Append to `tests/test_cli_stage3.py`:

```python
PATTERN_ARGS = [
    "--set", "id=P1", "--set", "name=strncpy with strlen of source",
    "--set", "regex=strncpy", "--set", "origin_finding=G1-F1",
]


def test_patterns_gate_fails_on_an_unswept_pattern(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_patterns",
               *PATTERN_ARGS).returncode == 0
    r = run("patterns", "--db", db, "--gate")
    assert r.returncode == 1
    assert "NEVER SWEPT" in r.stdout
    assert "audit.py sweep" in r.stdout


def test_patterns_gate_passes_once_the_pattern_is_swept(tmp_path, tmp_path_factory):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_patterns",
               *PATTERN_ARGS).returncode == 0
    src = tmp_path_factory.mktemp("src")
    (src / "a.c").write_text("strncpy(d, s, strlen(s));\n")
    assert run("sweep", "--db", db, "--pattern", "P1",
               "--root", str(src), "--record").returncode == 0
    r = run("patterns", "--db", db, "--gate")
    assert r.returncode == 0, r.stdout
    assert "0 unswept" in r.stdout


def test_patterns_gate_passes_when_nothing_is_registered(tmp_path):
    """No registered pattern is not a failure. A run that confirmed no
    generalisable pattern has nothing to sweep, and a gate that failed there
    would push an operator to register a junk pattern to clear it."""
    db = seeded(tmp_path)
    r = run("patterns", "--db", db, "--gate")
    assert r.returncode == 0
    assert "none registered" in r.stdout
```

- [ ] **Step 11: Run everything**

Run: `python3 -m pytest -q && python3 audit.py selftest`
Expected: PASS; `selftest` reports 18 verbs.

- [ ] **Step 12: Commit**

```bash
git add audit_core/patterns.py audit_core/sweep.py audit.py \
        tests/test_patterns.py tests/test_sweep.py tests/test_cli_stage3.py
git commit -m "$(cat <<'MSG'
feat: a registered pattern that was never swept is a reportable gap

Spec 3.5. strncpy(dst, src, strlen(src)) was found twice in the tplink run,
named as a pattern, and never grepped for; two reference-set CRITICALs are
that pattern elsewhere. Stage 2 shipped the sweep and no way to tell whether
one had happened.

The unit is the pattern, not the finding: whether a finding's root cause
generalises is a judgment a script cannot make, and a rule that guessed would
fire on everything and be switched off.

sweep.record now refuses a truncated result outright, before writing any
hits -- a capped sweep does not know what it did not see, and recording it
would set swept_at, after which the pattern never surfaces again.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 4: Coverage as a gate

Spec §3.5.3: "`not_audited` rows with reasons are mandatory. 'Have we audited everything' is answered by `audit.py coverage`." Spec §R3's anti-rationalization rule: "A group skipped for budget is a `not_audited(reason='budget')` row and **fails the quality gate**."

Stage 2 shipped the recording and the report, and said in `audit_core/coverage.py`'s own module docstring that gating is Stage 3's. This is that.

Ruling S3 applies: the gate is a command, not a block. Nothing in `audit_core` refuses to run because coverage is incomplete.

**Files:**
- Modify: `audit_core/coverage.py`
- Modify: `audit.py` (`cmd_coverage`, `build_parser`)
- Modify: `tests/test_coverage.py`
- Modify: `tests/test_cli_stage3.py`

**Interfaces:**
- Consumes: `coverage.CoverageReport`, `coverage.report`, `db.NOT_AUDITED_REASONS`.
- Produces:
  - `coverage.GateResult` — frozen dataclass: `ok: bool`, `failures: tuple[str, ...]`, `warnings: tuple[str, ...]`.
  - `coverage.gate(r: CoverageReport) -> GateResult`
  - `coverage.render_gate(g: GateResult) -> str`

- [ ] **Step 1: Write the failing gate tests**

Review Focus 4 is the second test here. `tests/test_coverage.py` already has a `con` pytest fixture (an initialised run database) and an `inventory(con, *units, kind="file")` helper. Use both. Append:

```python
def test_a_fully_analyzed_run_passes(con):
    inventory(con, "src/a.c")
    db.put(con, "cba_coverage", {"unit": "src/a.c", "phase": "audit",
                                 "state": "analyzed"})
    g = coverage.gate(coverage.report(con))
    assert g.ok is True
    assert g.failures == ()


def test_an_empty_inventory_fails_the_gate(con):
    """Review Focus 4. fraction is 0.0 with nothing inventoried, and the
    Stage 2 render says there is no denominator. A gate reading `0 budget
    skips, 0 unrecorded` and passing would pass hardest on the run that did
    the least."""
    g = coverage.gate(coverage.report(con))
    assert g.ok is False
    assert any("inventory" in f for f in g.failures)


def test_a_budget_skip_fails_the_gate(con):
    inventory(con, "src/a.c")
    db.put(con, "cba_coverage", {"unit": "src/a.c", "phase": "audit",
                                 "state": "not_audited", "reason": "budget"})
    g = coverage.gate(coverage.report(con))
    assert g.ok is False
    assert any("budget" in f for f in g.failures)
    assert any("checkpoint" in f.lower() for f in g.failures), (
        "the failure must name the remedy; R3 answers a budget skip with "
        "checkpoint-and-restart, never with skipping")


def test_an_inventoried_unit_with_no_coverage_row_fails_the_gate(con):
    """The silent case the whole mechanism exists for: a unit nobody ever
    recorded a decision about. Six of ten missed tplink CRITICALs are on
    surfaces that were never opened and never written down."""
    inventory(con, "src/a.c", "src/wifi.c")
    db.put(con, "cba_coverage", {"unit": "src/a.c", "phase": "audit",
                                 "state": "analyzed"})
    g = coverage.gate(coverage.report(con))
    assert g.ok is False
    assert any("unrecorded" in f for f in g.failures)


def test_a_recorded_non_budget_skip_warns_but_passes(con):
    """out-of-scope, vendored and the rest are decisions, recorded with
    reasons -- which is what the mechanism asks for. Failing on them would
    make the gate unclearable on any real target."""
    inventory(con, "vendor/lib.c")
    db.put(con, "cba_coverage", {"unit": "vendor/lib.c", "phase": "audit",
                                 "state": "not_audited", "reason": "vendored"})
    g = coverage.gate(coverage.report(con))
    assert g.ok is True
    assert any("vendored" in w for w in g.warnings)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_coverage.py -q`
Expected: FAIL — `AttributeError: module 'audit_core.coverage' has no attribute 'gate'`.

- [ ] **Step 3: Add `GateResult`, `gate` and `render_gate` to `coverage.py`**

Append to `audit_core/coverage.py`, and change the module docstring's last paragraph from "Stage 2 records and reports. Nothing here fails a run: gating on coverage is a Stage 3 quality change…" to state what is now true:

```python
@dataclass(frozen=True, slots=True)
class GateResult:
    ok: bool
    failures: tuple[str, ...]
    warnings: tuple[str, ...]


def gate(r: CoverageReport) -> GateResult:
    """Decide whether a phase's coverage is good enough to exit on.

    Three failures, and each one is a case where the record cannot support
    the claim "we audited everything":

    - Nothing inventoried. There is no denominator, so there is no claim.
      This is the vacuous pass: a run that never inventoried anything has
      zero budget skips and zero unrecorded units.
    - A unit skipped for budget. Spec R3, verbatim: a group skipped for
      budget "fails the quality gate". The budget governs where tokens are
      spent, never whether a surface is opened.
    - An inventoried unit with no coverage row. The silent case - nobody
      recorded a decision either way. Six of the ten missed tplink CRITICALs
      are on surfaces that were never opened and never written down.

    Everything else recorded as `not_audited` is a warning, not a failure.
    out-of-scope, vendored, generated and the rest are decisions, taken and
    written down, which is exactly what section 3.5 asks for. Failing on them
    would make the gate unclearable on any real target, and an unclearable
    gate gets turned off.
    """
    failures: list[str] = []
    warnings: list[str] = []
    scope = f" (phase {r.phase})" if r.phase else ""

    if r.inventoried == 0:
        failures.append(
            f"the inventory is empty{scope}, so there is no coverage "
            f"denominator. Populate it with `audit.py put --table "
            f"cba_inventory --set unit=<path> --set kind=file` per "
            f"analysable unit.")
    if r.budget_skips:
        failures.append(
            f"{r.budget_skips} unit(s) recorded not_audited(reason='budget'). "
            f"The budget governs where tokens are spent, never whether a "
            f"surface is opened: checkpoint and restart "
            f"(`audit.py checkpoint`), then audit them.")
    if r.unrecorded:
        failures.append(
            f"{r.unrecorded} inventoried unit(s) have no coverage row"
            f"{scope}. Record one per unit: state=analyzed, or "
            f"state=not_audited with a reason from {', '.join(NOT_AUDITED_REASONS)}.")

    for reason, n in r.by_reason:
        if reason != "budget":
            warnings.append(f"{n} unit(s) not_audited(reason='{reason}')")

    return GateResult(ok=not failures, failures=tuple(failures),
                      warnings=tuple(warnings))


def render_gate(g: GateResult) -> str:
    out = ["coverage gate: " + ("PASS" if g.ok else "FAIL")]
    out.extend(f"  FAIL  {f}" for f in g.failures)
    out.extend(f"  warn  {w}" for w in g.warnings)
    return "\n".join(out)
```

- [ ] **Step 4: Run the gate tests**

Run: `python3 -m pytest tests/test_coverage.py -q`
Expected: PASS.

- [ ] **Step 5: Add `--gate` to the `coverage` verb**

In `audit.py`'s `cmd_coverage`, after the existing render:

```python
    if args.json:
        payload = dataclasses.asdict(r) | {"fraction": r.fraction}
        if args.gate:
            payload["gate"] = dataclasses.asdict(coverage_mod.gate(r))
        print(json.dumps(payload, indent=2))
    else:
        print(coverage_mod.render(r))
    if args.gate:
        g = coverage_mod.gate(r)
        if not args.json:
            print(coverage_mod.render_gate(g))
        return 0 if g.ok else 1
    return 0
```

`build_parser`'s `cv` block gains:

```python
    cv.add_argument("--gate", action="store_true",
                    help="exit 1 if coverage cannot support a phase exit")
```

- [ ] **Step 6: Write the CLI tests**

Append to `tests/test_cli_stage3.py`:

```python
def test_coverage_gate_exits_one_on_a_budget_skip(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_inventory",
               "--set", "unit=src/wifi.c", "--set", "kind=file").returncode == 0
    assert run("put", "--db", db, "--table", "cba_coverage",
               "--set", "unit=src/wifi.c", "--set", "phase=audit",
               "--set", "state=not_audited",
               "--set", "reason=budget").returncode == 0
    r = run("coverage", "--db", db, "--gate")
    assert r.returncode == 1
    assert "coverage gate: FAIL" in r.stdout
    assert "checkpoint" in r.stdout


def test_coverage_gate_exits_zero_on_a_fully_analyzed_run(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_inventory",
               "--set", "unit=src/a.c", "--set", "kind=file").returncode == 0
    assert run("put", "--db", db, "--table", "cba_coverage",
               "--set", "unit=src/a.c", "--set", "phase=audit",
               "--set", "state=analyzed").returncode == 0
    r = run("coverage", "--db", db, "--gate")
    assert r.returncode == 0, r.stdout
    assert "coverage gate: PASS" in r.stdout


def test_coverage_without_gate_still_exits_zero_on_a_gap(tmp_path):
    """Ruling S3: the gate is opt-in. Bare `coverage` reports; it does not
    decide. A verb that started failing would break every existing caller."""
    db = seeded(tmp_path)
    r = run("coverage", "--db", db)
    assert r.returncode == 0
```

- [ ] **Step 7: Run everything**

Run: `python3 -m pytest -q && python3 audit.py selftest`
Expected: PASS; verb count unchanged at 18 (`--gate` is a flag, not a verb).

- [ ] **Step 8: Commit**

```bash
git add audit_core/coverage.py audit.py tests/test_coverage.py tests/test_cli_stage3.py
git commit -m "$(cat <<'MSG'
feat: coverage can now fail a phase exit

Spec 3.5 and R3. Stage 2 recorded and reported; coverage.py's own docstring
said gating was Stage 3's, so that it could be benchmarked on its own.

Three failures: an empty inventory (no denominator means no claim, and it is
the vacuous pass -- a run that inventoried nothing has zero skips and zero
gaps), a budget skip (R3 verbatim), and an inventoried unit with no coverage
row (the silent case; six of ten missed tplink CRITICALs are on surfaces
never opened and never written down).

Everything else recorded as not_audited warns. vendored and out-of-scope are
decisions written down, which is what the mechanism asks for; failing on them
would make the gate unclearable, and an unclearable gate gets turned off.

The gate is opt-in -- `coverage --gate`. Nothing in audit_core refuses to run
because coverage is incomplete: a hard block would strand a run with no way
to record the rows that clear it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 5: Identity discipline

Spec §1.3: "A self-assigned filename became a fact. `km0_boot_0C000020.elf` was treated as a bootloader for the whole run; it holds the Realtek Wi-Fi driver and several CRITICALs."

Spec §3.4 gives the table its columns: path, kind, asserted identity, **identity evidence**, confidence, version. Task 1 created it with a vocabulary check. This task adds the rule that makes it worth having.

**The rule:** evidence that only repeats the component's own path is not evidence. `km0_boot_0C000020.elf` is a bootloader *because it is called `km0_boot`* is the exact reasoning that cost six CRITICALs. Mechanically: reduce the evidence to tokens, subtract the tokens of the path, and require something to be left.

This is a narrow rule and it is deliberately narrow. It cannot tell a good identification from a bad one; it can tell a circular one from a non-circular one, which is the specific mistake this project has made.

**Files:**
- Create: `audit_core/identity.py`
- Create: `tests/test_identity.py`
- Modify: `audit_core/db.py` (`_validate_component` gains the evidence check)
- Modify: `audit.py` (`cmd_identify`, `HANDLERS`, `build_parser`)
- Modify: `tests/test_cli_stage3.py`

**Interfaces:**
- Consumes: `text.location_tokens`, `db.put`, `db.rows`, `db.DbError`, `db.COMPONENT_KINDS`.
- Produces:
  - `identity.MIN_EVIDENCE_CHARS = 20`
  - `identity.check_evidence(path: str, evidence: str) -> None` — raises `db.DbError`.
  - `identity.record(con, *, path, kind, identity, evidence, confidence="", version="", replace=False) -> None`
  - `identity.render(rows) -> str`

- [ ] **Step 1: Write the failing evidence tests**

Create `tests/test_identity.py`:

```python
import pytest

from audit_core import db, identity, workspace


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    yield c
    c.close()


def test_evidence_that_only_repeats_the_filename_is_rejected():
    """The tplink miss, exactly: km0_boot_0C000020.elf was treated as a
    bootloader because it is called km0_boot. It holds the Realtek Wi-Fi
    driver and several CRITICALs."""
    with pytest.raises(db.DbError) as exc:
        identity.check_evidence("images/km0_boot_0C000020.elf",
                                "the file is named km0_boot_0C000020.elf")
    message = str(exc.value)
    assert "path" in message
    assert "km0_boot" in message


def test_evidence_naming_something_outside_the_path_is_accepted():
    identity.check_evidence(
        "images/km0_boot_0C000020.elf",
        "contains the string 'rtl8710 wlan firmware' at 0x0C00A120 and "
        "imports wifi_hal_init")


def test_evidence_too_short_to_be_evidence_is_rejected():
    with pytest.raises(db.DbError) as exc:
        identity.check_evidence("images/boot.elf", "ELF")
    assert str(identity.MIN_EVIDENCE_CHARS) in str(exc.value)


def test_the_check_ignores_case_and_path_separators():
    """`SRC/OSAL/Tss.c` and `src_osal_tss` tokenize the same way; evidence
    that restates the path in another casing or with another separator is
    the same circular claim."""
    with pytest.raises(db.DbError):
        identity.check_evidence("src/osal/Tss.c",
                                "found under SRC/OSAL as TSS dot C file")


def test_record_writes_a_component_row(con):
    identity.record(
        con, path="images/km0_boot_0C000020.elf", kind="binary",
        identity="Realtek RTL8710 Wi-Fi driver image",
        evidence="contains 'rtl8710 wlan firmware' at 0x0C00A120; imports "
                 "wifi_hal_init; no reset vector at offset 0",
        confidence="8", version="1.0.11")
    row = db.rows(con, "cba_components")[0]
    assert row["asserted_identity"].startswith("Realtek")
    assert row["confidence"] == 8


def test_put_rejects_a_circular_component_row_too(con):
    """The rule lives in the table contract, not only in the verb, so the
    generic `audit.py put --table cba_components` path cannot route around
    it."""
    with pytest.raises(db.DbError):
        db.put(con, "cba_components", {
            "path": "images/km0_boot.elf", "kind": "binary",
            "asserted_identity": "bootloader",
            "identity_evidence": "it is km0_boot.elf"})


def test_an_unknown_kind_is_rejected(con):
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_components", {
            "path": "a.bin", "kind": "thingy",
            "asserted_identity": "x",
            "identity_evidence": "entropy 7.9 over the whole file, no ELF header"})
    assert "thingy" in str(exc.value)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_identity.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.identity'`.

- [ ] **Step 3: Put the rule in the table contract, in `db.py`**

The rule belongs to the table, not to the verb: `audit.py put --table cba_components` must not be able to route around it. `identity.py` imports `db`, so the check itself lives in `db.py` and `identity.py` re-exports it under a public name.

In `audit_core/db.py`, beside `_validate_component`:

```python
MIN_EVIDENCE_CHARS = 20


def check_identity_evidence(path: str, evidence: str) -> None:
    """Raise unless `evidence` says something the path does not already say.

    `text.location_tokens` lowercases, splits on non-identifier characters
    and drops anything under four characters, so `src/osal/Tss.c` and
    "found under SRC/OSAL as TSS dot C file" reduce to the same token set -
    which is the point. What survives the subtraction is the part of the
    claim that came from looking at the thing.

    Public, unlike the `_validate_*` functions beside it, because
    audit_core.identity re-exports it: identity.py imports db, so the rule
    cannot live there without a cycle, and a leading underscore on a name
    another module is meant to call is a lie about its scope.
    """
    evidence = (evidence or "").strip()
    if len(evidence) < MIN_EVIDENCE_CHARS:
        raise DbError(
            f"identity_evidence is {len(evidence)} characters; at least "
            f"{MIN_EVIDENCE_CHARS} are needed. Name what you looked at: a "
            f"string and its offset, an import, a header field, a build "
            f"artifact.")
    novel = text.location_tokens(evidence) - text.location_tokens(path)
    if not novel:
        raise DbError(
            f"identity_evidence for {path!r} only repeats its own path. A "
            f"filename is an assertion by whoever named it, not evidence: "
            f"km0_boot_0C000020.elf was treated as a bootloader for a whole "
            f"run on exactly this reasoning and holds a Wi-Fi driver. Cite "
            f"something you read out of the component itself.")
```

and in `_validate_component`, after the `kind` check and before the confidence block:

```python
    check_identity_evidence(str(row.get("path", "")),
                            str(row.get("identity_evidence", "") or ""))
```

`db.py` already imports `text`, so no new import is needed.

- [ ] **Step 4: Write `audit_core/identity.py`**

```python
"""An asserted identity needs evidence that is not the component's own name.

From the tplink post-mortem: `km0_boot_0C000020.elf` was treated as a
bootloader for the whole run because of what it is called. It holds the
Realtek Wi-Fi driver and several reference-set CRITICALs, and no finding in
that run sits below the IP layer.

The rule is narrow on purpose. It cannot tell a good identification from a
bad one. It can tell a circular one from a non-circular one, which is the
specific mistake this project has made, and a broader rule over English
evidence prose would fire on legitimate text and get switched off.
"""
from __future__ import annotations

import sqlite3

from audit_core import db


MIN_EVIDENCE_CHARS = db.MIN_EVIDENCE_CHARS
check_evidence = db.check_identity_evidence


def record(con: sqlite3.Connection, *, path: str, kind: str, identity: str,
           evidence: str, confidence: str = "", version: str = "",
           replace: bool = False) -> None:
    db.put(con, "cba_components", {
        "path": path, "kind": kind, "asserted_identity": identity,
        "identity_evidence": evidence, "confidence": confidence or "",
        "version": version or ""}, replace=replace)


def render(rows: list[sqlite3.Row]) -> str:
    if not rows:
        return ("components: none asserted.\n"
                "  Record what each analysed artifact actually is, with the "
                "evidence, using `audit.py identify`. A filename is an "
                "assertion by whoever named it.")
    out = [f"components: {len(rows)} asserted"]
    for r in rows:
        conf = f" (confidence {r['confidence']})" if r["confidence"] else ""
        out.append(f"  {r['path']}")
        out.append(f"    {r['kind']}: {r['asserted_identity']}{conf}")
        out.append(f"    evidence: {r['identity_evidence']}")
    return "\n".join(out)
```

`MIN_EVIDENCE_CHARS` and `check_evidence` come from `db` (Step 3), so the module declares neither. The path is tokenized whole rather than by basename: a component under `vendor/realtek/` legitimately draws evidence from where it sits in the tree, and tokens from that part of the path are not novel either.

- [ ] **Step 5: Run the identity tests**

Run: `python3 -m pytest tests/test_identity.py -q`
Expected: PASS, 7 tests.

- [ ] **Step 6: Add the `identify` verb**

In `audit.py`, import `from audit_core import identity as identity_mod  # noqa: E402`, then:

```python
def cmd_identify(args: argparse.Namespace) -> int:
    con = _open_db(args.db, read_only=not args.path)
    if con is None:
        return 1
    try:
        if not args.path:
            print(identity_mod.render(db_mod.rows(con, "cba_components")))
            return 0
        for name in ("kind", "identity", "evidence"):
            if not (getattr(args, name) or "").strip():
                print(f"--{name} is required with --path", file=sys.stderr)
                return 1
        identity_mod.record(
            con, path=args.path, kind=args.kind, identity=args.identity,
            evidence=args.evidence, confidence=args.confidence or "",
            version=args.version or "", replace=args.replace)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    print(f"cba_components: {args.path} recorded as {args.identity!r}")
    return 0
```

`HANDLERS` gains `"identify": cmd_identify,`. `build_parser` gains:

```python
    idf = sub.add_parser("identify", help="assert what a component is, with evidence that is not its filename")
    idf.add_argument("--db", required=True, metavar="AUDIT_DB")
    idf.add_argument("--path", default=None,
                     help="the component; omit to list what is recorded")
    idf.add_argument("--kind", default=None, choices=list(db_mod.COMPONENT_KINDS))
    idf.add_argument("--identity", default=None, help="what you say it is")
    idf.add_argument("--evidence", default=None,
                     help="what you read out of it that says so")
    idf.add_argument("--confidence", default=None, metavar="1-10")
    idf.add_argument("--version", default=None)
    idf.add_argument("--replace", action="store_true")
```

- [ ] **Step 7: Write the CLI tests**

Append to `tests/test_cli_stage3.py`:

```python
def test_identify_rejects_evidence_that_repeats_the_filename(tmp_path):
    db = seeded(tmp_path)
    r = run("identify", "--db", db, "--path", "images/km0_boot_0C000020.elf",
            "--kind", "binary", "--identity", "bootloader",
            "--evidence", "the file is named km0_boot_0C000020.elf")
    assert r.returncode == 1
    assert "km0_boot" in r.stderr


def test_identify_records_and_lists(tmp_path):
    db = seeded(tmp_path)
    assert run("identify", "--db", db,
               "--path", "images/km0_boot_0C000020.elf", "--kind", "binary",
               "--identity", "Realtek RTL8710 Wi-Fi driver image",
               "--evidence", "contains 'rtl8710 wlan firmware' at 0x0C00A120; "
                             "imports wifi_hal_init",
               "--confidence", "8").returncode == 0
    r = run("identify", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "Realtek RTL8710" in r.stdout
    assert "evidence:" in r.stdout


def test_identify_rejects_a_confidence_outside_the_range(tmp_path):
    db = seeded(tmp_path)
    r = run("identify", "--db", db, "--path", "a.bin", "--kind", "binary",
            "--identity", "x",
            "--evidence", "entropy 7.9 across the file, no ELF header present",
            "--confidence", "99")
    assert r.returncode == 1
    assert "1-10" in r.stderr
```

- [ ] **Step 8: Run everything**

Run: `python3 -m pytest -q && python3 audit.py selftest`
Expected: PASS; `selftest` reports 19 verbs.

- [ ] **Step 9: Commit**

```bash
git add audit_core/identity.py audit_core/db.py audit.py \
        tests/test_identity.py tests/test_cli_stage3.py
git commit -m "$(cat <<'MSG'
feat: an asserted identity needs evidence that is not the filename

Spec 1.3 and 3.4. km0_boot_0C000020.elf was treated as a bootloader for a
whole tplink run because of what it is called. It holds the Realtek Wi-Fi
driver and several reference-set CRITICALs, and no finding in that run sits
below the IP layer.

The check reduces the evidence to tokens, subtracts the path's own tokens,
and requires something to be left. Narrow on purpose: it cannot tell a good
identification from a bad one, only a circular one from a non-circular one,
and a broader rule over English prose would fire on legitimate text and get
switched off.

It lives in the table contract, so `put --table cba_components` cannot route
around the verb.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 6: Chain composition

Spec §1.3: "Chains were never composed. Two findings held both halves of an exploit chain and were never joined, because findings are born inside per-group subagents and nothing crosses them."

The structural cause is in that sentence. A per-group subagent sees its own group; nothing in the pipeline ever looks at two groups at once. So the mechanism is a cross-group pass the orchestrator runs after the audit phase, and it is a **proposer**, in the same discipline `dedup` and `bench` already follow: it offers ordered pairs, a human or an agent composes, and composition is a separate explicit act.

**The join:** finding A *enables* finding B when A's recorded `impact` names something B's recorded `attacker_position` or `boundary_crossed` requires. That is an approximation of a precondition relation over English prose, and it is noisy, so Review Focus 5 governs the shape: a stopword floor, a two-token minimum, cross-group only, and a hard cap.

**The diagnostic is half the value.** A finding with no `attacker_position` and no `boundary_crossed` cannot be the consumer half of any chain. Both columns are optional in `cba_findings`, so on a real run many findings will have neither — and the count of those is itself a finding about the audit's data quality. `propose` reports it.

**Files:**
- Create: `audit_core/chains.py`
- Create: `tests/test_chains.py`
- Modify: `audit.py` (`cmd_chain`, `HANDLERS`, `build_parser`)
- Modify: `tests/test_cli_stage3.py`

**Interfaces:**
- Consumes: `text.location_tokens`, `db.rows`, `db.put`, `db.DbError`, `db.CHAIN_COMPLETENESS`.
- Produces:
  - `chains.MAX_CANDIDATES = 100`, `chains.MIN_SHARED_TOKENS = 2`, `chains.NOISE: frozenset[str]`
  - `chains.ChainCandidate` — frozen dataclass: `enabler: str`, `consumer: str`, `shared: tuple[str, ...]`.
  - `chains.Proposal` — frozen dataclass: `candidates: tuple[ChainCandidate, ...]`, `findings_scanned: int`, `without_precondition: int`, `truncated: bool`.
  - `chains.propose(con) -> Proposal`
  - `chains.compose(con, *, chain_id, finding_ids, attacker_position, completeness, pre_auth="", blocking_unknowns="", replace=False) -> None`
  - `chains.render(p: Proposal) -> str`

- [ ] **Step 1: Write the failing proposal tests**

Review Focus 5 is tests three and four. Create `tests/test_chains.py`:

```python
import pytest

from audit_core import chains, db, workspace


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    yield c
    c.close()


def finding(con, fid, group, **over):
    row = {"id": fid, "group_id": group, "title": fid, "severity": "HIGH",
           "confidence": "9", "location": f"src/{group}.c:1",
           "root_cause": "rc", "impact": "", "attacker_position": "",
           "boundary_crossed": ""}
    row.update({k: v for k, v in over.items()})
    db.put(con, "cba_findings", row)


def test_an_impact_that_grants_another_findings_precondition_is_proposed(con):
    finding(con, "G1-F1", "G1",
            impact="leaks the session_token cookie to an unauthenticated caller")
    finding(con, "G2-F1", "G2",
            attacker_position="holder of a valid session_token cookie")
    p = chains.propose(con)
    assert len(p.candidates) == 1
    c = p.candidates[0]
    assert (c.enabler, c.consumer) == ("G1-F1", "G2-F1")
    assert "session_token" in c.shared


def test_two_findings_in_the_same_group_are_not_proposed(con):
    """Per-group subagents already see their own group. The whole reason
    chains were missed is that nothing crosses groups, so proposing within
    one adds noise and no information."""
    finding(con, "G1-F1", "G1", impact="leaks the session_token cookie")
    finding(con, "G1-F2", "G1", attacker_position="holder of a session_token")
    assert chains.propose(con).candidates == ()


def test_generic_english_overlap_alone_does_not_propose(con):
    """Review Focus 5. 'user', 'remote', 'file' and 'attacker' appear in
    almost every impact and almost every attacker position. Matching on them
    turns 45 findings into hundreds of candidates."""
    finding(con, "G1-F1", "G1",
            impact="allows a remote attacker to read a user file")
    finding(con, "G2-F1", "G2",
            attacker_position="remote attacker with a user account")
    assert chains.propose(con).candidates == ()


def test_a_single_shared_token_is_not_enough(con):
    finding(con, "G1-F1", "G1", impact="writes to nvram_config")
    finding(con, "G2-F1", "G2", attacker_position="needs nvram_config set")
    assert chains.propose(con).candidates == ()


def test_boundary_crossed_also_counts_as_a_precondition(con):
    finding(con, "G1-F1", "G1",
            impact="grants write access to the firmware_partition header")
    finding(con, "G2-F1", "G2",
            boundary_crossed="firmware_partition header parsed by the loader")
    assert len(chains.propose(con).candidates) == 1


def test_findings_with_no_recorded_precondition_are_counted(con):
    """The diagnostic. Both columns are optional in cba_findings, so a run
    that never filled them cannot produce a chain -- and that fact is worth
    more than the empty candidate list."""
    finding(con, "G1-F1", "G1", impact="leaks the session_token cookie")
    finding(con, "G2-F1", "G2")
    p = chains.propose(con)
    assert p.findings_scanned == 2
    assert p.without_precondition == 2
    assert p.candidates == ()


def test_the_candidate_list_is_capped(con):
    """Review Focus 5. An uncapped proposal dumping hundreds of pairs into
    the orchestrator is the exact R1 failure this mechanism exists to serve."""
    for i in range(40):
        finding(con, f"G1-F{i}", "G1",
                impact="writes the session_token into the nvram_config blob")
    for i in range(40):
        finding(con, f"G2-F{i}", "G2",
                attacker_position="needs session_token and nvram_config")
    p = chains.propose(con)
    assert len(p.candidates) == chains.MAX_CANDIDATES
    assert p.truncated is True
    assert "narrow" in chains.render(p).lower()
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_chains.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.chains'`.

- [ ] **Step 3: Write `audit_core/chains.py`**

```python
"""Propose cross-group finding pairs that compose into an exploit chain.

Spec section 1.3: "Two findings held both halves of an exploit chain and were
never joined, because findings are born inside per-group subagents and
nothing crosses them." The structural cause is in that sentence - no step in
the pipeline ever looked at two groups at once.

So this is a cross-group pass, and it proposes. `dedup` proposes duplicate
pairs and never merges; `bench` proposes candidate matches and never scores
them as matches. Same discipline: a chain is composed by a human or an agent
that read both findings, and `compose` records that decision.

The join is an approximation over English prose - finding A enables finding B
when A's recorded impact names something B's recorded attacker position or
crossed boundary requires - so every edge of it is bounded: generic words are
dropped, one shared word is not enough, same-group pairs are skipped, and the
list is capped.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from audit_core import db, text

MAX_CANDIDATES = 100
MIN_SHARED_TOKENS = 2

# Words that appear in almost every impact and almost every attacker
# position, so sharing one carries no information. Deliberately short and
# literal: a general English stopword list would start dropping the domain
# nouns - "session", "firmware", "partition" - that are the whole signal.
NOISE = frozenset({
    "able", "access", "after", "allow", "allows", "arbitrary", "attack",
    "attacker", "authenticated", "because", "before", "could", "cause",
    "causes", "control", "could", "data", "device", "does", "either",
    "execute", "execution", "file", "files", "from", "full", "give",
    "gives", "grant", "grants", "input", "into", "lead", "leads", "local",
    "network", "only", "over", "path", "position", "read", "remote",
    "request", "requests", "same", "server", "service", "stack", "system",
    "than", "that", "their", "them", "then", "there", "this", "through",
    "unauthenticated", "user", "users", "value", "when", "where", "which",
    "while", "with", "without", "write", "writes",
})


@dataclass(frozen=True, slots=True)
class ChainCandidate:
    enabler: str
    consumer: str
    shared: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Proposal:
    candidates: tuple[ChainCandidate, ...]
    findings_scanned: int
    without_precondition: int
    truncated: bool


def _significant(value: str) -> frozenset[str]:
    """Four-character-plus tokens, minus the words that say nothing.

    The four-character floor comes from text.location_tokens, where it was
    added because the bare token `tss` matched TssRSASecretKey and
    osal_tss_init and produced two false golden candidates. The same
    reasoning applies harder here: this runs over prose, not paths.
    """
    return frozenset(text.location_tokens(value) - NOISE)


def propose(con: sqlite3.Connection) -> Proposal:
    """Ordered (enabler, consumer) pairs, across groups only.

    `without_precondition` is the diagnostic, and on a real run it is the
    more useful number: attacker_position and boundary_crossed are optional
    in cba_findings, so a run that never filled them cannot produce a chain,
    and an empty candidate list would otherwise read as "no chains exist".

    Bounded at db.MAX_ROWS findings, stated here rather than left to the
    default: the tplink run produced 45, and a run that produced more than
    200 has a bigger problem than its chain list.
    """
    rows = db.rows(con, "cba_findings",
                   columns=("id", "group_id", "impact", "attacker_position",
                            "boundary_crossed"),
                   limit=db.MAX_ROWS)
    findings = []
    without = 0
    for r in rows:
        precondition = _significant(
            f"{r['attacker_position'] or ''} {r['boundary_crossed'] or ''}")
        if not precondition:
            without += 1
        findings.append((r["id"], r["group_id"] or "",
                         _significant(r["impact"] or ""), precondition))

    out: list[ChainCandidate] = []
    truncated = False
    for eid, egroup, impact, _ in findings:
        if not impact:
            continue
        for cid, cgroup, _, precondition in findings:
            if cid == eid or cgroup == egroup or not precondition:
                continue
            shared = impact & precondition
            if len(shared) < MIN_SHARED_TOKENS:
                continue
            if len(out) >= MAX_CANDIDATES:
                truncated = True
                break
            out.append(ChainCandidate(eid, cid, tuple(sorted(shared))))
        if truncated:
            break

    return Proposal(candidates=tuple(out), findings_scanned=len(findings),
                    without_precondition=without, truncated=truncated)


def compose(con: sqlite3.Connection, *, chain_id: str, finding_ids: str,
            attacker_position: str, completeness: str, pre_auth: str = "",
            blocking_unknowns: str = "", replace: bool = False) -> None:
    """Record a chain somebody decided on. Validates that it names real findings.

    A chain naming a finding that does not exist is a chain nothing can be
    checked against, and the finding ids are typed by hand from a candidate
    list. db.put's validator checks the shape of finding_ids; only a
    connection can check that they resolve.
    """
    ids = [p.strip() for p in finding_ids.split(",") if p.strip()]
    known = {r["id"] for r in db.rows(con, "cba_findings", columns=("id",))}
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise db.DbError(
            f"chain {chain_id} names finding(s) that do not exist: "
            f"{', '.join(unknown)}")
    db.put(con, "cba_chains", {
        "id": chain_id, "finding_ids": ", ".join(ids),
        "attacker_position": attacker_position, "pre_auth": pre_auth or "",
        "completeness": completeness,
        "blocking_unknowns": blocking_unknowns or ""}, replace=replace)


def render(p: Proposal) -> str:
    out = [f"chain candidates: {len(p.candidates)} across "
           f"{p.findings_scanned} finding(s)"]
    for c in p.candidates:
        out.append(f"  {c.enabler} -> {c.consumer}   shared: "
                   f"{', '.join(c.shared)}")
    if p.truncated:
        out.append(f"  capped at {MAX_CANDIDATES}. The impact and "
                   f"attacker-position text is too generic to join on as "
                   f"written - narrow it before reading this list.")
    if p.without_precondition:
        out.append(
            f"  {p.without_precondition} of {p.findings_scanned} finding(s) "
            f"record neither attacker_position nor boundary_crossed, so they "
            f"cannot be the consumer half of any chain. That is a gap in the "
            f"findings, not a statement that no chain exists.")
    if p.candidates:
        out.append("  These are proposals. Read both findings in full, then "
                   "record the decision with `audit.py chain --compose`.")
    return "\n".join(out)
```

- [ ] **Step 4: Run the proposal tests**

Run: `python3 -m pytest tests/test_chains.py -q`
Expected: PASS, 7 tests.

- [ ] **Step 5: Write the failing composition tests**

Append to `tests/test_chains.py`:

```python
def test_compose_records_an_ordered_chain(con):
    finding(con, "G1-F1", "G1", impact="leaks session_token")
    finding(con, "G2-F1", "G2", attacker_position="needs session_token")
    chains.compose(con, chain_id="C1", finding_ids="G1-F1, G2-F1",
                   attacker_position="unauthenticated on the LAN",
                   completeness="complete", pre_auth="yes")
    row = db.rows(con, "cba_chains")[0]
    assert row["finding_ids"] == "G1-F1, G2-F1"
    assert row["completeness"] == "complete"


def test_compose_rejects_a_finding_that_does_not_exist(con):
    finding(con, "G1-F1", "G1")
    with pytest.raises(db.DbError) as exc:
        chains.compose(con, chain_id="C1", finding_ids="G1-F1, G9-F9",
                       attacker_position="LAN", completeness="complete")
    assert "G9-F9" in str(exc.value)


def test_a_one_finding_chain_is_rejected(con):
    """A one-finding chain is a finding. Recording it as a chain hides it
    from the finding tally and inflates the chain tally."""
    finding(con, "G1-F1", "G1")
    with pytest.raises(db.DbError) as exc:
        chains.compose(con, chain_id="C1", finding_ids="G1-F1",
                       attacker_position="LAN", completeness="complete")
    assert "two" in str(exc.value)


def test_a_chain_that_repeats_a_finding_is_rejected(con):
    finding(con, "G1-F1", "G1")
    with pytest.raises(db.DbError):
        chains.compose(con, chain_id="C1", finding_ids="G1-F1, G1-F1",
                       attacker_position="LAN", completeness="complete")


def test_an_invented_completeness_is_rejected(con):
    finding(con, "G1-F1", "G1")
    finding(con, "G2-F1", "G2")
    with pytest.raises(db.DbError) as exc:
        chains.compose(con, chain_id="C1", finding_ids="G1-F1, G2-F1",
                       attacker_position="LAN", completeness="probably")
    assert "probably" in str(exc.value)
```

- [ ] **Step 6: Run them**

Run: `python3 -m pytest tests/test_chains.py -q`
Expected: PASS, 12 tests. `_validate_chain` from Task 1 supplies the last three; if any fails, the cause is there.

- [ ] **Step 7: Add the `chain` verb**

In `audit.py`, import `from audit_core import chains as chains_mod  # noqa: E402`, then:

```python
def cmd_chain(args: argparse.Namespace) -> int:
    composing = bool(args.compose)
    con = _open_db(args.db, read_only=not composing)
    if con is None:
        return 1
    try:
        if not composing:
            proposal = chains_mod.propose(con)
            if args.json:
                print(json.dumps(dataclasses.asdict(proposal), indent=2))
            else:
                print(chains_mod.render(proposal))
            return 0
        for name in ("findings", "attacker_position", "completeness"):
            if not (getattr(args, name) or "").strip():
                print(f"--{name.replace('_', '-')} is required with --compose",
                      file=sys.stderr)
                return 1
        chains_mod.compose(
            con, chain_id=args.compose, finding_ids=args.findings,
            attacker_position=args.attacker_position,
            completeness=args.completeness, pre_auth=args.pre_auth or "",
            blocking_unknowns=args.blocking_unknowns or "",
            replace=args.replace)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    print(f"cba_chains: {args.compose} recorded ({args.findings})")
    return 0
```

`HANDLERS` gains `"chain": cmd_chain,`. `build_parser` gains:

```python
    ch = sub.add_parser("chain", help="propose cross-group finding pairs, or record a composed chain")
    ch.add_argument("--db", required=True, metavar="AUDIT_DB")
    ch.add_argument("--compose", default=None, metavar="CHAIN_ID",
                    help="record a chain instead of proposing")
    ch.add_argument("--findings", default=None, metavar="ID,ID,...",
                    help="two or more finding ids, in attack order")
    ch.add_argument("--attacker-position", dest="attacker_position",
                    default=None)
    ch.add_argument("--completeness", default=None,
                    choices=list(db_mod.CHAIN_COMPLETENESS))
    ch.add_argument("--pre-auth", dest="pre_auth", default=None)
    ch.add_argument("--blocking-unknowns", dest="blocking_unknowns",
                    default=None)
    ch.add_argument("--replace", action="store_true")
    ch.add_argument("--json", action="store_true")
```

- [ ] **Step 8: Write the CLI tests**

Append to `tests/test_cli_stage3.py`:

```python
def test_chain_proposes_across_groups(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_findings",
               "--set", "id=G2-F1", "--set", "group_id=G2", "--set", "title=t",
               "--set", "severity=HIGH", "--set", "confidence=9",
               "--set", "location=src/b.c:1", "--set", "root_cause=rc",
               "--set", "impact=im",
               "--set", "attacker_position=needs session_token and nvram_config"
               ).returncode == 0
    assert run("put", "--db", db, "--table", "cba_findings",
               "--set", "id=G3-F1", "--set", "group_id=G3", "--set", "title=t",
               "--set", "severity=HIGH", "--set", "confidence=9",
               "--set", "location=src/c.c:1", "--set", "root_cause=rc",
               "--set", "impact=leaks session_token from the nvram_config blob"
               ).returncode == 0
    r = run("chain", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "G3-F1 -> G2-F1" in r.stdout
    assert "proposals" in r.stdout


def test_chain_compose_records_and_rejects_an_unknown_finding(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_findings",
               "--set", "id=G2-F1", "--set", "group_id=G2", "--set", "title=t",
               "--set", "severity=HIGH", "--set", "confidence=9",
               "--set", "location=src/b.c:1", "--set", "root_cause=rc",
               "--set", "impact=im").returncode == 0
    ok = run("chain", "--db", db, "--compose", "C1",
             "--findings", "G1-F1,G2-F1",
             "--attacker-position", "unauthenticated on the LAN",
             "--completeness", "complete")
    assert ok.returncode == 0, ok.stderr

    bad = run("chain", "--db", db, "--compose", "C2",
              "--findings", "G1-F1,G9-F9",
              "--attacker-position", "LAN", "--completeness", "complete")
    assert bad.returncode == 1
    assert "G9-F9" in bad.stderr


def test_chain_reports_findings_that_cannot_be_a_consumer(tmp_path):
    db = seeded(tmp_path)
    r = run("chain", "--db", db)
    assert r.returncode == 0
    assert "cannot be the consumer half" in r.stdout
```

- [ ] **Step 9: Run everything**

Run: `python3 -m pytest -q && python3 audit.py selftest`
Expected: PASS; `selftest` reports 20 verbs.

- [ ] **Step 10: Commit**

```bash
git add audit_core/chains.py audit.py tests/test_chains.py tests/test_cli_stage3.py
git commit -m "$(cat <<'MSG'
feat: propose cross-group chains, and record composed ones

Spec 1.3: two tplink findings held both halves of an exploit chain and were
never joined, because findings are born inside per-group subagents and
nothing crosses them. The fix is a cross-group pass, which is the one thing
the pipeline never had.

It proposes, like dedup and bench: an ordered (enabler, consumer) pair is an
approximation over English prose, so every edge is bounded -- generic words
dropped, one shared word not enough, same-group pairs skipped, list capped.

The diagnostic is half the value. attacker_position and boundary_crossed are
optional in cba_findings, so a run that never filled them cannot produce a
chain; without that count, an empty candidate list reads as "no chains
exist".

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 7: Precision in `bench`

Spec §6.1: "`audit.py bench` scores a run against a golden: recall …, **precision (rung-4 findings surviving adversarial review)**, coverage …, and cost per rung-4 finding."

`bench` scores recall, candidates and cost per match. It has never scored precision. Ruling S1 turns on this: the one tiering change the spec quarantines to Stage 3 is conditioned on "precision measured before and after", and neither measurement can exist until this task lands.

**What precision is, in this skill's vocabulary.** `codebase-audit` has no rungs; its adversarial review is the `fpcheck` phase. So precision is **TRUE_POSITIVE verdicts ÷ decided verdicts**, where decided excludes `DUPLICATE` and `NEEDS_VERIFICATION`:

- A `DUPLICATE` is not a wrong finding. It is the same right finding twice, and counting it against precision would punish a run for finding something from two angles.
- A `NEEDS_VERIFICATION` is undecided. Counting it either way asserts a verdict nobody reached.

**What it does not measure, and this must be said wherever the number is printed:** it measures what *this run's own FP-check* kept. A run whose FP-check is too lenient scores high precision and has learned nothing. Precision is a *comparative* instrument — the same golden, the same pipeline, one variable changed — which is exactly the use §7 puts it to.

**Files:**
- Modify: `audit_core/bench.py`
- Modify: `audit.py` (`cmd_bench`)
- Modify: `tests/test_bench.py`
- Modify: `tests/test_cli_bench.py`

**Interfaces:**
- Consumes: `bench.BenchResult`, `bench.score`, `sqlite3`.
- Produces:
  - `bench.Precision` — frozen dataclass: `true_positives: int`, `false_positives: int`, `duplicates: int`, `needs_verification: int`; properties `decided -> int` and `fraction -> float | None`.
  - `bench.precision_from_db(db_path) -> Precision | None` — `None` when the database has no `cba_fp_verdicts` table.
  - `bench.score(..., *, precision: Precision | None = None)` and `BenchResult.precision`.

- [ ] **Step 1: Write the failing precision tests**

Append to `tests/test_bench.py`:

```python
def test_precision_counts_decided_verdicts_only(tmp_path):
    con = verdicts(tmp_path, [
        ("G1-F1", "TRUE_POSITIVE"), ("G1-F2", "TRUE_POSITIVE"),
        ("G1-F3", "FALSE_POSITIVE"), ("G1-F4", "DUPLICATE"),
        ("G1-F5", "NEEDS_VERIFICATION"),
    ])
    p = bench.precision_from_db(con)
    assert p.true_positives == 2
    assert p.false_positives == 1
    assert p.duplicates == 1
    assert p.needs_verification == 1
    assert p.decided == 3
    assert p.fraction == pytest.approx(2 / 3)


def test_precision_is_none_when_nothing_is_decided(tmp_path):
    """A run with only duplicates and undecided findings has no precision to
    report. Returning 0.0 would read as "everything was a false positive"."""
    p = bench.precision_from_db(verdicts(tmp_path, [
        ("G1-F1", "DUPLICATE"), ("G1-F2", "NEEDS_VERIFICATION")]))
    assert p.decided == 0
    assert p.fraction is None


def test_precision_from_a_database_with_no_verdicts_table_is_none(tmp_path):
    """bench deliberately opens a run database without db.connect()'s schema
    gate, so it keeps working against run directories older than the current
    schema. Those have no cba_fp_verdicts, and bench must still score recall
    on them rather than traceback."""
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript(
        "CREATE TABLE cba_findings (id TEXT PRIMARY KEY, title TEXT, "
        "cwe TEXT, location TEXT, severity TEXT);")
    con.commit()
    con.close()
    assert bench.precision_from_db(path) is None


def test_score_carries_precision_through(tmp_path):
    p = bench.Precision(true_positives=3, false_positives=1,
                        duplicates=0, needs_verification=0)
    result = bench.score([], [], {}, precision=p)
    assert result.precision is p
```

`verdicts(tmp_path, pairs)` is a helper this task adds to `tests/test_bench.py`. That file currently imports only `sqlite3`, `pytest`, `bench` and `goldens`; add `db` and `workspace` to the `from audit_core import ...` line. The helper builds a run, writes each pair with `db.put` (since Task 2 a `FALSE_POSITIVE` needs `refuting_mechanism` and `enabled_observation`, so pass both), and returns the database **path**:

```python
def verdicts(tmp_path, pairs):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = db.connect(run / "audit.db")
    for fid, verdict in pairs:
        row = {"finding_id": fid, "verdict": verdict}
        if verdict == "FALSE_POSITIVE":
            row["refuting_mechanism"] = "bounded by the window"
            row["enabled_observation"] = "1"
        db.put(con, "cba_fp_verdicts", row)
    con.close()
    return run / "audit.db"
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_bench.py -q`
Expected: FAIL — `AttributeError: module 'audit_core.bench' has no attribute 'precision_from_db'`.

- [ ] **Step 3: Add `Precision` and `precision_from_db` to `bench.py`**

```python
@dataclass(frozen=True, slots=True)
class Precision:
    """TRUE_POSITIVE share of the verdicts somebody actually decided.

    DUPLICATE is excluded because a duplicate is not a wrong finding - it is
    the same right finding twice, and counting it against precision punishes
    a run for finding something from two angles. NEEDS_VERIFICATION is
    excluded because it is undecided, and counting it either way asserts a
    verdict nobody reached.

    This measures what THIS RUN'S OWN FP-check kept. A run whose FP-check is
    too lenient scores high and has learned nothing. The number is only
    meaningful comparatively: same golden, same pipeline, one variable
    changed - which is the use spec section 7 puts it to when it gates the
    Sonnet tiering change on "precision measured before and after".
    """
    true_positives: int
    false_positives: int
    duplicates: int
    needs_verification: int

    @property
    def decided(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def fraction(self) -> float | None:
        """None, not 0.0, when nothing was decided: 0.0 reads as "everything
        was a false positive"."""
        return (self.true_positives / self.decided) if self.decided else None


def precision_from_db(db_path: str | pathlib.Path) -> Precision | None:
    """Count verdicts. None when the run predates cba_fp_verdicts.

    Opened read-only without db.connect()'s schema gate, for the same reason
    load_findings_from_db is: bench must keep scoring recall against run
    directories older than the current schema, and that gate rejects exactly
    those.
    """
    path = pathlib.Path(db_path)
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        if not con.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'cba_fp_verdicts'").fetchone():
            return None
        counts = dict(con.execute(
            "SELECT verdict, COUNT(*) FROM cba_fp_verdicts GROUP BY verdict"))
    finally:
        con.close()
    return Precision(
        true_positives=counts.get("TRUE_POSITIVE", 0),
        false_positives=counts.get("FALSE_POSITIVE", 0),
        duplicates=counts.get("DUPLICATE", 0),
        needs_verification=counts.get("NEEDS_VERIFICATION", 0))
```

Add `precision: Precision | None = None` as the last field of `BenchResult`, and `precision: Precision | None = None` as a keyword-only parameter of `score`, passed straight through. Extend `score`'s existing note on keyword-only arguments to cover it — the reason is the same one already written there.

- [ ] **Step 4: Run the precision tests**

Run: `python3 -m pytest tests/test_bench.py -q`
Expected: PASS.

- [ ] **Step 5: Print precision from `cmd_bench`**

In `audit.py`'s `cmd_bench`, after `findings = bench_mod.load_findings_from_db(db)`:

```python
    precision = bench_mod.precision_from_db(db)
    result = bench_mod.score(refs, findings, adjudicated,
                             rejected=rejected, cost_usd=args.cost,
                             precision=precision)
```

and after the `findings` line in the human-readable block:

```python
    if result.precision is None:
        print("precision  not scored (this run has no cba_fp_verdicts table)")
    elif result.precision.fraction is None:
        print(f"precision  not scored ({result.precision.duplicates} duplicate(s), "
              f"{result.precision.needs_verification} undecided, 0 decided)")
    else:
        p = result.precision
        print(f"precision  {p.true_positives}/{p.decided} "
              f"({100 * p.fraction:.1f}%)  "
              f"[+{p.duplicates} dup, {p.needs_verification} undecided]")
        print("           what this run's own FP-check kept; comparable only "
              "against the same golden and pipeline")
```

The caveat line is not optional. It is the whole difference between a number that gates a model downgrade and a number that reads as a quality score.

- [ ] **Step 6: Write the CLI test**

`tests/test_cli_bench.py` has `make_golden(tmp_path)` and `make_db(tmp_path)`; `make_db` builds a bare `cba_findings` table and nothing else, which is exactly the old-run-directory case. Append:

```python
def test_bench_says_precision_is_not_scored_without_a_verdicts_table(tmp_path):
    r = run("bench", "--golden", str(make_golden(tmp_path)),
            "--db", str(make_db(tmp_path)))
    assert r.returncode == 0, r.stderr
    assert "precision  not scored" in r.stdout
    assert "cba_fp_verdicts" in r.stdout


def test_bench_prints_precision_and_its_caveat(tmp_path):
    db = make_db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cba_fp_verdicts (finding_id TEXT PRIMARY KEY, "
                "verdict TEXT NOT NULL)")
    con.executemany("INSERT INTO cba_fp_verdicts VALUES (?, ?)",
                    [("F-1", "TRUE_POSITIVE"), ("F-2", "TRUE_POSITIVE"),
                     ("F-3", "FALSE_POSITIVE")])
    con.commit(); con.close()
    r = run("bench", "--golden", str(make_golden(tmp_path)), "--db", str(db))
    assert r.returncode == 0, r.stderr
    assert "precision  2/3 (66.7%)" in r.stdout
    assert "comparable only" in r.stdout
```

The second test writes the table with raw SQL rather than `db.put` on purpose: it is checking what `bench` reads out of a database, and `bench` is the one module that opens a run database without the schema gate.

- [ ] **Step 7: Confirm the live benchmark is unmoved**

Run:
```bash
python3 audit.py bench --golden tests/goldens/tplink-dl110v2-1.0.11 \
  --db <the run database the Stage 2 merge used> --cost 658.37
```
Expected: recall still **9/19 (47.4%)**, 45 findings, **$73.15** per matched finding. Precision prints `not scored` against a database with no verdicts table, which is what the pinned run directory is. A recall figure that is not 9/19 means this task changed scoring, which it must not: stop and find out why.

If the Stage 2 run database is not reachable, say so in the report and skip this step rather than substituting a different database — a bench number against a different input is not a comparison.

- [ ] **Step 8: Run everything and commit**

Run: `python3 -m pytest -q && python3 audit.py selftest && python3 audit.py lint-skill`

```bash
git add audit_core/bench.py audit.py tests/test_bench.py tests/test_cli_bench.py
git commit -m "$(cat <<'MSG'
feat: bench scores precision

Spec 6.1 names precision as one of the four things bench scores, and it has
never scored it. Ruling S1 turns on this: the Sonnet tiering change spec 7
quarantines to Stage 3 is gated on "precision measured before and after", and
neither measurement could exist.

Precision is TRUE_POSITIVE over decided verdicts. DUPLICATE is excluded -- a
duplicate is the same right finding twice, not a wrong one. NEEDS_VERIFICATION
is excluded as undecided. Nothing decided returns None rather than 0.0, which
would read as "everything was a false positive".

It measures what this run's own FP-check kept, so the output carries that
caveat on the same screen as the number.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 8: The shipped prose, and two lint rules

Five mechanisms exist and nothing invokes them. This task is where the skill starts using them — and it is the task with this project's worst track record.

**Stage 1's carried finding #1 is binding here.** Rewriting shipped prose from scratch lost instructions five times out of five, and five separate reviews each caught a different subset while none caught all of them. The rule it produced: *any later stage that rewrites shipped prose must produce an explicit derivation — the old instruction set diffed against the new, with a justification for every dropped line — as a reviewable artifact, rather than relying on a reviewer to notice an absence.*

So Step 1 writes the derivation **before** any prose is edited, and Step 12 reconciles it against the real diff. This is not documentation of the work; it is the work's control.

**This task adds. It is not a rewrite.** Every edit below is an insertion or a replacement of a specific named block. If you find yourself retyping a section, stop: that is the failure mode this task is shaped around.

**Files:**
- Create: `docs/superpowers/derivations/2026-10-05-stage3-prose-derivation.md`
- Modify (CRLF): `SKILL.md`, `references/phase0-source-detection.md`, `references/phase4-deep-audit.md`, `references/phase5-fp-check.md`
- Modify (LF): `workflows/recon.md`, `workflows/audit.md`, `workflows/fpcheck.md`, `references/briefs/fpcheck-brief.md`, `references/briefs/audit-brief.md`, `audit_core/skill_lint.py`
- Modify: `tests/test_workflow_prose.py`, `tests/test_skill_lint.py`

**Interfaces:**
- Consumes: every verb Tasks 2-6 added (`pivot`, `patterns`, `identify`, `chain`), `coverage --gate`, and the flags named in each task's `build_parser` block. Use them exactly as those blocks declare them; `test_every_documented_audit_py_invocation_parses` checks every verb named in shipped prose against `audit.HANDLERS`.
- Produces: no code interface. The guard tests in Steps 10-11 are what later stages consume.

- [ ] **Step 1: Write the derivation, before touching any prose**

Create `docs/superpowers/derivations/2026-10-05-stage3-prose-derivation.md` (LF). Four columns, one row per intended edit, every row filled before Step 2 begins:

| Column | Holds |
|---|---|
| **Where** | `file:line-range`, as it stands before the edit |
| **What is there now** | The existing text, quoted, in full |
| **What replaces it** | The new text, quoted, in full — or "(inserted; nothing replaced)" |
| **Why** | The spec section or post-mortem finding that requires it, and explicitly: **what, if anything, is dropped** |

Open the file with the two headings the reconciliation needs:

```markdown
# Stage 3 prose derivation

Written before the prose was edited, per the Stage 1 finding that rewriting
shipped prose from scratch lost instructions five times out of five and that
absence is the hardest thing to review for.

## 1. Intended edits

<the four-column table>

## 2. Reconciliation against the real diff

<filled in at Step 12: every hunk of `git diff -U0` mapped to a row above,
and every removed line accounted for>
```

- [ ] **Step 2: `workflows/recon.md` (LF) — inventory and identity**

Two insertions, no replacements.

After Step 2's numbered list (`4. Insert into cba_sources.`), add a fifth item:

```markdown
5. Record what each confirmed artifact **is**, with evidence that is not its
   own filename:

       python3 __SKILL_DIR__/audit.py identify --db ${AUDIT_DIR}/audit.db \
         --path <path> --kind binary \
         --identity '<what it is>' --evidence '<what you read out of it>' \
         --confidence 8

   A filename is an assertion by whoever named it, not evidence. In a real
   run `km0_boot_0C000020.elf` was treated as a bootloader throughout; it
   holds the Wi-Fi driver and several CRITICALs. The verb rejects evidence
   that only repeats the path.
```

After Step 4's "Insert approved groups into `cba_feature_groups` (status='pending')." line, add:

```markdown
Then populate the coverage denominator. One `cba_inventory` row per
analysable unit — every file or function the audit could open, not only the
ones you intend to:

    python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db \
      --table cba_inventory --set unit=<path> --set kind=file --set group_id=$G

The inventory is what "have we audited everything" is measured against. A
unit nobody inventoried cannot be reported as a gap, which is how six of ten
missed CRITICALs sat on surfaces that were never opened and never written
down.
```

In the Quality Checks list, add:

```markdown
- [ ] `cba_inventory` has a row per analysable unit, and `audit.py coverage --db ${AUDIT_DIR}/audit.db` names a denominator
- [ ] Every confirmed source or binary has a `cba_components` row with evidence that is not its filename
```

- [ ] **Step 3: `workflows/audit.md` (LF) — patterns, chains, coverage at the exit**

Insert a new step between Step 5 (subagent failure handling) and Step 6 (update group status), numbered **Step 6**, and renumber the three that follow to 7, 8, 9. Renumbering is a mechanical edit of four headings; do not rewrite their bodies.

```markdown
## Step 6 — Sweep confirmed patterns, and look for chains

Two passes the per-group subagents structurally cannot do, because each one
sees only its own group.

**Patterns.** A confirmed finding is evidence about one call site and a
hypothesis about every other one. For each finding whose root cause could
appear elsewhere, register it and sweep:

    python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db \
      --table cba_patterns --set id=P1 --set name='<the shape>' \
      --set regex='<the regex>' --set origin_finding=G1-F1

    python3 __SKILL_DIR__/audit.py sweep --db ${AUDIT_DIR}/audit.db \
      --pattern P1 --root . --record

Hits land in `cba_pattern_hits` as candidates for triage, never verdicts. A
truncated sweep is refused: narrow the pattern and run it again.

    python3 __SKILL_DIR__/audit.py patterns --db ${AUDIT_DIR}/audit.db --gate

exits non-zero while any registered pattern has never been swept.
`strncpy(dst, src, strlen(src))` was found twice in a real run, named as a
pattern, and never grepped for; two reference-set CRITICALs are that pattern
elsewhere.

**Chains.** Findings are born inside per-group subagents and nothing crosses
them, so a chain whose halves sit in two groups is never composed:

    python3 __SKILL_DIR__/audit.py chain --db ${AUDIT_DIR}/audit.db

proposes ordered (enabler → consumer) pairs across groups. Read both findings
in full before accepting one, then record the decision:

    python3 __SKILL_DIR__/audit.py chain --db ${AUDIT_DIR}/audit.db \
      --compose C1 --findings G1-F2,G3-F4 \
      --attacker-position 'unauthenticated on the LAN' \
      --completeness complete --pre-auth yes

The command also reports how many findings record neither
`attacker_position` nor `boundary_crossed`. Those cannot be the consumer half
of any chain, and a high count means the findings are underspecified, not
that no chain exists.
```

In the USER GATE step — originally Step 8, **Step 9** after the renumber — before the "Say **go fpcheck**" line, insert:

```markdown
> Record coverage for this phase and check it:
>
>     python3 __SKILL_DIR__/audit.py coverage --db ${AUDIT_DIR}/audit.db --gate
>
> It exits non-zero on an empty inventory, on any unit skipped for budget, and
> on any inventoried unit with no coverage row. A budget skip is answered by
> `audit.py checkpoint` and a restart, never by skipping.
```

In the Quality Checks list, add:

```markdown
- [ ] `audit.py patterns --gate` exits 0 — every registered pattern has been swept
- [ ] `audit.py coverage --gate` exits 0, or every failure it names has been answered
- [ ] `audit.py chain` has been run and its proposals read
```

- [ ] **Step 4: `workflows/fpcheck.md` (LF) — the pivot rule**

Insert a new **Step 5** between the existing Step 4 (spawn subagents) and Step 5 (sanity-check completeness), renumbering the rest to 6-9.

```markdown
## Step 5 — The pivot rule

A `FALSE_POSITIVE` verdict is invalid unless it records what refuted the
finding and what that mechanism enables. Record both together:

    python3 __SKILL_DIR__/audit.py pivot --db ${AUDIT_DIR}/audit.db \
      --finding G1-F3 --group G1 \
      --mechanism '<what refuted it>' \
      --enables '<what that mechanism makes possible, or what you ruled out>' \
      --reason '<the FP reasoning>' --rule HE-7

This writes the observation into `cba_security_observations` and the verdict
into `cba_fp_verdicts` as one act, because a verdict written first and an
observation to follow is an observation nobody writes. `audit.py put --table
cba_fp_verdicts --set verdict=FALSE_POSITIVE` is refused without both fields.

The requirement is unconditional. A refuting mechanism is code, and code does
something; "no attacker-controlled path to the window size identified in this
review" is a legitimate answer and exactly the kind of observation that never
got written down. A blank is not.

In a real run a finding was correctly refuted by a 300-byte sliding-window
flush — and that flush is the attack surface for a reference-set CRITICAL.
The verdict schema recorded the refutation and nothing else.

    python3 __SKILL_DIR__/audit.py pivot --db ${AUDIT_DIR}/audit.db --check

lists any verdict whose `enabled_observation` no longer resolves.
```

In the Quality Checks list, replace the line

```
- [ ] Every FALSE_POSITIVE cites a specific HE/PR/CV rule
```

with

```
- [ ] Every FALSE_POSITIVE cites a specific HE/PR/CV rule, and records `refuting_mechanism` plus an `enabled_observation` that resolves (`audit.py pivot --check`)
```

This is the task's one replacement of an existing line. The original clause survives inside it verbatim — check that it does.

- [ ] **Step 5: `references/phase5-fp-check.md` (CRLF) — verdict processing**

**This file is CRLF.** Confirm with `grep -c $'\r' references/phase5-fp-check.md` before and after.

Under `### 2. Insert into SQL`, the existing example writes a `TRUE_POSITIVE` and still works. Append below it, inside the same section:

````markdown
A `FALSE_POSITIVE` takes a different verb, because it must also record what
refuted the finding and what that mechanism enables:

```bash
python3 __SKILL_DIR__/audit.py pivot --db ${AUDIT_DIR}/audit.db \
  --finding G1-F3 --group G1 \
  --mechanism '300-byte sliding-window flush in recv_loop' \
  --enables 'the flush takes an attacker-sized length at recv.c:214' \
  --reason '<why the original claim fails>' --rule HE-1
```

The observation is written as a rung-1 lead, not a finding. It is the step
that was missing when a correctly-refuted finding's refuting mechanism turned
out to be a CRITICAL in its own right.
````

Under `## Quality Gates`, add one checkbox after the existing five:

```markdown
- [ ] Every FALSE_POSITIVE has a `refuting_mechanism` and an `enabled_observation` that resolves
```

- [ ] **Step 6: `references/phase4-deep-audit.md` (CRLF) — patterns and chains**

**CRLF.** Under `## Post-Collection Processing`, after item 4 (dedup quick-check) and its code block, add items 5 and 6:

````markdown
5. **Register and sweep confirmed patterns**: a confirmed finding is evidence
   about one call site and a hypothesis about every other one.

   ```bash
   python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db \
     --table cba_patterns --set id=P1 --set name='<the shape>' \
     --set regex='<the regex>' --set origin_finding=G1-F1
   python3 __SKILL_DIR__/audit.py sweep --db ${AUDIT_DIR}/audit.db \
     --pattern P1 --root . --record
   python3 __SKILL_DIR__/audit.py patterns --db ${AUDIT_DIR}/audit.db --gate
   ```

   Hits are candidates for triage, never verdicts.

6. **Chain pass**: findings are born inside per-group subagents, so a chain
   whose halves sit in two groups is never composed.

   ```bash
   python3 __SKILL_DIR__/audit.py chain --db ${AUDIT_DIR}/audit.db
   ```

   These are proposals. Read both findings in full, then record the decision
   with `audit.py chain --compose`.
````

Under `## Quality Signals`, in the "Good findings have" list, add:

```markdown
- A recorded `attacker_position` and `boundary_crossed` — a finding with
  neither cannot be the consumer half of any chain
```

- [ ] **Step 7: `references/phase0-source-detection.md` (CRLF) — identity evidence**

**CRLF.** Under `## SQL Schema`, after the existing two sentences, add:

````markdown
Record what each confirmed artifact is, with evidence:

```bash
python3 __SKILL_DIR__/audit.py identify --db ${AUDIT_DIR}/audit.db \
  --path images/km0_boot_0C000020.elf --kind binary \
  --identity 'Realtek RTL8710 Wi-Fi driver image' \
  --evidence "contains 'rtl8710 wlan firmware' at 0x0C00A120; imports wifi_hal_init" \
  --confidence 8
```

A filename is an assertion by whoever named it. `km0_boot_0C000020.elf` was
treated as a bootloader for a whole run on the strength of its name; it holds
the Wi-Fi driver and several CRITICALs, and no finding in that run sits below
the IP layer. The verb refuses evidence that only repeats the path.
````

- [ ] **Step 8: The two brief templates (LF)**

`references/briefs/fpcheck-brief.md` — replace method step 9:

```
9. Issue a verdict: TRUE_POSITIVE, FALSE_POSITIVE or DUPLICATE.
```

with:

```
9. Issue a verdict: TRUE_POSITIVE, FALSE_POSITIVE or DUPLICATE.
10. For a FALSE_POSITIVE, take the pivot: name the mechanism that refuted the
    finding, and say what that mechanism itself enables. Record both with
    `audit.py pivot`, which writes the observation and the verdict together;
    a bare FALSE_POSITIVE insert is refused. The requirement is
    unconditional -- "no attacker-controlled path identified in this review"
    is a legitimate answer, a blank is not. A finding was once correctly
    refuted by a 300-byte sliding-window flush, and that flush is the attack
    surface for a CRITICAL.
```

The verbatim text of step 9 survives; step 10 is added after it. Nothing else in the file changes — the `{batch_id}`, `{finding_ids}`, `{run_dir}`, `{source_access}` and `{artifact_path}` placeholders and the return-contract line must come through untouched, or `test_workflow_supplies_every_var_its_template_declares` and `skill_lint`'s `no-return-contract` rule will say so.

`references/briefs/audit-brief.md` — add one line to the section describing where output goes, after the existing `cba_findings` instruction:

```
If a finding's root cause is a shape that could appear elsewhere in the tree,
register it: `audit.py put --table cba_patterns --set id=<id> --set name=...
--set regex=... --set origin_finding=<your finding id>`. The orchestrator
sweeps every registered pattern corpus-wide before the phase exits.
```

Read the file first and place this where its existing output instructions sit; do not restructure the section.

- [ ] **Step 9: `SKILL.md` (CRLF)**

**CRLF.** Four edits, all insertions except where noted.

*(a)* In `### SQL Tables`, after the `cba_checkpoints` row:

```markdown
| `cba_components` | What each artifact is, with the evidence that says so | recon |
| `cba_chains` | Composed exploit chains, ordered finding ids | audit |
```

*(b)* In `## Essential Principles`, append five numbered items continuing that list's numbering (read the file to find the last number; do not renumber what is there):

```markdown
N. **A FALSE_POSITIVE must say what refuted it and what that mechanism
   enables.** `audit.py pivot` writes both. Unconditional — a refuting
   mechanism is code, and code does something.
N+1. **A confirmed pattern is swept.** Register it in `cba_patterns`, sweep
   with `audit.py sweep`, and check with `audit.py patterns --gate`.
N+2. **Coverage has a denominator.** One `cba_inventory` row per analysable
   unit; `audit.py coverage --gate` fails on an empty inventory, a budget
   skip, or an inventoried unit with no decision recorded.
N+3. **An identity needs evidence that is not the filename.**
   `audit.py identify` refuses evidence that only repeats the path.
N+4. **Chains cross groups, so something must look across them.**
   `audit.py chain` proposes; a human composes.
```

*(c)* In `## Rationalizations to Reject`, five rows appended to the table:

```markdown
| "It's a false positive — verdict recorded, move on" | A FALSE_POSITIVE is invalid without `refuting_mechanism` and the observation of what that mechanism enables. A finding was once correctly refuted by a 300-byte sliding-window flush that is itself the attack surface for a CRITICAL. Use `audit.py pivot`. |
| "No attacker-controlled path, so there's nothing to record" | That IS the observation. Write it. A blank is what the rule forbids, not a negative result. |
| "The pattern only shows up in this one file" | You have not swept. `audit.py sweep --record`, then `audit.py patterns --gate`. `strncpy(dst, src, strlen(src))` was found twice, named, and never grepped for; two CRITICALs are that pattern elsewhere. |
| "It's called `km0_boot`, so it's the bootloader" | A filename is an assertion by whoever named it. `audit.py identify` with evidence you read out of the artifact. That exact file holds a Wi-Fi driver and several CRITICALs. |
| "Each group's findings are independent" | Chains cross groups, and per-group subagents cannot see across them. Run `audit.py chain` before the audit phase exits. |
```

*(d)* In `### Artifact Layout`, nothing changes — the new mechanisms write to `audit.db`, not to new files. Confirm this rather than assuming it.

- [ ] **Step 10: Two `skill_lint` rules**

In `audit_core/skill_lint.py`, same design as `RETIRED_QUERIES`: literal substrings pinning two specific mistakes. Add after `RETIRED_QUERIES`:

```python
# Two shapes that are correct SQL and wrong practice, each pinning a mistake
# this project has made. Same scope statement as the rule above: a clean run
# means these specific mistakes are absent, not that the skill works.
FP_VERDICT_INSERT = ("--tablecba_fp_verdicts", "verdict=false_positive")
PATTERN_INSERT = "--tablecba_patterns"
```

and inside the per-file loop, after the `RETIRED_QUERIES` check:

```python
        if all(n in squashed for n in FP_VERDICT_INSERT) \
                and "audit.pypivot" not in squashed:
            findings.append(Finding(
                "fp-verdict-without-pivot", rel,
                "documents writing a FALSE_POSITIVE through `put` without "
                "naming `audit.py pivot`; the verdict is refused without "
                "refuting_mechanism and enabled_observation"))

        if PATTERN_INSERT in squashed and "audit.pysweep" not in squashed:
            findings.append(Finding(
                "pattern-registered-without-sweep", rel,
                "registers a bug pattern without naming `audit.py sweep`; a "
                "pattern that is never swept is the tplink miss exactly"))
```

`_squash` removes whitespace entirely, which is why the needles carry none — do not "fix" them by adding spaces back.

- [ ] **Step 11: Guard tests for the prose**

Append to `tests/test_workflow_prose.py`:

```python
def test_every_stage3_verb_appears_in_shipped_prose():
    """A mechanism nothing invokes is a mechanism that does not run. Each
    verb must be named somewhere a phase actually reads."""
    text = "\n".join(p.read_text(encoding="utf-8") for p in live_markdown())
    for verb in ("audit.py pivot", "audit.py patterns", "audit.py identify",
                 "audit.py chain", "audit.py coverage"):
        assert verb in text, f"no shipped workflow or reference invokes {verb}"


def test_the_coverage_gate_is_invoked_at_a_phase_exit():
    assert "coverage --db ${AUDIT_DIR}/audit.db --gate" in \
        (ROOT / "workflows" / "audit.md").read_text(encoding="utf-8")


def test_the_pivot_rule_is_stated_as_unconditional():
    """It must not soften into "where applicable". The whole value is that it
    forces the question on every false positive."""
    for rel in ("workflows/fpcheck.md", "references/briefs/fpcheck-brief.md"):
        text = (ROOT / rel).read_text(encoding="utf-8").lower()
        assert "unconditional" in text, rel
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "refuting_mechanism" in skill


def test_the_five_stage3_rationalizations_are_in_the_rejection_table():
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    for needle in ("audit.py pivot", "That IS the observation",
                   "audit.py patterns --gate", "km0_boot",
                   "audit.py chain"):
        assert needle in text, needle


def test_skill_md_lists_the_two_new_tables():
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    for table in ("cba_components", "cba_chains"):
        assert table in text


def test_the_fpcheck_brief_kept_its_placeholders_and_return_contract():
    """The brief rewrite is the exact shape Stage 1 lost instructions in."""
    text = (ROOT / "references" / "briefs" / "fpcheck-brief.md").read_text()
    for var in ("{batch_id}", "{finding_ids}", "{run_dir}",
                "{source_access}", "{artifact_path}"):
        assert var in text, var
    assert "rows=<n> artifact=" in text
    assert "18 Hard Exclusions and 10 Precedent rules" in text
    assert "Capability Validity checks CV-1 to CV-3" in text
```

Extend the existing `test_every_instruction_the_replaced_blocks_sat_inside_survives` dict with the one line this task replaces:

```python
        "workflows/fpcheck.md": [
            "identify the missing batch and re-spawn just that one",
            "Order TPs by severity",
            "cites a specific HE/PR/CV rule",      # survived the pivot edit
        ],
```

Append to `tests/test_skill_lint.py`. That file has no tree-building helper — each test builds the tree inline — and it defines `KNOWN = set(audit.HANDLERS)` at module level. Follow both:

```python
def test_an_fp_verdict_insert_without_pivot_is_flagged(tmp_path):
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        "python3 audit.py put --table cba_fp_verdicts "
        "--set verdict=FALSE_POSITIVE\n")
    findings = skill_lint.lint(root, KNOWN)
    assert [f.rule for f in findings] == ["fp-verdict-without-pivot"]
    assert "audit.py pivot" in findings[0].detail


def test_the_same_file_naming_pivot_is_not_flagged(tmp_path):
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        "python3 audit.py put --table cba_fp_verdicts "
        "--set verdict=FALSE_POSITIVE\n"
        "Use `audit.py pivot` instead -- it writes both fields.\n")
    assert skill_lint.lint(root, KNOWN) == []


def test_a_pattern_insert_without_a_sweep_is_flagged(tmp_path):
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        "python3 audit.py put --table cba_patterns --set id=P1\n")
    findings = skill_lint.lint(root, KNOWN)
    assert [f.rule for f in findings] == ["pattern-registered-without-sweep"]
```

Each asserts the **exact** finding list rather than membership, which is how `test_a_retired_status_query_in_prose_is_a_finding` is written: a rule that fires alongside an unintended second rule is a rule that will be noisy on real prose.

- [ ] **Step 12: Reconcile the derivation against the real diff**

This is the step the Stage 1 finding exists for. Run:

```bash
git diff -U0 -- SKILL.md workflows/ references/ > /tmp/stage3-prose.diff
grep -c '^-[^-]' /tmp/stage3-prose.diff
```

Then, in §2 of the derivation document:

1. List **every** hunk in that diff, and map each to a row in §1.
2. List **every removed line** — each `^-` line that is not a `---` file header — and account for it individually: which row removed it, and why. "Reformatted" is not an account; quote where the text went.
3. State the count explicitly: *"N lines removed from shipped prose: <breakdown>. English instructions lost: <count>."* The expected answer is **zero English instructions lost** — this task replaces exactly one line (the fpcheck quality-check bullet, Step 4) and that line's text survives inside its replacement.

A hunk with no row, or a removed line with no account, is a defect found before review rather than after. Fix the prose or add the row, then re-run.

- [ ] **Step 13: Check line endings survived**

```bash
for f in SKILL.md references/phase0-source-detection.md \
         references/phase2-feature-mapping.md references/phase4-deep-audit.md \
         references/phase5-fp-check.md; do
  printf '%s ' "$f"; grep -c $'\r' "$f"
done
for f in workflows/*.md references/briefs/*.md references/lessons-learned.md \
         references/workflow-orchestration.md references/resume-note-template.md \
         references/phase6-report.md; do
  if grep -q $'\r' "$f"; then echo "CRLF LEAKED INTO $f"; fi
done
```

Expected: the first loop prints a non-zero count for each of the five CRLF files; the second prints nothing.

- [ ] **Step 14: Run everything**

Run: `python3 -m pytest -q && python3 audit.py selftest && python3 audit.py lint-skill`
Expected: all PASS, `lint-skill` clean. If `lint-skill` reports `fp-verdict-without-pivot` against `references/phase5-fp-check.md`, that is Step 10's rule firing correctly on Step 5's own file — the file names `audit.py pivot`, so it should not; if it does, the needle or the file disagrees and the file is right.

- [ ] **Step 15: Verify a clean install still works**

**Override all three variables.** A real installation exists at `~/.claude/skills/codebase-audit/`.

```bash
TMPHOME=$(mktemp -d)
HOME="$TMPHOME" CLAUDE_CONFIG_DIR="$TMPHOME/.claude" CODEX_HOME="$TMPHOME/.codex" \
  ./install.sh claude
grep -rl '__SKILL_DIR__' "$TMPHOME/.claude/skills/codebase-audit" \
  --include='*.md' | tee /dev/stderr | wc -l
python3 "$TMPHOME/.claude/skills/codebase-audit/audit.py" selftest
```

Expected: exit 0, **zero** markdown files carrying the sentinel, `selftest` reporting 20 verbs from the installed tree. Then confirm the real install is untouched: `ls -ld ~/.claude/skills/codebase-audit` — the mtime must be unchanged.

- [ ] **Step 16: Commit**

```bash
git add SKILL.md workflows/ references/ audit_core/skill_lint.py \
        tests/test_workflow_prose.py tests/test_skill_lint.py \
        docs/superpowers/derivations/2026-10-05-stage3-prose-derivation.md
git commit -m "$(cat <<'MSG'
feat: the skill invokes the five Stage 3 mechanisms

Five mechanisms existed and nothing called them. recon inventories units and
identifies components; audit registers and sweeps patterns, runs the chain
pass, and gates on coverage at its exit; fpcheck takes the pivot on every
false positive.

Written against a derivation produced before the edits, per the Stage 1
finding that rewriting shipped prose lost instructions five times out of five
and that absence is the hardest thing to review for. One existing line is
replaced -- the fpcheck FALSE_POSITIVE quality check -- and its text survives
verbatim inside the replacement. Everything else is an insertion.

Two lint rules pin the two mistakes this prose could still make: an FP
verdict documented through `put`, and a pattern registered without a sweep.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 9: The gate documents, and the tiering change held behind its measurement

Spec §7: Stage 3's additions are "**each benchmarked separately so attribution is possible**", and the tiering change ships "last and alone … with precision measured before and after".

None of that can happen in this repository. A benchmark is a full tplink audit run. This task writes the two procedures that say so plainly and say exactly what to run, in the same shape as `docs/baselines/2026-10-05-stage2-gate.md` — which states `**Status: NOT RUN.**` in its first line, and is the reason this project has not yet reported an ungated result as a gated one.

It also re-aims the two tests that quarantine the tiering change (ruling S1). They were written to say "Stage 1 tiers effort, not the model, because that is Stage 3's". That reason expires the moment this stage lands, and a guard test whose stated reason is false gets deleted by the next person who reads it.

**Files:**
- Create: `docs/baselines/2026-10-05-stage3-gate.md`
- Create: `docs/baselines/2026-10-05-stage3-tiering-gate.md`
- Modify: `tests/test_workflow_prose.py` (two docstrings and their assertions)
- Modify: `docs/baselines/README.md` (index the two new documents, following its existing format)

**Interfaces:** none. This task ships documents and test reasons.

- [ ] **Step 1: Write `docs/baselines/2026-10-05-stage3-gate.md`**

LF. Structure it on the Stage 2 gate document; the sections it must carry:

1. **`**Status: NOT RUN.**`** as the first line, with a pointer to the section that says what that means.
2. **The gate, verbatim** from spec §7 and §6.1, including "no change merges if recall drops" and the ≥ 9/19 floor that Stage 2 also has to clear. Note explicitly that **the Stage 2 gate is also still open**, so a Stage 3 run measures Stages 2 and 3 together unless Stage 2 is gated first — and that this is the sequencing decision the operator has to make before running anything.
3. **Separate benchmarking, and why it is expensive.** §7 wants each addition attributed. Five additions × two runs each = ten full tplink audits, which at the $658 baseline is not a thing anyone will do. State the affordable alternative and its cost: the five additions ship as five separate commits, so the gate runs **once** for the stage, and attribution — if the pair moves — comes from reverting one commit and re-running, exactly as §6 of the Stage 2 gate document specifies for Stage 2's levers. Say plainly that this is weaker than what §7 asks for.
4. **Deterministic leading indicators**, which is what §6.1 offers between milestones and what this stage can actually produce. These need no second run and are the reason the stage is worth shipping before its gate:

   | Indicator | Command | What a Stage 3 run should show against Stage 2 |
   |---|---|---|
   | Coverage percentage and gate verdict | `audit.py coverage --db <db> --gate` | a denominator exists at all; Stage 2 runs had none |
   | `not_audited` rows with reasons | `audit.py coverage --db <db>` | non-zero, with reasons, rather than silence |
   | Patterns registered and swept | `audit.py patterns --db <db>` | non-zero registered, zero unswept |
   | Pattern sweep hits | `audit.py rows --db <db> --table cba_pattern_hits` | the sweep found call sites the per-group pass did not |
   | Pivot observations | `audit.py rows --db <db> --table cba_security_observations` | one per FALSE_POSITIVE verdict |
   | Components with evidence | `audit.py identify --db <db>` | one per confirmed artifact |
   | Chain candidates and compositions | `audit.py chain --db <db>`; `audit.py rows --table cba_chains` | proposals read; compositions recorded |
   | Precision | `audit.py bench --golden <g> --db <db>` | a number, for the first time |

5. **The commands**, copied from §4 of the Stage 2 gate document with the Stage 3 verbs added, and the same `REPO` / `RUN` / `SESSION` three-root warning — `install.sh` does not copy `tests/`, so `bench` runs from the checkout.
6. **If recall falls**, repeating §6.1's rule verbatim and naming the revert-one-commit attribution path.
7. **"This gate has not been run"**, carrying forward the three standing verification gaps from the Stage 2 document (gate not run, `install.ps1` never executed, `preflight` never handed to a real MCP client) **plus** the one this stage adds: **no precision figure exists for any run**, so §7's tiering gate has no baseline.

- [ ] **Step 2: Write `docs/baselines/2026-10-05-stage3-tiering-gate.md`**

LF. This is the shorter document and the more load-bearing one, because it is the only record of why a spec-mandated change was not made.

It must carry:

1. **What is held and why.** Spec §7 assigns Sonnet tiering for feature mapping and `fpcheck` to Stage 3, conditioned on precision measured before and after. `bench` could not score precision until Task 7. There is no before-measurement, so the change is held. Ruling S1, with its cost-if-wrong.
2. **The procedure.** Two runs on the current (strongest-tier) configuration to establish precision-before; apply the diff in §3; two runs to establish precision-after; compare. §6.1's one-finding noise allowance applies to recall; state what the equivalent allowance is for precision and that it is a judgment, not a measured threshold — with 45 findings a one-verdict move is ~2 points.
3. **The exact diff to apply**, verbatim, so that applying it later is transcription:

   | File | From | To |
   |---|---|---|
   | `SKILL.md` → *Model and effort tiering* table | `Feature mapping, FP-check batches \| strongest tier, effort tiered down \| low to medium` | `Feature mapping, FP-check batches \| mid tier \| low to medium` |
   | `SKILL.md` → *Model and effort tiering*, the paragraph beginning **"Feature mapping and FP-check keep the strongest model"** | the whole paragraph | a replacement stating the measured precision before and after, and the date of the gate run |
   | `SKILL.md` → *Subagent Configuration* table, rows `recon (mapping)` and `fpcheck` | `strongest tier, low effort` / `strongest tier, medium effort` | `mid tier, low effort` / `mid tier, medium effort` |
   | `workflows/recon.md` → Step 5 **Model:** line | `strongest tier, low effort` | `mid tier, low effort` |
   | `workflows/fpcheck.md` → Step 4 **Model:** line | `strongest tier, medium effort` | `mid tier, medium effort` |
   | `tests/test_workflow_prose.py` | the two quarantine tests re-aimed in Step 3 below | inverted to assert `mid tier`, with the gate date in the docstring |

   Note that `workflows/audit.md`'s deep-audit tier is **not** in this table. §5.1 keeps L-dark hunt, chain composition and final severity calls on the strongest tier; the spec's "surface, L-sink and fpcheck" names the `firmware-audit` phases, whose `codebase-audit` analogues are feature mapping and FP-check. Say this, so a later reader does not extend the diff to the audit phase.
4. **What reverting costs:** one commit. §8's risk table already says so — "reverting is one table row".

- [ ] **Step 3: Re-aim the two quarantine tests**

In `tests/test_workflow_prose.py`, the assertions do not change — `mid tier` stays forbidden, `strongest tier` stays required. Only the stated reason changes, and it must change, because the old one is now false.

```python
@pytest.mark.parametrize("name", ["recon.md", "fpcheck.md"])
def test_mapping_and_fpcheck_keep_the_strongest_model(name):
    """Spec section 7 ships Sonnet tiering for mapping and fpcheck "last and
    alone ... with precision measured before and after".

    Stage 3 built the measurement (`bench` now scores precision) and did not
    take the measurement: that needs two full tplink runs, which this
    repository cannot do. No precision figure exists for any run, so the
    before-number the spec conditions the change on does not exist.

    The procedure and the exact diff this test guards are in
    docs/baselines/2026-10-05-stage3-tiering-gate.md. Change this test when
    that gate has been run, and put the date in the docstring.
    """
    text = (ROOT / "workflows" / name).read_text()
    assert "mid tier" not in text, (
        f"{name} downgrades the model with no precision baseline to compare "
        f"against; see docs/baselines/2026-10-05-stage3-tiering-gate.md")
    assert "strongest tier" in text


def test_skill_md_subagent_table_keeps_the_strongest_model_for_both():
    """Same gate as test_mapping_and_fpcheck_keep_the_strongest_model: no
    precision baseline exists. docs/baselines/2026-10-05-stage3-tiering-gate.md
    holds the procedure and the exact diff."""
    text = (ROOT / "SKILL.md").read_text()
    for row in ("| recon (mapping) |", "| fpcheck |"):
        line = next(l for l in text.splitlines() if l.startswith(row))
        assert "strongest tier" in line, line
        assert "mid tier" not in line, line
```

The parametrize list is already `["recon.md", "fpcheck.md"]` and stays that way. `audit.md` is deliberately not in it: §5.1 keeps deep audit, chain composition and final severity calls on the strongest tier **permanently**, not provisionally, so it does not belong in a test about a held change. Do not add it here.

- [ ] **Step 4: Add a test that the held change is documented where someone will find it**

Append to `tests/test_workflow_prose.py`:

```python
def test_the_tiering_gate_document_exists_and_says_it_has_not_run():
    """A spec-mandated change that was not made needs a record, or the next
    reader finds a quarantine test with no explanation and deletes it."""
    path = ROOT / "docs" / "baselines" / "2026-10-05-stage3-tiering-gate.md"
    text = path.read_text(encoding="utf-8")
    assert "NOT RUN" in text
    assert "precision" in text.lower()
    assert "mid tier" in text, "the document must carry the exact diff to apply"


def test_the_stage3_gate_document_says_it_has_not_run():
    path = ROOT / "docs" / "baselines" / "2026-10-05-stage3-gate.md"
    assert "**Status: NOT RUN.**" in path.read_text(encoding="utf-8")
```

- [ ] **Step 5: Index both documents in `docs/baselines/README.md`**

Read that file and follow its existing format. Do not restructure it.

- [ ] **Step 6: Run everything**

Run: `python3 -m pytest -q && python3 audit.py selftest && python3 audit.py lint-skill`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add docs/baselines/ tests/test_workflow_prose.py
git commit -m "$(cat <<'MSG'
docs: the Stage 3 gates, and why the tiering change is held

Spec 7 wants each addition benchmarked separately. A benchmark is a full
tplink run, so five additions attributed separately is ten runs at the $658
baseline. The gate document says that plainly and specifies the affordable
alternative -- one gated pair, with per-lever attribution by reverting one
commit -- and says it is weaker than what the spec asks for.

The tiering change is held. Spec 7 conditions it on "precision measured
before and after"; Task 7 built the measurement and nobody has taken it. The
two tests that quarantined the change keep their assertions and get a true
reason: the old one, "that is Stage 3's job", expires with this stage, and a
guard test whose stated reason is false gets deleted by the next reader.

The exact diff to apply once the gate runs is written out, so applying it is
transcription rather than redesign.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## What Stage 3 deliberately does not do

Each of these is a decision, not an oversight. Anything here that an implementer "fixes" is scope the reviewer should reject.

| Not done | Why | Where it belongs |
|---|---|---|
| Run the Stage 3 gate, or the Stage 2 gate | A gate is two full tplink audit runs. Neither is possible here, and Stage 2's is still open — so a Stage 3 run measures both stages together unless Stage 2 is gated first. | `docs/baselines/2026-10-05-stage3-gate.md`; the operator's sequencing call |
| Apply the Sonnet tiering prose change | Ruling S1: §7 conditions it on precision measured before and after, and no precision figure exists for any run. The measurement ships; the change does not. | `docs/baselines/2026-10-05-stage3-tiering-gate.md`, which carries the exact diff |
| Benchmark the five additions separately | §7 asks for it; it is ten full runs at the $658 baseline. The five ship as five revertible commits instead, which makes attribution answerable without being automatic. | Stage 3 gate doc §3, stated as weaker than the spec asks |
| Cross-target persistence for the pattern library | §3.5.2 says "The pattern library persists across targets." `cba_patterns` lives in one run's `audit.db`; there is no export, no import and no shared store, and this is the one §3.5 clause that shipped with neither an implementation nor a recorded decision — so this row is the decision. Building it is a new mechanism (a store outside the run directory, a merge rule for two targets' patterns, and a provenance rule for a hit found on a target the pattern did not come from), and adding one unplanned at the end of a stage is how scope creep enters. **The consequence, stated plainly: sweep-on-confirm does not compound across audits yet.** Every run starts with an empty pattern library and re-derives what the last run already learned; the `strncpy(dst, src, strlen(src))` shape confirmed on tplink is not carried into the next target. | Stage 4 |
| `cba_unknowns`, two-lane hunt, device-state model, `qualify`/`diff`/`decide` | §4 assigns all of these to `firmware-audit`. | Stage 4 |
| The rung vocabulary and `core/evidence-ladder.md` | §6.2's destination column names a `core/` that does not exist yet. Precision is defined here against this skill's existing `fpcheck` verdicts, deliberately, so it is measurable today. | Stage 4's monorepo restructure |
| Monorepo restructure, `firmware-audit` sibling | §3.1 and §7. | Stage 4 |
| Backport to `grey-audit` | §7. | Stage 5 |
| Wire any gate into `put` or `init` | Ruling S3. A gate that blocks writes strands a run with no way to record the rows that clear it. | — |
| Touch `matches.json` or `rejections.json` | Human adjudications. `bench` proposes; a human decides. | — |
| Close the two carried verification gaps (`install.ps1` unexecuted, `preflight` never given to a real MCP client) | No PowerShell on this machine; no MCP client run available. | Carried into the Stage 3 gate doc's §7, so the open items stay in one place |

---

## Execution Notes

**Task order is a dependency chain for Tasks 1-6.** Task 1 creates the columns and tables every later task writes to. Tasks 2-6 are independent of each other and could be reordered, but each one's `audit.py` edit touches `HANDLERS` and `build_parser`, so running them in parallel conflicts. Task 7 is independent of 2-6 and depends only on Task 2 (its `verdicts` helper writes a `FALSE_POSITIVE`). Task 8 depends on 2-6 being complete, because it documents their flags. Task 9 depends on Task 7.

**Expected verb count after each task:** 16 → 16 (T1) → 17 (T2) → 18 (T3) → 18 (T4) → 19 (T5) → 20 (T6) → 20 (T7-T9). Run `python3 audit.py selftest` at the end of each task; a count that does not match means `HANDLERS` and `build_parser` have drifted.

**Expected table count after Task 1:** `selftest` reports `tables 15 in schema.sql, 14 under contract`. The one-table difference is `sqlite_sequence`, created by the `AUTOINCREMENT` columns.

**The three big-blast-radius edits**, each of which will break tests in files the task does not name — this is expected, and fixing them is part of the task:
1. Task 1's `apply_schema` → `SchemaResult`: three call sites, all named in Step 11.
2. Task 2's verdict validator: every `FALSE_POSITIVE` write in the repository. A grep at the time of writing finds none in `tests/`, and two in shipped prose (`references/phase5-fp-check.md`, `references/briefs/fpcheck-brief.md`) which Task 8 handles. Re-grep rather than trusting this sentence.
3. Task 1's two new tables: `tests/test_workspace.py`'s `EXPECTED_TABLES`, and anything asserting a table count.

**Never run `install.sh` without all three environment overrides.** Task 8 Step 15 is the only step that runs it.

**Line endings.** `grep -c $'\r' <file>` before and after every markdown edit. Task 8 Step 13 checks all of them at once, but a flipped file is far cheaper to catch at the moment it flips.

**Do not soften the pivot rule.** The single most likely quality failure in this stage is prose that qualifies "unconditional" into "where applicable" — in the workflow, the brief, SKILL.md, or a commit message. The rule's entire value is that it forces the question on every false positive. Task 8's `test_the_pivot_rule_is_stated_as_unconditional` guards two files; the others are on the reviewer.

---

## Self-Review

Run against the spec after writing the plan.

**1. Spec coverage.** §3.5's three mechanisms: pivot (Task 2), sweep-on-confirm (Task 3), coverage denominator (Task 4). §1.3's remaining two named causes that §7 assigns here: identity discipline (Task 5), chain composition (Task 6). §3.4's state model: `cba_components` and `cba_chains` land in Task 1 with the columns §3.4 lists; `cba_unknowns` is Stage 4's, recorded above. §6.1's four bench metrics: recall and cost per match exist; precision is Task 7; **coverage is reported by `audit.py coverage` rather than by `bench`** — a deliberate split, because coverage reads a run database and bench reads a run database plus a golden, and nothing is gained by routing one through the other. §5.1's tiering: held, Task 9, ruling S1. §7's "each benchmarked separately": not done, Task 9 Step 1 §3, stated as weaker than asked.

*Gap found and accepted:* §6.2's table routes several mechanisms to a `core/` directory that does not exist until Stage 4. This plan implements their behaviour in `audit_core/` and leaves the file layout to Stage 4. Named in "What Stage 3 deliberately does not do".

**2. Placeholder scan.** No "TBD", no "add appropriate error handling", no "similar to Task N". Every code step carries the code. Two steps direct the implementer to read a file before editing rather than quoting it: Task 8 Step 8 (`references/briefs/audit-brief.md`'s output section) and Task 9 Step 5 (`docs/baselines/README.md`'s index format). Both are "insert one line following the existing format", where quoting the surrounding file would be longer than reading it and would go stale.

**3. Type consistency.** Checked across tasks: `db.migrate` returns `list[str]` and `workspace.SchemaResult.migrated` holds it (T1); `patterns.mark_swept(con, id, *, hit_count, when=None)` is called by `sweep.record` with `hit_count=len(result.hits)` and no `when` (T3); `coverage.gate` takes a `CoverageReport` and `cmd_coverage` builds one before calling it (T4); `db.check_identity_evidence` is defined in T5 Step 3 and re-exported in Step 4 under the name T5's tests call (`identity.check_evidence`); `chains.compose`'s `finding_ids` is the comma string `_validate_chain` parses (T1/T6); `bench.Precision` is constructed in T7 Step 3 and consumed in Step 5 with `.decided` and `.fraction`, both defined. `db.MAX_ROWS` bounds `chains.propose`; `patterns.MAX_PATTERNS` bounds `patterns.states`.

**4. Review Focus.** All five have a named test in the task that owns the code: RF1 → Task 1 Steps 7-9; RF2 → Task 2 Step 8 (`test_put_rejects_a_bare_false_positive_and_points_at_pivot`); RF3 → Task 3 Step 5 (`test_record_refuses_a_truncated_sweep`); RF4 → Task 4 Step 1 (`test_an_empty_inventory_fails_the_gate`); RF5 → Task 6 Step 1 (`test_generic_english_overlap_alone_does_not_propose`, `test_the_candidate_list_is_capped`).

**5. Test-fixture reality check.** Every helper this plan's tests call either exists in the target file or is defined by the same step. Verified against the current tree: `tests/test_sweep.py` has a `con` fixture and `tree()` — not a `swept_fixture`; `tests/test_coverage.py` has a `con` fixture and `inventory()` — not a `fresh()`; `tests/test_cli_bench.py` has `make_golden()` and `make_db()` — not a `bench_fixture`; `tests/test_skill_lint.py` has `KNOWN` and builds trees inline — it has no tree helper. Stage 2's pre-flight scan caught a plan that invented three such helpers; this check is why that is not repeated.
