# Stage 2 — `audit_core`, R1 and R3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared `audit_core` modules (validated db access, coverage
accounting, extract-then-fan-out, the annotation journal, the context ceiling,
the sweep engine) and wire R1 and R3 into the shipped `codebase-audit` skill
without changing a single phase's semantics.

**Architecture:** Nine tasks. Tasks 1-6 add stdlib-only modules under
`audit_core/` plus one `audit.py` verb each, every one independently testable
against a temporary run directory. Task 7 rewrites the shipped prose so the
orchestrator reads bounded rows and files instead of raw material, and
produces a line-by-line derivation artifact proving nothing was dropped. Task 8
makes the new surface enforceable (one lint rule, a selftest that cross-checks
the table contract against the database the schema actually builds, an
installer that prunes deleted files). Task 9 sharpens the scorer so the Stage 2
gate can be run twice without re-adjudicating the same false pairs.

**Tech Stack:** Python 3.10+, stdlib only (`sqlite3`, `json`, `re`, `pathlib`,
`os`, `hashlib`, `dataclasses`, `argparse`). pytest for tests. Bash and
PowerShell installers. Markdown for the shipped skill.

**Spec:** `docs/superpowers/specs/2026-10-04-audit-suite-design.md` — §3.3
(core boundary), §3.4 (state model), §3.5 (the three new mechanisms), §5 R1,
§5 R3, §6.2 (machinery that must survive), §7 Stage 2.

**Prior stages:** `docs/superpowers/plans/2026-10-04-stage0-instrumentation-and-goldens.md`,
`docs/superpowers/plans/2026-10-05-stage1-economics.md`. Their carried findings
are in `docs/superpowers/specs/2026-10-05-stage0-findings-for-later-stages.md`
and `...stage1-findings-for-later-stages.md`; this plan closes four of them and
names the rest where they land.

---

## Scope Rulings

The spec's Stage 2 bullet is one sentence. Four readings of it would have
produced materially different work, so each is settled here, with what it
costs if the ruling is wrong.

**S1 — No repository restructure in Stage 2.** Spec §3.1 draws a monorepo at
`Tools/audit-suite/` with `skills/codebase-audit/`, `skills/grey-audit/` and
`skills/firmware-audit/`. The Stage 2 bullet does not name it, and its words
"vendored into `codebase-audit`" are already satisfied: Stage 1's installer
copies `audit_core/` and `audit.py` into every install target. A monorepo
holding one skill is a rename that invalidates every `__SKILL_DIR__` path and
both installers for no benchmark benefit. The restructure moves to Stage 4,
where the second sibling actually exists. **Cost if wrong:** Stage 4 carries a
mechanical `git mv` plus installer path edits — hours, not rework.

**S2 — `extract.py` is backend-agnostic; only the source-tree backend ships.**
Spec R1 says `audit.py extract` is "the only place `mcp__autorev__*` is
called". A stdlib Python process cannot call an agent-side MCP tool, and §3.3
puts "how to extract (source tree / IDA / carved image)" on the *per sibling*
side of the core boundary. So Stage 2 ships the part that is core: the
snapshot store, the manifest, content-addressed versioning, `--refresh`, and
the **one-writer / assert-at-every-batch-boundary discipline** as a `Backend`
protocol the caller supplies. `codebase-audit`'s backend reads a source tree.
The IDA backend lands with `firmware-audit` in Stage 4 behind the same
interface. **Cost if wrong:** Stage 4 writes an MCP-client backend against an
interface that already exists; the interface is what Stage 2 commits to.

**S3 — Coverage and sweep ship as mechanism, not as gates.** Spec §7 assigns
the *behaviours* — the coverage denominator and sweep-on-confirm — to Stage 3,
"each benchmarked separately so attribution is possible". Stage 2's own
constraint is "existing phase semantics unchanged". So `coverage.py` and
`sweep.py` ship with their verbs and their tests, rows are recorded
additively, and **nothing in Stage 2 fails a run on either**. **Cost if
wrong:** Stage 3 wires consumers into prose that already has the data.

**S4 — The schema is extended additively under the `cba_` prefix.** Spec §3.4
lists eleven unprefixed tables (`runs`, `components`, `inventory`, …). That is
`firmware-audit`'s schema and it arrives in Stage 4. Stage 2 adds five tables
to the existing seven, all `cba_`-prefixed, all `IF NOT EXISTS`, and touches
no existing column. **Cost if wrong:** Stage 4 writes its own schema file;
the two coexist, which §3.1 already assumes by giving each skill its own
`audit.py`.

---

## Global Constraints

Every task's requirements implicitly include this section.

- **Python 3.10+, stdlib only.** No third-party imports in `audit_core/` or
  `audit.py`. `pyproject.toml` declares `dependencies = []` and
  `requires-python = ">=3.10"`; both stay true. pytest is a dev extra and is
  imported only by `tests/`.
- **No network access** in any module or test.
- **`~/Documents/Offsec/Opswat/Devices/` and `~/.claude/projects/` are
  READ-ONLY.** Tests never read them; they use `tests/fixtures/build.py`
  synthetic transcripts. Steps that read a real transcript are manual,
  read-only, and record their output in a doc.
- **Never run `install.sh` or `install.ps1` without overriding `HOME`,
  `CLAUDE_CONFIG_DIR` and `CODEX_HOME`.** The user's working installation at
  `~/.claude/skills/codebase-audit/` must not be touched.
- **Schema statements are all `CREATE TABLE IF NOT EXISTS`.** `audit.py init`
  is run again at the start of each phase; re-running a phase must never
  destroy a row an earlier phase recorded.
- **Line endings are per-file and must be preserved.** `SKILL.md`,
  `references/phase2-feature-mapping.md`, `references/phase4-deep-audit.md`
  and `references/phase5-fp-check.md` are **CRLF**. `workflows/*.md`,
  `references/resume-note-template.md`, `references/lessons-learned.md` and
  `references/briefs/*.md` are **LF**. `pathlib.read_text()` /
  `write_text()` silently converts; use `read_bytes()` / `write_bytes()`, or
  edit in place with a tool that preserves endings, and verify with
  `file -b <path> | grep -o CRLF` before committing.
- **Verb parity.** `HANDLERS` in `audit.py` is the single source of truth for
  which verbs exist. Every key has a subparser; every subparser has a key.
  `lint-skill` reads `HANDLERS`; the selftest asserts the parity.
- **Bounded output.** No verb prints unbounded rows or file contents. A verb
  that produces many rows prints counts plus the `audit.py rows …` command
  that reads them. This is R1 applied to the tooling itself.
- **Existing behaviour is frozen.** The seven `cba_*` tables keep their
  columns. The 173 tests passing at `c7d5944` keep passing. No phase changes
  what it does, only how it records and reads it.

---

## Review Focus

Five input classes the spec implies, that no task's own happy path exercises,
ordered by how badly they bite. Each has its test pinned to the task that owns
the code.

1. **A unit or snapshot name containing `..`, `/` or a leading dot.** A
   feature-group id or a source path flows straight into a filesystem path
   under `<run>/extract/`. A path that escapes the run directory is the worst
   outcome in this plan. Expected: `ExtractError` naming the component, before
   anything is written. **Pinned in Task 3, Step 9.**
2. **A journal line that is CRLF-terminated, or a truncated final line from a
   crash mid-append.** JSONL is append-only precisely so a crash costs one
   line; a reader that silently drops lines turns that into lost
   comprehension. Expected: the good entries are returned and the bad line
   numbers are *named*, never silently skipped. **Pinned in Task 4, Step 7.**
3. **A sweep over a tree containing a directory symlink loop, a 40 MB minified
   bundle, and a binary blob.** Expected: no hang, no decode explosion, and
   the skipped counts reported rather than absorbed. **Pinned in Task 6,
   Step 7.**
4. **A `put` whose value contains a quote, a semicolon or a NUL, or whose
   `--set` names a column that does not exist.** A generic row writer is an
   injection surface and a silent-drop surface. Expected: values are bound
   parameters and survive byte-for-byte; an unknown column raises `DbError`
   naming it. **Pinned in Task 1, Step 11.**
5. **`coverage` on a run whose inventory is empty.** The obvious
   implementation divides by zero on the first real invocation, because
   inventory is populated in a later phase than the one that reports.
   Expected: a report that says the inventory is empty and how to populate it,
   with no exception and no "0.0%" that reads as a coverage failure.
   **Pinned in Task 2, Step 7.**

---

## File Structure

**Create:**

| File | Responsibility |
|---|---|
| `audit_core/text.py` | Normalizing a root cause and a location into comparable keys. Shared by dedup (Task 1) and golden scoring (Task 9), because both answer "same defect?" and both learned the same lesson from the `tss` false pairs. |
| `audit_core/db.py` | The table contract: which tables are writable, which columns they have, which are required, which values are legal. One validated `put`, one bounded `rows`, the standard `status` counts, and dedup-by-root-cause. |
| `audit_core/coverage.py` | The coverage *report* only. Its vocabularies live in `db.py` with the other table contracts. |
| `audit_core/extract.py` | Snapshot store, manifest, versioning, and the batch-boundary assertion. Plus the source-tree backend. |
| `audit_core/annotations.py` | The append-only JSONL comprehension journal and its bounded index. |
| `audit_core/ceiling.py` | The R3 projection and the linear-model cross-check. |
| `audit_core/sweep.py` | The bounded corpus sweep. |
| `tests/test_text.py`, `tests/test_db.py`, `tests/test_coverage.py`, `tests/test_extract.py`, `tests/test_annotations.py`, `tests/test_ceiling.py`, `tests/test_sweep.py`, `tests/test_cli_stage2.py` | One test file per module, plus one for verb wiring. |
| `docs/superpowers/derivations/2026-10-05-stage2-prose-derivation.md` | Old instruction text against new, one row per replacement, with a justification for every line that does not survive. Required by Stage 1 finding #1. |
| `docs/baselines/2026-10-05-stage2-gate.md` | The two-run gate procedure and what it records. |
| `tests/goldens/tplink-dl110v2-1.0.11/rejections.json` | Adjudicated non-matches, so the gate's two runs do not re-adjudicate the same pairs. |

**Modify:**

| File | Change |
|---|---|
| `audit_core/schema.sql` | Five new `IF NOT EXISTS` tables appended. Existing seven untouched. |
| `audit_core/bench.py` | Candidate generation uses `text.location_tokens`; `score()` consults rejections. |
| `audit_core/goldens.py` | `load_rejections()`. |
| `audit_core/budget.py` | No change. Read by `ceiling.py`. |
| `audit_core/skill_lint.py` | One new rule, `hand-typed-status-sql`. |
| `audit.py` | Nine new verbs; selftest becomes a real cross-check. |
| `SKILL.md` | R1 and R3 sections; five new table rows; `extract/` and `journal.jsonl` in the artifact layout; three new rationalization rows. **CRLF.** |
| `workflows/audit.md`, `workflows/fpcheck.md`, `workflows/report.md`, `workflows/recon.md` | Hand-typed SQL replaced by verbs. **LF.** |
| `references/phase2-feature-mapping.md`, `references/phase4-deep-audit.md`, `references/phase5-fp-check.md` | INSERT blocks replaced by `audit.py put`. **CRLF.** |
| `references/resume-note-template.md` | Three SELECTs replaced by `audit.py status`. **LF.** |
| `install.sh` | Prune `workflows/`, `references/` and `audit_core/` before copying. |
| `tests/test_workflow_prose.py`, `tests/test_skill_lint.py`, `tests/test_install.py`, `tests/test_bench.py`, `tests/test_goldens.py`, `tests/test_cli.py` | Extended. |

---

## Task 1: The table contract — `text.py` and `db.py`

**Why this exists.** The orchestrator typed SQL by hand. The three status
SELECTs in `references/resume-note-template.md` were retyped once per
compaction restart; the deep-audit INSERT in `references/phase4-deep-audit.md`
was retyped once per feature group. That is R5's target. But a shell alias for
`sqlite3` would not be worth a module — what earns it is the *contract*: a
`put` that names a column the table does not have, or a verdict with an
invented value, must fail loudly instead of writing a row nothing ever reads.
This task also closes §6.2's "Dedup by root cause → `audit_core/db.py` → unit
test", which until now was a sentence in `phase4-deep-audit.md` asking the
orchestrator to compare 45 findings by eye.

**Files:**
- Create: `audit_core/text.py`
- Create: `audit_core/db.py`
- Create: `tests/test_text.py`
- Create: `tests/test_db.py`
- Modify: `audit.py` (four verbs: `put`, `rows`, `status`, `dedup`)
- Modify: `tests/test_cli.py` (verb parity list)

**Interfaces:**
- Consumes: `audit_core.workspace.init_run`, `audit_core.workspace.apply_schema`.
- Produces, used by Tasks 2, 5, 6, 7 and 9:
  - `text.root_cause_key(value: str | None) -> str`
  - `text.location_tokens(value: str | None) -> frozenset[str]`
  - `text.MIN_LOCATION_TOKEN: int` (= 4)
  - `db.DbError(Exception)`
  - `db.TableSpec` (frozen dataclass: `columns: tuple[str, ...]`, `required: tuple[str, ...]`, `validate: Callable[[dict[str, str]], None] | None`)
  - `db.TABLE_SPECS: dict[str, TableSpec]` — Task 2 adds five entries, Task 6 adds the pattern validator
  - `db.connect(db_path, *, read_only: bool = False) -> sqlite3.Connection`
  - `db.put(con, table: str, row: dict[str, str], *, replace: bool = False) -> None`
  - `db.rows(con, table, *, where=None, columns=None, limit=MAX_ROWS) -> list[sqlite3.Row]`
  - `db.status(con) -> Status`, `db.render_status(s: Status) -> str`
  - `db.duplicates(con) -> list[DuplicatePair]`
  - `db.MAX_ROWS: int` (= 200), `db.SEVERITIES`, `db.VERDICTS`

### Steps

- [ ] **Step 1: Write the failing tests for `text.py`**

Create `tests/test_text.py`:

```python
from audit_core import text


def test_root_cause_key_normalizes_case_punctuation_and_whitespace():
    a = "Unbounded memcpy() into a fixed stack buffer."
    b = "unbounded   memcpy  into a fixed stack buffer"
    assert text.root_cause_key(a) == text.root_cause_key(b)
    assert text.root_cause_key(a) == "unbounded memcpy into a fixed stack buffer"


def test_root_cause_key_of_nothing_is_empty_not_an_error():
    assert text.root_cause_key(None) == ""
    assert text.root_cause_key("   ") == ""
    assert text.root_cause_key("!!!") == ""


def test_location_tokens_drops_tokens_shorter_than_the_minimum():
    """The tplink golden produced two false pairs from the bare token `tss`.

    REF-10 (a degenerate strncpy in update_bind_token) paired against
    G6-F3 (RSA key disclosure via ATTPGV) and G6-F4 (ATTPSK key-store
    overwrite) purely because `tss` is a substring of `TssRSASecretKey`
    and `osal_tss_init`. Four characters is the floor.
    """
    assert text.MIN_LOCATION_TOKEN == 4
    assert "tss" not in text.location_tokens("osal_tss_init tss")
    assert "osal_tss_init" in text.location_tokens("osal_tss_init tss")


def test_location_tokens_splits_on_path_and_address_punctuation():
    got = text.location_tokens("src/handlers/klap.c:120 klap_handshake1_handle@0x0E043264")
    assert "handlers" in got
    assert "klap_handshake1_handle" in got
    assert "0x0E043264".lower() in got
    assert "src" not in got        # three characters
    assert "120" not in got        # three characters


def test_location_tokens_is_case_insensitive():
    assert text.location_tokens("KlapHandshake") == text.location_tokens("klaphandshake")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_text.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'audit_core.text'`

- [ ] **Step 3: Write `audit_core/text.py`**

```python
"""Normalization shared by finding dedup and golden scoring.

Both answer the same question - are these two records the same defect - and
both learned the same lesson from the tplink golden: a three-character
location token pairs with everything. The rule is stated once, here.
"""
from __future__ import annotations

import re

MIN_LOCATION_TOKEN = 4

_WS = re.compile(r"\s+")
_NOISE = re.compile(r"[^a-z0-9 ]+")
_TOKEN = re.compile(r"[A-Za-z0-9_]+")


def root_cause_key(value: str | None) -> str:
    """Lowercase, replace punctuation with spaces, collapse whitespace.

    Two findings written by different subagents describe the same mechanism
    in different words far more often than they describe it identically, so
    this is a coarse key by design: it is used to *propose* a duplicate, never
    to merge one.
    """
    return _WS.sub(" ", _NOISE.sub(" ", (value or "").lower())).strip()


def location_tokens(value: str | None) -> frozenset[str]:
    """Lowercased tokens of at least MIN_LOCATION_TOKEN characters.

    Shorter tokens are dropped. In the tplink golden the bare token `tss`
    matched `TssRSASecretKey` and `osal_tss_init`, producing two candidate
    pairs between entirely unrelated defects, each of which cost a human
    adjudication to reject.
    """
    return frozenset(t.lower() for t in _TOKEN.findall(value or "")
                     if len(t) >= MIN_LOCATION_TOKEN)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_text.py -v`
Expected: 5 passed

- [ ] **Step 5: Write the failing tests for `db.py`**

Create `tests/test_db.py`:

```python
import sqlite3

import pytest

from audit_core import db, workspace

FINDING = {
    "id": "G1-F1", "group_id": "G1", "title": "stack overflow in klap handshake",
    "severity": "HIGH", "confidence": "9", "location": "src/klap.c:120",
    "root_cause": "unbounded memcpy into a fixed stack buffer",
    "impact": "pre-auth remote code execution",
}


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    yield c
    c.close()


def test_connect_rejects_a_missing_database_with_the_fix_in_the_message(tmp_path):
    with pytest.raises(db.DbError) as exc:
        db.connect(tmp_path / "nope.db")
    assert "audit.py init" in str(exc.value)


def test_put_writes_a_row_that_rows_reads_back(con):
    db.put(con, "cba_findings", dict(FINDING))
    got = db.rows(con, "cba_findings", columns=("id", "severity", "location"))
    assert [tuple(r) for r in got] == [("G1-F1", "HIGH", "src/klap.c:120")]


def test_put_rejects_an_unknown_table(con):
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_nope", {"id": "x"})
    assert "cba_findings" in str(exc.value)      # names what IS writable


def test_put_rejects_an_unknown_column_and_names_it(con):
    bad = dict(FINDING) | {"sevrity": "HIGH"}
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_findings", bad)
    assert "sevrity" in str(exc.value)


def test_put_rejects_a_missing_required_column_and_names_it(con):
    bad = {k: v for k, v in FINDING.items() if k != "impact"}
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_findings", bad)
    assert "impact" in str(exc.value)


def test_put_treats_a_blank_required_column_as_missing(con):
    """`--set impact=` is the same failure as omitting it, and `briefs.py`
    already learned that an empty value reported as success is worse than a
    loud rejection."""
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_findings", dict(FINDING) | {"impact": "   "})
    assert "impact" in str(exc.value)


def test_put_rejects_an_invented_severity(con):
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_findings", dict(FINDING) | {"severity": "SEVERE"})
    assert "SEVERE" in str(exc.value)


def test_put_rejects_an_invented_verdict(con):
    db.put(con, "cba_findings", dict(FINDING))
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_fp_verdicts", {"finding_id": "G1-F1", "verdict": "PROBABLY"})
    assert "PROBABLY" in str(exc.value)


def test_put_without_replace_rejects_a_duplicate_primary_key(con):
    db.put(con, "cba_findings", dict(FINDING))
    with pytest.raises(db.DbError):
        db.put(con, "cba_findings", dict(FINDING))


def test_put_with_replace_overwrites(con):
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"severity": "CRITICAL"}, replace=True)
    assert db.rows(con, "cba_findings", columns=("severity",))[0][0] == "CRITICAL"


def test_put_binds_values_so_quotes_and_semicolons_survive_intact(con):
    """Review Focus 4. A root cause legitimately contains `'` and `;`.

    The column names are whitelisted against the TableSpec, so they can be
    interpolated; the values never are.
    """
    nasty = "strcpy(dst, src); the caller's bound is never checked -- see note"
    db.put(con, "cba_findings", dict(FINDING) | {"root_cause": nasty})
    assert db.rows(con, "cba_findings", columns=("root_cause",))[0][0] == nasty
    # The table still exists: the semicolon did not terminate a statement.
    assert db.rows(con, "cba_findings", columns=("id",))[0][0] == "G1-F1"


def test_rows_rejects_an_unknown_column_in_where(con):
    with pytest.raises(db.DbError) as exc:
        db.rows(con, "cba_findings", where={"sevrity": "HIGH"})
    assert "sevrity" in str(exc.value)


def test_rows_is_bounded_even_when_asked_for_more(con):
    for i in range(5):
        db.put(con, "cba_findings", dict(FINDING) | {"id": f"G1-F{i}"})
    assert len(db.rows(con, "cba_findings", limit=10_000)) <= db.MAX_ROWS
    assert len(db.rows(con, "cba_findings", limit=2)) == 2


def test_status_counts_groups_findings_and_verdicts(con):
    db.put(con, "cba_feature_groups", {"id": "G1", "name": "auth", "status": "complete"})
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"id": "G1-F2", "severity": "LOW"})
    db.put(con, "cba_fp_verdicts", {"finding_id": "G1-F1", "verdict": "TRUE_POSITIVE"})
    s = db.status(con)
    assert s.groups == (("G1", "auth", "complete"),)
    assert ("G1", "HIGH", 1) in s.findings_by_group_severity
    assert ("G1", "LOW", 1) in s.findings_by_group_severity
    assert s.verdicts == (("TRUE_POSITIVE", 1),)
    assert s.totals == {"groups": 1, "findings": 2, "verdicts": 1, "unverdicted": 1}


def test_render_status_names_the_unverdicted_gap(con):
    db.put(con, "cba_findings", dict(FINDING))
    out = db.render_status(db.status(con))
    assert "unverdicted" in out
    assert "1" in out


def test_duplicates_pairs_the_same_root_cause_across_groups(con):
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {
        "id": "G2-F3", "group_id": "G2", "confidence": "7",
        "root_cause": "Unbounded memcpy, into a fixed stack buffer!",
        "location": "src/klap.c:124",
    })
    pairs = db.duplicates(con)
    assert len(pairs) == 1
    assert pairs[0].keep == "G1-F1"        # confidence 9 beats 7
    assert pairs[0].drop == "G2-F3"
    assert "klap" in pairs[0].shared_locations


def test_duplicates_ignores_two_findings_in_the_same_group(con):
    """Within a group one subagent wrote both; cross-group collision is the
    case phase4 asked the orchestrator to catch by eye."""
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"id": "G1-F2"})
    assert db.duplicates(con) == []


def test_duplicates_ignores_a_shared_root_cause_in_unrelated_files(con):
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {
        "id": "G2-F1", "group_id": "G2", "location": "src/upnp/ssdp.c:41",
    })
    assert db.duplicates(con) == []


def test_duplicates_never_deletes_anything(con):
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"id": "G2-F3", "group_id": "G2"})
    db.duplicates(con)
    assert len(db.rows(con, "cba_findings")) == 2
```

- [ ] **Step 6: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_db.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'audit_core.db'`

- [ ] **Step 7: Write `audit_core/db.py`**

```python
"""Validated, bounded access to a run's audit.db.

The orchestrator used to type this SQL by hand. The three status SELECTs in
the resume-note template were retyped once per compaction restart, and the
deep-audit INSERT once per feature group - R5's target exactly. What makes
this a module rather than a shell alias is the contract: `put` knows which
columns each table has, which are required, and which values are legal, so a
typo fails loudly instead of writing a row nothing reads.
"""
from __future__ import annotations

import pathlib
import sqlite3
from dataclasses import dataclass
from typing import Callable

from audit_core import text

MAX_ROWS = 200

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
VERDICTS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE", "NEEDS_VERIFICATION")


class DbError(Exception):
    """A put or a query violated the table contract."""


Validator = Callable[[dict[str, str]], None]


@dataclass(frozen=True, slots=True)
class TableSpec:
    columns: tuple[str, ...]
    required: tuple[str, ...]
    validate: Validator | None = None


def one_of(column: str, allowed: tuple[str, ...]) -> Validator:
    def check(row: dict[str, str]) -> None:
        value = row.get(column)
        if value is not None and value not in allowed:
            raise DbError(f"{column}={value!r} is not one of {', '.join(allowed)}")
    return check


TABLE_SPECS: dict[str, TableSpec] = {
    "cba_sources": TableSpec(
        columns=("id", "type", "source_path", "source_language",
                 "source_file_count", "ida_binary", "ida_port", "ida_arch",
                 "confirmed_at"),
        required=("id", "type")),
    "cba_feature_groups": TableSpec(
        columns=("id", "name", "description", "key_paths", "status", "created_at"),
        required=("id", "name")),
    "cba_attack_surface": TableSpec(
        columns=("id", "group_id", "endpoint", "method", "auth_required",
                 "description"),
        required=("group_id", "endpoint")),
    "cba_security_observations": TableSpec(
        columns=("id", "group_id", "observation", "severity_hint", "location"),
        required=("group_id", "observation")),
    "cba_known_findings": TableSpec(
        columns=("id", "title", "location", "source", "patched_in", "severity", "raw"),
        required=("id", "title")),
    "cba_findings": TableSpec(
        columns=("id", "group_id", "title", "severity", "confidence", "cwe",
                 "location", "root_cause", "impact", "attacker_position",
                 "boundary_crossed", "data_flow", "verified", "poc",
                 "remediation", "artifact_path", "created_at"),
        required=("id", "group_id", "title", "severity", "confidence",
                  "location", "root_cause", "impact"),
        validate=one_of("severity", SEVERITIES)),
    "cba_fp_verdicts": TableSpec(
        columns=("finding_id", "verdict", "reason", "final_severity", "final_id",
                 "merged_into", "rule_applied", "reviewed_at"),
        required=("finding_id", "verdict"),
        validate=one_of("verdict", VERDICTS)),
}


def connect(db_path: str | pathlib.Path, *, read_only: bool = False) -> sqlite3.Connection:
    path = pathlib.Path(db_path)
    if not path.is_file():
        raise DbError(f"no audit.db at {path}; run `audit.py init` first")
    if read_only:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    return con


def _spec(table: str) -> TableSpec:
    spec = TABLE_SPECS.get(table)
    if spec is None:
        raise DbError(f"{table} is not a known table; "
                      f"known: {', '.join(sorted(TABLE_SPECS))}")
    return spec


def put(con: sqlite3.Connection, table: str, row: dict[str, str],
        *, replace: bool = False) -> None:
    """Insert one validated row.

    Column names are interpolated into the statement, which is safe only
    because every one of them has just been checked against the spec's own
    tuple of names. Values are always bound parameters.
    """
    spec = _spec(table)
    unknown = sorted(set(row) - set(spec.columns))
    if unknown:
        raise DbError(f"{table} has no column(s): {', '.join(unknown)}; "
                      f"columns are: {', '.join(spec.columns)}")
    missing = sorted(c for c in spec.required if not str(row.get(c, "")).strip())
    if missing:
        raise DbError(f"{table} requires a non-empty value for: {', '.join(missing)}")
    if spec.validate is not None:
        spec.validate(row)
    cols = sorted(row)
    verb = "INSERT OR REPLACE" if replace else "INSERT"
    sql = (f"{verb} INTO {table} ({', '.join(cols)}) "
           f"VALUES ({', '.join('?' for _ in cols)})")
    try:
        con.execute(sql, [row[c] for c in cols])
    except sqlite3.IntegrityError as exc:
        raise DbError(f"{table}: {exc}; pass --replace to overwrite") from exc
    con.commit()


def rows(con: sqlite3.Connection, table: str, *,
         where: dict[str, str] | None = None,
         columns: tuple[str, ...] | None = None,
         limit: int = MAX_ROWS) -> list[sqlite3.Row]:
    """A bounded read. R1: the orchestrator reads rows, never raw material."""
    spec = _spec(table)
    cols = tuple(columns) if columns else spec.columns
    unknown = sorted(set(cols) - set(spec.columns))
    if unknown:
        raise DbError(f"{table} has no column(s): {', '.join(unknown)}")
    clause, params = "", []
    if where:
        bad = sorted(set(where) - set(spec.columns))
        if bad:
            raise DbError(f"{table} has no column(s): {', '.join(bad)}")
        keys = sorted(where)
        clause = " WHERE " + " AND ".join(f"{k} = ?" for k in keys)
        params = [where[k] for k in keys]
    bounded = max(1, min(int(limit), MAX_ROWS))
    sql = f"SELECT {', '.join(cols)} FROM {table}{clause} LIMIT ?"
    return con.execute(sql, [*params, bounded]).fetchall()


@dataclass(frozen=True, slots=True)
class Status:
    groups: tuple[tuple[str, str, str], ...]
    findings_by_group_severity: tuple[tuple[str, str, int], ...]
    verdicts: tuple[tuple[str, int], ...]
    totals: dict[str, int]


def status(con: sqlite3.Connection) -> Status:
    """The counts the resume-note template used to carry as three SELECTs."""
    groups = tuple(
        (r[0], r[1] or "", r[2] or "")
        for r in con.execute(
            "SELECT id, name, status FROM cba_feature_groups ORDER BY id"))
    by_gs = tuple(
        (r[0], r[1], r[2])
        for r in con.execute(
            "SELECT group_id, severity, COUNT(*) FROM cba_findings "
            "GROUP BY 1, 2 ORDER BY 1, 2"))
    verdicts = tuple(
        (r[0], r[1])
        for r in con.execute(
            "SELECT verdict, COUNT(*) FROM cba_fp_verdicts "
            "GROUP BY verdict ORDER BY verdict"))
    findings = con.execute("SELECT COUNT(*) FROM cba_findings").fetchone()[0]
    verdict_rows = con.execute("SELECT COUNT(*) FROM cba_fp_verdicts").fetchone()[0]
    return Status(
        groups=groups,
        findings_by_group_severity=by_gs,
        verdicts=verdicts,
        totals={"groups": len(groups), "findings": findings,
                "verdicts": verdict_rows,
                "unverdicted": max(0, findings - verdict_rows)},
    )


def render_status(s: Status) -> str:
    out: list[str] = []
    t = s.totals
    out.append(f"groups {t['groups']}   findings {t['findings']}   "
               f"verdicts {t['verdicts']}   unverdicted {t['unverdicted']}")
    if s.groups:
        out.append("  groups:")
        out.extend(f"    {gid:6s} {name:30.30s} {state}" for gid, name, state in s.groups)
    if s.findings_by_group_severity:
        out.append("  findings by group and severity:")
        out.extend(f"    {gid:6s} {sev:14s} {n}" for gid, sev, n in s.findings_by_group_severity)
    if s.verdicts:
        out.append("  verdicts:")
        out.extend(f"    {v:20s} {n}" for v, n in s.verdicts)
    return "\n".join(out)


@dataclass(frozen=True, slots=True)
class DuplicatePair:
    keep: str
    drop: str
    key: str
    shared_locations: tuple[str, ...]


def duplicates(con: sqlite3.Connection) -> list[DuplicatePair]:
    """Cross-group findings describing the same defect.

    phase4-deep-audit.md asked the orchestrator to do this by eye: "if two
    findings from different groups describe the same vulnerability at the same
    code location, keep the one with higher confidence". Across 45 findings
    that is 990 comparisons.

    Two findings pair when their normalized root causes are equal AND their
    location tokens intersect. This proposes; it never merges and never
    deletes. The orchestrator writes the DUPLICATE verdict.
    """
    found = con.execute(
        "SELECT id, group_id, confidence, location, root_cause "
        "FROM cba_findings ORDER BY id").fetchall()
    out: list[DuplicatePair] = []
    for i, a in enumerate(found):
        key = text.root_cause_key(a["root_cause"])
        if not key:
            continue
        a_tokens = text.location_tokens(a["location"])
        for b in found[i + 1:]:
            if a["group_id"] == b["group_id"]:
                continue
            if key != text.root_cause_key(b["root_cause"]):
                continue
            shared = a_tokens & text.location_tokens(b["location"])
            if not shared:
                continue
            hi, lo = ((a, b) if _conf(a) >= _conf(b) else (b, a))
            out.append(DuplicatePair(hi["id"], lo["id"], key, tuple(sorted(shared))))
    return out


def _conf(row: sqlite3.Row) -> int:
    try:
        return int(row["confidence"])
    except (TypeError, ValueError):
        return 0
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_db.py tests/test_text.py -v`
Expected: all passed

- [ ] **Step 9: Add the four verbs to `audit.py`**

Add the import beside the existing ones:

```python
from audit_core import db as db_mod  # noqa: E402
```

Add a shared helper and the four handlers above `HANDLERS`:

```python
def _parse_set(pairs: list[str]) -> dict[str, str] | None:
    out: dict[str, str] = {}
    for spec in pairs:
        name, sep, value = spec.partition("=")
        if not sep or not name:
            print(f"bad --set {spec!r}; expected NAME=VALUE", file=sys.stderr)
            return None
        out[name] = value
    return out


def _open_db(path: str, read_only: bool = False):
    try:
        return db_mod.connect(pathlib.Path(path).expanduser(), read_only=read_only)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return None


def cmd_put(args: argparse.Namespace) -> int:
    row = _parse_set(args.set)
    if row is None:
        return 1
    con = _open_db(args.db)
    if con is None:
        return 1
    try:
        db_mod.put(con, args.table, row, replace=args.replace)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    print(f"{args.table}: 1 row")
    return 0


def cmd_rows(args: argparse.Namespace) -> int:
    where = _parse_set(args.where)
    if where is None:
        return 1
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        got = db_mod.rows(con, args.table, where=where or None,
                          columns=tuple(args.columns.split(",")) if args.columns else None,
                          limit=args.limit)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    if args.json:
        print(json.dumps([dict(r) for r in got], indent=2))
        return 0
    for r in got:
        print("\t".join("" if v is None else str(v) for v in r))
    print(f"({len(got)} row(s), capped at {db_mod.MAX_ROWS})", file=sys.stderr)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        s = db_mod.status(con)
    finally:
        con.close()
    if args.json:
        print(json.dumps(dataclasses.asdict(s), indent=2))
    else:
        print(db_mod.render_status(s))
    return 0


def cmd_dedup(args: argparse.Namespace) -> int:
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        pairs = db_mod.duplicates(con)
    finally:
        con.close()
    if args.json:
        print(json.dumps([dataclasses.asdict(p) for p in pairs], indent=2))
        return 0
    if not pairs:
        print("dedup: no cross-group duplicate candidates")
        return 0
    for p in pairs:
        print(f"  keep {p.keep}  drop {p.drop}  shared: {', '.join(p.shared_locations)}")
    print(f"dedup: {len(pairs)} candidate pair(s) - these are proposals. "
          f"Record a decision with `audit.py put --table cba_fp_verdicts "
          f"--set finding_id=<drop> --set verdict=DUPLICATE --set merged_into=<keep>`.")
    return 0
```

Register them in `HANDLERS`:

```python
    "put": cmd_put,
    "rows": cmd_rows,
    "status": cmd_status,
    "dedup": cmd_dedup,
```

And in `build_parser()`:

```python
    pu = sub.add_parser("put", help="insert one validated row into a run's audit.db")
    pu.add_argument("--db", required=True, metavar="AUDIT_DB")
    pu.add_argument("--table", required=True)
    pu.add_argument("--set", action="append", default=[], metavar="NAME=VALUE")
    pu.add_argument("--replace", action="store_true")
    ro = sub.add_parser("rows", help="read bounded rows out of a run's audit.db")
    ro.add_argument("--db", required=True, metavar="AUDIT_DB")
    ro.add_argument("--table", required=True)
    ro.add_argument("--where", action="append", default=[], metavar="NAME=VALUE")
    ro.add_argument("--columns", default=None, metavar="A,B,C")
    ro.add_argument("--limit", type=int, default=db_mod.MAX_ROWS)
    ro.add_argument("--json", action="store_true")
    st = sub.add_parser("status", help="group, finding and verdict counts for a run")
    st.add_argument("--db", required=True, metavar="AUDIT_DB")
    st.add_argument("--json", action="store_true")
    dd = sub.add_parser("dedup", help="propose cross-group duplicate findings")
    dd.add_argument("--db", required=True, metavar="AUDIT_DB")
    dd.add_argument("--json", action="store_true")
```

- [ ] **Step 10: Write `tests/test_cli_stage2.py`**

`tests/test_cli.py` drives `audit.py` as a subprocess through a `run()` helper.
Follow that idiom; the new file is where every Stage 2 verb's CLI wiring is
tested, and Tasks 2-6 each append to it.

```python
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FINDING_ARGS = [
    "--set", "id=G1-F1", "--set", "group_id=G1", "--set", "title=t",
    "--set", "severity=HIGH", "--set", "confidence=9",
    "--set", "location=src/klap.c:120", "--set", "root_cause=rc",
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


def test_put_then_status_round_trips(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    assert run("put", "--db", db, "--table", "cba_findings", *FINDING_ARGS).returncode == 0
    r = run("status", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "findings 1" in r.stdout
    assert "unverdicted 1" in r.stdout


def test_put_with_an_unknown_column_exits_one_and_names_it(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("put", "--db", db, "--table", "cba_findings", "--set", "nope=1")
    assert r.returncode == 1
    assert "nope" in r.stderr


def test_rows_prints_the_requested_columns(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    run("put", "--db", db, "--table", "cba_findings", *FINDING_ARGS)
    r = run("rows", "--db", db, "--table", "cba_findings", "--columns", "id,severity")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "G1-F1\tHIGH"


def test_verbs_against_a_missing_db_exit_one_with_the_fix(tmp_path):
    r = run("status", "--db", str(tmp_path / "nope.db"))
    assert r.returncode == 1
    assert "audit.py init" in r.stderr


def test_dedup_on_an_empty_run_says_so_and_exits_zero(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("dedup", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "no cross-group duplicate candidates" in r.stdout
```

- [ ] **Step 11: Run the Review Focus 4 test explicitly, then the full suite**

Run: `python3 -m pytest tests/test_db.py::test_put_binds_values_so_quotes_and_semicolons_survive_intact -v`
Expected: PASS

Run: `python3 -m pytest -q`
Expected: all previously passing tests still pass, plus the new ones. Output
pristine — no warnings.

- [ ] **Step 12: Commit**

```bash
git add audit_core/text.py audit_core/db.py audit.py \
  tests/test_text.py tests/test_db.py tests/test_cli_stage2.py
git commit -m "feat: validated table contract, bounded reads, and dedup by root cause

audit_core/db.py carries the table contract - columns, required columns and
legal values - so a put that names a column the table does not have fails
loudly instead of writing a row nothing reads. Column names are interpolated
only after being checked against the spec's own tuple; values are always bound.

audit_core/text.py holds the normalization that dedup and golden scoring both
need, with the four-character floor the tplink `tss` false pairs argued for.

db.duplicates() closes spec section 6.2's dedup-by-root-cause row: 990
comparisons that phase4-deep-audit.md asked the orchestrator to do by eye."
```

---

## Task 2: Schema extension and coverage accounting

**Why this exists.** The tplink post-mortem's sharpest quality finding was that
whole layers were never opened — no finding below the IP layer — and nothing in
the record said so. "Have we audited everything?" was answered by reading the
feature-group list, which is a list of what we *chose* to look at, not a
denominator. Spec §3.5 makes `not_audited` rows with reasons mandatory.

Per ruling **S3**, Stage 2 ships the mechanism and reports it. Nothing here
fails a run; gating on coverage is a Stage 3 change that gets its own
benchmark. The one thing Stage 2 does enforce is the *shape* of the record: a
`not_audited` row without a reason is a gap that hides itself, so the table
contract rejects it.

**Files:**
- Modify: `audit_core/schema.sql` (five new tables appended)
- Modify: `audit_core/db.py` (five new `TableSpec` entries, two new vocabularies, the coverage validator)
- Create: `audit_core/coverage.py`
- Create: `tests/test_coverage.py`
- Modify: `tests/test_db.py`, `tests/test_workspace.py` (table list)
- Modify: `audit.py` (verb `coverage`)
- Modify: `tests/test_cli_stage2.py`

**Interfaces:**
- Consumes: `db.TableSpec`, `db.DbError`, `db.put`, `db.rows`, `db.connect`.
- Produces, used by Tasks 5, 6, 7 and 9:
  - `db.COVERAGE_STATES: tuple[str, ...]` = `("analyzed", "not_audited")`
  - `db.NOT_AUDITED_REASONS: tuple[str, ...]`
  - `db.INVENTORY_KINDS: tuple[str, ...]` = `("file", "function", "endpoint", "binary")`
  - `coverage.CoverageReport` (frozen dataclass)
  - `coverage.report(con, phase: str | None = None) -> CoverageReport`
  - `coverage.render(r: CoverageReport) -> str`
  - new tables `cba_inventory`, `cba_coverage`, `cba_patterns`, `cba_pattern_hits`, `cba_checkpoints`

### Steps

- [ ] **Step 1: Write the failing tests**

Create `tests/test_coverage.py`:

```python
import pytest

from audit_core import coverage, db, workspace


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    yield c
    c.close()


def inventory(con, *units, kind="file"):
    for u in units:
        db.put(con, "cba_inventory", {"unit": u, "kind": kind})


def test_a_not_audited_row_without_a_reason_is_rejected(con):
    """A gap with no reason is a gap that hides itself - the exact failure
    the tplink post-mortem found below the IP layer."""
    inventory(con, "src/a.c")
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_coverage",
               {"unit": "src/a.c", "phase": "audit", "state": "not_audited"})
    assert "reason" in str(exc.value)


def test_a_not_audited_row_with_an_invented_reason_is_rejected(con):
    inventory(con, "src/a.c")
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_coverage", {"unit": "src/a.c", "phase": "audit",
                                     "state": "not_audited", "reason": "meh"})
    assert "meh" in str(exc.value)
    assert "budget" in str(exc.value)      # names the legal vocabulary


def test_an_analyzed_row_needs_no_reason(con):
    inventory(con, "src/a.c")
    db.put(con, "cba_coverage",
           {"unit": "src/a.c", "phase": "audit", "state": "analyzed"})
    assert coverage.report(con).analyzed == 1


def test_an_invented_state_is_rejected(con):
    inventory(con, "src/a.c")
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_coverage",
               {"unit": "src/a.c", "phase": "audit", "state": "skimmed"})
    assert "skimmed" in str(exc.value)


def test_report_counts_analyzed_not_audited_and_unrecorded(con):
    inventory(con, "a.c", "b.c", "c.c", "d.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "audit", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "b.c", "phase": "audit", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "c.c", "phase": "audit",
                                 "state": "not_audited", "reason": "vendored"})
    r = coverage.report(con)
    assert (r.inventoried, r.analyzed, r.not_audited, r.unrecorded) == (4, 2, 1, 1)
    assert r.fraction == 0.5
    assert r.by_reason == (("vendored", 1),)


def test_report_separates_budget_skips_from_every_other_reason(con):
    """Spec R3: a group skipped for budget is a quality-gate failure, not a
    scope decision. Stage 3 gates on this number; Stage 2 surfaces it."""
    inventory(con, "a.c", "b.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "audit",
                                 "state": "not_audited", "reason": "budget"})
    db.put(con, "cba_coverage", {"unit": "b.c", "phase": "audit",
                                 "state": "not_audited", "reason": "out-of-scope"})
    r = coverage.report(con)
    assert r.budget_skips == 1
    assert r.not_audited == 2
    assert "budget" in coverage.render(r)


def test_report_on_an_empty_inventory_does_not_divide_by_zero(con):
    """Review Focus 5. Inventory is populated in a later phase than the first
    one that reports, so this is the first real invocation, not an edge case."""
    r = coverage.report(con)
    assert r.inventoried == 0
    assert r.fraction == 0.0
    text = coverage.render(r)
    assert "inventory is empty" in text
    assert "cba_inventory" in text          # says how to populate it
    assert "0.0%" not in text               # does not read as a coverage failure


def test_report_can_be_scoped_to_one_phase(con):
    inventory(con, "a.c", "b.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "recon", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "b.c", "phase": "audit", "state": "analyzed"})
    assert coverage.report(con, phase="audit").analyzed == 1
    assert coverage.report(con).analyzed == 2


def test_a_unit_analyzed_in_two_phases_counts_once_overall(con):
    inventory(con, "a.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "recon", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "audit", "state": "analyzed"})
    r = coverage.report(con)
    assert r.analyzed == 1
    assert r.unrecorded == 0


def test_an_inventory_row_needs_a_known_kind(con):
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_inventory", {"unit": "a.c", "kind": "thingy"})
    assert "thingy" in str(exc.value)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_coverage.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'audit_core.coverage'`

- [ ] **Step 3: Append the five tables to `audit_core/schema.sql`**

Append exactly this block. Preserve the file's existing line endings (LF).

```sql

-- Stage 2 additions. Every statement below is IF NOT EXISTS for the same
-- reason the block above is: `audit.py init` runs again at the start of each
-- phase, and re-running a phase must never destroy a row an earlier phase
-- recorded.

CREATE TABLE IF NOT EXISTS cba_inventory (
    unit TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    group_id TEXT,
    size INTEGER,
    added_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_coverage (
    unit TEXT NOT NULL,
    phase TEXT NOT NULL,
    state TEXT NOT NULL,
    reason TEXT,
    recorded_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (unit, phase));

CREATE TABLE IF NOT EXISTS cba_patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    regex TEXT NOT NULL,
    origin_finding TEXT,
    language TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_pattern_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER NOT NULL,
    excerpt TEXT,
    triaged TEXT DEFAULT 'pending',
    swept_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phase TEXT NOT NULL,
    reason TEXT NOT NULL,
    turns INTEGER,
    projected_context INTEGER,
    resume_note TEXT,
    recorded_at TEXT DEFAULT (datetime('now')));
```

- [ ] **Step 4: Add the vocabularies, the validator and the five specs to `audit_core/db.py`**

Beside `SEVERITIES` and `VERDICTS`:

```python
COVERAGE_STATES = ("analyzed", "not_audited")
NOT_AUDITED_REASONS = ("budget", "out-of-scope", "generated", "vendored",
                       "third-party", "unreachable", "binary-only")
INVENTORY_KINDS = ("file", "function", "endpoint", "binary")
CHECKPOINT_REASONS = ("phase-exit", "ceiling", "manual")
```

Beside `one_of`:

```python
def _validate_coverage(row: dict[str, str]) -> None:
    """A gap needs a reason, and the reason has to come from the list.

    Spec section 3.5: `not_audited` rows with reasons are mandatory. A row
    without one records that something was skipped while hiding why, which is
    strictly worse than no row - it makes the denominator look accounted for.
    """
    state = row.get("state")
    if state not in COVERAGE_STATES:
        raise DbError(f"state={state!r} is not one of {', '.join(COVERAGE_STATES)}")
    reason = (row.get("reason") or "").strip()
    if state != "not_audited":
        return
    if not reason:
        raise DbError("state=not_audited requires a reason; one of: "
                      + ", ".join(NOT_AUDITED_REASONS))
    if reason not in NOT_AUDITED_REASONS:
        raise DbError(f"reason={reason!r} is not one of: "
                      + ", ".join(NOT_AUDITED_REASONS))
```

Add to `TABLE_SPECS`:

```python
    "cba_inventory": TableSpec(
        columns=("unit", "kind", "group_id", "size", "added_at"),
        required=("unit", "kind"),
        validate=one_of("kind", INVENTORY_KINDS)),
    "cba_coverage": TableSpec(
        columns=("unit", "phase", "state", "reason", "recorded_at"),
        required=("unit", "phase", "state"),
        validate=_validate_coverage),
    "cba_patterns": TableSpec(
        columns=("id", "name", "regex", "origin_finding", "language", "notes",
                 "created_at"),
        required=("id", "name", "regex")),
    "cba_pattern_hits": TableSpec(
        columns=("id", "pattern_id", "path", "line", "excerpt", "triaged",
                 "swept_at"),
        required=("pattern_id", "path", "line")),
    "cba_checkpoints": TableSpec(
        columns=("id", "phase", "reason", "turns", "projected_context",
                 "resume_note", "recorded_at"),
        required=("phase", "reason"),
        validate=one_of("reason", CHECKPOINT_REASONS)),
```

`cba_patterns` gets its regex-compile validator in Task 6, which is where the
sweep that depends on it is written.

- [ ] **Step 5: Write `audit_core/coverage.py`**

```python
"""Coverage accounting: the denominator, not a feeling.

"Have we audited everything?" was answered by reading the feature-group list,
which records what we chose to look at. The tplink post-mortem found whole
layers never opened - not one finding below the IP layer - with nothing in the
record saying so. An inventory gives the question a denominator, and a
`not_audited` row with a reason turns a silent gap into a visible decision.

Stage 2 records and reports. Nothing here fails a run: gating on coverage is a
Stage 3 quality change that is benchmarked on its own, so that if recall moves
we know which change moved it.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from audit_core.db import NOT_AUDITED_REASONS


@dataclass(frozen=True, slots=True)
class CoverageReport:
    inventoried: int
    analyzed: int
    not_audited: int
    unrecorded: int
    by_reason: tuple[tuple[str, int], ...]
    budget_skips: int
    phase: str | None

    @property
    def fraction(self) -> float:
        """Analyzed over inventoried. Zero when nothing is inventoried -
        a run with no inventory has no coverage claim to make, in either
        direction."""
        return (self.analyzed / self.inventoried) if self.inventoried else 0.0


def _distinct_units(con: sqlite3.Connection, state: str,
                    phase: str | None) -> int:
    sql = "SELECT COUNT(DISTINCT unit) FROM cba_coverage WHERE state = ?"
    params: list[str] = [state]
    if phase is not None:
        sql += " AND phase = ?"
        params.append(phase)
    return con.execute(sql, params).fetchone()[0]


def report(con: sqlite3.Connection, phase: str | None = None) -> CoverageReport:
    inventoried = con.execute("SELECT COUNT(*) FROM cba_inventory").fetchone()[0]
    analyzed = _distinct_units(con, "analyzed", phase)
    not_audited = _distinct_units(con, "not_audited", phase)

    recorded_sql = ("SELECT COUNT(DISTINCT c.unit) FROM cba_coverage c "
                    "JOIN cba_inventory i ON i.unit = c.unit")
    params: list[str] = []
    if phase is not None:
        recorded_sql += " WHERE c.phase = ?"
        params.append(phase)
    recorded = con.execute(recorded_sql, params).fetchone()[0]

    reason_sql = ("SELECT reason, COUNT(*) FROM cba_coverage "
                  "WHERE state = 'not_audited' AND reason IS NOT NULL")
    rparams: list[str] = []
    if phase is not None:
        reason_sql += " AND phase = ?"
        rparams.append(phase)
    reason_sql += " GROUP BY reason ORDER BY reason"
    by_reason = tuple((r[0], r[1]) for r in con.execute(reason_sql, rparams))

    return CoverageReport(
        inventoried=inventoried,
        analyzed=analyzed,
        not_audited=not_audited,
        unrecorded=max(0, inventoried - recorded),
        by_reason=by_reason,
        budget_skips=dict(by_reason).get("budget", 0),
        phase=phase,
    )


def render(r: CoverageReport) -> str:
    scope = f" (phase {r.phase})" if r.phase else ""
    if r.inventoried == 0:
        return (f"coverage{scope}: the inventory is empty, so there is no "
                f"denominator to report.\n"
                f"  Populate it with `audit.py put --table cba_inventory "
                f"--set unit=<path> --set kind=file` per analysable unit.")
    out = [f"coverage{scope}: {r.analyzed}/{r.inventoried} analyzed "
           f"({100 * r.fraction:.1f}%)",
           f"  not_audited {r.not_audited}   unrecorded {r.unrecorded}"]
    if r.by_reason:
        out.append("  not_audited by reason:")
        out.extend(f"    {reason:16s} {n}" for reason, n in r.by_reason)
    if r.budget_skips:
        out.append(f"  WARNING: {r.budget_skips} unit(s) skipped for budget. "
                   f"The budget governs where tokens are spent, never whether "
                   f"a surface is opened - checkpoint and restart instead "
                   f"(SKILL.md, R3).")
    if r.unrecorded:
        out.append(f"  {r.unrecorded} inventoried unit(s) have no coverage row "
                   f"in this scope. Legal reasons: {', '.join(NOT_AUDITED_REASONS)}.")
    return "\n".join(out)
```

- [ ] **Step 6: Add the `coverage` verb to `audit.py`**

```python
from audit_core import coverage as coverage_mod  # noqa: E402


def cmd_coverage(args: argparse.Namespace) -> int:
    con = _open_db(args.db, read_only=True)
    if con is None:
        return 1
    try:
        r = coverage_mod.report(con, phase=args.phase)
    finally:
        con.close()
    if args.json:
        print(json.dumps(dataclasses.asdict(r) | {"fraction": r.fraction}, indent=2))
    else:
        print(coverage_mod.render(r))
    return 0
```

```python
    "coverage": cmd_coverage,
```

```python
    cv = sub.add_parser("coverage", help="analyzed vs inventoried, with reasons for every gap")
    cv.add_argument("--db", required=True, metavar="AUDIT_DB")
    cv.add_argument("--phase", default=None)
    cv.add_argument("--json", action="store_true")
```

- [ ] **Step 7: Extend `tests/test_workspace.py` and `tests/test_cli_stage2.py`**

In `tests/test_workspace.py`, add the five new names to `EXPECTED_TABLES`:

```python
EXPECTED_TABLES = [
    "cba_attack_surface", "cba_checkpoints", "cba_coverage",
    "cba_feature_groups", "cba_findings", "cba_fp_verdicts", "cba_inventory",
    "cba_known_findings", "cba_pattern_hits", "cba_patterns",
    "cba_security_observations", "cba_sources",
]
```

Add to `tests/test_cli_stage2.py`:

```python
def test_coverage_on_an_empty_inventory_exits_zero_and_explains(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("coverage", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "inventory is empty" in r.stdout


def test_coverage_reports_a_budget_skip_as_a_warning(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    run("put", "--db", db, "--table", "cba_inventory",
        "--set", "unit=src/a.c", "--set", "kind=file")
    run("put", "--db", db, "--table", "cba_coverage", "--set", "unit=src/a.c",
        "--set", "phase=audit", "--set", "state=not_audited", "--set", "reason=budget")
    r = run("coverage", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "WARNING" in r.stdout
    assert "checkpoint and restart" in r.stdout


def test_a_not_audited_row_without_a_reason_is_refused_at_the_cli(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("put", "--db", db, "--table", "cba_coverage", "--set", "unit=a.c",
            "--set", "phase=audit", "--set", "state=not_audited")
    assert r.returncode == 1
    assert "reason" in r.stderr
```

- [ ] **Step 8: Run the Review Focus 5 test, then the full suite**

Run: `python3 -m pytest tests/test_coverage.py::test_report_on_an_empty_inventory_does_not_divide_by_zero -v`
Expected: PASS

Run: `python3 -m pytest -q`
Expected: all pass, output pristine.

- [ ] **Step 9: Verify `init` is still idempotent against a populated database**

Run:

```bash
python3 - <<'EOF'
import pathlib, tempfile
from audit_core import db, workspace
with tempfile.TemporaryDirectory() as d:
    run = workspace.init_run(d, timestamp="t")
    con = db.connect(run / "audit.db")
    db.put(con, "cba_inventory", {"unit": "a.c", "kind": "file"})
    con.close()
    workspace.init_run(d, timestamp="t")          # second init
    con = db.connect(run / "audit.db")
    assert len(db.rows(con, "cba_inventory")) == 1, "init destroyed a row"
    print("init is idempotent against the extended schema")
EOF
```

Expected: `init is idempotent against the extended schema`

- [ ] **Step 10: Commit**

```bash
git add audit_core/schema.sql audit_core/db.py audit_core/coverage.py audit.py \
  tests/test_coverage.py tests/test_workspace.py tests/test_cli_stage2.py
git commit -m "feat: coverage accounting with a denominator and mandatory gap reasons

Five tables appended to the schema, all IF NOT EXISTS, none touching the
existing seven. cba_inventory is the denominator the tplink run never had -
it found no finding below the IP layer and nothing in the record said so.

The table contract rejects a not_audited row with no reason, or with a reason
outside the list. A gap without a reason is worse than no row: it makes the
denominator look accounted for.

Stage 2 reports; it does not gate. Gating on coverage is a Stage 3 change
with its own benchmark, so that a recall movement can be attributed."
```

---

## Task 3: Extract-then-fan-out — `extract.py`

**Why this exists.** This is R1, and R1 is the one rule in the spec where the
cost argument and the quality argument are the same argument. `autorev` shares
one stdio IDA session, so parallel subagents clobber each other; work stayed
serial and in the orchestrator's context; cost exploded *and* fan-out was
capped, which is why surfaces went unopened. Snapshotting the material to files
once removes both at the same time: the orchestrator holds paths, and fan-out
is bounded by nothing.

Per ruling **S2**, the backend is an interface. What is core — and what ships
here — is the snapshot store, the manifest, content-addressed versioning, and
the one-writer discipline: `assert_ready()` at every batch boundary, which is
§6.2's "One-IDA-writer, `assert_database` at every batch boundary →
`audit_core/extract.py` → unit test". The source-tree backend ships because
`codebase-audit` needs it. The IDA backend lands in Stage 4 behind the same
protocol.

**Files:**
- Create: `audit_core/extract.py`
- Create: `tests/test_extract.py`
- Modify: `audit.py` (verb `extract`)
- Modify: `tests/test_cli_stage2.py`

**Interfaces:**
- Consumes: nothing from earlier tasks. It writes files, not rows.
- Produces, used by Task 7 (prose) and Stage 4:
  - `extract.Backend` (Protocol: `name: str`, `assert_ready() -> None`, `read(item: str) -> bytes`)
  - `extract.SourceTree(root)` — the shipped backend
  - `extract.ExtractStore(run_dir)` with `.write(unit, name, data, backend=...) -> Record`, `.manifest() -> list[Record]`, `.items(unit) -> list[str]`
  - `extract.extract_batch(store, backend, unit, items, batch_size=BATCH_SIZE) -> list[Record]`
  - `extract.flatten(path: str) -> str`
  - `extract.Record` (frozen dataclass: `unit, name, relpath, source, sha256, bytes, version, truncated, backend, extracted_at`)
  - `extract.ExtractError`, `extract.BATCH_SIZE` (= 25), `extract.MAX_UNIT_BYTES` (= 512_000)

### Steps

- [ ] **Step 1: Write the failing tests**

Create `tests/test_extract.py`:

```python
import pytest

from audit_core import extract


class Flaky:
    """A backend that stops being ready partway through, which is what a
    clobbered shared decompiler session looks like from the caller's side."""

    name = "flaky"

    def __init__(self, fail_from_batch: int, batch_size: int):
        self.fail_from_batch = fail_from_batch
        self.batch_size = batch_size
        self.checks = 0

    def assert_ready(self) -> None:
        self.checks += 1
        if self.checks > self.fail_from_batch:
            raise RuntimeError("session handle is stale")

    def read(self, item: str) -> bytes:
        return f"body of {item}".encode()


def tree(tmp_path, **files):
    root = tmp_path / "src"
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body.encode() if isinstance(body, str) else body)
    return root


def test_write_records_a_snapshot_and_its_digest(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    rec = store.write("G1", "auth.c", b"int main(void){}")
    assert rec.relpath == "extract/G1/auth.c"
    assert (tmp_path / "run" / "extract" / "G1" / "auth.c").read_bytes() == b"int main(void){}"
    assert rec.version == 1
    assert rec.bytes == 16
    assert len(rec.sha256) == 64


def test_rewriting_identical_content_does_not_bump_the_version(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    first = store.write("G1", "auth.c", b"same")
    again = store.write("G1", "auth.c", b"same")
    assert (first.version, again.version) == (1, 1)


def test_rewriting_changed_content_bumps_the_version(tmp_path):
    """Spec section 8: extract snapshots go stale as understanding improves.
    The version is how a reader knows the file under it moved."""
    store = extract.ExtractStore(tmp_path / "run")
    store.write("G1", "auth.c", b"v1")
    second = store.write("G1", "auth.c", b"v2")
    assert second.version == 2
    assert (tmp_path / "run" / "extract" / "G1" / "auth.c").read_bytes() == b"v2"


def test_manifest_survives_a_reopen(tmp_path):
    extract.ExtractStore(tmp_path / "run").write("G1", "auth.c", b"x")
    again = extract.ExtractStore(tmp_path / "run")
    assert [r.name for r in again.manifest()] == ["auth.c"]


def test_oversized_content_is_truncated_and_says_so(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    rec = store.write("G1", "big.js", b"a" * (extract.MAX_UNIT_BYTES + 10))
    assert rec.truncated is True
    assert rec.bytes <= extract.MAX_UNIT_BYTES + 200
    body = (tmp_path / "run" / "extract" / "G1" / "big.js").read_bytes()
    assert b"truncated by audit.py extract" in body


def test_a_unit_name_that_escapes_the_run_directory_is_refused(tmp_path):
    """Review Focus 1. A feature-group id and a source path both reach the
    filesystem; `..` must never be one of them."""
    store = extract.ExtractStore(tmp_path / "run")
    for bad in ("..", "../G1", "G1/../..", "/etc", ".hidden"):
        with pytest.raises(extract.ExtractError) as exc:
            store.write(bad, "auth.c", b"x")
        assert bad in str(exc.value)
    assert not (tmp_path / "run" / "extract").exists()


def test_a_snapshot_name_that_escapes_is_refused(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    with pytest.raises(extract.ExtractError):
        store.write("G1", "../../etc/passwd", b"x")


def test_flatten_turns_a_source_path_into_a_safe_name():
    assert extract.flatten("src/handlers/klap.c") == "src_handlers_klap.c"
    assert extract.flatten("/abs/path.c") == "abs_path.c"
    assert extract.flatten("../../etc/passwd") == "etc_passwd"
    assert extract.flatten(".env") == "env"


def test_source_tree_refuses_to_read_outside_its_root(tmp_path):
    root = tree(tmp_path, **{"a.c": "x"})
    (tmp_path / "secret").write_text("s")
    backend = extract.SourceTree(root)
    with pytest.raises(extract.ExtractError) as exc:
        backend.read("../secret")
    assert "escapes" in str(exc.value)


def test_extract_batch_asserts_readiness_once_per_batch(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    backend = Flaky(fail_from_batch=99, batch_size=2)
    extract.extract_batch(store, backend, "G1", ["a", "b", "c", "d", "e"], batch_size=2)
    assert backend.checks == 3          # ceil(5 / 2)


def test_a_backend_that_fails_mid_run_aborts_and_names_the_batch(tmp_path):
    """Section 6.2's one-IDA-writer proof. A batch written after the session
    was clobbered is silently wrong, so the boundary check is the whole point."""
    store = extract.ExtractStore(tmp_path / "run")
    backend = Flaky(fail_from_batch=1, batch_size=2)
    with pytest.raises(extract.ExtractError) as exc:
        extract.extract_batch(store, backend, "G1", ["a", "b", "c", "d"], batch_size=2)
    msg = str(exc.value)
    assert "batch 1" in msg
    assert "flaky" in msg
    assert "stale" in msg
    # Batch 0 landed; batch 1 wrote nothing at all.
    assert sorted(r.name for r in store.manifest()) == ["a", "b"]


def test_a_read_failure_inside_a_batch_writes_none_of_that_batch(tmp_path):
    class Breaks:
        name = "breaks"
        def assert_ready(self): pass
        def read(self, item):
            if item == "c":
                raise OSError("gone")
            return b"ok"

    store = extract.ExtractStore(tmp_path / "run")
    with pytest.raises(OSError):
        extract.extract_batch(store, Breaks(), "G1", ["a", "b", "c"], batch_size=3)
    assert store.manifest() == []


def test_source_tree_round_trip(tmp_path):
    root = tree(tmp_path, **{"a.c": "alpha", "sub/b.c": "beta"})
    store = extract.ExtractStore(tmp_path / "run")
    recs = extract.extract_batch(store, extract.SourceTree(root), "G1",
                                 ["a.c", "sub/b.c"])
    assert sorted(r.name for r in recs) == ["a.c", "sub_b.c"]
    assert sorted(r.source for r in recs) == ["a.c", "sub/b.c"]
    assert (tmp_path / "run" / "extract" / "G1" / "sub_b.c").read_bytes() == b"beta"


def test_items_lists_what_a_unit_already_holds_so_refresh_can_re_read(tmp_path):
    root = tree(tmp_path, **{"a.c": "1", "b.c": "2"})
    store = extract.ExtractStore(tmp_path / "run")
    extract.extract_batch(store, extract.SourceTree(root), "G1", ["a.c", "b.c"])
    assert store.items("G1") == ["a.c", "b.c"]
    assert store.items("G2") == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_extract.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'audit_core.extract'`

- [ ] **Step 3: Write `audit_core/extract.py`**

```python
"""Extract once, fan out without a cap (spec R1).

This is the one rule where the cost argument and the quality argument are the
same argument. A shared stdio decompiler session cannot serve parallel
subagents, so work stayed serial and in the orchestrator's context: cost
exploded AND fan-out was capped, which is why surfaces went unopened.
Snapshotting the material to files once removes both at the same time.

The backend is an interface because *how* you extract is per-target - a source
tree is a copy, a stripped binary is a decompiler session, a flash dump is a
carve - while the discipline is not. The discipline lives here: assert the
backend is still the one writer at every batch boundary, and never write a
partial batch.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
import re
from dataclasses import asdict, dataclass
from typing import Iterable, Protocol

BATCH_SIZE = 25
MAX_UNIT_BYTES = 512_000
TRUNCATION_MARK = b"\n...truncated by audit.py extract at %d bytes...\n"

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ExtractError(Exception):
    """A name would escape the run directory, or a backend was not ready."""


class Backend(Protocol):
    name: str

    def assert_ready(self) -> None:
        """Raise if this process is no longer the sole writer of the source.

        grey-audit's `assert_database` at every batch boundary, generalized. A
        shared decompiler session clobbered by a parallel caller keeps
        answering - with another binary's data - so the batch written after
        that point is silently wrong.
        """

    def read(self, item: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class Record:
    unit: str
    name: str
    relpath: str
    source: str
    sha256: str
    bytes: int
    version: int
    truncated: bool
    backend: str
    extracted_at: str


def _safe(component: str, label: str) -> str:
    if not _SAFE.match(component):
        raise ExtractError(
            f"unsafe {label} {component!r}: must match {_SAFE.pattern}. "
            f"Flatten a path with extract.flatten() first.")
    return component


def flatten(path: str) -> str:
    """Flatten a source path into one safe snapshot filename.

    `src/handlers/klap.c` becomes `src_handlers_klap.c`: the snapshot tree is
    one directory per unit, so a reader finding a name knows the unit without
    walking, and a `..` in the input cannot survive the substitution.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/\\"))
    cleaned = cleaned.strip("._-")
    return cleaned or "unnamed"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class ExtractStore:
    """Snapshots under `<run>/extract/`, indexed by `<run>/extract/manifest.json`.

    The manifest is JSON on disk rather than a table because every downstream
    reader is a subagent with file access and no obligation to open the
    database, and because extraction legitimately runs before a run's db has
    anything else in it.
    """

    def __init__(self, run_dir: str | pathlib.Path):
        self.base = pathlib.Path(run_dir) / "extract"
        self.manifest_path = self.base / "manifest.json"

    def _load(self) -> dict[str, dict]:
        if not self.manifest_path.is_file():
            return {}
        try:
            raw = json.loads(self.manifest_path.read_text())
        except json.JSONDecodeError as exc:
            raise ExtractError(f"{self.manifest_path} is not valid JSON: {exc}") from exc
        return raw if isinstance(raw, dict) else {}

    def _save(self, index: dict[str, dict]) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(json.dumps(index, indent=2, sort_keys=True))

    def write(self, unit: str, name: str, data: bytes, *,
              source: str | None = None, backend: str = "source-tree") -> Record:
        _safe(unit, "unit name")
        _safe(name, "snapshot name")
        truncated = len(data) > MAX_UNIT_BYTES
        if truncated:
            data = data[:MAX_UNIT_BYTES] + (TRUNCATION_MARK % MAX_UNIT_BYTES)
        digest = hashlib.sha256(data).hexdigest()
        index = self._load()
        key = f"{unit}/{name}"
        prior = index.get(key)
        if prior is None:
            version = 1
        elif prior.get("sha256") == digest:
            version = int(prior.get("version", 1))
        else:
            version = int(prior.get("version", 1)) + 1
        target = self.base / unit / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        rec = Record(unit=unit, name=name, relpath=f"extract/{unit}/{name}",
                     source=source if source is not None else name,
                     sha256=digest, bytes=len(data), version=version,
                     truncated=truncated, backend=backend, extracted_at=_now())
        index[key] = asdict(rec)
        self._save(index)
        return rec

    def manifest(self) -> list[Record]:
        return [Record(**value) for _, value in sorted(self._load().items())]

    def items(self, unit: str) -> list[str]:
        """The source items already snapshotted for a unit, for `--refresh`."""
        return sorted(r.source for r in self.manifest() if r.unit == unit)


class SourceTree:
    """The `codebase-audit` backend: snapshot files out of a source checkout."""

    name = "source-tree"

    def __init__(self, root: str | pathlib.Path):
        self.root = pathlib.Path(root).resolve()

    def assert_ready(self) -> None:
        if not self.root.is_dir():
            raise ExtractError(f"source root is gone: {self.root}")

    def read(self, item: str) -> bytes:
        path = (self.root / item).resolve()
        if not path.is_relative_to(self.root):
            raise ExtractError(f"{item!r} escapes the source root {self.root}")
        return path.read_bytes()


def extract_batch(store: ExtractStore, backend: Backend, unit: str,
                  items: Iterable[str],
                  batch_size: int = BATCH_SIZE) -> list[Record]:
    """Snapshot `items`, asserting one-writer at every batch boundary.

    Every item of a batch is read before any of them is written, so a backend
    that fails mid-batch leaves no partial batch on disk. A caller re-running
    after a failure therefore sees whole batches or nothing, never half of one.
    """
    pending = list(items)
    out: list[Record] = []
    for start in range(0, len(pending), batch_size):
        chunk = pending[start:start + batch_size]
        index = start // batch_size
        try:
            backend.assert_ready()
        except Exception as exc:
            raise ExtractError(
                f"backend {backend.name!r} is not ready at batch {index} "
                f"(items {start}..{start + len(chunk) - 1}): {exc}") from exc
        staged = [(item, backend.read(item)) for item in chunk]
        for item, data in staged:
            out.append(store.write(unit, flatten(item), data,
                                   source=item, backend=backend.name))
    return out
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_extract.py -v`
Expected: all passed

- [ ] **Step 5: Add the `extract` verb to `audit.py`**

```python
from audit_core import extract as extract_mod  # noqa: E402


def cmd_extract(args: argparse.Namespace) -> int:
    store = extract_mod.ExtractStore(pathlib.Path(args.run).expanduser())
    backend = extract_mod.SourceTree(pathlib.Path(args.root).expanduser())
    items = list(args.path)
    if args.from_file:
        src = pathlib.Path(args.from_file).expanduser()
        if not src.is_file():
            print(f"not found: {src}", file=sys.stderr)
            return 1
        items += [ln.strip() for ln in src.read_text().splitlines() if ln.strip()]
    if args.refresh and not items:
        items = store.items(args.unit)
        if not items:
            print(f"--refresh: unit {args.unit!r} has no snapshots yet",
                  file=sys.stderr)
            return 1
    if not items:
        print("nothing to extract; pass --path, --from-file or --refresh",
              file=sys.stderr)
        return 1
    try:
        recs = extract_mod.extract_batch(store, backend, args.unit, items,
                                         batch_size=args.batch_size)
    except extract_mod.ExtractError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"backend read failed: {exc}", file=sys.stderr)
        return 1
    changed = sum(1 for r in recs if r.version > 1)
    truncated = sum(1 for r in recs if r.truncated)
    # Bounded on purpose: R1 applies to this tool's own output. The manifest
    # holds the per-file detail, and it is a file, not a paste.
    print(f"extract {args.unit}: {len(recs)} snapshot(s), {changed} changed, "
          f"{truncated} truncated")
    print(store.manifest_path)
    return 0
```

```python
    "extract": cmd_extract,
```

```python
    ex = sub.add_parser("extract", help="snapshot source into <run>/extract/ once, for unbounded fan-out")
    ex.add_argument("--run", required=True, metavar="RUN_DIR")
    ex.add_argument("--root", required=True, metavar="SRC_DIR")
    ex.add_argument("--unit", required=True, help="feature group id, e.g. G1")
    ex.add_argument("--path", action="append", default=[], metavar="RELPATH")
    ex.add_argument("--from-file", default=None, metavar="LIST",
                    help="a file of one source path per line")
    ex.add_argument("--refresh", action="store_true",
                    help="re-read every item already snapshotted for this unit")
    ex.add_argument("--batch-size", type=int, default=extract_mod.BATCH_SIZE)
```

- [ ] **Step 6: Extend `tests/test_cli_stage2.py`**

```python
def test_extract_snapshots_a_source_tree_and_prints_a_bounded_summary(tmp_path):
    run_dir = new_run(tmp_path)
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "a.c").write_text("alpha")
    (src / "sub" / "b.c").write_text("beta")
    r = run("extract", "--run", str(run_dir), "--root", str(src),
            "--unit", "G1", "--path", "a.c", "--path", "sub/b.c")
    assert r.returncode == 0, r.stderr
    assert "2 snapshot(s), 0 changed, 0 truncated" in r.stdout
    assert (run_dir / "extract" / "G1" / "sub_b.c").read_text() == "beta"
    # The summary is two lines. The detail is in the manifest, which is a file.
    assert len(r.stdout.strip().splitlines()) == 2


def test_extract_refresh_re_reads_what_the_unit_already_holds(tmp_path):
    run_dir = new_run(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("v1")
    run("extract", "--run", str(run_dir), "--root", str(src), "--unit", "G1",
        "--path", "a.c")
    (src / "a.c").write_text("v2")
    r = run("extract", "--run", str(run_dir), "--root", str(src), "--unit", "G1",
            "--refresh")
    assert r.returncode == 0, r.stderr
    assert "1 changed" in r.stdout


def test_extract_with_no_items_exits_one(tmp_path):
    run_dir = new_run(tmp_path)
    (tmp_path / "src").mkdir()
    r = run("extract", "--run", str(run_dir), "--root", str(tmp_path / "src"),
            "--unit", "G1")
    assert r.returncode == 1
    assert "--refresh" in r.stderr
```

- [ ] **Step 7: Run the full suite**

Run: `python3 -m pytest -q`
Expected: all pass, output pristine.

- [ ] **Step 8: Commit**

```bash
git add audit_core/extract.py audit.py tests/test_extract.py tests/test_cli_stage2.py
git commit -m "feat: extract-then-fan-out with a batch-boundary one-writer assertion

R1. The orchestrator holds paths, not material. The backend is a protocol
because how you extract is per-target - a source tree is a copy, a stripped
binary is a decompiler session - while the discipline is not: assert the
backend is still the sole writer at every batch boundary, and stage a whole
batch in memory before writing any of it, so a failure leaves whole batches or
nothing.

Closes spec section 6.2's one-IDA-writer row. The IDA backend lands in Stage 4
behind this protocol; SourceTree is what codebase-audit needs today.

Unit and snapshot names are refused unless they match a strict pattern, so a
feature-group id or a source path cannot walk out of the run directory."
```

---

## Task 4: The annotation journal — `annotations.py`

**Why this exists.** Spec §3.4: `annotations/<binary>.jsonl` "holds
comprehension — function semantics, struct definitions, resolved questions —
and is the source of truth; an IDA `.i64` is a rebuildable cache." The same
holds for a source audit: the artifacts record what was *found*; nothing
records what was *understood*, and that is what a checkpoint-restart loses.
R3 is unaffordable without it — restarting is cheap only if the next segment
can reload comprehension instead of re-deriving it.

§5.2 names the shape: the orchestrator holds the index, never the analysis.
That is why `index()` returns one bounded row per key rather than the entries.

**Files:**
- Create: `audit_core/annotations.py`
- Create: `tests/test_annotations.py`
- Modify: `audit.py` (verb `note`)
- Modify: `tests/test_cli_stage2.py`

**Interfaces:**
- Consumes: nothing.
- Produces, used by Tasks 5 and 7:
  - `annotations.JOURNAL_NAME` = `"journal.jsonl"`
  - `annotations.Entry` (frozen dataclass: `key, kind, text, source, recorded_at`)
  - `annotations.IndexRow` (frozen dataclass: `key, kind, entries, latest_at, summary`)
  - `annotations.KINDS: tuple[str, ...]`
  - `annotations.append(path, key, kind, text, source=None) -> Entry`
  - `annotations.read(path, key=None, *, tolerate=False) -> tuple[list[Entry], list[int]]`
  - `annotations.index(path, *, tolerate=True) -> tuple[list[IndexRow], list[int]]`
  - `annotations.AnnotationError`

### Steps

- [ ] **Step 1: Write the failing tests**

Create `tests/test_annotations.py`:

```python
import json

import pytest

from audit_core import annotations


def journal(tmp_path):
    return tmp_path / "run" / annotations.JOURNAL_NAME


def test_append_creates_the_journal_and_round_trips(tmp_path):
    p = journal(tmp_path)
    annotations.append(p, "klap_handshake1_handle", "semantics",
                       "parses a 56-byte handshake; copies before checking length")
    entries, bad = annotations.read(p)
    assert bad == []
    assert len(entries) == 1
    assert entries[0].key == "klap_handshake1_handle"
    assert entries[0].kind == "semantics"
    assert entries[0].recorded_at


def test_every_line_is_one_json_object_terminated_by_exactly_one_newline(tmp_path):
    """Append-only JSONL is the point: a crash mid-write costs one line.
    Text mode on Windows would write CRLF and carry a stray \\r into values."""
    p = journal(tmp_path)
    annotations.append(p, "a", "semantics", "one")
    annotations.append(p, "b", "semantics", "two")
    raw = p.read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    lines = raw.split(b"\n")[:-1]
    assert len(lines) == 2
    assert all(isinstance(json.loads(ln), dict) for ln in lines)


def test_read_filters_by_key(tmp_path):
    p = journal(tmp_path)
    annotations.append(p, "a", "semantics", "one")
    annotations.append(p, "b", "semantics", "two")
    entries, _ = annotations.read(p, key="b")
    assert [e.text for e in entries] == ["two"]


def test_reading_a_journal_that_does_not_exist_yet_is_empty_not_an_error(tmp_path):
    assert annotations.read(tmp_path / "nothing.jsonl") == ([], [])


def test_a_corrupt_line_is_named_not_silently_dropped(tmp_path):
    """Review Focus 2. Silently skipping a bad line turns a one-line loss into
    an invisible one - and the journal is the source of truth."""
    p = journal(tmp_path)
    annotations.append(p, "a", "semantics", "one")
    with open(p, "ab") as fh:
        fh.write(b'{"key": "b", "kind": "sem"\n')     # crash mid-append
    annotations.append(p, "c", "semantics", "three")

    with pytest.raises(annotations.AnnotationError) as exc:
        annotations.read(p)
    assert "2" in str(exc.value)
    assert "tolerate" in str(exc.value)

    entries, bad = annotations.read(p, tolerate=True)
    assert [e.key for e in entries] == ["a", "c"]
    assert bad == [2]


def test_a_crlf_terminated_line_reads_cleanly(tmp_path):
    """A journal that has been through a Windows editor, or a CRLF-writing
    client, must not carry a stray carriage return into every value."""
    p = journal(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b'{"key":"a","kind":"semantics","text":"one",'
                  b'"source":null,"recorded_at":"2026-10-05T00:00:00+00:00"}\r\n')
    entries, bad = annotations.read(p)
    assert bad == []
    assert entries[0].text == "one"


def test_a_json_array_line_is_bad_not_an_entry(tmp_path):
    p = journal(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b'[1,2,3]\n')
    _, bad = annotations.read(p, tolerate=True)
    assert bad == [1]


def test_index_returns_one_bounded_row_per_key(tmp_path):
    """Spec section 5.2: the orchestrator holds the index, never the analysis."""
    p = journal(tmp_path)
    long_text = "x" * 400
    annotations.append(p, "klap", "semantics", "first pass")
    annotations.append(p, "klap", "semantics", long_text)
    annotations.append(p, "ssdp", "question", "is the handler reachable pre-auth?")

    rows, bad = annotations.index(p)
    assert bad == []
    assert [r.key for r in rows] == ["klap", "ssdp"]
    klap = rows[0]
    assert klap.entries == 2
    assert len(klap.summary) <= annotations.SUMMARY_CHARS + 1
    assert klap.summary.startswith("xxx")     # the latest entry, not the first
    assert klap.summary.endswith("…")


def test_index_tolerates_corruption_by_default_and_reports_it(tmp_path):
    p = journal(tmp_path)
    annotations.append(p, "a", "semantics", "one")
    with open(p, "ab") as fh:
        fh.write(b"not json\n")
    rows, bad = annotations.index(p)
    assert [r.key for r in rows] == ["a"]
    assert bad == [2]


def test_an_invented_kind_is_refused(tmp_path):
    with pytest.raises(annotations.AnnotationError) as exc:
        annotations.append(journal(tmp_path), "a", "vibes", "x")
    assert "vibes" in str(exc.value)
    assert "semantics" in str(exc.value)


def test_an_empty_key_or_text_is_refused(tmp_path):
    p = journal(tmp_path)
    with pytest.raises(annotations.AnnotationError):
        annotations.append(p, "  ", "semantics", "x")
    with pytest.raises(annotations.AnnotationError):
        annotations.append(p, "a", "semantics", "   ")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_annotations.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'audit_core.annotations'`

- [ ] **Step 3: Write `audit_core/annotations.py`**

```python
"""The annotation journal: comprehension that survives a restart.

Artifacts record what was found. Nothing recorded what was *understood* - what
a function does, what a field means, which question is settled - and that is
exactly what a checkpoint-restart loses. R3 is unaffordable without this: a
restart is cheap only if the next segment reloads comprehension instead of
re-deriving it.

Append-only JSONL, written in binary, so a crash mid-write costs one line and
no client's newline translation can reach the contents. `index()` returns one
bounded row per key because the orchestrator holds the table of contents, never
the analysis (spec section 5.2).
"""
from __future__ import annotations

import datetime
import json
import pathlib
from dataclasses import asdict, dataclass

JOURNAL_NAME = "journal.jsonl"
SUMMARY_CHARS = 120
KINDS = ("semantics", "struct", "question", "answer", "decision", "identity")


class AnnotationError(Exception):
    """A journal line is not an entry, or an entry is malformed."""


@dataclass(frozen=True, slots=True)
class Entry:
    key: str
    kind: str
    text: str
    source: str | None
    recorded_at: str


@dataclass(frozen=True, slots=True)
class IndexRow:
    key: str
    kind: str
    entries: int
    latest_at: str
    summary: str


def append(path: str | pathlib.Path, key: str, kind: str, text: str,
           source: str | None = None) -> Entry:
    if not (key or "").strip():
        raise AnnotationError("a journal entry needs a non-empty key")
    if not (text or "").strip():
        raise AnnotationError(f"entry {key!r} has no text")
    if kind not in KINDS:
        raise AnnotationError(f"kind={kind!r} is not one of {', '.join(KINDS)}")
    entry = Entry(key=key.strip(), kind=kind, text=text, source=source,
                  recorded_at=datetime.datetime.now(
                      datetime.timezone.utc).isoformat(timespec="seconds"))
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Binary append. json.dumps never emits a newline, and "ab" never
    # translates one, so the file is the same bytes on every platform.
    with open(path, "ab") as fh:
        fh.write(json.dumps(asdict(entry), sort_keys=True).encode("utf-8") + b"\n")
    return entry


def read(path: str | pathlib.Path, key: str | None = None, *,
         tolerate: bool = False) -> tuple[list[Entry], list[int]]:
    """Entries in write order, plus the line numbers that are not entries.

    A line that fails to parse is reported, never dropped. The journal is the
    source of truth; losing a line quietly is losing comprehension quietly.
    """
    path = pathlib.Path(path)
    if not path.is_file():
        return [], []
    entries: list[Entry] = []
    bad: list[int] = []
    for n, raw in enumerate(path.read_bytes().split(b"\n"), start=1):
        line = raw.strip()                 # also strips a CRLF carriage return
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            bad.append(n)
            continue
        if not isinstance(obj, dict) or not obj.get("key"):
            bad.append(n)
            continue
        entries.append(Entry(
            key=str(obj["key"]), kind=str(obj.get("kind", "")),
            text=str(obj.get("text", "")),
            source=obj.get("source"),
            recorded_at=str(obj.get("recorded_at", ""))))
    if bad and not tolerate:
        raise AnnotationError(
            f"{path}: line(s) {', '.join(map(str, bad))} are not journal "
            f"entries. Re-read with tolerate=True to use the rest; the bad "
            f"lines are reported, not discarded.")
    if key is not None:
        entries = [e for e in entries if e.key == key]
    return entries, bad


def index(path: str | pathlib.Path, *,
          tolerate: bool = True) -> tuple[list[IndexRow], list[int]]:
    """One bounded row per key: what is known about it, not what is known."""
    entries, bad = read(path, tolerate=tolerate)
    grouped: dict[str, list[Entry]] = {}
    for e in entries:
        grouped.setdefault(e.key, []).append(e)
    rows: list[IndexRow] = []
    for key in sorted(grouped):
        group = grouped[key]
        latest = group[-1]
        summary = latest.text.strip().replace("\n", " ")
        if len(summary) > SUMMARY_CHARS:
            summary = summary[:SUMMARY_CHARS] + "…"
        rows.append(IndexRow(key=key, kind=latest.kind, entries=len(group),
                             latest_at=latest.recorded_at, summary=summary))
    return rows, bad
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_annotations.py -v`
Expected: all passed

- [ ] **Step 5: Add the `note` verb to `audit.py`**

```python
from audit_core import annotations as annotations_mod  # noqa: E402


def cmd_note(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.run).expanduser() / annotations_mod.JOURNAL_NAME
    if args.text is not None:
        try:
            annotations_mod.append(path, args.key, args.kind, args.text,
                                   source=args.source)
        except annotations_mod.AnnotationError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"{path}: 1 entry")
        return 0
    if args.key:
        entries, bad = annotations_mod.read(path, key=args.key, tolerate=True)
        for e in entries:
            print(f"{e.recorded_at}  {e.kind}\n{e.text}\n")
    else:
        rows, bad = annotations_mod.index(path)
        if args.json:
            print(json.dumps([dataclasses.asdict(r) for r in rows], indent=2))
        else:
            for r in rows:
                print(f"  {r.key:40.40s} {r.kind:10s} x{r.entries:<3d} {r.summary}")
            print(f"({len(rows)} key(s); read one with "
                  f"`audit.py note --run {args.run} --key <key>`)")
    if bad:
        print(f"warning: {path} line(s) {', '.join(map(str, bad))} are not "
              f"journal entries and were not read", file=sys.stderr)
    return 0
```

```python
    "note": cmd_note,
```

```python
    nt = sub.add_parser("note", help="append to, or index, the run's annotation journal")
    nt.add_argument("--run", required=True, metavar="RUN_DIR")
    nt.add_argument("--key", default=None,
                    help="with --text, the entry key; alone, read that key")
    nt.add_argument("--kind", default="semantics",
                    choices=list(annotations_mod.KINDS))
    nt.add_argument("--text", default=None, help="append this entry")
    nt.add_argument("--source", default=None, metavar="FILE_OR_ADDR")
    nt.add_argument("--json", action="store_true")
```

Note: `--text` without `--key` must fail. Add at the top of `cmd_note`:

```python
    if args.text is not None and not (args.key or "").strip():
        print("--text requires --key", file=sys.stderr)
        return 1
```

- [ ] **Step 6: Extend `tests/test_cli_stage2.py`**

```python
def test_note_appends_then_indexes(tmp_path):
    run_dir = str(new_run(tmp_path))
    assert run("note", "--run", run_dir, "--key", "klap_handshake1_handle",
               "--kind", "semantics",
               "--text", "copies before checking length").returncode == 0
    r = run("note", "--run", run_dir)
    assert r.returncode == 0, r.stderr
    assert "klap_handshake1_handle" in r.stdout
    assert "1 key(s)" in r.stdout


def test_note_text_without_key_exits_one(tmp_path):
    run_dir = str(new_run(tmp_path))
    r = run("note", "--run", run_dir, "--text", "orphan")
    assert r.returncode == 1
    assert "--key" in r.stderr


def test_note_index_warns_about_a_corrupt_line_on_stderr(tmp_path):
    run_dir = new_run(tmp_path)
    run("note", "--run", str(run_dir), "--key", "a", "--text", "one")
    with open(run_dir / "journal.jsonl", "ab") as fh:
        fh.write(b"not json\n")
    r = run("note", "--run", str(run_dir))
    assert r.returncode == 0
    assert "line(s) 2" in r.stderr
```

- [ ] **Step 7: Run the Review Focus 2 tests, then the full suite**

Run: `python3 -m pytest tests/test_annotations.py -k "corrupt or crlf" -v`
Expected: 2 passed

Run: `python3 -m pytest -q`
Expected: all pass, output pristine.

- [ ] **Step 8: Commit**

```bash
git add audit_core/annotations.py audit.py tests/test_annotations.py tests/test_cli_stage2.py
git commit -m "feat: append-only annotation journal with a bounded index

Artifacts record what was found; nothing recorded what was understood, and
that is exactly what a checkpoint-restart loses. R3 is unaffordable without
this - restarting is cheap only if the next segment reloads comprehension
instead of re-deriving it.

JSONL written in binary so a crash costs one line and no client's newline
translation reaches the contents. A line that fails to parse is reported by
line number, never dropped: the journal is the source of truth, and losing a
line quietly is losing comprehension quietly.

index() returns one bounded row per key, per spec section 5.2 - the
orchestrator holds the table of contents, never the analysis."
```

---

## Task 5: The context ceiling — `ceiling.py`

**Why this exists.** R3. Cost is `Σ over turns of context(turn)`, so a session
pays for its own history on every remaining turn. The spec's model is
`context(n) = prefix + g·n`, and over a 1,000-turn workload the total is flat
between a 70k and a 120k ceiling and climbs steeply above; 100k is chosen
because it is within 4% of the minimum while giving 92 turns per segment
instead of 58.

Two honest limits shape what this module can be. **No client exposes the
orchestrator's live context size**, so nothing here can watch a number and fire.
What it can do is answer the question the orchestrator *can* ask — given a
prefix and a growth rate measured on a real transcript, how many turns does a
phase get before it must checkpoint — and record the checkpoint when it
happens. **And the model is an assumption.** Stage 0's finding #4 is explicit:
"any later stage that introduces a new measurement must introduce its external
check in the same commit." `linearity()` is that check, and Step 8 runs it
against the pinned tplink transcript.

The check has to be chosen carefully. Comparing a predicted *peak* to a
measured peak is an identity — `g` is defined as `(peak − floor) / (turns − 1)`
— and would pass no matter how badly the model fits. Comparing a predicted
*mean* is not: under linear growth the mean is `floor + g·(turns−1)/2`, and a
session whose context jumps early and plateaus will miss it by a wide margin.

**Files:**
- Create: `audit_core/ceiling.py`
- Create: `tests/test_ceiling.py`
- Modify: `audit.py` (verb `checkpoint`; `budget --project`)
- Modify: `tests/test_cli_stage2.py`
- Modify: `docs/baselines/2026-10-05-tplink-baseline.md` (the measured fit)

**Interfaces:**
- Consumes: `audit_core.budget.Report`, `audit_core.budget.Epoch`, `db.put`, `db.connect`, `db.CHECKPOINT_REASONS`.
- Produces, used by Task 7:
  - `ceiling.CEILING_TOKENS` (= 100_000), `ceiling.CHECKPOINT_FRACTION` (= 0.80)
  - `ceiling.Projection` (frozen dataclass: `prefix, growth_per_turn, ceiling, checkpoint_at, turns_to_checkpoint, turns_to_ceiling`; the two turn counts are `int | None`, `None` meaning "never reached")
  - `ceiling.project(prefix, growth_per_turn, ceiling=CEILING_TOKENS, fraction=CHECKPOINT_FRACTION) -> Projection`
  - `ceiling.render_projection(p) -> str`
  - `ceiling.LinearityCheck` (frozen dataclass: `epoch, turns, measured_mean, predicted_mean, deviation`)
  - `ceiling.linearity(report, min_turns=20) -> list[LinearityCheck]`
  - `ceiling.render_linearity(checks) -> str`

### Steps

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ceiling.py`:

```python
import pathlib

from audit_core import budget, ceiling, transcript as T
from tests.fixtures import build as B


def session(tmp_path, contexts) -> pathlib.Path:
    """A one-epoch transcript whose billed turns have exactly these contexts.

    Same idiom as tests/test_budget_epochs.py: write the fixture lines to a
    file and parse it. A distinct message id per line keeps one Turn per
    record, which is the shape the C1 fix established.
    """
    p = tmp_path / "s.jsonl"
    p.write_text("".join(
        B.assistant([{"type": "text", "text": "x"}], cache_read=c,
                    message_id=f"m{i}")
        for i, c in enumerate(contexts)))
    return p


def test_the_ceiling_and_checkpoint_are_the_spec_values():
    assert ceiling.CEILING_TOKENS == 100_000
    assert ceiling.CHECKPOINT_FRACTION == 0.80
    p = ceiling.project(prefix=45_000, growth_per_turn=600)
    assert p.checkpoint_at == 80_000


def test_project_counts_turns_to_checkpoint_and_to_ceiling():
    p = ceiling.project(prefix=45_000, growth_per_turn=600)
    assert p.turns_to_checkpoint == 58       # (80000 - 45000) // 600
    assert p.turns_to_ceiling == 91          # (100000 - 45000) // 600


def test_a_prefix_already_over_the_checkpoint_gets_zero_turns():
    p = ceiling.project(prefix=85_000, growth_per_turn=600)
    assert p.turns_to_checkpoint == 0
    assert p.turns_to_ceiling == 25


def test_a_prefix_over_the_ceiling_gets_zero_everywhere():
    p = ceiling.project(prefix=120_000, growth_per_turn=600)
    assert (p.turns_to_checkpoint, p.turns_to_ceiling) == (0, 0)


def test_zero_growth_never_reaches_the_ceiling():
    p = ceiling.project(prefix=45_000, growth_per_turn=0)
    assert p.turns_to_checkpoint is None
    assert p.turns_to_ceiling is None


def test_render_projection_names_the_measured_inputs():
    out = ceiling.render_projection(ceiling.project(45_000, 600))
    assert "45,000" in out
    assert "600" in out
    assert "58" in out


def test_the_measured_tplink_prefix_and_growth_leave_a_phase_15_turns():
    """The baseline is prefix 40,926-66,010 and g 2,573 tok/turn. Against a
    100k ceiling that is the number R3 exists to change: 15 turns is not a
    phase, which is why R4 (cutting the prefix) is a prerequisite for R3."""
    p = ceiling.project(prefix=40_926, growth_per_turn=2_573)
    assert p.turns_to_checkpoint == 15


def test_linearity_fits_a_perfectly_linear_epoch(tmp_path):
    """`project()` is only meaningful if growth is roughly linear. This check
    cannot pass by construction: comparing a predicted PEAK to a measured peak
    is an identity, because g is defined as (peak - floor) / (turns - 1).
    Comparing the mean is not."""
    r = budget.analyze(T.parse(session(
        tmp_path, [10_000 + 1_000 * i for i in range(40)])))
    checks = ceiling.linearity(r, min_turns=20)
    assert len(checks) == 1
    assert checks[0].deviation < 0.01


def test_linearity_flags_a_front_loaded_epoch(tmp_path):
    """Context that jumps early and plateaus has the same floor, peak and
    therefore the same g as a linear climb, and a mean nowhere near the
    model's. That is the failure this check exists to catch."""
    r = budget.analyze(T.parse(session(tmp_path, [10_000] + [50_000] * 39)))
    checks = ceiling.linearity(r, min_turns=20)
    assert checks[0].deviation > 0.25


def test_linearity_skips_epochs_too_short_to_judge(tmp_path):
    r = budget.analyze(T.parse(session(
        tmp_path, [10_000 + 1_000 * i for i in range(5)])))
    assert ceiling.linearity(r, min_turns=20) == []


def test_render_linearity_prints_every_deviation_not_a_verdict(tmp_path):
    r = budget.analyze(T.parse(session(
        tmp_path, [10_000 + 1_000 * i for i in range(40)])))
    out = ceiling.render_linearity(ceiling.linearity(r, min_turns=20))
    assert "deviation" in out
    assert "%" in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_ceiling.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'audit_core.ceiling'`

- [ ] **Step 3: Write `audit_core/ceiling.py`**

```python
"""The context ceiling and its checkpoint (spec R3).

Cost is the sum of context over turns, so a session pays for its own history
on every remaining turn. Under the model context(n) = prefix + g*n, the total
over a 1,000-turn workload is flat between a 70k and a 120k ceiling and climbs
steeply above it. 100k is chosen: within 4% of the numeric minimum, and 92
turns per segment instead of 58, which matters for phase continuity.

Two limits shape this module. No client exposes the orchestrator's live
context size, so nothing here watches a number and fires; it answers how many
turns a phase gets, and records the checkpoint when one is taken. And the
linear model is an assumption, so `linearity()` ships beside `project()` as
its external check - per Stage 0's finding that a figure regenerated from a
tool is only better than a hand calculation if the tool is validated against
something it did not produce.
"""
from __future__ import annotations

from dataclasses import dataclass

from audit_core.budget import Report

CEILING_TOKENS = 100_000
CHECKPOINT_FRACTION = 0.80


@dataclass(frozen=True, slots=True)
class Projection:
    prefix: int
    growth_per_turn: float
    ceiling: int
    checkpoint_at: int
    turns_to_checkpoint: int | None
    turns_to_ceiling: int | None


def project(prefix: int, growth_per_turn: float,
            ceiling: int = CEILING_TOKENS,
            fraction: float = CHECKPOINT_FRACTION) -> Projection:
    """How many turns a phase gets before it must checkpoint.

    `None` means the limit is never reached - a session with no measurable
    growth, which is a measurement to distrust rather than a budget to spend.
    """
    checkpoint_at = int(ceiling * fraction)

    def turns(limit: int) -> int | None:
        if growth_per_turn <= 0:
            return None
        return max(0, int((limit - prefix) // growth_per_turn))

    return Projection(prefix=prefix, growth_per_turn=growth_per_turn,
                      ceiling=ceiling, checkpoint_at=checkpoint_at,
                      turns_to_checkpoint=turns(checkpoint_at),
                      turns_to_ceiling=turns(ceiling))


def _turns(value: int | None) -> str:
    return "never (no measurable growth)" if value is None else f"{value}"


def render_projection(p: Projection) -> str:
    return "\n".join([
        f"  ceiling {p.ceiling:,}   checkpoint at {p.checkpoint_at:,} "
        f"({100 * CHECKPOINT_FRACTION:.0f}%)",
        f"  measured prefix {p.prefix:,}   growth {p.growth_per_turn:,.0f} tok/turn",
        f"  turns to checkpoint {_turns(p.turns_to_checkpoint)}   "
        f"turns to ceiling {_turns(p.turns_to_ceiling)}",
    ])


@dataclass(frozen=True, slots=True)
class LinearityCheck:
    epoch: int
    turns: int
    measured_mean: int
    predicted_mean: int
    deviation: float


def linearity(report: Report, min_turns: int = 20) -> list[LinearityCheck]:
    """How well `context(n) = floor + g*n` fits a measured session.

    Under that model an epoch's mean context is floor + g*(turns-1)/2.
    Comparing a predicted PEAK to the measured peak would be an identity - g
    is defined as (peak - floor) / (turns - 1) - and would pass for any data.
    The mean is independent of that definition, so a session whose context
    jumps early and plateaus fails this and should.
    """
    out: list[LinearityCheck] = []
    for e in report.epochs:
        if e.turns < min_turns or e.mean <= 0:
            continue
        predicted = e.floor + e.growth_per_turn * (e.turns - 1) / 2
        out.append(LinearityCheck(
            epoch=e.index, turns=e.turns, measured_mean=e.mean,
            predicted_mean=int(predicted),
            deviation=abs(predicted - e.mean) / e.mean))
    return out


def render_linearity(checks: list[LinearityCheck]) -> str:
    if not checks:
        return ("  linearity: no epoch long enough to judge the growth model")
    out = [f"  {'epoch':>5s} {'turns':>6s} {'measured mean':>14s} "
           f"{'predicted mean':>15s} {'deviation':>10s}"]
    out.extend(
        f"  {c.epoch:5d} {c.turns:6d} {c.measured_mean:14,} "
        f"{c.predicted_mean:15,} {100 * c.deviation:9.1f}%"
        for c in checks)
    out.append("  A large deviation means context is not growing linearly, so "
               "the turns-to-checkpoint")
    out.append("  figure above is unreliable for this session - report it "
               "rather than widening the bound.")
    return "\n".join(out)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_ceiling.py -v`
Expected: all passed

- [ ] **Step 5: Add `budget --project` and the `checkpoint` verb to `audit.py`**

In `cmd_budget`, after `print(budget_mod.render(r))`, when `args.project`:

```python
            if args.project:
                print()
                print(ceiling_mod.render_projection(ceiling_mod.project(
                    r.stats.prefix_floor, r.stats.growth_per_turn)))
                print(ceiling_mod.render_linearity(ceiling_mod.linearity(r)))
```

and add `b.add_argument("--project", action="store_true", help="project turns to the R3 checkpoint, with the linear model's fit")`.

```python
from audit_core import ceiling as ceiling_mod  # noqa: E402


def cmd_checkpoint(args: argparse.Namespace) -> int:
    row = {"phase": args.phase, "reason": args.reason}
    if args.turns is not None:
        row["turns"] = str(args.turns)
    if args.resume_note:
        note = pathlib.Path(args.resume_note).expanduser()
        if not note.is_file():
            print(f"resume note not found: {note}; write it before "
                  f"checkpointing - the note is the restart", file=sys.stderr)
            return 1
        row["resume_note"] = str(note)
    projection = None
    if args.prefix is not None and args.growth is not None:
        projection = ceiling_mod.project(args.prefix, args.growth)
        if args.turns is not None:
            row["projected_context"] = str(
                int(args.prefix + args.growth * args.turns))
    con = _open_db(args.db)
    if con is None:
        return 1
    try:
        db_mod.put(con, "cba_checkpoints", row)
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        con.close()
    print(f"checkpoint recorded: phase={args.phase} reason={args.reason}")
    if projection is not None:
        print(ceiling_mod.render_projection(projection))
    return 0
```

```python
    "checkpoint": cmd_checkpoint,
```

```python
    ck = sub.add_parser("checkpoint", help="record a phase exit or a ceiling trip")
    ck.add_argument("--db", required=True, metavar="AUDIT_DB")
    ck.add_argument("--phase", required=True)
    ck.add_argument("--reason", required=True,
                    choices=list(db_mod.CHECKPOINT_REASONS))
    ck.add_argument("--turns", type=int, default=None)
    ck.add_argument("--resume-note", default=None, metavar="PATH")
    ck.add_argument("--prefix", type=int, default=None,
                    help="measured prefix floor, from `audit.py budget`")
    ck.add_argument("--growth", type=float, default=None,
                    help="measured tokens per turn, from `audit.py budget`")
```

- [ ] **Step 6: Extend `tests/test_cli_stage2.py`**

```python
def test_checkpoint_records_a_row_and_prints_the_projection(tmp_path):
    run_dir = new_run(tmp_path)
    db = str(run_dir / "audit.db")
    note = tmp_path / "resume.md"
    note.write_text("resume note")
    r = run("checkpoint", "--db", db, "--phase", "audit", "--reason", "ceiling",
            "--turns", "58", "--resume-note", str(note),
            "--prefix", "45000", "--growth", "600")
    assert r.returncode == 0, r.stderr
    assert "turns to checkpoint 58" in r.stdout
    rows = run("rows", "--db", db, "--table", "cba_checkpoints",
               "--columns", "phase,reason,turns")
    assert rows.stdout.strip() == "audit\tceiling\t58"


def test_checkpoint_refuses_a_missing_resume_note(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("checkpoint", "--db", db, "--phase", "audit", "--reason",
            "phase-exit", "--resume-note", str(tmp_path / "nope.md"))
    assert r.returncode == 1
    assert "the note is the restart" in r.stderr


def test_checkpoint_rejects_an_invented_reason(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("checkpoint", "--db", db, "--phase", "audit", "--reason", "tired")
    assert r.returncode != 0
```

- [ ] **Step 7: Run the full suite**

Run: `python3 -m pytest -q`
Expected: all pass, output pristine.

- [ ] **Step 8: Run the external check against the pinned tplink transcript and record it**

This is read-only against `~/.claude/projects/`, which is one of the
READ-ONLY trees. Run:

```bash
python3 audit.py budget --project --report \
  ~/.claude/projects/-Users-danhnguyen-Documents-Offsec-Opswat-Devices-tplink/d87d98a0-1430-4218-a31e-9ae93a9ba275.jsonl
```

Confirm the printed `source_bytes` is **15,608,662** and `source_sha256`
starts **`a33f2f52`**. If either differs, the file has grown since the
baseline was pinned and the numbers below are not comparable — stop and
report that, do not record a figure against a different input.

Append a section to `docs/baselines/2026-10-05-tplink-baseline.md` (LF line
endings) recording, verbatim from the run: the projection block, the full
linearity table with every epoch's deviation, and one sentence stating what
the deviations mean for the 100k ceiling.

**If any epoch's deviation exceeds 30%, that is a finding about the spec's
growth model, not a bug in this code.** Record it in the baseline and in
`docs/superpowers/specs/2026-10-05-stage2-findings-for-later-stages.md`
(create it), say so in your report, and leave `project()` as written. Do not
widen a bound to make a measurement agree with a model.

- [ ] **Step 9: Commit**

```bash
git add audit_core/ceiling.py audit.py tests/test_ceiling.py \
  tests/test_cli_stage2.py docs/baselines/2026-10-05-tplink-baseline.md
git commit -m "feat: R3 context-ceiling projection, with its own external check

No client exposes the orchestrator's live context size, so this answers the
question the orchestrator can ask - given a measured prefix and growth, how
many turns does a phase get - and records the checkpoint when one is taken.

linearity() ships in the same commit as project(), per Stage 0's finding that
a regenerated figure is only better than a hand calculation if the tool is
validated against something it did not produce. It compares predicted to
measured MEAN, not peak: g is defined as (peak - floor) / (turns - 1), so a
peak comparison is an identity that passes for any data.

The baseline now records the measured fit. At the tplink prefix and growth a
phase gets 15 turns against a 100k ceiling, which is why R4 - cutting the
prefix - is a prerequisite for R3 rather than an independent lever."
```

---

## Task 6: The sweep engine — `sweep.py`

**Why this exists.** Spec §3.5: a confirmed finding is evidence about one call
site and a hypothesis about every other one. The tplink run confirmed patterns
and never swept for them. The sweep is deliberately a cheap regex pass that
produces **candidates for an agent to triage, never verdicts** — and it is
bounded, because an uncapped sweep dumping ten thousand hits into the
orchestrator is precisely the failure R1 exists to prevent.

Per ruling **S3**, Stage 2 ships the engine and the verb. Triggering a sweep
automatically on every confirmed finding is the Stage 3 quality change, and it
is benchmarked alone so that a recall movement can be attributed to it.

**Files:**
- Create: `audit_core/sweep.py`
- Create: `tests/test_sweep.py`
- Modify: `audit_core/db.py` (the `cba_patterns` regex validator)
- Modify: `audit.py` (verb `sweep`)
- Modify: `tests/test_cli_stage2.py`

**Interfaces:**
- Consumes: `db.put`, `db.rows`, `db.connect`, `db.DbError`, `db.TABLE_SPECS`.
- Produces, used by Task 7:
  - `sweep.Hit` (frozen dataclass: `path, line, excerpt`)
  - `sweep.SweepResult` (frozen dataclass: `pattern_id, hits, files_scanned, files_skipped_binary, files_skipped_large, truncated`)
  - `sweep.run(root, regex, *, pattern_id="", suffixes=None, max_hits=MAX_HITS) -> SweepResult`
  - `sweep.record(con, result) -> int`
  - `sweep.render(result) -> str`
  - `sweep.MAX_HITS` (= 500), `sweep.MAX_FILE_BYTES` (= 2_000_000), `sweep.SKIP_DIRS`

### Steps

- [ ] **Step 1: Write the failing tests**

Create `tests/test_sweep.py`:

```python
import os

import pytest

from audit_core import db, sweep, workspace


def tree(root, **files):
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body if isinstance(body, bytes) else body.encode())
    return root


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path / "ws", timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    db.put(c, "cba_patterns", {"id": "P1", "name": "degenerate strncpy",
                               "regex": r"strncpy\([^,]+,[^,]+,\s*strlen\("})
    yield c
    c.close()


def test_a_pattern_whose_regex_does_not_compile_is_refused(con):
    """A stored pattern that cannot compile is a sweep that silently never
    runs - the worst outcome for a mechanism whose whole value is breadth."""
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_patterns", {"id": "P2", "name": "bad", "regex": "([a-z"})
    assert "compile" in str(exc.value)


def test_run_finds_hits_with_path_line_and_excerpt(tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "int f(void){\n  strncpy(dst, src, strlen(src));\n}\n",
        "b.c": "int g(void){ return 0; }\n",
    })
    r = sweep.run(root, r"strncpy\([^,]+,[^,]+,\s*strlen\(", pattern_id="P1")
    assert len(r.hits) == 1
    assert r.hits[0].path == "a.c"
    assert r.hits[0].line == 2
    assert "strncpy" in r.hits[0].excerpt
    assert r.files_scanned == 2
    assert r.truncated is False


def test_suffixes_narrow_the_scan(tmp_path):
    root = tree(tmp_path / "src", **{"a.c": "needle\n", "a.md": "needle\n"})
    r = sweep.run(root, "needle", suffixes=(".c",))
    assert [h.path for h in r.hits] == ["a.c"]


def test_skip_dirs_are_not_walked(tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "needle\n", "node_modules/pkg/b.js": "needle\n",
        ".git/objects/c": "needle\n",
    })
    r = sweep.run(root, "needle")
    assert [h.path for h in r.hits] == ["a.c"]


def test_a_binary_file_is_skipped_and_counted_not_decoded(tmp_path):
    """Review Focus 3. A firmware tree is mostly binary; decoding it is slow
    and the hits are noise."""
    root = tree(tmp_path / "src", **{"a.c": "needle\n",
                                     "fw.bin": b"needle\x00\x01\x02needle"})
    r = sweep.run(root, "needle")
    assert [h.path for h in r.hits] == ["a.c"]
    assert r.files_skipped_binary == 1


def test_an_oversized_file_is_skipped_and_counted(tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "needle\n",
        "bundle.js": "needle " + "x" * (sweep.MAX_FILE_BYTES + 1),
    })
    r = sweep.run(root, "needle")
    assert [h.path for h in r.hits] == ["a.c"]
    assert r.files_skipped_large == 1


def test_a_directory_symlink_loop_does_not_hang(tmp_path):
    """Review Focus 3. os.walk(followlinks=False) is the guard; this test is
    what proves it is still there after a refactor."""
    root = tree(tmp_path / "src", **{"sub/a.c": "needle\n"})
    try:
        os.symlink(root, root / "sub" / "loop", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not allow directory symlinks")
    r = sweep.run(root, "needle")
    assert [h.path for h in r.hits] == [os.path.join("sub", "a.c")]


def test_hits_are_capped_and_the_truncation_is_reported(tmp_path):
    """An uncapped sweep dumping ten thousand hits into the orchestrator is
    the exact failure R1 exists to prevent."""
    root = tree(tmp_path / "src", **{"a.c": "needle\n" * (sweep.MAX_HITS + 50)})
    r = sweep.run(root, "needle")
    assert len(r.hits) == sweep.MAX_HITS
    assert r.truncated is True
    assert "truncated" in sweep.render(r)


def test_a_custom_cap_is_honoured(tmp_path):
    root = tree(tmp_path / "src", **{"a.c": "needle\n" * 20})
    r = sweep.run(root, "needle", max_hits=5)
    assert (len(r.hits), r.truncated) == (5, True)


def test_an_excerpt_is_bounded(tmp_path):
    root = tree(tmp_path / "src", **{"a.c": "needle " + "y" * 900 + "\n"})
    r = sweep.run(root, "needle")
    assert len(r.hits[0].excerpt) <= sweep.EXCERPT_CHARS


def test_undecodable_bytes_in_a_text_file_do_not_raise(tmp_path):
    root = tree(tmp_path / "src", **{"a.c": b"needle \xff\xfe not utf8\n"})
    r = sweep.run(root, "needle")
    assert len(r.hits) == 1


def test_record_writes_one_row_per_hit_and_rows_reads_them_back(con, tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "strncpy(d, s, strlen(s));\n",
        "b.c": "strncpy(d, s, strlen(s));\n",
    })
    r = sweep.run(root, r"strncpy\([^,]+,[^,]+,\s*strlen\(", pattern_id="P1")
    assert sweep.record(con, r) == 2
    got = db.rows(con, "cba_pattern_hits", where={"pattern_id": "P1"},
                  columns=("path", "line", "triaged"))
    assert sorted(tuple(x) for x in got) == [("a.c", 1, "pending"),
                                             ("b.c", 1, "pending")]


def test_record_refuses_a_result_with_no_pattern_id(con, tmp_path):
    root = tree(tmp_path / "src", **{"a.c": "needle\n"})
    with pytest.raises(db.DbError):
        sweep.record(con, sweep.run(root, "needle"))


def test_render_never_prints_the_hits_themselves(tmp_path):
    """R1 applied to this tool's own output: the summary says how to read the
    rows, it does not paste them."""
    root = tree(tmp_path / "src", **{"a.c": "needle\n"})
    out = sweep.render(sweep.run(root, "needle", pattern_id="P1"))
    assert "needle" not in out
    assert "audit.py rows" in out
    assert "cba_pattern_hits" in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_sweep.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'audit_core.sweep'`

- [ ] **Step 3: Add the regex validator to `audit_core/db.py`**

Beside `_validate_coverage`:

```python
def _validate_pattern(row: dict[str, str]) -> None:
    """Compile the regex before it is stored.

    A stored pattern that does not compile is a sweep that silently never
    runs, which is the worst possible outcome for a mechanism whose whole
    value is breadth.
    """
    import re as _re
    try:
        _re.compile(row["regex"])
    except _re.error as exc:
        raise DbError(f"regex {row['regex']!r} does not compile: {exc}") from exc
```

and attach it to the `cba_patterns` spec: `validate=_validate_pattern`.
Move the `import re` to the module's import block rather than inlining it.

- [ ] **Step 4: Write `audit_core/sweep.py`**

```python
"""Sweep a confirmed bug pattern across the corpus.

A confirmed finding is evidence about one call site and a hypothesis about
every other one. The tplink run confirmed patterns and never swept for them.

This is deliberately a cheap regex pass producing CANDIDATES for an agent to
triage, never verdicts - and it is bounded at every edge, because an uncapped
sweep dumping ten thousand hits into the orchestrator is the exact failure R1
exists to prevent. Binary files are skipped rather than decoded, oversized
files are skipped rather than read, symlinks are never followed, and both
skip counts are reported rather than absorbed.
"""
from __future__ import annotations

import itertools
import os
import pathlib
import re
import sqlite3
from dataclasses import dataclass
from typing import Iterator, Sequence

from audit_core import db

MAX_HITS = 500
MAX_FILE_BYTES = 2_000_000
EXCERPT_CHARS = 160
BINARY_SNIFF_BYTES = 8192
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".tox",
})


@dataclass(frozen=True, slots=True)
class Hit:
    path: str
    line: int
    excerpt: str


@dataclass(frozen=True, slots=True)
class SweepResult:
    pattern_id: str
    hits: tuple[Hit, ...]
    files_scanned: int
    files_skipped_binary: int
    files_skipped_large: int
    truncated: bool


def _scan(root: pathlib.Path, rx: re.Pattern[str],
          suffixes: Sequence[str] | None,
          counters: dict[str, int]) -> Iterator[Hit]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = pathlib.Path(dirpath) / name
            if path.is_symlink():
                continue
            if suffixes and path.suffix not in suffixes:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    counters["large"] += 1
                    continue
                blob = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in blob[:BINARY_SNIFF_BYTES]:
                counters["binary"] += 1
                continue
            counters["scanned"] += 1
            rel = str(path.relative_to(root))
            for n, line in enumerate(blob.decode("utf-8", "replace").splitlines(), 1):
                if rx.search(line):
                    yield Hit(rel, n, line.strip()[:EXCERPT_CHARS])


def run(root: str | pathlib.Path, regex: str, *, pattern_id: str = "",
        suffixes: Sequence[str] | None = None,
        max_hits: int = MAX_HITS) -> SweepResult:
    """Scan `root` for `regex`, stopping at `max_hits`.

    The counters reflect files visited before the cap was reached, so a
    truncated sweep under-reports how much of the tree it saw. That is the
    honest reading: the sweep stopped, so it does not know.
    """
    rx = re.compile(regex)
    root = pathlib.Path(root)
    counters = {"scanned": 0, "binary": 0, "large": 0}
    stream = _scan(root, rx, suffixes, counters)
    hits = tuple(itertools.islice(stream, max_hits))
    truncated = next(stream, None) is not None
    return SweepResult(pattern_id=pattern_id, hits=hits,
                       files_scanned=counters["scanned"],
                       files_skipped_binary=counters["binary"],
                       files_skipped_large=counters["large"],
                       truncated=truncated)


def record(con: sqlite3.Connection, result: SweepResult) -> int:
    """Write one `cba_pattern_hits` row per hit. Returns how many."""
    if not result.pattern_id:
        raise db.DbError("a sweep result with no pattern_id cannot be "
                         "recorded; pass pattern_id= to sweep.run()")
    for hit in result.hits:
        db.put(con, "cba_pattern_hits", {
            "pattern_id": result.pattern_id, "path": hit.path,
            "line": str(hit.line), "excerpt": hit.excerpt})
    return len(result.hits)


def render(result: SweepResult) -> str:
    """A bounded summary. R1 applies to this tool's own output: it says how
    to read the hits, it does not paste them."""
    out = [f"sweep {result.pattern_id or '(unrecorded)'}: {len(result.hits)} hit(s) "
           f"in {result.files_scanned} file(s)"]
    if result.files_skipped_binary or result.files_skipped_large:
        out.append(f"  skipped {result.files_skipped_binary} binary, "
                   f"{result.files_skipped_large} oversized file(s)")
    if result.truncated:
        out.append(f"  TRUNCATED at {len(result.hits)} hits - the pattern is "
                   f"too broad to triage as written. Narrow it, or sweep a "
                   f"subtree, before recording.")
    if result.pattern_id:
        out.append(f"  read them with `audit.py rows --table cba_pattern_hits "
                   f"--where pattern_id={result.pattern_id}`")
    out.append("  Hits are candidates for triage, never verdicts.")
    return "\n".join(out)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_sweep.py -v`
Expected: all passed

- [ ] **Step 6: Add the `sweep` verb to `audit.py`**

```python
from audit_core import sweep as sweep_mod  # noqa: E402


def cmd_sweep(args: argparse.Namespace) -> int:
    con = _open_db(args.db)
    if con is None:
        return 1
    try:
        found = db_mod.rows(con, "cba_patterns", where={"id": args.pattern},
                            columns=("id", "regex"))
        if not found:
            print(f"no pattern {args.pattern!r}; register one with "
                  f"`audit.py put --table cba_patterns --set id=... "
                  f"--set name=... --set regex=...`", file=sys.stderr)
            return 1
        result = sweep_mod.run(
            pathlib.Path(args.root).expanduser(), found[0]["regex"],
            pattern_id=args.pattern,
            suffixes=tuple(args.suffix) or None, max_hits=args.max_hits)
        print(sweep_mod.render(result))
        if args.record:
            if result.truncated:
                print("refusing to record a truncated sweep; narrow the "
                      "pattern first", file=sys.stderr)
                return 1
            print(f"recorded {sweep_mod.record(con, result)} hit(s)")
    except db_mod.DbError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except re.error as exc:
        print(f"stored regex does not compile: {exc}", file=sys.stderr)
        return 1
    finally:
        con.close()
    return 0
```

Add `import re` to `audit.py`'s imports.

```python
    "sweep": cmd_sweep,
```

```python
    sw = sub.add_parser("sweep", help="scan a tree for a registered bug pattern")
    sw.add_argument("--db", required=True, metavar="AUDIT_DB")
    sw.add_argument("--pattern", required=True, metavar="PATTERN_ID")
    sw.add_argument("--root", required=True, metavar="SRC_DIR")
    sw.add_argument("--suffix", action="append", default=[], metavar=".c")
    sw.add_argument("--max-hits", type=int, default=sweep_mod.MAX_HITS)
    sw.add_argument("--record", action="store_true",
                    help="write the hits to cba_pattern_hits")
```

- [ ] **Step 7: Extend `tests/test_cli_stage2.py`**

```python
def test_sweep_reports_hits_without_printing_them(tmp_path):
    run_dir = new_run(tmp_path)
    db = str(run_dir / "audit.db")
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("strncpy(d, s, strlen(s));\n")
    run("put", "--db", db, "--table", "cba_patterns", "--set", "id=P1",
        "--set", "name=degenerate strncpy",
        "--set", r"regex=strncpy\([^,]+,[^,]+,\s*strlen\(")
    r = run("sweep", "--db", db, "--pattern", "P1", "--root", str(src), "--record")
    assert r.returncode == 0, r.stderr
    assert "1 hit(s)" in r.stdout
    assert "recorded 1 hit(s)" in r.stdout
    assert "strncpy(d, s" not in r.stdout
    assert "candidates for triage, never verdicts" in r.stdout


def test_sweep_against_an_unregistered_pattern_exits_one(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("sweep", "--db", db, "--pattern", "P9", "--root", str(tmp_path))
    assert r.returncode == 1
    assert "cba_patterns" in r.stderr


def test_sweep_refuses_to_record_a_truncated_result(tmp_path):
    run_dir = new_run(tmp_path)
    db = str(run_dir / "audit.db")
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("needle\n" * 50)
    run("put", "--db", db, "--table", "cba_patterns", "--set", "id=P1",
        "--set", "name=broad", "--set", "regex=needle")
    r = run("sweep", "--db", db, "--pattern", "P1", "--root", str(src),
            "--max-hits", "5", "--record")
    assert r.returncode == 1
    assert "narrow the pattern" in r.stderr


def test_registering_an_uncompilable_pattern_exits_one(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("put", "--db", db, "--table", "cba_patterns", "--set", "id=P1",
            "--set", "name=bad", "--set", "regex=([a-z")
    assert r.returncode == 1
    assert "compile" in r.stderr
```

- [ ] **Step 8: Run the Review Focus 3 tests, then the full suite**

Run: `python3 -m pytest tests/test_sweep.py -k "symlink or binary or oversized or capped" -v`
Expected: 4 passed (or 3 passed, 1 skipped if the platform refuses directory symlinks)

Run: `python3 -m pytest -q`
Expected: all pass, output pristine.

- [ ] **Step 9: Commit**

```bash
git add audit_core/sweep.py audit_core/db.py audit.py tests/test_sweep.py \
  tests/test_cli_stage2.py
git commit -m "feat: bounded corpus sweep for confirmed bug patterns

A confirmed finding is evidence about one call site and a hypothesis about
every other. The tplink run confirmed patterns and never swept for them.

Bounded at every edge, because an uncapped sweep dumping ten thousand hits
into the orchestrator is the exact failure R1 exists to prevent: symlinks are
never followed, binary and oversized files are skipped and counted rather
than decoded, hits are capped, and render() says how to read the rows instead
of pasting them. Recording a truncated sweep is refused - a pattern too broad
to triage is a pattern to narrow.

A pattern's regex is compiled before it is stored: an uncompilable stored
pattern is a sweep that silently never runs.

Stage 2 ships the engine. Sweeping automatically on every confirmed finding is
the Stage 3 change, benchmarked alone so a recall movement can be attributed."
```

---

## Task 7: R1 and R3 in the shipped skill — with a derivation artifact

**Why this exists and why it is the risky task.** Stage 1's closing finding is
unambiguous: *rewriting shipped prose from scratch lost instructions five times
out of five* — the 18 Hard Exclusions, six of sixteen hunt categories, two of
nine FP method steps, the patch-bypass probe, the live-PoC prohibitions, plus
eight smaller narrowings. Five separate reviews each caught a different subset
and **none caught all of them**. Its implication is binding on this task:

> any later stage that rewrites shipped prose must produce an explicit
> derivation — the old instruction set diffed against the new, with a
> justification for every dropped line — as a reviewable artifact, rather than
> relying on a reviewer to notice an absence.

So the rule for this task is **replacement, never rewriting**. Every change
below swaps a hand-typed SQL block for the verb that produces the same rows.
The surrounding instructions — what to do with the result, when, and why — are
not touched. The derivation table is the deliverable that proves it, and the
reviewer's first job is to check the table against the diff, not the diff
against their memory.

**Files:**
- Create: `docs/superpowers/derivations/2026-10-05-stage2-prose-derivation.md`
- Modify: `SKILL.md` — **CRLF**
- Modify: `workflows/audit.md`, `workflows/fpcheck.md`, `workflows/report.md`, `workflows/recon.md` — **LF**
- Modify: `references/phase2-feature-mapping.md`, `references/phase4-deep-audit.md`, `references/phase5-fp-check.md` — **CRLF**
- Modify: `references/resume-note-template.md` — **LF**
- Modify: `tests/test_workflow_prose.py`

**Interfaces:**
- Consumes: every verb from Tasks 1-6 (`put`, `rows`, `status`, `dedup`, `coverage`, `extract`, `note`, `checkpoint`, `sweep`).
- Produces: the installed prose Task 8's linter checks.

### Steps

- [ ] **Step 1: Write the failing guard tests first**

These are what stop a sixth narrowing. Add to `tests/test_workflow_prose.py`,
following its existing idiom (it reads the shipped files as bytes and asserts
on content):

```python
def test_every_retired_query_is_gone_from_shipped_prose():
    """The five hand-typed SQL shapes Stage 2 replaced. Each was retyped
    after every compaction restart, which is R5's target exactly."""
    retired = [
        "SELECT id,name,status FROM cba_feature_groups",
        "SELECT group_id,severity,COUNT(*) FROM cba_findings",
        "SELECT verdict,COUNT(*) FROM cba_fp_verdicts",
        "FROM cba_fp_verdicts WHERE verdict = 'TRUE_POSITIVE'",
        "INSERT INTO cba_findings",
        "INSERT INTO cba_fp_verdicts",
        "INSERT INTO cba_attack_surface",
        "INSERT INTO cba_security_observations",
        "INSERT INTO cba_known_findings",
    ]
    for path in live_markdown():
        text = normalize_ws(path.read_text(encoding="utf-8"))
        for query in retired:
            assert normalize_ws(query) not in text, f"{path.name}: {query}"


def test_every_instruction_the_replaced_blocks_sat_inside_survives():
    """Stage 1's finding: five reviews each caught a different absence and
    none caught all of them. These are the surrounding instructions, not the
    SQL - the thing a replacement must not take with it."""
    expect = {
        "workflows/audit.md": [
            "Patch-bypass mining",
            "were they the ONLY sites of the vulnerable pattern",
            "Top patch-bypass discoveries",
        ],
        "workflows/fpcheck.md": [
            "identify the missing batch and re-spawn just that one",
            "Order TPs by severity",
        ],
        "workflows/report.md": [
            "Steps to reproduce is a reproduction GUIDE only",
            "do NOT run a PoC and do NOT paste captured output",
            "NOT live-verified",
        ],
        "references/phase2-feature-mapping.md": [
            "Save each group's full output to",
        ],
        "references/phase4-deep-audit.md": [
            "keep the one with higher confidence",
        ],
        "references/phase5-fp-check.md": [
            "Mix severities within batches",
            "If Finding A's truth value depends on Finding B",
        ],
    }
    for rel, needles in expect.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        for needle in needles:
            assert needle in text, f"{rel} lost: {needle}"


def test_skill_md_states_r1_and_r3():
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "### R1 " in text
    assert "### R3 " in text
    assert "audit.py extract" in text
    assert "audit.py checkpoint" in text
    assert "100k" in text or "100,000" in text


def test_the_anti_rationalization_rule_is_in_the_rejection_table():
    """Spec R3: 'near the ceiling, skip this group' is answered by
    checkpoint-and-restart, never by skipping."""
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "near the ceiling, skip this group" in text.lower() \
        or "skip this group" in text
    assert "not_audited(reason='budget')" in text


def test_skill_md_lists_the_five_new_tables():
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    for table in ("cba_inventory", "cba_coverage", "cba_patterns",
                  "cba_pattern_hits", "cba_checkpoints"):
        assert table in text


def test_every_documented_audit_py_invocation_parses():
    """Stage 1 shipped a documented command that exited 1. Every invocation in
    the shipped prose is parsed by the real parser, not eyeballed."""
    import re as _re
    import audit
    parser = audit.build_parser()
    pattern = _re.compile(r"audit\.py ([a-z-]+)((?: --[a-z-]+(?:[= ][^\s`]+)?)*)")
    for path in live_markdown():
        for verb, _ in pattern.findall(path.read_text(encoding="utf-8")):
            assert verb in audit.HANDLERS, f"{path.name}: unknown verb {verb}"
```

If `tests/test_workflow_prose.py` has no `live_markdown()` / `normalize_ws()`
/ `ROOT` helpers, add them there in its existing style; do not duplicate the
file walk in each test.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_workflow_prose.py -v`
Expected: the new tests FAIL (the retired queries are still present, `### R1`
is absent). The pre-existing tests in the file still PASS — if any of them
breaks, stop: the file-walk helpers were changed, not just extended.

- [ ] **Step 3: Write the derivation artifact FIRST, before editing any prose**

Create `docs/superpowers/derivations/2026-10-05-stage2-prose-derivation.md`.
Writing it first is the point: the table is the plan for the edit, not a
report about it.

For **every** block being replaced, one row with four columns:

| File:line | Old text (verbatim) | New text (verbatim) | What the new form does that the old did — and anything the old stated that the new does not, with why |

The nine replacements are listed in Steps 4-6 below. A row whose fourth column
says "nothing dropped" must be true: read the old block's surrounding
paragraph and confirm every instruction in it still appears somewhere.

Open the file with a short preamble naming Stage 1 finding #1 as the reason it
exists, and close it with an explicit count: *"N blocks replaced, M lines
dropped, each justified above."* If M is not zero, each dropped line gets its
own justification sentence.

- [ ] **Step 4: Replace the four read-side SQL blocks**

**4a. `references/resume-note-template.md` (LF)** — the three re-orient
queries. Replace:

```bash
sqlite3 reports/audit-<ts>/audit.db "SELECT id,name,status FROM cba_feature_groups;"
sqlite3 reports/audit-<ts>/audit.db "SELECT group_id,severity,COUNT(*) FROM cba_findings GROUP BY 1,2 ORDER BY 1,2;"
sqlite3 reports/audit-<ts>/audit.db "SELECT verdict,COUNT(*) FROM cba_fp_verdicts GROUP BY verdict;"
```

with:

```bash
python3 __SKILL_DIR__/audit.py status --db reports/audit-<ts>/audit.db
python3 __SKILL_DIR__/audit.py coverage --db reports/audit-<ts>/audit.db
```

The heading above it stays "## SQL re-orient queries (paste-and-run)" — rename
it to "## Re-orient after a restart (paste-and-run)" and note in the
derivation that the rename is cosmetic and drops nothing. `status` prints all
three of the replaced queries' results; `coverage` is additive and is the
reason a restart can tell whether anything was skipped.

**4b. `workflows/fpcheck.md` Step 5 (LF)** — replace the five-subquery
completeness SELECT with:

```bash
python3 __SKILL_DIR__/audit.py status --db ${AUDIT_DIR}/audit.db
```

Keep the sentence after it verbatim: "If `findings != verdicts`, identify the
missing batch and re-spawn just that one." Add one sentence naming where the
number now comes from: "`status` prints `unverdicted`, which is that
difference." The TP/FP/DUPLICATE breakdown the old query produced is in
`status`'s verdict table — confirm this in the derivation by running both and
comparing.

**4c. `workflows/audit.md` Step 7 (LF)** — replace the group × severity SELECT
with:

```bash
python3 __SKILL_DIR__/audit.py status --db ${AUDIT_DIR}/audit.db
```

Everything after it — the five resume-note bullets including **Top
patch-bypass discoveries** — is untouched.

**4d. `workflows/report.md` Mode B step 1 (LF)** — replace:

```sql
SELECT finding_id, final_severity FROM cba_fp_verdicts WHERE verdict = 'TRUE_POSITIVE';
```

with:

```bash
python3 __SKILL_DIR__/audit.py rows --db ${AUDIT_DIR}/audit.db \
  --table cba_fp_verdicts --where verdict=TRUE_POSITIVE \
  --columns finding_id,final_severity
```

Steps 2, 3 and 4 of Mode B — including "Steps to reproduce is a reproduction
GUIDE only", "do NOT run a PoC and do NOT paste captured output", and the
"NOT live-verified" statement — are untouched.

- [ ] **Step 5: Replace the four write-side SQL blocks**

Each becomes an `audit.py put` invocation showing every required column, so a
subagent copying it cannot produce a row the contract rejects.

**5a. `references/phase4-deep-audit.md` (CRLF)** — replace the `INSERT INTO
cba_findings` block with:

```bash
python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_findings \
  --set id=G1-F1 --set group_id=G1 --set title='<one line>' \
  --set severity=HIGH --set confidence=9 --set location='<file>:<line>' \
  --set root_cause='<mechanism>' --set impact='<consequence>' \
  --set attacker_position='<where the attacker stands>' \
  --set boundary_crossed='<trust boundary>' --set cwe=CWE-787 \
  --set artifact_path=artifacts/G1-findings.md
```

Then replace step 4 of that section — "**Dedup quick-check**: If two findings
from different groups describe the same vulnerability at the same code
location, keep the one with higher confidence and note the duplicate." — with
the same instruction plus the command that performs it:

```bash
python3 __SKILL_DIR__/audit.py dedup --db ${AUDIT_DIR}/audit.db
```

"These are proposals. Keep the one with higher confidence and record the other
as `verdict=DUPLICATE` with `merged_into` set." The phrase "keep the one with
higher confidence" must survive verbatim — a guard test asserts it.

**5b. `references/phase5-fp-check.md` (CRLF)** — replace the `INSERT INTO
cba_fp_verdicts` block with:

```bash
python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_fp_verdicts \
  --set finding_id=G1-F1 --set verdict=TRUE_POSITIVE \
  --set reason='<why>' --set final_severity=HIGH --set final_id=F-1 \
  --set rule_applied='<HE-n / PR-n / CV-n, or none>'
```

Also replace the batch-count pseudo-SQL:

```
total_findings = SELECT COUNT(*) FROM cba_findings
batch_count = CEILING(total_findings / 10)
```

with:

```
total_findings = the `findings` count from `audit.py status`
batch_count    = CEILING(total_findings / 10)
```

The three batching rules above it — group affinity, severity mixing, no
cross-dependencies — are untouched.

**5c. `references/phase2-feature-mapping.md` (CRLF)** — replace the two
INSERT blocks with:

```bash
python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_attack_surface \
  --set group_id=G1 --set endpoint='<route or entry point>' \
  --set method='<verb or protocol>' --set auth_required='<yes|no|partial>' \
  --set description='<what it does>'

python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_security_observations \
  --set group_id=G1 --set observation='<what was seen>' \
  --set severity_hint=MEDIUM --set location='<file>:<line>'
```

Item 1 of that list — "**Session files**: Save each group's full output to
`files/{group_id}-mapping.md`" — is untouched.

**5d. `workflows/audit.md` Step 1 (LF)** — replace the `INSERT INTO
cba_known_findings` block with:

```bash
python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_known_findings \
  --set id=GHSA-xxxx-yyyy-zzzz --set title='<advisory title>' \
  --set location='<file or component>' --set source=GHSA \
  --set patched_in='<version>' --set severity=HIGH
```

**Step 2 — Patch-bypass mining is untouched**, including "were they the ONLY
sites of the vulnerable pattern". It was lost once already, in Stage 1, and is
guard-tested.

- [ ] **Step 6: Add R1 and R3 to `SKILL.md` (CRLF — verify after editing)**

**6a.** In the `## Economics Contract` preamble, replace:

> The rules below are R2, R4, R5 and R6 of the economics contract; R1
> (extract-then-fan-out) and R3 (the context ceiling) are enforced in the
> audit workflows rather than here.

with:

> The rules below are the economics contract in full: R1 and R3 govern what
> enters the orchestrator's context and for how long; R2, R4, R5 and R6 govern
> each of the ways it gets in.

**6b.** Insert `### R1 — The orchestrator never holds raw material` as the
first rule, before the tiering table:

```markdown
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

The orchestrator's own reads are bounded too. Rows come from
`audit.py rows`, `audit.py status` and `audit.py coverage`, which cap at 200
rows; comprehension comes from `audit.py note`, which returns one line per
key, not the analysis behind it.
```

**6c.** Insert `### R3 — Context ceiling with checkpoint-restart` after R1:

```markdown
### R3 — Context ceiling with checkpoint-restart

Ceiling **100k**, checkpoint at 80%. On a trip, write the resume note and the
journal, record the checkpoint, and end the phase; the next phase starts
fresh at a ~45k prefix.

    python3 __SKILL_DIR__/audit.py checkpoint --db ${AUDIT_DIR}/audit.db \
      --phase audit --reason ceiling --turns <n> \
      --resume-note /memories/session/<project>-audit-resume.md

Compaction is not the mechanism: it costs a full-context read plus a summary,
lands at 60k-80k of lossy summary rather than 45k of real prefix, and discards
the technical state the next step needs. `audit.py budget --project` reports
the measured prefix and growth and how many turns they leave.

**The budget governs where tokens are spent, never whether a surface is
opened.** A group skipped for budget is a `not_audited(reason='budget')` row
and fails the quality gate.
```

**6d.** In `## Quick Reference → SQL Tables`, add five rows:

```markdown
| `cba_inventory` | One row per analysable unit — the coverage denominator | recon |
| `cba_coverage` | `analyzed` / `not_audited(reason)` per unit per phase | every phase |
| `cba_patterns` | Confirmed bug patterns, with the finding they came from | audit |
| `cba_pattern_hits` | Sweep candidates awaiting triage | audit |
| `cba_checkpoints` | Phase exits and ceiling trips | every phase |
```

**6e.** In `## Quick Reference → Artifact Layout`, add inside the
`reports/audit-<YYYYMMDD-HHMMSS>/` tree, after `briefs/`:

```
├── extract/                        # snapshotted material (audit.py extract)
│   ├── manifest.json               # sha256 + version per snapshot
│   └── G<n>/<flattened-path>       # one directory per feature group
├── journal.jsonl                   # annotation journal (audit.py note)
```

**6f.** In `## Rationalizations to Reject`, add three rows at the end:

```markdown
| "Near the ceiling — skip this group" | Checkpoint and restart. A group skipped for budget is a `not_audited(reason='budget')` row and fails the quality gate. The budget governs where tokens are spent, never whether a surface is opened. |
| "I'll just read the file into my own context to check one thing" | R1. Snapshot it with `audit.py extract` and send a subagent the path, or read the rows with `audit.py rows`. A token admitted at turn N is paid for on every remaining turn. |
| "We confirmed the pattern here; the other call sites are probably fine" | A confirmed finding is a hypothesis about every other call site. Register it with `audit.py put --table cba_patterns` and sweep. |
```

- [ ] **Step 7: Verify the line endings survived**

Run:

```bash
for f in SKILL.md references/phase2-feature-mapping.md \
         references/phase4-deep-audit.md references/phase5-fp-check.md; do
  file -b "$f" | grep -q CRLF || { echo "LOST CRLF: $f"; exit 1; }
done
for f in workflows/audit.md workflows/fpcheck.md workflows/report.md \
         workflows/recon.md references/resume-note-template.md; do
  file -b "$f" | grep -q CRLF && { echo "GAINED CRLF: $f"; exit 1; }
done
echo "line endings intact"
```

Expected: `line endings intact`

- [ ] **Step 8: Run the guard tests, then the full suite**

Run: `python3 -m pytest tests/test_workflow_prose.py -v`
Expected: all pass, including the pre-existing Stage 1 guards.

Run: `python3 -m pytest -q`
Expected: all pass, output pristine.

- [ ] **Step 9: Check the derivation table against the diff**

Run `git diff --stat` and confirm the derivation file has a row for every
hunk in the eight prose files. A hunk with no row is a change made without a
justification, which is exactly what Stage 1 could not catch. Fix the table,
not the diff.

- [ ] **Step 10: Commit**

```bash
git add SKILL.md workflows references docs/superpowers/derivations tests/test_workflow_prose.py
git commit -m "feat: R1 and R3 in the shipped skill, by replacement not rewrite

Stage 1's closing finding was that rewriting shipped prose from scratch lost
instructions five times out of five, and that five separate reviews each
caught a different subset while none caught all. So nothing here is rewritten:
nine hand-typed SQL blocks are swapped for the verbs that produce the same
rows, and every surrounding instruction is left exactly as it was.

docs/superpowers/derivations/2026-10-05-stage2-prose-derivation.md is the
artifact that finding asked for - old text against new, one row per block,
with a justification for anything that did not survive. It was written before
the edits, not after.

SKILL.md gains R1 and R3, the five new tables, extract/ and journal.jsonl in
the artifact layout, and three rejection rows - including the one R3 names
directly: near the ceiling, checkpoint and restart, never skip a group."
```

---

## Task 8: Make the new surface enforceable — lint, selftest, installer

**Why this exists.** Stage 1's finding #2 is the scope statement this task has
to live inside: *"these rules pin specific past mistakes. A clean run means
those mistakes are absent. It is not evidence the skill functions."* The
Stage 1 linter reported clean on a tree in which every command it checked was
unrunnable, because the defect was not among the things it looked for. So one
rule is added here, pinning one specific mistake Stage 2 makes possible, and
nothing is made fuzzy.

The bigger piece is the selftest. Stage 0's finding #4: *"a figure regenerated
from a tool is only better than computing it by hand if the tool is validated
against something it did not produce."* `TABLE_SPECS` is now the contract
every write goes through, and it is a hand-maintained dict that can drift from
`schema.sql` silently — a column renamed in one and not the other produces a
`DbError` on a real run, six phases in. The selftest cross-checks the dict
against the database `schema.sql` actually builds, which is a structure the
dict did not produce.

Finally, the carried Stage 1 item: `install.sh` does not remove `workflows/`
or `references/` before copying, so a file deleted from the repo lingers in a
`.sh`-installed tree. `install.ps1` already prunes.

**Files:**
- Modify: `audit_core/skill_lint.py` (one rule)
- Modify: `audit.py` (`cmd_selftest`)
- Modify: `install.sh`
- Modify: `tests/test_skill_lint.py`, `tests/test_cli.py`, `tests/test_install.py`

**Interfaces:**
- Consumes: `db.TABLE_SPECS`, `workspace.apply_schema`, `HANDLERS`, `build_parser`.
- Produces: nothing downstream depends on it. This is the net.

### Steps

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_skill_lint.py`, in its existing style:

```python
def test_a_retired_status_query_in_prose_is_a_finding(tmp_path):
    """One rule, one specific past mistake: the three SELECTs the resume-note
    template carried, retyped after every compaction restart. This does NOT
    try to detect hand-written SQL in general - a fuzzy linter over English
    produces false positives on legitimate text and gets disabled."""
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        'sqlite3 audit.db "SELECT group_id, severity, COUNT(*) FROM cba_findings '
        'GROUP BY 1,2;"\n')
    findings = skill_lint.lint(root, {"status"})
    assert [f.rule for f in findings] == ["hand-typed-status-sql"]
    assert "audit.py status" in findings[0].detail


def test_the_rule_ignores_whitespace_differences(tmp_path):
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        "SELECT id,name,status FROM cba_feature_groups\n")
    assert [f.rule for f in skill_lint.lint(root, {"status"})] == \
        ["hand-typed-status-sql"]


def test_an_audit_py_status_invocation_is_not_a_finding(tmp_path):
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        "python3 /x/audit.py status --db audit.db\n")
    assert skill_lint.lint(root, {"status"}) == []


def test_mentioning_a_table_name_in_prose_is_not_a_finding(tmp_path):
    """The scope statement, enforced: this rule pins four literal queries, not
    the idea of SQL."""
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        "Rows land in `cba_findings`; counts come from `cba_fp_verdicts`.\n")
    assert skill_lint.lint(root, {"status"}) == []
```

Add to `tests/test_cli.py`:

```python
def test_selftest_cross_checks_the_table_contract_against_the_real_schema():
    r = run("selftest")
    assert r.returncode == 0, r.stderr
    assert "tables" in r.stdout
    assert "verbs" in r.stdout


def test_selftest_fails_when_a_spec_column_is_not_in_the_schema(tmp_path):
    """Stage 0's finding: a tool's output is only trustworthy if the tool is
    validated against something it did not produce. TABLE_SPECS is
    hand-maintained; schema.sql builds the database. They can drift."""
    import audit
    from audit_core import db
    original = db.TABLE_SPECS["cba_findings"]
    db.TABLE_SPECS["cba_findings"] = db.TableSpec(
        columns=original.columns + ("imaginary_column",),
        required=original.required, validate=original.validate)
    try:
        assert audit.cmd_selftest(None) == 1
    finally:
        db.TABLE_SPECS["cba_findings"] = original


def test_selftest_fails_when_a_handler_has_no_subparser():
    import audit
    audit.HANDLERS["ghost"] = lambda args: 0
    try:
        assert audit.cmd_selftest(None) == 1
    finally:
        del audit.HANDLERS["ghost"]
```

Add to `tests/test_install.py`, matching its existing `HOME`-override idiom:

```python
def test_install_removes_a_workflow_deleted_from_the_repo(tmp_path):
    """Carried from Stage 1: install.ps1 prunes, install.sh did not, so a
    file deleted from the repo lingered in a .sh-installed tree forever."""
    home = install_into_temp_home(tmp_path)          # existing helper
    skill = home / ".claude" / "skills" / "codebase-audit"
    stale = skill / "workflows" / "ghost.md"
    stale.write_text("left over from an older install\n")
    stale_ref = skill / "references" / "ghost.md"
    stale_ref.write_text("also stale\n")

    install_into_temp_home(tmp_path, home=home)      # second install
    assert not stale.exists()
    assert not stale_ref.exists()
    assert (skill / "workflows" / "audit.md").is_file()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_skill_lint.py tests/test_cli.py tests/test_install.py -v`
Expected: the new tests FAIL; every pre-existing test still passes.

- [ ] **Step 3: Add the lint rule**

In `audit_core/skill_lint.py`, beside the other literals:

```python
# Query shapes the Stage 2 verbs replaced. Each was retyped by the
# orchestrator after every compaction restart, which is what R5 costs.
# These are literal strings on purpose. A rule that tried to recognize
# hand-written SQL in general would fire on legitimate prose about the
# schema, and a linter that cries wolf gets switched off. The honest scope
# statement is that a clean run means these four specific mistakes are
# absent - not that the skill works.
RETIRED_QUERIES = (
    "SELECT id,name,status FROM cba_feature_groups",
    "SELECT group_id,severity,COUNT(*) FROM cba_findings",
    "SELECT verdict,COUNT(*) FROM cba_fp_verdicts",
    "SELECT COUNT(*) FROM cba_fp_verdicts WHERE verdict",
)

_WS = re.compile(r"\s+")


def _squash(value: str) -> str:
    """Collapse whitespace so `SELECT id, name` and `SELECT id,name` match."""
    return _WS.sub("", value).lower()
```

In the per-file loop:

```python
        squashed = _squash(text)
        for query in RETIRED_QUERIES:
            if _squash(query) in squashed:
                findings.append(Finding(
                    "hand-typed-status-sql", rel,
                    f"prose carries the retired query {query!r}; "
                    f"`audit.py status` prints it"))
```

- [ ] **Step 4: Rewrite `cmd_selftest` as a real cross-check**

```python
def cmd_selftest(_args: argparse.Namespace) -> int:
    """Verify the vendored core is importable AND internally consistent.

    Printing a version number proves an import. These three checks prove the
    things that actually break a run six phases in, and each compares two
    structures that were built independently - per Stage 0's finding that a
    tool's output is only trustworthy when validated against something it did
    not produce.
    """
    problems: list[str] = []

    # 1. Verbs: HANDLERS against the argument parser's subcommands.
    parser = build_parser()
    sub = next((a for a in parser._actions                     # noqa: SLF001
                if isinstance(a, argparse._SubParsersAction)), None)
    declared = set(sub.choices) if sub is not None else set()
    for verb in sorted(set(HANDLERS) - declared):
        problems.append(f"verb {verb!r} has a handler but no subparser")
    for verb in sorted(declared - set(HANDLERS)):
        problems.append(f"verb {verb!r} has a subparser but no handler")

    # 2. Tables: TABLE_SPECS against the database schema.sql actually builds.
    with tempfile.TemporaryDirectory() as tmp:
        db_path = pathlib.Path(tmp) / "selftest.db"
        try:
            tables = set(workspace_mod.apply_schema(db_path))
        except Exception as exc:                       # noqa: BLE001
            print(f"selftest: schema.sql does not apply: {exc}", file=sys.stderr)
            return 1
        con = sqlite3.connect(db_path)
        try:
            for table, spec in sorted(db_mod.TABLE_SPECS.items()):
                if table not in tables:
                    problems.append(f"{table} is in TABLE_SPECS but not in schema.sql")
                    continue
                actual = {r[1] for r in con.execute(
                    f"PRAGMA table_info({table})")}
                for column in sorted(set(spec.columns) - actual):
                    problems.append(f"{table}.{column} is in TABLE_SPECS "
                                    f"but not in schema.sql")
                for column in sorted(c for c in spec.required if c not in actual):
                    problems.append(f"{table}.{column} is required by "
                                    f"TABLE_SPECS but does not exist")
        finally:
            con.close()

    if problems:
        print(f"selftest: {len(problems)} inconsistenc(ies)", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"audit_core {audit_core.__version__} ok")
    print(f"  verbs  {len(HANDLERS)} declared, all dispatchable")
    print(f"  tables {len(tables)} in schema.sql, "
          f"{len(db_mod.TABLE_SPECS)} under contract, columns agree")
    return 0
```

Add `import sqlite3` and `import tempfile` to `audit.py`.

`HANDLERS` and `build_parser` are defined below `cmd_selftest` in the current
file; Python resolves them at call time, so no reordering is needed. Verify
that by running the test, not by reading.

- [ ] **Step 5: Prune in `install.sh`**

In `install_skill_files`, immediately before the `for sub in workflows
references; do` loop:

```bash
  # Remove before copying, so a file deleted from the repo does not linger in
  # an installed tree forever. install.ps1 already does this; this is the
  # matching behaviour. The clone-in-place guard above has already run, so
  # ${target} is never this checkout.
  for sub in workflows references; do
    rm -rf "${target:?}/${sub}"
  done
```

`${target:?}` makes an empty `target` abort rather than expanding to `rm -rf
/workflows`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_skill_lint.py tests/test_cli.py tests/test_install.py -v`
Expected: all pass.

**The install test must override `HOME`, `CLAUDE_CONFIG_DIR` and
`CODEX_HOME`.** Confirm before and after that `~/.claude/skills/codebase-audit`
is untouched:

```bash
stat -f '%Sm %N' ~/.claude/skills/codebase-audit
```

- [ ] **Step 7: Run `lint-skill` against the real checkout and the full suite**

Run: `python3 audit.py lint-skill`
Expected: `skill lint: clean`

Run: `python3 audit.py selftest`
Expected: three lines, exit 0.

Run: `python3 -m pytest -q`
Expected: all pass, output pristine.

- [ ] **Step 8: Commit**

```bash
git add audit_core/skill_lint.py audit.py install.sh \
  tests/test_skill_lint.py tests/test_cli.py tests/test_install.py
git commit -m "feat: selftest cross-checks the table contract; lint pins the retired queries

selftest printed a version number, which proves an import. It now compares two
independently built structures: HANDLERS against the argument parser's
subcommands, and TABLE_SPECS against the database schema.sql actually builds.
A column renamed in one and not the other used to surface as a DbError six
phases into a real run.

One lint rule, four literal strings - the status queries Stage 2 replaced.
Deliberately not a general SQL detector: a rule that fires on legitimate prose
about the schema gets the linter switched off. A clean run means those four
mistakes are absent, which is not the same as the skill working.

install.sh now prunes workflows/ and references/ before copying, matching
install.ps1. A file deleted from the repo used to linger in a .sh-installed
tree forever."
```

---

## Task 9: Sharpen the scorer for a gate that runs twice

**Why this exists.** Stage 2's gate is *"tplink re-run twice — cost must fall
and recall must be ≥ 9/19."* Two runs against the current scorer means
adjudicating the same false pairs twice. Stage 0 recorded why:

- **Finding #2 — the scorer has no memory of rejected candidates.** The two
  false `REF-10` pairs, produced by the bare three-character token `tss`, will
  resurface on every future run and demand re-adjudication, and the cost grows
  with every target added to the golden set.
- **Finding #3 — golden location tokens are too coarse and too sparse.**
  `REF-14` carries the bare token `test`, which is strictly worse than `tss`
  and is currently masked only because REF-14 is already adjudicated. If it
  ever becomes unmatched it pairs against every finding whose location contains
  `test`, `latest` or `attestation`. Separately, several entries omit addresses
  their source report cites, so a future run citing only an omitted address
  surfaces as nothing at all.

Both land here, before the gate that depends on them. Stage 0's finding #1
(severity agreement) does **not**: it belongs with the Stage 3 re-rating step
that gives it something to score.

**Files:**
- Modify: `audit_core/goldens.py` (`load_rejections`)
- Modify: `audit_core/bench.py` (token-based candidates, rejections)
- Modify: `audit.py` (`cmd_bench` loads rejections)
- Create: `tests/goldens/tplink-dl110v2-1.0.11/rejections.json`
- Modify: `tests/goldens/tplink-dl110v2-1.0.11/reference.json`, `README.md`
- Modify: `tests/test_bench.py`, `tests/test_goldens.py`
- Create: `docs/baselines/2026-10-05-stage2-gate.md`

**Interfaces:**
- Consumes: `text.location_tokens`, `text.MIN_LOCATION_TOKEN`.
- Produces: `goldens.load_rejections(path) -> set[tuple[str, str]]`; `bench.score(refs, findings, adjudicated, rejected=frozenset(), cost_usd=None)`.

### Steps

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_goldens.py`:

```python
def test_load_rejections_returns_pairs(tmp_path):
    p = tmp_path / "rejections.json"
    p.write_text('[{"reference_id": "REF-10", "finding_id": "G6-F3", '
                 '"reason": "bare `tss` token; unrelated defects"}]')
    assert goldens.load_rejections(p) == {("REF-10", "G6-F3")}


def test_a_missing_rejections_file_is_empty_not_an_error(tmp_path):
    assert goldens.load_rejections(tmp_path / "nope.json") == set()


def test_a_rejection_without_a_reason_is_refused(tmp_path):
    """A rejection with no reason is indistinguishable from a mistake, and it
    silences a candidate forever."""
    p = tmp_path / "rejections.json"
    p.write_text('[{"reference_id": "REF-10", "finding_id": "G6-F3"}]')
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_rejections(p)
    assert "reason" in str(exc.value)


def test_rejections_must_be_a_list(tmp_path):
    p = tmp_path / "rejections.json"
    p.write_text('{"REF-10": "G6-F3"}')
    with pytest.raises(goldens.GoldenError):
        goldens.load_rejections(p)
```

Add to `tests/test_bench.py`:

```python
def test_a_rejected_pair_is_not_offered_as_a_candidate_again():
    refs = [mkref("REF-10", locations=["update_bind_token", "tss"])]
    findings = [mkfinding("G6-F3", location="TssRSASecretKey @0x1234")]
    assert bench.score(refs, findings, {}).candidates != ()
    scored = bench.score(refs, findings, {},
                         rejected=frozenset({("REF-10", "G6-F3")}))
    assert scored.candidates == ()
    assert scored.unmatched_references == ("REF-10",)


def test_a_short_location_token_no_longer_generates_a_candidate():
    """REF-10's bare `tss` matched TssRSASecretKey and osal_tss_init. The
    four-character floor is why that pair cannot be raised at all now."""
    refs = [mkref("REF-10", locations=["tss"])]
    findings = [mkfinding("G6-F3", location="TssRSASecretKey")]
    assert bench.score(refs, findings, {}).candidates == ()


def test_a_full_symbol_still_generates_a_candidate():
    refs = [mkref("REF-1", locations=["tbtp_handle_characteristic_received"])]
    findings = [mkfinding("G5-F1",
                          location="tbtp_handle_characteristic_received@0x2001CA2C")]
    c = bench.score(refs, findings, {}).candidates
    assert len(c) == 1
    assert "tbtp_handle_characteristic_received" in c[0].reason


def test_candidate_matching_is_case_insensitive():
    refs = [mkref("REF-1", locations=["KlapHandshake1Handle"])]
    findings = [mkfinding("G1-F7", location="klaphandshake1handle@0x0E043264")]
    assert len(bench.score(refs, findings, {}).candidates) == 1


def test_rejecting_a_pair_does_not_hide_an_adjudicated_match():
    """A rejection silences a candidate, never a match. matches.json wins."""
    refs = [mkref("REF-19", locations=["tbtp_handle_characteristic_received"])]
    findings = [mkfinding("G5-F1", location="tbtp_handle_characteristic_received")]
    scored = bench.score(refs, findings, {"REF-19": "G5-F1"},
                         rejected=frozenset({("REF-19", "G5-F1")}))
    assert scored.matched == (("REF-19", "G5-F1"),)
```

Use whatever `mkref` / `mkfinding` helpers `tests/test_bench.py` already has;
add them in its style if it builds the objects inline.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_bench.py tests/test_goldens.py -v`
Expected: the new tests FAIL (`load_rejections` missing; `score()` has no
`rejected` parameter). Every pre-existing test still passes — in particular
the one that asserts only adjudicated pairs count toward recall.

- [ ] **Step 3: Add `load_rejections` to `audit_core/goldens.py`**

```python
def load_rejections(path: str | pathlib.Path) -> set[tuple[str, str]]:
    """Pairs a human has looked at and rejected.

    matches.json records adjudicated matches; nothing recorded adjudicated
    non-matches, so the two false REF-10 pairs resurfaced on every scoring run
    and cost a fresh adjudication each time. A rejection must carry a reason:
    one without is indistinguishable from a mistake, and it silences a
    candidate permanently.
    """
    path = pathlib.Path(path)
    if not path.is_file():
        return set()
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise GoldenError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, list):
        raise GoldenError(f"{path}: expected a list of rejection objects")
    out: set[tuple[str, str]] = set()
    for i, item in enumerate(raw):
        for key in ("reference_id", "finding_id", "reason"):
            if not str(item.get(key, "")).strip():
                raise GoldenError(f"{path}[{i}]: missing '{key}'")
        out.add((str(item["reference_id"]), str(item["finding_id"])))
    return out
```

- [ ] **Step 4: Change candidate generation in `audit_core/bench.py`**

Replace the substring-containment block with token intersection, and add the
`rejected` parameter:

```python
from audit_core import text


def score(
    refs: list[Reference],
    findings: list[RunFinding],
    adjudicated: dict[str, str],
    rejected: frozenset[tuple[str, str]] = frozenset(),
    cost_usd: float | None = None,
) -> BenchResult:
    ...
    candidates: list[Candidate] = []
    for ref in refs:
        if ref.id in matched_refs:
            continue
        ref_tokens = frozenset().union(
            *(text.location_tokens(loc) for loc in ref.locations)) \
            if ref.locations else frozenset()
        for finding in findings:
            if finding.id in matched_findings:
                continue
            if (ref.id, finding.id) in rejected:
                continue
            shared = ref_tokens & text.location_tokens(finding.location)
            if shared:
                candidates.append(Candidate(
                    ref.id, finding.id,
                    "location overlap: " + ", ".join(sorted(shared))))
```

Note the behaviour change to state in the commit message: matching is now on
**whole tokens of four or more characters**, not substrings. `tss` inside
`TssRSASecretKey` no longer matches; `tbtp_handle_characteristic_received`
still does. The adjudicated matches in `matches.json` are unaffected — they
are matches, not candidates.

- [ ] **Step 5: Load rejections in `cmd_bench`**

```python
    rejected = goldens_mod.load_rejections(golden / "rejections.json")
    ...
    result = bench_mod.score(refs, findings, adjudicated,
                             rejected=rejected, cost_usd=args.cost)
```

and in the human-readable output, after the candidates block:

```python
    if rejected:
        print(f"({len(rejected)} previously rejected pair(s) suppressed)")
```

- [ ] **Step 6: Write the golden's `rejections.json`**

Create `tests/goldens/tplink-dl110v2-1.0.11/rejections.json` with the two
pairs the README's adjudication log already records, quoting its own reasons:

```json
[
  {
    "reference_id": "REF-10",
    "finding_id": "G6-F3",
    "reason": "False pair from the bare three-character token `tss` matching TssRSASecretKey / osal_tss_*. REF-10 is a degenerate-strncpy heap overflow in update_bind_token; G6-F3 is disclosure of the RSA private key over the debug UART via ATTPGV. Different defects.",
    "adjudicated": "2026-10-05"
  },
  {
    "reference_id": "REF-10",
    "finding_id": "G6-F4",
    "reason": "The same bare-`tss` false pair. G6-F4 is ATTPSK/ATTPSV overwriting the key store in flash. Different defect.",
    "adjudicated": "2026-10-05"
  }
]
```

Add a paragraph to that golden's `README.md`, under the adjudication log,
stating that rejections now live in `rejections.json`, that the file is
append-only and human-written exactly like `matches.json`, and that the
four-character token floor means these two pairs would no longer be raised in
the first place — the file is kept because the floor is a heuristic and the
adjudication is a fact.

- [ ] **Step 7: Close the "too sparse" half of Stage 0 finding #3**

Finding #3 names three omitted addresses: `REF-11` omits
`0x0E08D9FC-0x0E08D9FE` and `0x0E08D9E8-0x0E08D9F8`; `REF-13` omits SRAM
`0x2000BE34`.

Read them from the source report — `~/Documents/Offsec/Opswat/Devices/tplink/findings.txt`,
section `# CRITICAL (19)` — **read-only**. Confirm each address against the
entry that cites it before adding it to that reference's `locations` array in
`reference.json`. Then, for every one of the 19 entries, check its `locations`
against the addresses its source entry cites and add any that are missing.

Two hard rules:

- **Adding a location can only create candidates, never matches.** Nothing in
  `matches.json` changes. Re-run `bench` afterwards and confirm recall is
  still 9/19.
- **If an address in the source report is ambiguous, leave it out and say so**
  in the README rather than guessing. A wrong location token is worse than a
  missing one: it produces a candidate that costs an adjudication.

Record what you added, per reference id, in the golden's README.

- [ ] **Step 8: Re-run the real benchmark and confirm the baseline is unmoved**

```bash
python3 audit.py bench \
  --golden tests/goldens/tplink-dl110v2-1.0.11 \
  --db ~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db \
  --cost 658.37
```

Expected: `recall 9/19 (47.4%)`, `findings 45`, `cost per matched finding
$73.15`. The candidate list should be **shorter** than before (the `tss` pairs
are gone twice over) and must contain no pair that `rejections.json` holds.

If recall moved, stop. Nothing in this task may change recall: the scorer's
match path was not touched, only candidate generation. A moved number means
`reference.json` was edited in a way that altered an adjudicated pair.

- [ ] **Step 9: Write the gate procedure**

Create `docs/baselines/2026-10-05-stage2-gate.md`:

- **The gate, verbatim from spec §7:** "tplink re-run twice — cost must fall
  and recall must be ≥ 9/19." Note that the figure reads 9 rather than the
  spec's 8 after the REF-19 adjudication, and that §6.1's rule governs:
  **no change merges if recall drops; cost targets are subordinate.**
- **What "cost must fall" is measured against:** $658.37, 224.2M Σ context,
  843 billed turns, 265,897 mean context, g 2,573 tok/turn, 7 epochs — the
  figures in `docs/baselines/2026-10-05-tplink-baseline.md`, against a
  transcript pinned at 15,608,662 bytes / sha256 `a33f2f52…`.
- **Why two runs:** §6.1's non-determinism limitation. A one-finding delta is
  noise. Both runs are recorded; the gate is judged on the pair, not the
  better one.
- **The exact commands** for each run: `preflight`, the strict relaunch,
  `init`, the phases, then `budget --project`, `bench`, `coverage` and
  `status` for the record.
- **The deterministic leading indicators** to record alongside, from §6.1,
  since they do not need a second run to be meaningful: coverage percentage,
  surfaces opened, sweep hit counts, `not_audited` row count, and the measured
  linearity deviation from Task 5.
- **What to do if cost falls and recall falls with it:** §5.3 — "If cost falls
  and recall falls with it, the design has failed." The stage does not merge.
- **An explicit statement that this gate has not been run.** Stage 2's code
  can be complete and merged for review while the gate remains open; what must
  not happen is the gate being reported as passed because the unit tests are
  green. Name the two standing verification gaps from Stage 1 in the same
  paragraph — `install.ps1` has still never been executed, and `preflight`
  output has still never been handed to a client that connected a real MCP
  server — so the open list is in one place.

- [ ] **Step 10: Run the full suite and lint**

Run: `python3 -m pytest -q`
Expected: all pass, output pristine.

Run: `python3 audit.py lint-skill && python3 audit.py selftest`
Expected: both exit 0.

- [ ] **Step 11: Commit**

```bash
git add audit_core/goldens.py audit_core/bench.py audit.py \
  tests/test_bench.py tests/test_goldens.py tests/goldens docs/baselines
git commit -m "feat: the scorer remembers rejections and matches whole tokens

Stage 2's gate re-runs tplink twice, which under the old scorer meant
adjudicating the same false pairs twice. rejections.json closes Stage 0's
finding #2: adjudicated non-matches are recorded beside adjudicated matches,
human-written and append-only, and each one must carry a reason - a rejection
without one is indistinguishable from a mistake and silences a candidate
permanently.

Candidate generation now intersects whole tokens of four or more characters
instead of testing substring containment, closing the 'too coarse' half of
finding #3. The bare token `tss` no longer matches TssRSASecretKey; REF-14's
bare `test` can no longer pair with every location containing `latest` or
`attestation`. Adjudicated matches are untouched - they are matches, not
candidates - and recall is still 9/19 against the pinned run.

The gate procedure is written down, including the fact that it has not been
run, so that a green unit-test suite cannot be mistaken for a passed gate."
```

---

## What Stage 2 deliberately does not do

Named here so a reviewer does not read an absence as an oversight, and so the
later stages inherit a clean list.

| Not done | Where it lands | Why not here |
|---|---|---|
| The `Tools/audit-suite/` monorepo restructure | Stage 4 | Ruling S1. A monorepo with one skill invalidates every install path for no benchmark benefit. |
| The IDA / `mcp__autorev__*` extract backend | Stage 4 | Ruling S2. The `Backend` protocol is the Stage 2 commitment; a stdlib process cannot call agent-side MCP tools. |
| Spec §3.4's eleven unprefixed tables | Stage 4 | Ruling S4. That is `firmware-audit`'s schema. |
| Gating a run on coverage, or sweeping automatically on every confirmed finding | Stage 3 | Ruling S3, and spec §7 — each quality addition is benchmarked alone so a recall movement can be attributed. |
| The pivot rule, identity discipline, chain composition | Stage 3 | Spec §7. |
| Sonnet tiering for `surface`, L-sink and `fpcheck` | Stage 3, last and alone | Spec §7 and §8 — the one tiering change that can cost quality, precision-gated. |
| Severity-agreement scoring in `bench` | Stage 3 | Stage 0 finding #1. It needs the re-rating step to have something to score. |
| Running the Stage 2 gate | After this plan merges | The gate is two full tplink runs. Task 9 writes the procedure and states explicitly that it has not been run. |
| Executing `install.ps1` | Standing gap | No PowerShell on this machine. Carried from Stage 1 and restated in Task 9's gate doc. |
| Handing `preflight` output to a client that connects a real MCP server | Standing gap | Carried from Stage 1 and restated in Task 9's gate doc. |

---

## Self-Review

Run against the spec with fresh eyes after the plan was complete.

**1. Spec coverage.**

| Spec requirement | Task |
|---|---|
| §7 Stage 2: `audit_core` db | 1 |
| §7 Stage 2: `audit_core` coverage | 2 |
| §7 Stage 2: `audit_core` extract | 3 |
| §7 Stage 2: `audit_core` annotations | 4 |
| §7 Stage 2: `audit_core` budget | 5 (extends the Stage 0 module; `ceiling.py` is the R3 half) |
| §7 Stage 2: `audit_core` sweep | 6 |
| §7 Stage 2: R1 | 3 (mechanism) + 7 (shipped rule) |
| §7 Stage 2: R3 | 5 (mechanism) + 7 (shipped rule) |
| §7 Stage 2: vendored into `codebase-audit`, phase semantics unchanged | 7 (replacement not rewrite) + 8 (installer) |
| §7 Stage 2: benchmark-gated | 9 |
| §3.5 pivot rule | **Stage 3** — listed above |
| §3.5 sweep-on-confirm | 6 (engine) + **Stage 3** (trigger) |
| §3.5 coverage as a denominator | 2 (mechanism) + **Stage 3** (gate) |
| §6.2 one-IDA-writer, `assert_database` at every batch boundary → unit test | 3, Step 1 |
| §6.2 annotation journal as source of truth → schema test | 4 |
| §6.2 dedup by root cause → unit test | 1 |
| §6.2 resume-note discipline → phase-exit assertion | 5 (`checkpoint` refuses a missing note) + 7 |
| §5.3 measurement: measured `g`, cost per rung-4 finding | 5, 9 |

**Gap found and closed during review:** §6.2's resume-note row had no owner.
It is now `cmd_checkpoint` refusing to record a checkpoint whose
`--resume-note` path does not exist — the phase-exit assertion the spec asks
for, in the one place a phase actually exits.

**Gap found and left open deliberately:** §6.2's remaining rows — the 18 Hard
Exclusions moving to `core/fp-rules.md`, the evidence ladder moving to
`core/evidence-ladder.md`, the report lint — all require the `core/` directory
that ruling S1 defers to Stage 4. They are *already present and guard-tested*
in `references/` from Stage 1; Stage 2 moves none of them, which is why
nothing in this plan can lose them.

**2. Placeholder scan.** Run over the finished plan: no `TBD`, `TODO`,
"implement later", "add appropriate error handling", "handle edge cases", or
"similar to Task N". Every code step carries the code. Every test step carries
the assertions.

**3. Type consistency.** Checked across tasks:
- `db.TABLE_SPECS` is written in Task 1, extended in Task 2 (five entries) and
  Task 6 (one validator). Same dict, same `TableSpec` shape.
- `db.DbError` is raised by `coverage`'s validator (Task 2), `sweep.record`
  (Task 6) and every CLI handler. One exception type.
- `text.location_tokens` has exactly two consumers: `db.duplicates` (Task 1)
  and `bench.score` (Task 9). Same signature, same four-character floor.
- `_open_db` and `_parse_set` are defined once in Task 1 and reused by Tasks
  2, 5 and 6's handlers.
- `ceiling.project` takes `(prefix: int, growth_per_turn: float)`; both
  callers — `cmd_budget --project` and `cmd_checkpoint` — pass
  `stats.prefix_floor` and `stats.growth_per_turn`, which are `int` and
  `float` on `budget.Stats`.
- `sweep.run(...)` returns `SweepResult`; `sweep.record` and `sweep.render`
  both take exactly that.
- `goldens.load_rejections` returns `set[tuple[str, str]]`; `bench.score`
  declares the parameter as `frozenset[tuple[str, str]]` and only ever tests
  membership, so a `set` is accepted. The CLI passes the `set` directly.

**4. Review Focus.** Each of the five has its test in the task that owns the
code: 1 → Task 3 Step 1 and Step 9's explicit run; 2 → Task 4 Step 1 and
Step 7; 3 → Task 6 Step 1 and Step 8; 4 → Task 1 Step 5 and Step 11;
5 → Task 2 Step 1 and Step 8. None was added as an afterthought to a task that
did not already touch that code.

---

## Execution Notes

**Order matters.** Tasks 1 → 2 → 3 → 4 → 5 → 6 are a dependency chain only at
two points: Task 2 extends Task 1's `TABLE_SPECS`, and Task 6 attaches a
validator to a spec Task 2 wrote. Tasks 3, 4 and 5 touch no shared file except
`audit.py`'s `HANDLERS` dict and `build_parser`, so they must still be run
serially to avoid conflicts, but a reviewer can reject one without affecting
its neighbours. Task 7 depends on all of 1-6 (it documents their verbs). Tasks
8 and 9 depend on 7 and 1 respectively.

**Task 7 is the one to slow down on.** It is the only task that edits prose a
user already has installed, and Stage 1's evidence is that prose edits lose
things that five reviews will not all catch. Its derivation artifact is
written *before* the edits, and Step 9 checks the artifact against the diff
rather than the diff against anyone's memory.

**Commits.** End every commit message with:

```
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
```

**After every task:** `python3 -m pytest -q` must be green and the output
pristine. After Tasks 7 and 8: `python3 audit.py lint-skill` and
`python3 audit.py selftest` must both exit 0.

**Never run `install.sh` or `install.ps1` without overriding `HOME`,
`CLAUDE_CONFIG_DIR` and `CODEX_HOME`.** The user's working installation at
`~/.claude/skills/codebase-audit/` is not a test fixture.
