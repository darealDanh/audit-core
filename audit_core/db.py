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
import re
import sqlite3
from dataclasses import dataclass
from typing import Callable

from audit_core import text

MAX_ROWS = 200

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
VERDICTS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE", "NEEDS_VERIFICATION")
COVERAGE_STATES = ("analyzed", "not_audited")
NOT_AUDITED_REASONS = ("budget", "out-of-scope", "generated", "vendored",
                       "third-party", "unreachable", "binary-only")
INVENTORY_KINDS = ("file", "function", "endpoint", "binary")
CHECKPOINT_REASONS = ("phase-exit", "ceiling", "manual")
COMPONENT_KINDS = ("source-tree", "binary", "library", "firmware-image",
                   "service", "config")
CHAIN_COMPLETENESS = ("complete", "partial", "blocked")

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


def _validate_pattern(row: dict[str, str]) -> None:
    """Compile the regex before it is stored.

    A stored pattern that does not compile is a sweep that silently never
    runs, which is the worst possible outcome for a mechanism whose whole
    value is breadth.
    """
    try:
        re.compile(row["regex"])
    except re.error as exc:
        raise DbError(f"regex {row['regex']!r} does not compile: {exc}") from exc


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
                 "merged_into", "rule_applied", "refuting_mechanism",
                 "enabled_observation", "reviewed_at"),
        required=("finding_id", "verdict"),
        validate=one_of("verdict", VERDICTS)),
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
                 "swept_at", "hit_count", "created_at"),
        required=("id", "name", "regex"),
        validate=_validate_pattern),
    "cba_pattern_hits": TableSpec(
        columns=("id", "pattern_id", "path", "line", "excerpt", "triaged",
                 "swept_at"),
        required=("pattern_id", "path", "line")),
    "cba_checkpoints": TableSpec(
        columns=("id", "phase", "reason", "turns", "projected_context",
                 "resume_note", "recorded_at"),
        required=("phase", "reason"),
        validate=one_of("reason", CHECKPOINT_REASONS)),
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
}


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


def connect(db_path: str | pathlib.Path, *, read_only: bool = False) -> sqlite3.Connection:
    """Open a run's audit.db, or say exactly what is wrong with it.

    The missing-*file* case was already covered. The missing-*schema* case was
    not, and it is the normal upgrade path: a user upgrades an installed skill
    and the next phase of an in-flight audit opens a run directory created
    before these tables existed. Every verb that touched one answered with
    `sqlite3.OperationalError: no such table` and a raw traceback.

    The check is here rather than in each verb because every verb reaches the
    database through this function - except `bench`, which opens `cba_findings`
    read-only on its own and must keep working against exactly the old run
    directories this gate rejects.
    """
    path = pathlib.Path(db_path)
    if not path.is_file():
        raise DbError(f"no audit.db at {path}; run `audit.py init` first")
    if read_only:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    try:
        present = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
    except sqlite3.DatabaseError as exc:
        con.close()
        raise DbError(f"{path} is not a readable SQLite database: {exc}") from exc
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
