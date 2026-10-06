"""Create a codebase-audit run directory and apply its schema.

This replaces the CREATE TABLE blocks that were spread across four workflow
files and retyped by the orchestrator on every run. See spec rule R5.
"""
from __future__ import annotations

import datetime
import pathlib
import sqlite3
from dataclasses import dataclass

from audit_core import db

SUBDIRS = ("files", "artifacts", "archived-poc", "briefs")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent / "schema.sql"


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


def init_run(root: str | pathlib.Path,
             timestamp: str | None = None) -> pathlib.Path:
    """Create reports/audit-<ts>/ under root, with its subdirs and audit.db."""
    run, _ = _init_run_with_schema_result(root, timestamp)
    return run


def _init_run_with_schema_result(
        root: str | pathlib.Path,
        timestamp: str | None = None) -> tuple[pathlib.Path, SchemaResult]:
    """`init_run`'s own body, plus the `SchemaResult` it would otherwise
    discard.

    `apply_schema` (and the `migrate` it runs) is idempotent: calling it a
    second time to recover a report for the CLI would always see a database
    already caught up, and `migrated` would read empty even on a real
    upgrade. So `init_run` and `cmd_init` share this one application instead
    of each calling `apply_schema` on their own.
    """
    if timestamp is None:
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d-%H%M%S")
    run = pathlib.Path(root) / "reports" / f"audit-{timestamp}"
    for sub in SUBDIRS:
        (run / sub).mkdir(parents=True, exist_ok=True)
    result = apply_schema(run / "audit.db")
    return run, result
