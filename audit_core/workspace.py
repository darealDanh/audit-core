"""Create a codebase-audit run directory and apply its schema.

This replaces the CREATE TABLE blocks that were spread across four workflow
files and retyped by the orchestrator on every run. See spec rule R5.
"""
from __future__ import annotations

import datetime
import pathlib
import sqlite3

SUBDIRS = ("files", "artifacts", "archived-poc", "briefs")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent / "schema.sql"


def apply_schema(db_path: str | pathlib.Path) -> list[str]:
    """Apply schema.sql to db_path. Idempotent. Returns the table names present."""
    con = sqlite3.connect(pathlib.Path(db_path))
    try:
        con.executescript(SCHEMA_PATH.read_text())
        con.commit()
        rows = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    finally:
        con.close()
    return [r[0] for r in rows]


def init_run(root: str | pathlib.Path,
             timestamp: str | None = None) -> pathlib.Path:
    """Create reports/audit-<ts>/ under root, with its subdirs and audit.db."""
    if timestamp is None:
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d-%H%M%S")
    run = pathlib.Path(root) / "reports" / f"audit-{timestamp}"
    for sub in SUBDIRS:
        (run / sub).mkdir(parents=True, exist_ok=True)
    apply_schema(run / "audit.db")
    return run
