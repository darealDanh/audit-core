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
from audit_core import patterns

MAX_HITS = 500
MAX_FILE_BYTES = 2_000_000
EXCERPT_CHARS = 160
BINARY_SNIFF_BYTES = 8192
# `reports` is the audit's own run directory, and it is here for the same
# reason `build` is: it holds generated copies of files that are already in
# the tree. `audit.py extract` writes verbatim source snapshots under
# `reports/audit-<ts>/extract/`, and both `workflows/audit.md` and
# `references/phase4-deep-audit.md` tell the orchestrator to sweep with
# `--root .` from the project root. Reproduced on one real call site: two
# recorded hits in the audit's own extract copies.
#
# Sweeping it inflates `hit_count` - a gate-document leading indicator - puts
# non-source paths in the triage list, and on a real corpus pushes toward
# MAX_HITS, which trips `record`'s truncation refusal, which makes
# `patterns --gate` unclearable.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", "reports", ".mypy_cache", ".pytest_cache", ".tox",
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

    `max_hits` is clamped to MAX_HITS: a caller that raised it past the cap
    would get `truncated=False` on a sweep that stopped anyway, and
    `record`'s truncation refusal is the only thing standing between a
    partial hit list and a permanently-`swept_at` pattern.
    """
    rx = re.compile(regex)
    # Clamped, not trusted. `--max-hits 100000` left `truncated` False on a
    # sweep that stopped well short of the tree and defeated `record`'s
    # truncation refusal; `--max-hits -1` reached `itertools.islice` as a raw
    # ValueError traceback. The cap is the module's, not the caller's.
    max_hits = max(1, min(int(max_hits), MAX_HITS))
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


def render(result: SweepResult) -> str:
    """A bounded summary. R1 applies to this tool's own output: it says how
    to read the hits, it does not paste them."""
    out = [f"sweep {result.pattern_id or '(unrecorded)'}: {len(result.hits)} hit(s) "
           f"in {result.files_scanned} file(s)"]
    if result.files_skipped_binary or result.files_skipped_large:
        out.append(f"  skipped {result.files_skipped_binary} binary, "
                   f"{result.files_skipped_large} oversized file(s)")
    if result.truncated:
        out.append(f"  truncated at {len(result.hits)} hits - the pattern is "
                   f"too broad to triage as written. Narrow it, or sweep a "
                   f"subtree, before recording.")
    if result.pattern_id:
        out.append(f"  read them with `audit.py rows --table cba_pattern_hits "
                   f"--where pattern_id={result.pattern_id}`")
    out.append("  Hits are candidates for triage, never verdicts.")
    return "\n".join(out)
