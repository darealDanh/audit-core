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
