"""Compare image-scoped firmware manifests by exact path and content hash."""
from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping
from typing import cast


class FirmwareDiffError(Exception):
    """Firmware manifests cannot be compared without misleading output."""


@dataclasses.dataclass(frozen=True, slots=True)
class DiffEntry:
    path: str
    change: str
    reference_kind: str | None
    target_kind: str | None
    reference_size: int | None
    target_size: int | None
    reference_sha256: str | None
    target_sha256: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class Comparison:
    entries: tuple[DiffEntry, ...]
    added_count: int
    removed_count: int
    modified_count: int
    unchanged_count: int


def _by_path(rows: Iterable[Mapping[str, object]],
             side: str) -> dict[str, Mapping[str, object]]:
    files: dict[str, Mapping[str, object]] = {}
    for row in rows:
        path = cast(str, row["path"])
        if path in files:
            raise FirmwareDiffError(f"Duplicate {side} manifest path: {path}")
        files[path] = row
    return files


def compare(reference: Iterable[Mapping[str, object]],
            target: Iterable[Mapping[str, object]]) -> Comparison:
    """Return changed paths in Python string order and counts for all paths.

    Inputs contain manifest rows with path, kind, size, and sha256 fields.
    Kind and size are retained as evidence; only SHA-256 determines equality.
    """
    reference_files = _by_path(reference, "reference")
    target_files = _by_path(target, "target")
    entries: list[DiffEntry] = []
    added = removed = modified = unchanged = 0
    for path in sorted(reference_files.keys() | target_files.keys()):
        before = reference_files.get(path)
        after = target_files.get(path)
        if before is None:
            change = "added"
            added += 1
        elif after is None:
            change = "removed"
            removed += 1
        elif before["sha256"] != after["sha256"]:
            change = "modified"
            modified += 1
        else:
            unchanged += 1
            continue
        entries.append(DiffEntry(
            path=path,
            change=change,
            reference_kind=cast(str, before["kind"]) if before is not None else None,
            target_kind=cast(str, after["kind"]) if after is not None else None,
            reference_size=cast(int, before["size"]) if before is not None else None,
            target_size=cast(int, after["size"]) if after is not None else None,
            reference_sha256=cast(str, before["sha256"]) if before is not None else None,
            target_sha256=cast(str, after["sha256"]) if after is not None else None,
        ))
    return Comparison(tuple(entries), added, removed, modified, unchanged)
