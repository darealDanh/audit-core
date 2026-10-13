"""Compare image-scoped firmware manifests by exact path and content hash."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import sqlite3
import tempfile
from collections.abc import Iterable, Mapping
from typing import cast

from audit_core import db


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


@dataclasses.dataclass(frozen=True, slots=True)
class DiffSummary:
    id: str
    reference_image_id: str
    target_image_id: str
    added_count: int
    removed_count: int
    modified_count: int
    unchanged_count: int
    manifest_path: str


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


def _resolve_pair(con: sqlite3.Connection, target_image_id: str | None,
                  reference_image_id: str | None) -> tuple[sqlite3.Row, sqlite3.Row]:
    if (target_image_id is None) != (reference_image_id is None):
        raise FirmwareDiffError("Both target and reference image IDs are required together")
    if target_image_id is not None and target_image_id == reference_image_id:
        raise FirmwareDiffError("Reference and target image IDs must differ")
    images = []
    for image_id, role in ((reference_image_id, "diff-reference"),
                           (target_image_id, "target")):
        if image_id is None:
            candidates = con.execute("SELECT * FROM cba_images WHERE role = ?",
                                     (role,)).fetchall()
            if len(candidates) != 1:
                raise FirmwareDiffError(
                    f"Expected exactly one {role} image; found {len(candidates)}. "
                    "Supply both image IDs to select an explicit pair")
            image = candidates[0]
        else:
            image = con.execute("SELECT * FROM cba_images WHERE id = ?",
                                (image_id,)).fetchone()
            if image is None:
                raise FirmwareDiffError(f"Unknown {role} image ID: {image_id}")
            if image["role"] != role:
                raise FirmwareDiffError(f"Image {image_id} must have role {role}")
        if image["id"] == db.FIRMWARE_IMAGE_UNSCOPED:
            raise FirmwareDiffError("legacy-unscoped has no acquired-image provenance")
        images.append(image)
    reference, target = images
    for field in ("vendor", "model"):
        if reference[field].strip().lower() != target[field].strip().lower():
            raise FirmwareDiffError(f"Reference and target {field} must match")
    if reference["sha256"].lower() == target["sha256"].lower():
        raise FirmwareDiffError("Reference and target acquired-image hashes must differ")
    return reference, target


def _image_metadata(image: sqlite3.Row) -> dict[str, str]:
    return {field: image[field] for field in
            ("id", "vendor", "model", "version", "role", "sha256")}


def _install_manifest(run_dir: pathlib.Path, diff_id: str, content: bytes) -> str:
    digest = hashlib.sha256(content).hexdigest()[:16]
    destination = run_dir / "files" / f"{diff_id}-{digest}.json"
    temporary = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent,
                                         prefix=f".{diff_id}-", suffix=".tmp",
                                         delete=False) as stream:
            temporary = pathlib.Path(stream.name)
            stream.write(content)
        os.replace(temporary, destination)
    except OSError as exc:
        raise FirmwareDiffError(f"Cannot install diff manifest: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return str(destination)


def run(con: sqlite3.Connection, run_dir: str | pathlib.Path, *,
        target_image_id: str | None = None,
        reference_image_id: str | None = None,
        replace: bool = False) -> DiffSummary:
    """Compare stored manifests and atomically persist a bounded summary.

    The caller must supply an idle connection. No carved tree is reread.
    Install the content-addressed artifact before opening the SQL transaction;
    a failed write may leave an unreferenced generation but preserves any prior
    summary, entries, and referenced artifact.
    """
    if con.in_transaction:
        raise FirmwareDiffError("Diff requires a connection without an active transaction")
    reference, target = _resolve_pair(con, target_image_id, reference_image_id)
    manifests = []
    for image in (reference, target):
        rows = [dict(row) for row in con.execute(
            "SELECT path, kind, size, sha256 FROM cba_firmware_files "
            "WHERE image_id = ? ORDER BY path", (image["id"],))]
        if not rows:
            raise FirmwareDiffError(f"Image {image['id']} has an empty triage manifest")
        manifests.append(rows)
    diff_id = "diff-" + hashlib.sha256(
        f"{reference['id']}\0{target['id']}".encode("utf-8")).hexdigest()[:16]
    if not replace and con.execute("SELECT 1 FROM cba_diffs WHERE id = ?",
                                  (diff_id,)).fetchone() is not None:
        raise FirmwareDiffError(f"Diff {diff_id} already exists; pass --replace to overwrite")
    comparison = compare(*manifests)
    counts = {name: getattr(comparison, name) for name in
              ("added_count", "removed_count", "modified_count", "unchanged_count")}
    metadata = {"id": diff_id, "reference_image_id": reference["id"],
                "target_image_id": target["id"], **counts}
    entries = [dataclasses.asdict(entry) for entry in comparison.entries]
    artifact = {**metadata, "reference_image": _image_metadata(reference),
                "target_image": _image_metadata(target), "entries": entries}
    content = (json.dumps(artifact, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":")) + "\n").encode("utf-8")
    manifest_path = _install_manifest(pathlib.Path(run_dir), diff_id, content)
    summary = DiffSummary(**metadata, manifest_path=manifest_path)
    try:
        con.execute("BEGIN")
        if replace:
            con.execute("DELETE FROM cba_diff_entries WHERE diff_id = ?", (diff_id,))
        db.put(con, "cba_diffs", {key: str(value) for key, value in
                                 dataclasses.asdict(summary).items()},
               replace=replace, commit=False)
        for entry in entries:
            db.put(con, "cba_diff_entries", {
                "diff_id": diff_id,
                **{key: str(value) for key, value in entry.items() if value is not None},
            }, commit=False)
        con.commit()
    except Exception as exc:
        con.rollback()
        raise FirmwareDiffError(f"Cannot persist diff {diff_id}: {exc}") from exc
    return summary
