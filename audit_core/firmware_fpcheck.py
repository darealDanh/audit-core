"""Prepare immutable firmware review assignments from a verified completed hunt."""
from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import sqlite3

from audit_core import db, hunt, surface


class FpcheckError(Exception):
    """Firmware review provenance or publication cannot be established."""


@dataclasses.dataclass(frozen=True, slots=True)
class BatchDescriptor:
    path: str
    sha256: str
    candidate_count: int


@dataclasses.dataclass(frozen=True, slots=True)
class PreparationSummary:
    image_id: str
    manifest_sha256: str
    surface_snapshot_sha256: str
    candidate_snapshot_sha256: str
    generation: str
    worklist_path: str
    worklist_sha256: str
    candidate_count: int
    batch_count: int


def _identity(snapshot: hunt.VerifiedHuntSnapshot) -> dict[str, object]:
    lanes = {row.lane: row.worklist_sha256 for row in snapshot.lanes}
    return {"schema_version": 1, "image_id": snapshot.image_id,
            "manifest_sha256": snapshot.manifest_sha256,
            "surface_snapshot_sha256": snapshot.surface_snapshot_sha256,
            "sink_worklist_sha256": lanes["l-sink"], "dark_worklist_sha256": lanes["l-dark"]}


def _candidate_snapshot(snapshot: hunt.VerifiedHuntSnapshot) -> bytes:
    """Preserve all verified evidence, ordered by the lane-qualified identity."""
    rows = sorted(snapshot.candidates, key=lambda row: (row.lane, row.candidate_id))
    return surface.canonical_bytes(_identity(snapshot) | {
        "candidates": [dataclasses.asdict(row) for row in rows]})


def _signature(image_id: str, candidate: hunt.VerifiedHuntCandidate) -> str:
    """Priority hint only: equality assigns a reviewer, never merges findings."""
    def normalize(value: str) -> str:
        return " ".join(value.casefold().split())

    fields = ("component_path", "bug_class", "dangerous_operation", "input_evidence",
              "data_flow", "operation_evidence")
    projection = {field: normalize(getattr(candidate, field)) for field in fields}
    projection.update(image_id=image_id, surface_ids=sorted({normalize(value) for value in candidate.surface_ids}))
    return hashlib.sha256(surface.canonical_bytes(projection)).hexdigest()


def _worklist(snapshot: hunt.VerifiedHuntSnapshot, batch_size: int) -> tuple[dict[str, bytes], str]:
    identity = _identity(snapshot) | {
        "candidate_snapshot_sha256": hashlib.sha256(_candidate_snapshot(snapshot)).hexdigest()}
    clusters: dict[str, list[dict[str, object]]] = {}
    for candidate in sorted(snapshot.candidates, key=lambda row: (row.lane, row.candidate_id)):
        signature = _signature(snapshot.image_id, candidate)
        clusters.setdefault(signature, []).append(dataclasses.asdict(candidate) | {"similarity_signature": signature})
    assignments: list[list[dict[str, object]]] = []
    pending: list[dict[str, object]] = []
    for signature in sorted(clusters):
        cluster = clusters[signature]
        if len(cluster) > 1000:
            raise FpcheckError("A firmware review cluster cannot exceed 1,000 candidates")
        if pending and len(pending) + len(cluster) > batch_size:
            assignments.append(pending)
            pending = []
        pending.extend(cluster)
    if pending or not assignments:
        assignments.append(pending)
    files = {}
    descriptors = []
    for number, assigned in enumerate(assignments, 1):
        if len(assigned) > 1000:
            raise FpcheckError("A firmware review batch cannot exceed 1,000 candidates")
        batch_id = f"batch-{number:04}"
        content = surface.canonical_bytes(identity | {"batch_id": batch_id, "candidates": assigned})
        name = batch_id + ".json"
        files[name] = content
        descriptors.append(dataclasses.asdict(BatchDescriptor(name, hashlib.sha256(content).hexdigest(), len(assigned))))
    files["index.json"] = surface.canonical_bytes(identity | {"batch_size": batch_size,
        "candidate_count": len(snapshot.candidates), "batches": descriptors})
    return files, hashlib.sha256(files["index.json"]).hexdigest()


def invalidate(con: sqlite3.Connection, image_id: str, *, commit: bool = False) -> None:
    """Delete exactly one image's Stage 4f state in the caller's transaction."""
    for table in ("cba_firmware_findings", "cba_firmware_pivots", "cba_firmware_fp_verdicts",
                  "cba_firmware_fp_receipts", "cba_firmware_fp_runs"):
        con.execute(f"DELETE FROM {table} WHERE image_id=?", (image_id,))
    if commit:
        con.commit()


def _checked_install(destination: pathlib.Path, files: dict[str, bytes]) -> None:
    """Re-read the whole installed generation while holding the publication lock."""
    for directory in (destination, *tuple(destination.parents)[:3]):
        if directory.is_symlink() or not directory.is_dir():
            raise FpcheckError("Invalid installed firmware review worklist directory")
    if {path.name for path in destination.iterdir()} != set(files):
        raise FpcheckError("Installed firmware review generation has different artifacts")
    for name, expected in files.items():
        path = destination / name
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise FpcheckError("Installed firmware review worklist differs before publication")


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
            *, image_id: str | None = None, batch_size: int = 20) -> PreparationSummary:
    """Install all assignments, reverify hunt/root under lock, publish one pending run."""
    started = False
    try:
        if con.in_transaction:
            raise FpcheckError("Preparation requires a connection without an active transaction")
        if type(batch_size) is not int or not 1 <= batch_size <= 200:
            raise FpcheckError("batch_size must be an integer from 1 to 200")
        run_dir = pathlib.Path(run_dir).absolute()
        snapshot = hunt.verified_snapshot(con, run_dir, root, image_id=image_id)
        prior = surface._query(con, "SELECT * FROM cba_firmware_fp_runs WHERE image_id=?", (snapshot.image_id,))
        files, digest = _worklist(snapshot, batch_size)
        # The index binds the snapshot AND assignment policy; changing batch size
        # cannot collide with a previously installed immutable generation.
        destination = run_dir / "files/firmware-fpcheck" / digest
        index = _identity(snapshot)
        summary = PreparationSummary(snapshot.image_id, snapshot.manifest_sha256, snapshot.surface_snapshot_sha256,
            hashlib.sha256(_candidate_snapshot(snapshot)).hexdigest(), digest, str(destination / "index.json"),
            digest, len(snapshot.candidates), len(files) - 1)
        record = {key: value for key, value in dataclasses.asdict(summary).items() if key != "generation"}
        record.update(sink_worklist_sha256=index["sink_worklist_sha256"], dark_worklist_sha256=index["dark_worklist_sha256"])
        same = len(prior) == 1 and all(prior[0][key] == value for key, value in record.items())
        for directory in tuple(destination.parents)[:3]:
            if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                raise FpcheckError("Invalid firmware review installation parent")
        surface.atomic_install(destination, files)
        con.execute("BEGIN IMMEDIATE")
        started = True
        if (hunt.verified_snapshot(con, run_dir, root, image_id=image_id) != snapshot or
                surface._query(con, "SELECT * FROM cba_firmware_fp_runs WHERE image_id=?", (snapshot.image_id,)) != prior):
            raise FpcheckError("Firmware review inputs changed before publication")
        _checked_install(destination, files)
        if not same:
            invalidate(con, snapshot.image_id)
            db.put(con, "cba_firmware_fp_runs", record | {"status": "pending"}, commit=False)
        con.commit()
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, OSError, db.DbError, hunt.HuntError, surface.SurfaceError)):
            raise FpcheckError(f"Cannot prepare firmware review: {exc}") from exc
        raise
