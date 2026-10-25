"""Freeze complete reviewed firmware evidence for one global chain review."""
from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import sqlite3

from audit_core import db, firmware_fpcheck, surface


class FirmwareChainError(Exception):
    """Firmware chain provenance or publication cannot be established."""


@dataclasses.dataclass(frozen=True, slots=True)
class PreparationSummary:
    image_id: str
    manifest_sha256: str
    surface_snapshot_sha256: str
    candidate_snapshot_sha256: str
    generation: str
    worklist_path: str
    worklist_sha256: str
    finding_count: int
    surface_count: int
    unknown_count: int
    pivot_count: int


def _worklist(snapshot: firmware_fpcheck.VerifiedFirmwareFindingsSnapshot) -> bytes:
    """Preserve the complete verified input with context-only pivots, without caps."""
    projection = dataclasses.asdict(snapshot)
    projection["schema_version"] = 1
    for collection, identifier in (("findings", "finding_id"), ("surfaces", "surface_id"),
                                   ("unknowns", "id"), ("pivots", "pivot_id")):
        projection[collection] = sorted(projection[collection], key=lambda row: row[identifier])
    projection["pivots"] = [row | {"context_only": True} for row in projection["pivots"]]
    return surface.canonical_bytes(projection)


def invalidate(con: sqlite3.Connection, image_id: str, *, commit: bool = False) -> None:
    """Delete exactly one image's six Stage 4g tables in dependency order."""
    for table in ("cba_firmware_chain_edges", "cba_firmware_chains", "cba_firmware_chain_dispositions",
                  "cba_firmware_chain_unknowns", "cba_firmware_chain_receipts", "cba_firmware_chain_runs"):
        con.execute(f"DELETE FROM {table} WHERE image_id=?", (image_id,))
    if commit:
        con.commit()


def _installation_parents(destination: pathlib.Path) -> None:
    """Reject redirected or non-directory generation parents before any install."""
    for directory in tuple(destination.parents)[:3]:
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise FirmwareChainError("Invalid firmware chain installation parent")


def _checked_install(destination: pathlib.Path, content: bytes) -> None:
    """Re-read installed bytes and directory ownership under the publication lock."""
    _installation_parents(destination)
    if destination.is_symlink() or not destination.is_dir():
        raise FirmwareChainError("Invalid installed firmware chain worklist directory")
    if {path.name for path in destination.iterdir()} != {"worklist.json"}:
        raise FirmwareChainError("Installed firmware chain generation has different artifacts")
    path = destination / "worklist.json"
    if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
        raise FirmwareChainError("Installed firmware chain worklist differs before publication")


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
            *, image_id: str | None = None) -> PreparationSummary:
    """Install one global worklist, then lock and reverify before pending publication.

    Byte-identical preparation retains all imported/completed state and timestamps.
    Artifact publication precedes SQL: a failed transaction can leave only an
    unreferenced immutable worklist, never a partially replaced selected image.
    """
    started = False
    try:
        if con.in_transaction:
            raise FirmwareChainError("Preparation requires a connection without an active transaction")
        run_dir = pathlib.Path(run_dir).absolute()
        snapshot = firmware_fpcheck.verified_findings_snapshot(con, run_dir, root, image_id=image_id)
        prior = surface._query(con, "SELECT * FROM cba_firmware_chain_runs WHERE image_id=?", (snapshot.image_id,))
        content = _worklist(snapshot)
        digest = hashlib.sha256(content).hexdigest()
        destination = run_dir / "files/firmware-chain" / digest
        summary = PreparationSummary(snapshot.image_id, snapshot.manifest_sha256, snapshot.surface_snapshot_sha256,
            snapshot.candidate_snapshot_sha256, digest, str(destination / "worklist.json"), digest,
            len(snapshot.findings), len(snapshot.surfaces), len(snapshot.unknowns), len(snapshot.pivots))
        record = {key: value for key, value in dataclasses.asdict(summary).items() if key != "generation"}
        record.update(fpcheck_artifact_path=str(run_dir / snapshot.findings_artifact_path),
                      fpcheck_artifact_sha256=snapshot.findings_artifact_sha256)
        same = len(prior) == 1 and all(prior[0][key] == value for key, value in record.items())
        _installation_parents(destination)
        surface.atomic_install(destination, {"worklist.json": content})
        con.execute("BEGIN IMMEDIATE")
        started = True
        if (firmware_fpcheck.verified_findings_snapshot(con, run_dir, root, image_id=image_id) != snapshot or
                surface._query(con, "SELECT * FROM cba_firmware_chain_runs WHERE image_id=?", (snapshot.image_id,)) != prior):
            raise FirmwareChainError("Firmware chain inputs changed before publication")
        _checked_install(destination, content)
        if not same:
            invalidate(con, snapshot.image_id)
            db.put(con, "cba_firmware_chain_runs", record | {"status": "pending"}, commit=False)
        con.commit()
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, db.DbError)):
            raise FirmwareChainError("database operation failed") from exc
        if isinstance(exc, (OSError, firmware_fpcheck.FpcheckError, surface.SurfaceError)):
            raise FirmwareChainError(f"Cannot prepare firmware chain: {exc}") from exc
        raise
