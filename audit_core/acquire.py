"""Record local firmware image provenance without fetching or copying it."""
from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import sqlite3

from audit_core import db

CHUNK_SIZE = 1024 * 1024


class AcquireError(Exception):
    """The requested image cannot be recorded from the local filesystem."""


@dataclasses.dataclass(frozen=True, slots=True)
class ImageRecord:
    id: str
    path: str
    sha256: str
    size: int


def record(con: sqlite3.Connection, *, vendor: str, model: str, version: str,
           role: str, path: str | pathlib.Path, source: str,
           replace: bool = False) -> ImageRecord:
    if con.in_transaction:
        raise AcquireError("Acquire requires a connection without an active transaction")
    image = pathlib.Path(path)
    if not image.is_file():
        raise AcquireError(f"{image} is not a regular readable file")
    digest = hashlib.sha256()
    try:
        with image.open("rb") as handle:
            while chunk := handle.read(CHUNK_SIZE):
                digest.update(chunk)
        size = image.stat().st_size
    except OSError as exc:
        raise AcquireError(f"{image} is not a regular readable file: {exc}") from exc

    normalized_vendor = vendor.strip().lower()
    normalized_model = model.strip().lower()
    image_id = f"{normalized_vendor}|{normalized_model}|{role}"
    row = {
        "id": image_id,
        "vendor": normalized_vendor,
        "model": normalized_model,
        "version": version.strip(),
        "role": role,
        "path": str(image),
        "sha256": digest.hexdigest(),
        "size": str(size),
    }
    if source.strip():
        row["source"] = source.strip()
    try:
        con.execute("BEGIN")
        previous = con.execute("SELECT sha256, version FROM cba_images WHERE id = ?",
                               (image_id,)).fetchone()
        db.put(con, "cba_images", row, replace=replace, commit=False)
        if previous is not None and (previous["sha256"] != row["sha256"] or
                                     previous["version"] != row["version"]):
            # A manifest belongs to the acquired provenance. Preserve other
            # scopes and the shared coverage inventory, but require retriage.
            con.execute("DELETE FROM cba_firmware_files WHERE image_id = ?", (image_id,))
        con.commit()
    except Exception:
        con.rollback()
        raise
    return ImageRecord(id=image_id, path=str(image), sha256=digest.hexdigest(), size=size)
