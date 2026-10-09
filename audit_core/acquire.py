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
    db.put(con, "cba_images", row, replace=replace)
    return ImageRecord(id=image_id, path=str(image), sha256=digest.hexdigest(), size=size)
