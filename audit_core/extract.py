"""Extract once, fan out without a cap (spec R1).

This is the one rule where the cost argument and the quality argument are the
same argument. A shared stdio decompiler session cannot serve parallel
subagents, so work stayed serial and in the orchestrator's context: cost
exploded AND fan-out was capped, which is why surfaces went unopened.
Snapshotting the material to files once removes both at the same time.

The backend is an interface because *how* you extract is per-target - a source
tree is a copy, a stripped binary is a decompiler session, a flash dump is a
carve - while the discipline is not. The discipline lives here: assert the
backend is still the one writer at every batch boundary, and never write a
partial batch.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
import re
from dataclasses import asdict, dataclass
from typing import Iterable, Protocol

BATCH_SIZE = 25
MAX_UNIT_BYTES = 512_000
TRUNCATION_MARK = b"\n...truncated by audit.py extract at %d bytes...\n"

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ExtractError(Exception):
    """A name would escape the run directory, or a backend was not ready."""


class Backend(Protocol):
    name: str

    def assert_ready(self) -> None:
        """Raise if this process is no longer the sole writer of the source.

        grey-audit's `assert_database` at every batch boundary, generalized. A
        shared decompiler session clobbered by a parallel caller keeps
        answering - with another binary's data - so the batch written after
        that point is silently wrong.
        """

    def read(self, item: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class Record:
    unit: str
    name: str
    relpath: str
    source: str
    sha256: str
    bytes: int
    version: int
    truncated: bool
    backend: str
    extracted_at: str


def _safe(component: str, label: str) -> str:
    if not _SAFE.match(component):
        raise ExtractError(
            f"unsafe {label} {component!r}: must match {_SAFE.pattern}. "
            f"Flatten a path with extract.flatten() first.")
    return component


def flatten(path: str) -> str:
    """Flatten a source path into one safe snapshot filename.

    `src/handlers/klap.c` becomes `src_handlers_klap.c`: the snapshot tree is
    one directory per unit, so a reader finding a name knows the unit without
    walking, and a `..` in the input cannot survive the substitution.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/\\"))
    cleaned = cleaned.strip("._-")
    return cleaned or "unnamed"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class ExtractStore:
    """Snapshots under `<run>/extract/`, indexed by `<run>/extract/manifest.json`.

    The manifest is JSON on disk rather than a table because every downstream
    reader is a subagent with file access and no obligation to open the
    database, and because extraction legitimately runs before a run's db has
    anything else in it.
    """

    def __init__(self, run_dir: str | pathlib.Path):
        self.base = pathlib.Path(run_dir) / "extract"
        self.manifest_path = self.base / "manifest.json"

    def _load(self) -> dict[str, dict]:
        if not self.manifest_path.is_file():
            return {}
        try:
            raw = json.loads(self.manifest_path.read_text())
        except json.JSONDecodeError as exc:
            raise ExtractError(f"{self.manifest_path} is not valid JSON: {exc}") from exc
        return raw if isinstance(raw, dict) else {}

    def _save(self, index: dict[str, dict]) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(json.dumps(index, indent=2, sort_keys=True))

    def write(self, unit: str, name: str, data: bytes, *,
              source: str | None = None, backend: str = "source-tree") -> Record:
        _safe(unit, "unit name")
        _safe(name, "snapshot name")
        truncated = len(data) > MAX_UNIT_BYTES
        if truncated:
            data = data[:MAX_UNIT_BYTES] + (TRUNCATION_MARK % MAX_UNIT_BYTES)
        digest = hashlib.sha256(data).hexdigest()
        index = self._load()
        key = f"{unit}/{name}"
        prior = index.get(key)
        if prior is None:
            version = 1
        elif prior.get("sha256") == digest:
            version = int(prior.get("version", 1))
        else:
            version = int(prior.get("version", 1)) + 1
        target = self.base / unit / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        rec = Record(unit=unit, name=name, relpath=f"extract/{unit}/{name}",
                     source=source if source is not None else name,
                     sha256=digest, bytes=len(data), version=version,
                     truncated=truncated, backend=backend, extracted_at=_now())
        index[key] = asdict(rec)
        self._save(index)
        return rec

    def manifest(self) -> list[Record]:
        return [Record(**value) for _, value in sorted(self._load().items())]

    def items(self, unit: str) -> list[str]:
        """The source items already snapshotted for a unit, for `--refresh`."""
        return sorted(r.source for r in self.manifest() if r.unit == unit)


class SourceTree:
    """The `codebase-audit` backend: snapshot files out of a source checkout."""

    name = "source-tree"

    def __init__(self, root: str | pathlib.Path):
        self.root = pathlib.Path(root).resolve()

    def assert_ready(self) -> None:
        if not self.root.is_dir():
            raise ExtractError(f"source root is gone: {self.root}")

    def read(self, item: str) -> bytes:
        path = (self.root / item).resolve()
        if not path.is_relative_to(self.root):
            raise ExtractError(f"{item!r} escapes the source root {self.root}")
        return path.read_bytes()


def extract_batch(store: ExtractStore, backend: Backend, unit: str,
                  items: Iterable[str],
                  batch_size: int = BATCH_SIZE) -> list[Record]:
    """Snapshot `items`, asserting one-writer at every batch boundary.

    Every item of a batch is read before any of them is written, so a backend
    that fails mid-batch leaves no partial batch on disk. A caller re-running
    after a failure therefore sees whole batches or nothing, never half of one.
    """
    pending = list(items)
    out: list[Record] = []
    for start in range(0, len(pending), batch_size):
        chunk = pending[start:start + batch_size]
        index = start // batch_size
        try:
            backend.assert_ready()
        except Exception as exc:
            raise ExtractError(
                f"backend {backend.name!r} is not ready at batch {index} "
                f"(items {start}..{start + len(chunk) - 1}): {exc}") from exc
        staged = [(item, backend.read(item)) for item in chunk]
        for item, data in staged:
            out.append(store.write(unit, flatten(item), data,
                                   source=item, backend=backend.name))
    return out
