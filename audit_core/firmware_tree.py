"""Shared fail-closed inventory of an already-carved firmware tree."""
from __future__ import annotations

import dataclasses
import hashlib
import os
import pathlib
import stat

from audit_core import elf


class FirmwareTreeError(Exception):
    """The carved tree cannot be read without producing misleading facts."""


@dataclasses.dataclass(frozen=True, slots=True)
class FileFact:
    path: pathlib.Path
    relative: str
    kind: str
    size: int
    sha256: str
    elf: elf.ElfFacts | None


def _regular_files(root: pathlib.Path) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        directories = []
        try:
            # os.walk suppresses is_dir() errors and can omit a real subtree.
            with os.scandir(directory) as entries:
                for entry in sorted(entries, key=lambda entry: entry.name):
                    path = directory / entry.name
                    try:
                        is_directory = entry.is_dir(follow_symlinks=False)
                        mode = path.lstat().st_mode
                    except OSError as exc:
                        raise FirmwareTreeError(
                            f"Cannot classify carved tree path {path}: {exc}") from exc
                    if is_directory != stat.S_ISDIR(mode):
                        raise FirmwareTreeError(
                            f"Inconsistent directory classification for {path}")
                    if is_directory:
                        directories.append(path)
                    elif stat.S_ISREG(mode):
                        files.append(path)
        except OSError as exc:
            raise FirmwareTreeError(
                f"Cannot traverse carved tree {directory}: {exc}") from exc
        pending.extend(reversed(directories))
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())




def _kind(path: pathlib.Path, relative: str, facts: elf.ElfFacts | None) -> str:
    if facts is not None:
        return "binary"
    with path.open("rb") as handle:
        shebang = handle.read(2) == b"#!"
    if shebang:
        return "script"
    if relative == "etc" or relative.startswith("etc/"):
        return "config"
    return "file"


def scan(root: str | pathlib.Path) -> tuple[FileFact, ...]:
    """Return all regular-file facts in POSIX path order, or raise on I/O."""
    root_path = pathlib.Path(root)
    try:
        mode = root_path.lstat().st_mode
    except OSError as exc:
        raise FirmwareTreeError(
            f"Cannot stat carved rootfs directory {root_path}: {exc}") from exc
    if not stat.S_ISDIR(mode):
        raise FirmwareTreeError(f"{root_path} is not a carved rootfs directory")

    prepared = []
    for path in _regular_files(root_path):
        relative = path.relative_to(root_path).as_posix()
        try:
            sha256 = hashlib.sha256()
            facts = elf.read(path, strict_io=True, digest=sha256)
            kind = _kind(path, relative, facts)
            size = path.stat().st_size
            digest = sha256.hexdigest()
        except OSError as exc:
            raise FirmwareTreeError(
                f"Cannot read carved tree path {path}: {exc}") from exc
        prepared.append(FileFact(path, relative, kind, size, digest, facts))
    return tuple(prepared)
