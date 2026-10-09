"""Turn an already-carved root filesystem into durable audit inventory."""
from __future__ import annotations

import dataclasses
import hashlib
import os
import pathlib
import re
import sqlite3
import stat

from audit_core import db, elf


class TriageError(Exception):
    """The carved tree cannot be inventoried without misleading output."""


@dataclasses.dataclass(frozen=True, slots=True)
class TriageSummary:
    inventory_count: int
    elf_count: int
    service_count: int


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_files(root: pathlib.Path) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        names[:] = sorted(
            name for name in names
            if not (pathlib.Path(directory) / name).is_symlink())
        for name in sorted(filenames):
            path = pathlib.Path(directory) / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode):
                files.append(path)
    return files


def _kind(path: pathlib.Path, relative: str,
          facts: elf.ElfFacts | None) -> str:
    if facts is not None:
        return "binary"
    try:
        with path.open("rb") as handle:
            shebang = handle.read(2) == b"#!"
    except OSError:
        shebang = False
    if shebang:
        return "script"
    if relative == "etc" or relative.startswith("etc/"):
        return "config"
    return "file"


_ABSOLUTE_EXEC = re.compile(r"(?<![A-Za-z0-9_.-])(/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)")


def _boot_sources(root: pathlib.Path) -> list[pathlib.Path]:
    candidates: list[pathlib.Path] = []
    for directory in (root / "etc/init.d", root / "etc/rc.d"):
        if directory.is_dir():
            candidates.extend(
                path for path in directory.iterdir()
                if path.is_file() and not path.is_symlink())
    for path in (root / "etc/inittab", root / "etc/rc.local"):
        if path.is_file() and not path.is_symlink():
            candidates.append(path)
    return sorted(candidates, key=lambda path: path.relative_to(root).as_posix())


def _services(root: pathlib.Path) -> list[dict[str, str]]:
    root_resolved = root.resolve()
    found: dict[str, dict[str, str]] = {}
    for source in _boot_sources(root):
        try:
            lines = source.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for raw_line in lines:
            evidence = raw_line.strip()
            if not evidence or evidence.startswith("#"):
                continue
            match = _ABSOLUTE_EXEC.search(evidence)
            if match is None:
                continue
            claimed = match.group(1)
            executable = (root_resolved / claimed.lstrip("/")).resolve()
            if not executable.is_relative_to(root_resolved) or not executable.is_file():
                continue
            name = executable.name
            if name in found:
                continue
            found[name] = {
                "name": name,
                "start_source": source.relative_to(root).as_posix(),
                "exec_path": executable.relative_to(root_resolved).as_posix(),
                "evidence": evidence,
            }
    return list(found.values())


def run(con: sqlite3.Connection, root: str | pathlib.Path, *,
        image_id: str | None = None,
        allow_no_elf: bool = False) -> TriageSummary:
    root_path = pathlib.Path(root)
    if not root_path.is_dir():
        raise TriageError(f"{root_path} is not a carved rootfs directory")
    if image_id is not None:
        found = db.rows(con, "cba_images", where={"id": image_id},
                        columns=("id",), limit=1)
        if not found:
            raise TriageError(f"image_id {image_id!r} is not recorded in cba_images")

    files = _regular_files(root_path)
    if not files:
        raise TriageError(f"{root_path} contains no regular files")
    discovered = [(path, elf.read(path)) for path in files]
    discovered_elfs = sum(facts is not None for _, facts in discovered)
    if discovered_elfs == 0 and not allow_no_elf:
        raise TriageError(f"{root_path} contains zero ELF binaries; pass "
                          "--allow-no-elf only for a confirmed non-ELF image")

    inventory_count = 0
    elf_count = 0
    for path, facts in discovered:
        relative = path.relative_to(root_path).as_posix()
        db.put(con, "cba_inventory", {
            "unit": relative,
            "kind": _kind(path, relative, facts),
            "size": str(path.stat().st_size),
        }, replace=True)
        inventory_count += 1
        if facts is None:
            continue
        row = {
            "path": relative,
            "machine": facts.machine,
            "bits": str(facts.bits),
            "endian": facts.endian,
            "elf_type": facts.elf_type,
            "needed": ",".join(facts.needed),
            "nx": facts.nx,
            "pie": facts.pie,
            "relro": facts.relro,
            "canary": facts.canary,
            "stripped": facts.stripped,
            "static": facts.static,
            "sha256": _sha256(path),
        }
        if image_id is not None:
            row["image_id"] = image_id
        if facts.interp is not None:
            row["interp"] = facts.interp
        if facts.runpath is not None:
            row["runpath"] = facts.runpath
        db.put(con, "cba_binfacts", row, replace=True)
        elf_count += 1
    services = _services(root_path)
    for service in services:
        if image_id is not None:
            service["image_id"] = image_id
        db.put(con, "cba_services", service, replace=True)
    return TriageSummary(inventory_count, elf_count, len(services))
