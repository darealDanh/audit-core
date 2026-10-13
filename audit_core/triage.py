"""Turn an already-carved root filesystem into durable audit inventory."""
from __future__ import annotations

import dataclasses
import hashlib
import os
import pathlib
import re
import shlex
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

    def traversal_error(exc: OSError) -> None:
        raise TriageError(f"Cannot traverse carved tree {root}: {exc}") from exc

    for directory, names, filenames in os.walk(
            root, followlinks=False, onerror=traversal_error):
        directories = []
        for name in sorted(names):
            path = pathlib.Path(directory) / name
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise TriageError(f"Cannot stat carved tree path {path}: {exc}") from exc
            if stat.S_ISDIR(mode):
                directories.append(name)
        names[:] = directories
        for name in sorted(filenames):
            path = pathlib.Path(directory) / name
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise TriageError(f"Cannot stat carved tree path {path}: {exc}") from exc
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


def _boot_sources(root: pathlib.Path,
                  regular_files: list[pathlib.Path] | None = None
                  ) -> list[pathlib.Path]:
    files = regular_files if regular_files is not None else _regular_files(root)
    candidates = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        if (relative in ("etc/inittab", "etc/rc.local") or
                relative.startswith("etc/init.d/") or
                relative.startswith("etc/rc.d/")):
            candidates.append(path)
    return sorted(candidates, key=lambda path: path.relative_to(root).as_posix())


_INITTAB_ACTIONS = {"askfirst", "once", "respawn", "sysinit", "wait"}
_STOP_WORDS = {"--stop", "-K", "kill", "killall", "stop"}


def _startup_command(evidence: str, relative_source: str) -> str | None:
    command = evidence
    if relative_source == "etc/inittab":
        fields = evidence.split(":", 3)
        if len(fields) != 4 or fields[2] not in _INITTAB_ACTIONS:
            return None
        command = fields[3]
    try:
        tokens = shlex.split(command, comments=True, posix=True)
    except ValueError:
        return None
    if not tokens or any(token in _STOP_WORDS for token in tokens):
        return None
    if tokens[0] in ("exec", "nohup"):
        tokens = tokens[1:]
    elif tokens[:2] == ["procd_set_param", "command"]:
        tokens = tokens[2:]
    elif tokens[0] == "start-stop-daemon":
        if not ({"--start", "-S"} & set(tokens)):
            return None
        for option in ("--exec", "-x"):
            if option in tokens and tokens.index(option) + 1 < len(tokens):
                return tokens[tokens.index(option) + 1]
        return None
    return tokens[0] if tokens and tokens[0].startswith("/") else None


def _services(root: pathlib.Path,
              regular_files: list[pathlib.Path] | None = None
              ) -> list[dict[str, str]]:
    root_resolved = root.resolve()
    found: dict[str, dict[str, str]] = {}
    for source in _boot_sources(root, regular_files):
        relative_source = source.relative_to(root).as_posix()
        try:
            lines = source.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for raw_line in lines:
            evidence = raw_line.strip()
            if not evidence or evidence.startswith("#"):
                continue
            claimed = _startup_command(evidence, relative_source)
            if claimed is None or _ABSOLUTE_EXEC.fullmatch(claimed) is None:
                continue
            executable = (root_resolved / claimed.lstrip("/")).resolve()
            if not executable.is_relative_to(root_resolved) or not executable.is_file():
                continue
            name = executable.name
            if name in found:
                continue
            found[name] = {
                "name": name,
                "start_source": relative_source,
                "exec_path": executable.relative_to(root_resolved).as_posix(),
                "evidence": evidence,
            }
    return list(found.values())


def run(con: sqlite3.Connection, root: str | pathlib.Path, *,
        image_id: str | None = None,
        allow_no_elf: bool = False) -> TriageSummary:
    if con.in_transaction:
        raise TriageError("Triage requires a connection without an active transaction")
    root_path = pathlib.Path(root)
    if not root_path.is_dir():
        raise TriageError(f"{root_path} is not a carved rootfs directory")
    effective_image_id = db.FIRMWARE_IMAGE_UNSCOPED
    mirror_inventory = True
    if image_id is not None:
        found = db.rows(con, "cba_images", where={"id": image_id},
                        columns=("id", "role"), limit=1)
        if not found:
            raise TriageError(f"image_id {image_id!r} is not recorded in cba_images")
        effective_image_id = image_id
        mirror_inventory = found[0]["role"] == "target"

    files = _regular_files(root_path)
    if not files:
        raise TriageError(f"{root_path} contains no regular files")
    discovered = [(path, elf.read(path)) for path in files]
    discovered_elfs = sum(facts is not None for _, facts in discovered)
    if discovered_elfs == 0 and not allow_no_elf:
        raise TriageError(f"{root_path} contains zero ELF binaries; pass "
                          "--allow-no-elf only for a confirmed non-ELF image")

    # Finish filesystem reads before the first write, so a failed hash cannot
    # leave an incomplete manifest. ELF facts reuse the one digest per file.
    prepared = []
    for path, facts in discovered:
        relative = path.relative_to(root_path).as_posix()
        prepared.append((facts, {
            "image_id": effective_image_id,
            "path": relative,
            "kind": _kind(path, relative, facts),
            "size": str(path.stat().st_size),
            "sha256": _sha256(path),
        }))
    services = _services(root_path, files)

    # Publish the complete prepared generation together, including coverage
    # mirrors. A write/commit failure must preserve any prior triage generation.
    try:
        con.execute("BEGIN")
        for facts, manifest in prepared:
            db.put(con, "cba_firmware_files", manifest, replace=True, commit=False)
            if mirror_inventory:
                db.put(con, "cba_inventory", {
                    "unit": manifest["path"],
                    "kind": manifest["kind"],
                    "size": manifest["size"],
                }, replace=True, commit=False)
            if facts is None:
                continue
            row = {
                "image_id": effective_image_id,
                "path": manifest["path"],
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
                "sha256": manifest["sha256"],
            }
            if facts.interp is not None:
                row["interp"] = facts.interp
            if facts.runpath is not None:
                row["runpath"] = facts.runpath
            db.put(con, "cba_binfacts", row, replace=True, commit=False)
        for service in services:
            service["image_id"] = effective_image_id
            db.put(con, "cba_services", service, replace=True, commit=False)
        con.commit()
    except Exception as exc:
        con.rollback()
        raise TriageError(f"Cannot publish triage for {effective_image_id}: {exc}") from exc
    return TriageSummary(len(files), discovered_elfs, len(services))
