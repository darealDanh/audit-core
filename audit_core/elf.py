"""Read bounded, useful facts from an ELF without external dependencies."""
from __future__ import annotations

import dataclasses
import pathlib
import struct

UNKNOWN = "unknown"
MAX_READ = 128 * 1024 * 1024
MAX_HEADERS = 65_536

MACHINES = {3: "i386", 8: "mips", 20: "ppc", 40: "arm", 62: "x86-64",
            183: "aarch64", 243: "riscv"}
ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


@dataclasses.dataclass(frozen=True, slots=True)
class ElfFacts:
    machine: str
    bits: int
    endian: str
    elf_type: str
    interp: str | None
    needed: tuple[str, ...]
    runpath: str | None
    nx: str
    pie: str
    relro: str
    canary: str
    stripped: str
    static: str


def _range(blob: bytes, offset: int, size: int) -> bytes | None:
    if offset < 0 or size < 0 or offset > len(blob) or size > len(blob) - offset:
        return None
    return blob[offset:offset + size]


def _cstring(blob: bytes, offset: int) -> str | None:
    if offset < 0 or offset >= len(blob):
        return None
    end = blob.find(b"\0", offset)
    if end < 0:
        return None
    return blob[offset:end].decode("utf-8", errors="replace")


def _dynamic_entries(blob: bytes, offset: int, size: int, step: int,
                     entry_fmt: str) -> tuple[list[tuple[int, int]], bool]:
    entry_size = struct.calcsize(entry_fmt)
    if (step < entry_size or size // step > MAX_HEADERS or
            _range(blob, offset, size) is None):
        return [], False
    entries = []
    end = offset + size
    for current in range(offset, end, step):
        if current + entry_size > end:
            return entries, False
        raw = blob[current:current + entry_size]
        tag, value = struct.unpack(entry_fmt, raw)
        if tag == 0:
            return entries, True
        entries.append((tag, value))
    return entries, False


def _mapped_blob(blob: bytes, address: int, size: int,
                 loads: list[tuple[int, int, int]]) -> bytes | None:
    for file_offset, virtual_address, file_size in loads:
        delta = address - virtual_address
        if 0 <= delta <= file_size and size <= file_size - delta:
            return _range(blob, file_offset + delta, size)
    return None


def read(path: str | pathlib.Path, *, strict_io: bool = False) -> ElfFacts | None:
    """Read ELF facts; strict_io propagates I/O errors, never malformed data."""
    try:
        with pathlib.Path(path).open("rb") as handle:
            blob = handle.read(MAX_READ + 1)
    except OSError:
        if strict_io:
            raise
        return None
    if len(blob) < 16 or blob[:4] != b"\x7fELF":
        return None
    elf_class, data = blob[4], blob[5]
    if elf_class not in (1, 2) or data not in (1, 2):
        return None
    bits = 32 if elf_class == 1 else 64
    endian = "little" if data == 1 else "big"
    order = "<" if data == 1 else ">"
    header_fmt = order + ("16sHHIIIIIHHHHHH" if bits == 32 else "16sHHIQQQIHHHHHH")
    header_size = struct.calcsize(header_fmt)
    raw_header = _range(blob, 0, header_size)
    if raw_header is None:
        return None
    values = struct.unpack(header_fmt, raw_header)
    (_ident, type_no, machine_no, _version, _entry, phoff, shoff, _flags,
     _ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = values

    ph_fmt = order + ("IIIIIIII" if bits == 32 else "IIQQQQQQ")
    expected_ph = struct.calcsize(ph_fmt)
    program_ok = (phnum == 0 or
                  (phentsize >= expected_ph and phnum <= MAX_HEADERS and
                   _range(blob, phoff, phentsize * phnum) is not None))
    interp = None
    interp_seen = False
    interp_valid = True
    has_dynamic = False
    stack_flags = None
    has_relro = False
    program_headers: list[tuple[int, int, int, int, int]] = []
    if program_ok:
        for index in range(phnum):
            raw = blob[phoff + index * phentsize:
                       phoff + index * phentsize + expected_ph]
            fields = struct.unpack(ph_fmt, raw)
            if bits == 32:
                p_type, p_offset, _vaddr, _paddr, p_filesz, _memsz, p_flags, _align = fields
            else:
                p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz, _memsz, _align = fields
            program_headers.append((p_type, p_offset, _vaddr, p_filesz, p_flags))
            if p_type == 3:  # PT_INTERP
                interp_seen = True
                payload = (_range(blob, p_offset, p_filesz)
                           if 0 < p_filesz <= 4096 else None)
                if payload and b"\0" in payload and payload[0] != 0:
                    interp = payload.split(b"\0", 1)[0].decode("utf-8", errors="replace")
                else:
                    interp_valid = False
            elif p_type == 2:  # PT_DYNAMIC
                has_dynamic = True
            elif p_type == 0x6474E551:  # PT_GNU_STACK
                stack_flags = p_flags
            elif p_type == 0x6474E552:  # PT_GNU_RELRO
                has_relro = True

    sh_fmt = order + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
    expected_sh = struct.calcsize(sh_fmt)
    sections: list[tuple[int, int, int, int, int, int]] = []
    section_ok = (shnum > 0 and shnum <= MAX_HEADERS and shstrndx < shnum and
                  shentsize >= expected_sh and
                  _range(blob, shoff, shentsize * shnum) is not None)
    if section_ok:
        for index in range(shnum):
            raw = blob[shoff + index * shentsize:
                       shoff + index * shentsize + expected_sh]
            fields = struct.unpack(sh_fmt, raw)
            name, kind = fields[0], fields[1]
            offset, size, link, entsize = fields[4], fields[5], fields[6], fields[9]
            sections.append((name, kind, offset, size, link, entsize))

    named: dict[str, tuple[int, int, int, int, int, int]] = {}
    if section_ok:
        _, _, names_off, names_size, _, _ = sections[shstrndx]
        names_blob = _range(blob, names_off, names_size)
        if names_blob is None:
            section_ok = False
        else:
            for section in sections:
                name = _cstring(names_blob, section[0])
                if name is not None:
                    named[name] = section

    needed: list[str] = []
    runpath = None
    bind_now = False
    dynamic_complete = not has_dynamic
    dynamic = named.get(".dynamic") if section_ok else None
    if dynamic is not None:
        _, _, dyn_off, dyn_size, link, dyn_entsize = dynamic
        strings = sections[link] if 0 <= link < len(sections) else None
        strings_blob = (_range(blob, strings[2], strings[3]) if strings else None)
        entry_fmt = order + ("iI" if bits == 32 else "qQ")
        entry_size = struct.calcsize(entry_fmt)
        step = dyn_entsize or entry_size
        entries, entries_complete = _dynamic_entries(
            blob, dyn_off, dyn_size, step, entry_fmt)
        dynamic_complete = entries_complete and strings_blob is not None
    elif program_ok and has_dynamic:
        entry_fmt = order + ("iI" if bits == 32 else "qQ")
        entry_size = struct.calcsize(entry_fmt)
        dynamic_header = next(
            (header for header in program_headers if header[0] == 2), None)
        entries = []
        entries_complete = False
        strings_blob = None
        if dynamic_header is not None:
            _, dyn_off, _dyn_vaddr, dyn_size, _dyn_flags = dynamic_header
            entries, entries_complete = _dynamic_entries(
                blob, dyn_off, dyn_size, entry_size, entry_fmt)
            string_address = next(
                (value for tag, value in entries if tag == 5), None)
            string_size = next(
                (value for tag, value in entries if tag == 10), None)
            loads = [(offset, vaddr, size)
                     for kind, offset, vaddr, size, _flags in program_headers
                     if kind == 1]
            if string_address is not None and string_size is not None:
                strings_blob = _mapped_blob(
                    blob, string_address, string_size, loads)
        dynamic_complete = entries_complete and strings_blob is not None
    else:
        entries = []
        strings_blob = None

    if strings_blob is not None:
        for tag, value in entries:
            if tag == 1:
                name = _cstring(strings_blob, value)
                if name is None:
                    dynamic_complete = False
                else:
                    needed.append(name)
            elif tag in (15, 29):
                runpath = _cstring(strings_blob, value)
                if runpath is None:
                    dynamic_complete = False
            elif tag == 24:
                bind_now = True

    symtab = named.get(".symtab") if section_ok else None
    stripped = "yes" if section_ok and symtab is None else ("no" if symtab else UNKNOWN)
    canary = UNKNOWN
    if symtab is not None:
        _, _, sym_off, sym_size, link, sym_entsize = symtab
        strings = sections[link] if 0 <= link < len(sections) else None
        strings_blob = (_range(blob, strings[2], strings[3]) if strings else None)
        entry_size = 16 if bits == 32 else 24
        step = sym_entsize or entry_size
        table_blob = _range(blob, sym_off, sym_size)
        if (strings_blob is not None and table_blob is not None and
                step >= entry_size and sym_size % step == 0 and
                sym_size // step <= MAX_HEADERS):
            canary = "no"
            for offset in range(sym_off, sym_off + sym_size, step):
                raw = blob[offset:offset + entry_size]
                name_offset = struct.unpack_from(order + "I", raw)[0]
                name = _cstring(strings_blob, name_offset)
                if name is None:
                    canary = UNKNOWN
                    break
                if name == "__stack_chk_fail":
                    canary = "yes"
                    break

    elf_type = ELF_TYPES.get(type_no, str(type_no))
    if program_ok:
        nx = UNKNOWN if stack_flags is None else ("no" if stack_flags & 1 else "yes")
        static = (UNKNOWN if interp_seen and not interp_valid else
                  "yes" if interp is None and not has_dynamic else "no")
        relro = (UNKNOWN if has_relro and has_dynamic and not dynamic_complete else
                 "full" if has_relro and bind_now else
                 "partial" if has_relro else "none")
    else:
        nx = static = relro = UNKNOWN
    pie = (UNKNOWN if not program_ok or (interp_seen and not interp_valid) else
           "yes" if elf_type == "DYN" and interp is not None else "no")
    return ElfFacts(
        machine=MACHINES.get(machine_no, str(machine_no)), bits=bits,
        endian=endian, elf_type=elf_type, interp=interp,
        needed=tuple(needed), runpath=runpath, nx=nx, pie=pie, relro=relro,
        canary=canary, stripped=stripped, static=static)
