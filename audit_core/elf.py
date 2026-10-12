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


def read(path: str | pathlib.Path) -> ElfFacts | None:
    """Return facts for a structurally recognisable ELF; never raise on data."""
    try:
        with pathlib.Path(path).open("rb") as handle:
            blob = handle.read(MAX_READ + 1)
    except OSError:
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
    has_dynamic = False
    stack_flags = None
    has_relro = False
    if program_ok:
        for index in range(phnum):
            raw = blob[phoff + index * phentsize:
                       phoff + index * phentsize + expected_ph]
            fields = struct.unpack(ph_fmt, raw)
            if bits == 32:
                p_type, p_offset, _vaddr, _paddr, p_filesz, _memsz, p_flags, _align = fields
            else:
                p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz, _memsz, _align = fields
            if p_type == 3:  # PT_INTERP
                payload = _range(blob, p_offset, min(p_filesz, 4096))
                if payload:
                    interp = payload.split(b"\0", 1)[0].decode("utf-8", errors="replace")
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
    dynamic = named.get(".dynamic") if section_ok else None
    if dynamic is not None:
        _, _, dyn_off, dyn_size, link, dyn_entsize = dynamic
        strings = sections[link] if 0 <= link < len(sections) else None
        strings_blob = (_range(blob, strings[2], strings[3]) if strings else None)
        entry_fmt = order + ("iI" if bits == 32 else "qQ")
        entry_size = struct.calcsize(entry_fmt)
        step = dyn_entsize or entry_size
        section_end = dyn_off + dyn_size
        if strings_blob is not None and step >= entry_size and dyn_size // step <= MAX_HEADERS:
            for offset in range(dyn_off, dyn_off + dyn_size, step):
                raw = (None if offset + entry_size > section_end
                       else _range(blob, offset, entry_size))
                if raw is None:
                    break
                tag, value = struct.unpack(entry_fmt, raw)
                if tag == 0:
                    break
                if tag == 1:
                    name = _cstring(strings_blob, value)
                    if name is not None:
                        needed.append(name)
                elif tag in (15, 29):
                    runpath = _cstring(strings_blob, value)
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
        if strings_blob is not None and step >= entry_size and sym_size // step <= MAX_HEADERS:
            canary = "no"
            for offset in range(sym_off, sym_off + sym_size, step):
                raw = _range(blob, offset, 4)
                if raw is None:
                    canary = UNKNOWN
                    break
                name_offset = struct.unpack(order + "I", raw)[0]
                if _cstring(strings_blob, name_offset) == "__stack_chk_fail":
                    canary = "yes"
                    break

    elf_type = ELF_TYPES.get(type_no, str(type_no))
    if program_ok:
        nx = UNKNOWN if stack_flags is None else ("no" if stack_flags & 1 else "yes")
        static = "yes" if interp is None and not has_dynamic else "no"
        relro = ("full" if has_relro and bind_now else
                 "partial" if has_relro else "none")
    else:
        nx = static = relro = UNKNOWN
    pie = "yes" if elf_type == "DYN" and interp is not None else "no"
    return ElfFacts(
        machine=MACHINES.get(machine_no, str(machine_no)), bits=bits,
        endian=endian, elf_type=elf_type, interp=interp,
        needed=tuple(needed), runpath=runpath, nx=nx, pie=pie, relro=relro,
        canary=canary, stripped=stripped, static=static)
