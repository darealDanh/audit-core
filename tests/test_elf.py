import struct

import pytest

from audit_core import elf


def header_only(*, bits=64, endian="little", machine=62, elf_type=2):
    order = "<" if endian == "little" else ">"
    ident = b"\x7fELF" + bytes((2 if bits == 64 else 1, 1 if endian == "little" else 2, 1)) + b"\0" * 9
    if bits == 64:
        return struct.pack(order + "16sHHIQQQIHHHHHH", ident, elf_type, machine, 1,
                           0, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    return struct.pack(order + "16sHHIIIIIHHHHHH", ident, elf_type, machine, 1,
                       0, 0, 0, 0, 52, 32, 0, 40, 0, 0)


def rich_elf(*, elf_type=3, interp=True, stack_exec=False, relro=True,
             bind_now=True, symtab=True, canary=True):
    order = "<"
    ehsize, phentsize, shentsize = 64, 56, 64
    phnum = int(interp) + 1 + int(relro) + 1  # interp, stack, relro, dynamic
    cursor = 0x200
    interp_data = b"/lib/ld-musl.so.1\0" if interp else b""
    interp_off = cursor
    cursor += len(interp_data)
    dynstr = b"\0libc.so.6\0/opt/lib\0"
    dynstr_off = cursor
    cursor += len(dynstr)
    dynamic = struct.pack("<qQ", 1, 1) + struct.pack("<qQ", 29, 11)
    if bind_now:
        dynamic += struct.pack("<qQ", 24, 0)
    dynamic += struct.pack("<qQ", 0, 0)
    dynamic_off = cursor
    cursor += len(dynamic)
    strtab = b"\0__stack_chk_fail\0other\0"
    strtab_off = cursor
    cursor += len(strtab)
    symbols = b"\0" * 24
    if canary:
        symbols += struct.pack("<IBBHQQ", 1, 0, 0, 0, 0, 0)
    symtab_off = cursor
    cursor += len(symbols)
    names = ["", ".shstrtab", ".dynstr", ".dynamic", ".strtab"]
    if symtab:
        names.append(".symtab")
    shstr = b"\0" + b"\0".join(n.encode() for n in names[1:]) + b"\0"
    name_at, offset = {}, 1
    for name in names[1:]:
        name_at[name] = offset
        offset += len(name) + 1
    shstr_off = cursor
    cursor += len(shstr)
    shoff = (cursor + 7) & ~7

    phdrs = []
    if interp:
        phdrs.append(struct.pack("<IIQQQQQQ", 3, 4, interp_off, 0, 0,
                                 len(interp_data), len(interp_data), 1))
    phdrs.append(struct.pack("<IIQQQQQQ", 0x6474E551, 7 if stack_exec else 6,
                             0, 0, 0, 0, 0, 16))
    if relro:
        phdrs.append(struct.pack("<IIQQQQQQ", 0x6474E552, 4, 0, 0, 0, 0, 0, 1))
    phdrs.append(struct.pack("<IIQQQQQQ", 2, 4, dynamic_off, 0, 0,
                             len(dynamic), len(dynamic), 8))

    sections = [b"\0" * shentsize]
    sections.append(struct.pack("<IIQQQQIIQQ", name_at[".shstrtab"], 3, 0, 0,
                                shstr_off, len(shstr), 0, 0, 1, 0))
    sections.append(struct.pack("<IIQQQQIIQQ", name_at[".dynstr"], 3, 0, 0,
                                dynstr_off, len(dynstr), 0, 0, 1, 0))
    sections.append(struct.pack("<IIQQQQIIQQ", name_at[".dynamic"], 6, 0, 0,
                                dynamic_off, len(dynamic), 2, 0, 8, 16))
    sections.append(struct.pack("<IIQQQQIIQQ", name_at[".strtab"], 3, 0, 0,
                                strtab_off, len(strtab), 0, 0, 1, 0))
    if symtab:
        sections.append(struct.pack("<IIQQQQIIQQ", name_at[".symtab"], 2, 0, 0,
                                    symtab_off, len(symbols), 4, 0, 8, 24))
    ident = b"\x7fELF" + bytes((2, 1, 1)) + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, elf_type, 62, 1, 0, 64,
                         shoff, 0, ehsize, phentsize, phnum, shentsize,
                         len(sections), 1)
    blob = bytearray(shoff + len(sections) * shentsize)
    blob[:64] = header
    blob[64:64 + len(b"".join(phdrs))] = b"".join(phdrs)
    blob[interp_off:interp_off + len(interp_data)] = interp_data
    blob[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    blob[dynamic_off:dynamic_off + len(dynamic)] = dynamic
    blob[strtab_off:strtab_off + len(strtab)] = strtab
    blob[symtab_off:symtab_off + len(symbols)] = symbols
    blob[shstr_off:shstr_off + len(shstr)] = shstr
    blob[shoff:] = b"".join(sections)
    return bytes(blob)


@pytest.mark.parametrize("bits,endian,machine,name", [
    (32, "big", 8, "mips"), (32, "little", 8, "mips"),
    (32, "little", 40, "arm"), (64, "little", 183, "aarch64"),
    (64, "little", 62, "x86-64"),
])
def test_reads_architecture_class_and_byte_order(tmp_path, bits, endian, machine, name):
    path = tmp_path / "program"
    path.write_bytes(header_only(bits=bits, endian=endian, machine=machine))
    facts = elf.read(path)
    assert (facts.machine, facts.bits, facts.endian, facts.elf_type) == (
        name, bits, endian, "EXEC")


@pytest.mark.parametrize("number,name", [(1, "REL"), (2, "EXEC"), (3, "DYN"), (4, "CORE")])
def test_reads_elf_type(tmp_path, number, name):
    path = tmp_path / name
    path.write_bytes(header_only(elf_type=number))
    assert elf.read(path).elf_type == name


def test_reads_dynamic_dependencies_and_mitigations(tmp_path):
    path = tmp_path / "httpd"
    path.write_bytes(rich_elf())
    facts = elf.read(path)
    assert facts.interp == "/lib/ld-musl.so.1"
    assert facts.needed == ("libc.so.6",)
    assert facts.runpath == "/opt/lib"
    assert (facts.nx, facts.pie, facts.relro) == ("yes", "yes", "full")
    assert (facts.canary, facts.stripped, facts.static) == ("yes", "no", "no")


def test_reports_partial_relro_executable_stack_and_shared_library(tmp_path):
    path = tmp_path / "libx.so"
    path.write_bytes(rich_elf(interp=False, stack_exec=True, bind_now=False,
                              canary=False))
    facts = elf.read(path)
    assert (facts.nx, facts.pie, facts.relro) == ("no", "no", "partial")
    assert facts.canary == "no"
    assert facts.static == "no"


def test_stripped_static_binary_has_unknown_canary(tmp_path):
    path = tmp_path / "static"
    path.write_bytes(header_only())
    facts = elf.read(path)
    assert (facts.stripped, facts.canary, facts.static) == ("unknown", "unknown", "yes")


@pytest.mark.parametrize("payload", [b"", b"not elf", b"\x7fELF", b"\x7fELF\x02\x01"])
def test_non_elf_and_truncated_headers_return_none(tmp_path, payload):
    path = tmp_path / "bad"
    path.write_bytes(payload)
    assert elf.read(path) is None


def test_offsets_and_counts_past_eof_do_not_raise(tmp_path):
    path = tmp_path / "bad-offsets"
    blob = bytearray(header_only())
    struct.pack_into("<Q", blob, 40, 0xFFFFFFFF)  # e_shoff
    struct.pack_into("<H", blob, 60, 0xFFFF)      # e_shnum
    path.write_bytes(blob)
    facts = elf.read(path)
    assert facts.machine == "x86-64"
    assert facts.canary == "unknown"


def test_truncated_program_table_yields_unknown_mitigations(tmp_path):
    path = tmp_path / "bad-phdrs"
    blob = bytearray(header_only())
    struct.pack_into("<Q", blob, 32, 60)  # e_phoff: table starts before EOF
    struct.pack_into("<Q", blob, 40, 0)
    struct.pack_into("<H", blob, 54, 56)
    struct.pack_into("<H", blob, 56, 4)   # but four entries do not fit
    path.write_bytes(blob)
    facts = elf.read(path)
    assert (facts.nx, facts.pie, facts.relro) == ("unknown", "no", "unknown")
