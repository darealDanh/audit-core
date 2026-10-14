"""Filesystem contracts for the shared, complete-or-error carved-tree scan."""
import dataclasses
import os
import pathlib

import pytest

from audit_core import elf, firmware_tree


# Literal x86-64 EXEC header; no program or section headers.
ELF_BYTES = bytes.fromhex(
    "7f454c4602010100000000000000000002003e00010000000000000000000000"
    "0000000000000000000000000000000000000000400038000000400000000000")


def tree(tmp_path):
    root = tmp_path / "root"
    (root / "bin").mkdir(parents=True)
    (root / "etc/init.d").mkdir(parents=True)
    (root / "usr/share").mkdir(parents=True)
    (root / "bin/httpd").write_bytes(ELF_BYTES)
    (root / "etc/httpd.conf").write_bytes(b"port=80\n")
    (root / "etc/init.d/S50httpd").write_bytes(b"#!/bin/sh\n/bin/httpd\n")
    (root / "usr/share/banner").write_bytes(b"hello\n")
    return root


def test_scan_retains_exact_order_kind_size_digest_and_elf(tmp_path):
    # Breaks: wrong kind priority, size, digest, ordering, or discarded ELF facts.
    root = tree(tmp_path)
    facts = firmware_tree.scan(str(root))
    assert isinstance(facts, tuple)
    assert [(f.relative, f.kind, f.size, f.sha256) for f in facts] == [
        ("bin/httpd", "binary", 64,
         "51224867e5fb13d0c6052397c9f4959c7c87bb8bc7d750c91429728a18b507d9"),
        ("etc/httpd.conf", "config", 8,
         "8ac56ba2b165fcd437ca405ef420a36ccbda0f41ce603a07db42752ff00335a2"),
        ("etc/init.d/S50httpd", "script", 21,
         "db21b439bed93b3f035f8cb41ef06cd7c68dfe9cfe306b67173199f295993c3f"),
        ("usr/share/banner", "file", 6,
         "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"),
    ]
    assert [f.path for f in facts] == [root / f.relative for f in facts]
    assert facts[0].elf == elf.ElfFacts(
        "x86-64", 64, "little", "EXEC", None, (), None,
        "unknown", "no", "none", "unknown", "unknown", "yes")
    assert all(f.elf is None for f in facts[1:])
    with pytest.raises(dataclasses.FrozenInstanceError):
        facts[0].kind = "file"


def test_scan_excludes_links_fifo_and_socket_and_sorts_by_posix_path(tmp_path, monkeypatch):
    # Breaks: following links or opening nonregular files; sorting by basename.
    import socket

    root = tree(tmp_path)
    (root / "bin/link").symlink_to("httpd")
    (root / "directory-link").symlink_to(root / "usr", target_is_directory=True)
    (root / "missing-link").symlink_to("missing")
    outside = tmp_path / "outside"
    outside.write_bytes(ELF_BYTES)
    (root / "outside-link").symlink_to(outside)
    (root / "z").write_bytes(b"")
    (root / "a").write_bytes(b"")
    os.mkfifo(root / "pipe")
    monkeypatch.chdir(root)
    with socket.socket(socket.AF_UNIX) as sock:
        sock.bind("socket")
        assert [f.relative for f in firmware_tree.scan(root)] == [
            "a", "bin/httpd", "etc/httpd.conf", "etc/init.d/S50httpd",
            "usr/share/banner", "z"]


@pytest.mark.parametrize("kind", ["missing", "file", "symlink"])
def test_scan_rejects_non_directory_or_link_root(tmp_path, kind):
    # Breaks: accepting a non-directory root or following a root symlink.
    root = tmp_path / kind
    if kind == "file":
        root.write_bytes(b"x")
    elif kind == "symlink":
        target = tree(tmp_path)
        root.symlink_to(target, target_is_directory=True)
    with pytest.raises(firmware_tree.FirmwareTreeError) as caught:
        firmware_tree.scan(root)
    assert str(root) in str(caught.value)


def test_scan_empty_tree_returns_complete_empty_tuple(tmp_path):
    tmp_path.joinpath("empty").mkdir()
    assert firmware_tree.scan(tmp_path / "empty") == ()


@pytest.mark.parametrize("operation", [
    "lstat", "stat", "open-first", "open-kind", "open-hash",
    "read-first", "read-kind", "read-hash"])
def test_file_io_failure_after_readable_siblings_aborts_with_path(tmp_path, monkeypatch, operation):
    # Breaks: swallowing an I/O race as non-ELF/file or returning partial facts.
    root = tree(tmp_path)
    blocked = root / "usr/share/banner"
    method = "open" if operation.startswith(("open-", "read-")) else operation
    original = getattr(pathlib.Path, method)
    seen = 0
    fail_at = {"first": 1, "kind": 2, "hash": 3}.get(operation.split("-")[-1], 1)

    class ReadFailure:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

        def read(self, *args):
            self.handle.read(*args)
            raise OSError("injected file race")

    def fail(path, *args, **kwargs):
        nonlocal seen
        if path == blocked:
            seen += 1
            if seen == fail_at:
                # One transient error, followed by normal real filesystem reads.
                if operation.startswith("read-"):
                    return ReadFailure(original(path, *args, **kwargs))
                raise OSError("injected file race")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, method, fail)
    with pytest.raises(firmware_tree.FirmwareTreeError, match="injected file race") as caught:
        firmware_tree.scan(root)
    assert str(blocked) in str(caught.value)


@pytest.mark.parametrize("operation", ["scandir", "iteration", "is_dir", "mismatch"])
def test_traversal_failure_aborts_with_failing_path(tmp_path, monkeypatch, operation):
    # Breaks: omitted subtree after scandir/iteration/is_dir failure or mismatch.
    root = tree(tmp_path)
    blocked = root / "usr"
    original = os.scandir

    class Entry:
        def __init__(self, entry):
            self.entry = entry

        def __getattr__(self, name):
            return getattr(self.entry, name)

        def is_dir(self, *, follow_symlinks=True):
            if pathlib.Path(self.entry.path) == blocked:
                if operation == "is_dir":
                    raise OSError("injected classification race")
                if operation == "mismatch":
                    return False
            return self.entry.is_dir(follow_symlinks=follow_symlinks)

    class Entries:
        def __init__(self, path):
            self.path = pathlib.Path(path)
            self.iterator = original(path)

        def __enter__(self):
            self.iterator.__enter__()
            return self

        def __exit__(self, *args):
            return self.iterator.__exit__(*args)

        def __iter__(self):
            return self

        def __next__(self):
            entry = next(self.iterator)
            if self.path == blocked and operation == "iteration":
                raise OSError("injected iteration race")
            return Entry(entry)

    def fail(path):
        if pathlib.Path(path) == blocked and operation == "scandir":
            raise PermissionError("injected scandir failure")
        return Entries(path)

    monkeypatch.setattr(os, "scandir", fail)
    with pytest.raises(firmware_tree.FirmwareTreeError) as caught:
        firmware_tree.scan(root)
    assert str(blocked) in str(caught.value)


def test_strict_elf_io_preserves_default_but_raises_on_read_race(tmp_path, monkeypatch):
    # Breaks: default callers raising or strict callers misclassifying failed reads.
    path = tmp_path / "binary"
    path.write_bytes(ELF_BYTES)
    original = pathlib.Path.open

    def fail_open(current, *args, **kwargs):
        if current == path:
            raise OSError("injected ELF read race")
        return original(current, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "open", fail_open)
    assert elf.read(path) is None
    with pytest.raises(OSError, match="ELF read race"):
        elf.read(path, strict_io=True)
