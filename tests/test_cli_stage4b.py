import json
import pathlib
import struct
import subprocess
import sys

from audit_core import workspace

ROOT = pathlib.Path(__file__).resolve().parent.parent
AUDIT = ROOT / "audit.py"


def run_cli(*args):
    return subprocess.run([sys.executable, str(AUDIT), *map(str, args)],
                          capture_output=True, text=True)


def make_run(tmp_path):
    return workspace.init_run(tmp_path, timestamp="20261009-030000")


def make_rootfs(tmp_path):
    root = tmp_path / "rootfs"
    (root / "bin").mkdir(parents=True)
    ident = b"\x7fELF" + bytes((2, 1, 1)) + b"\0" * 9
    (root / "bin/app").write_bytes(struct.pack(
        "<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0, 0, 0, 0,
        64, 56, 0, 64, 0, 0))
    return root


def test_stage4b_help_exposes_required_inputs():
    acquire = run_cli("acquire", "--help")
    triage = run_cli("triage", "--help")
    assert acquire.returncode == triage.returncode == 0
    for flag in ("--run", "--vendor", "--model", "--version", "--role", "--file"):
        assert flag in acquire.stdout
    for flag in ("--run", "--root", "--image-id", "--allow-no-elf"):
        assert flag in triage.stdout


def test_acquire_json_and_text_output(tmp_path):
    run = make_run(tmp_path)
    image = tmp_path / "fw.bin"
    image.write_bytes(b"firmware")
    args = ("acquire", "--run", run, "--vendor", "Acme", "--model", "R1",
            "--version", "1", "--role", "target", "--file", image,
            "--source", "vendor.example")
    result = run_cli(*args, "--json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["id"] == "acme|r1|target"
    text = run_cli(*args, "--replace")
    assert text.returncode == 0, text.stderr
    assert "acme|r1|target" in text.stdout


def test_triage_json_and_text_output(tmp_path):
    run = make_run(tmp_path)
    rootfs = make_rootfs(tmp_path)
    result = run_cli("triage", "--run", run, "--root", rootfs, "--json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "inventory_count": 1, "elf_count": 1, "service_count": 0}
    text = run_cli("triage", "--run", run, "--root", rootfs)
    assert text.returncode == 0, text.stderr
    assert "1 file(s), 1 ELF" in text.stdout


def test_acquire_refusals_have_no_traceback(tmp_path):
    run = make_run(tmp_path)
    result = run_cli(
        "acquire", "--run", run, "--vendor", "acme", "--model", "r1",
        "--version", "1", "--role", "target", "--file", tmp_path / "missing",
        "--source", "local")
    assert result.returncode == 1
    assert "regular readable file" in result.stderr
    assert "Traceback" not in result.stderr


def test_duplicate_and_triage_refusals_are_named(tmp_path):
    run = make_run(tmp_path)
    image = tmp_path / "fw.bin"
    image.write_bytes(b"x")
    args = ("acquire", "--run", run, "--vendor", "acme", "--model", "r1",
            "--version", "1", "--role", "target", "--file", image,
            "--source", "local")
    assert run_cli(*args).returncode == 0
    duplicate = run_cli(*args)
    assert duplicate.returncode == 1 and "--replace" in duplicate.stderr
    missing_root = run_cli("triage", "--run", run, "--root", tmp_path / "missing")
    assert missing_root.returncode == 1 and "directory" in missing_root.stderr
    rootfs = make_rootfs(tmp_path)
    unknown = run_cli("triage", "--run", run, "--root", rootfs,
                      "--image-id", "unknown|x|target")
    assert unknown.returncode == 1 and "not recorded" in unknown.stderr
    assert "Traceback" not in duplicate.stderr + missing_root.stderr + unknown.stderr


def test_zero_elf_refusal_and_override(tmp_path):
    run = make_run(tmp_path)
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "README").write_text("RTOS")
    refused = run_cli("triage", "--run", run, "--root", rootfs)
    assert refused.returncode == 1 and "zero ELF" in refused.stderr
    allowed = run_cli("triage", "--run", run, "--root", rootfs,
                      "--allow-no-elf", "--json")
    assert allowed.returncode == 0
    assert json.loads(allowed.stdout)["elf_count"] == 0


def test_invalid_or_missing_arguments_are_usage_errors(tmp_path):
    bad_role = run_cli("acquire", "--run", tmp_path, "--vendor", "v",
                       "--model", "m", "--version", "1", "--role", "snapshot",
                       "--file", tmp_path / "x", "--source", "local")
    missing_root = run_cli("triage", "--run", tmp_path)
    assert bad_role.returncode == missing_root.returncode == 2
