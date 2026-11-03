"""Firmware dive CLI exposes bounded file-oriented workflow modes."""
import json
import pathlib
import sqlite3
from types import SimpleNamespace

import pytest

import audit
from audit_core import db, firmware_dive, firmware_dive_acquisition, firmware_dive_results


PREPARE_FIELDS = {
    "image_id", "dive_generation", "graph_sha256", "analyst_manifest_sha256",
    "journal_input_path", "question_index_path", "question_count",
    "chain_blocker_count", "surface_unknown_count", "analyst_question_count",
    "retry_count", "conflict_count",
}
ACQUISITION_FIELDS = {
    "image_id", "dive_generation", "question_id", "acquisition_id", "kind",
    "spec_path", "manifest_path", "file_count", "byte_count",
}
RECORD_FIELDS = {
    "image_id", "dive_generation", "receipt_key", "observation_id",
    "artifact_path", "dependency_count", "evidence_count", "successor_count",
}
CHECK_FIELDS = {
    "image_id", "dive_generation", "question_count", "supported_count",
    "refuted_count", "inconclusive_count", "current_count", "stale_count",
    "contested_count", "journal_path", "journal_sha256", "overlay_sha256",
    "complete",
}


@pytest.mark.parametrize("flags", [
    [], ["--run", "unused"],
    ["--run", "unused", "--prepare", "--check", "--root", "root"],
    ["--run", "unused", "--probe", "p", "--capture", "c", "--root", "root"],
    ["--run", "unused", "--record", "r", "--check", "--root", "root"],
    ["--run", "unused", "--probe"], ["--run", "unused", "--capture"],
    ["--run", "unused", "--record"], ["--prepare", "--root", "root"],
])
def test_route_syntax_errors_exit_two_before_database_access(tmp_path, monkeypatch, capsys, flags):
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: pytest.fail("database opened"))
    flags = [str(tmp_path / "unused") if value == "unused" else value for value in flags]
    with pytest.raises(SystemExit) as exc:
        audit.main(["dive", *flags])
    assert exc.value.code == 2
    out = capsys.readouterr()
    assert out.out == "" and "error:" in out.err
    assert not (tmp_path / "unused").exists()


@pytest.mark.parametrize("flags,message", [
    (["--prepare"], "--root is required"),
    (["--check"], "--root is required"),
    (["--probe", "spec"], "--root is required"),
    (["--capture", "spec"], "--root is required"),
    (["--record", "result", "--root", "root"], "--root"),
    (["--check", "--root", "root", "--questions", "q"], "--questions requires --prepare"),
    (["--check", "--root", "root", "--retry", "q"], "--retry requires --prepare"),
])
def test_semantic_constraints_exit_one_before_database_access(tmp_path, monkeypatch, capsys, flags, message):
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: pytest.fail("database opened"))
    assert audit.main(["dive", "--run", str(tmp_path / "missing"), *flags]) == 1
    out = capsys.readouterr()
    assert out.out == "" and message in out.err
    assert not (tmp_path / "missing").exists()


def _summary(mode, root):
    common = {"image_id": "image", "dive_generation": "a" * 64}
    if mode == "prepare":
        common.update(graph_sha256="b" * 64, analyst_manifest_sha256="c" * 64,
            journal_input_path=str(root / "journal.json"), question_index_path=str(root / "questions.json"),
            question_count=3, chain_blocker_count=1, surface_unknown_count=1,
            analyst_question_count=1, retry_count=0, conflict_count=0)
    elif mode in {"probe", "capture"}:
        common.update(question_id="q1", acquisition_id="acq1", kind=mode,
            spec_path=str(root / "spec.json"), manifest_path=str(root / "manifest.json"),
            file_count=2, byte_count=42)
    elif mode == "record":
        common.update(receipt_key="receipt", observation_id=None,
            artifact_path="artifact.json", dependency_count=0, evidence_count=0,
            successor_count=0)
    else:
        common.update(question_count=3, supported_count=1, refuted_count=1,
            inconclusive_count=1, current_count=3, stale_count=0, contested_count=0,
            questions=(SimpleNamespace(question_id="PRIVATE"),),
            journal_path=str(root / "journal.json"), journal_sha256="d" * 64,
            overlay_sha256="e" * 64, complete=True)
    return SimpleNamespace(**common)


@pytest.mark.parametrize("mode,fields", [
    ("prepare", PREPARE_FIELDS), ("probe", ACQUISITION_FIELDS),
    ("capture", ACQUISITION_FIELDS), ("record", RECORD_FIELDS),
    ("check", CHECK_FIELDS),
])
@pytest.mark.parametrize("json_output", [False, True])
def test_exact_delegation_and_scalar_output(tmp_path, monkeypatch, capsys, mode, fields, json_output):
    run = tmp_path / "run"
    root = tmp_path / "PRIVATE_ROOT"
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    result = _summary(mode, root)

    def delegated(connection, run_dir, *args, **kwargs):
        assert connection is con and run_dir == run
        if mode == "prepare":
            assert args == (root,) and kwargs == {
                "image_id": "image", "questions_path": pathlib.Path("questions.json"),
                "retry": ("q1", "q2"),
            }
        elif mode in {"probe", "capture"}:
            assert args == (root, pathlib.Path("spec.json")) and kwargs == {}
        elif mode == "record":
            assert args == (pathlib.Path("result.json"),) and kwargs == {}
        else:
            assert args == (root,) and kwargs == {"image_id": "image"}
        return result

    target = {
        "prepare": (firmware_dive, "prepare"),
        "probe": (firmware_dive_acquisition, "run_probe"),
        "capture": (firmware_dive_acquisition, "seal_capture"),
        "record": (firmware_dive_results, "record"),
        "check": (firmware_dive, "check"),
    }[mode]
    monkeypatch.setattr(*target, delegated)
    flags = ["--" + mode]
    if mode in {"probe", "capture"}:
        flags += ["spec.json"]
    elif mode == "record":
        flags += ["result.json"]
    if mode != "record":
        flags += ["--root", str(root)]
    if mode in {"prepare", "check"}:
        flags += ["--image-id", "image"]
    if mode == "prepare":
        flags += ["--questions", "questions.json", "--retry", "q1", "--retry", "q2"]
    if json_output:
        flags += ["--json"]

    assert audit.main(["dive", "--run", str(run), *flags]) == 0
    out = capsys.readouterr()
    assert out.err == ""
    if json_output:
        payload = json.loads(out.out)
        assert set(payload) == fields
        assert all(value is None or isinstance(value, (str, int, bool)) for value in payload.values())
    else:
        assert out.out.isascii() and str(root) not in out.out
        assert all(len(line) <= 512 for line in out.out.splitlines())
    with pytest.raises(sqlite3.ProgrammingError):
        con.execute("SELECT 1")


@pytest.mark.parametrize("mode,error_type", [
    ("prepare", firmware_dive.FirmwareDiveError),
    ("probe", firmware_dive_acquisition.AcquisitionError),
    ("capture", firmware_dive_acquisition.AcquisitionError),
    ("record", firmware_dive_results.FirmwareDiveResultError),
    ("check", db.DbError),
    ("check", sqlite3.OperationalError),
    ("check", OSError),
])
def test_expected_errors_are_bounded_and_database_errors_fixed(tmp_path, monkeypatch, capsys, mode, error_type):
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    root = tmp_path / "PRIVATE_ROOT"
    error = error_type(f"cannot use {root}: private\n\x1b" + "x" * 1000)

    def fail(*args, **kwargs):
        raise error

    target = {
        "prepare": (firmware_dive, "prepare"), "probe": (firmware_dive_acquisition, "run_probe"),
        "capture": (firmware_dive_acquisition, "seal_capture"), "record": (firmware_dive_results, "record"),
        "check": (firmware_dive, "check"),
    }[mode]
    monkeypatch.setattr(*target, fail)
    flags = ["--" + mode]
    if mode in {"probe", "capture"}:
        flags += ["spec.json"]
    elif mode == "record":
        flags += ["result.json"]
    if mode != "record":
        flags += ["--root", str(root)]
    assert audit.main(["dive", "--run", str(tmp_path / "run"), *flags]) == 1
    out = capsys.readouterr()
    assert out.out == "" and out.err.isascii() and len(out.err) <= 513
    if error_type is sqlite3.OperationalError:
        assert out.err == "dive: database operation failed\n"
    elif mode != "record":
        assert str(root) not in out.err and "<root>" in out.err
    with pytest.raises(sqlite3.ProgrammingError):
        con.execute("SELECT 1")
