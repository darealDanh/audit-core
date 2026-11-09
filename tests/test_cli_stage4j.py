"""Firmware report CLI exposes only bounded per-item workflow modes."""
import dataclasses
import json
import pathlib
import sqlite3
from types import SimpleNamespace

import pytest

import audit
from audit_core import db, firmware_report, firmware_report_results


FIELDS = {
    "prepare": {field.name for field
                in dataclasses.fields(firmware_report.ReportPreparationSummary)},
    "record": {field.name for field
               in dataclasses.fields(firmware_report_results.ReportRecordSummary)},
    "check": {field.name for field in dataclasses.fields(firmware_report.ReportSummary)},
}


@pytest.mark.parametrize("flags", [
    [], ["--prepare", "--record", "r"], ["--record", "r", "--check"],
    ["--prepare", "--check"],
])
def test_syntax_errors_precede_database_access(tmp_path, monkeypatch, flags):
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: pytest.fail("database opened"))
    with pytest.raises(SystemExit) as exc:
        audit.main(["firmware-report", "--run", str(tmp_path / "run"), *flags])
    assert exc.value.code == 2


@pytest.mark.parametrize("flags,message", [
    (["--prepare"], "--root is required"),
    (["--check"], "--root is required"),
    (["--record", "result", "--root", "r"], "--root"),
    (["--record", "result", "--image-id", "image"], "--image-id"),
])
def test_semantic_errors_precede_database_access(tmp_path, monkeypatch, capsys, flags, message):
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: pytest.fail("database opened"))
    assert audit.main(["firmware-report", "--run", str(tmp_path / "run"), *flags]) == 1
    assert message in capsys.readouterr().err


def _summary(mode):
    common = {"image_id": "image", "report_generation": "a" * 64}
    if mode == "prepare":
        common.update(decision_generation="b" * 64, decision_package_sha256="c" * 64,
            style_contract_sha256="d" * 64,
            manifest_path="files/firmware-report/" + "a" * 64 + "/manifest.json",
            manifest_sha256="e" * 64, item_count=2, results_path=None,
            results_sha256=None, status="pending")
    elif mode == "record":
        common.update(chain_id="chain-1", ordinal=1,
            result_path="artifacts/firmware-report-results/x/result.json",
            result_sha256="b" * 64, item_count=2, recorded_count=1, status="pending")
    else:
        common.update(decision_generation="b" * 64, decision_package_sha256="c" * 64,
            style_contract_sha256="d" * 64, results_path="artifacts/r/results.json",
            results_sha256="e" * 64, item_count=2,
            report_path="artifacts/firmware-report/g/report.md", report_sha256="f" * 64,
            index_path="artifacts/firmware-report/g/report.json", index_sha256="0" * 64,
            status="complete")
    return SimpleNamespace(**common)


def _target(mode):
    return ((firmware_report_results, "record") if mode == "record"
            else (firmware_report, mode))


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
@pytest.mark.parametrize("json_output", [False, True])
def test_exact_delegation_and_bounded_output(tmp_path, monkeypatch, capsys, mode, json_output):
    run, root = tmp_path / "run", tmp_path / "PRIVATE_ROOT"
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    result = _summary(mode)

    def delegated(connection, run_dir, *args, **kwargs):
        assert connection is con and run_dir == run
        if mode == "record":
            assert args == (pathlib.Path("result.json"),) and kwargs == {}
        else:
            assert args == (root,) and kwargs == {"image_id": "image"}
        return result

    monkeypatch.setattr(*_target(mode), delegated)
    flags = ["--" + mode]
    if mode == "record":
        flags += ["result.json"]
    else:
        flags += ["--root", str(root), "--image-id", "image"]
    if json_output:
        flags += ["--json"]
    assert audit.main(["firmware-report", "--run", str(run), *flags]) == 0
    out = capsys.readouterr()
    assert out.err == ""
    if json_output:
        payload = json.loads(out.out)
        assert set(payload) == FIELDS[mode]
        assert "PRIVATE_ROOT" not in out.out
    else:
        assert out.out.isascii() and "PRIVATE_ROOT" not in out.out
        assert all(len(line) <= 512 for line in out.out.splitlines())
        assert result.status in out.out
    with pytest.raises(sqlite3.ProgrammingError):
        con.execute("SELECT 1")


def test_prepare_prints_only_bounded_scalars_never_item_paths(tmp_path, monkeypatch, capsys):
    """Consumers read the N item paths from the bounded manifest, not stdout."""
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    summary = _summary("prepare")
    summary.item_count = 4096
    monkeypatch.setattr(firmware_report, "prepare", lambda *a, **k: summary)
    assert audit.main(["firmware-report", "--run", str(tmp_path / "run"),
                       "--root", str(tmp_path), "--prepare"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [
        "firmware-report prepare image: 4096 item count, pending",
        "report generation " + "a" * 64,
        summary.manifest_path,
    ]
    assert "items/" not in out


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
@pytest.mark.parametrize("image_id", ["路由器|r1|target", "image\n\x1b\t\"", "x" * 800])
@pytest.mark.parametrize("json_output", [False, True])
def test_public_identity_round_trips_json_and_human_output_stays_bounded(
        tmp_path, monkeypatch, capsys, mode, image_id, json_output):
    root = tmp_path / "PRIVATE_ROOT"
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    summary = _summary(mode)
    summary.image_id = image_id + str(root)
    path_field = {"prepare": "manifest_path", "record": "result_path",
                  "check": "report_path"}[mode]
    path = "files/" + str(root).lstrip("/") + "/雪/" + "/".join(["x" * 200] * 3) + ".json"
    setattr(summary, path_field, path)
    monkeypatch.setattr(*_target(mode), lambda *a, **k: summary)
    flags = (["--record", "result.json"] if mode == "record"
             else ["--" + mode, "--root", str(root)])
    if json_output:
        flags += ["--json"]
    assert audit.main(["firmware-report", "--run", str(tmp_path / "run"), *flags]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    if json_output:
        payload = json.loads(output.out)
        assert set(payload) == FIELDS[mode]
        assert payload["image_id"] == image_id + str(root)
        assert payload[path_field] == path
    else:
        assert output.out.isascii()
        assert all(len(line) <= 512 for line in output.out.splitlines())
        if mode != "record":
            assert str(root) not in output.out


@pytest.mark.parametrize("mode,error_type", [
    ("prepare", firmware_report.FirmwareReportError),
    ("record", firmware_report_results.FirmwareReportResultError),
    ("check", firmware_report.FirmwareReportError),
    ("check", db.DbError), ("check", sqlite3.OperationalError), ("check", OSError),
])
def test_expected_errors_are_bounded(tmp_path, monkeypatch, capsys, mode, error_type):
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    root = tmp_path / "PRIVATE_ROOT"

    def fail(*args, **kwargs):
        raise error_type(f"cannot use {root}: private\n\x1b" + "x" * 1000)

    monkeypatch.setattr(*_target(mode), fail)
    flags = ["--" + mode]
    if mode == "record":
        flags += ["result.json"]
    else:
        flags += ["--root", str(root)]
    assert audit.main(["firmware-report", "--run", str(tmp_path / "run"), *flags]) == 1
    out = capsys.readouterr()
    assert out.out == "" and out.err.isascii() and len(out.err) <= 513
    if error_type is sqlite3.OperationalError:
        assert out.err == "firmware-report: database operation failed\n"
    elif mode != "record":
        assert str(root) not in out.err


def test_unexpected_exceptions_propagate_after_rollback(tmp_path, monkeypatch):
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE t (a)")
    con.execute("BEGIN")
    con.execute("INSERT INTO t VALUES (1)")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)

    def fail(*args, **kwargs):
        raise ZeroDivisionError("programming fault")

    monkeypatch.setattr(firmware_report, "check", fail)
    with pytest.raises(ZeroDivisionError):
        audit.main(["firmware-report", "--run", str(tmp_path / "run"),
                    "--root", str(tmp_path), "--check"])


def test_database_open_failure_is_a_fixed_diagnostic(tmp_path, capsys):
    """A missing run directory never reaches the report module."""
    assert audit.main(["firmware-report", "--run", str(tmp_path / "missing"),
                       "--root", str(tmp_path), "--check"]) == 1
    err = capsys.readouterr().err
    assert err and err.isascii() and len(err) <= 513


def test_record_refusal_on_a_complete_generation_is_reported(tmp_path, monkeypatch, capsys):
    """A complete generation refuses further records; the CLI reports exit 1."""
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)

    def refuse(*args, **kwargs):
        raise firmware_report_results.FirmwareReportResultError(
            "report generation is already complete")

    monkeypatch.setattr(firmware_report_results, "record", refuse)
    assert audit.main(["firmware-report", "--run", str(tmp_path / "run"),
                       "--record", "result.json"]) == 1
    assert capsys.readouterr().err == "report generation is already complete\n"


def test_ordinary_report_phase_has_no_cli_verb():
    """The ordinary report stays a skill workflow; only firmware gets a verb."""
    assert "report" not in audit.HANDLERS
    assert audit.HANDLERS["firmware-report"] is audit.cmd_firmware_report
