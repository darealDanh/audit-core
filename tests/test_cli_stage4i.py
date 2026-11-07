"""Firmware decision CLI exposes only bounded global workflow modes."""
import json
import pathlib
import sqlite3
from types import SimpleNamespace

import pytest

import audit
from audit_core import db, firmware_decide, firmware_decide_results


FIELDS = {
    "prepare": {"image_id", "decision_generation", "graph_sha256", "dive_generation",
                "overlay_sha256", "policy_id", "policy_path", "policy_sha256",
                "worklist_path", "worklist_sha256", "chain_count",
                "open_precondition_count"},
    "record": {"image_id", "decision_generation", "result_path", "result_sha256",
               "chain_count", "bench_test_count", "script_count", "recorded"},
    "check": {"image_id", "decision_generation", "decision", "primary_reason",
              "reason_codes", "chain_count", "bench_test_count", "script_count",
              "policy_match_count", "package_path", "package_sha256", "complete"},
}


@pytest.mark.parametrize("flags", [
    [], ["--prepare", "--record", "r"], ["--record", "r", "--check"],
    ["--prepare", "--check"],
])
def test_syntax_errors_precede_database_access(tmp_path, monkeypatch, flags):
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: pytest.fail("database opened"))
    with pytest.raises(SystemExit) as exc:
        audit.main(["decide", "--run", str(tmp_path / "run"), *flags])
    assert exc.value.code == 2


@pytest.mark.parametrize("flags,message", [
    (["--prepare", "--policy", "p"], "--root is required"),
    (["--prepare", "--root", "r"], "--policy is required"),
    (["--check"], "--root is required"),
    (["--record", "result", "--root", "r"], "--root"),
    (["--record", "result", "--policy", "p"], "--policy"),
    (["--check", "--root", "r", "--policy", "p"], "--policy"),
    (["--record", "result", "--image-id", "image"], "--image-id"),
])
def test_semantic_errors_precede_database_access(tmp_path, monkeypatch, capsys, flags, message):
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: pytest.fail("database opened"))
    assert audit.main(["decide", "--run", str(tmp_path / "run"), *flags]) == 1
    assert message in capsys.readouterr().err


def _summary(mode, root):
    common = {"image_id": "image", "decision_generation": "a" * 64}
    if mode == "prepare":
        common.update(graph_sha256="b" * 64, dive_generation="c" * 64,
            overlay_sha256="d" * 64, policy_id="policy", policy_path="files/policy.json",
            policy_sha256="e" * 64, worklist_path="files/worklist.json",
            worklist_sha256="f" * 64, chain_count=2, open_precondition_count=1)
    elif mode == "record":
        common.update(result_path="files/result.json", result_sha256="b" * 64,
            chain_count=2, bench_test_count=1, script_count=1, recorded=True)
    else:
        common.update(decision="acquire", primary_reason="eligible-chain",
            reason_codes=("eligible-chain",), chain_count=2, bench_test_count=1,
            script_count=1, policy_match_count=1, package_path="artifacts/package.json",
            package_sha256="b" * 64, complete=True)
    return SimpleNamespace(**common)


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
@pytest.mark.parametrize("json_output", [False, True])
def test_exact_delegation_and_bounded_output(tmp_path, monkeypatch, capsys, mode, json_output):
    run, root = tmp_path / "run", tmp_path / "PRIVATE_ROOT"
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    result = _summary(mode, root)
    def delegated(connection, run_dir, *args, **kwargs):
        assert connection is con and run_dir == run
        if mode == "prepare":
            assert args == (root, pathlib.Path("policy.json")) and kwargs == {"image_id": "image"}
        elif mode == "record":
            assert args == (pathlib.Path("result.json"),) and kwargs == {}
        else:
            assert args == (root,) and kwargs == {"image_id": "image"}
        return result
    target = (firmware_decide_results, "record") if mode == "record" else (firmware_decide, mode)
    monkeypatch.setattr(*target, delegated)
    flags = ["--" + mode]
    if mode == "record": flags += ["result.json"]
    else: flags += ["--root", str(root), "--image-id", "image"]
    if mode == "prepare": flags += ["--policy", "policy.json"]
    if json_output: flags += ["--json"]
    assert audit.main(["decide", "--run", str(run), *flags]) == 0
    out = capsys.readouterr()
    assert out.err == ""
    if json_output:
        payload = json.loads(out.out)
        assert set(payload) == FIELDS[mode]
        assert "PRIVATE_ROOT" not in out.out
    else:
        assert out.out.isascii() and "PRIVATE_ROOT" not in out.out
        assert all(len(line) <= 512 for line in out.out.splitlines())
    with pytest.raises(sqlite3.ProgrammingError): con.execute("SELECT 1")


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
@pytest.mark.parametrize("image_id", ["路由器|r1|target", "image\n\x1b\t\"", "x" * 800])
@pytest.mark.parametrize("json_output", [False, True])
def test_public_identity_round_trips_json_and_human_output_stays_bounded(
        tmp_path, monkeypatch, capsys, mode, image_id, json_output):
    root = tmp_path / "PRIVATE_ROOT"
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    summary = _summary(mode, root)
    summary.image_id = image_id + str(root)
    path_field = {"prepare": "worklist_path", "record": "result_path",
                  "check": "package_path"}[mode]
    # Valid run-relative paths may share a root prefix and contain Unicode.
    path = "files/" + str(root).lstrip("/") + "/雪/" + "/".join(["x" * 200] * 3) + ".json"
    setattr(summary, path_field, path)
    target = (firmware_decide_results, "record") if mode == "record" else (firmware_decide, mode)
    monkeypatch.setattr(*target, lambda *a, **k: summary)
    flags = ["--record", "result.json"] if mode == "record" else ["--" + mode, "--root", str(root)]
    if mode == "prepare":
        flags += ["--policy", "policy.json"]
    if json_output:
        flags += ["--json"]
    assert audit.main(["decide", "--run", str(tmp_path / "run"), *flags]) == 0
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
    ("prepare", firmware_decide.FirmwareDecideError),
    ("record", firmware_decide_results.FirmwareDecideResultError),
    ("check", db.DbError), ("check", sqlite3.OperationalError), ("check", OSError),
])
def test_expected_errors_are_bounded(tmp_path, monkeypatch, capsys, mode, error_type):
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    root = tmp_path / "PRIVATE_ROOT"
    def fail(*args, **kwargs):
        raise error_type(f"cannot use {root}: private\n\x1b" + "x" * 1000)
    target = (firmware_decide_results, "record") if mode == "record" else (firmware_decide, mode)
    monkeypatch.setattr(*target, fail)
    flags = ["--" + mode]
    if mode == "record": flags += ["result.json"]
    else: flags += ["--root", str(root)]
    if mode == "prepare": flags += ["--policy", "policy.json"]
    assert audit.main(["decide", "--run", str(tmp_path / "run"), *flags]) == 1
    out = capsys.readouterr()
    assert out.out == "" and out.err.isascii() and len(out.err) <= 513
    if error_type is sqlite3.OperationalError:
        assert out.err == "decide: database operation failed\n"
    elif mode != "record":
        assert str(root) not in out.err
