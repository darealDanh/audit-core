# tests/test_cli_budget.py
import json, pathlib, subprocess, sys
from tests.fixtures import build as B

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args):
    return subprocess.run([sys.executable, str(ROOT / "audit.py"), *args],
                          capture_output=True, text=True)


def session(tmp_path) -> pathlib.Path:
    p = tmp_path / "s.jsonl"
    p.write_text(B.assistant([{"type": "text", "text": "a" * 400}], cache_read=50_000)
                 + B.assistant([], cache_read=70_000)
                 + B.cost_state(2.0))
    return p


def test_budget_report_prints_human_summary(tmp_path):
    r = run("budget", "--report", str(session(tmp_path)))
    assert r.returncode == 0, r.stderr
    assert "sum_context" in r.stdout
    assert "assistant_text" in r.stdout


def test_budget_report_json_is_machine_readable(tmp_path):
    r = run("budget", "--report", str(session(tmp_path)), "--json")
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert payload[0]["stats"]["sum_context"] == 120_000
    assert payload[0]["cost_usd"] == 2.0
    assert payload[0]["source_bytes"] == session(tmp_path).stat().st_size
    assert len(payload[0]["source_sha256"]) == 64


def test_missing_file_exits_one(tmp_path):
    r = run("budget", "--report", str(tmp_path / "nope.jsonl"))
    assert r.returncode == 1
    assert "not found" in (r.stdout + r.stderr).lower()
