import json
import pathlib
import subprocess
import sys

import pytest

from audit_core import preflight

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_write_config_emits_mcpServers_shape(tmp_path):
    out = tmp_path / ".audit-mcp.json"
    preflight.write_config(out, {"autorev": {"command": "autorev-mcp"}})
    payload = json.loads(out.read_text())
    assert payload == {"mcpServers": {"autorev": {"command": "autorev-mcp"}}}


def test_write_config_refuses_to_clobber(tmp_path):
    """Review Focus 3: a user's MCP config is theirs, not ours."""
    out = tmp_path / ".audit-mcp.json"
    out.write_text('{"mcpServers": {"theirs": {}}}')
    with pytest.raises(FileExistsError):
        preflight.write_config(out, {"autorev": {"command": "x"}})
    assert json.loads(out.read_text())["mcpServers"] == {"theirs": {}}


def test_write_config_force_overwrites(tmp_path):
    out = tmp_path / ".audit-mcp.json"
    out.write_text('{"mcpServers": {"theirs": {}}}')
    preflight.write_config(out, {"autorev": {"command": "x"}}, force=True)
    assert "autorev" in json.loads(out.read_text())["mcpServers"]


def test_launch_command_names_both_flags(tmp_path):
    cmd = preflight.launch_command(tmp_path / ".audit-mcp.json")
    assert "--strict-mcp-config" in cmd
    assert "--mcp-config" in cmd


def test_cli_preflight_writes_and_prints(tmp_path):
    out = tmp_path / ".audit-mcp.json"
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight",
         "--out", str(out), "--server", "autorev=autorev-mcp"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert "--strict-mcp-config" in r.stdout
    assert json.loads(out.read_text())["mcpServers"]["autorev"]["command"] == "autorev-mcp"


def test_cli_preflight_exits_one_on_existing_file(tmp_path):
    out = tmp_path / ".audit-mcp.json"
    out.write_text("{}")
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight",
         "--out", str(out), "--server", "autorev=autorev-mcp"],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "exists" in (r.stdout + r.stderr).lower()


def test_cli_preflight_rejects_malformed_server_spec(tmp_path):
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight",
         "--out", str(tmp_path / "c.json"), "--server", "noequalssign"],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "NAME=COMMAND" in (r.stdout + r.stderr)
