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


# --- I1: a real server definition, not just {"command": ...} -----------------

AUTOREV_STDIO = {
    "type": "stdio",
    "command": "uv",
    "args": ["run", "--directory", "/opt/autorev", "autorev-mcp"],
    "env": {"IDA_DIR": "/opt/ida"},
}
REMOTE_SSE = {"type": "sse", "url": "https://mcp.example.test/sse"}


def _source_config(tmp_path):
    src = tmp_path / "mcp.json"
    src.write_text(json.dumps({"mcpServers": {
        "autorev": AUTOREV_STDIO,
        "remote": REMOTE_SSE,
        "unwanted": {"command": "noise"},
    }}))
    return src


def test_load_servers_copies_the_whole_object_verbatim(tmp_path):
    """`{"command": command}` cannot express a real server. The autorev server
    R4 names as its example has type, command, args AND env; an SSE server has
    no command at all. A config built from a command string yields a strict
    run with zero working servers - the opposite of R4's purpose."""
    got = preflight.load_servers(_source_config(tmp_path), ["autorev", "remote"])
    assert got == {"autorev": AUTOREV_STDIO, "remote": REMOTE_SSE}


def test_load_servers_deep_copies(tmp_path):
    got = preflight.load_servers(_source_config(tmp_path), ["autorev"])
    got["autorev"]["args"].append("mutated")
    assert preflight.load_servers(
        _source_config(tmp_path), ["autorev"])["autorev"] == AUTOREV_STDIO


def test_load_servers_names_the_missing_server(tmp_path):
    with pytest.raises(preflight.PreflightError) as exc:
        preflight.load_servers(_source_config(tmp_path), ["nosuch"])
    assert "nosuch" in str(exc.value)
    assert "autorev" in str(exc.value)


def test_load_servers_rejects_a_missing_file(tmp_path):
    with pytest.raises(preflight.PreflightError):
        preflight.load_servers(tmp_path / "absent.json", ["autorev"])


def test_load_servers_rejects_a_config_without_mcpServers(tmp_path):
    src = tmp_path / "mcp.json"
    src.write_text('{"servers": {}}')
    with pytest.raises(preflight.PreflightError) as exc:
        preflight.load_servers(src, ["autorev"])
    assert "mcpServers" in str(exc.value)


def test_cli_preflight_keeps_a_server_from_an_existing_config(tmp_path):
    src = _source_config(tmp_path)
    out = tmp_path / ".audit-mcp.json"
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight", "--out", str(out),
         "--from-config", str(src), "--keep", "autorev"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    written = json.loads(out.read_text())["mcpServers"]
    assert written == {"autorev": AUTOREV_STDIO}
    assert "unwanted" not in written


def test_cli_preflight_still_supports_the_simple_server_form(tmp_path):
    out = tmp_path / ".audit-mcp.json"
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight", "--out", str(out),
         "--server", "simple=simple-mcp"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text())["mcpServers"] == {
        "simple": {"command": "simple-mcp"}}


def test_cli_preflight_exits_one_when_the_named_server_is_absent(tmp_path):
    src = _source_config(tmp_path)
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight",
         "--out", str(tmp_path / "c.json"),
         "--from-config", str(src), "--keep", "nosuch"],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "nosuch" in (r.stdout + r.stderr)


def test_cli_preflight_warns_when_it_writes_zero_servers(tmp_path):
    """An empty config is legitimate only when the target needs no MCP tooling.
    Silently handing a strict relaunch zero servers is how binary analysis got
    disabled without anyone noticing."""
    out = tmp_path / ".audit-mcp.json"
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight", "--out", str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert "warning" in r.stderr.lower()
    assert json.loads(out.read_text())["mcpServers"] == {}


def test_server_merges_over_a_kept_definition(tmp_path):
    """Reproduced 2026-10-07: `--keep autorev --server autorev=uvx` wrote
    {"command": "uvx"} and exited 0, discarding args and env.

    That is the exact degradation load_servers' docstring says --keep exists
    to prevent - a config --strict-mcp-config accepts and that then exposes a
    server which cannot start. On a firmware audit it is the IDA server
    arriving broken with no warning."""
    src = tmp_path / "src.json"
    src.write_text(json.dumps({"mcpServers": {"autorev": {
        "command": "uvx", "args": ["autorev-mcp", "--db", "x.i64"],
        "env": {"K": "v"}}}}))
    out = tmp_path / "out.json"
    p = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight",
         "--from-config", str(src), "--keep", "autorev",
         "--server", "autorev=uvx-new", "--out", str(out)],
        capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    server = json.loads(out.read_text())["mcpServers"]["autorev"]
    assert server["command"] == "uvx-new"       # the override applies
    assert server["args"] == ["autorev-mcp", "--db", "x.i64"]   # nothing else lost
    assert server["env"] == {"K": "v"}


def test_server_without_a_kept_definition_is_still_a_bare_command():
    """The untested half. A --server naming something --keep never copied
    must still produce a working single-key definition."""
    assert preflight.merge_server(None, "uvx") == {"command": "uvx"}
    assert preflight.merge_server({}, "uvx") == {"command": "uvx"}


def test_merge_does_not_mutate_the_kept_definition():
    kept = {"command": "old", "args": ["a"]}
    merged = preflight.merge_server(kept, "new")
    assert kept == {"command": "old", "args": ["a"]}
    assert merged["command"] == "new"
    assert merged["args"] == ["a"]
