"""Write a project-scoped MCP config naming only the servers a run needs.

Unused MCP tool schemas sit in the resident prefix, which is 20.9% of
measured context cost, and deferred-tool records are charged again in
accumulation. See spec rule R4.
"""
from __future__ import annotations

import copy
import json
import pathlib

MCP_CONFIG_NAME = ".audit-mcp.json"


class PreflightError(Exception):
    """An MCP source config is missing, malformed, or lacks a requested server."""


def load_servers(config_path: str | pathlib.Path,
                 names: list[str]) -> dict[str, dict]:
    """Copy the named server objects verbatim out of an existing MCP config.

    A real server definition is never just `{"command": ...}`: a stdio server
    carries `args` and usually `env`, and an SSE/HTTP server carries `type` and
    `url` instead. Re-deriving one from a command string produces a config that
    `--strict-mcp-config` accepts and that then exposes zero working servers,
    which silently disables the tooling R4 exists to keep.
    """
    config_path = pathlib.Path(config_path).expanduser()
    if not config_path.is_file():
        raise PreflightError(f"not found: {config_path}")
    try:
        payload = json.loads(config_path.read_text())
    except json.JSONDecodeError as exc:
        raise PreflightError(f"{config_path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PreflightError(f"{config_path} does not contain a JSON object")
    found = payload.get("mcpServers")
    if not isinstance(found, dict):
        raise PreflightError(f"{config_path} has no `mcpServers` object")

    out: dict[str, dict] = {}
    for name in names:
        if name not in found:
            raise PreflightError(
                f"{config_path} has no server named {name!r}; it defines: "
                + (", ".join(sorted(found)) or "(none)"))
        server = found[name]
        if not isinstance(server, dict):
            raise PreflightError(
                f"server {name!r} in {config_path} is not a JSON object")
        out[name] = copy.deepcopy(server)
    return out


def write_config(path: str | pathlib.Path,
                 servers: dict[str, dict],
                 force: bool = False) -> None:
    path = pathlib.Path(path)
    if path.exists() and not force:
        raise FileExistsError(
            f"{path} exists; refusing to overwrite an MCP config we did not write "
            f"(pass --force to replace it)")
    path.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n")


def launch_command(config_path: str | pathlib.Path) -> str:
    return f"claude --strict-mcp-config --mcp-config {pathlib.Path(config_path)}"


def merge_server(kept: dict | None, command: str) -> dict:
    """Apply a `--server NAME=COMMAND` override to a kept definition.

    Replacing the whole object discards `args` and `env`, which is exactly
    the degradation `load_servers` exists to prevent: the result is a config
    `--strict-mcp-config` accepts and that then exposes a server unable to
    start. Overriding the command alone keeps the rest.
    """
    if not kept:
        return {"command": command}
    merged = dict(kept)
    merged["command"] = command
    return merged
