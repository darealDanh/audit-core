"""Write a project-scoped MCP config naming only the servers a run needs.

Unused MCP tool schemas sit in the resident prefix, which is 20.9% of
measured context cost, and deferred-tool records are charged again in
accumulation. See spec rule R4.
"""
from __future__ import annotations

import json
import pathlib

MCP_CONFIG_NAME = ".audit-mcp.json"


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
