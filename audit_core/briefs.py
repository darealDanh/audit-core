"""Render a subagent dispatch brief from a template.

Dispatch prompts are the largest single category of tool-call input - 196,996
tokens over 117 dispatches in the measured sessions, averaging 1,684 each -
and most of each one is boilerplate the orchestrator retyped. Rendering from a
template on disk means the dispatch carries a path, not the template. See
spec rule R6.
"""
from __future__ import annotations

import pathlib
import re

TEMPLATE_DIR = pathlib.Path(__file__).resolve().parent.parent / "references" / "briefs"

# A placeholder is {name} where name is an identifier. This deliberately does
# not match ${HOME}, {} or {"json": ...}.
_PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")


class BriefError(Exception):
    """A brief template is missing, or a placeholder was left unfilled."""


def render(template_text: str,
           variables: dict[str, str],
           allow_empty: bool = False) -> str:
    """Fill every `{placeholder}` the template declares.

    An empty value is rejected as hard as a missing one. `--var source_access=`
    renders a brief whose "Source access" section is blank, and the subagent
    then has to guess where the code is - the same failure as an unfilled
    placeholder, except the renderer reported success. Genuinely empty
    sections (source mode has no known findings yet) pass `allow_empty=True`.
    """
    missing: list[str] = []
    empty: list[str] = []

    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in variables:
            missing.append(name)
            return match.group(0)
        value = str(variables[name])
        if not allow_empty and not value.strip():
            empty.append(name)
        return value

    out = _PLACEHOLDER.sub(replace, template_text)
    if missing:
        raise BriefError(
            "unsubstituted placeholder(s): " + ", ".join(sorted(set(missing))))
    if empty:
        raise BriefError(
            "empty value for placeholder(s): " + ", ".join(sorted(set(empty)))
            + " (pass --allow-empty if the section is genuinely empty)")
    return out


def write_brief(phase: str,
                unit: str,
                run_dir: str | pathlib.Path,
                variables: dict[str, str],
                template_dir: str | pathlib.Path | None = None,
                allow_empty: bool = False) -> pathlib.Path:
    tpl_dir = pathlib.Path(template_dir) if template_dir else TEMPLATE_DIR
    template = tpl_dir / f"{phase}-brief.md"
    if not template.is_file():
        raise BriefError(f"no brief template for phase {phase!r} at {template}")
    out_dir = pathlib.Path(run_dir) / "briefs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{phase}-{unit}-brief.md"
    out.write_text(render(template.read_text(), variables,
                          allow_empty=allow_empty))
    return out
