"""Check the shipped skill against the economics contract.

The spec's own lesson is that prose discipline failed empirically: recon.md
already asked subagents for compact summaries, and 30k-token reports arrived
anyway. These checks make R2, R5 and R6 enforceable rather than aspirational.
"""
from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass

VERB_MENTION = re.compile(r"audit\.py\s+([a-z][a-z-]*)")
RETURN_CONTRACT = "rows=<n> artifact="
BLANKET_MANDATE = "strongest model your client offers"


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    path: str
    detail: str


def _live_markdown(root: pathlib.Path) -> list[pathlib.Path]:
    """Skill prose that ships. Archived files (leading underscore) are history."""
    out: list[pathlib.Path] = []
    skill = root / "SKILL.md"
    if skill.is_file():
        out.append(skill)
    for sub in ("workflows", "references"):
        d = root / sub
        if d.is_dir():
            out.extend(p for p in sorted(d.rglob("*.md"))
                       if not p.name.startswith("_"))
    return out


def lint(root: str | pathlib.Path, known_verbs: set[str]) -> list[Finding]:
    root = pathlib.Path(root)
    findings: list[Finding] = []

    for path in _live_markdown(root):
        rel = str(path.relative_to(root))
        text = path.read_text()

        for verb in sorted(set(VERB_MENTION.findall(text))):
            if verb not in known_verbs:
                findings.append(Finding(
                    "unknown-verb", rel,
                    f"prose names `audit.py {verb}`, which is not a real verb"))

        # Scoped to every live markdown file this walk covers (workflows/ and
        # references/), not just workflows/. references/phase0-source-detection.md
        # once carried a `CREATE TABLE IF NOT EXISTS cba_sources` block that a
        # workflows-only scope would have missed entirely.
        if "CREATE TABLE" in text:
            findings.append(Finding(
                "inline-ddl", rel,
                "inline DDL; the schema belongs in audit_core/schema.sql via audit.py init"))

        if BLANKET_MANDATE in text and path.name != "SKILL.md":
            findings.append(Finding(
                "blanket-model-mandate", rel,
                "mandates the strongest model for everything; tier it instead"))

    briefs = root / "references" / "briefs"
    if briefs.is_dir():
        for path in sorted(briefs.glob("*-brief.md")):
            if RETURN_CONTRACT not in path.read_text():
                findings.append(Finding(
                    "no-return-contract", str(path.relative_to(root)),
                    "brief template does not state the R2 one-line return contract"))

    return findings
