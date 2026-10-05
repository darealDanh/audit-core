import pathlib
import re

import pytest

from audit_core import briefs

TEMPLATES = sorted(briefs.TEMPLATE_DIR.glob("*-brief.md"))
PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")

RETURN_CONTRACT = "rows=<n> artifact="


def test_three_templates_exist():
    names = {p.name for p in TEMPLATES}
    assert names == {"recon-brief.md", "audit-brief.md", "fpcheck-brief.md"}


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_every_template_states_the_return_contract(path):
    assert RETURN_CONTRACT in path.read_text(), (
        f"{path.name} must carry the R2 one-line return contract")


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_every_template_renders_with_its_declared_variables(path):
    text = path.read_text()
    names = sorted(set(PLACEHOLDER.findall(text)))
    filled = {n: f"<{n}>" for n in names}
    out = briefs.render(text, filled)
    assert not PLACEHOLDER.search(out)


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_no_template_tells_the_agent_to_return_findings_inline(path):
    text = path.read_text().lower()
    for banned in ("return findings as a markdown list",
                   "return a structured markdown document"):
        assert banned not in text, f"{path.name} still asks for an inline dump"


def test_write_brief_resolves_the_real_template_dir_by_default(tmp_path):
    """The default TEMPLATE_DIR path is what the workflows use; nothing else
    exercises it, because every other test passes template_dir explicitly."""
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    path = briefs.write_brief("audit", "G7", run, {
        "group_id": "G7", "group_name": "n", "run_dir": str(run),
        "mapping_path": "m.md", "artifact_path": "a.md",
        "source_access": "s", "known_findings": "k",
    })
    assert path.is_file()
    assert "G7" in path.read_text()
