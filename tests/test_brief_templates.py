import pathlib
import re

import pytest

from audit_core import briefs

TEMPLATES = sorted(briefs.TEMPLATE_DIR.glob("*-brief.md"))
PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")

RETURN_CONTRACT = "rows=<n> artifact="

FP_RULES = pathlib.Path(__file__).resolve().parent.parent / "references" / "phase5-fp-check.md"


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


def test_fp_rule_counts_are_intact():
    """The spec names 18 Hard Exclusions, 10 Precedent rules and 3 Capability
    Validity checks as machinery that must survive any refactor, with a
    rule-count assertion as its proof. An earlier draft of this task's brief
    would have deleted all of them with the prompt fence they lived in."""
    text = FP_RULES.read_text()
    assert len(re.findall(r"^HE-\d+", text, re.M)) == 18
    assert len(re.findall(r"^PR-\d+", text, re.M)) == 10
    assert len(re.findall(r"^CV-\d+", text, re.M)) == 3


def test_fp_rules_are_documentation_not_a_prompt_literal():
    """They must live as real markdown, not frozen inside a fenced block that a
    later edit could delete as 'the prompt template'."""
    inside = outside = 0
    in_fence = False
    for line in FP_RULES.read_text(newline="").split("\n"):
        stripped = line.rstrip("\r")
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if re.match(r"^(HE|PR|CV)-\d", stripped):
            if in_fence:
                inside += 1
            else:
                outside += 1
    assert inside == 0, f"{inside} FP rule lines are trapped inside a fenced block"
    assert outside == 31


def test_fpcheck_brief_cross_reference_resolves():
    """fpcheck-brief.md sends the agent to phase5-fp-check.md for the rules."""
    brief_text = (briefs.TEMPLATE_DIR / "fpcheck-brief.md").read_text()
    assert "references/phase5-fp-check.md" in brief_text
    assert FP_RULES.is_file()


def test_audit_brief_keeps_every_hunt_category():
    """The prompt this template replaced listed 16 categories. Writing the
    template from scratch dropped six of them, including XXE and CSRF."""
    text = (briefs.TEMPLATE_DIR / "audit-brief.md").read_text()
    assert len(re.findall(r"^\d+\. ", text, re.M)) >= 16
    for term in ("Information disclosure", "CSRF", "XXE", "Header injection",
                 "Configuration weaknesses", "Information leakage"):
        assert term in text, f"audit-brief.md no longer mentions {term}"


def test_fpcheck_brief_keeps_every_method_step():
    """The methodology this template replaced had 9 steps. Two defence-in-depth
    gates - the confidence threshold and the devil's advocate review - were lost."""
    text = (briefs.TEMPLATE_DIR / "fpcheck-brief.md").read_text()
    assert len(re.findall(r"^\d+\. ", text, re.M)) == 9
    assert "confidence threshold" in text.lower()
    assert "devil's advocate" in text.lower()
