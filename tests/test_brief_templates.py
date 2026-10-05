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
        "test_instance": "No test instance available.",
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


def _section(text: str, heading: str) -> str:
    """The body under a `## heading`, up to the next `## `."""
    start = text.index(heading) + len(heading)
    rest = text[start:]
    end = rest.find("\n## ")
    return rest if end == -1 else rest[:end]


def test_audit_brief_keeps_every_hunt_category():
    """The prompt this template replaced listed 16 categories. Writing the
    template from scratch dropped six of them, including XXE and CSRF.

    Scoped to the hunt section: counting every `^\\d+. ` line in the file also
    swept up the six rules of engagement, so the assertion would still have
    passed with only 10 hunt categories left."""
    text = (briefs.TEMPLATE_DIR / "audit-brief.md").read_text()
    hunt = _section(text, "## What to hunt")
    assert len(re.findall(r"^\d+\. ", hunt, re.M)) == 16
    for term in ("Information disclosure", "CSRF", "XXE", "Header injection",
                 "Configuration weaknesses", "Information leakage"):
        assert term in hunt, f"audit-brief.md no longer mentions {term}"


def test_audit_brief_keeps_the_quality_narrowings():
    """Each term below names a vulnerability class or a gate that the old
    prompt carried and the rewritten template dropped. Quality is the binding
    constraint for this stage, so each one is pinned by name."""
    text = (briefs.TEMPLATE_DIR / "audit-brief.md").read_text()
    hunt = _section(text, "## What to hunt")

    # Authorization bypass must name IDOR; resource exhaustion must name
    # algorithmic complexity, and must NOT pre-filter the hunt with an
    # amplification-factor rule (that is a false-positive rule, not a hunt rule).
    assert "IDOR" in hunt
    assert "algorithmic complexity" in hunt.lower()
    assert "amplification factor" not in text.lower()

    rules = _section(text, "## Rules of engagement")
    for item in ("Input validation",
                 "WAF rule or middleware",
                 "framework feature",
                 "Parameterized queries"):
        assert item in rules, f"mitigation checklist lost {item!r}"

    # rows=0 is not a coverage statement.
    assert "zero vulnerabilities" in text
    assert "every entry point you reviewed" in text

    # SKILL.md documents cba_findings.artifact_path; something must instruct the
    # agent to WRITE that column. Asserting on the bare token "artifact_path"
    # could never fail: the section already said "the detailed write-up to
    # {artifact_path}" before the instruction was restored. Pin the restored
    # sentence's own words instead.
    # Whitespace-normalised: the sentence wraps mid-phrase in the template.
    output = " ".join(_section(text, "## Where your output goes").split())
    assert "Set each row's `artifact_path` column to" in output, (
        "audit-brief.md no longer tells the agent to populate "
        "cba_findings.artifact_path")


def test_audit_brief_carries_the_patch_bypass_probe_instruction():
    """workflows/audit.md calls patch-bypass mining the HIGH-VALUE STEP and
    gates the phase exit on it having been probed. Nothing dispatched that."""
    text = (briefs.TEMPLATE_DIR / "audit-brief.md").read_text()
    assert "## Known findings and patch-bypass surface" in text
    assert "sibling or adjacent site" in text
    assert "highest-severity findings" in text


def test_audit_brief_carries_the_live_poc_conduct_rules():
    """The old phase4 prompt had an `If a Test Instance is Available` block
    with an explicit Do NOT list. The template had no test-instance section at
    all, and the dispatch bullets carried none of the prohibitions."""
    text = (briefs.TEMPLATE_DIR / "audit-brief.md").read_text()
    assert "{test_instance}" in text
    for prohibition in ("Exfiltrate real data",
                        "Crash the instance permanently",
                        "Modify admin credentials",
                        "Install persistence"):
        assert prohibition in text, f"audit-brief.md lost {prohibition!r}"


def test_fpcheck_brief_step_six_traces_data_flow():
    """HE-1 is "no source-to-sink data flow demonstrated", so the step that
    produces that evidence cannot be a re-read alone."""
    text = (briefs.TEMPLATE_DIR / "fpcheck-brief.md").read_text()
    assert "Trace the actual data flow in source code" in text


def test_fpcheck_brief_keeps_every_method_step():
    """The methodology this template replaced had 9 steps. Two defence-in-depth
    gates - the confidence threshold and the devil's advocate review - were lost."""
    text = (briefs.TEMPLATE_DIR / "fpcheck-brief.md").read_text()
    assert len(re.findall(r"^\d+\. ", text, re.M)) == 9
    assert "confidence threshold" in text.lower()
    assert "devil's advocate" in text.lower()
