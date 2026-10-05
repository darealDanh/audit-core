import pathlib
import subprocess
import sys

import pytest

import audit
from audit_core import skill_lint

ROOT = pathlib.Path(__file__).resolve().parent.parent
# The set `audit.py lint-skill` itself passes (cmd_lint_skill: set(HANDLERS)).
# This was a hand-copied literal and went stale the moment Stage 2 added a
# verb: every real verb the shipped prose started naming was reported as "not
# a real verb" by the test while the shipped command accepted it.
KNOWN = set(audit.HANDLERS)


def test_shipped_skill_passes_its_own_lint():
    assert skill_lint.lint(ROOT, KNOWN) == []


def test_unknown_verb_is_flagged(tmp_path):
    """Review Focus 1: a typo'd verb in prose ships silently and fails
    only mid-audit."""
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("see audit.py innit for setup")
    (tmp_path / "workflows" / "recon.md").write_text("x")
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert any(f.rule == "unknown-verb" and "innit" in f.detail for f in findings)


def test_inline_ddl_is_flagged(tmp_path):
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "workflows" / "audit.md").write_text("CREATE TABLE x (a INT);")
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert any(f.rule == "inline-ddl" for f in findings)


def test_template_without_return_contract_is_flagged(tmp_path):
    (tmp_path / "workflows").mkdir()
    briefs = tmp_path / "references" / "briefs"
    briefs.mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (briefs / "audit-brief.md").write_text("do the audit and tell me about it")
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert any(f.rule == "no-return-contract" for f in findings)


def test_blanket_model_mandate_is_flagged(tmp_path):
    """The only rule the brief's own test list never exercised. The real skill
    has zero occurrences of the mandate string, so the shipped-skill test
    cannot cover it either - a typo in BLANKET_MANDATE would ship silently."""
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "workflows" / "audit.md").write_text(
        "Use the strongest model your client offers for every subagent.")
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert any(f.rule == "blanket-model-mandate" for f in findings)


def test_blanket_model_mandate_is_not_flagged_in_skill_md(tmp_path):
    """SKILL.md is exempt on purpose: it may quote the old mandate in its
    rejection table. Pin the exemption so a later change cannot silently
    widen or lose it."""
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text(
        'Rejection: "use the strongest model your client offers" - tier it instead.')
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert not any(f.rule == "blanket-model-mandate" for f in findings)


def test_unsubstituted_skill_dir_is_flagged(tmp_path):
    """C1: `__SKILL_DIR__` is an installer sentinel. Surviving into installed
    content means `python3 __SKILL_DIR__/audit.py ...` is literally what the
    agent runs, and every audit.py command in that file is unrunnable."""
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "workflows" / "recon.md").write_text(
        "    python3 __SKILL_DIR__/audit.py init\n")
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert any(f.rule == "unsubstituted-skill-dir" and f.path.endswith("recon.md")
               for f in findings)


def test_unsubstituted_skill_dir_is_not_flagged_in_the_source_checkout(tmp_path):
    """The authoring side is where the sentinel belongs - install.sh is the
    thing that substitutes it. Its presence marks the source checkout; it is
    never copied into an install target."""
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "install.sh").write_text("#!/usr/bin/env bash\n")
    (tmp_path / "workflows" / "recon.md").write_text(
        "    python3 __SKILL_DIR__/audit.py init\n")
    assert skill_lint.lint(tmp_path, KNOWN) == []


def test_the_real_skill_still_carries_the_sentinel_for_the_installer():
    """If the templates ever stop carrying it, install-time substitution has
    silently become a no-op and the rule above can never fire."""
    text = (ROOT / "workflows" / "recon.md").read_text()
    assert skill_lint.SKILL_DIR_SENTINEL in text


def test_nested_skill_md_is_not_exempt_from_the_blanket_mandate(tmp_path):
    """The exemption keyed on `path.name`, so any nested SKILL.md anywhere in
    workflows/ or references/ got a free pass."""
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "workflows" / "SKILL.md").write_text(
        "Use the strongest model your client offers for every subagent.")
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert any(f.rule == "blanket-model-mandate" and f.path != "SKILL.md"
               for f in findings)


def test_lint_raises_on_a_missing_root(tmp_path):
    with pytest.raises(skill_lint.SkillLintError):
        skill_lint.lint(tmp_path / "nope", KNOWN)


def test_lint_raises_when_the_root_has_no_skill_md(tmp_path):
    with pytest.raises(skill_lint.SkillLintError):
        skill_lint.lint(tmp_path, KNOWN)


def test_cli_lint_skill_exits_non_zero_on_a_missing_root(tmp_path):
    """Deferred minor 133: it printed 'clean' and exited 0 about a path it
    never read - the exact failure the verb exists to prevent."""
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "lint-skill",
         "--root", str(tmp_path / "nonexistent")],
        capture_output=True, text=True)
    assert r.returncode != 0
    assert "clean" not in r.stdout.lower()
    assert "no such skill root" in (r.stdout + r.stderr)


def test_cli_lint_skill_exits_non_zero_when_root_has_no_skill_md(tmp_path):
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "lint-skill", "--root", str(tmp_path)],
        capture_output=True, text=True)
    assert r.returncode != 0
    assert "clean" not in r.stdout.lower()
    assert "SKILL.md" in (r.stdout + r.stderr)


def test_archived_workflows_are_ignored(tmp_path):
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "workflows" / "_old-archive.md").write_text("CREATE TABLE x (a INT);")
    assert skill_lint.lint(tmp_path, KNOWN) == []


def test_cli_lint_skill_exits_zero_on_the_real_skill():
    r = subprocess.run([sys.executable, str(ROOT / "audit.py"), "lint-skill"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clean" in r.stdout.lower()


def test_cli_lint_skill_exits_one_when_findings_exist(tmp_path):
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "workflows" / "audit.md").write_text("CREATE TABLE x (a INT);")
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "lint-skill", "--root", str(tmp_path)],
        capture_output=True, text=True)
    assert r.returncode == 1
    assert "inline-ddl" in r.stdout


def test_a_retired_status_query_in_prose_is_a_finding(tmp_path):
    """One rule, one specific past mistake: the three SELECTs the resume-note
    template carried, retyped after every compaction restart. This does NOT
    try to detect hand-written SQL in general - a fuzzy linter over English
    produces false positives on legitimate text and gets disabled."""
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        'sqlite3 audit.db "SELECT group_id, severity, COUNT(*) FROM cba_findings '
        'GROUP BY 1,2;"\n')
    findings = skill_lint.lint(root, KNOWN)
    assert [f.rule for f in findings] == ["hand-typed-status-sql"]
    assert "audit.py status" in findings[0].detail


def test_the_rule_ignores_whitespace_differences(tmp_path):
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        "SELECT id,name,status FROM cba_feature_groups\n")
    assert [f.rule for f in skill_lint.lint(root, KNOWN)] == \
        ["hand-typed-status-sql"]


def test_an_audit_py_status_invocation_is_not_a_finding(tmp_path):
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        "python3 /x/audit.py status --db audit.db\n")
    assert skill_lint.lint(root, KNOWN) == []


def test_mentioning_a_table_name_in_prose_is_not_a_finding(tmp_path):
    """The scope statement, enforced: this rule pins four literal queries, not
    the idea of SQL."""
    root = tmp_path / "skill"
    (root / "workflows").mkdir(parents=True)
    (root / "SKILL.md").write_text("# skill\n")
    (root / "workflows" / "x.md").write_text(
        "Rows land in `cba_findings`; counts come from `cba_fp_verdicts`.\n")
    assert skill_lint.lint(root, KNOWN) == []
