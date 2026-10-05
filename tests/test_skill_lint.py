import pathlib
import subprocess
import sys

import pytest

from audit_core import skill_lint

ROOT = pathlib.Path(__file__).resolve().parent.parent
KNOWN = {"selftest", "budget", "bench", "init", "preflight", "brief", "lint-skill"}


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
