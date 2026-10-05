import pathlib
import subprocess
import sys

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
