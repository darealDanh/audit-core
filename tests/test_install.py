# tests/test_install.py
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_install_sh_copies_the_tool_and_selftest_passes(tmp_path):
    """Review Focus 4: an installed copy without audit_core/ loads fine and
    then dies at the first audit.py call. The install must fail loudly."""
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude")}
    r = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "claude"],
        capture_output=True, text=True,
        env=env,
        cwd=str(ROOT),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    target = home / ".claude" / "skills" / "codebase-audit"
    assert (target / "SKILL.md").is_file()
    assert (target / "workflows").is_dir()
    assert (target / "references").is_dir()
    assert (target / "audit.py").is_file()
    assert (target / "audit_core" / "__init__.py").is_file()
    assert (target / "audit_core" / "schema.sql").is_file()

    s = subprocess.run([sys.executable, str(target / "audit.py"), "selftest"],
                       capture_output=True, text=True)
    assert s.returncode == 0, s.stderr
    assert "audit_core" in s.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_installed_skill_content_has_no_unsubstituted_skill_dir(tmp_path):
    """C1: `copy_template` only ever ran on the Claude launchers, so every
    `python3 __SKILL_DIR__/audit.py ...` in SKILL.md, workflows/ and
    references/ shipped literally and died with
    "can't open file '.../__SKILL_DIR__/audit.py'"."""
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude")}
    r = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "claude"],
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    target = home / ".claude" / "skills" / "codebase-audit"

    # The subdirectory is load-bearing: briefs.TEMPLATE_DIR resolves there, so
    # `audit.py brief` fails outright if install drops or nests it.
    assert (target / "references" / "briefs" / "audit-brief.md").is_file()

    offenders = []
    candidates = [target / "SKILL.md"]
    candidates += sorted((target / "workflows").rglob("*.md"))
    candidates += sorted((target / "references").rglob("*.md"))
    for path in candidates:
        if "__SKILL_DIR__" in path.read_text():
            offenders.append(str(path.relative_to(target)))
    assert offenders == [], f"unsubstituted __SKILL_DIR__ in: {offenders}"

    # ...and the substitution landed on the install dir, not on nothing.
    assert str(target) in (target / "workflows" / "recon.md").read_text()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_install_preserves_crlf_in_the_files_that_use_it(tmp_path):
    """sed is line-content oriented, so substitution must not normalise CRLF.
    Three files ship with CRLF and must keep it."""
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude")}
    r = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "claude"],
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    target = home / ".claude" / "skills" / "codebase-audit"
    for rel in ("SKILL.md",
                "references/phase0-source-detection.md",
                "references/phase2-feature-mapping.md",
                "references/phase4-deep-audit.md",
                "references/phase5-fp-check.md"):
        src = (ROOT / rel).read_bytes()
        dst = (target / rel).read_bytes()
        if b"\r\n" not in src:
            continue
        assert b"\r\n" in dst, f"{rel} lost its CRLF line endings on install"
        assert src.count(b"\r\n") == dst.count(b"\r\n"), rel


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_install_sh_covers_both_codex_directories(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "CODEX_HOME": str(home / ".codex")}
    r = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "codex"],
        capture_output=True, text=True,
        env=env,
        cwd=str(ROOT),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    for d in (home / ".agents" / "skills", home / ".codex" / "skills"):
        assert (d / "codebase-audit" / "audit.py").is_file(), f"missing under {d}"
