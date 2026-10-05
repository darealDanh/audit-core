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
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "CODEX_HOME": str(home / ".codex")}
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
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "CODEX_HOME": str(home / ".codex")}
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
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "CODEX_HOME": str(home / ".codex")}
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


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_install_sh_refuses_when_the_source_dir_is_the_install_dir(tmp_path):
    """Cloning the repo straight into a per-client skill dir used to be
    documented as supported: the installer printed "(source dir IS install dir;
    skipping skill file copy)", returned 0 and said "Done." -- while every
    __SKILL_DIR__ in the tree survived, so all ten documented `audit.py`
    commands were unrunnable. `lint-skill` could not catch it either, because
    its unsubstituted-skill-dir rule exempts any tree with install.sh at its
    root, which a clone-in-place tree has. Substitution cannot run in place
    without rewriting the checkout, so the configuration is refused instead."""
    home = tmp_path / "home"
    target = home / ".claude" / "skills" / "codebase-audit"
    target.parent.mkdir(parents=True)
    # A clone-in-place tree: the repo checked out AT the install location.
    shutil.copytree(ROOT, target,
                    ignore=shutil.ignore_patterns(".git", "__pycache__",
                                                  ".pytest_cache"))
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "CODEX_HOME": str(home / ".codex")}
    r = subprocess.run(
        ["bash", str(target / "install.sh"), "claude"],
        capture_output=True, text=True, env=env, cwd=str(target),
    )
    assert r.returncode != 0, (
        "install.sh accepted a clone-in-place install:\n" + r.stdout + r.stderr)
    out = r.stdout + r.stderr
    assert "source directory IS the install directory" in out, out
    assert "__SKILL_DIR__" in out, out
    assert "separate checkout" in out, out
    assert "Done." not in out, "the installer still claimed success"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_install_removes_a_workflow_deleted_from_the_repo(tmp_path):
    """Carried from Stage 1: install.ps1 prunes, install.sh did not, so a
    file deleted from the repo lingered in a .sh-installed tree forever."""
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "CODEX_HOME": str(home / ".codex")}
    r = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "claude"],
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    target = home / ".claude" / "skills" / "codebase-audit"

    stale = target / "workflows" / "ghost.md"
    stale.write_text("left over from an older install\n")
    stale_ref = target / "references" / "ghost.md"
    stale_ref.write_text("also stale\n")

    r2 = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "claude"],
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert not stale.exists()
    assert not stale_ref.exists()
    assert (target / "workflows" / "audit.md").is_file()


def test_readme_does_not_document_cloning_into_an_install_dir():
    """README used to present clone-in-place as a supported configuration."""
    text = (ROOT / "README.md").read_text()
    assert "skips the skill-file copy" not in text
    assert "Do not clone into an install dir" in text
