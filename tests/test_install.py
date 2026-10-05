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
