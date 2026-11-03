# tests/test_install.py
import os
import pathlib
import re
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
    assert (target / "audit_core" / "hunt_results.py").is_file()
    assert (target / "references" / "briefs" / "hunt-brief.md").is_file()
    assert (target / "references" / "briefs" / "firmware-dive-brief.md").is_file()
    for module in ("firmware_dive.py", "firmware_dive_questions.py",
                   "firmware_dive_acquisition.py", "firmware_dive_results.py"):
        assert (target / "audit_core" / module).is_file()

    s = subprocess.run([sys.executable, str(target / "audit.py"), "selftest"],
                       capture_output=True, text=True)
    assert s.returncode == 0, s.stderr
    assert "audit_core" in s.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_installed_hunt_brief_resolves_schema_and_renders_from_installed_tree(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "CODEX_HOME": str(home / ".codex")}
    install = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "claude"],
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    assert install.returncode == 0, install.stdout + install.stderr
    target = home / ".claude" / "skills" / "codebase-audit"
    template = target / "references" / "briefs" / "hunt-brief.md"
    template_text = template.read_text()
    assert "__SKILL_DIR__" not in template_text
    assert str(target) in template_text
    assert (target / "audit_core" / "hunt_results.py").is_file()

    run = tmp_path / "run"
    generation = run / "files" / "hunt" / ("a" * 64) / "l-dark"
    variables = {
        "run_dir": str(run), "db_path": str(run / "audit.db"),
        "rootfs": str(tmp_path / "rootfs"), "image_id": "target",
        "lane": "l-dark", "manifest_sha256": "b" * 64,
        "surface_snapshot_sha256": "c" * 64,
        "worklist_index": str(generation / "index.json"),
        "batch_path": str(generation / "batch-0001.json"),
        "result_path": str(run / "files" / "result.json"),
    }
    command = [sys.executable, str(target / "audit.py"), "brief", "--phase",
               "hunt", "--unit", "l-dark-batch-0001", "--run", str(run)]
    for name, value in variables.items():
        command.extend(["--var", f"{name}={value}"])
    rendered = subprocess.run(command, capture_output=True, text=True)
    assert rendered.returncode == 0, rendered.stderr
    output = run / "briefs" / "hunt-l-dark-batch-0001-brief.md"
    assert rendered.stdout == f"{output}\n"
    text = output.read_text()
    assert str(target / "audit_core" / "hunt_results.py") in text
    assert "__SKILL_DIR__" not in text
    assert str(target) in text
    assert not re.search(r"(?<!\$)\{[A-Za-z_][A-Za-z0-9_]*\}", text)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize("client", ("claude", "codex"))
def test_installed_firmware_review_resolves_rules_and_renders(tmp_path, client):
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "CODEX_HOME": str(home / ".codex")}
    installed = subprocess.run(["bash", str(ROOT / "install.sh"), client],
                               capture_output=True, text=True, env=env, cwd=ROOT)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    roots = [home / ".claude"] if client == "claude" else [home / ".agents", home / ".codex"]
    for directory in roots:
        target = directory / "skills" / "codebase-audit"
        run = directory / "run"
        variables = dict(run_dir=str(run), db_path=str(run / "audit.db"),
                         rootfs=str(tmp_path / "rootfs"), image_id="router-target",
                         candidate_snapshot_sha256="a" * 64,
                         worklist_index=str(run / "files" / "index.json"),
                         batch_path=str(run / "files" / "batch-0001.json"),
                         result_path=str(run / "files" / "review.json"))
        command = [sys.executable, str(target / "audit.py"), "brief", "--phase",
                   "firmware-fpcheck", "--unit", "batch-0001", "--run", str(run)]
        for name, value in variables.items():
            command.extend(["--var", f"{name}={value}"])
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        output = run / "briefs" / "firmware-fpcheck-batch-0001-brief.md"
        assert result.stdout == f"{output}\n"
        text = output.read_text()
        assert "__SKILL_DIR__" not in text
        assert str(target / "audit_core" / "firmware_fpcheck_results.py") in text
        rules = target / "references" / "phase5-fp-check.md"
        assert str(rules) in text
        assert rules.is_file()
        assert (target / "audit_core" / "firmware_fpcheck_results.py").is_file()
        assert "firmware-fpcheck-brief.md" in (target / "SKILL.md").read_text()
        assert not re.search(r"(?<!\$)\{[A-Za-z_][A-Za-z0-9_]*\}", text)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize("client", ("claude", "codex"))
def test_installed_firmware_chain_renders_global_brief_and_route(tmp_path, client):
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "CODEX_HOME": str(home / ".codex")}
    installed = subprocess.run(["bash", str(ROOT / "install.sh"), client],
                               capture_output=True, text=True, env=env, cwd=ROOT)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    roots = [home / ".claude"] if client == "claude" else [home / ".agents", home / ".codex"]
    for directory in roots:
        target = directory / "skills" / "codebase-audit"
        run = directory / "run"
        variables = dict(run_dir=str(run), db_path=str(run / "audit.db"),
                         rootfs=str(tmp_path / "rootfs"), image_id="router-target",
                         candidate_snapshot_sha256="a" * 64,
                         worklist_path=str(run / "files" / "worklist.json"),
                         result_path=str(run / "files" / "chain-result.json"))
        command = [sys.executable, str(target / "audit.py"), "brief", "--phase",
                   "firmware-chain", "--unit", "global", "--run", str(run)]
        for name, value in variables.items():
            command.extend(["--var", f"{name}={value}"])
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        output = run / "briefs" / "firmware-chain-global-brief.md"
        assert result.stdout == f"{output}\n"
        text = output.read_text()
        assert "__SKILL_DIR__" not in text
        for module in ("firmware_chain_results.py", "firmware_chain.py"):
            assert str(target / "audit_core" / module) in text
            assert (target / "audit_core" / module).is_file()
        skill = (target / "SKILL.md").read_text()
        assert "firmware-chain-brief.md" in skill
        assert "Stage 4g firmware chain" in skill
        assert f"python3 {target}/audit.py chain --run" in skill
        assert not re.search(r"(?<!\$)\{[A-Za-z_][A-Za-z0-9_]*\}", text)


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
