# tests/test_firmware_audit_install.py
#
# The firmware-audit skill ships as its own self-contained install tree,
# vendoring an identical audit.py + audit_core/ alongside its own surface
# (SKILL.md, references/briefs/ with the nine firmware briefs, and
# references/phase5-fp-check.md). These tests install BOTH skills into a
# sandbox HOME and assert each tree stands alone, that the firmware briefs live
# only under firmware-audit/ and the generic briefs only under codebase-audit/,
# and that an installed firmware-audit tree renders and routes its firmware
# briefs. Every subprocess runs against a throwaway HOME (+CODEX_HOME); the real
# HOME is never touched.
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

FIRMWARE_BRIEFS = (
    "hunt-brief.md", "surface-brief.md", "diff-brief.md", "triage-brief.md",
    "firmware-fpcheck-brief.md", "firmware-chain-brief.md",
    "firmware-dive-brief.md", "firmware-decide-brief.md",
    "firmware-report-brief.md",
)
GENERIC_BRIEFS = ("audit-brief.md", "recon-brief.md", "fpcheck-brief.md")

# Every client install root, grouped by skill. codex installs into two roots.
SKILL_ROOTS = {
    "codebase-audit": (
        ".claude/skills/codebase-audit",
        ".copilot/skills/codebase-audit",
        ".agents/skills/codebase-audit",
        ".codex/skills/codebase-audit",
    ),
    "firmware-audit": (
        ".claude/skills/firmware-audit",
        ".copilot/skills/firmware-audit",
        ".agents/skills/firmware-audit",
        ".codex/skills/firmware-audit",
    ),
}


def _sandbox_env(home: pathlib.Path) -> dict[str, str]:
    """A sandbox HOME + CODEX_HOME. Mirrors tests/test_install.py exactly: the
    real HOME is never named, so no subprocess can reach it."""
    return {**os.environ, "HOME": str(home),
            "CLAUDE_CONFIG_DIR": str(home / ".claude"),
            "CODEX_HOME": str(home / ".codex")}


def _install_all(home: pathlib.Path) -> None:
    home.mkdir(exist_ok=True)
    env = _sandbox_env(home)
    r = subprocess.run(["bash", str(ROOT / "install.sh")],
                       capture_output=True, text=True, env=env, cwd=str(ROOT))
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_both_skills_install_self_contained_trees(tmp_path):
    """Install both skills into a sandbox HOME; assert each tree is
    self-contained, the briefs are partitioned correctly, each tree passes its
    own selftest, no __SKILL_DIR__ sentinel survives, the real install dirs'
    mtimes are unchanged, and a sandbox that equals the real HOME is refused."""
    home = (tmp_path / "home").resolve()

    # The sandbox HOME must not be the real HOME, nor contain the real install
    # dirs: the same guard scripts/harness.py applies before it ever writes.
    real_home = pathlib.Path(os.path.expanduser("~")).resolve()
    assert home != real_home, "refused: the sandbox HOME is the real HOME"
    for rels in SKILL_ROOTS.values():
        for rel in rels:
            real_dir = (real_home / rel).resolve()
            try:
                real_dir.relative_to(home)
            except ValueError:
                continue
            pytest.fail(f"refused: real install dir {real_dir} is in the sandbox")

    # Snapshot the real install dirs' mtimes before touching anything.
    real_dirs = [real_home / rel
                 for rels in SKILL_ROOTS.values() for rel in rels]
    before = {d: (d.stat().st_mtime if d.exists() else None) for d in real_dirs}

    _install_all(home)

    for skill, rels in SKILL_ROOTS.items():
        for rel in rels:
            target = home / rel
            assert (target / "audit.py").is_file(), f"{skill}: missing audit.py"
            assert (target / "audit_core" / "__init__.py").is_file(), (
                f"{skill}: missing audit_core/")
            assert (target / "audit_core" / "schema.sql").is_file(), skill
            assert (target / "SKILL.md").is_file(), f"{skill}: missing SKILL.md"

            briefs = target / "references" / "briefs"
            if skill == "firmware-audit":
                for b in FIRMWARE_BRIEFS:
                    assert (briefs / b).is_file(), f"firmware-audit missing {b}"
                assert (target / "references" / "phase5-fp-check.md").is_file()
            else:
                for b in GENERIC_BRIEFS:
                    assert (briefs / b).is_file(), f"codebase-audit missing {b}"
                for b in FIRMWARE_BRIEFS:
                    assert not (briefs / b).is_file(), (
                        f"codebase-audit must not ship the firmware brief {b}")

            # The installed tree runs its own selftest.
            env = _sandbox_env(home)
            s = subprocess.run([sys.executable, str(target / "audit.py"),
                                "selftest"], capture_output=True, text=True,
                               env=env, cwd=str(target))
            assert s.returncode == 0, f"{skill} selftest: {s.stdout + s.stderr}"

    # No __SKILL_DIR__ sentinel survives in any installed markdown.
    survivors = [str(p.relative_to(home)) for p in home.rglob("*.md")
                 if p.is_file() and "__SKILL_DIR__" in p.read_text(errors="replace")]
    assert survivors == [], f"__SKILL_DIR__ survived in: {survivors}"

    # The real install dirs were never touched.
    after = {d: (d.stat().st_mtime if d.exists() else None) for d in real_dirs}
    moved = [str(d) for d in real_dirs if before[d] != after[d]]
    assert moved == [], f"the real install was modified: {moved}"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_installed_firmware_hunt_brief_resolves_schema_and_renders(tmp_path):
    """Render the hunt brief from the installed firmware-audit tree and assert
    its result-contract schema reference resolves to that tree."""
    home = (tmp_path / "home").resolve()
    _install_all(home)
    target = home / ".claude" / "skills" / "firmware-audit"
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
    """Render the firmware review (fpcheck) brief from the installed
    firmware-audit tree and assert its FP-rules reference resolves."""
    home = (tmp_path / "home").resolve()
    _install_all(home)
    roots = [home / ".claude"] if client == "claude" else [home / ".agents",
                                                            home / ".codex"]
    for directory in roots:
        target = directory / "skills" / "firmware-audit"
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
    """Render the firmware chain brief from the installed firmware-audit tree
    and assert the global route (SKILL.md Stage 4g) resolves."""
    home = (tmp_path / "home").resolve()
    _install_all(home)
    roots = [home / ".claude"] if client == "claude" else [home / ".agents",
                                                            home / ".codex"]
    for directory in roots:
        target = directory / "skills" / "firmware-audit"
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
