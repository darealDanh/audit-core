"""The verification harness checks the project; these check the harness.

Two of these matter more than the rest. `test_the_eol_manifest_matches_the_tree`
puts the line-ending contract inside the pytest suite, so a drifted file is
caught by `make test` and not only by the gate that happens to run later. And
`test_the_install_gate_refuses_a_sandbox_that_is_the_real_home` pins the
assertion that stands between a routine `make check` and overwriting the
operator's working skill install.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "cba_harness", ROOT / "scripts" / "harness.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cba_harness"] = mod
    spec.loader.exec_module(mod)
    return mod


harness = _load()


def test_every_gate_is_documented_and_dispatchable():
    """`--list` prints each gate's first docstring line. A gate with no
    docstring prints a blank description, which is how a gate nobody can
    explain survives in the runner."""
    for name, fn in harness.GATES.items():
        assert fn.__doc__ and fn.__doc__.strip(), f"{name} has no docstring"
        assert callable(fn)


def test_the_default_set_is_a_subset_of_the_gates():
    """DEFAULT is written by hand; a renamed gate leaves a name behind in it
    that `--only` would reject but the default run would silently KeyError."""
    missing = [g for g in harness.DEFAULT if g not in harness.GATES]
    assert missing == [], f"DEFAULT names gates that do not exist: {missing}"


def test_bench_is_not_in_the_default_set():
    """bench reads a corpus outside the repository. Putting it in the default
    set makes `make check` fail on every machine but one."""
    assert "bench" not in harness.DEFAULT


def test_the_eol_manifest_matches_the_tree():
    """The CRLF/LF split is a contract (see scripts/eol-manifest.txt for why).
    This is the same comparison the eol gate makes, run as a test so that
    `make test` alone catches a drifted file."""
    expected = harness.read_manifest()
    actual = harness.crlf_files()
    assert actual == expected, (
        f"gained CRLF: {sorted(actual - expected)}; "
        f"lost CRLF: {sorted(expected - actual)}")


def test_the_manifest_only_names_files_that_exist():
    """A manifest entry for a deleted file is a contract nobody can violate,
    which reads as a passing gate."""
    for rel in harness.read_manifest():
        assert (ROOT / rel).is_file(), f"{rel} is in the manifest but not on disk"


def test_manifest_parsing_drops_comments_and_blanks(tmp_path, monkeypatch):
    f = tmp_path / "m.txt"
    f.write_text("# a comment\n\nSKILL.md\nfoo.md  # trailing\n   \n")
    monkeypatch.setattr(harness, "MANIFEST", f)
    assert harness.read_manifest() == {"SKILL.md", "foo.md"}


def test_real_install_dirs_follow_codex_home(monkeypatch, tmp_path):
    """install.sh reads $CODEX_HOME for one of its four destinations. If the
    gate's before/after mtime snapshot does not read it too, a run that writes
    there is invisible to the safety assertion."""
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codexhome"))
    dirs = [str(d) for d in harness.real_install_dirs()]
    assert str(tmp_path / "codexhome" / "skills" / "codebase-audit") in dirs


def test_real_install_dirs_cover_every_client_root():
    """Four destinations: copilot, claude, ~/.agents and $CODEX_HOME. Missing
    one means the gate reports 'real install untouched' about a directory it
    never looked at."""
    dirs = [str(d) for d in harness.real_install_dirs()]
    assert len(dirs) == 4
    for fragment in (".copilot/skills", ".claude/skills", ".agents/skills"):
        assert any(fragment in d for d in dirs), fragment


def test_the_install_gate_refuses_a_sandbox_that_is_the_real_home(monkeypatch):
    """The refusal, exercised. TemporaryDirectory is stubbed to hand back the
    real HOME; the gate must fail closed and must not invoke install.sh."""
    real_home = pathlib.Path(os.path.expanduser("~")).resolve()

    class FakeTmp:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return str(real_home)

        def __exit__(self, *a):
            return False

    invoked: list[list[str]] = []

    def spy(cmd, **kw):
        invoked.append(cmd)
        raise AssertionError("install.sh must not run once the guard trips")

    monkeypatch.setattr(harness.tempfile, "TemporaryDirectory", FakeTmp)
    monkeypatch.setattr(harness, "run", spy)

    res = harness.gate_install()
    assert res.status == harness.FAIL
    assert "refused" in res.summary
    assert invoked == []


def test_results_serialise_for_the_json_report():
    r = harness.Result("x", harness.PASS, "fine", "detail", 1.234)
    d = r.as_dict()
    assert d["gate"] == "x" and d["status"] == "pass" and d["seconds"] == 1.23


def test_list_exits_zero():
    assert harness.main(["--list"]) == 0


def test_an_unknown_gate_is_rejected_rather_than_ignored():
    """`--only typo` silently running nothing and exiting 0 is the worst
    possible outcome for a gate runner wired into CI."""
    assert harness.main(["--only", "no-such-gate"]) == 2


def test_selftest_reports_every_verb_the_parser_declares():
    """The manifest gate checks feature_lists.json against audit.py. This
    checks audit.py against itself, so a verb added to HANDLERS without a
    subparser fails here rather than at a user's first invocation."""
    import subprocess
    proc = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "selftest"],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "23 declared, all dispatchable" in proc.stdout
