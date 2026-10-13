import json
import pathlib
import sqlite3
import subprocess
import sys

import pytest

import audit

from audit_core import db, workspace

ROOT = pathlib.Path(__file__).resolve().parent.parent
AUDIT = ROOT / "audit.py"


def run_cli(*args):
    return subprocess.run([sys.executable, str(AUDIT), *map(str, args)],
                          capture_output=True, text=True)


def seed_image(con, image_id, role, digest):
    db.put(con, "cba_images", {
        "id": image_id, "vendor": "acme", "model": "r1", "version": "1",
        "role": role, "path": "/unavailable/firmware.bin", "sha256": digest,
    })


def seed_file(con, image_id, path, digest):
    db.put(con, "cba_firmware_files", {
        "image_id": image_id, "path": path, "kind": "file", "size": "1",
        "sha256": digest,
    })


@pytest.fixture()
def paired_run(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20261012-030000")
    con = db.connect(run / "audit.db")
    try:
        seed_image(con, "ref", "diff-reference", "1" * 64)
        seed_image(con, "target", "target", "2" * 64)
        for row in (("ref", "removed", "a" * 64),
                    ("ref", "modified", "b" * 64),
                    ("ref", "unchanged", "c" * 64),
                    ("target", "unchanged", "c" * 64),
                    ("target", "modified", "d" * 64),
                    ("target", "added", "e" * 64)):
            seed_file(con, *row)
    finally:
        con.close()
    return run


def test_diff_help_exposes_pair_selection_and_output_flags():
    result = run_cli("diff", "--help")
    assert result.returncode == 0, result.stderr
    for flag in ("--run", "--target-image-id", "--reference-image-id",
                 "--replace", "--json"):
        assert flag in result.stdout


def test_diff_implicit_pair_prints_exactly_summary_and_manifest(paired_run):
    result = run_cli("diff", "--run", paired_run)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    con = db.connect(paired_run / "audit.db")
    try:
        summary = dict(con.execute("SELECT * FROM cba_diffs").fetchone())
    finally:
        con.close()
    assert result.stdout.splitlines() == [
        f"diff {summary['id']}: 1 added, 1 removed, 1 modified, 1 unchanged",
        summary["manifest_path"],
    ]
    assert pathlib.Path(summary["manifest_path"]).is_file()


def test_diff_explicit_pair_json_selects_amid_ambiguous_roles(paired_run):
    con = db.connect(paired_run / "audit.db")
    try:
        seed_image(con, "extra", "target", "3" * 64)
    finally:
        con.close()
    result = run_cli("diff", "--run", paired_run, "--target-image-id", "target",
                     "--reference-image-id", "ref", "--json")
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    summary = json.loads(result.stdout)
    assert summary == {
        "id": "diff-14cdfdd6b750da43", "reference_image_id": "ref",
        "target_image_id": "target", "added_count": 1, "removed_count": 1,
        "modified_count": 1, "unchanged_count": 1,
        "manifest_path": summary["manifest_path"],
    }
    assert pathlib.Path(summary["manifest_path"]).is_file()


@pytest.mark.parametrize("flag", ["--target-image-id", "--reference-image-id"])
def test_diff_half_explicit_ids_refuse_before_opening_missing_run(tmp_path, flag):
    result = run_cli("diff", "--run", tmp_path / "missing", flag, "target")
    assert result.returncode == 1
    assert "Both target and reference image IDs" in result.stderr
    assert "audit.py init" not in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize(("case", "cause"), [
    ("missing-target", "exactly one target"),
    ("missing-reference", "exactly one diff-reference"),
    ("multiple-targets", "exactly one target"),
    ("multiple-references", "exactly one diff-reference"),
    ("unknown-target", "Unknown target image ID"),
    ("unknown-reference", "Unknown diff-reference image ID"),
    ("reversed-roles", "must have role diff-reference"),
    ("same-id", "image IDs must differ"),
    ("vendor-mismatch", "vendor must match"),
    ("model-mismatch", "model must match"),
    ("same-hash", "acquired-image hashes must differ"),
    ("empty-target", "empty triage manifest"),
    ("empty-reference", "empty triage manifest"),
    ("legacy-unscoped", "no acquired-image provenance"),
])
def test_diff_pair_refusals_are_named_and_create_no_output(paired_run, case, cause):
    con = db.connect(paired_run / "audit.db")
    args = []
    try:
        if case.startswith("missing-"):
            image_id = "target" if case == "missing-target" else "ref"
            con.execute("DELETE FROM cba_images WHERE id = ?", (image_id,))
        elif case.startswith("multiple-"):
            role = "target" if case == "multiple-targets" else "diff-reference"
            seed_image(con, "extra", role, "3" * 64)
        elif case in ("unknown-target", "unknown-reference", "reversed-roles", "same-id"):
            target, reference = {
                "unknown-target": ("missing", "ref"),
                "unknown-reference": ("target", "missing"),
                "reversed-roles": ("ref", "target"),
                "same-id": ("target", "target"),
            }[case]
            args = ["--target-image-id", target, "--reference-image-id", reference]
        elif case == "vendor-mismatch":
            con.execute("UPDATE cba_images SET vendor = 'other' WHERE id = 'target'")
        elif case == "model-mismatch":
            con.execute("UPDATE cba_images SET model = 'other' WHERE id = 'target'")
        elif case == "same-hash":
            con.execute("UPDATE cba_images SET sha256 = ?", ("1" * 64,))
        elif case.startswith("empty-"):
            image_id = "target" if case == "empty-target" else "ref"
            con.execute("DELETE FROM cba_firmware_files WHERE image_id = ?", (image_id,))
        else:
            con.execute("UPDATE cba_images SET id = 'legacy-unscoped' WHERE id = 'ref'")
        con.commit()
        result = run_cli("diff", "--run", paired_run, *args, "--json")
        assert result.returncode == 1
        assert cause in result.stderr
        assert "Traceback" not in result.stderr
        assert result.stdout == ""
        assert con.execute("SELECT COUNT(*) FROM cba_diffs").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM cba_diff_entries").fetchone()[0] == 0
        assert list((paired_run / "files").iterdir()) == []
    finally:
        con.close()


def test_diff_duplicate_refuses_and_replace_succeeds(paired_run):
    args = ("diff", "--run", paired_run, "--json")
    first = run_cli(*args)
    assert first.returncode == 0, first.stderr
    before = {path: path.read_bytes() for path in (paired_run / "files").iterdir()}
    duplicate = run_cli(*args)
    assert duplicate.returncode == 1
    assert "already exists" in duplicate.stderr and "--replace" in duplicate.stderr
    assert "Traceback" not in duplicate.stderr
    assert duplicate.stdout == ""
    assert {path: path.read_bytes() for path in (paired_run / "files").iterdir()} == before
    replaced = run_cli(*args, "--replace")
    assert replaced.returncode == 0, replaced.stderr
    assert json.loads(replaced.stdout) == json.loads(first.stdout)


def test_diff_missing_database_refuses_with_remedy(tmp_path):
    result = run_cli("diff", "--run", tmp_path)
    assert result.returncode == 1
    assert "audit.py init" in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""


def test_diff_stale_stage4b_key_refuses_with_remedy(paired_run):
    con = db.connect(paired_run / "audit.db")
    try:
        ddl = con.execute("SELECT sql FROM sqlite_master WHERE name = 'cba_binfacts'").fetchone()[0]
        con.execute("DROP TABLE cba_binfacts")
        con.execute(ddl.replace("PRIMARY KEY (image_id, path)", "PRIMARY KEY (path)"))
        con.commit()
    finally:
        con.close()
    result = run_cli("diff", "--run", paired_run)
    assert result.returncode == 1
    assert "cba_binfacts primary key" in result.stderr
    assert "audit.py init" in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""


def test_diff_manifest_install_failure_is_named(paired_run):
    (paired_run / "files").rmdir()
    (paired_run / "files").write_text("blocked")
    result = run_cli("diff", "--run", paired_run)
    assert result.returncode == 1
    assert "Cannot install diff manifest" in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""
    con = db.connect(paired_run / "audit.db")
    try:
        assert con.execute("SELECT COUNT(*) FROM cba_diffs").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM cba_diff_entries").fetchone()[0] == 0
    finally:
        con.close()


@pytest.mark.parametrize("table", ["cba_images", "cba_firmware_files"])
def test_diff_cli_read_database_error_returns_named_exit_one(
        paired_run, monkeypatch, capsys, table):
    original = audit._open_db

    def open_with_denied_read(path):
        con = original(path)
        con.set_authorizer(lambda action, name, column, database, source:
                           sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_READ and name == table
                           else sqlite3.SQLITE_OK)
        return con

    monkeypatch.setattr(audit, "_open_db", open_with_denied_read)
    assert audit.main(["diff", "--run", str(paired_run)]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "Cannot read" in output.err
    assert "firmware diff" in output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize("json_output", [False, True])
def test_diff_output_stays_bounded_for_250_file_manifests(paired_run, json_output):
    con = db.connect(paired_run / "audit.db")
    try:
        con.execute("DELETE FROM cba_firmware_files")
        con.commit()
        for index in range(250):
            path = f"etc/file-{index:03d}"
            seed_file(con, "ref", path, "a" * 64)
            seed_file(con, "target", path, "b" * 64)
    finally:
        con.close()
    result = run_cli("diff", "--run", paired_run, *(["--json"] if json_output else []))
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert len(result.stdout) < 1024
    if json_output:
        summary = json.loads(result.stdout)
        assert set(summary) == {"id", "reference_image_id", "target_image_id",
                                "added_count", "removed_count", "modified_count",
                                "unchanged_count", "manifest_path"}
        assert [summary[field] for field in ("added_count", "removed_count",
                                            "modified_count", "unchanged_count")] == [0, 0, 250, 0]
        manifest_path = summary["manifest_path"]
    else:
        lines = result.stdout.splitlines()
        assert len(lines) == 2
        assert lines[0] == "diff diff-14cdfdd6b750da43: 0 added, 0 removed, 250 modified, 0 unchanged"
        manifest_path = lines[1]
    manifest = json.loads(pathlib.Path(manifest_path).read_text())
    assert len(manifest["entries"]) == 250
    assert manifest["entries"][-1]["path"] == "etc/file-249"


@pytest.mark.parametrize(("args", "cause"), [
    (("diff",), "following arguments are required: --run"),
    (("diff", "--run"), "argument --run: expected one argument"),
    (("diff", "--run", "/unused", "--target-image-id"),
     "argument --target-image-id: expected one argument"),
])
def test_diff_missing_arguments_are_usage_errors(args, cause):
    result = run_cli(*args)
    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert cause in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""
