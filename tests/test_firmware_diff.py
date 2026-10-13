import dataclasses
import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, firmware_diff, workspace


def test_compare_classifies_paths_and_retains_side_evidence():
    reference = [
        {"path": "removed", "kind": "config", "size": 12, "sha256": "a" * 64},
        {"path": "modified", "kind": "binary", "size": 8, "sha256": "b" * 64},
        {"path": "unchanged", "kind": "file", "size": 9, "sha256": "c" * 64},
    ]
    target = [
        {"path": "unchanged", "kind": "script", "size": 99, "sha256": "c" * 64},
        {"path": "modified", "kind": "binary", "size": 8, "sha256": "d" * 64},
        {"path": "added", "kind": "script", "size": 0, "sha256": "e" * 64},
    ]

    assert firmware_diff.compare(reference, target) == firmware_diff.Comparison(
        entries=(
            firmware_diff.DiffEntry("added", "added", None, "script", None, 0,
                                   None, "e" * 64),
            firmware_diff.DiffEntry("modified", "modified", "binary", "binary",
                                   8, 8, "b" * 64, "d" * 64),
            firmware_diff.DiffEntry("removed", "removed", "config", None, 12,
                                   None, "a" * 64, None),
        ),
        added_count=1, removed_count=1, modified_count=1, unchanged_count=1,
    )


def test_compare_retains_kind_and_size_changes_as_modified_evidence():
    reference = [{"path": "bin/app", "kind": "file", "size": 4,
                  "sha256": "a" * 64}]
    target = [{"path": "bin/app", "kind": "binary", "size": 7,
               "sha256": "b" * 64}]
    assert firmware_diff.compare(reference, target).entries == (
        firmware_diff.DiffEntry("bin/app", "modified", "file", "binary",
                               4, 7, "a" * 64, "b" * 64),
    )


def test_compare_is_unbounded_unicode_safe_and_input_order_independent():
    paths = [f"file/{i:03d}" for i in range(247)] + ["é", "中", "😀"]
    reference = [{"path": path, "kind": "file", "size": 1, "sha256": "a" * 64}
                 for path in paths]
    target = [{"path": path, "kind": "file", "size": 1, "sha256": "b" * 64}
              for path in reversed(paths)]

    result = firmware_diff.compare(reference, target)
    assert (result.added_count, result.removed_count, result.modified_count,
            result.unchanged_count) == (0, 0, 250, 0)
    assert len(result.entries) == 250
    assert [entry.path for entry in result.entries] == sorted(paths)
    assert [entry.path for entry in result.entries[-3:]] == ["é", "中", "😀"]
    assert firmware_diff.compare(reversed(reference), target) == result
    assert firmware_diff.compare(reference, reversed(target)) == result
    assert firmware_diff.compare(reversed(reference), reversed(target)) == result


@pytest.mark.parametrize("side", ["reference", "target"])
@pytest.mark.parametrize("second_hash", ["a" * 64, "b" * 64])
def test_compare_refuses_duplicate_paths_on_either_side(side, second_hash):
    duplicate = [
        {"path": "etc/重复", "kind": "config", "size": 1, "sha256": "a" * 64},
        {"path": "etc/重复", "kind": "config", "size": 1, "sha256": second_hash},
    ]
    reference, target = (duplicate, []) if side == "reference" else ([], duplicate)
    with pytest.raises(firmware_diff.FirmwareDiffError, match="etc/重复"):
        firmware_diff.compare(reference, target)


def test_compare_accepts_empty_and_one_shot_iterables():
    assert firmware_diff.compare(iter(()), iter(())) == firmware_diff.Comparison(
        (), 0, 0, 0, 0)
    rows = [{"path": "empty", "kind": "file", "size": 0, "sha256": "a" * 64}]
    assert firmware_diff.compare(iter(rows), iter(rows)) == firmware_diff.Comparison(
        (), 0, 0, 0, 1)


@pytest.fixture()
def con(tmp_path):
    run_dir = workspace.init_run(tmp_path / "project", timestamp="20261012-010000")
    connection = db.connect(run_dir / "audit.db")
    yield connection
    connection.close()


def seed_image(con, image_id, role, digest, **overrides):
    db.put(con, "cba_images", {
        "id": image_id, "vendor": "acme", "model": "r1", "version": "1",
        "role": role, "path": "/unavailable/firmware.bin", "sha256": digest,
        **overrides,
    })


def seed_file(con, image_id, path, digest, *, kind="file", size=1):
    db.put(con, "cba_firmware_files", {
        "image_id": image_id, "path": path, "sha256": digest,
        "kind": kind, "size": str(size),
    })


def seed_pair(con, *, reverse=False):
    seed_image(con, "ref", "diff-reference", "1" * 64)
    seed_image(con, "target", "target", "2" * 64)
    rows = [
        ("ref", "removed", "a" * 64),
        ("ref", "modified", "b" * 64),
        ("ref", "unchanged", "c" * 64),
        ("target", "unchanged", "c" * 64),
        ("target", "modified", "d" * 64),
        ("target", "added", "e" * 64),
    ]
    for args in reversed(rows) if reverse else rows:
        seed_file(con, *args)


def diff_snapshot(con):
    return tuple(tuple(tuple(row) for row in con.execute(query)) for query in (
        "SELECT * FROM cba_diffs ORDER BY id",
        "SELECT * FROM cba_diff_entries ORDER BY diff_id, path",
    ))


@pytest.mark.parametrize("case", [
    "missing-target", "missing-reference", "multiple-targets", "multiple-references",
    "only-target-id", "only-reference-id", "unknown-target", "unknown-reference",
    "reversed-roles", "same-id", "vendor-mismatch", "model-mismatch", "same-hash",
    "empty-target", "empty-reference", "legacy-unscoped",
])
def test_run_refuses_invalid_pairs_before_any_output(con, tmp_path, case):
    seed_pair(con)
    kwargs = {}
    if case.startswith("missing-"):
        image_id = "target" if case == "missing-target" else "ref"
        con.execute("DELETE FROM cba_images WHERE id = ?", (image_id,))
    elif case.startswith("multiple-"):
        role = "target" if case == "multiple-targets" else "diff-reference"
        seed_image(con, "extra", role, "3" * 64)
    elif case == "only-target-id":
        kwargs = {"target_image_id": "target"}
    elif case == "only-reference-id":
        kwargs = {"reference_image_id": "ref"}
    elif case in ("unknown-target", "unknown-reference", "reversed-roles", "same-id"):
        target, reference = {
            "unknown-target": ("missing", "ref"),
            "unknown-reference": ("target", "missing"),
            "reversed-roles": ("ref", "target"),
            "same-id": ("target", "target"),
        }[case]
        kwargs = {"target_image_id": target, "reference_image_id": reference}
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
        con.execute("UPDATE cba_firmware_files SET image_id = 'legacy-unscoped' "
                    "WHERE image_id = 'ref'")
    con.commit()

    with pytest.raises(firmware_diff.FirmwareDiffError):
        firmware_diff.run(con, tmp_path / "output", **kwargs)

    assert diff_snapshot(con) == ((), ())
    assert not (tmp_path / "output").exists()


def test_run_persists_exact_counts_and_only_changed_entries(con, tmp_path):
    seed_pair(con)
    result = firmware_diff.run(con, tmp_path / "output")
    expected_id = "diff-" + hashlib.sha256(b"ref\0target").hexdigest()[:16]
    assert isinstance(result, firmware_diff.DiffSummary)
    summary = dataclasses.asdict(result)
    assert summary == {
        "id": expected_id, "reference_image_id": "ref", "target_image_id": "target",
        "added_count": 1, "removed_count": 1, "modified_count": 1,
        "unchanged_count": 1, "manifest_path": result.manifest_path,
    }
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.added_count = 10
    stored = dict(con.execute("SELECT * FROM cba_diffs").fetchone())
    stored.pop("recorded_at")
    assert stored == summary
    entries = [dict(row) for row in con.execute(
        "SELECT * FROM cba_diff_entries ORDER BY path")]
    assert [(row["path"], row["change"]) for row in entries] == [
        ("added", "added"), ("modified", "modified"), ("removed", "removed")]
    assert entries[0]["reference_sha256"] is None
    assert entries[0]["target_sha256"] == "e" * 64
    assert entries[1]["reference_sha256"] == "b" * 64
    assert entries[1]["target_sha256"] == "d" * 64
    assert entries[2]["target_sha256"] is None


def test_run_explicit_pair_bypasses_ambiguity_and_normalizes_metadata(con, tmp_path):
    seed_pair(con)
    seed_image(con, "extra", "target", "3" * 64)
    con.execute("UPDATE cba_images SET vendor = ' ACME ', model = ' R1 ' "
                "WHERE id = 'target'")
    con.commit()
    result = firmware_diff.run(con, tmp_path, target_image_id="target",
                               reference_image_id="ref")
    assert (result.reference_image_id, result.target_image_id) == ("ref", "target")
    assert result.modified_count == 1


def test_manifest_is_content_addressed_canonical_and_database_independent(con, tmp_path):
    seed_pair(con)
    first = firmware_diff.run(con, tmp_path / "one")
    first_path = pathlib.Path(first.manifest_path)
    raw = first_path.read_bytes()
    assert first_path.name == f"{first.id}-{hashlib.sha256(raw).hexdigest()[:16]}.json"
    assert first_path.parent == tmp_path / "one" / "files"
    manifest = json.loads(raw)
    assert raw == (json.dumps(manifest, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":")) + "\n").encode("utf-8")
    assert manifest["id"] == first.id
    assert manifest["reference_image"] == {
        "id": "ref", "vendor": "acme", "model": "r1", "version": "1",
        "role": "diff-reference", "sha256": "1" * 64,
    }
    assert manifest["target_image"] == {
        "id": "target", "vendor": "acme", "model": "r1", "version": "1",
        "role": "target", "sha256": "2" * 64,
    }
    assert set(manifest) == {
        "id", "reference_image_id", "target_image_id", "reference_image", "target_image",
        "added_count", "removed_count", "modified_count", "unchanged_count", "entries",
    }
    assert (manifest["reference_image_id"], manifest["target_image_id"]) == ("ref", "target")
    assert [manifest[key] for key in ("added_count", "removed_count", "modified_count",
                                    "unchanged_count")] == [1, 1, 1, 1]
    assert [entry["path"] for entry in manifest["entries"]] == ["added", "modified", "removed"]
    sql_entries = [dict(row) for row in con.execute(
        "SELECT * FROM cba_diff_entries ORDER BY path")]
    for entry in sql_entries:
        entry.pop("diff_id")
    assert manifest["entries"] == sql_entries

    other_run = workspace.init_run(tmp_path / "other", timestamp="20261012-020000")
    other = db.connect(other_run / "audit.db")
    try:
        seed_pair(other, reverse=True)
        other.execute("UPDATE cba_images SET path = '/different/location', acquired_at = 'different'")
        other.execute("UPDATE cba_firmware_files SET recorded_at = 'different'")
        other.commit()
        second = firmware_diff.run(other, tmp_path / "two")
        assert pathlib.Path(second.manifest_path).read_bytes() == raw
    finally:
        other.close()


def test_run_compares_full_manifests_above_bounded_query_limit(con, tmp_path):
    seed_pair(con)
    for index in range(251):
        seed_file(con, "ref", f"é/{index:03d}", "a" * 64)
        seed_file(con, "target", f"é/{index:03d}", "f" * 64)
    result = firmware_diff.run(con, tmp_path)
    assert (result.added_count, result.removed_count, result.modified_count,
            result.unchanged_count) == (1, 1, 252, 1)
    assert con.execute("SELECT COUNT(*) FROM cba_diff_entries").fetchone()[0] == 254
    entries = json.loads(pathlib.Path(result.manifest_path).read_bytes())["entries"]
    assert len(entries) == 254
    assert entries[-1]["path"] == "é/250"


def test_run_records_an_empty_diff_for_nonempty_identical_manifests(con, tmp_path):
    seed_image(con, "ref", "diff-reference", "1" * 64)
    seed_image(con, "target", "target", "2" * 64)
    for image_id in ("ref", "target"):
        seed_file(con, image_id, "same", "a" * 64)
    result = firmware_diff.run(con, tmp_path)
    assert (result.added_count, result.removed_count, result.modified_count,
            result.unchanged_count) == (0, 0, 0, 1)
    assert db.rows(con, "cba_diff_entries") == []
    assert json.loads(pathlib.Path(result.manifest_path).read_bytes())["entries"] == []


def test_run_duplicate_refuses_without_creating_an_artifact(con, tmp_path):
    seed_pair(con)
    firmware_diff.run(con, tmp_path)
    before = diff_snapshot(con)
    files_before = {path: path.read_bytes() for path in (tmp_path / "files").iterdir()}
    seed_file(con, "target", "new-generation", "f" * 64)
    with pytest.raises(firmware_diff.FirmwareDiffError, match="replace"):
        firmware_diff.run(con, tmp_path)
    assert diff_snapshot(con) == before
    assert {path: path.read_bytes() for path in (tmp_path / "files").iterdir()} == files_before


def test_run_replace_removes_stale_entries_and_preserves_other_pairs(con, tmp_path):
    seed_pair(con)
    old = firmware_diff.run(con, tmp_path)
    old_bytes = pathlib.Path(old.manifest_path).read_bytes()
    seed_image(con, "other", "target", "3" * 64)
    seed_file(con, "other", "different", "a" * 64)
    other = firmware_diff.run(con, tmp_path, target_image_id="other", reference_image_id="ref")
    other_before = tuple(tuple(row) for row in con.execute(
        "SELECT * FROM cba_diff_entries WHERE diff_id = ?", (other.id,)))
    con.execute("DELETE FROM cba_firmware_files WHERE image_id = 'target'")
    con.execute("INSERT INTO cba_firmware_files (image_id, path, kind, size, sha256) "
                "SELECT 'target', path, kind, size, sha256 FROM cba_firmware_files WHERE image_id = 'ref'")
    con.commit()
    result = firmware_diff.run(con, tmp_path, target_image_id="target",
                               reference_image_id="ref", replace=True)
    assert result.id == old.id
    assert (result.added_count, result.removed_count, result.modified_count,
            result.unchanged_count) == (0, 0, 0, 3)
    assert con.execute("SELECT * FROM cba_diff_entries WHERE diff_id = ?", (old.id,)).fetchall() == []
    assert tuple(tuple(row) for row in con.execute(
        "SELECT * FROM cba_diff_entries WHERE diff_id = ?", (other.id,))) == other_before
    assert result.manifest_path != old.manifest_path
    assert pathlib.Path(old.manifest_path).read_bytes() == old_bytes


def test_manifest_install_failure_preserves_previous_result(con, tmp_path, monkeypatch):
    seed_pair(con)
    old = firmware_diff.run(con, tmp_path)
    before = diff_snapshot(con)
    old_bytes = pathlib.Path(old.manifest_path).read_bytes()
    seed_file(con, "target", "new-generation", "f" * 64)

    def fail_install(source, destination):
        raise OSError("injected install failure")

    monkeypatch.setattr("os.replace", fail_install)
    with pytest.raises(firmware_diff.FirmwareDiffError, match="injected install failure"):
        firmware_diff.run(con, tmp_path, replace=True)
    assert diff_snapshot(con) == before
    assert pathlib.Path(old.manifest_path).read_bytes() == old_bytes
    assert list((tmp_path / "files").iterdir()) == [pathlib.Path(old.manifest_path)]


@pytest.mark.parametrize("failure_table", ["cba_diffs", "cba_diff_entries"])
def test_database_failure_rolls_back_replacement_and_retains_old_manifest(
        con, tmp_path, monkeypatch, failure_table):
    seed_pair(con)
    old = firmware_diff.run(con, tmp_path)
    before = diff_snapshot(con)
    old_bytes = pathlib.Path(old.manifest_path).read_bytes()
    seed_file(con, "target", "new-generation", "f" * 64)
    original = db.put

    def fail_write(connection, table, row, *, replace=False, commit=True):
        # Fail after a real write; accidental per-row commits must be detected.
        original(connection, table, row, replace=replace, commit=commit)
        if table == failure_table:
            raise sqlite3.OperationalError("injected database failure")

    monkeypatch.setattr(db, "put", fail_write)
    with pytest.raises(firmware_diff.FirmwareDiffError, match="injected database failure"):
        firmware_diff.run(con, tmp_path, replace=True)
    assert not con.in_transaction
    assert diff_snapshot(con) == before
    assert pathlib.Path(old.manifest_path).read_bytes() == old_bytes
    generations = list((tmp_path / "files").iterdir())
    assert len(generations) == 2
    for generation in generations:
        assert json.loads(generation.read_bytes())["id"] == old.id


def test_run_refuses_an_existing_transaction_without_rolling_back_caller_work(con, tmp_path):
    seed_pair(con)
    con.execute("UPDATE cba_images SET version = 'pending' WHERE id = 'target'")
    with pytest.raises(firmware_diff.FirmwareDiffError, match="transaction"):
        firmware_diff.run(con, tmp_path / "output")
    assert con.in_transaction
    assert con.execute("SELECT version FROM cba_images WHERE id = 'target'").fetchone()[0] == "pending"
    assert diff_snapshot(con) == ((), ())
    assert not (tmp_path / "output").exists()
