import pytest

from audit_core import firmware_diff


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
