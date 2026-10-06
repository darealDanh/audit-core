import os

import pytest

from audit_core import db, patterns, sweep, workspace


def tree(root, **files):
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body if isinstance(body, bytes) else body.encode())
    return root


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path / "ws", timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    db.put(c, "cba_patterns", {"id": "P1", "name": "degenerate strncpy",
                               "regex": r"strncpy\([^,]+,[^,]+,\s*strlen\("})
    yield c
    c.close()


def test_a_pattern_whose_regex_does_not_compile_is_refused(con):
    """A stored pattern that cannot compile is a sweep that silently never
    runs - the worst outcome for a mechanism whose whole value is breadth."""
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_patterns", {"id": "P2", "name": "bad", "regex": "([a-z"})
    assert "compile" in str(exc.value)


def test_run_finds_hits_with_path_line_and_excerpt(tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "int f(void){\n  strncpy(dst, src, strlen(src));\n}\n",
        "b.c": "int g(void){ return 0; }\n",
    })
    r = sweep.run(root, r"strncpy\([^,]+,[^,]+,\s*strlen\(", pattern_id="P1")
    assert len(r.hits) == 1
    assert r.hits[0].path == "a.c"
    assert r.hits[0].line == 2
    assert "strncpy" in r.hits[0].excerpt
    assert r.files_scanned == 2
    assert r.truncated is False


def test_suffixes_narrow_the_scan(tmp_path):
    root = tree(tmp_path / "src", **{"a.c": "needle\n", "a.md": "needle\n"})
    r = sweep.run(root, "needle", suffixes=(".c",))
    assert [h.path for h in r.hits] == ["a.c"]


def test_skip_dirs_are_not_walked(tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "needle\n", "node_modules/pkg/b.js": "needle\n",
        ".git/objects/c": "needle\n",
    })
    r = sweep.run(root, "needle")
    assert [h.path for h in r.hits] == ["a.c"]


def test_a_binary_file_is_skipped_and_counted_not_decoded(tmp_path):
    """Review Focus 3. A firmware tree is mostly binary; decoding it is slow
    and the hits are noise."""
    root = tree(tmp_path / "src", **{"a.c": "needle\n",
                                     "fw.bin": b"needle\x00\x01\x02needle"})
    r = sweep.run(root, "needle")
    assert [h.path for h in r.hits] == ["a.c"]
    assert r.files_skipped_binary == 1


def test_an_oversized_file_is_skipped_and_counted(tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "needle\n",
        "bundle.js": "needle " + "x" * (sweep.MAX_FILE_BYTES + 1),
    })
    r = sweep.run(root, "needle")
    assert [h.path for h in r.hits] == ["a.c"]
    assert r.files_skipped_large == 1


def test_a_directory_symlink_loop_does_not_hang(tmp_path):
    """Review Focus 3. os.walk(followlinks=False) is the guard; this test is
    what proves it is still there after a refactor."""
    root = tree(tmp_path / "src", **{"sub/a.c": "needle\n"})
    try:
        os.symlink(root, root / "sub" / "loop", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not allow directory symlinks")
    r = sweep.run(root, "needle")
    assert [h.path for h in r.hits] == [os.path.join("sub", "a.c")]


def test_hits_are_capped_and_the_truncation_is_reported(tmp_path):
    """An uncapped sweep dumping ten thousand hits into the orchestrator is
    the exact failure R1 exists to prevent."""
    root = tree(tmp_path / "src", **{"a.c": "needle\n" * (sweep.MAX_HITS + 50)})
    r = sweep.run(root, "needle")
    assert len(r.hits) == sweep.MAX_HITS
    assert r.truncated is True
    assert "truncated" in sweep.render(r)


def test_a_custom_cap_is_honoured(tmp_path):
    root = tree(tmp_path / "src", **{"a.c": "needle\n" * 20})
    r = sweep.run(root, "needle", max_hits=5)
    assert (len(r.hits), r.truncated) == (5, True)


def test_an_excerpt_is_bounded(tmp_path):
    root = tree(tmp_path / "src", **{"a.c": "needle " + "y" * 900 + "\n"})
    r = sweep.run(root, "needle")
    assert len(r.hits[0].excerpt) <= sweep.EXCERPT_CHARS


def test_undecodable_bytes_in_a_text_file_do_not_raise(tmp_path):
    root = tree(tmp_path / "src", **{"a.c": b"needle \xff\xfe not utf8\n"})
    r = sweep.run(root, "needle")
    assert len(r.hits) == 1


def test_record_writes_one_row_per_hit_and_rows_reads_them_back(con, tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "strncpy(d, s, strlen(s));\n",
        "b.c": "strncpy(d, s, strlen(s));\n",
    })
    r = sweep.run(root, r"strncpy\([^,]+,[^,]+,\s*strlen\(", pattern_id="P1")
    assert sweep.record(con, r) == 2
    got = db.rows(con, "cba_pattern_hits", where={"pattern_id": "P1"},
                  columns=("path", "line", "triaged"))
    assert sorted(tuple(x) for x in got) == [("a.c", 1, "pending"),
                                             ("b.c", 1, "pending")]


def test_record_refuses_a_result_with_no_pattern_id(con, tmp_path):
    root = tree(tmp_path / "src", **{"a.c": "needle\n"})
    with pytest.raises(db.DbError):
        sweep.record(con, sweep.run(root, "needle"))


def test_render_never_prints_the_hits_themselves(tmp_path):
    """R1 applied to this tool's own output: the summary says how to read the
    rows, it does not paste them."""
    root = tree(tmp_path / "src", **{"a.c": "needle\n"})
    out = sweep.render(sweep.run(root, "needle", pattern_id="P1"))
    assert "needle" not in out
    assert "audit.py rows" in out
    assert "cba_pattern_hits" in out


REGEX = r"strncpy\([^,]+,[^,]+,\s*strlen\("


def test_record_marks_the_pattern_swept(con, tmp_path):
    root = tree(tmp_path / "src", **{
        "a.c": "strncpy(dst, src, strlen(src));\n",
        "b.c": "strncpy(d2, s2, strlen(s2));\n",
    })
    result = sweep.run(root, REGEX, pattern_id="P1")
    assert sweep.record(con, result) == 2
    state = patterns.states(con)[0]
    assert state.swept is True
    assert state.hit_count == 2


def test_record_refuses_a_truncated_sweep(con, tmp_path):
    """Review Focus 3. A sweep that stopped at its cap does not know what it
    did not see. Marking that pattern swept is a false coverage claim about
    the one mechanism whose whole value is breadth -- and the pattern would
    then never appear in `patterns.unswept` again."""
    root = tree(tmp_path / "src", **{
        "a.c": "strncpy(dst, src, strlen(src));\n",
        "b.c": "strncpy(d2, s2, strlen(s2));\n",
    })
    result = sweep.run(root, REGEX, pattern_id="P1", max_hits=1)
    assert result.truncated is True
    with pytest.raises(db.DbError) as exc:
        sweep.record(con, result)
    assert "truncated" in str(exc.value).lower()
    assert patterns.states(con)[0].swept is False
    assert db.rows(con, "cba_pattern_hits") == []


def test_the_sweep_skips_the_audits_own_run_directory(tmp_path):
    """IMPORTANT. `workflows/audit.md` and `references/phase4-deep-audit.md`
    both say to sweep with `--root .` from the project root, and
    `audit.py extract` writes verbatim source copies under
    `reports/audit-<ts>/extract/`. Reproduced: one real call site in the tree,
    two recorded hits -- one of them the audit's own copy of the other.

    Counting them inflates `hit_count` (a gate-document leading indicator),
    puts non-source paths in the triage list, and on a real corpus pushes
    toward MAX_HITS, which trips `record`'s truncation refusal, which makes
    `patterns --gate` unclearable.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("strcpy(dst, src);\n")
    extract = tmp_path / "reports" / "audit-20260105-120000" / "extract"
    extract.mkdir(parents=True)
    (extract / "a.c").write_text("strcpy(dst, src);\n")

    result = sweep.run(tmp_path, r"strcpy\(")
    assert [h.path for h in result.hits] == ["src/a.c"]
    assert "reports" in sweep.ROOT_ONLY_SKIP_DIRS


def test_a_nested_source_directory_called_reports_is_still_scanned(tmp_path):
    """The other direction, and the breakage the first version of this fix
    caused. `_scan` filters `dirnames` at every os.walk level, so putting
    `reports` in SKIP_DIRS excluded any directory of that name at any depth --
    and `render` reports skipped files, never skipped directories.

    On a project with an `app/reports/` or `src/reports/` source tree that is
    a silent false negative in a vulnerability scanner, and `patterns --gate`
    then reports PASS over it. The target was the audit's own run directory,
    which is a direct child of the scanned root; a source directory that
    happens to share the name is not.
    """
    (tmp_path / "src" / "reports").mkdir(parents=True)
    (tmp_path / "src" / "reports" / "export.c").write_text("strcpy(a, b);\n")
    (tmp_path / "src" / "core").mkdir()
    (tmp_path / "src" / "core" / "ok.c").write_text("strcpy(c, d);\n")
    # And the run directory at the root is still excluded, in the same tree.
    run_dir = tmp_path / "reports" / "audit-20260105-120000" / "extract"
    run_dir.mkdir(parents=True)
    (run_dir / "export.c").write_text("strcpy(a, b);\n")

    result = sweep.run(tmp_path, r"strcpy\(")
    assert sorted(h.path for h in result.hits) == [
        "src/core/ok.c", "src/reports/export.c"]
    assert "reports" not in sweep.SKIP_DIRS


def test_max_hits_is_clamped_to_the_modules_own_cap(tmp_path):
    """`--max-hits 100000` left `truncated` False on a sweep that stopped
    anyway, and that flag is the only thing standing between a partial hit
    list and a pattern permanently marked swept."""
    (tmp_path / "a.c").write_text("".join(
        "strcpy(a, b);\n" for _ in range(sweep.MAX_HITS + 50)))
    result = sweep.run(tmp_path, r"strcpy\(", max_hits=100_000)
    assert len(result.hits) == sweep.MAX_HITS
    assert result.truncated is True


def test_a_nonsense_max_hits_does_not_reach_islice(tmp_path):
    """`--max-hits -1` raised a bare ValueError out of itertools.islice."""
    (tmp_path / "a.c").write_text("strcpy(a, b);\nstrcpy(c, d);\n")
    result = sweep.run(tmp_path, r"strcpy\(", max_hits=-1)
    assert len(result.hits) == 1
    assert result.truncated is True
