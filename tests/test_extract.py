import pytest

from audit_core import extract


class Flaky:
    """A backend that stops being ready partway through, which is what a
    clobbered shared decompiler session looks like from the caller's side."""

    name = "flaky"

    def __init__(self, fail_from_batch: int, batch_size: int):
        self.fail_from_batch = fail_from_batch
        self.batch_size = batch_size
        self.checks = 0

    def assert_ready(self) -> None:
        self.checks += 1
        if self.checks > self.fail_from_batch:
            raise RuntimeError("session handle is stale")

    def read(self, item: str) -> bytes:
        return f"body of {item}".encode()


def tree(tmp_path, **files):
    root = tmp_path / "src"
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body.encode() if isinstance(body, str) else body)
    return root


def test_write_records_a_snapshot_and_its_digest(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    rec = store.write("G1", "auth.c", b"int main(void){}")
    assert rec.relpath == "extract/G1/auth.c"
    assert (tmp_path / "run" / "extract" / "G1" / "auth.c").read_bytes() == b"int main(void){}"
    assert rec.version == 1
    assert rec.bytes == 16
    assert len(rec.sha256) == 64


def test_rewriting_identical_content_does_not_bump_the_version(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    first = store.write("G1", "auth.c", b"same")
    again = store.write("G1", "auth.c", b"same")
    assert (first.version, again.version) == (1, 1)


def test_rewriting_changed_content_bumps_the_version(tmp_path):
    """Spec section 8: extract snapshots go stale as understanding improves.
    The version is how a reader knows the file under it moved."""
    store = extract.ExtractStore(tmp_path / "run")
    store.write("G1", "auth.c", b"v1")
    second = store.write("G1", "auth.c", b"v2")
    assert second.version == 2
    assert (tmp_path / "run" / "extract" / "G1" / "auth.c").read_bytes() == b"v2"


def test_manifest_survives_a_reopen(tmp_path):
    extract.ExtractStore(tmp_path / "run").write("G1", "auth.c", b"x")
    again = extract.ExtractStore(tmp_path / "run")
    assert [r.name for r in again.manifest()] == ["auth.c"]


def test_oversized_content_is_truncated_and_says_so(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    rec = store.write("G1", "big.js", b"a" * (extract.MAX_UNIT_BYTES + 10))
    assert rec.truncated is True
    assert rec.bytes <= extract.MAX_UNIT_BYTES + 200
    body = (tmp_path / "run" / "extract" / "G1" / "big.js").read_bytes()
    assert b"truncated by audit.py extract" in body


def test_a_unit_name_that_escapes_the_run_directory_is_refused(tmp_path):
    """Review Focus 1. A feature-group id and a source path both reach the
    filesystem; `..` must never be one of them."""
    store = extract.ExtractStore(tmp_path / "run")
    for bad in ("..", "../G1", "G1/../..", "/etc", ".hidden"):
        with pytest.raises(extract.ExtractError) as exc:
            store.write(bad, "auth.c", b"x")
        assert bad in str(exc.value)
    assert not (tmp_path / "run" / "extract").exists()


def test_a_snapshot_name_that_escapes_is_refused(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    with pytest.raises(extract.ExtractError):
        store.write("G1", "../../etc/passwd", b"x")


def test_flatten_turns_a_source_path_into_a_safe_name():
    assert extract.flatten("src/handlers/klap.c") == "src_handlers_klap.c"
    assert extract.flatten("/abs/path.c") == "abs_path.c"
    assert extract.flatten("../../etc/passwd") == "etc_passwd"
    assert extract.flatten(".env") == "env"


def test_source_tree_refuses_to_read_outside_its_root(tmp_path):
    root = tree(tmp_path, **{"a.c": "x"})
    (tmp_path / "secret").write_text("s")
    backend = extract.SourceTree(root)
    with pytest.raises(extract.ExtractError) as exc:
        backend.read("../secret")
    assert "escapes" in str(exc.value)


def test_extract_batch_asserts_readiness_once_per_batch(tmp_path):
    store = extract.ExtractStore(tmp_path / "run")
    backend = Flaky(fail_from_batch=99, batch_size=2)
    extract.extract_batch(store, backend, "G1", ["a", "b", "c", "d", "e"], batch_size=2)
    assert backend.checks == 3          # ceil(5 / 2)


def test_a_backend_that_fails_mid_run_aborts_and_names_the_batch(tmp_path):
    """Section 6.2's one-IDA-writer proof. A batch written after the session
    was clobbered is silently wrong, so the boundary check is the whole point."""
    store = extract.ExtractStore(tmp_path / "run")
    backend = Flaky(fail_from_batch=1, batch_size=2)
    with pytest.raises(extract.ExtractError) as exc:
        extract.extract_batch(store, backend, "G1", ["a", "b", "c", "d"], batch_size=2)
    msg = str(exc.value)
    assert "batch 1" in msg
    assert "flaky" in msg
    assert "stale" in msg
    # Batch 0 landed; batch 1 wrote nothing at all.
    assert sorted(r.name for r in store.manifest()) == ["a", "b"]


def test_a_read_failure_inside_a_batch_writes_none_of_that_batch(tmp_path):
    class Breaks:
        name = "breaks"
        def assert_ready(self): pass
        def read(self, item):
            if item == "c":
                raise OSError("gone")
            return b"ok"

    store = extract.ExtractStore(tmp_path / "run")
    with pytest.raises(OSError):
        extract.extract_batch(store, Breaks(), "G1", ["a", "b", "c"], batch_size=3)
    assert store.manifest() == []


def test_source_tree_round_trip(tmp_path):
    root = tree(tmp_path, **{"a.c": "alpha", "sub/b.c": "beta"})
    store = extract.ExtractStore(tmp_path / "run")
    recs = extract.extract_batch(store, extract.SourceTree(root), "G1",
                                 ["a.c", "sub/b.c"])
    assert sorted(r.name for r in recs) == ["a.c", "sub_b.c"]
    assert sorted(r.source for r in recs) == ["a.c", "sub/b.c"]
    assert (tmp_path / "run" / "extract" / "G1" / "sub_b.c").read_bytes() == b"beta"


def test_items_lists_what_a_unit_already_holds_so_refresh_can_re_read(tmp_path):
    root = tree(tmp_path, **{"a.c": "1", "b.c": "2"})
    store = extract.ExtractStore(tmp_path / "run")
    extract.extract_batch(store, extract.SourceTree(root), "G1", ["a.c", "b.c"])
    assert store.items("G1") == ["a.c", "b.c"]
    assert store.items("G2") == []
