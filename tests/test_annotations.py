import json

import pytest

from audit_core import annotations


def journal(tmp_path):
    return tmp_path / "run" / annotations.JOURNAL_NAME


def test_append_creates_the_journal_and_round_trips(tmp_path):
    p = journal(tmp_path)
    annotations.append(p, "klap_handshake1_handle", "semantics",
                       "parses a 56-byte handshake; copies before checking length")
    entries, bad = annotations.read(p)
    assert bad == []
    assert len(entries) == 1
    assert entries[0].key == "klap_handshake1_handle"
    assert entries[0].kind == "semantics"
    assert entries[0].recorded_at


def test_every_line_is_one_json_object_terminated_by_exactly_one_newline(tmp_path):
    """Append-only JSONL is the point: a crash mid-write costs one line.
    Text mode on Windows would write CRLF and carry a stray \\r into values."""
    p = journal(tmp_path)
    annotations.append(p, "a", "semantics", "one")
    annotations.append(p, "b", "semantics", "two")
    raw = p.read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    lines = raw.split(b"\n")[:-1]
    assert len(lines) == 2
    assert all(isinstance(json.loads(ln), dict) for ln in lines)


def test_read_filters_by_key(tmp_path):
    p = journal(tmp_path)
    annotations.append(p, "a", "semantics", "one")
    annotations.append(p, "b", "semantics", "two")
    entries, _ = annotations.read(p, key="b")
    assert [e.text for e in entries] == ["two"]


def test_reading_a_journal_that_does_not_exist_yet_is_empty_not_an_error(tmp_path):
    assert annotations.read(tmp_path / "nothing.jsonl") == ([], [])


def test_a_corrupt_line_is_named_not_silently_dropped(tmp_path):
    """Review Focus 2. Silently skipping a bad line turns a one-line loss into
    an invisible one - and the journal is the source of truth."""
    p = journal(tmp_path)
    annotations.append(p, "a", "semantics", "one")
    with open(p, "ab") as fh:
        fh.write(b'{"key": "b", "kind": "sem"\n')     # crash mid-append
    annotations.append(p, "c", "semantics", "three")

    with pytest.raises(annotations.AnnotationError) as exc:
        annotations.read(p)
    assert "2" in str(exc.value)
    assert "tolerate" in str(exc.value)

    entries, bad = annotations.read(p, tolerate=True)
    assert [e.key for e in entries] == ["a", "c"]
    assert bad == [2]


def test_a_crlf_terminated_line_reads_cleanly(tmp_path):
    """A journal that has been through a Windows editor, or a CRLF-writing
    client, must not carry a stray carriage return into every value."""
    p = journal(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b'{"key":"a","kind":"semantics","text":"one",'
                  b'"source":null,"recorded_at":"2026-10-05T00:00:00+00:00"}\r\n')
    entries, bad = annotations.read(p)
    assert bad == []
    assert entries[0].text == "one"


def test_a_json_array_line_is_bad_not_an_entry(tmp_path):
    p = journal(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b'[1,2,3]\n')
    _, bad = annotations.read(p, tolerate=True)
    assert bad == [1]


def test_index_returns_one_bounded_row_per_key(tmp_path):
    """Spec section 5.2: the orchestrator holds the index, never the analysis."""
    p = journal(tmp_path)
    long_text = "x" * 400
    annotations.append(p, "klap", "semantics", "first pass")
    annotations.append(p, "klap", "semantics", long_text)
    annotations.append(p, "ssdp", "question", "is the handler reachable pre-auth?")

    rows, bad = annotations.index(p)
    assert bad == []
    assert [r.key for r in rows] == ["klap", "ssdp"]
    klap = rows[0]
    assert klap.entries == 2
    assert len(klap.summary) <= annotations.SUMMARY_CHARS + 1
    assert klap.summary.startswith("xxx")     # the latest entry, not the first
    assert klap.summary.endswith("…")


def test_index_tolerates_corruption_by_default_and_reports_it(tmp_path):
    p = journal(tmp_path)
    annotations.append(p, "a", "semantics", "one")
    with open(p, "ab") as fh:
        fh.write(b"not json\n")
    rows, bad = annotations.index(p)
    assert [r.key for r in rows] == ["a"]
    assert bad == [2]


def test_an_invented_kind_is_refused(tmp_path):
    with pytest.raises(annotations.AnnotationError) as exc:
        annotations.append(journal(tmp_path), "a", "vibes", "x")
    assert "vibes" in str(exc.value)
    assert "semantics" in str(exc.value)


def test_an_empty_key_or_text_is_refused(tmp_path):
    p = journal(tmp_path)
    with pytest.raises(annotations.AnnotationError):
        annotations.append(p, "  ", "semantics", "x")
    with pytest.raises(annotations.AnnotationError):
        annotations.append(p, "a", "semantics", "   ")


# --- Stage 3c Task 15: boundaries the first mutation sweep found unpinned ----

def test_a_summary_of_exactly_the_limit_is_not_truncated(tmp_path):
    """annotations.py:119. `len > SUMMARY_CHARS` cuts only what EXCEEDS the
    limit; text of exactly SUMMARY_CHARS is kept whole, with no ellipsis, and
    one character more is cut."""
    p = journal(tmp_path)
    annotations.append(p, "exact", "semantics", "y" * annotations.SUMMARY_CHARS)
    annotations.append(p, "over", "semantics", "y" * (annotations.SUMMARY_CHARS + 1))
    rows, _ = annotations.index(p)
    by_key = {r.key: r.summary for r in rows}
    assert by_key["exact"] == "y" * annotations.SUMMARY_CHARS
    assert by_key["over"] == "y" * annotations.SUMMARY_CHARS + "…"
