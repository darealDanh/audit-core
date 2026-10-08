import json, pathlib, pytest
from audit_core import goldens

HERE = pathlib.Path(__file__).resolve().parent
TPLINK = HERE / "goldens" / "tplink-dl110v2-1.0.11"


def test_reference_entries_load(tmp_path):
    p = tmp_path / "reference.json"
    p.write_text(json.dumps([{
        "id": "REF-13", "title": "KLAP handshake0 overflow", "cwe": "CWE-787",
        "locations": ["sub_E0941B4", "0x0E0941B4"],
        "root_cause_key": "klap-handshake0-unbounded-copy", "severity": "CRITICAL",
    }]))
    refs = goldens.load_reference(p)
    assert refs[0].id == "REF-13"
    assert "sub_E0941B4" in refs[0].locations


def test_duplicate_reference_ids_rejected(tmp_path):
    p = tmp_path / "reference.json"
    p.write_text(json.dumps([
        {"id": "REF-1", "title": "a", "cwe": None, "locations": ["f"],
         "root_cause_key": "k1", "severity": "CRITICAL"},
        {"id": "REF-1", "title": "b", "cwe": None, "locations": ["g"],
         "root_cause_key": "k2", "severity": "HIGH"},
    ]))
    with pytest.raises(goldens.GoldenError):
        goldens.load_reference(p)


def test_reference_without_locations_rejected(tmp_path):
    p = tmp_path / "reference.json"
    p.write_text(json.dumps([{"id": "REF-1", "title": "a", "cwe": None,
                              "locations": [], "root_cause_key": "k",
                              "severity": "CRITICAL"}]))
    with pytest.raises(goldens.GoldenError):
        goldens.load_reference(p)


def test_matches_file_loads_as_mapping(tmp_path):
    p = tmp_path / "matches.json"
    p.write_text(json.dumps({"REF-13": "F-1"}))
    assert goldens.load_matches(p) == {"REF-13": "F-1"}


def test_missing_matches_file_is_empty_mapping(tmp_path):
    assert goldens.load_matches(tmp_path / "absent.json") == {}


def test_tplink_golden_has_nineteen_criticals():
    refs = goldens.load_reference(TPLINK / "reference.json")
    assert len([r for r in refs if r.severity == "CRITICAL"]) == 19
    assert len({r.id for r in refs}) == len(refs)


def test_load_rejections_returns_pairs(tmp_path):
    p = tmp_path / "rejections.json"
    p.write_text('[{"reference_id": "REF-10", "finding_id": "G6-F3", '
                 '"reason": "bare `tss` token; unrelated defects"}]')
    assert goldens.load_rejections(p) == {("REF-10", "G6-F3")}


def test_a_missing_rejections_file_is_empty_not_an_error(tmp_path):
    assert goldens.load_rejections(tmp_path / "nope.json") == set()


def test_a_rejection_without_a_reason_is_refused(tmp_path):
    """A rejection with no reason is indistinguishable from a mistake, and it
    silences a candidate forever."""
    p = tmp_path / "rejections.json"
    p.write_text('[{"reference_id": "REF-10", "finding_id": "G6-F3"}]')
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_rejections(p)
    assert "reason" in str(exc.value)


def test_rejections_must_be_a_list(tmp_path):
    p = tmp_path / "rejections.json"
    p.write_text('{"REF-10": "G6-F3"}')
    with pytest.raises(goldens.GoldenError):
        goldens.load_rejections(p)


def test_tplink_rejections_name_real_reference_ids():
    """A rejection against an id no reference carries silences nothing and is
    almost certainly a typo in a hand-written file."""
    ids = {r.id for r in goldens.load_reference(TPLINK / "reference.json")}
    rejected = goldens.load_rejections(TPLINK / "rejections.json")
    assert rejected
    assert {ref for ref, _ in rejected} <= ids


def test_tplink_rejections_do_not_contradict_matches():
    """matches.json wins: a pair cannot be both adjudicated and rejected."""
    adjudicated = set(goldens.load_matches(TPLINK / "matches.json").items())
    assert adjudicated & goldens.load_rejections(TPLINK / "rejections.json") == set()


def test_a_rejection_that_is_not_an_object_is_refused(tmp_path):
    """A list of bare strings must fail as a golden error with a position, not
    as an AttributeError from item.get()."""
    p = tmp_path / "rejections.json"
    p.write_text('["REF-10"]')
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_rejections(p)
    assert "[0]" in str(exc.value)


@pytest.mark.parametrize("missing", ["reference_id", "finding_id", "reason"])
def test_a_rejection_missing_any_required_key_is_refused(tmp_path, missing):
    item = {"reference_id": "REF-10", "finding_id": "G6-F3", "reason": "why"}
    del item[missing]
    p = tmp_path / "rejections.json"
    p.write_text(json.dumps([item]))
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_rejections(p)
    assert missing in str(exc.value)


def test_a_blank_reason_is_refused_like_a_missing_one(tmp_path):
    p = tmp_path / "rejections.json"
    p.write_text(json.dumps([{"reference_id": "REF-10", "finding_id": "G6-F3",
                              "reason": "   "}]))
    with pytest.raises(goldens.GoldenError):
        goldens.load_rejections(p)


# --- loader validations (Stage 3c task 8). Every fixture lives in tmp_path;
# tests/goldens/ is the benchmark's only independent reference and is never
# written. All five _REQUIRED keys are present in _ref() so each test reaches
# the guard it names, not an earlier one.
def _ref(**over):
    base = {"id": "REF-1", "title": "t", "locations": ["a.c:1"],
            "root_cause_key": "cmdi", "severity": "HIGH"}
    base.update(over)
    return base


def test_reference_load_reports_unreadable_json(tmp_path):
    p = tmp_path / "refs.json"
    p.write_text("{not json")
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_reference(p)
    assert str(exc.value).startswith(f"cannot read {p}: ")


def test_reference_load_requires_a_list(tmp_path):
    p = tmp_path / "refs.json"
    p.write_text('{"id": "REF-1"}')
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_reference(p)
    assert str(exc.value) == f"{p}: expected a list of reference objects"


def test_reference_load_names_the_index_and_key_of_the_bad_entry(tmp_path):
    p = tmp_path / "refs.json"
    p.write_text(json.dumps([_ref(), {"id": "REF-2"}]))
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_reference(p)
    assert str(exc.value) == f"{p}[1]: missing 'title'"


def test_reference_without_root_cause_key_is_refused_before_locations(tmp_path):
    item = _ref(locations=[])
    del item["root_cause_key"]
    p = tmp_path / "refs.json"
    p.write_text(json.dumps([item]))
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_reference(p)
    assert str(exc.value) == f"{p}[0]: missing 'root_cause_key'"


def test_matches_load_reports_unreadable_json(tmp_path):
    p = tmp_path / "matches.json"
    p.write_text("{not json")
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_matches(p)
    assert str(exc.value).startswith(f"cannot read {p}: ")


def test_matches_load_requires_an_object(tmp_path):
    p = tmp_path / "matches.json"
    p.write_text('["REF-1", "F-1"]')
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_matches(p)
    assert str(exc.value) == (
        f"{p}: expected an object mapping reference id to finding id")


def test_matches_load_coerces_values_to_strings(tmp_path):
    p = tmp_path / "matches.json"
    p.write_text('{"REF-1": 7}')
    assert goldens.load_matches(p) == {"REF-1": "7"}


def test_rejections_load_reports_unreadable_json(tmp_path):
    p = tmp_path / "rejections.json"
    p.write_text("[not json")
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_rejections(p)
    assert str(exc.value).startswith(f"cannot read {p}: ")


def test_rejections_load_requires_a_list_with_its_own_message(tmp_path):
    p = tmp_path / "rejections.json"
    p.write_text('{"reference_id": "REF-10"}')
    with pytest.raises(goldens.GoldenError) as exc:
        goldens.load_rejections(p)
    assert str(exc.value) == f"{p}: expected a list of rejection objects"
