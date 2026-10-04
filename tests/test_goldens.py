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
