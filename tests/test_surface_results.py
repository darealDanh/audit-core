"""Agent claims need complete assignments, exact provenance and honest unknowns."""
import copy
import dataclasses
import hashlib
import json
import os
import pathlib
import sqlite3

import pytest

from audit_core import db, surface, workspace


HELLO = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
RESULT = '''{
 "schema_version":1,"image_id":"target","manifest_sha256":"MANIFEST",
 "worklist_sha256":"WORKLIST","batch_path":"batch-0001.json","batch_sha256":"BATCH",
 "decisions":[
  {"path":"etc/settings.conf","state":"analyzed","reason":"Configuration has no dispatcher.","surfaces":[],"unknowns":[]},
  {"path":"usr/httpd","state":"analyzed","reason":null,"surfaces":[
   {"surface_id":"http-status","component_path":"usr/httpd","entry_point":"GET /status","protocol":"http","dispatch_path":"route_status -> status","handler":"status","lifecycle_required":"provisioned","posture_required":"sta-lan","auth_required":"pre-auth","reachability":"evidenced","reach_evidence":"usr/httpd: route_status calls status before auth"}],"unknowns":[]},
  {"path":"usr/relay","state":"analyzed","reason":null,"surfaces":[
   {"surface_id":"relay-rpc","component_path":"usr/relay","entry_point":"RPC 1","protocol":"tcp","dispatch_path":"dispatch[1] -> relay","handler":"relay","lifecycle_required":"bound-to-owner","posture_required":"unknown","auth_required":"session","reachability":"evidenced","reach_evidence":"usr/relay: dispatch table slot 1"}],"unknowns":[
   {"id":"relay-posture","component_path":"usr/relay","surface_id":"relay-rpc","field":"posture","question":"Is relay available on the LAN?","settling_observation":"Observe bind interface after provisioning.","method":"hardware","status":"open","resolution":null,"evidence":null}]}]}
'''
# Hand-written, independently ordered canonical oracle; only fixture digests vary.
CANONICAL = ('{"batch_path":"batch-0001.json","batch_sha256":"BATCH","decisions":['
 '{"path":"etc/settings.conf","reason":"Configuration has no dispatcher.","state":"analyzed","surfaces":[],"unknowns":[]},'
 '{"path":"usr/httpd","reason":null,"state":"analyzed","surfaces":[{"auth_required":"pre-auth","component_path":"usr/httpd","dispatch_path":"route_status -> status","entry_point":"GET /status","handler":"status","lifecycle_required":"provisioned","posture_required":"sta-lan","protocol":"http","reach_evidence":"usr/httpd: route_status calls status before auth","reachability":"evidenced","surface_id":"http-status"}],"unknowns":[]},'
 '{"path":"usr/relay","reason":null,"state":"analyzed","surfaces":[{"auth_required":"session","component_path":"usr/relay","dispatch_path":"dispatch[1] -> relay","entry_point":"RPC 1","handler":"relay","lifecycle_required":"bound-to-owner","posture_required":"unknown","protocol":"tcp","reach_evidence":"usr/relay: dispatch table slot 1","reachability":"evidenced","surface_id":"relay-rpc"}],"unknowns":[{"component_path":"usr/relay","evidence":null,"field":"posture","id":"relay-posture","method":"hardware","question":"Is relay available on the LAN?","resolution":null,"settling_observation":"Observe bind interface after provisioning.","status":"open","surface_id":"relay-rpc"}]}],'
 '"image_id":"target","manifest_sha256":"MANIFEST","schema_version":1,"worklist_sha256":"WORKLIST"}\n')


@pytest.fixture
def prepared(tmp_path):
    run = workspace.init_run(tmp_path / "project", timestamp="20261014-000000")
    con = db.connect(run / "audit.db")
    root = tmp_path / "root"
    db.put(con, "cba_images", {"id": "target", "role": "target", "vendor": "v",
        "model": "m", "version": "1", "path": "image.bin", "sha256": "a" * 64})
    for path, kind in [("etc/settings.conf", "config"), ("usr/httpd", "file"),
                       ("usr/relay", "file"), ("zzz/outside", "file")]:
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(b"hello\n")
        db.put(con, "cba_firmware_files", {"image_id": "target", "path": path,
            "kind": kind, "size": "6", "sha256": HELLO})
        db.put(con, "cba_inventory", {"unit": path, "kind": kind, "size": "6"})
    summary = surface.prepare(con, run, root, batch_size=3)
    batch = pathlib.Path(summary.worklist_path).with_name("batch-0001.json")
    replacements = {"MANIFEST": summary.manifest_sha256, "WORKLIST": summary.worklist_sha256,
                    "BATCH": hashlib.sha256(batch.read_bytes()).hexdigest()}
    def substitute(text):
        for key, value in replacements.items():
            text = text.replace(key, value)
        return text
    yield con, run, json.loads(substitute(RESULT)), substitute(CANONICAL).encode(), summary
    con.close()


def api():
    # Import inside tests makes the missing implementation a precise RED failure.
    from audit_core import surface_results
    return surface_results


def load_payload(prepared, payload):
    path = prepared[1] / "result.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return api().load(path)


def validate_payload(prepared, payload):
    return api().validate(prepared[0], prepared[1], load_payload(prepared, payload))


def test_literal_complete_result_has_frozen_records_and_canonical_bytes(prepared):
    con, run, payload, expected, summary = prepared
    before = con.total_changes
    validated = validate_payload(prepared, payload)
    assert validated.assigned_units == ("etc/settings.conf", "usr/httpd", "usr/relay")
    assert validated.index_path == summary.worklist_path
    assert validated.result.schema_version == 1
    assert validated.result.decisions[0].surfaces == ()
    assert validated.result.decisions[1].surfaces[0].auth_required == "pre-auth"
    assert validated.result.decisions[2].unknowns[0].resolution is None
    assert api().canonical_bytes(validated) == expected
    assert con.total_changes == before and not con.in_transaction
    for record in (validated, validated.result, validated.result.decisions[1],
                   validated.result.decisions[1].surfaces[0], validated.result.decisions[2].unknowns[0]):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, dataclasses.fields(record)[0].name, "modified")


@pytest.mark.parametrize("raw", [b"\xff", b"{", b"[]", b"null", b"true", b"1",
    b'{"schema_version":1,"schema_version":1}', b'{"schema_version":NaN}',
    b'{"schema_version":Infinity}', b"[" * 1500 + b"]" * 1500])
def test_bad_json_is_named_and_never_writes(prepared, raw):
    con, run, *_ = prepared
    path = run / "bad.json"
    path.write_bytes(raw)
    before = con.total_changes
    with pytest.raises(surface.SurfaceError):
        api().load(path)
    assert con.total_changes == before


@pytest.mark.parametrize("location", ["result", "decision", "surface", "unknown"])
@pytest.mark.parametrize("damage", ["extra", "missing"])
def test_exact_keys_at_every_level(prepared, location, damage):
    payload = copy.deepcopy(prepared[2])
    objects = {"result": payload, "decision": payload["decisions"][0],
        "surface": payload["decisions"][1]["surfaces"][0],
        "unknown": payload["decisions"][2]["unknowns"][0]}
    row = objects[location]
    if damage == "extra":
        row["recorded_at"] = "agent supplied"
    else:
        row.pop(next(iter(row)))
    with pytest.raises(surface.SurfaceError):
        load_payload(prepared, payload)


TYPE_FIELDS = [
    ("result", "schema_version"), ("result", "image_id"), ("result", "decisions"),
    ("decision", "path"), ("decision", "state"), ("decision", "reason"),
    ("decision", "surfaces"), ("decision", "unknowns"),
    ("surface", "entry_point"), ("unknown", "surface_id"),
    ("unknown", "resolution"), ("unknown", "evidence"), ("unknown", "question")]


@pytest.mark.parametrize("location,key,value", [
    (location, key, value) for location, key in TYPE_FIELDS for value in [True, 1, {}, None]
    if not (key == "schema_version" and type(value) is int and value == 1)
    and not (value is None and key in ("reason", "surface_id", "resolution", "evidence"))])
def test_no_coercion_of_json_types(prepared, location, key, value):
    payload = copy.deepcopy(prepared[2])
    row = {"result": payload, "decision": payload["decisions"][0],
        "surface": payload["decisions"][1]["surfaces"][0],
        "unknown": payload["decisions"][2]["unknowns"][0]}[location]
    row[key] = value
    with pytest.raises(surface.SurfaceError):
        load_payload(prepared, payload)


def test_input_limit_is_checked_before_json_parsing(prepared):
    path = prepared[1] / "large.json"
    path.write_bytes(b" " * (8 * 1024 * 1024 + 1))
    with pytest.raises(surface.SurfaceError, match="size|large|limit|bytes"):
        api().load(path)


def test_exact_size_limit_accepts_json_without_truncation(prepared):
    path = prepared[1] / "boundary.json"
    content = json.dumps(prepared[2]).encode()
    path.write_bytes(content + b" " * (8 * 1024 * 1024 - len(content)))
    assert api().load(path).image_id == "target"


def test_duplicate_json_key_error_never_reflects_untrusted_key(prepared):
    # Breaks: reflecting a huge or terminal-active key in a parser diagnostic.
    key = "PRIVATE_KEY\n\r\t\x1b\x00" + "x" * 100_000
    encoded_key = json.dumps(key)
    path = prepared[1] / "duplicate.json"
    path.write_text('{"nested":{' + encoded_key + ':0,' + encoded_key + ':1}}')
    with pytest.raises(surface.SurfaceError) as caught:
        api().load(path)
    assert len(str(caught.value)) < 100
    assert str(caught.value) == "Duplicate JSON key"


@pytest.mark.parametrize("damage", ["missing", "directory", "symlink", "unreadable", "surrogate"])
def test_result_files_and_text_fail_closed(prepared, monkeypatch, damage):
    path = prepared[1] / "input.json"
    if damage == "directory":
        path.mkdir()
    elif damage == "symlink":
        real = path.with_name("real.json")
        real.write_text(json.dumps(prepared[2]))
        path.symlink_to(real)
    elif damage == "unreadable":
        path.write_bytes(b"{}")
        original = pathlib.Path.open
        def refuse(file, *args, **kwargs):
            if file == path:
                raise PermissionError("result read denied")
            return original(file, *args, **kwargs)
        monkeypatch.setattr(pathlib.Path, "open", refuse)
    elif damage == "surrogate":
        payload = prepared[2] | {"image_id": "\ud800"}
        path.write_text(json.dumps(payload))
    with pytest.raises(surface.SurfaceError):
        api().load(path)


@pytest.mark.parametrize("key,value", [
    ("schema_version", 2), ("image_id", "other"), ("image_id", "legacy-unscoped"),
    ("manifest_sha256", "b" * 64), ("worklist_sha256", "b" * 64),
    ("batch_sha256", "b" * 64), ("manifest_sha256", "A" * 64),
    ("worklist_sha256", "a"), ("batch_sha256", "z" * 64),
    ("batch_path", "../batch-0001.json"), ("batch_path", "/batch-0001.json"),
    ("batch_path", "batch-9999.json")])
def test_provenance_must_match_prepared_target(prepared, key, value):
    before = prepared[0].total_changes
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, prepared[2] | {key: value})
    assert prepared[0].total_changes == before


@pytest.mark.parametrize("damage", ["omit", "extra", "duplicate", "surface-outside",
    "surface-other-decision", "unknown-outside", "unknown-other-decision"])
def test_exact_batch_membership_and_row_ownership(prepared, damage):
    payload = copy.deepcopy(prepared[2])
    if damage == "omit":
        payload["decisions"].pop()
    elif damage == "extra":
        payload["decisions"].append({"path": "zzz/outside", "state": "analyzed",
                                   "reason": None, "surfaces": [], "unknowns": []})
    elif damage == "duplicate":
        payload["decisions"].append(copy.deepcopy(payload["decisions"][0]))
    elif damage.startswith("surface"):
        payload["decisions"][1]["surfaces"][0]["component_path"] = (
            "zzz/outside" if damage == "surface-outside" else "usr/relay")
    else:
        payload["decisions"][2]["unknowns"][0]["component_path"] = (
            "zzz/outside" if damage == "unknown-outside" else "usr/httpd")
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, payload)


def test_membership_is_established_before_row_semantics(prepared):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"].pop()
    payload["decisions"][1]["surfaces"][0]["auth_required"] = "invalid"
    with pytest.raises(surface.SurfaceError, match="membership|assigned|decision|missing"):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("reason", [None, "", " \t\n"])
def test_analyzed_empty_batch_cannot_claim_coverage_without_explanations(prepared, reason):
    payload = copy.deepcopy(prepared[2])
    for decision in payload["decisions"]:
        decision.update(reason=reason, surfaces=[], unknowns=[])
    before = prepared[0].total_changes
    with pytest.raises(surface.SurfaceError, match="explanation|reason"):
        validate_payload(prepared, payload)
    assert prepared[0].total_changes == before


@pytest.mark.parametrize("reason", [None, "", " \t\n"])
def test_explanatory_unknown_can_support_analyzed_decision_without_a_surface(prepared, reason):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][0].update(reason=reason, unknowns=[{
        "id": "config-dispatch", "component_path": "etc/settings.conf", "surface_id": None,
        "field": "dispatch", "question": "Does this configuration select an undiscovered service wrapper?",
        "settling_observation": "Trace the configured wrapper to its caller.",
        "method": "static", "status": "open", "resolution": None, "evidence": None}])
    validated = validate_payload(prepared, payload)
    assert validated.result.decisions[0].reason == reason
    assert validated.result.decisions[0].unknowns[0].id == "config-dispatch"


def test_no_surface_explanation_is_retained_in_the_canonical_artifact(prepared):
    validated = validate_payload(prepared, prepared[2])
    assert b'"reason":"Configuration has no dispatcher."' in api().canonical_bytes(validated)


@pytest.mark.parametrize("damage", ["missing-reason", "blank-reason", "bad-reason", "surface", "bad-state"])
def test_coverage_decisions_follow_existing_coverage_contract(prepared, damage):
    payload = copy.deepcopy(prepared[2])
    row = payload["decisions"][0 if damage != "surface" else 1]
    row["state"] = "not_audited"
    row["reason"] = {"missing-reason": None, "blank-reason": " ", "bad-reason": "guess",
                     "surface": "budget", "bad-state": "budget"}[damage]
    if damage == "bad-state":
        row["state"] = "skipped"
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("field", ["surface_id", "entry_point", "protocol", "dispatch_path", "handler",
    "lifecycle_required", "posture_required", "auth_required", "reachability", "reach_evidence"])
def test_blank_surface_fields_refuse(prepared, field):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][1]["surfaces"][0][field] = "   "
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("field", ["lifecycle_required", "posture_required", "auth_required", "reachability"])
@pytest.mark.parametrize("value", ["invalid", "unknown"])
def test_surface_states_need_valid_enums_and_matching_open_questions(prepared, field, value):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][1]["surfaces"][0][field] = value
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("damage", ["id", "duplicate-surface", "duplicate-unknown", "dangling",
    "other-component-link", "blank-link", "bad-field", "bad-method", "bad-status", "blank-question",
    "blank-observation", "open-resolution", "open-evidence", "resolved-resolution", "resolved-evidence"])
def test_unknown_identity_payload_and_linkage(prepared, damage):
    payload = copy.deepcopy(prepared[2])
    row = payload["decisions"][2]["unknowns"][0]
    if damage == "duplicate-surface":
        payload["decisions"][2]["surfaces"][0]["surface_id"] = "http-status"
    elif damage == "duplicate-unknown":
        payload["decisions"][2]["unknowns"].append(copy.deepcopy(row))
    else:
        key, value = {
            "id": ("id", "../bad"), "dangling": ("surface_id", "absent"),
            "other-component-link": ("surface_id", "http-status"), "blank-link": ("surface_id", ""),
            "bad-field": ("field", "state"), "bad-method": ("method", "guess"),
            "bad-status": ("status", "closed"), "blank-question": ("question", " "),
            "blank-observation": ("settling_observation", " "),
            "open-resolution": ("resolution", "solved"), "open-evidence": ("evidence", "proof"),
            "resolved-resolution": ("resolution", None), "resolved-evidence": ("evidence", None)
        }[damage]
        if damage.startswith("resolved"):
            row.update(status="resolved", resolution="LAN", evidence="bind observation")
        row[key] = value
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("field,key", [("lifecycle", "lifecycle_required"), ("posture", "posture_required"),
                                      ("auth", "auth_required"), ("reachability", "reachability")])
def test_matching_open_unknown_per_field_validates(prepared, field, key):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][2]["surfaces"][0]["posture_required"] = "sta-lan"
    payload["decisions"][2]["surfaces"][0][key] = "unknown"
    payload["decisions"][2]["unknowns"][0]["field"] = field
    validate_payload(prepared, payload)


def test_resolved_and_unattached_unknowns_are_valid_without_unknown_state(prepared):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][2]["surfaces"][0]["posture_required"] = "sta-lan"
    row = payload["decisions"][2]["unknowns"][0]
    row.update(status="resolved", resolution="LAN only", evidence="usr/relay: bind LAN")
    validate_payload(prepared, payload)
    row.update(surface_id=None, status="open", resolution="", evidence="", field="dispatch")
    validate_payload(prepared, payload)


def test_resolved_question_does_not_settle_an_unknown_state(prepared):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][2]["unknowns"][0].update(
        status="resolved", resolution="LAN", evidence="bind observation")
    with pytest.raises(surface.SurfaceError, match="open unknown"):
        validate_payload(prepared, payload)


def test_budget_decision_is_valid_output_for_the_later_completion_gate(prepared):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][0].update(state="not_audited", reason="budget")
    validated = validate_payload(prepared, payload)
    assert validated.result.decisions[0].state == "not_audited"


@pytest.mark.parametrize("value", ["../bad", "x" * 129, "_prefix", "é", "a/b"])
def test_surface_ids_use_the_safe_identifier_alphabet(prepared, value):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][1]["surfaces"][0]["surface_id"] = value
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, payload)


def test_canonical_result_preserves_utf8_and_excludes_host_paths(prepared):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][0]["reason"] = "Phân tích cấu hình."
    content = api().canonical_bytes(validate_payload(prepared, payload))
    assert '"reason":"Phân tích cấu hình."'.encode() in content
    assert str(prepared[1]).encode() not in content
    assert content.endswith(b"}\n") and not content.endswith(b"\n\n")


@pytest.mark.parametrize("damage", ["wrong-role", "empty-manifest", "changed-manifest", "inventory",
    "no-run", "run-manifest", "run-count", "index-missing", "index-bytes", "batch-missing", "batch-bytes"])
def test_changed_prepared_inputs_refuse_without_writes(prepared, damage):
    con, run, payload, _, summary = prepared
    index_path = pathlib.Path(summary.worklist_path)
    sql = {"wrong-role": "UPDATE cba_images SET role='diff-reference'",
        "empty-manifest": "DELETE FROM cba_firmware_files",
        "changed-manifest": "UPDATE cba_firmware_files SET sha256='" + "b" * 64 + "'",
        "inventory": "DELETE FROM cba_inventory WHERE unit='zzz/outside'",
        "no-run": "DELETE FROM cba_surface_runs",
        "run-manifest": "UPDATE cba_surface_runs SET manifest_sha256='" + "b" * 64 + "'",
        "run-count": "UPDATE cba_surface_runs SET unit_count=5"}
    if damage in sql:
        con.execute(sql[damage])
        con.commit()
    else:
        file = index_path if damage.startswith("index") else index_path.with_name("batch-0001.json")
        if damage.endswith("missing"):
            file.unlink()
        else:
            # Parseable altered bytes must still fail the independently bound hash.
            file.write_bytes(file.read_bytes() + b" ")
    before = con.total_changes
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, payload)
    assert con.total_changes == before and not con.in_transaction


def test_expected_sql_read_failures_are_named(prepared):
    result = load_payload(prepared, prepared[2])
    con = sqlite3.connect(":memory:")
    try:
        with pytest.raises(surface.SurfaceError):
            api().validate(con, prepared[1], result)
    finally:
        con.close()


def test_worklist_directory_stat_failure_is_named_and_pure(prepared, monkeypatch):
    result = load_payload(prepared, prepared[2])
    directory = pathlib.Path(prepared[4].worklist_path).parent
    original = pathlib.Path.is_symlink
    def denied(path):
        if path == directory:
            raise PermissionError("generation directory stat denied")
        return original(path)
    monkeypatch.setattr(pathlib.Path, "is_symlink", denied)
    before = prepared[0].total_changes
    with pytest.raises(surface.SurfaceError, match="directory stat denied"):
        api().validate(prepared[0], prepared[1], result)
    assert prepared[0].total_changes == before


@pytest.mark.parametrize("damage", ["surrogate", "nonrecord", "recursive"])
def test_direct_typed_results_cannot_leak_encoding_or_shape_errors(prepared, damage):
    result = load_payload(prepared, prepared[2])
    if damage == "surrogate":
        result = dataclasses.replace(result, image_id="\ud800")
    elif damage == "nonrecord":
        result = dataclasses.replace(result, decisions=(object(),))
    else:
        recursive = []
        recursive.append(recursive)
        result = dataclasses.replace(result, decisions=recursive)
    with pytest.raises(surface.SurfaceError):
        api().validate(prepared[0], prepared[1], result)


def test_validate_refuses_untyped_result(prepared):
    with pytest.raises(surface.SurfaceError):
        api().validate(prepared[0], prepared[1], prepared[2])


def rebind_generation(prepared, index, batch):
    """Test-only corrupt generation with consistent hashes, reaching shape checks."""
    con, run, payload, _, summary = prepared
    old_path = pathlib.Path(summary.worklist_path)
    batch_bytes = json.dumps(batch).encode()
    batch_sha = hashlib.sha256(batch_bytes).hexdigest()
    if isinstance(index, dict) and isinstance(index.get("batches"), list):
        for descriptor in index["batches"]:
            if isinstance(descriptor, dict) and descriptor.get("path") == "batch-0001.json":
                descriptor["sha256"] = batch_sha
    index_bytes = json.dumps(index).encode()
    worklist_sha = hashlib.sha256(index_bytes).hexdigest()
    destination = run / "files/surface" / worklist_sha
    destination.mkdir()
    (destination / "index.json").write_bytes(index_bytes)
    (destination / "batch-0001.json").write_bytes(batch_bytes)
    (destination / "batch-0002.json").write_bytes(old_path.with_name("batch-0002.json").read_bytes())
    con.execute("UPDATE cba_surface_runs SET worklist_path=?,worklist_sha256=?",
                (str(destination / "index.json"), worklist_sha))
    con.commit()
    return payload | {"worklist_sha256": worklist_sha, "batch_sha256": batch_sha}


@pytest.mark.parametrize("damage", ["index-array", "index-extra", "index-schema", "index-image",
    "index-manifest", "batch-size", "unit-count-bool", "unit-count", "batches-object", "batches-empty",
    "descriptor-null", "descriptor-path", "descriptor-duplicate", "descriptor-digest", "descriptor-count",
    "descriptor-count-bool", "total-count", "batch-array", "batch-extra", "batch-schema", "batch-image",
    "batch-manifest", "batch-id", "units-object", "unit-null", "unit-missing", "unit-duplicate",
    "unit-content", "unit-unassigned", "unit-count"])
def test_hash_consistent_artifacts_still_need_valid_shapes_and_current_units(prepared, damage):
    index_path = pathlib.Path(prepared[4].worklist_path)
    index = json.loads(index_path.read_bytes())
    batch = json.loads(index_path.with_name("batch-0001.json").read_bytes())
    if damage == "index-array":
        index = []
    elif damage in ("index-extra", "index-schema", "index-image", "index-manifest", "batch-size", "unit-count-bool", "unit-count", "batches-object", "batches-empty"):
        key, value = {"index-extra": ("timestamp", "agent"), "index-schema": ("schema_version", True),
            "index-image": ("image_id", "other"), "index-manifest": ("manifest_sha256", "b" * 64),
            "batch-size": ("batch_size", 0), "unit-count-bool": ("unit_count", True),
            "unit-count": ("unit_count", 5), "batches-object": ("batches", {}),
            "batches-empty": ("batches", [])}[damage]
        index[key] = value
    elif damage.startswith("descriptor") or damage == "total-count":
        descriptor = index["batches"][1]
        if damage == "descriptor-null":
            index["batches"][1] = None
        elif damage == "descriptor-duplicate":
            descriptor["path"] = "batch-0001.json"
        else:
            key, value = {"descriptor-path": ("path", "../outside.json"),
                "descriptor-digest": ("sha256", "A" * 64), "descriptor-count": ("unit_count", 4),
                "descriptor-count-bool": ("unit_count", True), "total-count": ("unit_count", 2)}[damage]
            descriptor[key] = value
    elif damage == "batch-array":
        batch = []
    elif damage in ("batch-extra", "batch-schema", "batch-image", "batch-manifest", "batch-id", "units-object"):
        key, value = {"batch-extra": ("timestamp", "agent"), "batch-schema": ("schema_version", True),
            "batch-image": ("image_id", "other"), "batch-manifest": ("manifest_sha256", "b" * 64),
            "batch-id": ("batch_id", "batch-0002"), "units-object": ("units", {})}[damage]
        batch[key] = value
    elif damage == "unit-null":
        batch["units"][0] = None
    elif damage == "unit-missing":
        batch["units"][0].pop("path")
    elif damage == "unit-duplicate":
        batch["units"][1] = batch["units"][0]
    elif damage == "unit-content":
        batch["units"][0]["sha256"] = "b" * 64
    elif damage == "unit-unassigned":
        batch["units"][0]["path"] = "no-such-component"
    else:
        batch["units"].pop()
    payload = rebind_generation(prepared, index, batch)
    before = prepared[0].total_changes
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, payload)
    assert prepared[0].total_changes == before


@pytest.mark.parametrize("damage", ["path-outside", "generation-link", "files-link", "batch-link"])
def test_prepared_artifacts_cannot_escape_the_run(prepared, damage):
    con, run, payload, _, summary = prepared
    index = pathlib.Path(summary.worklist_path)
    if damage == "path-outside":
        outside = run / "outside.json"
        outside.write_bytes(index.read_bytes())
        con.execute("UPDATE cba_surface_runs SET worklist_path=?", (str(outside),))
        con.commit()
    else:
        path = index.parent if damage == "generation-link" else (
            run / "files" if damage == "files-link" else index.with_name("batch-0001.json"))
        saved = run / "saved-artifact"
        path.rename(saved)
        path.symlink_to(saved, target_is_directory=damage != "batch-link")
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("collision", ["surface", "unknown", "other-image-unknown"])
def test_ids_cannot_steal_rows_owned_by_other_batches_or_images(prepared, collision):
    con, *_ = prepared
    if collision == "surface":
        con.execute("INSERT INTO cba_firmware_surfaces (image_id,surface_id,component_path,entry_point,protocol,dispatch_path,handler,lifecycle_required,posture_required,auth_required,reachability,reach_evidence,artifact_path,artifact_sha256) VALUES ('target','http-status','zzz/outside','e','p','d','h','provisioned','sta-lan','pre-auth','evidenced','proof','old','" + "a" * 64 + "')")
    else:
        image = "other" if collision == "other-image-unknown" else "target"
        con.execute("INSERT INTO cba_unknowns (id,image_id,component_path,field,question,settling_observation,method,status,artifact_path,artifact_sha256) VALUES ('relay-posture',?,'zzz/outside','dispatch','q','o','static','open','old',?)", (image, "a" * 64))
    con.commit()
    before = con.total_changes
    with pytest.raises(surface.SurfaceError):
        validate_payload(prepared, prepared[2])
    assert con.total_changes == before


def sql_snapshot(con):
    """Include all contracted tables, timestamps and unrelated phase/image rows."""
    return {table: sorted((tuple(row) for row in con.execute(f"SELECT * FROM {table}")), key=repr)
            for table in db.TABLE_SPECS}


def record_payload(prepared, payload=None, **kwargs):
    load_payload(prepared, prepared[2] if payload is None else payload)
    return api().record(prepared[0], prepared[1], prepared[1] / "result.json", **kwargs)


def sibling_payload(prepared):
    batch = pathlib.Path(prepared[4].worklist_path).with_name("batch-0002.json")
    decision = copy.deepcopy(prepared[2]["decisions"][2])
    decision["path"] = "zzz/outside"
    decision["surfaces"][0].update(component_path="zzz/outside", surface_id="outside-rpc")
    decision["unknowns"][0].update(component_path="zzz/outside", surface_id="outside-rpc", id="outside-posture")
    return prepared[2] | {"batch_path": "batch-0002.json",
        "batch_sha256": hashlib.sha256(batch.read_bytes()).hexdigest(), "decisions": [decision]}


def completed(con):
    con.execute("UPDATE cba_surface_runs SET status='complete',completed_at='old-completion'")
    con.commit()


def test_import_derives_canonical_provenance_and_publishes_exact_rows(prepared):
    # Breaks: persisting raw input bytes, partial coverage, or completing during import.
    con, run, payload, canonical, _ = prepared
    completed(con)
    summary = record_payload(prepared)
    digest = hashlib.sha256(canonical).hexdigest()
    artifact = pathlib.Path(summary.artifact_path)
    assert artifact.relative_to(run / "artifacts/surface").parts == (digest, "result.json")
    assert artifact.read_bytes() == canonical
    assert dataclasses.asdict(summary) == {"image_id": "target", "batch_path": "batch-0001.json",
        "unit_count": 3, "surface_count": 2, "unknown_count": 1, "artifact_path": str(artifact)}
    with pytest.raises(dataclasses.FrozenInstanceError):
        summary.unit_count = 99
    assert [tuple(row) for row in con.execute(
        "SELECT unit,phase,state,reason FROM cba_coverage ORDER BY unit")] == [
        ("etc/settings.conf", "surface", "analyzed", "Configuration has no dispatcher."),
        ("usr/httpd", "surface", "analyzed", None), ("usr/relay", "surface", "analyzed", None)]
    for decision in payload["decisions"]:
        for table, records in [("cba_firmware_surfaces", decision["surfaces"]), ("cba_unknowns", decision["unknowns"])]:
            for expected in records:
                key = "surface_id" if table == "cba_firmware_surfaces" else "id"
                row = dict(con.execute(f"SELECT * FROM {table} WHERE {key}=?", (expected[key],)).fetchone())
                assert row.pop("recorded_at")
                assert row == expected | {"image_id": "target", "artifact_path": str(artifact), "artifact_sha256": digest}
    assert tuple(con.execute("SELECT status,completed_at FROM cba_surface_runs").fetchone()) == ("pending", None)
    assert not con.in_transaction


def test_all_units_imported_still_require_the_explicit_completion_gate(prepared):
    record_payload(prepared)
    record_payload(prepared, sibling_payload(prepared))
    assert prepared[0].execute("SELECT COUNT(*) FROM cba_coverage WHERE phase='surface'").fetchone()[0] == 4
    assert tuple(prepared[0].execute("SELECT status,completed_at FROM cba_surface_runs").fetchone()) == ("pending", None)


@pytest.mark.parametrize("existing", ["import", "surface", "unknown", "coverage"])
def test_duplicate_refusal_preserves_entire_sql_generation(prepared, existing):
    # Breaks: duplicate checking coverage alone or deleting prior rows before refusing.
    con = prepared[0]
    record_payload(prepared)
    if existing != "import":
        keep = {"surface": "cba_firmware_surfaces", "unknown": "cba_unknowns", "coverage": "cba_coverage"}[existing]
        for table in ("cba_firmware_surfaces", "cba_unknowns", "cba_coverage"):
            if table != keep:
                con.execute(f"DELETE FROM {table}")
        con.commit()
    completed(con)
    before = sql_snapshot(con)
    with pytest.raises(surface.SurfaceError, match="existing|already|replace|duplicate"):
        record_payload(prepared)
    assert sql_snapshot(con) == before
    assert not con.in_transaction


def test_replacement_reuses_owned_ids_removes_stale_rows_and_preserves_sibling(prepared):
    # Breaks: refusing owned IDs, blanket image deletes, or retaining stale batch rows.
    con = prepared[0]
    first = record_payload(prepared)
    record_payload(prepared, sibling_payload(prepared))
    db.put(con, "cba_coverage", {"unit": "usr/httpd", "phase": "audit", "state": "analyzed"})
    completed(con)
    before = sql_snapshot(con)
    changed = copy.deepcopy(prepared[2])
    changed["decisions"][1].update(surfaces=[], unknowns=[], reason="Dispatcher retired in revised analysis.")
    changed["decisions"][2]["surfaces"][0].update(handler="revised-relay", posture_required="sta-lan")
    changed["decisions"][2]["unknowns"][0].update(status="resolved", resolution="LAN only", evidence="usr/relay: bind LAN")
    validated = validate_payload(prepared, changed)
    assert validated.result.decisions[2].surfaces[0].surface_id == "relay-rpc"
    assert validated.result.decisions[2].unknowns[0].id == "relay-posture"
    summary = record_payload(prepared, changed, replace=True)
    assert summary.artifact_path != first.artifact_path
    after = sql_snapshot(con)
    for table, column in [("cba_firmware_surfaces", 2), ("cba_unknowns", 2), ("cba_coverage", 0)]:
        assert [r for r in after[table] if r[column] == "zzz/outside"] == [r for r in before[table] if r[column] == "zzz/outside"]
    assert [r for r in after["cba_coverage"] if r[1] == "audit"] == [r for r in before["cba_coverage"] if r[1] == "audit"]
    assert con.execute("SELECT surface_id,handler FROM cba_firmware_surfaces WHERE component_path='usr/relay'").fetchone()[1] == "revised-relay"
    assert con.execute("SELECT status,resolution FROM cba_unknowns WHERE id='relay-posture'").fetchone()[1] == "LAN only"
    assert con.execute("SELECT COUNT(*) FROM cba_firmware_surfaces WHERE component_path='usr/httpd'").fetchone()[0] == 0
    assert pathlib.Path(first.artifact_path).read_bytes() == prepared[3]


@pytest.mark.parametrize("collision", ["surface", "unknown"])
def test_replace_cannot_take_a_sibling_batch_id(prepared, collision):
    record_payload(prepared)
    record_payload(prepared, sibling_payload(prepared))
    payload = copy.deepcopy(prepared[2])
    if collision == "surface":
        payload["decisions"][1]["surfaces"][0]["surface_id"] = "outside-rpc"
    else:
        payload["decisions"][2]["unknowns"][0]["id"] = "outside-posture"
    before = sql_snapshot(prepared[0])
    with pytest.raises(surface.SurfaceError, match="another.*batch"):
        record_payload(prepared, payload, replace=True)
    assert sql_snapshot(prepared[0]) == before


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("failure", ["mkdir", "create", "write", "replace", "surface-insert", "unknown-insert", "coverage-insert", "commit"])
def test_failed_import_preserves_exact_prior_sql(prepared, monkeypatch, replace, failure):
    # Breaks: SQL before immutable installation, early commits, or incomplete rollback.
    con, run, payload, *_ = prepared
    record_payload(prepared, sibling_payload(prepared))
    if replace:
        record_payload(prepared)
    completed(con)
    before = sql_snapshot(con)
    old_files = {p: p.read_bytes() for p in (run / "artifacts/surface").rglob("*.json")}
    changed = copy.deepcopy(payload)
    changed["decisions"][1]["surfaces"][0]["handler"] = "changed-handler"
    load_payload(prepared, changed)
    if failure == "mkdir":
        monkeypatch.setattr(pathlib.Path, "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("injected mkdir")))
    elif failure == "create":
        monkeypatch.setattr(surface.tempfile, "mkdtemp", lambda *a, **k: (_ for _ in ()).throw(OSError("injected create")))
    elif failure == "write":
        monkeypatch.setattr(pathlib.Path, "write_bytes", lambda *a, **k: (_ for _ in ()).throw(OSError("injected write")))
    elif failure == "replace":
        monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("injected replace")))
    elif failure.endswith("insert"):
        table = {"surface-insert": "cba_firmware_surfaces", "unknown-insert": "cba_unknowns", "coverage-insert": "cba_coverage"}[failure]
        con.execute(f"CREATE TRIGGER fail_record BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected SQL'); END")
        con.commit()
    else:
        class CommitFailure(sqlite3.Connection):
            def commit(self):
                raise sqlite3.OperationalError("injected commit")
        con = sqlite3.connect(run / "audit.db", factory=CommitFailure)
        con.row_factory = sqlite3.Row
    try:
        with pytest.raises(surface.SurfaceError, match="injected"):
            api().record(con, run, run / "result.json", replace=replace)
        assert sql_snapshot(con) == before
        assert not con.in_transaction
        current_files = {p: p.read_bytes() for p in (run / "artifacts/surface").rglob("*.json")}
        assert all(current_files[p] == content for p, content in old_files.items())
        extras = set(current_files) - set(old_files)
        assert len(extras) == (1 if failure.endswith("insert") or failure == "commit" else 0)
        for artifact in extras:
            assert artifact.parent.name == hashlib.sha256(current_files[artifact]).hexdigest()
            assert not any(str(artifact) in repr(row) for rows in before.values() for row in rows)
        assert not list((run / "artifacts/surface").glob(".surface-*"))
    finally:
        if failure == "commit":
            con.close()


def test_import_refuses_caller_transaction_without_rolling_it_back(prepared):
    con = prepared[0]
    con.execute("UPDATE cba_surface_runs SET completed_at='caller-owned'")
    before = sql_snapshot(con)
    with pytest.raises(surface.SurfaceError, match="active transaction"):
        record_payload(prepared)
    assert con.in_transaction
    assert sql_snapshot(con) == before
    assert not (prepared[1] / "artifacts/surface").exists()


def test_invalid_import_installs_no_artifact_or_sql(prepared):
    before = sql_snapshot(prepared[0])
    with pytest.raises(surface.SurfaceError):
        record_payload(prepared, prepared[2] | {"batch_sha256": "b" * 64})
    assert sql_snapshot(prepared[0]) == before
    assert not (prepared[1] / "artifacts/surface").exists()


def test_duplicate_check_sql_failure_is_named_before_install(prepared):
    # Breaks: leaking raw SQLite errors outside the publication transaction.
    class ReadFailure(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql.startswith("SELECT 1 FROM cba_firmware_surfaces"):
                raise sqlite3.OperationalError("injected duplicate read")
            return super().execute(sql, *args, **kwargs)
    load_payload(prepared, prepared[2])
    con = sqlite3.connect(prepared[1] / "audit.db", factory=ReadFailure)
    con.row_factory = sqlite3.Row
    try:
        before = sql_snapshot(con)
        with pytest.raises(surface.SurfaceError, match="injected duplicate read"):
            api().record(con, prepared[1], prepared[1] / "result.json")
        assert sql_snapshot(con) == before
        assert not con.in_transaction
        assert not (prepared[1] / "artifacts/surface").exists()
    finally:
        con.close()


@pytest.mark.parametrize("change", ["duplicate", "provenance", "ownership"])
def test_inputs_changed_during_install_are_rechecked_before_sql(prepared, monkeypatch, change):
    # Breaks: deleting or upserting using validation from before another writer.
    con, run, payload, *_ = prepared
    load_payload(prepared, payload)
    original = surface.atomic_install
    concurrent = {}
    def install_and_change(destination, files):
        original(destination, files)
        with db.connect(run / "audit.db") as other:
            if change == "duplicate":
                db.put(other, "cba_coverage", {"unit": "usr/httpd", "phase": "surface", "state": "analyzed"})
            elif change == "provenance":
                other.execute("UPDATE cba_surface_runs SET worklist_sha256=?", ("b" * 64,))
                other.commit()
            else:
                row = payload["decisions"][1]["surfaces"][0] | {"component_path": "zzz/outside",
                    "image_id": "target", "artifact_path": "sibling.json", "artifact_sha256": "a" * 64}
                db.put(other, "cba_firmware_surfaces", row)
            concurrent.update(sql_snapshot(other))
    monkeypatch.setattr(surface, "atomic_install", install_and_change)
    with pytest.raises(surface.SurfaceError):
        api().record(con, run, run / "result.json", replace=change != "duplicate")
    assert sql_snapshot(con) == concurrent
    assert not con.in_transaction


def test_unexpected_publication_exception_also_rolls_back_every_row(prepared, monkeypatch):
    # Breaks: rollback restricted to expected filesystem/SQLite exceptions.
    con = prepared[0]
    record_payload(prepared)
    completed(con)
    before = sql_snapshot(con)
    original = db.put
    def fail_after_write(connection, table, row, **kwargs):
        original(connection, table, row, **kwargs)
        if table == "cba_unknowns":
            raise RuntimeError("injected unexpected error after write")
    monkeypatch.setattr(db, "put", fail_after_write)
    with pytest.raises(RuntimeError, match="unexpected"):
        record_payload(prepared, replace=True)
    assert sql_snapshot(con) == before
    assert not con.in_transaction


def test_import_normalizes_budget_reason_for_the_existing_coverage_gate(prepared):
    # Breaks: validated whitespace hiding a budget skip from SQL-based coverage.
    from audit_core import coverage
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][0].update(state="not_audited", reason=" \tbudget\n")
    summary = record_payload(prepared, payload)
    record_payload(prepared, sibling_payload(prepared))
    report = coverage.report(prepared[0], "surface")
    assert report.budget_skips == 1
    assert not coverage.gate(report).ok
    artifact = json.loads(pathlib.Path(summary.artifact_path).read_bytes())
    assert artifact["decisions"][0]["reason"] == " \tbudget\n"
