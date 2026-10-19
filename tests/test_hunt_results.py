"""Hunt results must bind complete assignments before publishing candidate claims."""
import copy
import dataclasses
import json
import pathlib

import pytest

from audit_core import db, hunt, surface, surface_results, workspace


HELLO = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
RESULT = '''{"schema_version":1,"image_id":"target","lane":"l-sink",
"manifest_sha256":"MANIFEST","surface_snapshot_sha256":"SNAPSHOT",
"worklist_sha256":"WORKLIST","batch_path":"batch-0001.json","batch_sha256":"BATCH",
"decisions":[
{"path":"a","disposition":"analyzed","reason":"No attacker input reaches an operation.","candidates":[]},
{"path":"b","disposition":"not_applicable","reason":"Read-only data contains no executable instructions.","candidates":[]},
{"path":"c","disposition":"analyzed","reason":null,"candidates":[{
"candidate_id":"shell-1","component_path":"c","title":"Command injection hypothesis","bug_class":"command injection",
"surface_ids":["http-c"],"surface_context":"POST /run handler at c:10.",
"attacker_position":"lan","input_evidence":"c:10 reads attacker-controlled POST parameter cmd.",
"data_flow":"Attacker POST cmd at c:10 passes through trim at c:12 to system at c:20.",
"dangerous_operation":"system","operation_evidence":"c:20 calls system(cmd).",
"mitigations_checked":"c:12 trims whitespace but does not quote shell characters.",
"lifecycle_required":"provisioned","posture_required":"sta-lan","auth_required":"pre-auth",
"reachability":"evidenced","state_evidence":"c:8 registers /run before authentication.",
"confidence":6,"impact_hypothesis":"Shell command execution as the daemon user may be possible.",
"blockers":[{"id":"shell-context","question":"Which UID runs the daemon?","settling_observation":"Inspect daemon UID after provisioning.","method":"hardware"}]}]}]}'''
# Hand-ordered oracle; only provenance placeholders depend on prepared fixture bytes.
CANONICAL = ('{"batch_path":"batch-0001.json","batch_sha256":"BATCH","decisions":['
 '{"candidates":[],"disposition":"analyzed","path":"a","reason":"No attacker input reaches an operation."},'
 '{"candidates":[],"disposition":"not_applicable","path":"b","reason":"Read-only data contains no executable instructions."},'
 '{"candidates":[{"attacker_position":"lan","auth_required":"pre-auth","blockers":[{"id":"shell-context","method":"hardware","question":"Which UID runs the daemon?","settling_observation":"Inspect daemon UID after provisioning."}],"bug_class":"command injection","candidate_id":"shell-1","component_path":"c","confidence":6,"dangerous_operation":"system","data_flow":"Attacker POST cmd at c:10 passes through trim at c:12 to system at c:20.","impact_hypothesis":"Shell command execution as the daemon user may be possible.","input_evidence":"c:10 reads attacker-controlled POST parameter cmd.","lifecycle_required":"provisioned","mitigations_checked":"c:12 trims whitespace but does not quote shell characters.","operation_evidence":"c:20 calls system(cmd).","posture_required":"sta-lan","reachability":"evidenced","state_evidence":"c:8 registers /run before authentication.","surface_context":"POST /run handler at c:10.","surface_ids":["http-c"],"title":"Command injection hypothesis"}],"disposition":"analyzed","path":"c","reason":null}],'
 '"image_id":"target","lane":"l-sink","manifest_sha256":"MANIFEST","schema_version":1,"surface_snapshot_sha256":"SNAPSHOT","worklist_sha256":"WORKLIST"}\n')


@pytest.fixture
def prepared(tmp_path):
    run = workspace.init_run(tmp_path / "project", timestamp="20261019-000000")
    con = db.connect(run / "audit.db")
    root = tmp_path / "root"
    root.mkdir()
    db.put(con, "cba_images", {"id": "target", "role": "target", "vendor": "v",
        "model": "m", "version": "1", "path": "firmware.bin", "sha256": "a" * 64})
    for path in ("a", "b", "c", "d"):
        (root / path).write_bytes(b"hello\n")
        db.put(con, "cba_firmware_files", {"image_id": "target", "path": path,
            "kind": "file", "size": "6", "sha256": HELLO})
        db.put(con, "cba_inventory", {"unit": db.firmware_unit_key("target", path), "kind": "file", "size": "6"})
    mapped = surface.prepare(con, run, root)
    index = json.loads(pathlib.Path(mapped.worklist_path).read_bytes())
    artifact = run / "surface-result.json"
    artifact.write_text(json.dumps({"schema_version": 1, "image_id": "target",
        "manifest_sha256": mapped.manifest_sha256, "worklist_sha256": mapped.worklist_sha256,
        "batch_path": index["batches"][0]["path"], "batch_sha256": index["batches"][0]["sha256"],
        "decisions": [{"path": path, "state": "analyzed", "reason": "Direct dispatcher assessment.",
            "unknowns": [], "surfaces": [] if path != "c" else [{"surface_id": "http-c",
                "component_path": "c", "entry_point": "POST /run", "protocol": "http",
                "dispatch_path": "route -> run", "handler": "run", "lifecycle_required": "provisioned",
                "posture_required": "sta-lan", "auth_required": "pre-auth", "reachability": "evidenced",
                "reach_evidence": "c:8 registers before authentication."}]} for path in ("a", "b", "c", "d")]}))
    surface_results.record(con, run, artifact)
    surface.check(con)
    summary = hunt.prepare(con, run, root, sink_batch_size=3, dark_batch_size=3)
    lane = summary.lanes[0]
    descriptor = json.loads(pathlib.Path(lane.worklist_path).read_bytes())["batches"][0]
    replacements = {"MANIFEST": summary.manifest_sha256, "SNAPSHOT": summary.surface_snapshot_sha256,
                    "WORKLIST": lane.worklist_sha256, "BATCH": descriptor["sha256"]}
    def substitute(text):
        for key, value in replacements.items():
            text = text.replace(key, value)
        return text
    yield con, run, json.loads(substitute(RESULT)), substitute(CANONICAL).encode(), summary
    con.close()


def api():
    from audit_core import hunt_results
    return hunt_results


def load_payload(prepared, payload):
    path = prepared[1] / "hunt-result.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return api().load(path)


def validate_payload(prepared, payload):
    return api().validate(prepared[0], prepared[1], load_payload(prepared, payload))


def candidate(payload):
    return payload["decisions"][2]["candidates"][0]


def test_complete_literal_result_is_immutable_canonical_and_read_only(prepared):
    # Breaks: dropping evidence, changing serialization, mutating SQL during validation.
    con, _, payload, expected, summary = prepared
    before = con.total_changes
    validated = validate_payload(prepared, payload)
    assert validated.assigned_units == ("a", "b", "c")
    assert validated.index_path == summary.lanes[0].worklist_path
    assert isinstance(validated, api().ValidatedBatch)
    assert isinstance(validated.result, api().BatchResult)
    decision = validated.result.decisions[2]
    row = decision.candidates[0]
    assert isinstance(decision, api().UnitDecision) and isinstance(row, api().Candidate)
    assert row.surface_ids == ("http-c",) and row.confidence == 6
    assert isinstance(row.blockers[0], api().Blocker)
    assert row.blockers[0].settling_observation == "Inspect daemon UID after provisioning."
    assert api().canonical_bytes(validated) == expected
    assert con.total_changes == before and not con.in_transaction
    for record in (validated, validated.result, decision, row, row.blockers[0]):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, dataclasses.fields(record)[0].name, "changed")


@pytest.mark.parametrize("raw", [b"\xff", b"{", b"[]", b"null", b"true", b"1",
    b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}', b'{"x":Infinity}',
    b"[" * 1500 + b"]" * 1500, b" " * (8 * 1024 * 1024 + 1)],
    ids=["utf8", "truncated", "array", "null", "boolean", "number", "duplicate", "nan", "infinity", "depth", "oversized"])
def test_load_rejects_malformed_unbounded_or_non_object_json(tmp_path, raw):
    # Breaks: permissive JSON decoding or unbounded reads.
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(hunt.HuntError):
        api().load(path)


@pytest.mark.parametrize("kind", ["symlink", "directory", "missing"])
def test_load_requires_regular_existing_file(tmp_path, kind):
    path = tmp_path / "result.json"
    if kind == "symlink":
        target = tmp_path / "target.json"
        target.write_text(RESULT)
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
    with pytest.raises(hunt.HuntError):
        api().load(path)


@pytest.mark.parametrize("level", ["result", "decision", "candidate", "blocker"])
@pytest.mark.parametrize("damage", ["extra", "missing"])
def test_load_rejects_extra_or_missing_keys(prepared, level, damage):
    payload = prepared[2]
    row = {"result": payload, "decision": payload["decisions"][0],
           "candidate": candidate(payload), "blocker": candidate(payload)["blockers"][0]}[level]
    if damage == "extra":
        row["confirmed"] = True
    else:
        row.pop(next(iter(row)))
    with pytest.raises(hunt.HuntError):
        load_payload(prepared, payload)


@pytest.mark.parametrize("field,value", [("schema_version", True), ("schema_version", 2),
    ("lane", "sink"), ("image_id", ""), ("manifest_sha256", "A" * 64),
    ("surface_snapshot_sha256", "a" * 63), ("worklist_sha256", 1), ("batch_sha256", "z" * 64),
    ("batch_path", "/batch-0001.json"), ("batch_path", "../batch-0001.json"),
    ("batch_path", "dir/batch-0001.json"), ("decisions", {})])
def test_load_rejects_invalid_result_fields(prepared, field, value):
    payload = prepared[2]
    payload[field] = value
    with pytest.raises(hunt.HuntError):
        load_payload(prepared, payload)


@pytest.mark.parametrize("field,value", [("confidence", True), ("confidence", 1.5),
    ("confidence", -1), ("confidence", 11), ("candidate_id", "bad/id"),
    ("candidate_id", "a" * 129), ("component_path", "/c"), ("component_path", "a/../c"),
    ("surface_ids", ["http-c", "http-c"]), ("surface_ids", ["bad/id"]),
    ("lifecycle_required", "running"), ("posture_required", "internet"),
    ("auth_required", "none"), ("reachability", "confirmed"), ("blockers", {}),
    ("title", "\ud800"), ("attacker_position", "a" * 1025)])
def test_load_rejects_invalid_candidate_shapes_and_values(prepared, field, value):
    payload = prepared[2]
    candidate(payload)[field] = value
    with pytest.raises(hunt.HuntError):
        load_payload(prepared, payload)


@pytest.mark.parametrize("field", ["image_id", "lane", "manifest_sha256", "surface_snapshot_sha256",
    "worklist_sha256", "batch_sha256", "batch_path"])
def test_provenance_must_match_current_preparation(prepared, field):
    payload = prepared[2]
    payload[field] = {"image_id": "foreign", "lane": "l-dark", "batch_path": "batch-9999.json"}.get(field, "0" * 64)
    before = prepared[0].total_changes
    with pytest.raises(hunt.HuntError):
        validate_payload(prepared, payload)
    assert prepared[0].total_changes == before


@pytest.mark.parametrize("damage", ["missing", "extra", "duplicate", "path-absolute", "path-escape"])
def test_decisions_match_entire_assigned_batch(prepared, damage):
    payload = prepared[2]
    if damage == "missing":
        payload["decisions"].pop()
    elif damage in ("extra", "duplicate"):
        row = copy.deepcopy(payload["decisions"][0])
        row["path"] = "d" if damage == "extra" else "a"
        payload["decisions"].append(row)
    else:
        payload["decisions"][0]["path"] = "/a" if damage == "path-absolute" else "x/../a"
    with pytest.raises(hunt.HuntError):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("damage", ["hunt-missing", "surface-pending", "surface-evidence", "manifest",
    "inventory", "index", "batch", "run-count", "run-path", "symlink-directory"])
def test_stale_or_corrupt_current_state_is_rejected(prepared, damage):
    con, run, payload, _, summary = prepared
    index = pathlib.Path(summary.lanes[0].worklist_path)
    if damage == "hunt-missing":
        con.execute("DELETE FROM cba_hunt_runs WHERE lane='l-sink'")
    elif damage == "surface-pending":
        con.execute("UPDATE cba_surface_runs SET status='pending',completed_at=NULL")
    elif damage == "surface-evidence":
        next((run / "artifacts/surface").rglob("result.json")).write_text("{}")
    elif damage == "manifest":
        con.execute("UPDATE cba_firmware_files SET sha256=? WHERE path='a'", ("0" * 64,))
    elif damage == "inventory":
        con.execute("DELETE FROM cba_inventory WHERE unit=?", (db.firmware_unit_key("target", "a"),))
    elif damage in ("index", "batch"):
        (index if damage == "index" else index.with_name("batch-0001.json")).write_text("{}")
    elif damage == "run-count":
        con.execute("UPDATE cba_hunt_runs SET unit_count=1 WHERE lane='l-sink'")
    elif damage == "run-path":
        con.execute("UPDATE cba_hunt_runs SET worklist_path=? WHERE lane='l-sink'", (str(run / "outside/index.json"),))
    else:
        moved = index.parent.with_name("moved")
        index.parent.rename(moved)
        index.parent.symlink_to(moved, target_is_directory=True)
    con.commit()
    before = con.total_changes
    with pytest.raises(hunt.HuntError):
        validate_payload(prepared, payload)
    assert con.total_changes == before and not con.in_transaction


@pytest.mark.parametrize("disposition,reason", [("analyzed", None), ("analyzed", " "),
    ("not_applicable", None), ("not_applicable", " "), ("not_audited", None),
    ("not_audited", "uncertain"), ("unknown", "Evidence.")])
def test_clear_and_skip_decisions_require_evidence_or_permitted_reason(prepared, disposition, reason):
    payload = prepared[2]
    payload["decisions"][0].update(disposition=disposition, reason=reason)
    with pytest.raises(hunt.HuntError):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("reason", db.NOT_AUDITED_REASONS)
def test_honest_not_audited_including_budget_is_representable(prepared, reason):
    payload = prepared[2]
    payload["decisions"][0].update(disposition="not_audited", reason=reason)
    assert validate_payload(prepared, payload).result.decisions[0].reason == reason


@pytest.mark.parametrize("damage", ["not_applicable", "not_audited", "foreign-component",
    "foreign-surface", "other-component-surface", "duplicate-candidate", "no-surface-explanation",
    "duplicate-blocker", "bad-blocker-id", "bad-blocker-method", "empty-question", "empty-observation",
    "sink-without-influence", "sink-without-influence-in-trace", "sink-without-operation-trace"])
def test_candidate_ownership_blockers_and_sink_flow_are_required(prepared, damage):
    payload = prepared[2]
    row = candidate(payload)
    if damage in ("not_applicable", "not_audited"):
        payload["decisions"][2].update(disposition=damage, reason="budget" if damage == "not_audited" else "Data only.")
    elif damage == "foreign-component":
        row["component_path"] = "a"
    elif damage == "foreign-surface":
        prepared[0].execute("UPDATE cba_firmware_surfaces SET image_id='foreign' WHERE surface_id='http-c'")
    elif damage == "other-component-surface":
        # Keep the canonical Stage 4d snapshot intact: http-c exists, but is
        # owned by c, whereas this otherwise valid candidate now belongs to a.
        row["component_path"] = "a"
        payload["decisions"][0].update(candidates=[row], reason=None)
        payload["decisions"][2].update(candidates=[], reason="No surviving candidate.")
    elif damage == "duplicate-candidate":
        payload["decisions"][2]["candidates"].append(copy.deepcopy(row))
    elif damage == "no-surface-explanation":
        row.update(surface_ids=[], surface_context=" ")
    elif damage == "duplicate-blocker":
        row["blockers"].append(copy.deepcopy(row["blockers"][0]))
    elif damage.startswith("bad-blocker"):
        row["blockers"][0]["id" if damage.endswith("id") else "method"] = "invalid/value"
    elif damage.startswith("empty-"):
        row["blockers"][0]["question" if damage == "empty-question" else "settling_observation"] = " "
    elif damage == "sink-without-influence":
        row.update(input_evidence="Imports system.", data_flow="Calls system at c:20.")
    elif damage == "sink-without-influence-in-trace":
        row["data_flow"] = "Calls system at c:20."
    else:
        row["data_flow"] = "Attacker POST parameter passes through trim."
    with pytest.raises(hunt.HuntError):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("field", ["title", "bug_class", "attacker_position", "input_evidence", "data_flow",
    "dangerous_operation", "operation_evidence", "mitigations_checked", "state_evidence", "impact_hypothesis",
    "surface_context"])
def test_candidate_requires_nonempty_evidence(prepared, field):
    candidate(prepared[2])[field] = " \n"
    with pytest.raises(hunt.HuntError):
        validate_payload(prepared, prepared[2])


def dark_payload(prepared):
    payload = prepared[2]
    lane = prepared[4].lanes[1]
    index = json.loads(pathlib.Path(lane.worklist_path).read_bytes())
    payload.update(lane="l-dark", worklist_sha256=lane.worklist_sha256,
                   batch_sha256=index["batches"][0]["sha256"])
    return payload


@pytest.mark.parametrize("mechanism", ["UPnP SSDP responder", "mDNS parser", "TR-069 CWMP client",
    "cloud tunnel", "P2P pairing", "proprietary UDP discovery", "Unix socket IPC",
    "OTA signature verification", "heap corruption", "owner trust boundary"])
def test_dark_lane_accepts_named_mechanisms_without_surface_hints(prepared, mechanism):
    payload = dark_payload(prepared)
    candidate(payload).update(surface_ids=[], surface_context="New unmapped dispatch path at c:10.",
        dangerous_operation=mechanism, data_flow=f"Attacker bytes at c:10 cross {mechanism} to c:20.")
    assert validate_payload(prepared, payload).result.lane == "l-dark"


def test_dark_lane_rejects_generic_interesting_binary_observation(prepared):
    payload = dark_payload(prepared)
    candidate(payload).update(dangerous_operation="interesting binary", data_flow="Changed code at c:20.")
    with pytest.raises(hunt.HuntError):
        validate_payload(prepared, payload)


@pytest.mark.parametrize("operation", ["cheap integer comparison", "total byte count"])
def test_dark_lane_rejects_mechanism_substrings_in_unrelated_words(prepared, operation):
    # Breaks: accepting heap/OTA fragments rather than a named lane mechanism.
    payload = dark_payload(prepared)
    candidate(payload).update(dangerous_operation=operation,
        data_flow="Attacker parameter at c:10 reaches an integer comparison at c:20.")
    with pytest.raises(hunt.HuntError, match="L-dark requires a named"):
        validate_payload(prepared, payload)


def test_direct_typed_call_cannot_bypass_loading_checks(prepared):
    result = load_payload(prepared, prepared[2])
    row = result.decisions[2].candidates[0]
    bad = dataclasses.replace(result, decisions=(*result.decisions[:2],
        dataclasses.replace(result.decisions[2], candidates=(dataclasses.replace(row, confidence=True),))))
    with pytest.raises(hunt.HuntError):
        api().validate(prepared[0], prepared[1], bad)
