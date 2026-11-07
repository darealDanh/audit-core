"""Strict, canonical operator policy snapshots for Stage 4i."""
import json

import pytest

from audit_core import firmware_decide as decide


POLICY = {
    "schema_version": 1,
    "policy_id": "operator-2026-11",
    "currency": "USD",
    "acquisition_cost_minor": 12999,
    "max_acquisition_cost_minor": 25000,
    "support_status": "supported",
    "support_basis": "vendor.example support list checked 2026-11-04",
    "payout_paths": [
        {"path_id": "vendor-vdp", "status": "eligible",
         "basis": "vendor.example security program checked 2026-11-04"},
        {"path_id": "zdi", "status": "unknown",
         "basis": "zdi.example program rules require manual confirmation 2026-11-04"},
    ],
    "tiers": [
        {"tier_id": "vendor-preauth", "payout_path_id": "vendor-vdp", "ordinal": 0,
         "minimum_minor": 50000, "maximum_minor": 150000,
         "accepted_pre_auth": ["yes"], "minimum_confidence": 7,
         "accepted_completeness": ["complete"],
         "accepted_evidence_rungs": ["static-chained"],
         "physical_access_allowed": False},
        {"tier_id": "zdi-blocked", "payout_path_id": "zdi", "ordinal": 1,
         "minimum_minor": 10000, "maximum_minor": 50000,
         "accepted_pre_auth": ["unknown", "yes"], "minimum_confidence": 5,
         "accepted_completeness": ["blocked", "complete"],
         "accepted_evidence_rungs": ["static-chained"],
         "physical_access_allowed": True},
    ],
    "notes": ["Amounts are policy projections, not payout promises."],
}
RAW = (json.dumps(POLICY, ensure_ascii=False, sort_keys=True,
                  separators=(",", ":")) + "\n").encode()


def write_policy(tmp_path, raw=RAW):
    path = tmp_path / "policy.json"
    path.write_bytes(raw)
    return path


def test_policy_literal_canonical_bytes_and_frozen_records(tmp_path):
    policy = decide.load_policy(write_policy(tmp_path))
    assert decide.policy_bytes(policy) == RAW
    assert policy.policy_id == "operator-2026-11"
    assert policy.payout_paths[0].path_id == "vendor-vdp"
    assert policy.tiers[1].accepted_pre_auth == ("unknown", "yes")
    with pytest.raises((AttributeError, TypeError)):
        policy.notes += ("changed",)


@pytest.mark.parametrize("mutate,match", [
    (lambda p: p.update(schema_version=True), "schema_version"),
    (lambda p: p.update(schema_version=2), "schema_version"),
    (lambda p: p.update(policy_id="bad/id"), "policy_id"),
    (lambda p: p.update(currency="usd"), "currency"),
    (lambda p: p.update(currency="USDD"), "currency"),
    (lambda p: p.update(acquisition_cost_minor=True), "acquisition_cost_minor"),
    (lambda p: p.update(acquisition_cost_minor=-1), "acquisition_cost_minor"),
    (lambda p: p.update(max_acquisition_cost_minor=1_000_000_001), "max_acquisition_cost_minor"),
    (lambda p: p.update(support_status="maybe"), "support_status"),
    (lambda p: p.update(support_basis=" "), "support_basis"),
    (lambda p: p["payout_paths"].append(dict(p["payout_paths"][0])), "payout_paths"),
    (lambda p: p["payout_paths"][0].update(path_id="bad/path"), "path_id"),
    (lambda p: p["payout_paths"][0].update(status="maybe"), "status"),
    (lambda p: p["tiers"][0].update(payout_path_id="missing"), "payout_path_id"),
    (lambda p: p["tiers"][1].update(ordinal=2), "ordinal"),
    (lambda p: p["tiers"][0].update(minimum_minor=200000), "minimum_minor"),
    (lambda p: p["tiers"][0].update(minimum_confidence=11), "minimum_confidence"),
    (lambda p: p["tiers"][0].update(accepted_pre_auth=["maybe"]), "accepted_pre_auth"),
    (lambda p: p["tiers"][0].update(accepted_completeness=["partial"]), "accepted_completeness"),
    (lambda p: p["tiers"][0].update(accepted_evidence_rungs=["hardware"]), "accepted_evidence_rungs"),
    (lambda p: p["tiers"][0].update(physical_access_allowed=1), "physical_access_allowed"),
    (lambda p: p.update(notes=["x" * 4097]), "notes"),
])
def test_policy_rejects_invalid_semantics(tmp_path, mutate, match):
    body = json.loads(RAW)
    mutate(body)
    raw = (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with pytest.raises(decide.FirmwareDecideError, match=match):
        decide.load_policy(write_policy(tmp_path, raw))


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"schema_version":1}\n',
    b'{"schema_version":NaN}\n',
    b'[]\n',
    b'\xff',
    RAW[:-1],
    RAW.replace(b'"currency":"USD"', b'"currency": "USD"'),
])
def test_policy_rejects_hostile_or_noncanonical_encoding(tmp_path, raw):
    with pytest.raises(decide.FirmwareDecideError):
        decide.load_policy(write_policy(tmp_path, raw))


def test_policy_rejects_unknown_and_missing_keys(tmp_path):
    body = json.loads(RAW)
    body["extra"] = 1
    raw = (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with pytest.raises(decide.FirmwareDecideError, match="keys"):
        decide.load_policy(write_policy(tmp_path, raw))
    body = json.loads(RAW)
    del body["notes"]
    raw = (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with pytest.raises(decide.FirmwareDecideError, match="keys"):
        decide.load_policy(write_policy(tmp_path, raw))


def test_policy_rejects_oversize_input_before_json(tmp_path):
    with pytest.raises(decide.FirmwareDecideError, match="size"):
        decide.load_policy(write_policy(tmp_path, b"{" + b" " * (1024 * 1024) + b"}"))


def test_policy_rejects_integer_beyond_conversion_limit_as_policy_error(tmp_path):
    """Catches a >4300-digit integer escaping load_policy as a raw ValueError."""
    raw = RAW.replace(b'"acquisition_cost_minor":12999', b'"acquisition_cost_minor":' + b"9" * 5000)
    assert b"9" * 5000 in raw
    with pytest.raises(decide.FirmwareDecideError, match="canonical UTF-8 JSON") as caught:
        decide.load_policy(write_policy(tmp_path, raw))
    assert isinstance(caught.value.__cause__, ValueError)
    assert not isinstance(caught.value.__cause__, json.JSONDecodeError)
