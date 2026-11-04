"""Prepare and verify policy-bound firmware acquisition decisions.

Stage 4i keeps operator policy separate from technical evidence.  This module
owns policy parsing now; later tasks add current-input verification, immutable
preparation, deterministic completion, and the verified package boundary.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import re

from audit_core import db


class FirmwareDecideError(Exception):
    """Decision policy, provenance, or publication cannot be established."""


MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_TEXT = 4096
MAX_POLICY_NOTES = 64
MAX_PAYOUT_PATHS = 64
MAX_POLICY_TIERS = 128
MAX_MONEY_MINOR = 1_000_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


@dataclasses.dataclass(frozen=True, slots=True)
class PayoutPath:
    path_id: str
    status: str
    basis: str


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyTier:
    tier_id: str
    payout_path_id: str
    ordinal: int
    minimum_minor: int
    maximum_minor: int
    accepted_pre_auth: tuple[str, ...]
    minimum_confidence: int
    accepted_completeness: tuple[str, ...]
    accepted_evidence_rungs: tuple[str, ...]
    physical_access_allowed: bool


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionPolicy:
    schema_version: int
    policy_id: str
    currency: str
    acquisition_cost_minor: int
    max_acquisition_cost_minor: int
    support_status: str
    support_basis: str
    payout_paths: tuple[PayoutPath, ...]
    tiers: tuple[PolicyTier, ...]
    notes: tuple[str, ...]


def _fail(message: str) -> None:
    raise FirmwareDecideError(message)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate key: {key}")
        value[key] = item
    return value


def _object(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail(f"{label} keys differ")
    return value


def _identifier(value, label):
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _fail(f"{label} requires a safe identifier")
    return value


def _text(value, label):
    if (not isinstance(value, str) or not value.strip() or len(value) > MAX_POLICY_TEXT
            or any(ord(char) < 0x20 and char not in "\n\t" for char in value)):
        _fail(f"{label} requires bounded UTF-8 text")
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} requires bounded UTF-8 text")
    return value


def _integer(value, label, maximum=MAX_MONEY_MINOR):
    if type(value) is not int or not 0 <= value <= maximum:
        _fail(f"{label} requires an integer from 0 through {maximum}")
    return value


def _enum(value, allowed, label):
    if not isinstance(value, str) or value not in allowed:
        _fail(f"{label} is invalid")
    return value


def _strings(value, allowed, label):
    if (not isinstance(value, list) or not value or len(value) > len(allowed)
            or any(not isinstance(item, str) or item not in allowed for item in value)
            or value != sorted(set(value))):
        _fail(f"{label} requires sorted unique allowed values")
    return tuple(value)


def _wire(policy: DecisionPolicy):
    return dataclasses.asdict(policy)


def policy_bytes(policy: DecisionPolicy) -> bytes:
    if not isinstance(policy, DecisionPolicy):
        _fail("policy requires a frozen DecisionPolicy")
    try:
        return (json.dumps(_wire(policy), ensure_ascii=False, allow_nan=False,
                           sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FirmwareDecideError("policy cannot be canonicalized") from exc


def _parse(raw: bytes) -> DecisionPolicy:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda token: _fail(f"non-finite value: {token}"))
    except FirmwareDecideError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise FirmwareDecideError("policy requires canonical UTF-8 JSON") from exc
    top = _object(value, (
        "schema_version", "policy_id", "currency", "acquisition_cost_minor",
        "max_acquisition_cost_minor", "support_status", "support_basis",
        "payout_paths", "tiers", "notes"), "policy")
    if type(top["schema_version"]) is not int or top["schema_version"] != 1:
        _fail("schema_version must equal 1")
    policy_id = _identifier(top["policy_id"], "policy_id")
    currency = top["currency"]
    if not isinstance(currency, str) or re.fullmatch(r"[A-Z]{3}", currency) is None:
        _fail("currency requires three uppercase ASCII letters")
    acquisition = _integer(top["acquisition_cost_minor"], "acquisition_cost_minor")
    maximum = _integer(top["max_acquisition_cost_minor"], "max_acquisition_cost_minor")
    support = _enum(top["support_status"], db.FIRMWARE_DECIDE_SUPPORT, "support_status")
    support_basis = _text(top["support_basis"], "support_basis")

    raw_paths = top["payout_paths"]
    if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= MAX_PAYOUT_PATHS:
        _fail("payout_paths requires 1-64 entries")
    paths = []
    for raw_path in raw_paths:
        item = _object(raw_path, ("path_id", "status", "basis"), "payout_path")
        paths.append(PayoutPath(_identifier(item["path_id"], "path_id"),
            _enum(item["status"], db.FIRMWARE_DECIDE_PAYOUT_STATUS, "status"),
            _text(item["basis"], "basis")))
    if tuple(paths) != tuple(sorted(paths, key=lambda item: item.path_id)) or len({p.path_id for p in paths}) != len(paths):
        _fail("payout_paths requires sorted unique path_id values")
    path_ids = {item.path_id for item in paths}

    raw_tiers = top["tiers"]
    if not isinstance(raw_tiers, list) or not 1 <= len(raw_tiers) <= MAX_POLICY_TIERS:
        _fail("tiers requires 1-128 entries")
    tiers = []
    previous = {}
    for index, raw_tier in enumerate(raw_tiers):
        item = _object(raw_tier, (
            "tier_id", "payout_path_id", "ordinal", "minimum_minor",
            "maximum_minor", "accepted_pre_auth", "minimum_confidence",
            "accepted_completeness", "accepted_evidence_rungs",
            "physical_access_allowed"), "tier")
        tier_id = _identifier(item["tier_id"], "tier_id")
        payout_path_id = _identifier(item["payout_path_id"], "payout_path_id")
        if payout_path_id not in path_ids:
            _fail("payout_path_id must reference a declared payout path")
        ordinal = _integer(item["ordinal"], "ordinal", MAX_POLICY_TIERS - 1)
        if ordinal != index:
            _fail("ordinal values must be contiguous from zero")
        minimum = _integer(item["minimum_minor"], "minimum_minor")
        maximum_minor = _integer(item["maximum_minor"], "maximum_minor")
        if minimum > maximum_minor:
            _fail("minimum_minor cannot exceed maximum_minor")
        prior = previous.get(payout_path_id)
        if prior is not None and (minimum < prior[0] or maximum_minor < prior[1]):
            _fail("tier ranges must be monotonic within a payout path")
        previous[payout_path_id] = (minimum, maximum_minor)
        confidence = _integer(item["minimum_confidence"], "minimum_confidence", 10)
        if type(item["physical_access_allowed"]) is not bool:
            _fail("physical_access_allowed requires a boolean")
        tiers.append(PolicyTier(tier_id, payout_path_id, ordinal, minimum, maximum_minor,
            _strings(item["accepted_pre_auth"], db.FIRMWARE_CHAIN_PRE_AUTH, "accepted_pre_auth"),
            confidence,
            _strings(item["accepted_completeness"], db.FIRMWARE_CHAIN_COMPLETENESS,
                     "accepted_completeness"),
            _strings(item["accepted_evidence_rungs"], db.FIRMWARE_CHAIN_EVIDENCE_RUNGS,
                     "accepted_evidence_rungs"),
            item["physical_access_allowed"]))
    if len({tier.tier_id for tier in tiers}) != len(tiers):
        _fail("tiers requires unique tier_id values")

    raw_notes = top["notes"]
    if (not isinstance(raw_notes, list) or len(raw_notes) > MAX_POLICY_NOTES
            or any(not isinstance(note, str) for note in raw_notes)):
        _fail("notes requires at most 64 strings")
    notes = tuple(_text(note, "notes") for note in raw_notes)
    if list(notes) != sorted(set(notes)):
        _fail("notes requires sorted unique entries")
    return DecisionPolicy(1, policy_id, currency, acquisition, maximum, support,
        support_basis, tuple(paths), tuple(tiers), notes)


def load_policy(path: str | pathlib.Path) -> DecisionPolicy:
    try:
        with pathlib.Path(path).open("rb") as stream:
            raw = stream.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise FirmwareDecideError("cannot read policy") from exc
    if len(raw) > MAX_POLICY_BYTES:
        _fail("policy size exceeds 1 MiB")
    policy = _parse(raw)
    if raw != policy_bytes(policy):
        _fail("policy requires canonical UTF-8 JSON")
    return policy
