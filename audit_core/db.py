"""Validated, bounded access to a run's audit.db.

The orchestrator used to type this SQL by hand. The three status SELECTs in
the resume-note template were retyped once per compaction restart, and the
deep-audit INSERT once per feature group - R5's target exactly. What makes
this a module rather than a shell alias is the contract: `put` knows which
columns each table has, which are required, and which values are legal, so a
typo fails loudly instead of writing a row nothing reads.
"""
from __future__ import annotations

import json
import pathlib
import re
import sqlite3
import unicodedata
from dataclasses import dataclass
from typing import Callable

from audit_core import text

MAX_ROWS = 200

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
VERDICTS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE", "NEEDS_VERIFICATION")
COVERAGE_STATES = ("analyzed", "not_audited")
NOT_AUDITED_REASONS = ("budget", "out-of-scope", "generated", "vendored",
                       "third-party", "unreachable", "binary-only")
INVENTORY_KINDS = ("file", "function", "endpoint", "binary", "script", "config")
CHECKPOINT_REASONS = ("phase-exit", "ceiling", "manual")
COMPONENT_KINDS = ("source-tree", "binary", "library", "firmware-image",
                   "service", "config")
CHAIN_COMPLETENESS = ("complete", "partial", "blocked")
IMAGE_ROLES = ("target", "diff-reference")
TRISTATE = ("yes", "no", "unknown")
RELRO_STATES = ("full", "partial", "none", "unknown")
FIRMWARE_IMAGE_UNSCOPED = "legacy-unscoped"
DIFF_CHANGES = ("added", "removed", "modified")
SURFACE_RUN_STATES = ("pending", "complete")
HUNT_LANES = ("l-sink", "l-dark")
HUNT_RUN_STATES = ("pending", "complete")
HUNT_DISPOSITIONS = ("analyzed", "not_applicable", "not_audited")
FIRMWARE_FP_RUN_STATES = ("pending", "complete")
FIRMWARE_FP_VERDICTS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE")
FIRMWARE_FP_EVIDENCE_RUNGS = ("static-reviewed",)
FIRMWARE_CHAIN_RUN_STATES = ("pending", "complete")
FIRMWARE_CHAIN_DISPOSITIONS = ("chained", "standalone", "unchainable", "blocked")
FIRMWARE_CHAIN_COMPLETENESS = ("complete", "blocked")
FIRMWARE_CHAIN_PRE_AUTH = ("yes", "no", "unknown")
FIRMWARE_CHAIN_EVIDENCE_RUNGS = ("static-chained",)
FIRMWARE_CHAIN_CAPABILITY_KINDS = (
    "credential-possession", "session-possession", "file-read", "file-write",
    "config-read", "config-write", "command-execution", "code-execution",
    "ipc-access", "network-reachability", "firmware-update-control",
    "persistent-execution", "reboot-control", "physical-access", "other-specific")
FIRMWARE_CHAIN_LIFECYCLE_STATES = ("factory-fresh", "provisioned", "bound-to-owner",
                                   "cloud-registered", "post-reset")
FIRMWARE_CHAIN_POSTURE_STATES = ("SoftAP-setup", "STA-LAN", "WAN-exposed", "BLE",
                                 "cloud-tunnel-only")
FIRMWARE_CHAIN_AUTH_STATES = ("pre-auth", "session", "admin", "local-shell", "physical-UART")
FIRMWARE_CHAIN_TRANSITION_KINDS = ("direct", "reboot", "service-restart", "factory-reset", "reprovision")
FIRMWARE_CHAIN_METHODS = ("static", "emulate", "hardware")
FIRMWARE_CHAIN_AXES = ("authentication", "lifecycle", "posture", "reachability")
LIFECYCLE_STATES = ("factory-fresh", "provisioned", "bound-to-owner",
                    "cloud-registered", "post-reset", "unknown")
POSTURE_STATES = ("softap-setup", "sta-lan", "wan-exposed", "ble",
                  "cloud-tunnel-only", "unknown")
AUTH_STATES = ("pre-auth", "session", "admin", "local-shell", "physical-uart",
               "unknown")
REACHABILITY_STATES = ("evidenced", "refuted", "unknown")
UNKNOWN_FIELDS = ("dispatch", "handler", "lifecycle", "posture", "auth",
                  "reachability")
UNKNOWN_METHODS = ("static", "emulate", "hardware")
UNKNOWN_STATES = ("open", "resolved")


def firmware_unit_key(image_id: str, path: str) -> str:
    """Database-only firmware unit identity; artifacts retain the raw path.

    The image length (Unicode characters), colon, exact image, colon and raw
    path frame an injective, reversible pair even when either contains colons.
    Leading '/' separates qualified keys from valid relative manifest paths.
    An empty path gives the exact image prefix for scoped inventory reads.
    Legacy unscoped triage keeps its historical raw keys; callers must never
    infer ownership of old raw rows from an acquired image's manifest.
    """
    if image_id == FIRMWARE_IMAGE_UNSCOPED:
        return path
    return f"/firmware/{len(image_id)}:{image_id}:{path}"


# Columns added to tables that already existed when an earlier stage shipped.
# `CREATE TABLE IF NOT EXISTS` adds a table; it does nothing to a table that
# is already there, and SQLite has no `ALTER TABLE ... ADD COLUMN IF NOT
# EXISTS`. So the list is explicit and ordered, and a reviewer can read
# exactly what will be run against a user's database.
#
# Append to this tuple; never reorder it and never remove an entry. A removed
# entry is a column that stops being added to the databases that still lack
# it, and nothing reports that - the column simply is not there.
MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("cba_fp_verdicts", "refuting_mechanism", "TEXT"),
    ("cba_fp_verdicts", "enabled_observation", "TEXT"),
    ("cba_patterns", "swept_at", "TEXT"),
    ("cba_patterns", "hit_count", "INTEGER"),
)


class DbError(Exception):
    """A put or a query violated the table contract."""


Validator = Callable[[dict[str, str]], None]


@dataclass(frozen=True, slots=True)
class TableSpec:
    columns: tuple[str, ...]
    required: tuple[str, ...]
    primary_key: tuple[str, ...]
    validate: Validator | None = None


def one_of(column: str, allowed: tuple[str, ...]) -> Validator:
    def check(row: dict[str, str]) -> None:
        value = row.get(column)
        if value is not None and value not in allowed:
            raise DbError(f"{column}={value!r} is not one of {', '.join(allowed)}")
    return check


def _validate_coverage(row: dict[str, str]) -> None:
    """A gap needs a reason, and the reason has to come from the list.

    Spec section 3.5: `not_audited` rows with reasons are mandatory. A row
    without one records that something was skipped while hiding why, which is
    strictly worse than no row - it makes the denominator look accounted for.
    """
    state = row.get("state")
    if state not in COVERAGE_STATES:
        raise DbError(f"state={state!r} is not one of {', '.join(COVERAGE_STATES)}")
    reason = (row.get("reason") or "").strip()
    if state != "not_audited":
        return
    if not reason:
        raise DbError("state=not_audited requires a reason; one of: "
                      + ", ".join(NOT_AUDITED_REASONS))
    if reason not in NOT_AUDITED_REASONS:
        raise DbError(f"reason={reason!r} is not one of: "
                      + ", ".join(NOT_AUDITED_REASONS))


def _validate_pattern(row: dict[str, str]) -> None:
    """Compile the regex before it is stored.

    A stored pattern that does not compile is a sweep that silently never
    runs, which is the worst possible outcome for a mechanism whose whole
    value is breadth.
    """
    try:
        re.compile(row["regex"])
    except re.error as exc:
        raise DbError(f"regex {row['regex']!r} does not compile: {exc}") from exc


def _validate_verdict(row: dict[str, str]) -> None:
    """Spec section 3.5: a FALSE_POSITIVE must say what refuted it, and what
    that mechanism enables.

    From the tplink post-mortem: a finding was correctly refuted by a
    300-byte sliding-window flush, and that flush is the attack surface for a
    reference-set CRITICAL. The verdict schema recorded the refutation and
    nothing else, so the pivot was never taken.

    The requirement is unconditional. A refuting mechanism is code, and code
    does something; "no attacker-controlled path identified in this review"
    is a legitimate answer and a useful rung-1 observation. A blank is not.
    """
    verdict = row.get("verdict")
    if verdict not in VERDICTS:
        raise DbError(f"verdict={verdict!r} is not one of {', '.join(VERDICTS)}")
    if verdict != "FALSE_POSITIVE":
        return
    missing = [c for c in ("refuting_mechanism", "enabled_observation")
               if not str(row.get(c, "") or "").strip()]
    if missing:
        raise DbError(
            f"a FALSE_POSITIVE verdict requires {', '.join(missing)}: what "
            f"refuted the finding, and the id of the observation recording "
            f"what that mechanism enables. Write both with "
            f"`audit.py pivot --db <db> --finding {row.get('finding_id', '<id>')} "
            f"--group <group> --mechanism '<what refuted it>' "
            f"--enables '<what it enables, or what was ruled out>'`, which "
            f"records the observation and the verdict together.")


MIN_EVIDENCE_CHARS = 20


def check_identity_evidence(path: str, evidence: str) -> None:
    """Raise unless `evidence` says something the path does not already say.

    `text.location_tokens` lowercases, splits on non-identifier characters
    and drops anything under four characters, so `src/osal/Tss.c` and
    "found under SRC/OSAL as TSS dot C file" reduce to the same token set -
    which is the point. What survives the subtraction, after also dropping
    `text.NOISE_WORDS` (English filler that would otherwise let a circular
    claim slip through dressed as a sentence), is the part of the claim that
    came from looking at the thing.

    Public, unlike the `_validate_*` functions beside it, because
    audit_core.identity re-exports it: identity.py imports db, so the rule
    cannot live there without a cycle, and a leading underscore on a name
    another module is meant to call is a lie about its scope.
    """
    evidence = (evidence or "").strip()
    if len(evidence) < MIN_EVIDENCE_CHARS:
        raise DbError(
            f"identity_evidence is {len(evidence)} characters; at least "
            f"{MIN_EVIDENCE_CHARS} are needed. Name what you looked at: a "
            f"string and its offset, an import, a header field, a build "
            f"artifact.")
    novel = (text.location_tokens(evidence) - text.location_tokens(path)
             - text.NOISE_WORDS)
    if not novel:
        raise DbError(
            f"identity_evidence for {path!r} only repeats its own path. A "
            f"filename is an assertion by whoever named it, not evidence: "
            f"km0_boot_0C000020.elf was treated as a bootloader for a whole "
            f"run on exactly this reasoning and holds a Wi-Fi driver. Cite "
            f"something you read out of the component itself.")


def _validate_component(row: dict[str, str]) -> None:
    kind = row.get("kind")
    if kind not in COMPONENT_KINDS:
        raise DbError(f"kind={kind!r} is not one of {', '.join(COMPONENT_KINDS)}")
    check_identity_evidence(str(row.get("path", "")),
                            str(row.get("identity_evidence", "") or ""))
    raw = str(row.get("confidence", "") or "").strip()
    if not raw:
        return
    try:
        value = int(raw)
    except ValueError:
        raise DbError(f"confidence={raw!r} is not an integer 1-10") from None
    if not 1 <= value <= 10:
        raise DbError(f"confidence={value} is outside 1-10")


def _validate_chain(row: dict[str, str]) -> None:
    """A chain is an ordered list of findings, and two is the minimum.

    A one-finding chain is a finding. Recording it as a chain hides it from
    the finding tally and inflates the chain tally, which is the one thing
    this table exists to count honestly.
    """
    completeness = row.get("completeness")
    if completeness not in CHAIN_COMPLETENESS:
        raise DbError(f"completeness={completeness!r} is not one of "
                      + ", ".join(CHAIN_COMPLETENESS))
    ids = [part.strip() for part in str(row.get("finding_ids", "")).split(",")]
    ids = [i for i in ids if i]
    if len(ids) < 2:
        raise DbError("finding_ids needs at least two comma-separated finding "
                      "ids, in attack order; a one-finding chain is a finding")
    if len(set(ids)) != len(ids):
        raise DbError(f"finding_ids repeats an id: {', '.join(ids)}")


def _validate_binfacts(row: dict[str, str]) -> None:
    for column in ("nx", "pie", "canary", "stripped", "static"):
        value = row.get(column)
        if value is not None and value not in TRISTATE:
            raise DbError(f"{column}={value!r} is not one of {', '.join(TRISTATE)}")
    relro = row.get("relro")
    if relro is not None and relro not in RELRO_STATES:
        raise DbError(f"relro={relro!r} is not one of {', '.join(RELRO_STATES)}")


def _validate_service(row: dict[str, str]) -> None:
    ports = str(row.get("ports", "") or "").strip()
    evidence = str(row.get("ports_evidence", "") or "").strip()
    if ports and not evidence:
        raise DbError("ports requires ports_evidence naming how the listening "
                      "port was established")


def _validate_nonnegative_integers(row: dict[str, str],
                                  columns: tuple[str, ...]) -> None:
    for column in columns:
        # SQLite ignores ASCII whitespace around numeric values; Python's
        # default strip also accepts Unicode whitespace retained as TEXT.
        raw = str(row.get(column, "")).strip(" \t\n\r\v\f")
        if re.fullmatch(r"[+-]?[0-9]+", raw) is None:
            raise DbError(f"{column}={raw!r} is not a non-negative integer")
        try:
            value = int(raw)
        except ValueError:
            raise DbError(f"{column}={raw!r} is not a non-negative integer") from None
        if not 0 <= value <= 9223372036854775807:
            raise DbError(f"{column}={raw!r} is outside the SQLite non-negative "
                          "integer range 0-9223372036854775807")


def _validate_diff(row: dict[str, str]) -> None:
    _validate_nonnegative_integers(row, ("added_count", "removed_count",
                                        "modified_count", "unchanged_count"))


def _validate_surface_text(row: dict[str, str], table: str,
                           *, counts: tuple[str, ...] = ()) -> None:
    for column in TABLE_SPECS[table].required:
        if column in counts:
            continue
        value = row.get(column)
        if not isinstance(value, str) or not value.strip():
            raise DbError(f"{column} requires a non-empty string")


def _validate_sha256(row: dict[str, str], column: str) -> None:
    value = row.get(column)
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise DbError(f"{column} must be exactly 64 lower-case hexadecimal characters")


def _validate_surface_identifier(row: dict[str, str], column: str) -> None:
    value = row.get(column)
    if not isinstance(value, str) or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise DbError(f"{column} must be a safe identifier of 1-128 characters")


def _validate_surface_run(row: dict[str, str]) -> None:
    counts = ("unit_count", "batch_count")
    _validate_surface_text(row, "cba_surface_runs", counts=counts)
    _validate_nonnegative_integers(row, counts)
    for column in ("manifest_sha256", "worklist_sha256"):
        _validate_sha256(row, column)
    one_of("status", SURFACE_RUN_STATES)(row)


def _validate_firmware_surface(row: dict[str, str]) -> None:
    _validate_surface_text(row, "cba_firmware_surfaces")
    _validate_surface_identifier(row, "surface_id")
    _validate_sha256(row, "artifact_sha256")
    for column, allowed in (("lifecycle_required", LIFECYCLE_STATES),
                            ("posture_required", POSTURE_STATES),
                            ("auth_required", AUTH_STATES),
                            ("reachability", REACHABILITY_STATES)):
        one_of(column, allowed)(row)


def _validate_unknown(row: dict[str, str]) -> None:
    _validate_surface_text(row, "cba_unknowns")
    _validate_surface_identifier(row, "id")
    surface_id = row.get("surface_id")
    if surface_id is not None and surface_id != "" and (
            not isinstance(surface_id, str) or surface_id.strip()):
        _validate_surface_identifier(row, "surface_id")
    _validate_sha256(row, "artifact_sha256")
    for column, allowed in (("field", UNKNOWN_FIELDS),
                            ("method", UNKNOWN_METHODS),
                            ("status", UNKNOWN_STATES)):
        one_of(column, allowed)(row)
    for column in ("resolution", "evidence"):
        value = row.get(column)
        if value is not None and not isinstance(value, str):
            raise DbError(f"{column} must be a string or absent")
        present = bool(value and value.strip())
        if row["status"] == "open" and present:
            raise DbError(f"an open unknown requires empty {column}")
        if row["status"] == "resolved" and not present:
            raise DbError(f"a resolved unknown requires non-empty {column}")


def _validate_hunt_run(row: dict[str, str]) -> None:
    counts = ("unit_count", "batch_count")
    _validate_surface_text(row, "cba_hunt_runs", counts=counts)
    _validate_nonnegative_integers(row, counts)
    one_of("lane", HUNT_LANES)(row)
    one_of("status", HUNT_RUN_STATES)(row)
    for column in ("manifest_sha256", "surface_snapshot_sha256", "worklist_sha256"):
        _validate_sha256(row, column)


def _validate_hunt_receipt(row: dict[str, str]) -> None:
    counts = ("unit_count", "candidate_count")
    _validate_surface_text(row, "cba_hunt_receipts", counts=counts)
    _validate_nonnegative_integers(row, counts)
    one_of("lane", HUNT_LANES)(row)
    for column in ("worklist_sha256", "batch_sha256", "result_sha256"):
        _validate_sha256(row, column)


def _hunt_json_array(row: dict[str, str], column: str) -> list:
    """Cells are compact canonical UTF-8 JSON, without an artifact newline.

    Re-encoding also rejects duplicate object keys: no canonical encoding of
    the parsed object can reproduce a source that names a key twice.
    """
    raw = row[column]
    try:
        parsed = json.loads(raw)
        canonical = json.dumps(parsed, sort_keys=True, ensure_ascii=False,
                               allow_nan=False, separators=(",", ":"))
        canonical.encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise DbError(f"{column} requires canonical UTF-8 JSON") from exc
    if not isinstance(parsed, list) or raw != canonical:
        raise DbError(f"{column} requires a canonical JSON array")
    return parsed


def _validate_hunt_candidate(row: dict[str, str]) -> None:
    _validate_surface_text(row, "cba_hunt_candidates", counts=("confidence",))
    _validate_nonnegative_integers(row, ("confidence",))
    if int(row["confidence"]) > 10:
        raise DbError("confidence must be an integer 0-10")
    _validate_surface_identifier(row, "candidate_id")
    _validate_sha256(row, "artifact_sha256")
    for column, allowed in (("lane", HUNT_LANES),
                            ("lifecycle_required", LIFECYCLE_STATES),
                            ("posture_required", POSTURE_STATES),
                            ("auth_required", AUTH_STATES),
                            ("reachability", REACHABILITY_STATES)):
        one_of(column, allowed)(row)
    surface_ids = _hunt_json_array(row, "surface_ids")
    seen: set[str] = set()
    for identifier in surface_ids:
        _validate_surface_identifier({"surface_ids": identifier}, "surface_ids")
        if identifier in seen:
            raise DbError("surface_ids must not repeat an identifier")
        seen.add(identifier)
    blockers = _hunt_json_array(row, "blockers")
    seen.clear()
    fields = {"id", "question", "settling_observation", "method"}
    for blocker in blockers:
        if not isinstance(blocker, dict) or set(blocker) != fields:
            raise DbError("blockers require exactly id, question, settling_observation, method")
        if any(not isinstance(blocker[field], str) or not blocker[field].strip()
               for field in fields):
            raise DbError("blockers require non-empty string fields")
        try:
            _validate_surface_identifier(blocker, "id")
        except DbError as exc:
            raise DbError(f"blockers: {exc}") from exc
        if blocker["method"] not in UNKNOWN_METHODS:
            raise DbError("blockers method must be static, emulate, or hardware")
        if blocker["id"] in seen:
            raise DbError("blockers must not repeat an id")
        seen.add(blocker["id"])


def _firmware_fp_text(value: object, column: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DbError(f"{column} requires a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise DbError(f"{column} requires UTF-8 text") from exc


def _firmware_fp_path(value: object, column: str, *, absolute: bool = False) -> None:
    """Validate spelling only; phase modules establish run containment."""
    _firmware_fp_text(value, column)
    parts = value[1:].split("/") if absolute and value.startswith("/") else value.split("/")
    if ("\\" in value or "\x00" in value or re.match(r"^[A-Za-z]:", value)
            or (value.startswith("/") and not absolute)
            or any(part in ("", ".", "..") for part in parts)):
        raise DbError(f"{column} requires a canonical {'stored' if absolute else 'relative'} path")


def _firmware_fp_base(row: dict[str, str], table: str) -> None:
    counts = tuple(column for column in TABLE_SPECS[table].required
                   if column.endswith("_count") or column == "confidence")
    _validate_surface_text(row, table, counts=counts)
    _validate_nonnegative_integers(row, counts)
    for column in TABLE_SPECS[table].required:
        if column in counts:
            continue
        _firmware_fp_text(row[column], column)
        if column.endswith("_sha256"):
            _validate_sha256(row, column)
        if column in ("worklist_path", "result_path", "artifact_path"):
            _firmware_fp_path(row[column], column, absolute=True)
    if "confidence" in counts and int(row["confidence"]) > 10:
        raise DbError("confidence requires an integer 0-10")


def _firmware_fp_array(row: dict[str, str], column: str, *, nonempty: bool = False) -> list:
    values = _hunt_json_array(row, column)
    if nonempty and not values:
        raise DbError(f"{column} requires at least one entry")
    seen: set[object] = set()
    for value in values:
        if column == "contributors":
            if not isinstance(value, dict) or set(value) != {"lane", "candidate_id"}:
                raise DbError("contributors require exactly lane and candidate_id")
            try:
                _firmware_fp_text(value["lane"], "lane")
                one_of("lane", HUNT_LANES)(value)
                _validate_surface_identifier(value, "candidate_id")
            except DbError as exc:
                raise DbError(f"contributors: {exc}") from exc
            identity = (value["lane"], value["candidate_id"])
        else:
            _firmware_fp_text(value, column)
            if column == "component_paths":
                _firmware_fp_path(value, column)
            elif column == "lanes":
                one_of(column, HUNT_LANES)({column: value})
            else:
                _validate_surface_identifier({column: value}, column)
            identity = value
        if identity in seen:
            raise DbError(f"{column} must not repeat an entry")
        seen.add(identity)
    return values


def _validate_firmware_fp_run(row: dict[str, str]) -> None:
    _firmware_fp_base(row, "cba_firmware_fp_runs")
    one_of("status", FIRMWARE_FP_RUN_STATES)(row)


def _validate_firmware_fp_receipt(row: dict[str, str]) -> None:
    _firmware_fp_base(row, "cba_firmware_fp_receipts")
    _firmware_fp_path(row["batch_path"], "batch_path")


def _validate_firmware_fp_verdict(row: dict[str, str]) -> None:
    _firmware_fp_base(row, "cba_firmware_fp_verdicts")
    one_of("lane", HUNT_LANES)(row)
    one_of("verdict", FIRMWARE_FP_VERDICTS)(row)
    _validate_surface_identifier(row, "candidate_id")
    _firmware_fp_path(row["batch_path"], "batch_path")
    _firmware_fp_array(row, "rules_applied")
    variants = {
        "TRUE_POSITIVE": ("root_cause_key", "root_cause", "dedup_evidence",
                          "reviewed_attacker_position", "reviewed_data_flow",
                          "reviewed_impact_hypothesis", "component_paths", "surface_ids"),
        "FALSE_POSITIVE": ("refuting_mechanism", "pivot_id"),
        "DUPLICATE": ("duplicate_lane", "duplicate_candidate_id", "dedup_evidence"),
    }
    required = variants[row["verdict"]]
    for column in set().union(*variants.values()) - set(required):
        if row.get(column) is not None:
            raise DbError(f"{column} must be NULL for {row['verdict']}")
    for column in required:
        _firmware_fp_text(row.get(column), column)
    for column in ("root_cause_key", "pivot_id", "duplicate_candidate_id"):
        if column in required:
            _validate_surface_identifier(row, column)
    if row["verdict"] == "DUPLICATE":
        one_of("duplicate_lane", HUNT_LANES)(row)
    if row["verdict"] == "TRUE_POSITIVE":
        _firmware_fp_array(row, "component_paths", nonempty=True)
        _firmware_fp_array(row, "surface_ids")


def _validate_firmware_pivot(row: dict[str, str]) -> None:
    _firmware_fp_base(row, "cba_firmware_pivots")
    for column in ("pivot_id", "source_candidate_id"):
        _validate_surface_identifier(row, column)
    one_of("source_lane", HUNT_LANES)(row)
    _firmware_fp_path(row["component_path"], "component_path")


def _validate_firmware_finding(row: dict[str, str]) -> None:
    _firmware_fp_base(row, "cba_firmware_findings")
    for column in ("finding_id", "root_cause_key", "canonical_candidate_id"):
        _validate_surface_identifier(row, column)
    one_of("canonical_lane", HUNT_LANES)(row)
    one_of("evidence_rung", FIRMWARE_FP_EVIDENCE_RUNGS)(row)
    for column in ("contributors", "lanes", "component_paths", "surface_ids"):
        _firmware_fp_array(row, column, nonempty=column != "surface_ids")


def _firmware_chain_base(row: dict[str, str], table: str) -> None:
    """Local scalar shape only; phase modules prove ownership and derivation."""
    counts = tuple(column for column in TABLE_SPECS[table].required
                   if column.endswith("_count") or column in ("confidence", "ordinal"))
    _validate_surface_text(row, table, counts=counts)
    _validate_nonnegative_integers(row, counts)
    for column, value in row.items():
        if column in counts or value is None:
            continue
        _firmware_fp_text(value, column)
        if column.endswith("_sha256"):
            _validate_sha256(row, column)
        if column.endswith("_path"):
            _firmware_fp_path(value, column, absolute=True)
        if column in ("finding_id", "chain_id", "blocker_id", "producer_finding_id", "consumer_finding_id"):
            _validate_surface_identifier(row, column)
    if "confidence" in counts and int(row["confidence"]) > 10:
        raise DbError("confidence requires an integer 0-10")


def _firmware_chain_unique(values: list, column: str, *, ordered: bool = False) -> None:
    if len(set(values)) != len(values):
        raise DbError(f"{column} must not repeat an entry")
    if not ordered and values != sorted(values):
        raise DbError(f"{column} requires sorted entries")


def _firmware_chain_ids(row: dict[str, str], column: str, *, minimum: int = 0,
                        ordered: bool = False) -> list:
    values = _hunt_json_array(row, column)
    if len(values) < minimum:
        raise DbError(f"{column} requires at least {minimum} entries")
    for value in values:
        _validate_surface_identifier({column: value}, column)
    _firmware_chain_unique(values, column, ordered=ordered)
    return values


def _firmware_chain_axes(values: object, column: str) -> None:
    if not isinstance(values, list) or not values:
        raise DbError(f"{column} requires at least one affected axis")
    for value in values:
        if value not in FIRMWARE_CHAIN_AXES:
            raise DbError(f"{column} has an invalid affected axis")
    _firmware_chain_unique(values, column)


def _firmware_chain_refs(row: dict[str, str], column: str, *, initial: bool = False,
                         supplemental: bool = False) -> None:
    values = _hunt_json_array(row, column)
    if not supplemental and not values:
        raise DbError(f"{column} requires at least one evidence reference")
    for value in values:
        _firmware_fp_text(value, column)
        match = re.fullmatch(r"(finding|surface|unknown):([A-Za-z0-9][A-Za-z0-9._:-]{0,127})#([a-z_]+)", value)
        if match is None:
            raise DbError(f"{column} requires machine-addressable evidence references")
        kind, _, field = match.groups()
        fields = {"finding": ("root_cause", "attacker_position", "data_flow", "impact_hypothesis", "evidence_summary"),
                  "surface": ("reach_evidence",), "unknown": ("evidence",)}
        if (field not in fields[kind] or (supplemental and kind == "finding")
                or (not supplemental and not initial and kind != "finding")
                or (initial and (kind == "unknown" or
                     (kind == "finding" and field not in ("attacker_position", "evidence_summary"))))):
            raise DbError(f"{column} has an invalid evidence variant")
    _firmware_chain_unique(values, column)


def _firmware_chain_state(row: dict[str, str], column: str, sentinel: str) -> None:
    raw = row[column]
    try:
        values = json.loads(raw)
        canonical = json.dumps(values, sort_keys=True, ensure_ascii=False,
                               allow_nan=False, separators=(",", ":"))
        canonical.encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise DbError(f"{column} requires canonical UTF-8 JSON") from exc
    if (raw != canonical or not isinstance(values, dict)
            or set(values) != {"lifecycle", "posture", "authentication"}):
        raise DbError(f"{column} requires exactly lifecycle, posture, authentication")
    for axis, allowed in (("lifecycle", FIRMWARE_CHAIN_LIFECYCLE_STATES),
                           ("posture", FIRMWARE_CHAIN_POSTURE_STATES),
                           ("authentication", FIRMWARE_CHAIN_AUTH_STATES)):
        if values[axis] not in (*allowed, sentinel):
            raise DbError(f"{column} has an invalid {axis} state")


def _validate_firmware_chain_run(row: dict[str, str]) -> None:
    _firmware_chain_base(row, "cba_firmware_chain_runs")
    one_of("status", FIRMWARE_CHAIN_RUN_STATES)(row)
    for column in ("graph_path", "graph_sha256", "completed_at"):
        if row["status"] == "pending" and row.get(column) is not None:
            raise DbError(f"{column} must be NULL for a pending chain run")
        if row["status"] == "complete":
            _firmware_fp_text(row.get(column), column)


def _validate_firmware_chain_receipt(row: dict[str, str]) -> None:
    _firmware_chain_base(row, "cba_firmware_chain_receipts")


def _validate_firmware_chain_disposition(row: dict[str, str]) -> None:
    _firmware_chain_base(row, "cba_firmware_chain_dispositions")
    one_of("disposition", FIRMWARE_CHAIN_DISPOSITIONS)(row)
    arrays = {column: _firmware_chain_ids(row, column) for column in
              ("chain_ids", "existing_unknown_ids", "blocker_ids", "pivot_followup_ids")}
    if bool(arrays["chain_ids"]) != (row["disposition"] == "chained"):
        raise DbError("chain_ids must be non-empty exactly for a chained disposition")
    if row["disposition"] == "blocked" and not (arrays["existing_unknown_ids"] or arrays["blocker_ids"]):
        raise DbError("a blocked disposition requires existing_unknown_ids or blocker_ids")
    if row["disposition"] in ("standalone", "unchainable") and (
            arrays["existing_unknown_ids"] or arrays["blocker_ids"]):
        raise DbError("unresolved references require a blocked or chained disposition")
    if arrays["pivot_followup_ids"] and row["disposition"] not in ("unchainable", "blocked"):
        raise DbError("pivot_followup_ids are only valid for unchainable or blocked dispositions")


def _validate_firmware_chain_unknown(row: dict[str, str]) -> None:
    _firmware_chain_base(row, "cba_firmware_chain_unknowns")
    one_of("method", FIRMWARE_CHAIN_METHODS)(row)
    one_of("status", ("open",))(row)
    _firmware_chain_axes(_hunt_json_array(row, "axes"), "axes")
    findings = _firmware_chain_ids(row, "affected_finding_ids")
    edges = _hunt_json_array(row, "affected_edges")
    identities = []
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != {"chain_id", "ordinal"}:
            raise DbError("affected_edges require exactly chain_id and ordinal")
        try:
            _validate_surface_identifier(edge, "chain_id")
            if isinstance(edge["ordinal"], bool) or not isinstance(edge["ordinal"], int):
                raise DbError("ordinal requires an integer")
            _validate_nonnegative_integers(edge, ("ordinal",))
        except DbError as exc:
            raise DbError(f"affected_edges: {exc}") from exc
        identities.append((edge["chain_id"], edge["ordinal"]))
    _firmware_chain_unique(identities, "affected_edges")
    if not findings and not edges:
        raise DbError("affected_finding_ids or affected_edges must be non-empty")


def _validate_firmware_chain(row: dict[str, str]) -> None:
    _firmware_chain_base(row, "cba_firmware_chains")
    for column, allowed in (("initial_lifecycle", FIRMWARE_CHAIN_LIFECYCLE_STATES),
                            ("initial_posture", FIRMWARE_CHAIN_POSTURE_STATES),
                            ("initial_authentication", FIRMWARE_CHAIN_AUTH_STATES),
                            ("pre_auth", FIRMWARE_CHAIN_PRE_AUTH),
                            ("completeness", FIRMWARE_CHAIN_COMPLETENESS),
                            ("evidence_rung", FIRMWARE_CHAIN_EVIDENCE_RUNGS)):
        one_of(column, allowed)(row)
    _firmware_chain_ids(row, "member_ids", minimum=2, ordered=True)
    _firmware_chain_refs(row, "initial_evidence_refs", initial=True)
    blockers = [_firmware_chain_ids(row, column) for column in ("existing_unknown_ids", "blocker_ids")]
    if any(blockers) != (row["completeness"] == "blocked"):
        raise DbError("completeness must be blocked exactly when blocker references are present")


def _validate_firmware_chain_edge(row: dict[str, str]) -> None:
    _firmware_chain_base(row, "cba_firmware_chain_edges")
    one_of("capability_kind", FIRMWARE_CHAIN_CAPABILITY_KINDS)(row)
    one_of("transition_kind", FIRMWARE_CHAIN_TRANSITION_KINDS)(row)
    if (row["capability_kind"] == "other-specific" and
            not firmware_chain_other_specific_link_key(row["link_key"])):
        raise DbError("link_key for other-specific requires a namespace-like resource key")
    for column in ("producer_evidence_refs", "consumer_evidence_refs", "supplemental_evidence_refs"):
        _firmware_chain_refs(row, column, supplemental=column == "supplemental_evidence_refs")
    _firmware_chain_state(row, "required_state", "any")
    _firmware_chain_state(row, "result_state", "unchanged")
    _firmware_chain_ids(row, "blocker_ids")
    unknowns = _hunt_json_array(row, "existing_unknowns")
    identities = []
    for unknown in unknowns:
        if not isinstance(unknown, dict) or set(unknown) != {"unknown_id", "axes"}:
            raise DbError("existing_unknowns require exactly unknown_id and axes")
        _validate_surface_identifier({"existing_unknowns": unknown["unknown_id"]}, "existing_unknowns")
        _firmware_chain_axes(unknown["axes"], "existing_unknowns")
        identities.append(unknown["unknown_id"])
    _firmware_chain_unique(identities, "existing_unknowns")


def firmware_chain_other_specific_link_key(value: object) -> bool:
    """Return whether a broad link key names one concrete custom resource."""
    if not isinstance(value, str) or value != value.strip():
        return False
    try:
        if len(value.encode("utf-8")) > 4096:
            return False
    except UnicodeError:
        return False
    if any(unicodedata.category(char) == "Cc" for char in value):
        return False
    parts = value.split(":", 1)
    generic = {"generic", "other", "access", "capability", "resource", "state", "unknown", "any"}
    return (len(parts) == 2 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", parts[0]) is not None
            and bool(parts[1].strip())
            and all(part.strip().casefold() not in generic for part in parts))


def _validate_diff_entry(row: dict[str, str]) -> None:
    change = row.get("change")
    if change not in DIFF_CHANGES:
        raise DbError(f"change={change!r} is not one of {', '.join(DIFF_CHANGES)}")
    sides = (("target",) if change == "added" else
             ("reference",) if change == "removed" else ("reference", "target"))
    missing = [f"{side}_{field}" for side in sides
               for field in ("kind", "size", "sha256")
               if row.get(f"{side}_{field}") is None
               or not str(row[f"{side}_{field}"]).strip()]
    if missing:
        raise DbError(f"change={change} requires a non-empty value for: "
                      + ", ".join(missing))


TABLE_SPECS: dict[str, TableSpec] = {
    "cba_sources": TableSpec(
        columns=("id", "type", "source_path", "source_language",
                 "source_file_count", "ida_binary", "ida_port", "ida_arch",
                 "confirmed_at"),
        required=("id", "type"), primary_key=("id",)),
    "cba_feature_groups": TableSpec(
        columns=("id", "name", "description", "key_paths", "status", "created_at"),
        required=("id", "name"), primary_key=("id",)),
    "cba_attack_surface": TableSpec(
        columns=("id", "group_id", "endpoint", "method", "auth_required",
                 "description"),
        required=("group_id", "endpoint"), primary_key=("id",)),
    "cba_security_observations": TableSpec(
        columns=("id", "group_id", "observation", "severity_hint", "location"),
        required=("group_id", "observation"), primary_key=("id",)),
    "cba_known_findings": TableSpec(
        columns=("id", "title", "location", "source", "patched_in", "severity", "raw"),
        required=("id", "title"), primary_key=("id",)),
    "cba_findings": TableSpec(
        columns=("id", "group_id", "title", "severity", "confidence", "cwe",
                 "location", "root_cause", "impact", "attacker_position",
                 "boundary_crossed", "data_flow", "verified", "poc",
                 "remediation", "artifact_path", "created_at"),
        required=("id", "group_id", "title", "severity", "confidence",
                  "location", "root_cause", "impact"),
        primary_key=("id",),
        validate=one_of("severity", SEVERITIES)),
    "cba_fp_verdicts": TableSpec(
        columns=("finding_id", "verdict", "reason", "final_severity", "final_id",
                 "merged_into", "rule_applied", "refuting_mechanism",
                 "enabled_observation", "reviewed_at"),
        required=("finding_id", "verdict"),
        primary_key=("finding_id",),
        validate=_validate_verdict),
    "cba_inventory": TableSpec(
        columns=("unit", "kind", "group_id", "size", "added_at"),
        required=("unit", "kind"),
        primary_key=("unit",),
        validate=one_of("kind", INVENTORY_KINDS)),
    "cba_coverage": TableSpec(
        columns=("unit", "phase", "state", "reason", "recorded_at"),
        required=("unit", "phase", "state"),
        primary_key=("unit", "phase"),
        validate=_validate_coverage),
    "cba_patterns": TableSpec(
        columns=("id", "name", "regex", "origin_finding", "language", "notes",
                 "swept_at", "hit_count", "created_at"),
        required=("id", "name", "regex"),
        primary_key=("id",),
        validate=_validate_pattern),
    "cba_pattern_hits": TableSpec(
        columns=("id", "pattern_id", "path", "line", "excerpt", "triaged",
                 "swept_at"),
        required=("pattern_id", "path", "line"), primary_key=("id",)),
    "cba_checkpoints": TableSpec(
        columns=("id", "phase", "reason", "turns", "projected_context",
                 "resume_note", "recorded_at"),
        required=("phase", "reason"),
        primary_key=("id",),
        validate=one_of("reason", CHECKPOINT_REASONS)),
    "cba_components": TableSpec(
        columns=("path", "kind", "asserted_identity", "identity_evidence",
                 "confidence", "version", "recorded_at"),
        required=("path", "kind", "asserted_identity", "identity_evidence"),
        primary_key=("path",),
        validate=_validate_component),
    "cba_chains": TableSpec(
        columns=("id", "finding_ids", "attacker_position", "pre_auth",
                 "completeness", "blocking_unknowns", "created_at"),
        required=("id", "finding_ids", "attacker_position", "completeness"),
        primary_key=("id",),
        validate=_validate_chain),
    "cba_images": TableSpec(
        columns=("id", "vendor", "model", "version", "role", "path", "sha256",
                 "size", "source", "acquired_at"),
        required=("id", "vendor", "model", "version", "role", "path", "sha256"),
        primary_key=("id",),
        validate=one_of("role", IMAGE_ROLES)),
    "cba_binfacts": TableSpec(
        columns=("image_id", "path", "machine", "bits", "endian", "elf_type",
                 "interp", "needed", "runpath", "nx", "pie", "relro", "canary",
                 "stripped", "static", "sha256", "recorded_at"),
        required=("image_id", "path", "machine", "bits", "endian", "elf_type"),
        primary_key=("image_id", "path"),
        validate=_validate_binfacts),
    "cba_services": TableSpec(
        columns=("image_id", "name", "start_source", "exec_path", "evidence",
                 "ports", "ports_evidence", "recorded_at"),
        required=("image_id", "name", "start_source", "evidence"),
        primary_key=("image_id", "name"),
        validate=_validate_service),
    "cba_firmware_files": TableSpec(
        columns=("image_id", "path", "kind", "size", "sha256", "recorded_at"),
        required=("image_id", "path", "kind", "size", "sha256"),
        primary_key=("image_id", "path")),
    "cba_diffs": TableSpec(
        columns=("id", "reference_image_id", "target_image_id", "added_count",
                 "removed_count", "modified_count", "unchanged_count",
                 "manifest_path", "recorded_at"),
        required=("id", "reference_image_id", "target_image_id", "added_count",
                  "removed_count", "modified_count", "unchanged_count",
                  "manifest_path"),
        primary_key=("id",),
        validate=_validate_diff),
    "cba_diff_entries": TableSpec(
        columns=("diff_id", "path", "change", "reference_kind", "target_kind",
                 "reference_size", "target_size", "reference_sha256",
                 "target_sha256"),
        required=("diff_id", "path", "change"),
        primary_key=("diff_id", "path"),
        validate=_validate_diff_entry),
    "cba_surface_runs": TableSpec(
        columns=("image_id", "manifest_sha256", "worklist_path", "worklist_sha256",
                 "unit_count", "batch_count", "status", "prepared_at", "completed_at"),
        required=("image_id", "manifest_sha256", "worklist_path", "worklist_sha256",
                  "unit_count", "batch_count", "status"),
        primary_key=("image_id",), validate=_validate_surface_run),
    "cba_firmware_surfaces": TableSpec(
        columns=("image_id", "surface_id", "component_path", "entry_point", "protocol",
                 "dispatch_path", "handler", "lifecycle_required", "posture_required",
                 "auth_required", "reachability", "reach_evidence", "artifact_path",
                 "artifact_sha256", "recorded_at"),
        required=("image_id", "surface_id", "component_path", "entry_point", "protocol",
                  "dispatch_path", "handler", "lifecycle_required", "posture_required",
                  "auth_required", "reachability", "reach_evidence", "artifact_path",
                  "artifact_sha256"),
        primary_key=("image_id", "surface_id"), validate=_validate_firmware_surface),
    "cba_unknowns": TableSpec(
        columns=("id", "image_id", "component_path", "surface_id", "field", "question",
                 "settling_observation", "method", "status", "resolution", "evidence",
                 "artifact_path", "artifact_sha256", "recorded_at"),
        required=("id", "image_id", "component_path", "field", "question",
                  "settling_observation", "method", "status", "artifact_path",
                  "artifact_sha256"),
        primary_key=("id",), validate=_validate_unknown),
    "cba_hunt_runs": TableSpec(
        columns=("image_id", "lane", "manifest_sha256", "surface_snapshot_sha256",
                 "worklist_path", "worklist_sha256", "unit_count", "batch_count",
                 "status", "prepared_at", "completed_at"),
        required=("image_id", "lane", "manifest_sha256", "surface_snapshot_sha256",
                  "worklist_path", "worklist_sha256", "unit_count", "batch_count", "status"),
        primary_key=("image_id", "lane"), validate=_validate_hunt_run),
    "cba_hunt_receipts": TableSpec(
        columns=("image_id", "lane", "worklist_sha256", "batch_path", "batch_sha256",
                 "result_path", "result_sha256", "unit_count", "candidate_count", "recorded_at"),
        required=("image_id", "lane", "worklist_sha256", "batch_path", "batch_sha256",
                  "result_path", "result_sha256", "unit_count", "candidate_count"),
        primary_key=("image_id", "lane", "worklist_sha256", "batch_path"),
        validate=_validate_hunt_receipt),
    "cba_hunt_candidates": TableSpec(
        columns=("image_id", "lane", "candidate_id", "component_path", "title", "bug_class",
                 "surface_ids", "surface_context", "attacker_position", "input_evidence",
                 "data_flow", "dangerous_operation", "operation_evidence", "mitigations_checked",
                 "lifecycle_required", "posture_required", "auth_required", "reachability",
                 "state_evidence", "confidence", "impact_hypothesis", "blockers", "artifact_path",
                 "artifact_sha256", "recorded_at"),
        required=("image_id", "lane", "candidate_id", "component_path", "title", "bug_class",
                  "surface_ids", "surface_context", "attacker_position", "input_evidence",
                  "data_flow", "dangerous_operation", "operation_evidence", "mitigations_checked",
                  "lifecycle_required", "posture_required", "auth_required", "reachability",
                  "state_evidence", "confidence", "impact_hypothesis", "blockers", "artifact_path",
                  "artifact_sha256"),
        primary_key=("image_id", "lane", "candidate_id"), validate=_validate_hunt_candidate),
    "cba_firmware_fp_runs": TableSpec(
        columns=("image_id", "manifest_sha256", "surface_snapshot_sha256", "sink_worklist_sha256",
                 "dark_worklist_sha256", "candidate_snapshot_sha256", "worklist_path", "worklist_sha256",
                 "candidate_count", "batch_count", "status", "prepared_at", "completed_at"),
        required=("image_id", "manifest_sha256", "surface_snapshot_sha256", "sink_worklist_sha256",
                  "dark_worklist_sha256", "candidate_snapshot_sha256", "worklist_path", "worklist_sha256",
                  "candidate_count", "batch_count", "status"),
        primary_key=("image_id",), validate=_validate_firmware_fp_run),
    "cba_firmware_fp_receipts": TableSpec(
        columns=("image_id", "candidate_snapshot_sha256", "worklist_sha256", "batch_path", "batch_sha256",
                 "result_path", "result_sha256", "assigned_count", "verdict_count", "true_positive_count",
                 "false_positive_count", "duplicate_count", "pivot_count", "recorded_at"),
        required=("image_id", "candidate_snapshot_sha256", "worklist_sha256", "batch_path", "batch_sha256",
                  "result_path", "result_sha256", "assigned_count", "verdict_count", "true_positive_count",
                  "false_positive_count", "duplicate_count", "pivot_count"),
        primary_key=("image_id", "candidate_snapshot_sha256", "batch_path"),
        validate=_validate_firmware_fp_receipt),
    "cba_firmware_fp_verdicts": TableSpec(
        columns=("image_id", "lane", "candidate_id", "candidate_snapshot_sha256", "batch_path", "verdict",
                 "reason", "attacker_advantage", "rules_applied", "mitigation_analysis", "confidence",
                 "root_cause_key", "root_cause", "dedup_evidence", "duplicate_lane", "duplicate_candidate_id",
                 "refuting_mechanism", "pivot_id", "reviewed_attacker_position", "reviewed_data_flow",
                 "reviewed_impact_hypothesis", "component_paths", "surface_ids", "artifact_path",
                 "artifact_sha256", "reviewed_at"),
        required=("image_id", "lane", "candidate_id", "candidate_snapshot_sha256", "batch_path", "verdict",
                  "reason", "attacker_advantage", "rules_applied", "mitigation_analysis", "confidence",
                  "artifact_path", "artifact_sha256"),
        primary_key=("image_id", "lane", "candidate_id"), validate=_validate_firmware_fp_verdict),
    "cba_firmware_pivots": TableSpec(
        columns=("image_id", "pivot_id", "candidate_snapshot_sha256", "source_lane", "source_candidate_id",
                 "component_path", "refuting_mechanism", "enabled_observation", "evidence", "artifact_path",
                 "artifact_sha256", "recorded_at"),
        required=("image_id", "pivot_id", "candidate_snapshot_sha256", "source_lane", "source_candidate_id",
                  "component_path", "refuting_mechanism", "enabled_observation", "evidence", "artifact_path",
                  "artifact_sha256"),
        primary_key=("image_id", "pivot_id"), validate=_validate_firmware_pivot),
    "cba_firmware_findings": TableSpec(
        columns=("image_id", "finding_id", "candidate_snapshot_sha256", "root_cause_key", "canonical_lane",
                 "canonical_candidate_id", "contributors", "lanes", "component_paths", "surface_ids", "title",
                 "bug_class", "root_cause", "attacker_position", "data_flow", "impact_hypothesis",
                 "evidence_summary", "confidence", "evidence_rung", "artifact_path", "artifact_sha256", "derived_at"),
        required=("image_id", "finding_id", "candidate_snapshot_sha256", "root_cause_key", "canonical_lane",
                  "canonical_candidate_id", "contributors", "lanes", "component_paths", "surface_ids", "title",
                  "bug_class", "root_cause", "attacker_position", "data_flow", "impact_hypothesis",
                  "evidence_summary", "confidence", "evidence_rung", "artifact_path", "artifact_sha256"),
        primary_key=("image_id", "finding_id"), validate=_validate_firmware_finding),
    "cba_firmware_chain_runs": TableSpec(
        columns=("image_id", "manifest_sha256", "surface_snapshot_sha256", "candidate_snapshot_sha256",
                 "fpcheck_artifact_path", "fpcheck_artifact_sha256", "worklist_path", "worklist_sha256",
                 "finding_count", "surface_count", "unknown_count", "pivot_count", "status", "graph_path",
                 "graph_sha256", "prepared_at", "completed_at"),
        required=("image_id", "manifest_sha256", "surface_snapshot_sha256", "candidate_snapshot_sha256",
                  "fpcheck_artifact_path", "fpcheck_artifact_sha256", "worklist_path", "worklist_sha256",
                  "finding_count", "surface_count", "unknown_count", "pivot_count", "status"),
        primary_key=("image_id",), validate=_validate_firmware_chain_run),
    "cba_firmware_chain_receipts": TableSpec(
        columns=("image_id", "candidate_snapshot_sha256", "worklist_sha256", "result_path", "result_sha256",
                 "disposition_count", "blocker_count", "chain_count", "edge_count", "recorded_at"),
        required=("image_id", "candidate_snapshot_sha256", "worklist_sha256", "result_path", "result_sha256",
                  "disposition_count", "blocker_count", "chain_count", "edge_count"),
        primary_key=("image_id", "candidate_snapshot_sha256"), validate=_validate_firmware_chain_receipt),
    "cba_firmware_chain_dispositions": TableSpec(
        columns=("image_id", "finding_id", "candidate_snapshot_sha256", "disposition", "explanation",
                 "chain_ids", "existing_unknown_ids", "blocker_ids", "pivot_followup_ids", "artifact_path",
                 "artifact_sha256", "recorded_at"),
        required=("image_id", "finding_id", "candidate_snapshot_sha256", "disposition", "explanation",
                  "chain_ids", "existing_unknown_ids", "blocker_ids", "pivot_followup_ids", "artifact_path",
                  "artifact_sha256"),
        primary_key=("image_id", "finding_id"), validate=_validate_firmware_chain_disposition),
    "cba_firmware_chain_unknowns": TableSpec(
        columns=("image_id", "blocker_id", "candidate_snapshot_sha256", "question", "settling_observation",
                 "method", "axes", "affected_finding_ids", "affected_edges", "status", "artifact_path",
                 "artifact_sha256", "recorded_at"),
        required=("image_id", "blocker_id", "candidate_snapshot_sha256", "question", "settling_observation",
                  "method", "axes", "affected_finding_ids", "affected_edges", "status", "artifact_path",
                  "artifact_sha256"),
        primary_key=("image_id", "blocker_id"), validate=_validate_firmware_chain_unknown),
    "cba_firmware_chains": TableSpec(
        columns=("image_id", "chain_id", "candidate_snapshot_sha256", "title", "summary", "member_ids",
                 "initial_attacker_position", "initial_evidence_refs", "initial_lifecycle", "initial_posture",
                 "initial_authentication", "pre_auth", "confidence", "completeness", "existing_unknown_ids",
                 "blocker_ids", "evidence_rung", "artifact_path", "artifact_sha256", "derived_at"),
        required=("image_id", "chain_id", "candidate_snapshot_sha256", "title", "summary", "member_ids",
                  "initial_attacker_position", "initial_evidence_refs", "initial_lifecycle", "initial_posture",
                  "initial_authentication", "pre_auth", "confidence", "completeness", "existing_unknown_ids",
                  "blocker_ids", "evidence_rung", "artifact_path", "artifact_sha256"),
        primary_key=("image_id", "chain_id"), validate=_validate_firmware_chain),
    "cba_firmware_chain_edges": TableSpec(
        columns=("image_id", "chain_id", "ordinal", "candidate_snapshot_sha256", "producer_finding_id",
                 "consumer_finding_id", "capability_kind", "link_key", "produced_capability",
                 "required_precondition", "producer_evidence_refs", "consumer_evidence_refs",
                 "supplemental_evidence_refs", "required_state", "result_state", "transition_kind",
                 "confidence", "existing_unknowns", "blocker_ids", "artifact_path", "artifact_sha256", "derived_at"),
        required=("image_id", "chain_id", "ordinal", "candidate_snapshot_sha256", "producer_finding_id",
                  "consumer_finding_id", "capability_kind", "link_key", "produced_capability",
                  "required_precondition", "producer_evidence_refs", "consumer_evidence_refs",
                  "supplemental_evidence_refs", "required_state", "result_state", "transition_kind",
                  "confidence", "existing_unknowns", "blocker_ids", "artifact_path", "artifact_sha256"),
        primary_key=("image_id", "chain_id", "ordinal"), validate=_validate_firmware_chain_edge),
}


def table_columns(con: sqlite3.Connection, table: str) -> tuple[str, ...]:
    """The columns a database actually has for `table`, in declared order.

    `table` is interpolated into the PRAGMA, which takes no bound parameters.
    It is checked against TABLE_SPECS first, so the only strings that reach
    the statement are the fourteen literals this module declares.
    """
    _spec(table)
    return tuple(r[1] for r in con.execute(f"PRAGMA table_info({table})"))


def _rebuild_firmware_table(con: sqlite3.Connection, table: str) -> None:
    """Copy a Stage 4b table into the current schema inside migrate's transaction.

    Reuse the shipped DDL rather than maintaining a second current definition.
    Column names come from the registered table contract; values, including
    the legacy scope, are bound. Explicit column lists preserve timestamps and
    every optional fact even though the current declaration changes order.
    """
    _spec(table)
    private = f"_stage4c_{table}"
    con.execute(f"ALTER TABLE {table} RENAME TO {private}")
    schema = (pathlib.Path(__file__).resolve().parent / "schema.sql").read_text()
    declaration = next(statement for statement in schema.split(";")
                       if f"CREATE TABLE IF NOT EXISTS {table} (" in statement)
    con.execute(declaration)
    columns = table_columns(con, table)
    selected = ", ".join("COALESCE(image_id, ?)" if c == "image_id" else c
                         for c in columns)
    con.execute(f"INSERT INTO {table} ({', '.join(columns)}) "
                f"SELECT {selected} FROM {private}", (FIRMWARE_IMAGE_UNSCOPED,))
    con.execute(f"DROP TABLE {private}")


def migrate(con: sqlite3.Connection) -> list[str]:
    """Add missing columns and rebuild Stage 4b firmware keys atomically.

    Idempotent, and safe against a database that has none of the tables yet:
    a table that is not there is skipped rather than reported, because that
    is what `init` sees on a fresh run before schema.sql has been applied.
    """
    present = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    additions = [(table, column, decl) for table, column, decl in MIGRATIONS
                 if table in present and column not in table_columns(con, table)]
    rebuilds = [table for table, old_key in (
        ("cba_binfacts", ("path",)), ("cba_services", ("name",)))
        if table in present and primary_key(con, table) == old_key]
    if not additions and not rebuilds:
        return []
    applied: list[str] = []
    with con:
        # DDL alone does not start sqlite3's implicit transaction. An explicit
        # BEGIN makes both renames/creates/copies/drops rollback together.
        if not con.in_transaction:
            con.execute("BEGIN")
        for table, column, decl in additions:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
            applied.append(f"{table}.{column}")
        for table in rebuilds:
            _rebuild_firmware_table(con, table)
            applied.append(f"{table}.primary_key")
    return applied


def connect(db_path: str | pathlib.Path, *, read_only: bool = False) -> sqlite3.Connection:
    """Open a run's audit.db, or say exactly what is wrong with it.

    The missing-*file* case was already covered. The missing-*schema* case was
    not, and it is the normal upgrade path: a user upgrades an installed skill
    and the next phase of an in-flight audit opens a run directory created
    before these tables existed. Every verb that touched one answered with
    `sqlite3.OperationalError: no such table` and a raw traceback.

    The check is here rather than in each verb because every verb reaches the
    database through this function - except `bench`, which opens `cba_findings`
    read-only on its own and must keep working against exactly the old run
    directories this gate rejects.
    """
    path = pathlib.Path(db_path)
    if not path.is_file():
        raise DbError(f"no audit.db at {path}; run `audit.py init` first")
    if read_only:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    try:
        present = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
    except sqlite3.DatabaseError as exc:
        con.close()
        raise DbError(f"{path} is not a readable SQLite database: {exc}") from exc
    missing_tables = sorted(set(TABLE_SPECS) - present)
    missing_columns: list[str] = []
    stale_keys: list[str] = []
    if not missing_tables:
        # Only when every table is there: naming a column of a table that
        # does not exist is noise on top of the real problem.
        for table, spec in sorted(TABLE_SPECS.items()):
            have = set(table_columns(con, table))
            missing_columns.extend(
                f"{table}.{c}" for c in spec.columns if c not in have)
            actual_key = primary_key(con, table)
            if actual_key != spec.primary_key:
                stale_keys.append(f"{table} primary key {actual_key!r} "
                                  f"(expected {spec.primary_key!r})")
    if missing_tables or missing_columns or stale_keys:
        con.close()
        noun = ("table(s)" if missing_tables else "column(s)" if missing_columns
                else "current primary key(s)")
        names = ", ".join(missing_tables or missing_columns or stale_keys)
        raise DbError(
            f"{path} is missing {noun}: {names}. This run "
            f"directory predates the current schema. Re-apply it in place "
            f"with `audit.py init --root <project> --timestamp <ts>`, where "
            f"<ts> is the timestamp already in the run directory name - "
            f"every statement in schema.sql is CREATE TABLE IF NOT EXISTS "
            f"and migrations add missing columns and rebuild legacy firmware "
            f"keys transactionally, preserving rows. Without --timestamp, "
            f"`init` creates a new run directory "
            f"instead.")
    return con


def _spec(table: str) -> TableSpec:
    spec = TABLE_SPECS.get(table)
    if spec is None:
        raise DbError(f"{table} is not a known table; "
                      f"known: {', '.join(sorted(TABLE_SPECS))}")
    return spec


def primary_key(con: sqlite3.Connection, table: str) -> tuple[str, ...]:
    """The declared primary-key columns of `table`, in key order.

    `table` is checked against TABLE_SPECS by `table_columns`, so the only
    strings that reach the PRAGMA are this module's own literals.
    """
    _spec(table)
    keyed = [(r[5], r[1]) for r in con.execute(f"PRAGMA table_info({table})")
             if r[5]]
    return tuple(name for _, name in sorted(keyed))


def _merge_with_stored(con: sqlite3.Connection, table: str, spec: TableSpec,
                       row: dict[str, str]) -> dict[str, str]:
    """`row`, filled out from the row it is about to replace.

    `INSERT OR REPLACE` deletes the conflicting row and inserts a new one, so
    every column the caller omits is silently reset - to its DEFAULT if it has
    one, to NULL if it does not. That is not what any caller means by
    "replace this row", and the columns at risk are owned by a *different*
    workflow step than the one doing the replacing.

    Reproduced before this merge existed: fpcheck assigns `cba_fp_verdicts`
    .final_id by a raw UPDATE after the verdicts exist, `pivot.record` writes
    6 of that table's 10 columns, and `pivot --replace` therefore destroyed
    final_id, merged_into, final_severity and reason - the report's finding
    numbering, which exists nowhere else - with exit 0 and no warning, and
    neither `status` nor `pivot --check` noticed.

    So a replace is a merge: the caller's columns win, and the ones it does
    not name keep what is stored. A stored NULL is left out rather than
    bound, so a column's DEFAULT still applies on the re-insert.
    """
    key = primary_key(con, table)
    if not key or any(c not in row for c in key):
        # No declared key, or the caller did not name all of it: there is no
        # row this one provably replaces, so there is nothing to merge.
        return row
    clause = " AND ".join(f"{c} = ?" for c in key)
    stored = con.execute(
        f"SELECT {', '.join(spec.columns)} FROM {table} WHERE {clause}",
        [row[c] for c in key]).fetchone()
    if stored is None:
        return row
    kept = {c: stored[c] for c in spec.columns
            if c not in row and stored[c] is not None}
    return {**kept, **row}


def put(con: sqlite3.Connection, table: str, row: dict[str, str],
        *, replace: bool = False, commit: bool = True) -> None:
    """Insert one validated row. With `replace`, merge it over the stored one.

    Column names are interpolated into the statement, which is safe only
    because every one of them has just been checked against the spec's own
    tuple of names. Values are always bound parameters.

    Validation runs on both what the caller wrote and the effective merged
    result. The first check prevents a new claim from borrowing stale evidence;
    the second prevents an explicit clear from invalidating a retained claim.
    With `commit=False`, the caller owns committing or rolling back the write.
    """
    spec = _spec(table)
    unknown = sorted(set(row) - set(spec.columns))
    if unknown:
        raise DbError(f"{table} has no column(s): {', '.join(unknown)}; "
                      f"columns are: {', '.join(spec.columns)}")
    missing = sorted(c for c in spec.required if not str(row.get(c, "")).strip())
    if missing:
        raise DbError(f"{table} requires a non-empty value for: {', '.join(missing)}")
    if spec.validate is not None:
        spec.validate(row)
    values = _merge_with_stored(con, table, spec, row) if replace else row
    if spec.validate is not None and values is not row:
        spec.validate(values)
    cols = sorted(values)
    verb = "INSERT OR REPLACE" if replace else "INSERT"
    sql = (f"{verb} INTO {table} ({', '.join(cols)}) "
           f"VALUES ({', '.join('?' for _ in cols)})")
    try:
        con.execute(sql, [values[c] for c in cols])
    except sqlite3.IntegrityError as exc:
        raise DbError(f"{table}: {exc}; pass --replace to overwrite") from exc
    if commit:
        con.commit()


def rows(con: sqlite3.Connection, table: str, *,
         where: dict[str, str] | None = None,
         columns: tuple[str, ...] | None = None,
         limit: int = MAX_ROWS) -> list[sqlite3.Row]:
    """A bounded read. R1: the orchestrator reads rows, never raw material."""
    spec = _spec(table)
    cols = tuple(columns) if columns else spec.columns
    unknown = sorted(set(cols) - set(spec.columns))
    if unknown:
        raise DbError(f"{table} has no column(s): {', '.join(unknown)}")
    clause, params = "", []
    if where:
        bad = sorted(set(where) - set(spec.columns))
        if bad:
            raise DbError(f"{table} has no column(s): {', '.join(bad)}")
        keys = sorted(where)
        clause = " WHERE " + " AND ".join(f"{k} = ?" for k in keys)
        params = [where[k] for k in keys]
    bounded = max(1, min(int(limit), MAX_ROWS))
    sql = f"SELECT {', '.join(cols)} FROM {table}{clause} LIMIT ?"
    return con.execute(sql, [*params, bounded]).fetchall()


@dataclass(frozen=True, slots=True)
class Status:
    groups: tuple[tuple[str, str, str], ...]
    findings_by_group_severity: tuple[tuple[str, str, int], ...]
    verdicts: tuple[tuple[str, int], ...]
    totals: dict[str, int]


def status(con: sqlite3.Connection) -> Status:
    """The counts the resume-note template used to carry as three SELECTs."""
    groups = tuple(
        (r[0], r[1] or "", r[2] or "")
        for r in con.execute(
            "SELECT id, name, status FROM cba_feature_groups ORDER BY id"))
    by_gs = tuple(
        (r[0], r[1], r[2])
        for r in con.execute(
            "SELECT group_id, severity, COUNT(*) FROM cba_findings "
            "GROUP BY 1, 2 ORDER BY 1, 2"))
    verdicts = tuple(
        (r[0], r[1])
        for r in con.execute(
            "SELECT verdict, COUNT(*) FROM cba_fp_verdicts "
            "GROUP BY verdict ORDER BY verdict"))
    findings = con.execute("SELECT COUNT(*) FROM cba_findings").fetchone()[0]
    verdict_rows = con.execute("SELECT COUNT(*) FROM cba_fp_verdicts").fetchone()[0]
    return Status(
        groups=groups,
        findings_by_group_severity=by_gs,
        verdicts=verdicts,
        totals={"groups": len(groups), "findings": findings,
                "verdicts": verdict_rows,
                "unverdicted": max(0, findings - verdict_rows)},
    )


def render_status(s: Status) -> str:
    out: list[str] = []
    t = s.totals
    out.append(f"groups {t['groups']}   findings {t['findings']}   "
               f"verdicts {t['verdicts']}   unverdicted {t['unverdicted']}")
    if s.groups:
        out.append("  groups:")
        out.extend(f"    {gid:6s} {name:30.30s} {state}" for gid, name, state in s.groups)
    if s.findings_by_group_severity:
        out.append("  findings by group and severity:")
        out.extend(f"    {gid:6s} {sev:14s} {n}" for gid, sev, n in s.findings_by_group_severity)
    if s.verdicts:
        out.append("  verdicts:")
        out.extend(f"    {v:20s} {n}" for v, n in s.verdicts)
    return "\n".join(out)


@dataclass(frozen=True, slots=True)
class DuplicatePair:
    keep: str
    drop: str
    key: str
    shared_locations: tuple[str, ...]


def duplicates(con: sqlite3.Connection) -> list[DuplicatePair]:
    """Cross-group findings describing the same defect.

    phase4-deep-audit.md asked the orchestrator to do this by eye: "if two
    findings from different groups describe the same vulnerability at the same
    code location, keep the one with higher confidence". Across 45 findings
    that is 990 comparisons.

    Two findings pair when their normalized root causes are equal AND their
    location tokens intersect. This proposes; it never merges and never
    deletes. The orchestrator writes the DUPLICATE verdict.
    """
    found = con.execute(
        "SELECT id, group_id, confidence, location, root_cause "
        "FROM cba_findings ORDER BY id").fetchall()
    out: list[DuplicatePair] = []
    for i, a in enumerate(found):
        key = text.root_cause_key(a["root_cause"])
        if not key:
            continue
        a_tokens = text.location_tokens(a["location"])
        for b in found[i + 1:]:
            if a["group_id"] == b["group_id"]:
                continue
            if key != text.root_cause_key(b["root_cause"]):
                continue
            shared = a_tokens & text.location_tokens(b["location"])
            if not shared:
                continue
            hi, lo = ((a, b) if _conf(a) >= _conf(b) else (b, a))
            out.append(DuplicatePair(hi["id"], lo["id"], key, tuple(sorted(shared))))
    return out


def _conf(row: sqlite3.Row) -> int:
    try:
        return int(row["confidence"])
    except (TypeError, ValueError):
        return 0
