"""Canonical Stage 4j Markdown: exact bytes, escaping, citations and index."""
import copy
import json

import pytest

from audit_core import firmware_decide as decide
from audit_core import firmware_report as report
from audit_core import firmware_report_results as results
from tests.test_firmware_report_results import (
    BLOCKER_REF, CHAIN_ID, FINDING_REF, GENERATION, SURFACE_REF, canonical,
    cited, seed)


SECOND_CHAIN = "chain:" + "f" * 64
IMAGE_SHA = "a" * 64
PACKAGE_SHA = "c" * 64
DECISION_GENERATION = "b" * 64
METADATA = [
    "Firmware assessment report",
    f"Image: `v m 1.0` (`{IMAGE_SHA}`)",
    "Decision: `acquire` (`eligible-chain`)",
    "Assessment basis: source-level; not runtime-verified.",
]


class Package:
    """Exactly the verified package projection the renderer may read."""

    image_id = "target"
    decision = "acquire"
    primary_reason = "eligible-chain"
    decision_generation = DECISION_GENERATION
    package_sha256 = PACKAGE_SHA
    image = decide.VerifiedFirmwareImageIdentity(
        "target", "v", "m", "1.0", "target", IMAGE_SHA)


def answer(**overrides):
    """One accepted worker answer, written for the shared assignment catalog."""
    value = {
        "title_detail": "Unauthenticated command injection in usr/sbin/service",
        "summary": [cited("The request handler in usr/sbin/service passes attacker "
                          "text to a shell interpreter without quoting.")],
        "root_cause": [cited("handle_request in usr/sbin/service builds the shell "
                             "argument by concatenating request text.")],
        "reproduction_steps": [cited("Read handle_request in usr/sbin/service and "
                                     "follow the request text into the shell call.")],
        "impact": [cited("A caller reaching usr/sbin/service gains shell execution "
                         "with the privileges of that service process.")],
        "severity": "high",
        "severity_justification": cited(
            "The injection in usr/sbin/service is reachable from the network surface "
            "and yields direct shell execution."),
        "fix_direction": None,
    }
    value.update(overrides)
    return value


def envelope(seed_value, ordinal):
    chain_id = seed_value["chain"]["chain_id"]
    return canonical({
        "assignment_sha256": report._digest(canonical(seed_value)),
        "report_generation": GENERATION,
        "result_path": (f"files/firmware-report-results/{GENERATION}/"
                        f"{ordinal}-{chain_id}.json"),
        "seed": seed_value,
    })


def validated(seed_value, answer_value, ordinal=1):
    """One assignment byte string with the validated result that answers it."""
    raw = envelope(seed_value, ordinal)
    parsed = results._parse(canonical({
        "schema_version": 1,
        "image_id": "target",
        "report_generation": GENERATION,
        "chain_id": seed_value["chain"]["chain_id"],
        "assignment_sha256": json.loads(raw)["assignment_sha256"],
        "answer": answer_value,
    }))
    return raw, results.validate(parsed, raw)


def built(*cases):
    """Assignments plus results for one ordered list of (seed, answer) cases."""
    items, contents, values = [], {}, {}
    for ordinal, (seed_value, answer_value) in enumerate(cases, 1):
        chain_id = seed_value["chain"]["chain_id"]
        raw, value = validated(seed_value, answer_value, ordinal)
        contents[f"items/{ordinal}-{chain_id}.json"] = raw
        items.append({
            "ordinal": ordinal,
            "chain_id": chain_id,
            "assignment_path": (f"files/firmware-report/{GENERATION}/items/"
                                f"{ordinal}-{chain_id}.json"),
            "assignment_sha256": json.loads(raw)["assignment_sha256"],
            "result_path": (f"files/firmware-report-results/{GENERATION}/"
                            f"{ordinal}-{chain_id}.json"),
        })
        values[chain_id] = value
    contents["manifest.json"] = canonical({"items": items})
    assignments = report._Assignments(
        GENERATION, "d" * 64, tuple(items), contents, None, {})
    return assignments, values


def render(*cases):
    assignments, values = built(*cases)
    return report._render(Package, assignments, values)


def document(*cases):
    return render(*cases)[0].decode().split("\n")


def second_seed(rank=2, **chain_overrides):
    chain = {"chain_id": SECOND_CHAIN, "rank": rank, "pre_auth": "yes"}
    chain.update(chain_overrides)
    value = seed(ordinal=rank, open_preconditions=[])
    value["chain"] = {**value["chain"], **chain}
    return value


def test_render_writes_exact_canonical_markdown_for_one_chain():
    raw, _, _ = render((seed(), answer()))

    assert raw.decode().split("\n") == METADATA + [
        "",
        f"# `{CHAIN_ID}`: Unauthenticated command injection in usr/sbin/service",
        "",
        "## Affected Version",
        "- Image: `v m 1.0`",
        f"- Image SHA-256: `{IMAGE_SHA}`",
        "- Chain members: `F-1`",
        "",
        "## Summary",
        "The request handler in usr/sbin/service passes attacker text to a shell "
        "interpreter without quoting. "
        f"(`usr/sbin/service:handle_request` [`{FINDING_REF}`])",
        "",
        "## Root Cause",
        "handle\\_request in usr/sbin/service builds the shell argument by "
        "concatenating request text. "
        f"(`usr/sbin/service:handle_request` [`{FINDING_REF}`])",
        "",
        "## Steps to reproduce",
        "Source-level verification guide; no runtime execution is claimed.",
        "",
        "1. Read handle\\_request in usr/sbin/service and follow the request text "
        f"into the shell call. (`usr/sbin/service:handle_request` [`{FINDING_REF}`])",
        "",
        "## Impact",
        "A caller reaching usr/sbin/service gains shell execution with the "
        "privileges of that service process. "
        f"(`usr/sbin/service:handle_request` [`{FINDING_REF}`])",
        "",
        "Pre-authentication path: not established: blocked by `blocker:B-1`.",
        "Severity: HIGH. The injection in usr/sbin/service is reachable from the "
        "network surface and yields direct shell execution. "
        f"(`usr/sbin/service:handle_request` [`{FINDING_REF}`])",
        "Provisional: unresolved preconditions `blocker:B-1`.",
        "",
    ]
    assert raw.endswith(b"\n") and b"\r" not in raw


def test_render_writes_exact_bytes_for_a_zero_chain_report():
    assignments = report._Assignments(GENERATION, "d" * 64, (), {}, None, {})

    raw, index_raw, sections = report._render(Package, assignments, {})

    assert sections == ()
    assert raw == ("\n".join(METADATA) + "\n\nNo technical chain is present in the "
                   "current completed decision package.\n").encode()
    assert json.loads(index_raw)["sections"] == []


def test_render_repeats_one_h1_and_five_h2_per_chain_in_ascending_rank():
    lines = document((seed(), answer()),
                     (second_seed(), answer(severity="medium")))

    headings = [line for line in lines if line.startswith("#")]
    assert headings == [
        f"# `{CHAIN_ID}`: Unauthenticated command injection in usr/sbin/service",
        "## Affected Version", "## Summary", "## Root Cause",
        "## Steps to reproduce", "## Impact",
        f"# `{SECOND_CHAIN}`: Unauthenticated command injection in usr/sbin/service",
        "## Affected Version", "## Summary", "## Root Cause",
        "## Steps to reproduce", "## Impact",
    ]
    assert lines[:4] == METADATA
    assert not any(line.startswith("###") for line in lines)
    assert not any("CVSS" in line for line in lines)
    assert lines.index(f"# `{CHAIN_ID}`: Unauthenticated command injection in "
                       "usr/sbin/service") < lines.index(
        f"# `{SECOND_CHAIN}`: Unauthenticated command injection in usr/sbin/service")


def test_render_refuses_assignments_that_are_not_in_ascending_ordinal_order():
    assignments, values = built((seed(), answer()),
                                (second_seed(), answer(severity="medium")))
    reordered = report._Assignments(
        assignments.generation, assignments.manifest_sha256,
        tuple(reversed(assignments.items)), assignments.contents, None, {})

    with pytest.raises(report.FirmwareReportError, match="ascending"):
        report._render(Package, reordered, values)


def test_render_refuses_a_rank_that_differs_from_its_ordinal():
    value = seed()
    value["chain"] = {**value["chain"], "rank": 3}

    with pytest.raises(report.FirmwareReportError, match="rank"):
        render((value, answer()))


def test_render_requires_exactly_one_result_for_every_assignment():
    assignments, values = built((seed(), answer()),
                                (second_seed(), answer(severity="medium")))
    with pytest.raises(report.FirmwareReportError, match="one result"):
        report._render(Package, assignments, {CHAIN_ID: values[CHAIN_ID]})

    foreign = dict(values)
    foreign.pop(SECOND_CHAIN)
    foreign["chain:" + "0" * 64] = values[CHAIN_ID]
    with pytest.raises(report.FirmwareReportError, match="result"):
        report._render(Package, assignments, foreign)


def test_render_uses_the_three_contract_citation_displays():
    value = answer(summary=[cited(
        "The request handler in usr/sbin/service reaches the shell call from the "
        "listening surface before any credential check.",
        [BLOCKER_REF, FINDING_REF, SURFACE_REF])])

    lines = document((seed(), value))

    assert lines[lines.index("## Summary") + 1].endswith(
        f"(evidence `{BLOCKER_REF}`; "
        f"`usr/sbin/service:handle_request` [`{FINDING_REF}`]; "
        f"`usr/sbin/service:main` [`{SURFACE_REF}`])")


def test_render_never_displays_internal_or_absolute_catalog_paths():
    value = seed()
    entries = copy.deepcopy(value["evidence_catalog"])
    for entry in entries:
        if entry["ref"] == FINDING_REF:
            entry["location"] = "/root/build/service.c:88"
        if entry["ref"] == SURFACE_REF:
            entry["component_path"] = (
                f"files/firmware-report/{GENERATION}/items/1-{CHAIN_ID}.json")
    value["evidence_catalog"] = entries
    answer_value = answer(summary=[cited(
        "The request handler in usr/sbin/service reaches the shell call from the "
        "listening surface before any credential check.",
        [FINDING_REF, SURFACE_REF])])

    lines = document((value, answer_value))
    body = "\n".join(lines)

    assert lines[lines.index("## Summary") + 1].endswith(
        f"(`usr/sbin/service` [`{FINDING_REF}`]; evidence `{SURFACE_REF}`)")
    assert "files/firmware-report" not in body
    assert "artifacts/firmware-" not in body
    assert "/root/build/service.c:88" not in body


def test_render_escapes_displayed_worker_text_and_catalog_locations():
    value = seed()
    entries = copy.deepcopy(value["evidence_catalog"])
    for entry in entries:
        if entry["ref"] == FINDING_REF:
            entry["location"] = "surface.handler`rm -rf`"
    value["evidence_catalog"] = entries
    answer_value = answer(
        title_detail="Injection in <usr/sbin/service> [*sink*]",
        impact=[cited("A caller reaching usr/sbin/service gains shell execution "
                      "via # | _ * [ ] ` & < > characters.")],
        root_cause=[cited("- usr/sbin/service concatenates request text into the "
                          "shell argument of the request handler.")],
        reproduction_steps=[cited("1. usr/sbin/service receives the request text "
                                  "that reaches the shell argument.")])

    lines = document((value, answer_value))

    assert lines[1 + lines.index("")] == (
        f"# `{CHAIN_ID}`: Injection in \\<usr/sbin/service\\> \\[\\*sink\\*\\]")
    assert lines[lines.index("## Root Cause") + 1].startswith(
        "\\- usr/sbin/service concatenates")
    assert lines[lines.index("## Steps to reproduce") + 3].startswith(
        "1. 1\\. usr/sbin/service receives")
    assert lines[lines.index("## Impact") + 1].startswith(
        "A caller reaching usr/sbin/service gains shell execution via \\# \\| \\_ "
        "\\* \\[ \\] \\` \\& \\< \\> characters.")
    assert lines[lines.index("## Impact") + 1].endswith(
        f"(usr/sbin/service:surface.handler\\`rm -rf\\` [`{FINDING_REF}`])")


def test_render_maps_pre_authentication_exactly_and_labels_provisional_chains():
    established = document((second_seed(rank=1), answer()))
    assert "Pre-authentication path: established." in established
    assert not any(line.startswith("Provisional:") for line in established)

    refused = document((second_seed(rank=1, pre_auth="no"), answer()))
    assert "Pre-authentication path: not established." in refused

    blocked = seed()
    blocked["open_preconditions"] = [
        blocked["open_preconditions"][0],
        {**blocked["open_preconditions"][0], "precondition_id": "blocker:A-9",
         "source_id": "A-9"}]
    lines = document((blocked, answer()))
    assert "Pre-authentication path: not established: blocked by `blocker:A-9`, " \
           "`blocker:B-1`." in lines
    assert "Provisional: unresolved preconditions `blocker:A-9`, `blocker:B-1`." in lines


def test_render_refuses_unknown_pre_authentication_without_a_precondition():
    value = second_seed(rank=1, pre_auth="unknown")

    with pytest.raises(report.FirmwareReportError, match="pre-authentication"):
        render((value, answer()))


def test_render_states_severity_and_optional_fix_direction_last():
    fix = cited("Quote the request text before it reaches the shell call in "
                "usr/sbin/service.")
    lines = document((second_seed(rank=1), answer(severity="informational",
                                                  fix_direction=fix)))

    assert lines[-3] == (
        "Severity: INFORMATIONAL. The injection in usr/sbin/service is reachable "
        "from the network surface and yields direct shell execution. "
        f"(`usr/sbin/service:handle_request` [`{FINDING_REF}`])")
    assert lines[-2] == (
        "Fix direction: Quote the request text before it reaches the shell call in "
        f"usr/sbin/service. (`usr/sbin/service:handle_request` [`{FINDING_REF}`])")
    assert lines[-1] == ""


def test_render_writes_multiple_paragraphs_and_steps_in_order():
    value = answer(
        summary=[cited("The request handler in usr/sbin/service passes attacker "
                       "text to a shell interpreter without quoting."),
                 cited("Reaching that handler requires one request to the listening "
                       "surface of usr/sbin/service.")],
        reproduction_steps=[
            cited("Read handle_request in usr/sbin/service and follow the request "
                  "text into the shell call."),
            cited("Trace the shell argument of usr/sbin/service back to the "
                  "request field that supplies it.")])

    lines = document((seed(), value))

    start = lines.index("## Summary")
    assert lines[start + 2] == ""
    assert lines[start + 3].startswith("Reaching that handler requires")
    steps = lines.index("## Steps to reproduce")
    assert lines[steps + 3].startswith("1. Read handle\\_request")
    assert lines[steps + 4].startswith("2. Trace the shell argument")


def test_render_builds_the_exact_canonical_report_index():
    raw, index_raw, sections = render(
        (seed(), answer()),
        (second_seed(), answer(severity="medium",
                               summary=[cited("The request handler in usr/sbin/service "
                                              "passes attacker text onward.",
                                              [FINDING_REF, SURFACE_REF])])))

    assert json.loads(index_raw) == {
        "schema_version": 1,
        "image_id": "target",
        "report_generation": GENERATION,
        "decision_generation": DECISION_GENERATION,
        "decision_package_sha256": PACKAGE_SHA,
        "report_sha256": report._digest(raw),
        "sections": [
            {"ordinal": 1, "chain_id": CHAIN_ID, "severity": "high",
             "pre_auth": "unknown", "citation_refs": [FINDING_REF]},
            {"ordinal": 2, "chain_id": SECOND_CHAIN, "severity": "medium",
             "pre_auth": "yes", "citation_refs": [FINDING_REF, SURFACE_REF]},
        ],
    }
    assert index_raw == canonical(json.loads(index_raw))
    assert sections == (
        report.VerifiedFirmwareReportSection(1, CHAIN_ID, "high", "unknown",
                                             (FINDING_REF,)),
        report.VerifiedFirmwareReportSection(2, SECOND_CHAIN, "medium", "yes",
                                             (FINDING_REF, SURFACE_REF)),
    )


def test_render_refuses_an_index_beyond_its_byte_cap(monkeypatch):
    monkeypatch.setattr(report, "MAX_REPORT_INDEX_BYTES", 64)

    with pytest.raises(report.FirmwareReportError, match="index"):
        render((seed(), answer()))


def test_render_refuses_a_citation_outside_the_assignment_catalog():
    value = seed()
    value["evidence_catalog"] = [entry for entry in value["evidence_catalog"]
                                 if entry["ref"] != FINDING_REF]
    assignments, values = built((seed(), answer()))
    raw = envelope(value, 1)
    assignments.contents["items/1-" + CHAIN_ID + ".json"] = raw

    with pytest.raises(report.FirmwareReportError, match="catalog"):
        report._render(Package, assignments, values)
