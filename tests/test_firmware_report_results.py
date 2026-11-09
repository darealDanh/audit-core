"""Strict Stage 4j worker report results: exact schema, bounds and hostile input."""
import json
import os
import pathlib

import pytest

from audit_core import db
from audit_core import firmware_report as report
from audit_core import firmware_report_results as results


CHAIN_ID = "chain:" + "e" * 64
GENERATION = "f" * 64
FINDING_REF = "finding:F-1#root_cause"
SURFACE_REF = "surface:S-1#reach_evidence"
BLOCKER_REF = "blocker:B-1#question"


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def catalog():
    return [
        {"ref": BLOCKER_REF, "kind": "precondition", "owner_id": "B-1",
         "component_path": None, "location": None, "field": "question",
         "evidence_rung": "unresolved", "excerpt": "retained question"},
        {"ref": FINDING_REF, "kind": "finding", "owner_id": "F-1",
         "component_path": "usr/sbin/service", "location": "handle_request",
         "field": "root_cause", "evidence_rung": "static-chained",
         "excerpt": "retained root cause"},
        {"ref": SURFACE_REF, "kind": "edge", "owner_id": "S-1",
         "component_path": "usr/sbin/service", "location": "main",
         "field": "reach_evidence", "evidence_rung": "static-chained",
         "excerpt": "retained reach evidence"},
    ]


def seed(**overrides):
    """One assignment seed shaped exactly as Stage 4j preparation writes it."""
    value = {
        "schema_version": 1,
        "image": {"image_id": "target", "vendor": "vendor", "model": "model",
                  "version": "1.0", "role": "target", "sha256": "a" * 64},
        "decision": {"generation": "b" * 64, "package_sha256": "c" * 64,
                     "decision": "acquire", "primary_reason": "reason"},
        "ordinal": 1,
        "chain": {
            "chain_id": CHAIN_ID, "rank": 1, "title": "title", "summary": "summary",
            "member_ids": ["F-1"], "pre_auth": "unknown", "confidence": 5,
            "completeness": "blocked", "evidence_rung": "static-chained",
            "disposition": "retain", "rationale": "rationale", "limitations": [],
        },
        "members": [{"finding_id": "F-1"}],
        "edges": [{"ordinal": 1,
                   "required_state": {"authentication": "unauthenticated"}}],
        "open_preconditions": [{
            "kind": "blocker", "precondition_id": "blocker:B-1", "source_id": "B-1",
            "question": "question", "settling_observation": "observation",
            "method": "static", "axes": [], "locations": []}],
        "evidence_catalog": catalog(),
        "style_contract_sha256": report._style_contract_sha256(),
    }
    value.update(overrides)
    return value


def envelope_for(seed_value, **overrides):
    value = {
        "assignment_sha256": report._digest(canonical(seed_value)),
        "report_generation": GENERATION,
        "result_path": f"files/firmware-report-results/{GENERATION}/1-{CHAIN_ID}.json",
        "seed": seed_value,
    }
    value.update(overrides)
    return canonical(value), value


def assignment(**seed_overrides):
    return envelope_for(seed(**seed_overrides))


def cited(text, refs=(FINDING_REF,)):
    return {"text": text, "citation_refs": list(refs)}


def answer(**overrides):
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


def result(**overrides):
    value = {
        "schema_version": 1,
        "image_id": "target",
        "report_generation": GENERATION,
        "chain_id": CHAIN_ID,
        "assignment_sha256": assignment()[1]["assignment_sha256"],
        "answer": answer(),
    }
    value.update(overrides)
    return value


def save(tmp_path, value, name="result.json"):
    path = tmp_path / name
    path.write_bytes(value if isinstance(value, bytes) else canonical(value))
    return path


def test_load_parses_one_exact_worker_result(tmp_path):
    parsed = results.load(save(tmp_path, result()))

    assert isinstance(parsed, results.ReportResult)
    assert parsed.schema_version == 1
    assert parsed.image_id == "target"
    assert parsed.chain_id == CHAIN_ID
    assert parsed.report_generation == GENERATION
    assert parsed.assignment_sha256 == assignment()[1]["assignment_sha256"]
    assert isinstance(parsed.answer, results.ReportAnswer)
    assert isinstance(parsed.answer.summary[0], results.CitedText)
    assert parsed.answer.summary[0].citation_refs == (FINDING_REF,)
    assert parsed.answer.severity == "high"
    assert parsed.answer.fix_direction is None


def test_load_accepts_optional_fix_direction(tmp_path):
    value = result(answer=answer(fix_direction=cited(
        "Quote the request text before it reaches the shell call in usr/sbin/service.")))

    parsed = results.load(save(tmp_path, value))

    assert parsed.answer.fix_direction.text.startswith("Quote the request text")
    assert parsed.answer.fix_direction.citation_refs == (FINDING_REF,)


def test_load_refuses_duplicate_unknown_and_missing_keys(tmp_path):
    raw = canonical(result()).replace(b'"image_id":"target"',
                                      b'"image_id":"target","image_id":"other"', 1)
    with pytest.raises(results.FirmwareReportResultError, match="duplicate key"):
        results.load(save(tmp_path, raw, "duplicate.json"))

    extra = result()
    extra["extra"] = 1
    with pytest.raises(results.FirmwareReportResultError, match="report result keys"):
        results.load(save(tmp_path, extra, "extra.json"))

    missing = result()
    del missing["chain_id"]
    with pytest.raises(results.FirmwareReportResultError, match="report result keys"):
        results.load(save(tmp_path, missing, "missing.json"))

    unknown_answer = result(answer={**answer(), "provisional": "x"})
    with pytest.raises(results.FirmwareReportResultError, match="answer keys"):
        results.load(save(tmp_path, unknown_answer, "answer.json"))

    unknown_entry = result(answer=answer(
        summary=[{**cited("A caller reaches usr/sbin/service directly."), "note": 1}]))
    with pytest.raises(results.FirmwareReportResultError, match="summary keys"):
        results.load(save(tmp_path, unknown_entry, "entry.json"))


def test_load_refuses_invalid_utf8_lone_surrogates_and_non_json(tmp_path):
    with pytest.raises(results.FirmwareReportResultError, match="strict UTF-8 JSON"):
        results.load(save(tmp_path, b'{"image_id":"\xff\xfe"}', "invalid.json"))
    with pytest.raises(results.FirmwareReportResultError, match="strict UTF-8 JSON"):
        results.load(save(tmp_path, b"not json", "text.json"))
    with pytest.raises(results.FirmwareReportResultError, match="non-finite"):
        results.load(save(tmp_path, b'{"schema_version":NaN}\n', "nan.json"))
    with pytest.raises(results.FirmwareReportResultError, match="report result keys"):
        results.load(save(tmp_path, b"[]\n", "array.json"))

    surrogate = canonical(result()).replace(
        b'"title_detail":"', b'"title_detail":"\\ud800', 1)
    with pytest.raises(results.FirmwareReportResultError, match="title_detail"):
        results.load(save(tmp_path, surrogate, "surrogate.json"))

    identity = canonical(result()).replace(
        b'"image_id":"target"', b'"image_id":"\\ud800target"', 1)
    with pytest.raises(results.FirmwareReportResultError, match="image_id"):
        results.load(save(tmp_path, identity, "identity-surrogate.json"))


def test_load_refuses_symlink_fifo_and_nonregular_inputs(tmp_path):
    target = save(tmp_path, result())
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(results.FirmwareReportResultError, match="cannot read report result"):
        results.load(link)

    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    with pytest.raises(results.FirmwareReportResultError, match="cannot read report result"):
        results.load(fifo)

    with pytest.raises(results.FirmwareReportResultError, match="cannot read report result"):
        results.load(tmp_path)

    with pytest.raises(results.FirmwareReportResultError, match="cannot read report result"):
        results.load(tmp_path / "absent.json")


def test_load_refuses_results_beyond_the_sixteen_kib_cap(tmp_path):
    path = tmp_path / "big.json"
    path.write_bytes(b'{"schema_version":1,"pad":"' + b"a" * results.MAX_RESULT_BYTES + b'"}\n')
    with pytest.raises(results.FirmwareReportResultError, match="exceeds 16 KiB"):
        results.load(path)


@pytest.mark.parametrize("value", [True, 1.0, "1", None, 2, 10 ** 400])
def test_schema_version_requires_exactly_one_without_coercion(tmp_path, value):
    raw = canonical(result()).replace(
        b'"schema_version":1',
        b'"schema_version":' + json.dumps(value).encode(), 1)
    with pytest.raises(results.FirmwareReportResultError, match="schema_version"):
        results.load(save(tmp_path, raw, "schema.json"))


@pytest.mark.parametrize("field,value,message", [
    ("image_id", "", "image_id"),
    ("image_id", 1, "image_id"),
    ("image_id", "a" * 5000, "image_id"),
    ("image_id", "a\0b", "image_id"),
    ("report_generation", "F" * 64, "report_generation"),
    ("report_generation", "ab", "report_generation"),
    ("report_generation", 7, "report_generation"),
    ("chain_id", "", "chain_id"),
    ("chain_id", "../escape", "chain_id"),
    ("chain_id", 5, "chain_id"),
    ("assignment_sha256", "g" * 64, "assignment_sha256"),
])
def test_identity_fields_require_exact_shapes(tmp_path, field, value, message):
    with pytest.raises(results.FirmwareReportResultError, match=message):
        results.load(save(tmp_path, result(**{field: value}), "identity.json"))


@pytest.mark.parametrize("severity", list(db.FIRMWARE_REPORT_SEVERITIES))
def test_every_contract_severity_is_accepted(tmp_path, severity):
    parsed = results.load(save(tmp_path, result(answer=answer(severity=severity))))
    assert parsed.answer.severity == severity


@pytest.mark.parametrize("severity", ["HIGH", "urgent", "", None, 1])
def test_severity_outside_the_enum_is_refused(tmp_path, severity):
    with pytest.raises(results.FirmwareReportResultError, match="severity"):
        results.load(save(tmp_path, result(answer=answer(severity=severity)), "sev.json"))


@pytest.mark.parametrize("field,count", [
    ("summary", 0), ("summary", 3), ("root_cause", 0), ("root_cause", 5),
    ("reproduction_steps", 0), ("reproduction_steps", 9), ("impact", 0), ("impact", 3),
])
def test_entry_counts_match_the_style_contract(tmp_path, field, count):
    entries = [cited(f"The handler in usr/sbin/service reaches shell call {index}.")
               for index in range(count)]
    with pytest.raises(results.FirmwareReportResultError, match=field):
        results.load(save(tmp_path, result(answer=answer(**{field: entries})), "count.json"))


@pytest.mark.parametrize("field,count", [
    ("summary", 2), ("root_cause", 4), ("reproduction_steps", 8), ("impact", 2)])
def test_entry_counts_accept_their_upper_bound(tmp_path, field, count):
    entries = [cited(f"The handler in usr/sbin/service reaches shell call {index}.")
               for index in range(count)]
    parsed = results.load(save(tmp_path, result(answer=answer(**{field: entries})), "ok.json"))
    assert len(getattr(parsed.answer, field)) == count


@pytest.mark.parametrize("text", ["a" * 11, "a" * 161, 7])
def test_title_detail_bounds_are_exact(tmp_path, text):
    with pytest.raises(results.FirmwareReportResultError, match="title_detail"):
        results.load(save(tmp_path, result(answer=answer(title_detail=text)), "title.json"))


def test_title_detail_accepts_both_byte_bounds(tmp_path):
    for text in ("b" * 12, "c" * 160):
        parsed = results.load(save(tmp_path, result(answer=answer(title_detail=text)), "t.json"))
        assert parsed.answer.title_detail == text


@pytest.mark.parametrize("text", ["a" * 19, "a" * 1201, 42, None])
def test_paragraph_text_bounds_are_exact(tmp_path, text):
    with pytest.raises(results.FirmwareReportResultError, match="summary"):
        results.load(save(tmp_path, result(answer=answer(summary=[cited(text)])), "text.json"))


def test_paragraph_text_accepts_both_byte_bounds(tmp_path):
    for text in ("d" * 20, "e" * 1200):
        parsed = results.load(save(
            tmp_path, result(answer=answer(summary=[cited(text)])), "p.json"))
        assert parsed.answer.summary[0].text == text


@pytest.mark.parametrize("text", ["f" * 39, "g" * 401])
def test_severity_justification_bounds_are_exact(tmp_path, text):
    with pytest.raises(results.FirmwareReportResultError, match="severity_justification"):
        results.load(save(tmp_path, result(
            answer=answer(severity_justification=cited(text))), "just.json"))


def test_severity_justification_accepts_both_byte_bounds(tmp_path):
    for text in ("h" * 40, "i" * 400):
        parsed = results.load(save(tmp_path, result(
            answer=answer(severity_justification=cited(text))), "j.json"))
        assert parsed.answer.severity_justification.text == text


@pytest.mark.parametrize("value", ["k" * 19, "l" * 401, 1, [], {"text": "m" * 30}])
def test_fix_direction_bounds_and_shape_are_exact(tmp_path, value):
    body = cited(value) if isinstance(value, str) else value
    with pytest.raises(results.FirmwareReportResultError, match="fix_direction"):
        results.load(save(tmp_path, result(answer=answer(fix_direction=body)), "fix.json"))


def test_fix_direction_accepts_both_byte_bounds(tmp_path):
    for text in ("n" * 20, "o" * 400):
        parsed = results.load(save(tmp_path, result(
            answer=answer(fix_direction=cited(text))), "f.json"))
        assert parsed.answer.fix_direction.text == text


@pytest.mark.parametrize("refs,message", [
    ([], "citations"),
    ([SURFACE_REF, FINDING_REF], "sorted unique"),
    ([FINDING_REF, FINDING_REF], "sorted unique"),
    ([f"finding:F-1#field{index:02d}" for index in range(17)], "citations"),
    ([1], "references"),
    ([""], "references"),
    (["a" * 5000], "references"),
    (["a\0b"], "references"),
    ("not-a-list", "citations"),
])
def test_citation_arrays_are_bounded_sorted_and_unique(tmp_path, refs, message):
    value = result(answer=answer(summary=[{
        "text": "The handler in usr/sbin/service reaches the shell call.",
        "citation_refs": refs}]))
    with pytest.raises(results.FirmwareReportResultError, match=message):
        results.load(save(tmp_path, value, "refs.json"))


def test_sixteen_citations_are_accepted(tmp_path):
    refs = sorted(f"finding:F-1#field{index:02d}" for index in range(16))
    value = result(answer=answer(summary=[{
        "text": "The handler in usr/sbin/service reaches the shell call.",
        "citation_refs": refs}]))
    parsed = results.load(save(tmp_path, value, "sixteen.json"))
    assert len(parsed.answer.summary[0].citation_refs) == 16


@pytest.mark.parametrize("text", [
    "The handler in usr/sbin/service\nreaches the shell call.",
    "The handler in usr/sbin/service\rreaches the shell call.",
    "The handler in usr/sbin/service\treaches the shell call.",
    "The handler in usr/sbin/service\x00reaches the shell call.",
    "The handler in usr/sbin/service\x7freaches the shell call.",
    "The handler in usr/sbin/service\u00a0reaches the shell call.",
    "The handler in usr/sbin/service\u2028reaches the shell call.",
])
def test_control_characters_and_non_ascii_whitespace_are_refused(tmp_path, text):
    with pytest.raises(results.FirmwareReportResultError, match="summary"):
        results.load(save(tmp_path, result(answer=answer(summary=[cited(text)])), "ctl.json"))


def test_text_is_normalized_to_nfc_before_bounds_are_measured(tmp_path):
    decomposed = "Service e\u0301tat in usr/sbin/service reaches the shell call."

    parsed = results.load(save(tmp_path, result(
        answer=answer(summary=[cited(decomposed)])), "nfc.json"))

    assert parsed.answer.summary[0].text == (
        "Service \u00e9tat in usr/sbin/service reaches the shell call.")


@pytest.mark.parametrize("field", ["summary", "root_cause", "reproduction_steps", "impact"])
def test_entry_arrays_require_lists_of_objects(tmp_path, field):
    with pytest.raises(results.FirmwareReportResultError, match=field):
        results.load(save(tmp_path, result(answer=answer(**{field: {"text": "x"}})), "arr.json"))
    with pytest.raises(results.FirmwareReportResultError, match=field):
        results.load(save(tmp_path, result(answer=answer(**{field: ["text"]})), "arr2.json"))


def test_answer_and_justification_require_objects(tmp_path):
    with pytest.raises(results.FirmwareReportResultError, match="answer keys"):
        results.load(save(tmp_path, result(answer=[]), "answer.json"))
    with pytest.raises(results.FirmwareReportResultError, match="severity_justification keys"):
        results.load(save(tmp_path, result(answer=answer(severity_justification=None)), "sj.json"))


def test_canonical_bytes_round_trip_the_loaded_file(tmp_path):
    raw = canonical(result())
    path = save(tmp_path, raw, "canonical.json")
    assignment_bytes, _ = assignment()

    validated = results.validate(results.load(path), assignment_bytes)

    assert results._canonical(validated) == raw
    assert results._canonical(validated) == results._canonical(
        results.validate(results.load(path), assignment_bytes))


def test_canonical_bytes_refuse_results_beyond_the_result_cap():
    _, envelope = assignment()
    text = results.CitedText(
        "The handler in usr/sbin/service reaches the shell call.",
        tuple(sorted(f"finding:F-1#{'p' * 4000}{index}" for index in range(16))))
    validated = results.ValidatedReportResult(
        image_id="target", report_generation=envelope["report_generation"],
        chain_id=CHAIN_ID, ordinal=1, assignment_sha256=envelope["assignment_sha256"],
        result_path=envelope["result_path"], pre_auth="unknown",
        open_precondition_ids=("blocker:B-1",), severity="high",
        citation_refs=text.citation_refs,
        answer=results.ReportAnswer(
            title_detail="Unauthenticated command injection in usr/sbin/service",
            summary=(text,), root_cause=(text,), reproduction_steps=(text,),
            impact=(text,), severity="high", severity_justification=text,
            fix_direction=text))

    with pytest.raises(results.FirmwareReportResultError, match="exceeds 16 KiB"):
        results._canonical(validated)


def test_validate_binds_identity_ordinal_and_open_preconditions():
    assignment_bytes, envelope = assignment()

    validated = results.validate(results._parse(canonical(result())), assignment_bytes)

    assert isinstance(validated, results.ValidatedReportResult)
    assert validated.image_id == "target"
    assert validated.chain_id == CHAIN_ID
    assert validated.ordinal == 1
    assert validated.report_generation == envelope["report_generation"]
    assert validated.assignment_sha256 == envelope["assignment_sha256"]
    assert validated.result_path == envelope["result_path"]
    assert validated.pre_auth == "unknown"
    assert validated.open_precondition_ids == ("blocker:B-1",)
    assert validated.severity == "high"
    assert validated.citation_refs == (FINDING_REF,)


@pytest.mark.parametrize("field,value", [
    ("image_id", "other"),
    ("report_generation", "0" * 64),
    ("chain_id", "chain:" + "d" * 64),
    ("assignment_sha256", "1" * 64),
])
def test_validate_refuses_a_result_from_another_assignment(field, value):
    assignment_bytes, _ = assignment()
    parsed = results._parse(canonical(result(**{field: value})))
    with pytest.raises(results.FirmwareReportResultError, match=field):
        results.validate(parsed, assignment_bytes)


def test_validate_requires_canonical_bounded_assignment_bytes():
    assignment_bytes, envelope = assignment()
    parsed = results._parse(canonical(result()))

    with pytest.raises(results.FirmwareReportResultError, match="not canonical"):
        results.validate(parsed, assignment_bytes.replace(b"{", b" {", 1))
    with pytest.raises(results.FirmwareReportResultError, match="strict UTF-8 JSON"):
        results.validate(parsed, b"{")
    with pytest.raises(results.FirmwareReportResultError, match="byte cap"):
        results.validate(parsed, b"a" * (report.MAX_ASSIGNMENT_BYTES + 1))
    with pytest.raises(results.FirmwareReportResultError, match="byte cap"):
        results.validate(parsed, "not bytes")
    with pytest.raises(results.FirmwareReportResultError, match="assignment keys"):
        results.validate(parsed, canonical({**envelope, "extra": 1}))


@pytest.mark.parametrize("key,value,message", [
    ("report_generation", "zz", "assignment report_generation"),
    ("result_path", "/absolute/result.json", "assignment result_path"),
    ("result_path", "files/../result.json", "assignment result_path"),
    ("result_path", "", "assignment result_path"),
    ("result_path", 7, "assignment result_path"),
])
def test_validate_refuses_an_unsafe_assignment_envelope(key, value, message):
    _, envelope = assignment()
    parsed = results._parse(canonical(result()))
    with pytest.raises(results.FirmwareReportResultError, match=message):
        results.validate(parsed, canonical({**envelope, key: value}))


@pytest.mark.parametrize("value,message", [
    ("target", "assignment image keys"),
    ({"image_id": "target"}, "assignment image keys"),
    ({**seed()["image"], "image_id": ""}, "assignment image_id"),
])
def test_validate_refuses_an_invalid_seed_image(value, message):
    assignment_bytes, envelope = envelope_for(seed(image=value))
    parsed = results._parse(canonical(result(
        assignment_sha256=envelope["assignment_sha256"])))
    with pytest.raises(results.FirmwareReportResultError, match=message):
        results.validate(parsed, assignment_bytes)


def test_validate_refuses_a_seed_that_differs_from_its_digest():
    _, envelope = assignment()
    tampered = canonical({**envelope, "assignment_sha256": "2" * 64})
    parsed = results._parse(canonical(result(assignment_sha256="2" * 64)))
    with pytest.raises(results.FirmwareReportResultError, match="seed bytes"):
        results.validate(parsed, tampered)


def test_validate_refuses_a_seed_with_inexact_keys():
    broken = seed()
    del broken["members"]
    assignment_bytes, envelope = envelope_for(broken)
    parsed = results._parse(canonical(result(
        assignment_sha256=envelope["assignment_sha256"])))
    with pytest.raises(results.FirmwareReportResultError, match="assignment seed keys"):
        results.validate(parsed, assignment_bytes)


@pytest.mark.parametrize("key,value,message", [
    ("schema_version", 2, "assignment seed schema_version"),
    ("style_contract_sha256", "3" * 64, "style contract"),
    ("ordinal", 0, "ordinal"),
    ("ordinal", True, "ordinal"),
    ("chain", {"chain_id": CHAIN_ID}, "assignment chain keys"),
    ("chain", {**seed()["chain"], "pre_auth": "maybe"}, "pre_auth"),
    ("chain", {**seed()["chain"], "member_ids": [1]}, "member_id"),
    ("chain", {**seed()["chain"], "member_ids": {}}, "member_ids"),
    ("members", {}, "assignment members"),
    ("edges", [["bad"]], "assignment edge"),
    ("edges", {}, "assignment edges"),
    ("open_preconditions", ["blocker:B-1"], "precondition is invalid"),
    ("open_preconditions", [{"precondition_id": 1, "source_id": "B-1"}], "precondition_id"),
    ("open_preconditions", [{"precondition_id": "blocker:B-1", "source_id": 2}],
     "precondition source_id"),
    ("open_preconditions", {}, "open_preconditions"),
    ("evidence_catalog", [], "evidence catalog"),
    ("evidence_catalog", {}, "evidence catalog"),
])
def test_validate_refuses_invalid_seed_projections(key, value, message):
    assignment_bytes, envelope = envelope_for(seed(**{key: value}))
    parsed = results._parse(canonical(result(
        assignment_sha256=envelope["assignment_sha256"])))
    with pytest.raises(results.FirmwareReportResultError, match=message):
        results.validate(parsed, assignment_bytes)


@pytest.mark.parametrize("entry,message", [
    ({"ref": FINDING_REF}, "catalog entry keys"),
    ("text", "catalog entry keys"),
    ({**catalog()[1], "evidence_rung": "rung-9"}, "evidence_rung"),
    ({**catalog()[1], "kind": "guess"}, "catalog kind"),
    ({**catalog()[1], "ref": 7}, "catalog ref"),
    ({**catalog()[1], "owner_id": ""}, "catalog owner_id"),
    ({**catalog()[1], "component_path": 7}, "catalog component_path"),
    ({**catalog()[1], "location": 7}, "catalog location"),
    ({**catalog()[1], "field": 7}, "catalog field"),
    ({**catalog()[1], "excerpt": 7}, "catalog excerpt"),
    ({**catalog()[1], "excerpt": "x" * (report.MAX_EXCERPT_BYTES + 1)}, "catalog excerpt"),
])
def test_validate_refuses_invalid_catalog_entries(entry, message):
    assignment_bytes, envelope = envelope_for(seed(evidence_catalog=[entry]))
    parsed = results._parse(canonical(result(
        assignment_sha256=envelope["assignment_sha256"])))
    with pytest.raises(results.FirmwareReportResultError, match=message):
        results.validate(parsed, assignment_bytes)


def test_validate_requires_a_sorted_unique_catalog():
    assignment_bytes, envelope = envelope_for(
        seed(evidence_catalog=[catalog()[1], catalog()[1]]))
    parsed = results._parse(canonical(result(
        assignment_sha256=envelope["assignment_sha256"])))
    with pytest.raises(results.FirmwareReportResultError, match="sorted unique"):
        results.validate(parsed, assignment_bytes)


def test_validate_accepts_both_catalog_rung_variants():
    """Precondition entries carry `unresolved`; chain entries carry the rung."""
    assignment_bytes, _ = assignment()

    validated = results.validate(results._parse(canonical(result(
        answer=answer(summary=[cited(
            "The question for B-1 remains open for usr/sbin/service.",
            refs=(BLOCKER_REF,))])))), assignment_bytes)

    assert validated.citation_refs == (BLOCKER_REF, FINDING_REF)


def test_validate_requires_a_report_result_instance():
    assignment_bytes, _ = assignment()
    with pytest.raises(results.FirmwareReportResultError, match="ReportResult"):
        results.validate({"schema_version": 1}, assignment_bytes)


def test_canonical_requires_a_validated_result():
    with pytest.raises(results.FirmwareReportResultError, match="ValidatedReportResult"):
        results._canonical(results._parse(canonical(result())))


def test_load_accepts_a_path_object(tmp_path):
    path = save(tmp_path, result())
    assert results.load(pathlib.Path(path)).chain_id == CHAIN_ID
