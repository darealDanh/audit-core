"""Every versioned Stage 4j prose rule, citation rule and severity judgment."""
import pytest

from audit_core import firmware_report as report
from audit_core import firmware_report_results as results
from tests.test_firmware_report_results import (
    BLOCKER_REF, CHAIN_ID, FINDING_REF, SURFACE_REF, answer, assignment, canonical,
    catalog, cited, envelope_for, result, seed)


CONTRACT = report._style_contract()
ANCHORED = "The handler in usr/sbin/service reaches the shell call"


def validate(value, assignment_bytes=None):
    if assignment_bytes is None:
        assignment_bytes = assignment()[0]
    return results.validate(results._parse(canonical(value)), assignment_bytes)


def with_summary(text, refs=(FINDING_REF,)):
    return result(answer=answer(summary=[cited(text, refs)]))


def rejected(value, field, rule, probe=""):
    with pytest.raises(results.FirmwareReportResultError) as caught:
        validate(value)
    assert str(caught.value) == f"report item 1 field {field}: {rule}"
    if probe:
        assert probe not in str(caught.value)


def test_a_complete_professional_result_is_accepted():
    validated = validate(result())
    assert validated.severity == "high"
    assert validated.answer.title_detail.endswith("usr/sbin/service")


@pytest.mark.parametrize("phrase", CONTRACT["banned"]["phrases"])
def test_every_banned_phrase_is_rejected(phrase):
    rejected(with_summary(f"{ANCHORED} and {phrase} the parser trusts it."),
             "summary", "banned-phrase", probe=phrase)


@pytest.mark.parametrize("token", CONTRACT["banned"]["absolute_tokens"])
def test_every_absolute_token_is_rejected(token):
    rejected(with_summary(f"{ANCHORED} and {token} rejects the request."),
             "summary", "absolute-claim", probe=token)


@pytest.mark.parametrize("phrase", CONTRACT["banned"]["absolute_phrases"])
def test_every_absolute_phrase_is_rejected(phrase):
    rejected(with_summary(f"{ANCHORED} so the device is {phrase} by one request."),
             "summary", "absolute-claim", probe=phrase)


@pytest.mark.parametrize("phrase", CONTRACT["banned"]["meta_phrases"])
def test_every_meta_phrase_is_rejected(phrase):
    rejected(with_summary(f"{ANCHORED} and {phrase} supplies the rest."),
             "summary", "meta-phrase", probe=phrase)


@pytest.mark.parametrize("token", CONTRACT["banned"]["runtime_tokens"])
def test_every_runtime_term_is_rejected(token):
    rejected(with_summary(f"{ANCHORED} and the call {token} during the review."),
             "summary", "runtime-term", probe=token)


@pytest.mark.parametrize("text", [
    "in \u017fummary the handler in usr/sbin/service reaches the shell call",
    "UTILIZE the handler in usr/sbin/service to reach the shell call",
    "The handler in usr/sbin/service is CrUcIaL to the shell call",
    "The handler in usr/sbin/service works in today\u2019s firmware build",
])
def test_casefold_and_punctuation_bypasses_are_rejected(text):
    with pytest.raises(results.FirmwareReportResultError, match="field summary"):
        validate(with_summary(text))


@pytest.mark.parametrize("word", [
    "leveraged", "utilized", "delved", "overallocation", "neverending",
    "configured", "observable", "crucially"])
def test_ascii_token_boundaries_do_not_match_longer_words(word):
    """Phrase matching is token-exact, so inflected words stay publishable."""
    assert validate(with_summary(f"{ANCHORED} after the buffer is {word} once.")).severity


def test_normalization_composes_text_before_rules_run():
    composed = f"{ANCHORED} in the de\u0301codeur routine."
    assert validate(with_summary(composed)).answer.summary[0].text == (
        f"{ANCHORED} in the d\u00e9codeur routine.")


def test_em_dash_is_rejected():
    rejected(with_summary(f"{ANCHORED}\u2014without quoting the request text."),
             "summary", "em-dash")


@pytest.mark.parametrize("code", [9728, 10175, 11013, 11035, 126976, 129791,
                                  129792, 130047, 65039])
def test_every_emoji_range_boundary_is_rejected(code):
    rejected(with_summary(f"{ANCHORED} {chr(code)} without quoting."),
             "summary", "emoji")


@pytest.mark.parametrize("mark", CONTRACT["formatting"]["repeated_punctuation"])
def test_repeated_punctuation_is_rejected(mark):
    rejected(with_summary(f"{ANCHORED} without quoting{mark}"),
             "summary", "repeated-punctuation")


@pytest.mark.parametrize("scheme", CONTRACT["formatting"]["raw_url_schemes"])
def test_raw_url_schemes_are_rejected(scheme):
    rejected(with_summary(f"{ANCHORED} described at {scheme}vendor.example/doc."),
             "summary", "raw-url")


@pytest.mark.parametrize("prefix", CONTRACT["formatting"]["internal_path_prefixes"])
def test_internal_artifact_paths_are_rejected(prefix):
    rejected(with_summary(f"{ANCHORED} recorded under {prefix}report/manifest.json."),
             "summary", "internal-path")


@pytest.mark.parametrize("text", [
    "/etc/passwd is read by the handler in usr/sbin/service once",
    f"{ANCHORED} and writes /tmp/session.state",
    f"{ANCHORED} on C:\\firmware\\service.exe",
])
def test_absolute_posix_and_windows_paths_are_rejected(text):
    rejected(with_summary(text), "summary", "absolute-path")


def test_sql_table_names_are_rejected():
    rejected(with_summary(f"{ANCHORED} as stored in cba_firmware_report_items."),
             "summary", "sql-table")


@pytest.mark.parametrize("character", CONTRACT["escaping"]["characters"])
def test_markdown_metacharacters_stay_worker_text(character):
    """The renderer escapes these; the lint must not duplicate that job."""
    assert validate(with_summary(f"{ANCHORED} using {character} in the argument.")).severity


@pytest.mark.parametrize("text", [
    "- the handler in usr/sbin/service reaches the shell call",
    "1. the handler in usr/sbin/service reaches the shell call",
    "> the handler in usr/sbin/service reaches the shell call",
    "# the handler in usr/sbin/service reaches the shell call",
    "```the handler in usr/sbin/service reaches the shell call```",
])
def test_leading_markdown_markers_stay_worker_text(text):
    assert validate(with_summary(text)).severity


def test_duplicate_normalized_sentences_across_entries_are_rejected():
    sentence = f"{ANCHORED} without quoting the request text."
    value = result(answer=answer(
        summary=[cited(sentence)],
        impact=[cited(f"{sentence.upper()} ")]))
    rejected(value, "impact", "duplicate-sentence")


def test_three_consecutive_sentences_with_one_prefix_are_rejected():
    value = result(answer=answer(reproduction_steps=[
        cited("The handler in usr/sbin/service accepts the request text."),
        cited("The handler in usr/sbin/service copies it into the argument."),
        cited("The handler in usr/sbin/service passes the argument onward."),
    ]))
    rejected(value, "reproduction_steps", "repeated-sentence-prefix")


def test_two_consecutive_sentences_with_one_prefix_are_accepted():
    value = result(answer=answer(reproduction_steps=[
        cited("The handler in usr/sbin/service accepts the request text."),
        cited("The handler in usr/sbin/service copies it into the argument."),
        cited("Reading handle_request shows the argument reaching the shell."),
    ]))
    assert len(validate(value).answer.reproduction_steps) == 3


def test_sentence_boundaries_exclude_periods_inside_owned_identifiers():
    text = "Read cfg v1. 2 before the shell call. Then stop."

    assert results._sentences(text, ("cfg v1. 2",)) == [
        "Read cfg v1. 2 before the shell call.", "Then stop."]
    assert results._sentences(text, ()) == [
        "Read cfg v1.", "2 before the shell call.", "Then stop."]
    assert results._sentences("No terminator here", ()) == ["No terminator here"]


@pytest.mark.parametrize("text", [
    "This condition lets an attacker reach a sensitive routine remotely.",
    "A remote caller can reach the vulnerable routine without credentials.",
    f"The reference {FINDING_REF} alone does not anchor this claim at all.",
])
def test_entries_without_any_cited_anchor_are_rejected(text):
    rejected(with_summary(text.replace("F-1", "X-9")), "summary", "unsupported-entry")


@pytest.mark.parametrize("anchor,refs", [
    ("usr/sbin/service", (FINDING_REF,)),
    ("handle_request", (FINDING_REF,)),
    ("F-1", (FINDING_REF,)),
    ("S-1", (SURFACE_REF,)),
    ("B-1", (BLOCKER_REF,)),
    ("unauthenticated", (FINDING_REF,)),
    (CHAIN_ID, (FINDING_REF,)),
    ("blocker:B-1", (BLOCKER_REF,)),
])
def test_every_assignment_owned_anchor_satisfies_the_vagueness_rule(anchor, refs):
    assert validate(with_summary(
        f"A remote caller reaches {anchor} and gains shell execution.", refs)).severity


def test_unsafe_catalog_paths_cannot_anchor_an_entry():
    """An internal or absolute catalog path is never a publishable anchor."""
    assignment_bytes, envelope = envelope_for(seed(
        edges=[{"ordinal": 1}],
        open_preconditions=[],
        evidence_catalog=[{**catalog()[1], "owner_id": "F-1",
                           "component_path": "files/firmware-report/x",
                           "location": None}]))
    value = result(assignment_sha256=envelope["assignment_sha256"], answer=answer(
        summary=[cited("A remote caller reaches the handler and gains execution.")]))

    with pytest.raises(results.FirmwareReportResultError,
                       match="field summary: unsupported-entry"):
        results.validate(results._parse(canonical(value)), assignment_bytes)


@pytest.mark.parametrize("field,builder", [
    ("title_detail", lambda text: answer(title_detail=text)),
    ("root_cause", lambda text: answer(root_cause=[cited(text)])),
    ("reproduction_steps", lambda text: answer(reproduction_steps=[cited(text)])),
    ("impact", lambda text: answer(impact=[cited(text)])),
    ("severity_justification", lambda text: answer(severity_justification=cited(text))),
    ("fix_direction", lambda text: answer(fix_direction=cited(text))),
])
def test_every_prose_field_is_linted(field, builder):
    text = f"{ANCHORED} and this highlights the quoting defect in that routine."
    rejected(result(answer=builder(text)), field, "banned-phrase")


def test_title_detail_needs_no_citation_but_still_needs_clean_prose():
    value = result(answer=answer(title_detail="Always exploitable handler"))
    rejected(value, "title_detail", "absolute-claim")
    assert validate(result(answer=answer(
        title_detail="Command injection in usr/sbin/service"))).severity


@pytest.mark.parametrize("refs", [
    ("finding:F-9#impact",),
    ("dive:" + "a" * 64 + "#conclusion",),
    (FINDING_REF, "surface:S-2#reach_evidence"),
])
def test_citations_outside_the_assignment_catalog_are_rejected(refs):
    rejected(with_summary(f"{ANCHORED} without quoting the request text.", refs),
             "summary", "citation-not-in-catalog")


def test_each_structured_entry_keeps_its_own_citation_subset():
    value = result(answer=answer(
        summary=[cited(f"{ANCHORED} without quoting the request text.", (FINDING_REF,))],
        impact=[cited("A caller reaching S-1 gains shell execution on the device.",
                      (SURFACE_REF,))]))

    validated = validate(value)

    assert validated.answer.summary[0].citation_refs == (FINDING_REF,)
    assert validated.answer.impact[0].citation_refs == (SURFACE_REF,)
    assert validated.citation_refs == (FINDING_REF, SURFACE_REF)


def test_open_preconditions_and_pre_auth_stay_core_owned():
    assignment_bytes, envelope = envelope_for(seed(
        chain={**seed()["chain"], "pre_auth": "no"},
        open_preconditions=[
            {"precondition_id": "unknown:U-2", "source_id": "U-2"},
            {"precondition_id": "blocker:B-1", "source_id": "B-1"}]))
    value = result(assignment_sha256=envelope["assignment_sha256"])

    validated = results.validate(results._parse(canonical(value)), assignment_bytes)

    assert validated.pre_auth == "no"
    assert validated.open_precondition_ids == ("blocker:B-1", "unknown:U-2")


def test_severity_judgment_and_justification_are_carried_exactly():
    value = result(answer=answer(
        severity="informational",
        severity_justification=cited(
            "The handler in usr/sbin/service is reachable only with an existing "
            "shell, which limits the added exposure.")))

    validated = validate(value)

    assert validated.severity == "informational"
    assert validated.answer.severity_justification.citation_refs == (FINDING_REF,)
    assert validated.answer.severity == "informational"
