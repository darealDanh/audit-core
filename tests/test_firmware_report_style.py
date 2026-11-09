"""Versioned Stage 4j report style-contract identity."""
import copy
import hashlib
import json

from audit_core import db
from audit_core import firmware_report as report


def test_style_contract_contains_every_bound_rule_and_renderer_decision():
    contract = report._style_contract()
    assert contract["schema_version"] == 1
    assert contract["bounds"] == {
        "assignment_bytes": 8 * 1024 * 1024,
        "catalog_excerpt_bytes": 4096,
        "citation_ref_bytes": 4096,
        "citations_per_entry": 16,
        "image_id_bytes": 4096,
        "fix_direction_bytes": [20, 400],
        "impact_paragraphs": [1, 2],
        "manifest_bytes": 8 * 1024 * 1024,
        "report_index_bytes": 8 * 1024 * 1024,
        "result_bytes": 16 * 1024,
        "root_cause_paragraphs": [1, 4],
        "severity_justification_bytes": [40, 400],
        "summary_paragraphs": [1, 2],
        "text_bytes": [20, 1200],
        "title_bytes": [12, 160],
        "reproduction_steps": [1, 8],
    }
    assert contract["normalization"] == {
        "casefold": "unicode-casefold-v1", "form": "NFC",
        "sentence_boundaries": "terminal-dot-question-exclamation-whitespace-v1",
        "token_boundaries": "ascii-alphanumeric-punctuation-space-v1",
        "version": "unicode-nfc-v1",
    }
    assert contract["escaping"]["characters"] == [
        "\\", "`", "<", ">", "&", "*", "_", "[", "]", "#", "|"]
    assert contract["escaping"]["leading_list_markers"] is True
    assert contract["banned"]["phrases"] == [
        "it is important to note", "it should be noted", "it is worth noting",
        "in today's", "in the ever-evolving", "robust security posture",
        "significant concern", "serious implications", "potentially",
        "could potentially", "may potentially", "this highlights",
        "this underscores", "overall", "in conclusion", "in summary",
        "delve", "leverage", "utilize", "crucial", "vital", "paramount"]
    assert contract["banned"]["absolute_tokens"] == [
        "always", "never", "infinite", "unlimited", "guaranteed",
        "impossible", "unexploitable"]
    assert contract["banned"]["absolute_phrases"] == ["fully compromised"]
    assert contract["banned"]["meta_phrases"] == [
        "as an ai", "the provided context", "the prompt", "the model",
        "the worker", "we recommend", "best practices", "industry standard"]
    assert contract["banned"]["runtime_tokens"] == [
        "confirmed", "observed", "reproduced", "crashed", "executed",
        "returned", "runtime-verified", "live-verified"]
    assert contract["formatting"]["raw_url_schemes"] == [
        "http://", "https://", "ftp://", "file://"]
    assert contract["formatting"]["internal_path_prefixes"] == [
        "reports/audit-", "files/firmware-", "artifacts/firmware-"]
    assert contract["formatting"]["sql_table_prefix"] == "cba_"
    assert contract["formatting"]["emoji_ranges"]
    assert contract["citation"] == {
        "display": ["path-location-ref", "path-ref", "evidence-ref"],
        "entry_requires_citation": True, "refs_sorted_unique": True,
        "subset_of_assignment_catalog": True, "vagueness_rule_version": 1,
    }
    assert contract["renderer"] == {
        "affected_version_heading": "Affected Version",
        "heading_template": ["Affected Version", "Summary", "Root Cause",
                             "Steps to reproduce", "Impact"],
        "section_h1": "# {chain_id}: {title_detail}",
        "source_level_preamble": "Assessment basis: source-level; not runtime-verified.",
        "version": 1,
    }
    assert contract["pre_auth_mapping"] == {
        "yes": "established", "no": "not established",
        "unknown": "not established: blocked by {precondition_ids}"}
    assert contract["severity_enum"] == list(db.FIRMWARE_REPORT_SEVERITIES)


def test_style_contract_hash_is_canonical_and_changes_for_every_rule_family(monkeypatch):
    original = report._style_contract()
    expected = hashlib.sha256((json.dumps(
        original, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":")) + "\n").encode()).hexdigest()
    assert report._style_contract_sha256() == expected
    for path in (("bounds", "title_bytes"), ("normalization", "version"),
                 ("escaping", "version"), ("banned", "phrases"),
                 ("formatting", "emoji_ranges"), ("citation", "display"),
                 ("renderer", "version"), ("pre_auth_mapping", "yes"),
                 ("severity_enum",)):
        changed = copy.deepcopy(original)
        target = changed
        for key in path[:-1]:
            target = target[key]
        key = path[-1]
        target[key] = target[key] + ["changed"] if isinstance(target[key], list) else "changed"
        monkeypatch.setattr(report, "_style_contract", lambda value=changed: value)
        assert report._style_contract_sha256() != expected
