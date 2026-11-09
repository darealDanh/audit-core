"""Strict Stage 4j worker report results and professional prose lint.

One fresh worker answers one assigned chain. This module reads that result with
the repository's bounded no-follow reader, parses exactly the worker-result
schema, binds it to the exact installed assignment bytes, requires every
structured entry to cite assignment-owned evidence, and enforces the versioned
style contract that `firmware_report` owns. It never derives facts, ordering,
pre-authentication status, severity or Markdown, and it never echoes rejected
prose in a diagnostic.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import re
import unicodedata

from audit_core import db, firmware_decide as decide
from audit_core import firmware_report as report


class FirmwareReportResultError(ValueError):
    """A report result violates its assignment, bounds or prose contract."""


RESULT_SCHEMA_VERSION = report.SCHEMA_VERSION
MAX_RESULT_BYTES = report.MAX_RESULT_BYTES
_STATE_SENTINELS = ("any", "unchanged")

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_TOKEN = re.compile(r"[0-9a-z]+")
_TERMINATORS = ".?!"
_CATALOG_KINDS = ("finding", "edge", "observation", "precondition")
_CATALOG_RUNGS = (db.FIRMWARE_FP_EVIDENCE_RUNGS + db.FIRMWARE_CHAIN_EVIDENCE_RUNGS
                  + db.FIRMWARE_DIVE_EVIDENCE_RUNGS + ("unresolved",))
_CATALOG_KEYS = ("ref", "kind", "owner_id", "component_path", "location",
                 "field", "evidence_rung", "excerpt")
_SEED_KEYS = ("schema_version", "image", "decision", "ordinal", "chain", "members",
              "edges", "open_preconditions", "evidence_catalog", "style_contract_sha256")
_IMAGE_KEYS = ("image_id", "vendor", "model", "version", "role", "sha256")
_CHAIN_KEYS = ("chain_id", "rank", "title", "summary", "member_ids", "pre_auth",
               "confidence", "completeness", "evidence_rung", "disposition",
               "rationale", "limitations")
_ENVELOPE_KEYS = ("report_generation", "assignment_sha256", "result_path", "seed")
_ANSWER_KEYS = ("title_detail", "summary", "root_cause", "reproduction_steps",
                "impact", "severity", "severity_justification", "fix_direction")
_RESULT_KEYS = ("schema_version", "image_id", "report_generation", "chain_id",
                "assignment_sha256", "answer")
_PARAGRAPH_FIELDS = ("summary", "root_cause", "reproduction_steps", "impact")


@dataclasses.dataclass(frozen=True, slots=True)
class CitedText:
    text: str
    citation_refs: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ReportAnswer:
    title_detail: str
    summary: tuple[CitedText, ...]
    root_cause: tuple[CitedText, ...]
    reproduction_steps: tuple[CitedText, ...]
    impact: tuple[CitedText, ...]
    severity: str
    severity_justification: CitedText
    fix_direction: CitedText | None


@dataclasses.dataclass(frozen=True, slots=True)
class ReportResult:
    schema_version: int
    image_id: str
    report_generation: str
    chain_id: str
    assignment_sha256: str
    answer: ReportAnswer


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedReportResult:
    image_id: str
    report_generation: str
    chain_id: str
    ordinal: int
    assignment_sha256: str
    result_path: str
    pre_auth: str
    open_precondition_ids: tuple[str, ...]
    severity: str
    citation_refs: tuple[str, ...]
    answer: ReportAnswer


def _fail(message: str):
    raise FirmwareReportResultError(message)


def _reject(item: int, field: str, rule: str):
    """One prose diagnostic: item, field and rule code, never the prose."""
    raise FirmwareReportResultError(f"report item {item} field {field}: {rule}")


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _fail("report JSON contains a duplicate key")
        value[key] = item
    return value


def _constant(token: str):
    _fail(f"non-finite value: {token}")


def _strict_json(raw: bytes, label: str):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_constant)
    except FirmwareReportResultError:
        raise
    except (ValueError, RecursionError) as exc:
        raise FirmwareReportResultError(f"{label} requires strict UTF-8 JSON") from exc


def _object(value, keys, label: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail(f"{label} keys differ")
    return value


def _array(value, label: str) -> list:
    if not isinstance(value, list):
        _fail(f"{label} requires an array")
    return value


def _sha256(value, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{label} requires a lowercase SHA-256")
    return value


def _identifier(value, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _fail(f"{label} requires a safe identifier")
    return value


def _integer(value, label: str, *, minimum: int) -> int:
    if type(value) is not int or value < minimum or value > 2 ** 63 - 1:
        _fail(f"{label} requires a bounded integer without coercion")
    return value


def _encoded(value, label: str) -> bytes:
    """UTF-8 bytes of one string, refusing lone surrogates."""
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise FirmwareReportResultError(f"{label} requires encodable UTF-8") from exc


def _image(value, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        _fail(f"{label} requires nonempty text without NUL")
    if len(_encoded(value, label)) > maximum:
        _fail(f"{label} exceeds its byte bound")
    return value


def _plain(value, label: str) -> str:
    """One NFC-normalized plain-text entry: no controls, no exotic whitespace.

    Zero-width and other format characters count as controls here: they are
    invisible in Markdown yet would split the ASCII tokens every banned phrase
    and token rule matches on.
    """
    if not isinstance(value, str):
        _fail(f"{label} requires text")
    text = unicodedata.normalize("NFC", value)
    _encoded(text, label)
    for char in text:
        if ord(char) < 0x20 or ord(char) == 0x7F or unicodedata.category(char) in ("Cc", "Cf"):
            _fail(f"{label} rejects control characters")
        if char.isspace() and char != " ":
            _fail(f"{label} rejects non-ASCII whitespace")
    return text


def _bounded(text: str, label: str, bounds) -> str:
    low, high = bounds
    if not low <= len(_encoded(text, label)) <= high:
        _fail(f"{label} exceeds its byte bounds")
    return text


def _citations(value, label: str, bounds) -> tuple[str, ...]:
    maximum = bounds["citations_per_entry"]
    if not isinstance(value, list) or not value or len(value) > maximum:
        _fail(f"{label} requires one to {maximum} citations")
    refs = []
    for item in value:
        if (not isinstance(item, str) or not item or "\0" in item
                or len(_encoded(item, label)) > bounds["citation_ref_bytes"]):
            _fail(f"{label} requires bounded text references")
        refs.append(item)
    if tuple(refs) != tuple(sorted(refs)) or len(set(refs)) != len(refs):
        _fail(f"{label} requires sorted unique citations")
    return tuple(refs)


def _cited(value, label: str, text_bounds, bounds) -> CitedText:
    row = _object(value, ("text", "citation_refs"), label)
    text = _bounded(_plain(row["text"], label), label, text_bounds)
    return CitedText(text, _citations(row["citation_refs"], label, bounds))


def _entries(value, label: str, count, text_bounds, bounds) -> tuple[CitedText, ...]:
    low, high = count
    if not isinstance(value, list) or not low <= len(value) <= high:
        _fail(f"{label} requires {low} to {high} entries")
    return tuple(_cited(item, label, text_bounds, bounds) for item in value)


def _answer(value, contract) -> ReportAnswer:
    row = _object(value, _ANSWER_KEYS, "report answer")
    bounds = contract["bounds"]
    text_bounds = bounds["text_bytes"]
    if row["severity"] not in contract["severity_enum"]:
        _fail("severity is outside the contract enum")
    fix = row["fix_direction"]
    if fix is not None:
        fix = _cited(fix, "fix_direction", bounds["fix_direction_bytes"], bounds)
    return ReportAnswer(
        _bounded(_plain(row["title_detail"], "title_detail"), "title_detail",
                 bounds["title_bytes"]),
        _entries(row["summary"], "summary", bounds["summary_paragraphs"],
                 text_bounds, bounds),
        _entries(row["root_cause"], "root_cause", bounds["root_cause_paragraphs"],
                 text_bounds, bounds),
        _entries(row["reproduction_steps"], "reproduction_steps",
                 bounds["reproduction_steps"], text_bounds, bounds),
        _entries(row["impact"], "impact", bounds["impact_paragraphs"],
                 text_bounds, bounds),
        row["severity"],
        _cited(row["severity_justification"], "severity_justification",
               bounds["severity_justification_bytes"], bounds),
        fix)


def _parse(raw: bytes) -> ReportResult:
    contract = report._style_contract()
    value = _strict_json(raw, "report result")
    row = _object(value, _RESULT_KEYS, "report result")
    if type(row["schema_version"]) is not int or row["schema_version"] != RESULT_SCHEMA_VERSION:
        _fail("schema_version must equal 1")
    return ReportResult(
        RESULT_SCHEMA_VERSION,
        _image(row["image_id"], "image_id", contract["bounds"]["image_id_bytes"]),
        _sha256(row["report_generation"], "report_generation"),
        _identifier(row["chain_id"], "chain_id"),
        _sha256(row["assignment_sha256"], "assignment_sha256"),
        _answer(row["answer"], contract))


def load(path: str | pathlib.Path) -> ReportResult:
    """Read and parse one worker result from an operator-named regular file."""
    try:
        raw = decide._read_stable_file(path, MAX_RESULT_BYTES)
    except OSError as exc:
        raise FirmwareReportResultError("cannot read report result") from exc
    if len(raw) > MAX_RESULT_BYTES:
        _fail("report result exceeds 16 KiB")
    return _parse(raw)


def _catalog_entry(value) -> dict:
    row = _object(value, _CATALOG_KEYS, "catalog entry")
    if not isinstance(row["ref"], str) or not row["ref"] or "\0" in row["ref"]:
        _fail("catalog ref requires a reference")
    _identifier(row["owner_id"], "catalog owner_id")
    for key in ("component_path", "location"):
        if row[key] is not None and not (isinstance(row[key], str) and row[key]):
            _fail(f"catalog {key} requires text or null")
    if not isinstance(row["field"], str) or not row["field"]:
        _fail("catalog field requires text")
    if (not isinstance(row["excerpt"], str) or not row["excerpt"]
            or len(_encoded(row["excerpt"], "catalog excerpt")) > report.MAX_EXCERPT_BYTES):
        _fail("catalog excerpt requires bounded retained text")
    if row["kind"] not in _CATALOG_KINDS:
        _fail("catalog kind is invalid")
    if row["evidence_rung"] not in _CATALOG_RUNGS:
        _fail("catalog evidence_rung is invalid")
    return row


def _catalog(value) -> dict[str, dict]:
    entries = _array(value, "evidence catalog")
    if not entries:
        _fail("evidence catalog requires at least one entry")
    parsed = [_catalog_entry(item) for item in entries]
    refs = [item["ref"] for item in parsed]
    if refs != sorted(refs) or len(set(refs)) != len(refs):
        _fail("evidence catalog requires sorted unique entries")
    return {item["ref"]: item for item in parsed}


def _safe(value, prefixes) -> str | None:
    """One catalog field a worker may name in published prose."""
    if value is None:
        return None
    if value.startswith("/") or any(value.startswith(item) for item in prefixes):
        return None
    return value


def _states(edges) -> list[str]:
    """Concrete edge state values; the `any`/`unchanged` sentinels name nothing."""
    values = []
    for edge in edges:
        if not isinstance(edge, dict):
            _fail("assignment edge is invalid")
        for key in ("required_state", "result_state"):
            state = edge.get(key)
            if isinstance(state, dict):
                values.extend(item for item in state.values()
                              if isinstance(item, str) and item not in _STATE_SENTINELS)
    return values


def _seed_anchors(seed) -> tuple[frozenset[str], tuple[str, ...]]:
    """Seed-scoped anchors: chain ID, member IDs, states and precondition IDs.

    Catalog `owner_id`, `component_path` and `location` stay scoped to the entry
    that cites them, so naming one chain member never supports a claim about
    another.
    """
    chain = _object(seed["chain"], _CHAIN_KEYS, "assignment chain")
    if chain["pre_auth"] not in db.FIRMWARE_CHAIN_PRE_AUTH:
        _fail("assignment chain pre_auth is invalid")
    anchors = {_identifier(chain["chain_id"], "assignment chain_id")}
    anchors.update(_identifier(item, "assignment member_id")
                   for item in _array(chain["member_ids"], "assignment member_ids"))
    _array(seed["members"], "assignment members")
    anchors.update(_states(_array(seed["edges"], "assignment edges")))
    preconditions = []
    for item in _array(seed["open_preconditions"], "assignment open_preconditions"):
        if not isinstance(item, dict):
            _fail("assignment precondition is invalid")
        identity = _identifier(item.get("precondition_id"), "assignment precondition_id")
        anchors.add(identity)
        anchors.add(_identifier(item.get("source_id"), "assignment precondition source_id"))
        preconditions.append(identity)
    return frozenset(anchors), tuple(sorted(preconditions))


def _relative(value, label: str) -> str:
    """The expected worker destination: one safe run-relative POSIX path."""
    if not isinstance(value, str) or not value or "\0" in value:
        _fail(f"{label} requires a relative path")
    pure = pathlib.PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        _fail(f"{label} requires a relative path")
    return value


def _assignment(assignment_bytes) -> tuple[dict, dict, dict[str, dict]]:
    if (not isinstance(assignment_bytes, bytes)
            or len(assignment_bytes) > report.MAX_ASSIGNMENT_BYTES):
        _fail("report assignment exceeds its byte cap")
    envelope = _strict_json(assignment_bytes, "report assignment")
    row = _object(envelope, _ENVELOPE_KEYS, "report assignment")
    if report._canonical(envelope) != assignment_bytes:
        _fail("report assignment is not canonical")
    seed = _object(row["seed"], _SEED_KEYS, "assignment seed")
    if seed["schema_version"] != RESULT_SCHEMA_VERSION:
        _fail("assignment seed schema_version must equal 1")
    if seed["style_contract_sha256"] != report._style_contract_sha256():
        _fail("assignment seed binds a different style contract")
    if report._digest(report._canonical(seed)) != _sha256(
            row["assignment_sha256"], "assignment_sha256"):
        _fail("assignment identity differs from its seed bytes")
    _sha256(row["report_generation"], "assignment report_generation")
    _relative(row["result_path"], "assignment result_path")
    _integer(seed["ordinal"], "assignment ordinal", minimum=1)
    return row, seed, _catalog(seed["evidence_catalog"])


def _tokens(text: str) -> tuple[str, ...]:
    """Casefolded ASCII tokens after punctuation becomes whitespace."""
    return tuple(_TOKEN.findall(unicodedata.normalize("NFC", text).casefold()))


def _contains(tokens, phrase) -> bool:
    width = len(phrase)
    return bool(phrase) and any(tokens[index:index + width] == phrase
                                for index in range(len(tokens) - width + 1))


def _protected(text: str, anchors) -> set[int]:
    spans: set[int] = set()
    for anchor in anchors:
        start = text.find(anchor)
        while start >= 0:
            spans.update(range(start, start + len(anchor)))
            start = text.find(anchor, start + 1)
    return spans


def _sentences(text: str, anchors) -> list[str]:
    """Split on terminal punctuation outside assignment-owned identifiers."""
    spans = _protected(text, anchors)
    parts, start = [], 0
    for index, char in enumerate(text):
        if (char in _TERMINATORS and index not in spans
                and (index + 1 == len(text) or text[index + 1] == " ")):
            parts.append(text[start:index + 1])
            start = index + 1
    parts.append(text[start:])
    return [item.strip() for item in parts if item.strip()]


def _text_rules(text: str, item: int, field: str, contract) -> None:
    tokens = _tokens(text)
    banned = contract["banned"]
    for key, rule in (("phrases", "banned-phrase"),
                      ("absolute_phrases", "absolute-claim"),
                      ("absolute_tokens", "absolute-claim"),
                      ("meta_phrases", "meta-phrase"),
                      ("runtime_tokens", "runtime-term")):
        for phrase in banned[key]:
            if _contains(tokens, _tokens(phrase)):
                _reject(item, field, rule)
    formatting = contract["formatting"]
    lowered = text.casefold()
    if formatting["em_dash"] in text:
        _reject(item, field, "em-dash")
    for mark in formatting["repeated_punctuation"]:
        if mark in text:
            _reject(item, field, "repeated-punctuation")
    for scheme in formatting["raw_url_schemes"]:
        if scheme in lowered:
            _reject(item, field, "raw-url")
    for prefix in formatting["internal_path_prefixes"]:
        if prefix in lowered:
            _reject(item, field, "internal-path")
    if formatting["sql_table_prefix"] in lowered:
        _reject(item, field, "sql-table")
    for low, high in formatting["emoji_ranges"]:
        if any(low <= ord(char) <= high for char in text):
            _reject(item, field, "emoji")
    posix = formatting["absolute_posix_prefix"]
    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(posix)}[A-Za-z0-9._-]", text) is not None:
        _reject(item, field, "absolute-path")
    if re.search(formatting["windows_drive_pattern"], text) is not None:
        _reject(item, field, "absolute-path")


def _entry_fields(answer: ReportAnswer):
    items = []
    for field in _PARAGRAPH_FIELDS:
        items.extend((field, entry) for entry in getattr(answer, field))
    items.append(("severity_justification", answer.severity_justification))
    if answer.fix_direction is not None:
        items.append(("fix_direction", answer.fix_direction))
    return tuple(items)


def _entry_anchors(entry: CitedText, catalog, prefixes) -> set[str]:
    anchors = set()
    for ref in entry.citation_refs:
        row = catalog[ref]
        anchors.add(row["owner_id"])
        anchors.update(item for item in (_safe(row["component_path"], prefixes),
                                        _safe(row["location"], prefixes))
                       if item is not None)
    return anchors


def _lint(answer: ReportAnswer, item: int, catalog, anchors, contract) -> tuple[str, ...]:
    prefixes = contract["formatting"]["internal_path_prefixes"]
    _text_rules(answer.title_detail, item, "title_detail", contract)
    refs: set[str] = set()
    sequence: list[tuple[str, str]] = []
    for field, entry in _entry_fields(answer):
        for ref in entry.citation_refs:
            if ref not in catalog:
                _reject(item, field, "citation-not-in-catalog")
        refs.update(entry.citation_refs)
        _text_rules(entry.text, item, field, contract)
        entry_tokens = _tokens(entry.text)
        owned = anchors | _entry_anchors(entry, catalog, prefixes)
        if not any(_contains(entry_tokens, _tokens(value)) for value in owned):
            _reject(item, field, "unsupported-entry")
        sequence.extend((field, sentence) for sentence in _sentences(entry.text, owned))
    repetition = contract["repetition"]
    width = repetition["prefix_tokens"]
    run = repetition["max_consecutive_same_prefix_sentences"]
    seen: set[str] = set()
    starts: list[tuple[str, ...]] = []
    for field, sentence in sequence:
        normalized = " ".join(_tokens(sentence))
        if normalized in seen:
            _reject(item, field, "duplicate-sentence")
        seen.add(normalized)
        starts.append(_tokens(sentence)[:width])
        if len(starts) >= run and len(set(starts[-run:])) == 1:
            _reject(item, field, "repeated-sentence-prefix")
    return tuple(sorted(refs))


def validate(result: ReportResult, assignment_bytes: bytes) -> ValidatedReportResult:
    """Bind one parsed result to its exact assignment and prose contract."""
    if not isinstance(result, ReportResult):
        _fail("validation requires a ReportResult")
    envelope, seed, catalog = _assignment(assignment_bytes)
    contract = report._style_contract()
    anchors, preconditions = _seed_anchors(seed)
    image = _object(seed["image"], _IMAGE_KEYS, "assignment image")
    if result.image_id != _image(image["image_id"], "assignment image_id",
                                 contract["bounds"]["image_id_bytes"]):
        _fail("result image_id differs from its assignment")
    if result.report_generation != envelope["report_generation"]:
        _fail("result report_generation differs from its assignment")
    if result.chain_id != seed["chain"]["chain_id"]:
        _fail("result chain_id differs from its assignment")
    if result.assignment_sha256 != envelope["assignment_sha256"]:
        _fail("result assignment_sha256 differs from its assignment")
    refs = _lint(result.answer, seed["ordinal"], catalog, anchors, contract)
    return ValidatedReportResult(
        result.image_id, result.report_generation, result.chain_id, seed["ordinal"],
        result.assignment_sha256, envelope["result_path"], seed["chain"]["pre_auth"],
        preconditions, result.answer.severity, refs, result.answer)


def _cited_wire(value: CitedText) -> dict:
    return {"text": value.text, "citation_refs": list(value.citation_refs)}


def _canonical(validated: ValidatedReportResult) -> bytes:
    """The one canonical byte string a recorded report result owns."""
    if not isinstance(validated, ValidatedReportResult):
        _fail("canonical bytes require a ValidatedReportResult")
    answer = validated.answer
    raw = report._canonical({
        "schema_version": RESULT_SCHEMA_VERSION,
        "image_id": validated.image_id,
        "report_generation": validated.report_generation,
        "chain_id": validated.chain_id,
        "assignment_sha256": validated.assignment_sha256,
        "answer": {
            "title_detail": answer.title_detail,
            "summary": [_cited_wire(item) for item in answer.summary],
            "root_cause": [_cited_wire(item) for item in answer.root_cause],
            "reproduction_steps": [_cited_wire(item) for item in answer.reproduction_steps],
            "impact": [_cited_wire(item) for item in answer.impact],
            "severity": answer.severity,
            "severity_justification": _cited_wire(answer.severity_justification),
            "fix_direction": None if answer.fix_direction is None
                             else _cited_wire(answer.fix_direction),
        },
    })
    if len(raw) > MAX_RESULT_BYTES:
        _fail("canonical report result exceeds 16 KiB")
    return raw
