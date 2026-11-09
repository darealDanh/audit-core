"""Strict Stage 4j worker report results and professional prose lint.

One fresh worker answers one assigned chain. This module reads that result with
the repository's bounded no-follow reader, parses exactly the worker-result
schema, binds it to the exact installed assignment bytes, requires every
structured entry to cite assignment-owned evidence, and enforces the versioned
style contract that `firmware_report` owns. It never derives facts, ordering,
pre-authentication status, severity or Markdown, and it never echoes rejected
prose in a diagnostic.

`record` then owns the per-item half of the Stage 4j lifecycle: it installs
the one canonical result artifact, reconstructs the current preparation under
`BEGIN IMMEDIATE`, fills exactly one item row with a guarded update, and
transitions the run to `recorded` with its exact result manifest only when
every assigned chain has a result.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import re
import sqlite3
import unicodedata

from audit_core import db, firmware_decide as decide, firmware_dive, surface
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


@dataclasses.dataclass(frozen=True, slots=True)
class ReportRecordSummary:
    image_id: str
    report_generation: str
    chain_id: str
    ordinal: int
    result_path: str
    result_sha256: str
    item_count: int
    recorded_count: int
    status: str


@dataclasses.dataclass(frozen=True, slots=True)
class _RecordState:
    row: dict
    items: tuple[dict, ...]
    item: dict
    recorded: str | None
    validated: ValidatedReportResult
    raw: bytes
    result_sha256: str
    assignments: report._Assignments
    identity: tuple


def _current_row(con, result) -> dict:
    """The unique highest active report preparation this result belongs to."""
    rows = surface._query(
        con, "SELECT * FROM cba_firmware_report_runs WHERE image_id=?",
        (result.image_id,))
    if not rows:
        _fail("image has no report preparation")
    top = max(int(row["preparation_ordinal"]) for row in rows)
    current = [row for row in rows if int(row["preparation_ordinal"]) == top]
    if len(current) != 1:
        _fail("image has more than one current report preparation")
    row, = current
    db.TABLE_SPECS["cba_firmware_report_runs"].validate(row)
    if row["report_generation"] != result.report_generation:
        _fail("result is not for the current report preparation")
    if row["status"] not in ("pending", "recorded"):
        _fail("the current report preparation is not active")
    return row


def _identity(item) -> dict:
    """Exactly the manifest projection one prepared item row owns."""
    return {"ordinal": int(item["ordinal"]), "chain_id": item["chain_id"],
            "assignment_path": item["assignment_path"],
            "assignment_sha256": item["assignment_sha256"],
            "result_path": item["result_path"]}


def _bound(validated: ValidatedReportResult, item, generation) -> None:
    """One validated result against the exact item row that assigned it."""
    if ((validated.report_generation, validated.chain_id, validated.ordinal,
         validated.assignment_sha256, validated.result_path)
            != (generation, item["chain_id"], int(item["ordinal"]),
                item["assignment_sha256"], item["result_path"])):
        _fail("report result differs from its assigned item")


def _recorded_entry(run, generation, item, assignment_bytes) -> dict:
    """One already recorded sibling result, re-read and re-validated."""
    raw = firmware_dive._read(
        run, report._result_artifact_path(generation, item["chain_id"],
                                          item["result_sha256"]),
        item["result_sha256"], MAX_RESULT_BYTES)
    value = validate(_parse(raw), assignment_bytes)
    _bound(value, item, generation)
    if _canonical(value) != raw:
        _fail("recorded report result is not canonical")
    return report._result_entry(generation, value, item["result_sha256"])


def _reconstruct(con, run, result: ReportResult) -> _RecordState:
    """Rebuild the current preparation, its installed bytes and this result.

    Recording owns no root and never widens the verified scope: the run row,
    its item rows and the immutable assignment bytes are the only authority,
    and they must agree on the exact manifest the preparation published.
    """
    row = _current_row(con, result)
    generation = row["report_generation"]
    items = surface._query(
        con, "SELECT * FROM cba_firmware_report_items WHERE image_id=? "
        "AND report_generation=? ORDER BY ordinal", (result.image_id, generation))
    contents, assigned = {}, []
    for item in items:
        db.TABLE_SPECS["cba_firmware_report_items"].validate(item)
        name = f"items/{int(item['ordinal'])}-{item['chain_id']}.json"
        contents[name] = firmware_dive._read(run, item["assignment_path"],
                                             maximum=report.MAX_ASSIGNMENT_BYTES)
        assigned.append((item, contents[name]))
    identities = tuple(_identity(item) for item, _ in assigned)
    manifest = report._canonical({
        "schema_version": RESULT_SCHEMA_VERSION,
        "image_id": row["image_id"],
        "report_generation": generation,
        "decision_generation": row["decision_generation"],
        "decision_package_sha256": row["decision_package_sha256"],
        "style_contract_sha256": report._style_contract_sha256(),
        "item_count": int(row["item_count"]),
        "items": list(identities)})
    manifest_sha256 = report._digest(manifest)
    if (len(identities) != int(row["item_count"])
            or manifest_sha256 != row["manifest_sha256"]
            or row["manifest_path"] != f"files/firmware-report/{generation}"
                                       "/manifest.json"):
        _fail("stored report items differ from the current report preparation")
    contents["manifest.json"] = manifest
    matching = [pair for pair in assigned if pair[0]["chain_id"] == result.chain_id]
    if len(matching) != 1:
        _fail("report result is not assigned by the current report preparation")
    (item, assignment_bytes), = matching
    validated = validate(result, assignment_bytes)
    _bound(validated, item, generation)
    raw = _canonical(validated)
    result_sha256 = report._digest(raw)
    recorded = item["result_sha256"]
    if recorded is not None and recorded != result_sha256:
        _fail("report item is already recorded with different result bytes")
    results_sha256, results_contents = None, {}
    if all(other["result_sha256"] is not None for other, _ in assigned
           if other["chain_id"] != item["chain_id"]):
        # This result is the last one the preparation waits for, so the exact
        # recorded result manifest is already determined.
        entries = [report._result_entry(generation, validated, result_sha256)
                   if other["chain_id"] == item["chain_id"]
                   else _recorded_entry(run, generation, other, other_bytes)
                   for other, other_bytes in assigned]
        results_sha256, results_raw = report._results(generation, entries)
        results_contents = {"results.json": results_raw}
    if row["status"] != "pending" and (
            results_sha256 is None
            or (row["results_sha256"], row["results_path"]) != (
                results_sha256, report._results_path(generation, results_sha256))):
        _fail("stored report result manifest differs from the recorded results")
    assignments = report._Assignments(generation, manifest_sha256, identities,
                                      contents, results_sha256, results_contents)
    return _RecordState(
        row, tuple(item for item, _ in assigned), item, recorded, validated, raw,
        result_sha256, assignments,
        (raw, generation, manifest_sha256, identities, contents))


def _publish(con, state: _RecordState, now: str) -> ReportRecordSummary:
    """Fill exactly one item, then transition a fully recorded run."""
    row, item = state.row, state.item
    generation = state.assignments.generation
    if now < row["prepared_at"]:
        # The prepare-side guard, for recording: a clock that moved backwards
        # never stamps a result before the preparation that assigned it.
        _fail("report recording timestamp precedes preparation")
    status, items = row["status"], int(row["item_count"])
    recorded_count = sum(other["result_sha256"] is not None
                         or other["chain_id"] == item["chain_id"]
                         for other in state.items)
    if state.recorded is None:
        db.TABLE_SPECS["cba_firmware_report_items"].validate(
            dict(item, result_sha256=state.result_sha256, recorded_at=now))
        cursor = con.execute(
            "UPDATE cba_firmware_report_items SET result_sha256=?,recorded_at=? "
            "WHERE image_id=? AND report_generation=? AND chain_id=? "
            "AND result_sha256 IS NULL",
            (state.result_sha256, now, row["image_id"], generation,
             item["chain_id"]))
        if cursor.rowcount != 1:
            _fail("report item was recorded before this result")
    if state.assignments.results_sha256 is not None and status == "pending":
        status = "recorded"
        results_path = report._results_path(generation,
                                            state.assignments.results_sha256)
        db.TABLE_SPECS["cba_firmware_report_runs"].validate(dict(
            row, status=status, result_count=items, results_path=results_path,
            results_sha256=state.assignments.results_sha256, recorded_at=now))
        cursor = con.execute(
            "UPDATE cba_firmware_report_runs SET status='recorded',result_count=?,"
            "results_path=?,results_sha256=?,recorded_at=? WHERE image_id=? "
            "AND report_generation=? AND status='pending'",
            (items, results_path, state.assignments.results_sha256, now,
             row["image_id"], generation))
        if cursor.rowcount != 1:
            _fail("report run was recorded before this result")
    return ReportRecordSummary(
        row["image_id"], generation, item["chain_id"], int(item["ordinal"]),
        report._result_artifact_path(generation, item["chain_id"],
                                     state.result_sha256),
        state.result_sha256, items, recorded_count, status)


def _artifact(run, state: _RecordState):
    return run / pathlib.PurePosixPath(report._result_artifact_path(
        state.assignments.generation, state.item["chain_id"],
        state.result_sha256)).parent


def record(con: sqlite3.Connection, run_dir: str | pathlib.Path,
           result_path: str | pathlib.Path) -> ReportRecordSummary:
    """Install one canonical worker result, then fill exactly one item row.

    The immutable result bytes are installed before any lock is taken, every
    authority is reconstructed again under `BEGIN IMMEDIATE`, and one guarded
    update fills the item. The run becomes `recorded`, with its exact result
    manifest, only when this result is the last one its preparation waits
    for. An identical retry writes nothing; conflicting bytes are refused.
    """
    started = False
    try:
        if con.in_transaction:
            _fail("report recording requires no active caller transaction")
        run = firmware_dive._selector(run_dir)
        result = load(result_path)
        con.execute("BEGIN")
        started = True
        first = _reconstruct(con, run, result)
        con.rollback()
        started = False
        destination = run / "files" / "firmware-report" / first.assignments.generation
        firmware_dive._install(_artifact(run, first), {"result.json": first.raw}, run)
        report._install_check(run, destination, first.assignments, installed=False)

        con.execute("BEGIN IMMEDIATE")
        started = True
        state = _reconstruct(con, run, result)
        if state.identity != first.identity:
            _fail("report recording inputs changed before publication")
        firmware_dive._checked_install(_artifact(run, state),
                                       {"result.json": state.raw}, run,
                                       exact_mode=0o600)
        # A sibling that landed between the passes makes this result the last
        # one, so its result manifest is installed before the row that names it.
        installed = (state.assignments.results_sha256
                     == first.assignments.results_sha256)
        report._install_check(run, destination, state.assignments,
                              installed=installed)
        if state.assignments.results_sha256 is not None:
            # `_install` falls back to a mode-blind check on an existing
            # destination, so the committing transaction asserts mode itself.
            firmware_dive._checked_install(
                report._results_destination(run, state.assignments.generation,
                                            state.assignments.results_sha256),
                state.assignments.results_contents, run, exact_mode=0o600)
        summary = _publish(con, state,
                           con.execute("SELECT datetime('now')").fetchone()[0])
        con.commit()
        started = False
        return summary
    except FirmwareReportResultError:
        raise
    except (sqlite3.Error, db.DbError) as exc:
        raise FirmwareReportResultError("database operation failed") from exc
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            report.FirmwareReportError, firmware_dive.FirmwareDiveError,
            surface.SurfaceError) as exc:
        raise FirmwareReportResultError("cannot record report result") from exc
    finally:
        if started:
            con.rollback()
