"""Prepare immutable Stage 4j firmware report assignments.

The sole input boundary is `firmware_decide.verified_package`. This module
owns the versioned style contract, the per-chain assignment seeds, the report
generation, the manifest and the artifact-first preparation lifecycle. It
never queries Stage 4g/4h/4i tables and never widens the verified scope.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import re
import sqlite3
import unicodedata

from audit_core import db, firmware_chain, firmware_chain_results
from audit_core import firmware_decide, firmware_dive, surface


class FirmwareReportError(Exception):
    """Report authority, assignment bytes, or publication cannot be established."""


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ASSIGNMENT_BYTES = 8 * 1024 * 1024
MAX_REPORT_INDEX_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 16 * 1024
MAX_EXCERPT_BYTES = 4096
MAX_CITATION_REF_BYTES = 4096
MAX_IMAGE_ID_BYTES = 4096


@dataclasses.dataclass(frozen=True, slots=True)
class ReportPreparationSummary:
    image_id: str
    report_generation: str
    decision_generation: str
    decision_package_sha256: str
    style_contract_sha256: str
    manifest_path: str
    manifest_sha256: str
    item_count: int
    results_path: str | None
    results_sha256: str | None
    status: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareReportSection:
    ordinal: int
    chain_id: str
    severity: str
    pre_auth: str
    citation_refs: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareReport:
    image_id: str
    report_generation: str
    decision_generation: str
    decision_package_sha256: str
    report_path: str
    report_sha256: str
    report_bytes: bytes
    index_path: str
    index_sha256: str
    sections: tuple[VerifiedFirmwareReportSection, ...]


def _fail(message: str) -> None:
    raise FirmwareReportError(message)


def _require(condition: object, message: str) -> None:
    if not condition:
        _fail(message)


def _canonical(value) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                           sort_keys=True, separators=(",", ":")) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise FirmwareReportError("report assignment cannot be canonicalized") from exc


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _style_contract() -> dict:
    """The one versioned object every report generation is bound to.

    Every bound, list, renderer decision, pre-authentication mapping and
    severity value the core enforces lives here, so changing any rule changes
    `_style_contract_sha256()` and therefore every report generation.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "bounds": {
            "assignment_bytes": MAX_ASSIGNMENT_BYTES,
            "catalog_excerpt_bytes": MAX_EXCERPT_BYTES,
            "citation_ref_bytes": MAX_CITATION_REF_BYTES,
            "citations_per_entry": 16,
            "image_id_bytes": MAX_IMAGE_ID_BYTES,
            "fix_direction_bytes": [20, 400],
            "impact_paragraphs": [1, 2],
            "manifest_bytes": MAX_MANIFEST_BYTES,
            "report_index_bytes": MAX_REPORT_INDEX_BYTES,
            "result_bytes": MAX_RESULT_BYTES,
            "root_cause_paragraphs": [1, 4],
            "severity_justification_bytes": [40, 400],
            "summary_paragraphs": [1, 2],
            "text_bytes": [20, 1200],
            "title_bytes": [12, 160],
            "reproduction_steps": [1, 8],
        },
        "normalization": {
            "casefold": "unicode-casefold-v1",
            "form": "NFC",
            "sentence_boundaries": "terminal-dot-question-exclamation-whitespace-v1",
            "token_boundaries": "ascii-alphanumeric-punctuation-space-v1",
            "version": "unicode-nfc-v1",
        },
        "escaping": {
            "characters": ["\\", "`", "<", ">", "&", "*", "_", "[", "]", "#", "|"],
            "leading_list_markers": True,
            "version": "markdown-escape-v1",
        },
        "banned": {
            "phrases": [
                "it is important to note", "it should be noted", "it is worth noting",
                "in today's", "in the ever-evolving", "robust security posture",
                "significant concern", "serious implications", "potentially",
                "could potentially", "may potentially", "this highlights",
                "this underscores", "overall", "in conclusion", "in summary",
                "delve", "leverage", "utilize", "crucial", "vital", "paramount"],
            "absolute_tokens": [
                "always", "never", "infinite", "unlimited", "guaranteed",
                "impossible", "unexploitable"],
            "absolute_phrases": ["fully compromised"],
            "meta_phrases": [
                "as an ai", "the provided context", "the prompt", "the model",
                "the worker", "we recommend", "best practices", "industry standard"],
            "runtime_tokens": [
                "confirmed", "observed", "reproduced", "crashed", "executed",
                "returned", "runtime-verified", "live-verified"],
        },
        "formatting": {
            "em_dash": "\u2014",
            "emoji_ranges": [[9728, 10175], [11013, 11035], [126976, 129791],
                             [129792, 130047], [65039, 65039]],
            "internal_path_prefixes": [
                "reports/audit-", "files/firmware-", "artifacts/firmware-"],
            "raw_url_schemes": ["http://", "https://", "ftp://", "file://"],
            "repeated_punctuation": ["!!", "??"],
            "absolute_posix_prefix": "/",
            "windows_drive_pattern": r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/]",
            "sql_table_prefix": "cba_",
        },
        "repetition": {
            "duplicate_normalized_sentences": False,
            "max_consecutive_same_prefix_sentences": 3,
            "prefix_tokens": 3,
        },
        "citation": {
            "display": ["path-location-ref", "path-ref", "evidence-ref"],
            "entry_requires_citation": True,
            "refs_sorted_unique": True,
            "subset_of_assignment_catalog": True,
            "vagueness_rule_version": 1,
        },
        "renderer": {
            "affected_version_heading": "Affected Version",
            "heading_template": ["Affected Version", "Summary", "Root Cause",
                                 "Steps to reproduce", "Impact"],
            "section_h1": "# {chain_id}: {title_detail}",
            "source_level_preamble": "Assessment basis: source-level; not runtime-verified.",
            "version": 1,
        },
        "pre_auth_mapping": {
            "yes": "established",
            "no": "not established",
            "unknown": "not established: blocked by {precondition_ids}",
        },
        "severity_enum": list(db.FIRMWARE_REPORT_SEVERITIES),
    }


def _style_contract_sha256() -> str:
    return _digest(_canonical(_style_contract()))


# Renderer-owned literals. Every escaping and path rule the renderer applies
# comes from the one hashed style contract; these are the fixed sentences the
# core writes around validated worker text.
_ESCAPED_CHARACTERS = tuple(_style_contract()["escaping"]["characters"])
_ORDERED_MARKER = re.compile(r"\d{1,9}[.)]")
_REPORT_TITLE = "Firmware assessment report"
_STEPS_PREAMBLE = "Source-level verification guide; no runtime execution is claimed."
_EMPTY_REPORT = ("No technical chain is present in the current completed "
                 "decision package.")
_PRE_AUTH_LINE = "Pre-authentication path: {state}."
_SEVERITY_LINE = "Severity: {severity}. {justification}"
_PROVISIONAL_LINE = "Provisional: unresolved preconditions {precondition_ids}."
_FIX_LINE = "Fix direction: {text}"


def _excerpt(value: object, label: str) -> str:
    """Copy one retained upstream text, bounded to the catalog excerpt cap."""
    _require(isinstance(value, str) and value, f"{label} requires retained text")
    raw = value.encode()
    if len(raw) <= MAX_EXCERPT_BYTES:
        return value
    # Cut on a character boundary so the excerpt stays valid canonical UTF-8.
    return raw[:MAX_EXCERPT_BYTES].decode(errors="ignore")


def _entry(ref, kind, owner_id, component_path, location, field, evidence_rung, excerpt):
    return {
        "ref": ref,
        "kind": kind,
        "owner_id": owner_id,
        "component_path": component_path,
        "location": location,
        "field": field,
        "evidence_rung": evidence_rung,
        "excerpt": excerpt,
    }


def _sole_path(paths) -> str | None:
    """One firmware-relative component path, or null; the core never picks."""
    return paths[0] if len(paths) == 1 else None


def _graph_entry(ref, assessment, findings, surfaces, unknowns, observations):
    """Project one upstream evidence reference owned by a chain's structure.

    Finding fields are already catalogued from the member findings, so the
    remaining graph-structural references are surface and resolved-unknown
    texts supplied through chain edges or the chain's initial state. Dive
    references are overlay observations.
    """
    dive = firmware_chain_results._DIVE_PATTERN.fullmatch(ref)
    if dive is not None:
        identity, field = dive.groups()
        observation = observations.get(identity)
        _require(observation is not None, "Assignment cites an absent dive observation")
        effect = observation.resolution_effect
        excerpt = observation.outcome
        if field == "evidence" and effect is not None:
            excerpt = effect.predicate
        return _entry(ref, "observation", identity, None, None, field,
                      observation.evidence_rung, _excerpt(excerpt, "observation evidence"))
    match = firmware_chain_results._EVIDENCE_PATTERN.fullmatch(ref)
    _require(match is not None, "Assignment cites an unparsable evidence reference")
    kind, identity, field = match.groups()
    if kind == "finding":
        _require(identity in findings, "Assignment cites a foreign finding")
        return None
    if kind == "surface":
        item = surfaces.get(identity)
        _require(item is not None, "Assignment cites an absent surface")
        return _entry(ref, "edge", identity, item.component_path, item.handler, field,
                      assessment.evidence_rung, _excerpt(item.reach_evidence, "surface evidence"))
    item = unknowns.get(identity)
    _require(item is not None, "Assignment cites an absent unknown")
    return _entry(ref, "edge", identity, item.component_path, None, field,
                  assessment.evidence_rung, _excerpt(item.evidence, "unknown evidence"))


def _catalog(package, assessment, chain, edges, members):
    """The exact, sorted, unique evidence surface one assignment may cite."""
    graph = package.technical_input.graph
    member_findings = {item.finding_id: item for item in members}
    surfaces = {item.surface_id: item for item in graph.surfaces}
    unknowns = {item.id: item for item in graph.unknowns}
    observations = {item.observation_id: item
                    for item in package.technical_input.dive.overlay.observations}
    entries: dict[str, dict] = {}

    def add(entry):
        if entry is not None:
            entries.setdefault(entry["ref"], entry)

    for finding in members:
        for field in firmware_chain_results._EVIDENCE_FIELDS["finding"]:
            add(_entry(f"finding:{finding.finding_id}#{field}", "finding",
                       finding.finding_id, _sole_path(finding.component_paths), None,
                       field, finding.evidence_rung,
                       _excerpt(getattr(finding, field), "finding evidence")))
    references = list(chain.initial_evidence_refs)
    for finding in members:
        # Reach evidence for every surface the member finding owns; the entry
        # point is the chain's structural edge into that component.
        references.extend(f"surface:{item}#reach_evidence"
                          for item in finding.surface_ids)
    for edge in edges:
        references.extend(edge.producer_evidence_refs)
        references.extend(edge.consumer_evidence_refs)
        references.extend(edge.supplemental_evidence_refs)
    references.extend(assessment.evidence_refs)
    for ref in references:
        add(_graph_entry(ref, assessment, member_findings,
                         surfaces, unknowns, observations))
    for precondition in assessment.open_preconditions:
        for field in ("question", "settling_observation"):
            add(_entry(f"{precondition.precondition_id}#{field}", "precondition",
                       precondition.source_id, None, None, field, "unresolved",
                       _excerpt(getattr(precondition, field), "precondition text")))
    return [entries[ref] for ref in sorted(entries)]


def _projection(value) -> dict:
    """One upstream object as seed data, without its run storage path.

    Artifact ownership stays provable through `artifact_sha256`; the
    run-relative `artifact_path` is storage, which seeds never carry.
    """
    return {key: item for key, item in dataclasses.asdict(value).items()
            if key != "artifact_path"}


def _assignment_seeds(package) -> tuple[dict, ...]:
    """One ordered seed per chain assessment, in ascending Stage 4i rank."""
    graph = package.technical_input.graph
    chains = {item.chain_id: item for item in graph.chains}
    findings = {item.finding_id: item for item in graph.findings}
    assessments = sorted(package.result.chain_assessments, key=lambda item: item.rank)
    _require(len(assessments) == len(graph.chains),
             "Report requires one assessment for every current chain")
    image = dataclasses.asdict(package.image)
    decision = {
        "generation": package.decision_generation,
        "package_sha256": package.package_sha256,
        "decision": package.decision,
        "primary_reason": package.primary_reason,
    }
    style_contract_sha256 = _style_contract_sha256()
    seeds = []
    for ordinal, assessment in enumerate(assessments, 1):
        _require(assessment.rank == ordinal, "Chain ranks must be contiguous from one")
        chain = chains.get(assessment.chain_id)
        _require(chain is not None, "Chain assessment has no current chain")
        _require(all(item in findings for item in chain.member_ids),
                 "Chain member finding is absent from the current graph")
        members = tuple(findings[item] for item in chain.member_ids)
        edges = tuple(sorted((item for item in graph.edges
                              if item.chain_id == chain.chain_id),
                             key=lambda item: item.ordinal))
        seeds.append({
            "schema_version": SCHEMA_VERSION,
            "image": image,
            "decision": decision,
            "ordinal": ordinal,
            "chain": {
                "chain_id": chain.chain_id,
                "rank": assessment.rank,
                "title": chain.title,
                "summary": chain.summary,
                "member_ids": list(chain.member_ids),
                "pre_auth": assessment.pre_auth,
                "confidence": assessment.confidence,
                "completeness": assessment.completeness,
                "evidence_rung": assessment.evidence_rung,
                "disposition": assessment.disposition,
                "rationale": assessment.rationale,
                "limitations": list(assessment.limitations),
            },
            "members": [_projection(item) for item in members],
            "edges": [_projection(item) for item in edges],
            "open_preconditions": [dataclasses.asdict(item)
                                   for item in assessment.open_preconditions],
            "evidence_catalog": _catalog(package, assessment, chain, edges, members),
            "style_contract_sha256": style_contract_sha256,
        })
    return tuple(seeds)


def _generation(package, seeds) -> str:
    """The report generation: image identity, package bytes, style and seeds."""
    return _digest(_canonical({
        "schema_version": SCHEMA_VERSION,
        "decision_package_sha256": package.package_sha256,
        "image": dataclasses.asdict(package.image),
        "style_contract_sha256": _style_contract_sha256(),
        "assignment_seed_sha256s": [_digest(_canonical(seed)) for seed in seeds],
    }))


def _manifest(package, generation, items) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "image_id": package.image_id,
        "report_generation": generation,
        "decision_generation": package.decision_generation,
        "decision_package_sha256": package.package_sha256,
        "style_contract_sha256": _style_contract_sha256(),
        "item_count": len(items),
        "items": list(items),
    }


def _assignment_path(generation, ordinal, chain_id) -> str:
    return f"files/firmware-report/{generation}/items/{ordinal}-{chain_id}.json"


def _result_path(generation, ordinal, chain_id) -> str:
    """Where the assigned worker is expected to write its one result file.

    The immutable recorded copy is content-addressed under
    `artifacts/firmware-report-results/`, so the expected destination stays
    outside every installed immutable directory.
    """
    return f"files/firmware-report-results/{generation}/{ordinal}-{chain_id}.json"


def _result_artifact_path(generation, chain_id, result_sha256) -> str:
    """The immutable destination one recorded worker result owns."""
    return (f"artifacts/firmware-report-results/{generation}/{chain_id}/"
            f"{result_sha256}/result.json")


def _result_entry(generation, validated, result_sha256) -> dict:
    """One recorded result as the result manifest records it."""
    return {
        "ordinal": validated.ordinal,
        "chain_id": validated.chain_id,
        "result_path": _result_artifact_path(
            generation, validated.chain_id, result_sha256),
        "result_sha256": result_sha256,
    }


def _results(generation, entries=()) -> tuple[str, bytes]:
    """The canonical result manifest one recorded report owns, in ordinal order."""
    raw = _canonical({"schema_version": SCHEMA_VERSION,
                      "report_generation": generation, "results": list(entries)})
    return _digest(raw), raw


@dataclasses.dataclass(frozen=True, slots=True)
class _Assignments:
    generation: str
    manifest_sha256: str
    items: tuple[dict, ...]
    contents: dict
    results_sha256: str | None
    results_contents: dict


def _assignments(package) -> _Assignments:
    """Build every immutable byte string one preparation installs."""
    seeds = _assignment_seeds(package)
    generation = _generation(package, seeds)
    items, contents = [], {}
    for seed in seeds:
        ordinal, chain_id = seed["ordinal"], seed["chain"]["chain_id"]
        assignment_sha256 = _digest(_canonical(seed))
        result_path = _result_path(generation, ordinal, chain_id)
        raw = _canonical({
            "assignment_sha256": assignment_sha256,
            "report_generation": generation,
            "result_path": result_path,
            "seed": seed,
        })
        _require(len(raw) <= MAX_ASSIGNMENT_BYTES, "Report assignment exceeds its byte cap")
        contents[f"items/{ordinal}-{chain_id}.json"] = raw
        items.append({
            "ordinal": ordinal,
            "chain_id": chain_id,
            "assignment_path": _assignment_path(generation, ordinal, chain_id),
            "assignment_sha256": assignment_sha256,
            "result_path": result_path,
        })
    manifest_raw = _canonical(_manifest(package, generation, tuple(items)))
    _require(len(manifest_raw) <= MAX_MANIFEST_BYTES, "Report manifest exceeds its byte cap")
    contents["manifest.json"] = manifest_raw
    results_sha256, results_contents = None, {}
    if not items:
        results_sha256, results_raw = _results(generation)
        results_contents = {"results.json": results_raw}
    return _Assignments(generation, _digest(manifest_raw), tuple(items), contents,
                        results_sha256, results_contents)


def _results_destination(run, generation, results_sha256):
    return run / "artifacts" / "firmware-report-results" / generation / results_sha256


def _results_path(generation, results_sha256) -> str:
    return (f"artifacts/firmware-report-results/{generation}/"
            f"{results_sha256}/results.json")


def _frozen(package, assignments) -> dict:
    """The report columns that must equal the current verified authority."""
    frozen = {
        "decision_generation": package.decision_generation,
        "decision_package_sha256": package.package_sha256,
        "style_contract_sha256": _style_contract_sha256(),
        "manifest_path": f"files/firmware-report/{assignments.generation}/manifest.json",
        "manifest_sha256": assignments.manifest_sha256,
        "item_count": len(assignments.items),
    }
    if not assignments.items:
        # A zero-item run owns its results manifest from preparation, so its
        # stored result identity is part of the current authority too.
        frozen["results_path"] = _results_path(assignments.generation,
                                               assignments.results_sha256)
        frozen["results_sha256"] = assignments.results_sha256
    return frozen


def _item_rows(package, assignments) -> tuple[dict, ...]:
    return tuple({
        "image_id": package.image_id,
        "report_generation": assignments.generation,
        "chain_id": item["chain_id"],
        "ordinal": item["ordinal"],
        "assignment_path": item["assignment_path"],
        "assignment_sha256": item["assignment_sha256"],
        "result_path": item["result_path"],
    } for item in assignments.items)


def _prepared_row(package, assignments, prepared_at, preparation_ordinal) -> dict:
    row = {
        "image_id": package.image_id,
        "report_generation": assignments.generation,
        "preparation_ordinal": preparation_ordinal,
        "status": "pending",
        **_frozen(package, assignments),
        "result_count": 0,
        "prepared_at": prepared_at,
    }
    if not assignments.items:
        # A zero-chain report has every result it will ever have.
        row.update(
            status="recorded",
            results_path=_results_path(assignments.generation, assignments.results_sha256),
            results_sha256=assignments.results_sha256,
            recorded_at=prepared_at)
    return row


def _summary(row) -> ReportPreparationSummary:
    return ReportPreparationSummary(
        row["image_id"], row["report_generation"], row["decision_generation"],
        row["decision_package_sha256"], row["style_contract_sha256"],
        row["manifest_path"], row["manifest_sha256"], int(row["item_count"]),
        row["results_path"] if row.get("results_path") else None,
        row["results_sha256"] if row.get("results_sha256") else None,
        row["status"])


@dataclasses.dataclass(frozen=True, slots=True)
class _PreparationState:
    same: dict | None
    stale: tuple[dict, ...]
    latest: bool
    next_ordinal: int


def _preparation_state(con, package, assignments) -> _PreparationState:
    """Classify an image's report rows against one exact current assignment.

    An active row frozen on a decision package that is no longer current can
    never complete, so it is returned as stale for the caller to supersede. An
    active sibling on the current package is a style or coverage change the
    operator must finish first. `latest` means this generation already is the
    unique highest preparation, so an identical prepare has nothing to do.
    """
    rows = surface._query(
        con, "SELECT * FROM cba_firmware_report_runs WHERE image_id=?",
        (package.image_id,))
    frozen = _frozen(package, assignments)
    table = db.TABLE_SPECS["cba_firmware_report_runs"]
    same, stale = None, []
    for row in rows:
        if row["report_generation"] == assignments.generation:
            same = row
        elif row["status"] in ("pending", "recorded"):
            table.validate(row)
            if (row["decision_generation"], row["decision_package_sha256"]) == (
                    package.decision_generation, package.package_sha256):
                _fail("Another firmware report generation is active")
            stale.append(row)
    top = max((row["preparation_ordinal"] for row in rows), default=0)
    latest = False
    if same is not None:
        table.validate(same)
        if same["status"] == "superseded":
            _fail("Report generation was superseded; prepare a changed decision package instead")
        for key, value in frozen.items():
            if same[key] != value:
                _fail("Existing report generation differs from current authority")
        stored = surface._query(
            con, "SELECT * FROM cba_firmware_report_items WHERE image_id=? "
            "AND report_generation=? ORDER BY ordinal",
            (package.image_id, assignments.generation))
        expected = _item_rows(package, assignments)
        if len(stored) != len(expected):
            _fail("Existing report items differ from current authority")
        for row, item in zip(stored, expected):
            if any(row[key] != value for key, value in item.items()):
                _fail("Existing report items differ from current authority")
        latest = not stale and [row["preparation_ordinal"] for row in rows].count(
            top) == 1 and same["preparation_ordinal"] == top
    return _PreparationState(same, tuple(stale), latest, top + 1)


def _publish_preparation(con, prepared, package, assignments):
    """Supersede stale active rows, then publish or re-rank this generation."""
    now = con.execute("SELECT datetime('now')").fetchone()[0]
    table = db.TABLE_SPECS["cba_firmware_report_runs"]
    for row in prepared.stale:
        # The check-side guard, for supersede: a clock that moved backwards
        # never writes a supersede earlier than the row's own lifecycle.
        if now < (row["recorded_at"] or row["prepared_at"]):
            _fail("Report supersede timestamp precedes preparation or recording")
        table.validate(dict(row, status="superseded", superseded_at=now))
        con.execute(
            "UPDATE cba_firmware_report_runs SET status='superseded',superseded_at=? "
            "WHERE image_id=? AND report_generation=? AND status=?",
            (now, row["image_id"], row["report_generation"], row["status"]))
    if prepared.same is not None:
        con.execute(
            "UPDATE cba_firmware_report_runs SET preparation_ordinal=? "
            "WHERE image_id=? AND report_generation=?",
            (prepared.next_ordinal, package.image_id, assignments.generation))
        return _summary(prepared.same)
    row = _prepared_row(package, assignments, now, prepared.next_ordinal)
    db.put(con, "cba_firmware_report_runs", row, commit=False)
    for item in _item_rows(package, assignments):
        db.put(con, "cba_firmware_report_items", item, commit=False)
    return _summary(row)


def _install_check(run, destination, assignments, *, installed):
    """Verify every immutable byte string this generation owns."""
    firmware_dive._checked_install(destination, assignments.contents, run,
                                   exact_mode=0o600)
    if assignments.results_contents:
        results = _results_destination(run, assignments.generation,
                                       assignments.results_sha256)
        if installed:
            firmware_dive._checked_install(results, assignments.results_contents, run,
                                           exact_mode=0o600)
        else:
            firmware_dive._install(results, assignments.results_contents, run)


def _guard(value: str) -> str:
    """One displayed value that cannot carry document structure of its own.

    Worker text is already plain by Task 4's parser, but copied upstream text
    (image identity, catalog locations, identifiers) is not. A line break or
    other control character would start a real heading, quote, rule or code
    block inside canonical bytes, so such a value is refused, never degraded.
    """
    _require(isinstance(value, str), "Report display values require text")
    for char in value:
        _require(not (ord(char) < 0x20 or ord(char) == 0x7F
                      or unicodedata.category(char) in ("Cc", "Cf")),
                 "Report display value contains a control character")
    return value


def _escape(value: str) -> str:
    """One displayed string that cannot introduce Markdown syntax."""
    text = _guard(value).strip(" ")
    for char in _ESCAPED_CHARACTERS:
        text = text.replace(char, "\\" + char)
    if text[:1] in ("-", "+"):
        return "\\" + text
    marker = _ORDERED_MARKER.match(text)
    if marker is None:
        return text
    # An ordered-list marker only starts a list through its punctuation.
    return text[:marker.end() - 1] + "\\" + text[marker.end() - 1:]


def _inline(value: str) -> str:
    """One core-owned identifier as a code span, or as escaped text."""
    text = _guard(value).strip(" ")
    return f"`{text}`" if "`" not in text else _escape(text)


def _display(ref, catalog, prefixes) -> str:
    """The exact display citation one catalog reference is rendered as.

    Run-relative storage paths and absolute roots are never displayed, so a
    reference whose component path is internal keeps only its reference.
    """
    from audit_core import firmware_report_results as results
    entry = catalog.get(ref)
    _require(entry is not None, "Report cites a reference outside its assignment catalog")
    path = results._safe(entry["component_path"], prefixes)
    if path is None:
        return f"evidence {_inline(ref)}"
    location = results._safe(entry["location"], prefixes)
    subject = path if location is None else f"{path}:{location}"
    return f"{_inline(subject)} [{_inline(ref)}]"


def _cited(entry, catalog, prefixes) -> str:
    """One worker text entry with its deterministic display citations."""
    citations = "; ".join(_display(ref, catalog, prefixes)
                          for ref in entry.citation_refs)
    return f"{_escape(entry.text)} ({citations})"


def _paragraphs(heading, entries, catalog, prefixes) -> list[str]:
    lines = ["", f"## {heading}"]
    for index, entry in enumerate(entries):
        if index:
            lines.append("")
        lines.append(_cited(entry, catalog, prefixes))
    return lines


def _pre_auth(value, preconditions, contract, *, inline: bool) -> str:
    """The fixed pre-authentication statement one chain is published with.

    The Markdown document shows the blocking precondition IDs as code spans;
    the report index carries the same statement as plain text.
    """
    _require(value != "unknown" or preconditions,
             "Unknown pre-authentication requires one open precondition")
    ids = [_inline(item) for item in preconditions] if inline else [
        _guard(item) for item in preconditions]
    return contract["pre_auth_mapping"][value].format(
        precondition_ids=", ".join(ids))


def _section(image, seed, validated, contract) -> list[str]:
    """One chain's exact one-H1, five-H2 section."""
    affected, summary, root_cause, steps, impact = (
        contract["renderer"]["heading_template"])
    prefixes = contract["formatting"]["internal_path_prefixes"]
    catalog = {entry["ref"]: entry for entry in seed["evidence_catalog"]}
    chain, answer = seed["chain"], validated.answer
    lines = ["", contract["renderer"]["section_h1"].format(
        chain_id=_inline(chain["chain_id"]),
        title_detail=_escape(answer.title_detail))]
    lines.extend(("", f"## {affected}",
                  f"- Image: {_inline(_image_label(image))}",
                  f"- Image SHA-256: {_inline(image.sha256)}",
                  "- Chain members: " + ", ".join(
                      _inline(member) for member in chain["member_ids"])))
    lines.extend(_paragraphs(summary, answer.summary, catalog, prefixes))
    lines.extend(_paragraphs(root_cause, answer.root_cause, catalog, prefixes))
    lines.extend(("", f"## {steps}", _STEPS_PREAMBLE, ""))
    lines.extend(f"{number}. {_cited(entry, catalog, prefixes)}"
                 for number, entry in enumerate(answer.reproduction_steps, 1))
    lines.extend(_paragraphs(impact, answer.impact, catalog, prefixes))
    lines.extend(("", _PRE_AUTH_LINE.format(state=_pre_auth(
        chain["pre_auth"], validated.open_precondition_ids, contract, inline=True)),
        _SEVERITY_LINE.format(
            severity=answer.severity.upper(),
            justification=_cited(answer.severity_justification, catalog, prefixes))))
    if validated.open_precondition_ids:
        lines.append(_PROVISIONAL_LINE.format(precondition_ids=", ".join(
            _inline(item) for item in validated.open_precondition_ids)))
    if answer.fix_direction is not None:
        lines.append(_FIX_LINE.format(
            text=_cited(answer.fix_direction, catalog, prefixes)))
    return lines


def _image_label(image) -> str:
    return f"{image.vendor} {image.model} {image.version}"


def _render(package, assignments, results) -> tuple[bytes, bytes, tuple]:
    """The canonical Markdown, report index and ordered sections of one report.

    This is the only code that writes Markdown syntax. Every displayed string
    is escaped here; worker text never reaches the document unescaped and
    never controls headings, ordering, inline code or citations.
    """
    contract = _style_contract()
    image = package.image
    lines = [_REPORT_TITLE,
             f"Image: {_inline(_image_label(image))} ({_inline(image.sha256)})",
             f"Decision: {_inline(package.decision)} "
             f"({_inline(package.primary_reason)})",
             contract["renderer"]["source_level_preamble"]]
    _require(len(results) == len(assignments.items),
             "Report requires exactly one result for every assignment")
    sections = []
    for ordinal, item in enumerate(assignments.items, 1):
        _require(item["ordinal"] == ordinal,
                 "Report assignments require ascending ordinals")
        validated = results.get(item["chain_id"])
        _require(validated is not None, "Report result is absent for an assigned chain")
        seed = json.loads(assignments.contents[
            f"items/{ordinal}-{item['chain_id']}.json"])["seed"]
        _require(seed["chain"]["rank"] == ordinal,
                 "Chain rank must equal its report ordinal")
        lines.extend(_section(image, seed, validated, contract))
        sections.append(VerifiedFirmwareReportSection(
            ordinal, item["chain_id"], validated.severity,
            _pre_auth(seed["chain"]["pre_auth"],
                      validated.open_precondition_ids, contract, inline=False),
            validated.citation_refs))
    if not sections:
        lines.extend(("", _EMPTY_REPORT))
    raw = ("\n".join(lines) + "\n").encode()
    index = _canonical({
        "schema_version": SCHEMA_VERSION,
        "image_id": package.image_id,
        "report_generation": assignments.generation,
        "decision_generation": package.decision_generation,
        "decision_package_sha256": package.package_sha256,
        "report_sha256": _digest(raw),
        "sections": [{"ordinal": section.ordinal, "chain_id": section.chain_id,
                      "severity": section.severity, "pre_auth": section.pre_auth,
                      "citation_refs": list(section.citation_refs)}
                     for section in sections],
    })
    _require(len(index) <= MAX_REPORT_INDEX_BYTES,
             "Report index exceeds its byte cap")
    return raw, index, tuple(sections)


def _report_path(generation, report_sha256) -> str:
    return f"artifacts/firmware-report/{generation}/{report_sha256}/report.md"


def _index_path(generation, report_sha256) -> str:
    return f"artifacts/firmware-report/{generation}/{report_sha256}/report.json"


def _report_destination(run, generation, report_sha256):
    return run / "artifacts" / "firmware-report" / generation / report_sha256


@dataclasses.dataclass(frozen=True, slots=True)
class _CompleteInputs:
    row: dict
    package: firmware_decide.VerifiedFirmwareDecisionPackage
    assignments: _Assignments
    results: tuple
    results_sha256: str
    report_sha256: str
    report_bytes: bytes
    index_sha256: str
    index_bytes: bytes
    sections: tuple[VerifiedFirmwareReportSection, ...]
    contents: dict


def _current_run(con, image_id) -> dict:
    """The unique highest preparation one image has; ties are refused."""
    rows = surface._query(
        con, "SELECT * FROM cba_firmware_report_runs WHERE image_id=?", (image_id,))
    _require(rows, "Image has no report preparation")
    top = max(row["preparation_ordinal"] for row in rows)
    latest = [row for row in rows if row["preparation_ordinal"] == top]
    _require(len(latest) == 1, "Image has more than one current report preparation")
    return latest[0]


def _verify_complete_inputs(con, run, root, *,
                            image_id: str | None = None) -> _CompleteInputs:
    """Reconstruct one current recorded or complete report without writing.

    The current package, assignments, recorded results, result manifest and
    canonical report bytes are rebuilt from authority, and any installed
    complete artifact is verified. Nothing is installed or repaired here.
    """
    from audit_core import firmware_report_results as results
    package = firmware_decide.verified_package(con, run, root, image_id=image_id)
    assignments = _assignments(package)
    row = _current_run(con, package.image_id)
    _require(row["report_generation"] == assignments.generation,
             "The current report preparation is not the current decision package")
    db.TABLE_SPECS["cba_firmware_report_runs"].validate(row)
    _require(row["status"] in ("recorded", "complete"),
             "The current firmware report has no recorded results")
    for key, value in _frozen(package, assignments).items():
        _require(row[key] == value, "Stored report differs from current authority")
    stored = surface._query(
        con, "SELECT * FROM cba_firmware_report_items WHERE image_id=? "
        "AND report_generation=? ORDER BY ordinal",
        (package.image_id, assignments.generation))
    expected = _item_rows(package, assignments)
    _require(len(stored) == len(expected),
             "Stored report items differ from current authority")
    validated, entries = {}, []
    for item, values in zip(stored, expected):
        _require(all(item[key] == value for key, value in values.items()),
                 "Stored report items differ from current authority")
        db.TABLE_SPECS["cba_firmware_report_items"].validate(item)
        _require(item["result_sha256"] is not None,
                 "A current report item is not recorded")
        # `assignment_sha256` identifies the seed, not the installed envelope,
        # so the exact current envelope bytes are the comparison.
        raw = firmware_dive._read(run, item["assignment_path"],
                                  maximum=MAX_ASSIGNMENT_BYTES)
        _require(raw == assignments.contents[
            f"items/{item['ordinal']}-{item['chain_id']}.json"],
            "Installed report assignment differs from current authority")
        result_raw = firmware_dive._read(
            run, _result_artifact_path(assignments.generation, item["chain_id"],
                                       item["result_sha256"]),
            item["result_sha256"], results.MAX_RESULT_BYTES)
        value = results.validate(results._parse(result_raw), raw)
        _require(results._canonical(value) == result_raw,
                 "Recorded report result is not canonical")
        _require((value.image_id, value.report_generation, value.chain_id,
                  value.ordinal) == (package.image_id, assignments.generation,
                                     item["chain_id"], item["ordinal"]),
                 "Recorded report result differs from its assignment")
        validated[item["chain_id"]] = value
        entries.append(_result_entry(assignments.generation, value,
                                     item["result_sha256"]))
    results_sha256, results_raw = _results(assignments.generation, entries)
    _require((row["results_sha256"], row["results_path"]) == (
        results_sha256, _results_path(assignments.generation, results_sha256)),
        "Stored report result manifest differs from current authority")
    firmware_dive._checked_install(
        _results_destination(run, assignments.generation, results_sha256),
        {"results.json": results_raw}, run, exact_mode=0o600)
    report_bytes, index_bytes, sections = _render(package, assignments, validated)
    report_sha256, index_sha256 = _digest(report_bytes), _digest(index_bytes)
    contents = {"report.md": report_bytes, "report.json": index_bytes}
    if row["status"] == "complete":
        _require((row["report_path"], row["report_sha256"], row["report_bytes"],
                  row["index_path"], row["index_sha256"]) == (
            _report_path(assignments.generation, report_sha256), report_sha256,
            report_bytes, _index_path(assignments.generation, report_sha256),
            index_sha256),
            "Stored complete report row differs from the canonical report")
        firmware_dive._checked_install(
            _report_destination(run, assignments.generation, report_sha256),
            contents, run, exact_mode=0o600)
    return _CompleteInputs(
        row, package, assignments,
        tuple(validated[item["chain_id"]] for item in stored), results_sha256,
        report_sha256, report_bytes, index_sha256, index_bytes, sections, contents)


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path,
        root: str | pathlib.Path, *,
        image_id: str | None = None) -> ReportPreparationSummary:
    """Install and publish one exact current report assignment set."""
    started = False
    try:
        if con.in_transaction:
            _fail("Report preparation requires no active caller transaction")
        run = firmware_dive._selector(run_dir)
        con.execute("BEGIN")
        started = True
        first_package = firmware_decide.verified_package(con, run, root, image_id=image_id)
        first = _assignments(first_package)
        destination = run / "files" / "firmware-report" / first.generation
        prepared = _preparation_state(con, first_package, first)
        if prepared.latest:
            _install_check(run, destination, first, installed=True)
            con.rollback()
            started = False
            return _summary(prepared.same)
        con.rollback()
        started = False
        firmware_dive._install(destination, first.contents, run)
        _install_check(run, destination, first, installed=False)

        con.execute("BEGIN IMMEDIATE")
        started = True
        package = firmware_decide.verified_package(con, run, root, image_id=image_id)
        assignments = _assignments(package)
        if package != first_package or assignments != first:
            _fail("Report inputs changed before publication")
        _install_check(run, destination, assignments, installed=True)
        prepared = _preparation_state(con, package, assignments)
        if prepared.latest:
            con.rollback()
            started = False
            return _summary(prepared.same)
        summary = _publish_preparation(con, prepared, package, assignments)
        con.commit()
        started = False
        return summary
    except FirmwareReportError:
        raise
    except (sqlite3.Error, db.DbError) as exc:
        raise FirmwareReportError("database operation failed") from exc
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            firmware_chain.FirmwareChainError, firmware_dive.FirmwareDiveError,
            firmware_decide.FirmwareDecideError, surface.SurfaceError) as exc:
        raise FirmwareReportError("Cannot prepare firmware report") from exc
    finally:
        if started:
            con.rollback()


def verified_report(con: sqlite3.Connection, run_dir: str | pathlib.Path,
        root: str | pathlib.Path, *,
        image_id: str | None = None) -> VerifiedFirmwareReport:
    """Return one current complete report without writing or repairing.

    Only the pure verifier runs here, inside a read transaction. A missing or
    differing artifact, a stale package, an ambiguous preparation or an
    incomplete lifecycle is refused; history is never used as a fallback.
    """
    owned = False
    try:
        if not con.in_transaction:
            con.execute("BEGIN")
            owned = True
        run = firmware_dive._selector(run_dir)
        verified = _verify_complete_inputs(con, run, root, image_id=image_id)
        _require(verified.row["status"] == "complete",
                 "The current firmware report is not complete")
        generation = verified.assignments.generation
        return VerifiedFirmwareReport(
            verified.package.image_id, generation,
            verified.package.decision_generation,
            verified.package.package_sha256,
            _report_path(generation, verified.report_sha256),
            verified.report_sha256, verified.report_bytes,
            _index_path(generation, verified.report_sha256),
            verified.index_sha256, verified.sections)
    except FirmwareReportError:
        raise
    except (sqlite3.Error, db.DbError) as exc:
        raise FirmwareReportError("database operation failed") from exc
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            firmware_chain.FirmwareChainError, firmware_dive.FirmwareDiveError,
            firmware_decide.FirmwareDecideError, surface.SurfaceError) as exc:
        raise FirmwareReportError("Cannot verify firmware report") from exc
    finally:
        if owned:
            con.rollback()
