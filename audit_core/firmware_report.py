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
import sqlite3

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


def _results(generation) -> tuple[str, bytes]:
    """The canonical zero-result manifest for a zero-chain report."""
    raw = _canonical({"schema_version": SCHEMA_VERSION,
                      "report_generation": generation, "results": []})
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
