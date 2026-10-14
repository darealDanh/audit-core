"""Bind deterministic surface assignments to an exact carved-tree manifest."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import re
import shutil
import sqlite3
import tempfile
from collections.abc import Iterable, Mapping

from audit_core import db, firmware_tree


class SurfaceError(Exception):
    """Surface work cannot be prepared without misleading assignments."""


@dataclasses.dataclass(frozen=True, slots=True)
class PreparationSummary:
    image_id: str
    manifest_sha256: str
    worklist_sha256: str
    unit_count: int
    batch_count: int
    worklist_path: str


@dataclasses.dataclass(frozen=True, slots=True)
class SurfaceCheck:
    image_id: str
    manifest_units: int
    analyzed: int
    not_audited: int
    surfaces: int
    open_unknowns: int
    resolved_unknowns: int
    complete: bool


def canonical_bytes(value: object) -> bytes:
    """Canonical UTF-8 JSON shared by preparation and result publication."""
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def canonical_manifest(rows: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    """Normalize complete plain manifest rows, independent of input order."""
    result: dict[str, dict[str, object]] = {}
    for row in rows:
        path = row.get("path")
        if (not isinstance(path, str) or not path or "\\" in path or
                path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/"))):
            raise SurfaceError(f"Invalid manifest path: {path!r}")
        if path in result:
            raise SurfaceError(f"Duplicate manifest path: {path}")
        kind, size, digest = row.get("kind"), row.get("size"), row.get("sha256")
        if kind not in ("binary", "script", "config", "file"):
            raise SurfaceError(f"Invalid manifest kind for {path}: {kind!r}")
        if type(size) is not int or not 0 <= size <= 9223372036854775807:
            raise SurfaceError(f"Invalid manifest size for {path}: {size!r}")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise SurfaceError(f"Invalid manifest SHA-256 for {path}: {digest!r}")
        result[path] = {"path": path, "kind": kind, "size": size, "sha256": digest}
    return [result[path] for path in sorted(result)]


def manifest_sha256(rows: Iterable[Mapping[str, object]]) -> str:
    return hashlib.sha256(canonical_bytes(canonical_manifest(rows))).hexdigest()


def atomic_install(destination: pathlib.Path, files: Mapping[str, bytes]) -> None:
    """Install a complete immutable directory, or verify its identical contents.

    A private sibling directory prevents partial generations from appearing.
    Existing generations are never overwritten, even when corrupted.
    """
    destination = pathlib.Path(destination)
    for name in files:
        if (not isinstance(name, str) or pathlib.PurePosixPath(name).name != name or
                name in ("", ".", "..")):
            raise SurfaceError(f"Invalid artifact filename: {name!r}")
    temporary = None
    try:
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_dir():
                raise SurfaceError(f"Invalid existing artifact directory: {destination}")
            if {p.name for p in destination.iterdir()} != set(files):
                raise SurfaceError(f"Existing generation has different artifacts: {destination}")
            for name, content in files.items():
                path = destination / name
                if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
                    raise SurfaceError(f"Existing artifact differs: {path}")
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = pathlib.Path(tempfile.mkdtemp(prefix=".surface-", dir=destination.parent))
        for name, content in files.items():
            (temporary / name).write_bytes(content)
        os.replace(temporary, destination)
    except OSError as exc:
        raise SurfaceError(f"Cannot install surface artifacts: {exc}") from exc
    finally:
        if temporary is not None and temporary.exists():
            shutil.rmtree(temporary)


def _query(con: sqlite3.Connection, sql: str, args: tuple = ()) -> list[dict[str, object]]:
    cursor = con.execute(sql, args)
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor]


def _resolve_target(images: list[dict[str, object]], image_id: str | None) -> str:
    if image_id == db.FIRMWARE_IMAGE_UNSCOPED:
        raise SurfaceError("legacy-unscoped has no acquired-image provenance")
    if image_id is None:
        candidates = [image for image in images if image["role"] == "target"]
        if len(candidates) != 1:
            raise SurfaceError(f"Expected exactly one target image; found {len(candidates)}. Supply image_id")
        chosen = candidates[0]
    else:
        chosen = next((image for image in images if image["id"] == image_id), None)
        if chosen is None:
            raise SurfaceError(f"Unknown target image ID: {image_id}")
        if chosen["role"] != "target":
            raise SurfaceError(f"Image {image_id} must have role target")
    if chosen["id"] == db.FIRMWARE_IMAGE_UNSCOPED:
        raise SurfaceError("legacy-unscoped has no acquired-image provenance")
    return str(chosen["id"])


def _manifest(con: sqlite3.Connection, image_id: str) -> list[dict[str, object]]:
    rows = canonical_manifest(_query(con, "SELECT path,kind,size,sha256 FROM cba_firmware_files WHERE image_id=?",
                                     (image_id,)))
    if not rows:
        raise SurfaceError(f"Image {image_id} has an empty triage manifest")
    return rows


def _inventory_agreement(con: sqlite3.Connection, manifest: list[dict[str, object]]) -> None:
    stored = {row["unit"]: (row["kind"], row["size"]) for row in
              _query(con, "SELECT unit,kind,size FROM cba_inventory")}
    expected = {row["path"]: (row["kind"], row["size"]) for row in manifest}
    differing = sorted(path for path in stored.keys() | expected.keys()
                       if stored.get(path) != expected.get(path))
    if differing:
        raise SurfaceError(f"Target inventory differs from manifest at {differing[0]}")


def _root_agreement(root: str | pathlib.Path, manifest: list[dict[str, object]]) -> None:
    scanned = canonical_manifest({"path": fact.relative, "kind": fact.kind,
                                  "size": fact.size, "sha256": fact.sha256}
                                 for fact in firmware_tree.scan(root))
    if scanned != manifest:
        expected = {row["path"]: row for row in manifest}
        actual = {row["path"]: row for row in scanned}
        differing = sorted(path for path in expected.keys() | actual.keys()
                           if expected.get(path) != actual.get(path))
        raise SurfaceError(f"Live root differs from target manifest at {differing[0]}")


def _bounded(row: Mapping[str, object], fields: tuple[str, ...]) -> dict[str, object]:
    return {field: (value[:1024] if isinstance(value, str) else value)
            for field in fields if (value := row.get(field)) is not None}


def _annotate(manifest: list[dict[str, object]], elf_rows: list[dict[str, object]],
              service_rows: list[dict[str, object]], component_rows: list[dict[str, object]]
              ) -> list[dict[str, object]]:
    elf_fields = ("machine", "bits", "endian", "elf_type", "interp", "needed", "runpath",
                  "nx", "pie", "relro", "canary", "stripped", "static")
    service_fields = ("name", "start_source", "exec_path", "evidence", "ports", "ports_evidence")
    component_fields = ("kind", "asserted_identity", "identity_evidence", "confidence", "version")
    elfs = {row["path"]: _bounded(row, elf_fields) for row in elf_rows}
    components = {row["path"]: _bounded(row, component_fields) for row in component_rows}
    services: dict[object, list[dict[str, object]]] = {}
    for row in sorted(service_rows, key=lambda row: str(row["name"])):
        for path in {row["exec_path"], row["start_source"]}:
            services.setdefault(path, []).append(_bounded(row, service_fields))
    result = []
    for row in manifest:
        unit = dict(row)
        path = row["path"]
        if path in elfs:
            unit["elf"] = elfs[path]
        if path in services:
            unit["services"] = services[path][:20]
        if path in components:
            unit["component"] = components[path]
        result.append(unit)
    return result


def _units(con: sqlite3.Connection, image_id: str,
           manifest: list[dict[str, object]]) -> list[dict[str, object]]:
    return _annotate(manifest,
        _query(con, "SELECT * FROM cba_binfacts WHERE image_id=?", (image_id,)),
        _query(con, "SELECT * FROM cba_services WHERE image_id=?", (image_id,)),
        _query(con, "SELECT * FROM cba_components"))


def _worklist(image_id: str, digest: str, units: list[dict[str, object]],
              batch_size: int) -> tuple[dict[str, bytes], str, int]:
    files = {}
    batches = []
    for start in range(0, len(units), batch_size):
        batch_id = f"batch-{len(batches) + 1:04}"
        assigned = units[start:start + batch_size]
        content = canonical_bytes({"schema_version": 1, "image_id": image_id,
            "manifest_sha256": digest, "batch_id": batch_id, "units": assigned})
        name = batch_id + ".json"
        files[name] = content
        batches.append({"path": name, "sha256": hashlib.sha256(content).hexdigest(),
                        "unit_count": len(assigned)})
    files["index.json"] = canonical_bytes({"schema_version": 1, "image_id": image_id,
        "manifest_sha256": digest, "batch_size": batch_size, "unit_count": len(units), "batches": batches})
    return files, hashlib.sha256(files["index.json"]).hexdigest(), len(batches)


def _prior_units(run: Mapping[str, object]) -> list[str]:
    """Read the prior bound assignments so removed manifest units are invalidated."""
    try:
        index_path = pathlib.Path(str(run["worklist_path"]))
        content = index_path.read_bytes()
        if hashlib.sha256(content).hexdigest() != run["worklist_sha256"]:
            raise SurfaceError("Prior worklist index digest differs")
        index = json.loads(content)
        if not isinstance(index, dict) or not isinstance(index.get("batches"), list):
            raise SurfaceError("Invalid prior worklist index shape")
        if index["image_id"] != run["image_id"] or index["manifest_sha256"] != run["manifest_sha256"]:
            raise SurfaceError("Prior worklist provenance differs")
        units = []
        for batch in index["batches"]:
            if not isinstance(batch, dict):
                raise SurfaceError("Invalid prior worklist batch descriptor shape")
            name = batch["path"]
            if not isinstance(name, str) or re.fullmatch(r"batch-[0-9]{4,}\.json", name) is None:
                raise SurfaceError("Invalid prior worklist batch path")
            content = index_path.with_name(name).read_bytes()
            if hashlib.sha256(content).hexdigest() != batch["sha256"]:
                raise SurfaceError(f"Prior worklist batch digest differs: {name}")
            payload = json.loads(content)
            if (not isinstance(payload, dict) or not isinstance(payload.get("units"), list) or
                    any(not isinstance(unit, dict) for unit in payload["units"])):
                raise SurfaceError(f"Invalid prior worklist batch shape: {name}")
            if payload["image_id"] != run["image_id"] or payload["manifest_sha256"] != run["manifest_sha256"]:
                raise SurfaceError(f"Prior worklist batch provenance differs: {name}")
            if len(payload["units"]) != batch["unit_count"]:
                raise SurfaceError(f"Prior worklist batch count differs: {name}")
            units.extend(payload["units"])
        manifest = canonical_manifest(units)
        if len(manifest) != run["unit_count"] or manifest_sha256(manifest) != run["manifest_sha256"]:
            raise SurfaceError("Prior worklist manifest differs")
        return [str(unit["path"]) for unit in manifest]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SurfaceError(f"Cannot read prior surface worklist: {exc}") from exc


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
            *, image_id: str | None = None, batch_size: int = 50) -> PreparationSummary:
    """Prepare every manifest unit; hints annotate assignments but never filter them."""
    if con.in_transaction:
        raise SurfaceError("Preparation requires a connection without an active transaction")
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise SurfaceError("batch_size must be an integer from 1 to 1000")
    try:
        selected = _resolve_target(_query(con, "SELECT id,role FROM cba_images"), image_id)
        manifest = _manifest(con, selected)
        _inventory_agreement(con, manifest)
        _root_agreement(root, manifest)
        digest = manifest_sha256(manifest)
        units = _units(con, selected, manifest)
        files, worklist_digest, batch_count = _worklist(selected, digest, units, batch_size)
        prior_rows = _query(con, "SELECT * FROM cba_surface_runs WHERE image_id=?", (selected,))
        prior = prior_rows[0] if prior_rows else None
        same = prior is not None and prior["manifest_sha256"] == digest and prior["worklist_sha256"] == worklist_digest
        prior_units = _prior_units(prior) if prior is not None and not same else []
    except (sqlite3.Error, firmware_tree.FirmwareTreeError) as exc:
        raise SurfaceError(f"Cannot read surface preparation inputs: {exc}") from exc
    destination = pathlib.Path(run_dir) / "files/surface" / worklist_digest
    summary = PreparationSummary(selected, digest, worklist_digest, len(manifest), batch_count,
                                 str(destination / "index.json"))
    atomic_install(destination, files)
    try:
        con.execute("BEGIN IMMEDIATE")
        # Detect another writer replacing the prepared inputs during file installation.
        if (_resolve_target(_query(con, "SELECT id,role FROM cba_images"), image_id) != selected or
                _manifest(con, selected) != manifest or _units(con, selected, manifest) != units or
                _query(con, "SELECT * FROM cba_surface_runs WHERE image_id=?", (selected,)) != prior_rows):
            raise SurfaceError("Surface preparation inputs changed before publication")
        _inventory_agreement(con, manifest)
        _root_agreement(root, manifest)
        if same:
            con.commit()
            return summary
        if prior is not None:
            con.execute("DELETE FROM cba_firmware_surfaces WHERE image_id=?", (selected,))
            con.execute("DELETE FROM cba_unknowns WHERE image_id=?", (selected,))
            con.executemany("DELETE FROM cba_coverage WHERE phase='surface' AND unit=?",
                            [(unit,) for unit in prior_units])
        con.execute("DELETE FROM cba_surface_runs WHERE image_id=?", (selected,))
        db.put(con, "cba_surface_runs", {
            **{key: str(value) for key, value in dataclasses.asdict(summary).items()},
            "status": "pending"}, commit=False)
        con.commit()
    except Exception as exc:
        con.rollback()
        raise SurfaceError(f"Cannot publish surface preparation for {selected}: {exc}") from exc
    return summary


def _checked_worklist(con: sqlite3.Connection, run: Mapping[str, object],
                      manifest: list[dict[str, object]]) -> pathlib.Path:
    """Verify every prepared assignment, including batches with no stored claims."""
    # Local import avoids the parser's SurfaceError/surface helper import cycle.
    from audit_core import surface_results as results

    index_path = pathlib.Path(str(run["worklist_path"]))
    if len(index_path.parents) < 4:
        raise SurfaceError("Invalid prepared worklist path")
    run_dir = index_path.parents[3]
    _, index = results._read_json(index_path)
    index = results._object(index, ("schema_version", "image_id", "manifest_sha256",
        "batch_size", "unit_count", "batches"), "index")
    descriptors = results._array(index["batches"], "batches")
    if not descriptors:
        raise SurfaceError("Prepared worklist has no batches")
    assigned = []
    for descriptor in descriptors:
        descriptor = results._object(descriptor, ("path", "sha256", "unit_count"), "batch descriptor")
        result = results.BatchResult(1, str(run["image_id"]), str(run["manifest_sha256"]),
            str(run["worklist_sha256"]), descriptor["path"], descriptor["sha256"], ())
        units, _ = results._assigned(con, run_dir, result)
        assigned.extend(units)
    if sorted(assigned) != [unit["path"] for unit in manifest]:
        raise SurfaceError("Prepared assignments must cover each current manifest unit exactly once")
    return run_dir


def _checked_artifacts(con: sqlite3.Connection, run_dir: pathlib.Path,
                       coverage: Mapping[str, Mapping[str, object]],
                       surfaces: list[dict[str, object]], unknowns: list[dict[str, object]]) -> None:
    """Bind both directions of every referenced canonical result to current SQL."""
    from audit_core import surface_results as results

    artifacts = {(str(row["artifact_path"]), str(row["artifact_sha256"]))
                 for row in surfaces + unknowns}
    for artifact_path, digest in sorted(artifacts):
        path = pathlib.Path(artifact_path)
        expected = run_dir / "artifacts/surface" / digest / "result.json"
        if path.absolute() != expected.absolute():
            raise SurfaceError("Surface artifact provenance is outside the current run generation")
        for directory in (path.parent, path.parent.parent, path.parent.parent.parent):
            if directory.is_symlink():
                raise SurfaceError(f"Surface artifact directory is a symlink: {directory}")
        content, payload = results._read_json(path, bounded=True)
        if hashlib.sha256(content).hexdigest() != digest:
            raise SurfaceError(f"Surface artifact SHA-256 differs: {path}")
        validated = results.validate(con, run_dir, results._parse(payload))
        if results.canonical_bytes(validated) != content:
            raise SurfaceError(f"Surface result artifact is not canonical: {path}")
        assigned = set(validated.assigned_units)
        for table_rows, field in ((surfaces, "surfaces"), (unknowns, "unknowns")):
            actual = [{key: value for key, value in row.items() if key != "recorded_at"}
                      for row in table_rows if row["component_path"] in assigned]
            expected_rows = [dataclasses.asdict(row) | {"image_id": validated.result.image_id,
                "artifact_path": artifact_path, "artifact_sha256": digest}
                for decision in validated.result.decisions for row in getattr(decision, field)]
            if sorted(actual, key=repr) != sorted(expected_rows, key=repr):
                raise SurfaceError(f"Stored {field} differ from their bound surface artifact")
        for decision in validated.result.decisions:
            stored = coverage[decision.path]
            reason = decision.reason.strip() if decision.state == "not_audited" else decision.reason
            stored_reason = stored["reason"]
            if decision.state == "not_audited" and isinstance(stored_reason, str):
                stored_reason = stored_reason.strip()
            if stored["state"] != decision.state or stored_reason != reason:
                raise SurfaceError(f"Stored coverage differs from its bound artifact: {decision.path}")


def _check_inputs(con: sqlite3.Connection, image_id: str | None
                  ) -> tuple[SurfaceCheck, dict[str, object]]:
    """Read the uncapped denominator and reject inconsistent current claims."""
    from audit_core import surface_results as results

    selected = _resolve_target(_query(con, "SELECT id,role FROM cba_images"), image_id)
    runs = _query(con, "SELECT * FROM cba_surface_runs WHERE image_id=?", (selected,))
    if not runs:
        raise SurfaceError("No prepared surface run for target")
    run = runs[0]
    db.TABLE_SPECS["cba_surface_runs"].validate(run)
    manifest = _manifest(con, selected)
    _inventory_agreement(con, manifest)
    if run["manifest_sha256"] != manifest_sha256(manifest):
        raise SurfaceError("Current and prepared surface manifest provenance differs")
    run_dir = _checked_worklist(con, run, manifest)
    paths = {str(unit["path"]) for unit in manifest}
    coverage = {str(row["unit"]): row for row in _query(con,
        "SELECT * FROM cba_coverage WHERE phase='surface'") if row["unit"] in paths}
    if set(coverage) != paths:
        missing = sorted(paths - coverage.keys())[0]
        raise SurfaceError(f"Missing surface coverage decision for {missing}")
    for row in coverage.values():
        if row["reason"] is not None and not isinstance(row["reason"], str):
            raise SurfaceError("Surface coverage reason must be text or absent")
        db.TABLE_SPECS["cba_coverage"].validate(row)
        if row["state"] == "not_audited" and row["reason"].strip() == "budget":
            raise SurfaceError(f"Surface coverage has a budget skip: {row['unit']}")
    surfaces = _query(con, "SELECT * FROM cba_firmware_surfaces WHERE image_id=?", (selected,))
    unknowns = _query(con, "SELECT * FROM cba_unknowns WHERE image_id=?", (selected,))
    for table, rows, cls, nullable in (
            ("cba_firmware_surfaces", surfaces, results.SurfaceRecord, ()),
            ("cba_unknowns", unknowns, results.UnknownRecord, ("surface_id", "resolution", "evidence"))):
        for row in rows:
            db.TABLE_SPECS[table].validate(row)
            fields = {field.name: row[field.name] for field in dataclasses.fields(cls)}
            results._record(fields, cls, nullable)
            if row["component_path"] not in paths:
                raise SurfaceError(f"Dangling surface component: {row['component_path']}")
    by_id = {row["surface_id"]: row for row in surfaces}
    for row in surfaces:
        if coverage[row["component_path"]]["state"] != "analyzed":
            raise SurfaceError("not_audited cannot publish surfaces")
    for row in unknowns:
        if row["surface_id"] is not None:
            results._identifier(row["surface_id"], "unknown surface_id")
            linked = by_id.get(row["surface_id"])
            if linked is None or linked["component_path"] != row["component_path"]:
                raise SurfaceError("Unknown surface linkage is dangling or belongs to another component")
    open_fields = {(row["surface_id"], row["field"]) for row in unknowns if row["status"] == "open"}
    for row in surfaces:
        for column, field in (("lifecycle_required", "lifecycle"), ("posture_required", "posture"),
                              ("auth_required", "auth"), ("reachability", "reachability")):
            if row[column] == "unknown" and (row["surface_id"], field) not in open_fields:
                raise SurfaceError(f"Unknown {field} requires a matching open unknown for {row['surface_id']}")
    _checked_artifacts(con, run_dir, coverage, surfaces, unknowns)
    return SurfaceCheck(selected, len(manifest),
        sum(row["state"] == "analyzed" for row in coverage.values()),
        sum(row["state"] == "not_audited" for row in coverage.values()), len(surfaces),
        sum(row["status"] == "open" for row in unknowns),
        sum(row["status"] == "resolved" for row in unknowns), True), run


def check(con: sqlite3.Connection, *, image_id: str | None = None) -> SurfaceCheck:
    """Certify current surface completeness; this is the sole completion transition."""
    started = False
    try:
        if con.in_transaction:
            raise SurfaceError("Surface check requires a connection without an active transaction")
        summary, run = _check_inputs(con, image_id)
        con.execute("BEGIN IMMEDIATE")
        started = True
        # Validation before locking is diagnostic only. All SQL and file evidence
        # is re-read while other SQL writers cannot publish another generation.
        current, current_run = _check_inputs(con, image_id)
        if current != summary or current_run != run:
            raise SurfaceError("Surface check inputs changed before completion")
        if run["status"] != "complete":
            con.execute("UPDATE cba_surface_runs SET status='complete',completed_at=datetime('now') WHERE image_id=?",
                        (summary.image_id,))
        con.commit()
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, OSError, db.DbError)):
            raise SurfaceError(f"Cannot check surface completeness: {exc}") from exc
        raise
