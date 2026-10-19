"""Prepare complete, independently batched firmware hunts bound to surface evidence."""
from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import sqlite3

from audit_core import db, firmware_tree, surface


class HuntError(Exception):
    """Hunt work cannot be published without misleading assignments."""


@dataclasses.dataclass(frozen=True, slots=True)
class LanePreparation:
    lane: str
    worklist_sha256: str
    unit_count: int
    batch_count: int
    worklist_path: str


@dataclasses.dataclass(frozen=True, slots=True)
class PreparationSummary:
    image_id: str
    manifest_sha256: str
    surface_snapshot_sha256: str
    generation: str
    lanes: tuple[LanePreparation, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class LaneCheck:
    image_id: str
    lane: str
    manifest_units: int
    analyzed: int
    not_applicable: int
    not_audited: int
    receipts: int
    candidates: int
    blockers: int
    complete: bool


@dataclasses.dataclass(frozen=True, slots=True)
class HuntCheck:
    image_id: str
    manifest_sha256: str
    surface_snapshot_sha256: str
    lanes: tuple[LaneCheck, ...]
    complete: bool


def _units(con: sqlite3.Connection, image_id: str,
           manifest: list[dict[str, object]]) -> list[dict[str, object]]:
    """Advisory context never changes the manifest denominator or carries host metadata."""
    query = surface._query
    owners: dict[object, set[object]] = {}
    for row in query(con, "SELECT image_id,path FROM cba_firmware_files"):
        owners.setdefault(row["path"], set()).add(row["image_id"])
    # Global component keys cannot distinguish two images sharing a raw path.
    components = [row for row in query(con, "SELECT * FROM cba_components")
                  if owners.get(row["path"]) == {image_id}]
    units = surface._annotate(manifest,
        query(con, "SELECT * FROM cba_binfacts WHERE image_id=?", (image_id,)),
        query(con, "SELECT * FROM cba_services WHERE image_id=?", (image_id,)), components)
    by_path = {row["path"]: row for row in units}
    fields = {
        "surfaces": ("surface_id", "entry_point", "protocol", "dispatch_path", "handler",
                     "lifecycle_required", "posture_required", "auth_required", "reachability", "reach_evidence"),
        "unknowns": ("id", "surface_id", "field", "question", "settling_observation", "method",
                     "status", "resolution", "evidence"),
        "diffs": ("diff_id", "change", "reference_kind", "target_kind", "reference_size",
                  "target_size", "reference_sha256", "target_sha256"),
        "fix_observations": ("id", "group_id", "observation", "location"),
    }
    for table, key, identifier in (("cba_firmware_surfaces", "surfaces", "surface_id"),
                                    ("cba_unknowns", "unknowns", "id")):
        for row in sorted(query(con, f"SELECT * FROM {table} WHERE image_id=?", (image_id,)),
                          key=lambda row: str(row[identifier])):
            if row["component_path"] in by_path:
                hints = by_path[row["component_path"]].setdefault(key, [])
                if len(hints) < 20:
                    hints.append(surface._bounded(row, fields[key]))
    entries = query(con, "SELECT e.* FROM cba_diff_entries e JOIN cba_diffs d ON d.id=e.diff_id "
                        "WHERE d.target_image_id=?", (image_id,))
    groups: dict[object, set[str]] = {}
    for row in sorted(entries, key=lambda row: (str(row["diff_id"]), str(row["path"]))):
        unit = by_path.get(row["path"])
        if unit is None or any(row["target_" + field] != unit[field] for field in ("kind", "size", "sha256")):
            continue
        hints = unit.setdefault("diffs", [])
        if len(hints) < 20:
            hints.append(surface._bounded(row, fields["diffs"]))
        groups.setdefault(row["path"], set()).add("diff-" + str(row["diff_id"]))
    observations = sorted(query(con, "SELECT * FROM cba_security_observations"),
                          key=lambda row: (str(row["group_id"]), row["id"]))
    for path, applicable in groups.items():
        hints = [surface._bounded(row, fields["fix_observations"])
                 for row in observations if row["group_id"] in applicable][:20]
        if hints:
            by_path[path]["fix_observations"] = hints
    return units


def _worklist(image_id: str, manifest_digest: str, snapshot_digest: str, lane: str,
              units: list[dict[str, object]], batch_size: int) -> tuple[dict[str, bytes], str, int]:
    identity = {"schema_version": 1, "image_id": image_id, "lane": lane,
                "manifest_sha256": manifest_digest, "surface_snapshot_sha256": snapshot_digest}
    files = {}
    batches = []
    for start in range(0, len(units), batch_size):
        batch_id = f"batch-{len(batches) + 1:04}"
        assigned = units[start:start + batch_size]
        content = surface.canonical_bytes(identity | {"batch_id": batch_id, "units": assigned})
        name = batch_id + ".json"
        files[name] = content
        batches.append({"path": name, "sha256": hashlib.sha256(content).hexdigest(), "unit_count": len(assigned)})
    files["index.json"] = surface.canonical_bytes(identity | {
        "batch_size": batch_size, "unit_count": len(units), "batches": batches})
    return files, hashlib.sha256(files["index.json"]).hexdigest(), len(batches)


def _inputs(con: sqlite3.Connection, run_dir: pathlib.Path, root: str | pathlib.Path,
            image_id: str | None) -> tuple[str, list[dict[str, object]], surface.SurfaceSnapshot,
                                           list[dict[str, object]], list[dict[str, object]]]:
    selected = surface._resolve_target(surface._query(con, "SELECT id,role FROM cba_images"), image_id)
    bound = surface.verified_snapshot(con, run_dir, image_id=selected)
    manifest = surface._manifest(con, selected)
    surface._inventory_agreement(con, selected, manifest)
    surface._root_agreement(root, manifest)
    units = _units(con, selected, manifest)
    prior = sorted(surface._query(con, "SELECT * FROM cba_hunt_runs WHERE image_id=?", (selected,)),
                   key=lambda row: str(row["lane"]))
    return selected, manifest, bound, units, prior


def _refuse_unqualified_coverage(con: sqlite3.Connection) -> None:
    prefixes = tuple(db.firmware_unit_key(str(row["id"]), "")
                     for row in surface._query(con, "SELECT id FROM cba_images")
                     if row["id"] != db.FIRMWARE_IMAGE_UNSCOPED)
    for row in surface._query(con, "SELECT unit FROM cba_coverage WHERE phase IN ('hunt-l-sink','hunt-l-dark')"):
        if not row["unit"].startswith(prefixes):
            raise HuntError("Ambiguous unqualified legacy hunt coverage ownership; use a fresh run")


def _clear_image(con: sqlite3.Connection, image_id: str) -> None:
    """Private preparation invalidator; shared upstream invalidation is a later task."""
    _refuse_unqualified_coverage(con)
    prefix = db.firmware_unit_key(image_id, "")
    keys = [(row["unit"], row["phase"]) for row in surface._query(con,
        "SELECT unit,phase FROM cba_coverage WHERE phase IN ('hunt-l-sink','hunt-l-dark')")
        if row["unit"].startswith(prefix)]
    con.executemany("DELETE FROM cba_coverage WHERE unit=? AND phase=?", keys)
    for table in ("cba_hunt_candidates", "cba_hunt_receipts", "cba_hunt_runs"):
        con.execute(f"DELETE FROM {table} WHERE image_id=?", (image_id,))


def _checked_install(destination: pathlib.Path, files: dict[str, bytes]) -> None:
    """Re-read installed evidence while holding the SQL publication lock."""
    for directory in (destination, destination.parent, destination.parent.parent, destination.parent.parent.parent):
        if directory.is_symlink() or not directory.is_dir():
            raise HuntError("Invalid installed hunt worklist directory")
    if {path.name for path in destination.iterdir()} != set(files):
        raise HuntError("Installed hunt generation has different artifacts")
    for name, expected in files.items():
        path = destination / name
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise HuntError("Installed hunt worklist differs before publication")


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
            *, image_id: str | None = None, sink_batch_size: int = 50,
            dark_batch_size: int = 50) -> PreparationSummary:
    """Install both immutable lane worklists, then atomically publish their pending rows."""
    if con.in_transaction:
        raise HuntError("Preparation requires a connection without an active transaction")
    for name, size in (("sink_batch_size", sink_batch_size), ("dark_batch_size", dark_batch_size)):
        if type(size) is not int or not 1 <= size <= 1000:
            raise HuntError(f"{name} must be an integer from 1 to 1000")
    run_dir = pathlib.Path(run_dir)
    started = False
    try:
        inputs = _inputs(con, run_dir, root, image_id)
        selected, manifest, bound, units, prior = inputs
        definitions = {lane: _worklist(selected, bound.manifest_sha256, bound.snapshot_sha256, lane, units, size)
                       for lane, size in zip(db.HUNT_LANES, (sink_batch_size, dark_batch_size))}
        generation = hashlib.sha256(surface.canonical_bytes({
            "image_id": selected, "manifest_sha256": bound.manifest_sha256,
            "surface_snapshot_sha256": bound.snapshot_sha256,
            "lanes": {lane: value[1] for lane, value in definitions.items()}})).hexdigest()
        destination = run_dir / "files/hunt" / generation
        lanes = tuple(LanePreparation(lane, value[1], len(manifest), value[2],
                                      str(destination / lane / "index.json"))
                      for lane, value in definitions.items())
        summary = PreparationSummary(selected, bound.manifest_sha256, bound.snapshot_sha256, generation, lanes)
        records = [{"image_id": selected, "lane": lane.lane, "manifest_sha256": bound.manifest_sha256,
            "surface_snapshot_sha256": bound.snapshot_sha256, "worklist_sha256": lane.worklist_sha256,
            "worklist_path": lane.worklist_path, "unit_count": lane.unit_count, "batch_count": lane.batch_count}
            for lane in lanes]
        same = len(prior) == len(records) and all(
            all(row[key] == value for key, value in record.items())
            for row, record in zip(prior, sorted(records, key=lambda row: row["lane"])))
        if not same:
            _refuse_unqualified_coverage(con)
        for lane, (files, _, _) in definitions.items():
            surface.atomic_install(destination / lane, files)
        con.execute("BEGIN IMMEDIATE")
        started = True
        if _inputs(con, run_dir, root, image_id) != inputs:
            raise HuntError("Hunt preparation inputs changed before publication")
        for lane, (files, _, _) in definitions.items():
            _checked_install(destination / lane, files)
        if not same:
            _clear_image(con, selected)
            for record in records:
                db.put(con, "cba_hunt_runs", {**{key: str(value) for key, value in record.items()},
                                             "status": "pending"}, commit=False)
        con.commit()
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, OSError, db.DbError, firmware_tree.FirmwareTreeError, surface.SurfaceError)):
            raise HuntError(f"Cannot prepare firmware hunt: {exc}") from exc
        raise


def _checked_lane(con: sqlite3.Connection, run_dir: pathlib.Path, run: dict[str, object],
                  manifest: list[dict[str, object]]) -> tuple[LaneCheck, tuple]:
    """Receipts, rather than artifact discovery, enumerate all evidence to verify."""
    from audit_core import hunt_results as results

    image_id, lane = str(run["image_id"]), str(run["lane"])
    db.TABLE_SPECS["cba_hunt_runs"].validate(run)
    if (run["status"] == "complete") != (run["completed_at"] is not None):
        raise HuntError("Hunt completion status and timestamp disagree")
    index_path = pathlib.Path(str(run["worklist_path"]))
    _, index = results._read_json(index_path)
    if not isinstance(index, dict) or not isinstance(index.get("batches"), list):
        raise HuntError("Invalid prepared hunt index")
    receipts = surface._query(con, "SELECT * FROM cba_hunt_receipts WHERE image_id=? AND lane=? "
                              "ORDER BY worklist_sha256,batch_path", (image_id, lane))
    descriptors = index["batches"]
    if any(not isinstance(row, dict) or not isinstance(row.get("path"), str) for row in descriptors):
        raise HuntError("Invalid prepared hunt batch descriptor")
    if (len(receipts) != run["batch_count"] or
            any(row["worklist_sha256"] != run["worklist_sha256"] for row in receipts) or
            {row["batch_path"] for row in receipts} != {row["path"] for row in descriptors}):
        raise HuntError("Every hunt batch requires exactly one current owned receipt")
    decisions = {}
    expected_candidates = {}
    blockers = 0
    for receipt in receipts:
        db.TABLE_SPECS["cba_hunt_receipts"].validate(receipt)
        path = pathlib.Path(receipt["result_path"])
        content, raw = results._read_json(path, bounded=True)
        validated = results.validate(con, run_dir, results._parse(raw))
        result = validated.result
        if (result.image_id, result.lane, result.worklist_sha256, result.batch_path, result.batch_sha256) != (
                image_id, lane, run["worklist_sha256"], receipt["batch_path"], receipt["batch_sha256"]):
            raise HuntError("Hunt receipt and result ownership differ")
        digest = hashlib.sha256(content).hexdigest()
        expected_path = (run_dir / "artifacts/hunt" / index_path.parent.parent.name / lane / digest / "result.json")
        if (content != results.canonical_bytes(validated) or digest != receipt["result_sha256"] or
                path.absolute() != expected_path.absolute()):
            raise HuntError("Hunt receipt does not name its canonical result")
        results._artifact_directories(run_dir.absolute(), path.parent.absolute())
        count = sum(len(unit.candidates) for unit in result.decisions)
        if receipt["unit_count"] != len(result.decisions) or receipt["candidate_count"] != count:
            raise HuntError("Hunt receipt counts disagree with its result")
        for decision in result.decisions:
            if decision.path in decisions:
                raise HuntError("Duplicate hunt decision ownership")
            if decision.disposition == "not_audited" and decision.reason == "budget":
                raise HuntError("Hunt lane has a budget skip")
            decisions[decision.path] = decision
            for candidate in decision.candidates:
                if candidate.candidate_id in expected_candidates:
                    raise HuntError("Duplicate hunt candidate ownership")
                row = dataclasses.asdict(candidate)
                for column in ("surface_ids", "blockers"):
                    row[column] = surface.canonical_bytes(row[column]).decode("utf-8").removesuffix("\n")
                expected_candidates[candidate.candidate_id] = row | {
                    "image_id": image_id, "lane": lane, "artifact_path": str(path), "artifact_sha256": digest}
                blockers += len(candidate.blockers)
    if set(decisions) != {unit["path"] for unit in manifest}:
        raise HuntError("Hunt decisions do not cover the complete manifest")
    prefix = db.firmware_unit_key(image_id, "")
    coverage = [row for row in surface._query(con,
        "SELECT * FROM cba_coverage WHERE phase=? ORDER BY unit", ("hunt-" + lane,))
        if row["unit"].startswith(prefix)]
    expected_coverage = {db.firmware_unit_key(image_id, unit.path): (
        "not_audited" if unit.disposition == "not_audited" else "analyzed", unit.reason)
        for unit in decisions.values()}
    if {row["unit"] for row in coverage} != set(expected_coverage):
        raise HuntError("Hunt coverage does not match the complete lane denominator")
    for row in coverage:
        db.TABLE_SPECS["cba_coverage"].validate(row)
        if (row["state"], row["reason"]) != expected_coverage[row["unit"]]:
            raise HuntError("Hunt coverage differs from its owning decision")
    candidates = surface._query(con, "SELECT * FROM cba_hunt_candidates WHERE image_id=? AND lane=? "
                                "ORDER BY candidate_id", (image_id, lane))
    actual_candidates = {}
    for row in candidates:
        db.TABLE_SPECS["cba_hunt_candidates"].validate(row)
        actual_candidates[row["candidate_id"]] = {key: value for key, value in row.items() if key != "recorded_at"}
    if actual_candidates != expected_candidates:
        raise HuntError("Hunt candidates differ from their owning canonical results")
    summary = LaneCheck(image_id, lane, len(manifest),
        sum(unit.disposition == "analyzed" for unit in decisions.values()),
        sum(unit.disposition == "not_applicable" for unit in decisions.values()),
        sum(unit.disposition == "not_audited" for unit in decisions.values()),
        len(receipts), len(candidates), blockers, True)
    return summary, (receipts, coverage, candidates)


def _check_inputs(con: sqlite3.Connection, run_dir: pathlib.Path, root: str | pathlib.Path,
                  image_id: str | None, lane: str | None) -> tuple[HuntCheck, tuple]:
    selected = surface._resolve_target(surface._query(con, "SELECT id,role FROM cba_images"), image_id)
    bound = surface.verified_snapshot(con, run_dir, image_id=selected, require_complete=True)
    manifest = surface._manifest(con, selected)
    surface._inventory_agreement(con, selected, manifest)
    surface._root_agreement(root, manifest)
    _refuse_unqualified_coverage(con)
    runs = surface._query(con, "SELECT * FROM cba_hunt_runs WHERE image_id=? ORDER BY lane", (selected,))
    if len(runs) != 2 or {row["lane"] for row in runs} != set(db.HUNT_LANES):
        raise HuntError("Both prepared hunt lanes are required")
    for row in runs:
        db.TABLE_SPECS["cba_hunt_runs"].validate(row)
        if (row["manifest_sha256"], row["surface_snapshot_sha256"]) != (bound.manifest_sha256, bound.snapshot_sha256):
            raise HuntError("Prepared hunt manifest or surface snapshot differs")
    if lane is None and any(row["status"] != "complete" for row in runs):
        raise HuntError("Both hunt lanes must already be complete before the final check")
    by_lane = {row["lane"]: row for row in runs}
    checked = [_checked_lane(con, run_dir, by_lane[name], manifest)
               for name in (db.HUNT_LANES if lane is None else (lane,))]
    summary = HuntCheck(selected, bound.manifest_sha256, bound.snapshot_sha256,
                        tuple(value[0] for value in checked), True)
    return summary, (bound, manifest, runs, tuple(value[1] for value in checked))


def check(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
          *, image_id: str | None = None, lane: str | None = None) -> HuntCheck:
    """Complete one evidence-bound lane, or read-only certify two completed lanes."""
    started = False
    try:
        if con.in_transaction:
            raise HuntError("Hunt check requires a connection without an active transaction")
        if lane is not None and lane not in db.HUNT_LANES:
            raise HuntError("Invalid hunt lane")
        inputs = _check_inputs(con, pathlib.Path(run_dir), root, image_id, lane)
        con.execute("BEGIN IMMEDIATE")
        started = True
        if _check_inputs(con, pathlib.Path(run_dir), root, image_id, lane) != inputs:
            raise HuntError("Hunt check inputs changed before completion")
        summary = inputs[0]
        if lane is not None:
            con.execute("UPDATE cba_hunt_runs SET status='complete',completed_at=datetime('now') "
                        "WHERE image_id=? AND lane=? AND status='pending'", (summary.image_id, lane))
        con.commit()
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, OSError, db.DbError, firmware_tree.FirmwareTreeError, surface.SurfaceError)):
            raise HuntError("Cannot check firmware hunt completeness") from exc
        raise
