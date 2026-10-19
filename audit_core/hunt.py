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
