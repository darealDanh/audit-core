"""Golden reference sets and adjudicated match records."""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass


class GoldenError(Exception):
    """A golden file is malformed."""


@dataclass(frozen=True, slots=True)
class Reference:
    id: str
    title: str
    cwe: str | None
    locations: tuple[str, ...]
    root_cause_key: str
    severity: str


_REQUIRED = ("id", "title", "locations", "root_cause_key", "severity")


def load_reference(path: str | pathlib.Path) -> list[Reference]:
    path = pathlib.Path(path)
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise GoldenError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, list):
        raise GoldenError(f"{path}: expected a list of reference objects")

    refs: list[Reference] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        for key in _REQUIRED:
            if key not in item:
                raise GoldenError(f"{path}[{i}]: missing '{key}'")
        if not item["locations"]:
            raise GoldenError(f"{path}[{i}]: 'locations' must be non-empty")
        if item["id"] in seen:
            raise GoldenError(f"{path}: duplicate reference id {item['id']}")
        seen.add(item["id"])
        refs.append(Reference(
            id=item["id"], title=item["title"], cwe=item.get("cwe"),
            locations=tuple(item["locations"]),
            root_cause_key=item["root_cause_key"], severity=item["severity"],
        ))
    return refs


def load_matches(path: str | pathlib.Path) -> dict[str, str]:
    path = pathlib.Path(path)
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise GoldenError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise GoldenError(f"{path}: expected an object mapping reference id to finding id")
    return {str(k): str(v) for k, v in raw.items()}


def load_rejections(path: str | pathlib.Path) -> set[tuple[str, str]]:
    """Pairs a human has looked at and rejected.

    matches.json records adjudicated matches; nothing recorded adjudicated
    non-matches, so the two false REF-10 pairs resurfaced on every scoring run
    and cost a fresh adjudication each time. A rejection must carry a reason:
    one without is indistinguishable from a mistake, and it silences a
    candidate permanently.
    """
    path = pathlib.Path(path)
    if not path.is_file():
        return set()
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise GoldenError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, list):
        raise GoldenError(f"{path}: expected a list of rejection objects")
    out: set[tuple[str, str]] = set()
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise GoldenError(f"{path}[{i}]: expected an object")
        for key in ("reference_id", "finding_id", "reason"):
            if not str(item.get(key, "")).strip():
                raise GoldenError(f"{path}[{i}]: missing '{key}'")
        out.add((str(item["reference_id"]), str(item["finding_id"])))
    return out
