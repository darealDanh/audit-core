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
