"""An asserted identity needs evidence that is not the component's own name.

From the tplink post-mortem: `km0_boot_0C000020.elf` was treated as a
bootloader for the whole run because of what it is called. It holds the
Realtek Wi-Fi driver and several reference-set CRITICALs, and no finding in
that run sits below the IP layer.

The rule is narrow on purpose. It cannot tell a good identification from a
bad one. It can tell a circular one from a non-circular one, which is the
specific mistake this project has made, and a broader rule over English
evidence prose would fire on legitimate text and get switched off.
"""
from __future__ import annotations

import sqlite3

from audit_core import db


MIN_EVIDENCE_CHARS = db.MIN_EVIDENCE_CHARS
check_evidence = db.check_identity_evidence


def record(con: sqlite3.Connection, *, path: str, kind: str, identity: str,
           evidence: str, confidence: str = "", version: str = "",
           replace: bool = False) -> None:
    row = {"path": path, "kind": kind, "asserted_identity": identity,
           "identity_evidence": evidence}
    # Optional columns are OMITTED when not given, not written as "": on
    # --replace db.put merges over the stored row, so an absent key keeps its
    # value and a present one overwrites it.
    for key, value in (("confidence", confidence), ("version", version)):
        if value:
            row[key] = value
    db.put(con, "cba_components", row, replace=replace)


def render(rows: list[sqlite3.Row]) -> str:
    if not rows:
        return ("components: none asserted.\n"
                "  Record what each analysed artifact actually is, with the "
                "evidence, using `audit.py identify`. A filename is an "
                "assertion by whoever named it.")
    out = [f"components: {len(rows)} asserted"]
    for r in rows:
        conf = f" (confidence {r['confidence']})" if r["confidence"] else ""
        out.append(f"  {r['path']}")
        out.append(f"    {r['kind']}: {r['asserted_identity']}{conf}")
        out.append(f"    evidence: {r['identity_evidence']}")
    return "\n".join(out)
