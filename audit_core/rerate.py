"""Does a finding's severity match the evidence the finding itself cites?

A severity is a claim about reachability and consequence. The pipeline fixes
it at discovery time, before chain composition runs, so a finding scored on
its own mechanism never gets re-read once its reach is understood. On tplink
that cost four of nine matches a correct rating, the worst being a
pre-authentication authentication bypass filed LOW.

This module REPORTS. It opens nothing for writing, stores no row, and changes
no severity. The mutating version stays unbuilt until a benchmark run can
show it helps; this report is the evidence for that decision, gathered at
zero cost and zero risk.

Known limitation: matches are not negation-aware. G4-F4 on the tplink corpus
is the known instance: its text reads "rather than an authentication bypass"
while its attacker_position is `authenticated-user`, yet the auth-bypass rule
fires. A negation guard is deferred until a second corpus shows the pattern
recurs; one example is not enough evidence, and a guard tuned to it would be
corpus overfitting (a look-back guard would also have suppressed G2-F6, a true
positive, over an unrelated "not" in a neighbouring column).

Precedent for the shape: `coverage --gate` reports and does not block.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass

from audit_core.db import SEVERITIES
from audit_core.readings import ABSENT, table_state

_TEXT_COLUMNS = ("title", "root_cause", "impact", "attacker_position",
                 "boundary_crossed", "data_flow", "poc")


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    pattern: re.Pattern
    floor: str
    why: str


RULES: tuple[Rule, ...] = (
    Rule("unauthenticated-reach",
         re.compile(r"\b(?:un[- ]?authenticated|pre[- ]?auth(?:entication)?|"
                    r"without\s+(?:any\s+)?authentication|"
                    r"no\s+authentication\s+(?:is\s+)?required)\b", re.I),
         "HIGH",
         "the finding's own text says it is reachable without credentials"),
    Rule("auth-bypass",
         re.compile(r"\b(?:auth(?:entication|orization)?\s+bypass|"
                    r"bypass(?:es|ing)?\s+(?:the\s+)?auth(?:entication|orization)?|"
                    r"access\s+control\s+bypass)\b", re.I),
         "HIGH",
         "the finding's own text describes bypassing an authentication or "
         "authorization check"),
)
"""Deliberately few, and each one quotes the finding back at itself.

A rule that infers severity from something the finding does not say is a
guess wearing a rule's clothes. Every rule here fires on language the audit
itself wrote, so the report can always answer "why is this flagged" with a
quotation.
"""

CHAIN_FLOOR = "CRITICAL"
"""Floor for membership of a chain marked pre-auth.

A bug reachable without credentials, as one step of a chain somebody has
already composed, is the shape of every finding in the reference set.

NOTE: this floor has never run on any corpus. The only real audit database
has no `cba_chains` table, so the pre-auth-chain rule is untested against
real data.
"""


@dataclass(frozen=True, slots=True)
class Signal:
    rule: str
    evidence: str
    column: str = ""


@dataclass(frozen=True, slots=True)
class Flag:
    finding_id: str
    severity: str
    implied_floor: str
    signals: tuple[Signal, ...]


def _rank(severity: str) -> int | None:
    try:
        return SEVERITIES.index((severity or "").strip().upper())
    except ValueError:
        return None


def _excerpt(text: str, match: re.Match, width: int = 60) -> str:
    """`text` must already be whitespace-collapsed (match offsets refer to it)."""
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    return ("..." if start else "") + text[start:end].strip() + (
        "..." if end < len(text) else "")


def _pre_auth_chain_members(con: sqlite3.Connection) -> set[str]:
    """Finding ids belonging to a chain whose `pre_auth` is affirmative.

    `cba_chains.finding_ids` is a comma-separated list, so this splits rather
    than joins. An absent table yields an empty set, and the caller says so
    in the report rather than pretending the rule ran.

    `pre_auth` is free TEXT and no format is pinned anywhere in the repo. The
    accepted values are exactly "1", "true" and "yes" (case-insensitive);
    anything else, including "yes - before login", is treated as NOT pre-auth.
    """
    if table_state(con, "cba_chains") == ABSENT:
        return set()
    members: set[str] = set()
    for (ids, pre_auth) in con.execute(
            "SELECT finding_ids, pre_auth FROM cba_chains"):
        if str(pre_auth or "").strip().lower() not in ("1", "true", "yes"):
            continue
        members.update(p.strip() for p in str(ids or "").split(",") if p.strip())
    return members


def examine(con: sqlite3.Connection) -> tuple[Flag, ...]:
    """Every finding rated below the floor its own evidence implies."""
    chain_members = _pre_auth_chain_members(con)
    columns = ", ".join(("id", "severity") + _TEXT_COLUMNS)
    flags: list[Flag] = []

    for row in con.execute(f"SELECT {columns} FROM cba_findings ORDER BY id"):
        finding_id, severity = row[0], row[1]
        cells = [(name, " ".join(str(c).split()))
                 for name, c in zip(_TEXT_COLUMNS, row[2:]) if c]

        signals: list[Signal] = []
        floors: list[str] = []
        for rule in RULES:
            for name, text in cells:
                match = rule.pattern.search(text)
                if match:
                    signals.append(Signal(rule.id, _excerpt(text, match), name))
                    floors.append(rule.floor)
                    break
        if finding_id in chain_members:
            signals.append(Signal(
                "pre-auth-chain",
                "member of a composed chain recorded as pre_auth",
                "cba_chains"))
            floors.append(CHAIN_FLOOR)

        if not floors:
            continue
        floor = min(floors, key=lambda s: SEVERITIES.index(s))
        found_rank, floor_rank = _rank(severity), SEVERITIES.index(floor)
        if found_rank is None or found_rank <= floor_rank:
            continue        # correctly rated, or rated higher; say nothing
        flags.append(Flag(finding_id, severity, floor, tuple(signals)))

    return tuple(flags)


def render(flags: tuple[Flag, ...], *, chains_absent: bool = False) -> str:
    if not flags:
        out = ["rerate: no finding is rated below the floor its own evidence "
               "implies."]
    else:
        out = [f"rerate: {len(flags)} finding(s) rated below the floor their "
               f"own evidence implies.", ""]
        for f in flags:
            out.append(f"  {f.finding_id}  filed {f.severity}, "
                       f"evidence implies at least {f.implied_floor}")
            for s in f.signals:
                where = f" in {s.column}" if s.column else ""
                out.append(f"      [{s.rule}{where}] {s.evidence}")
            out.append("")
    out.append("This is advisory. No severity has been changed and no row "
               "written; re-rating is a judgement for a human, and the "
               "mutating version is unbuilt until a benchmark run can show "
               "it helps.")
    if chains_absent:
        out.append("The pre-auth-chain rule did not run: cba_chains is not "
                   "in this database.")
    return "\n".join(out)
