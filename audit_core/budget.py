"""Economics of a Claude Code session: epochs, prefix, growth, attribution."""
from __future__ import annotations

import statistics
from dataclasses import dataclass

from audit_core.transcript import Transcript, Turn


@dataclass(frozen=True, slots=True)
class Epoch:
    index: int
    turns: int
    floor: int
    peak: int
    mean: int
    total: int
    growth_per_turn: float


@dataclass(frozen=True, slots=True)
class Stats:
    turns: int
    sum_context: int
    mean_context: int
    median_context: int
    p90_context: int
    max_context: int
    prefix_floor: int
    growth_per_turn: float


def _billed(turns: list[Turn]) -> list[Turn]:
    """Turns that cost context. Continuation iterations report 0."""
    return [t for t in turns if t.context > 0]


def epochs_of(t: Transcript) -> list[Epoch]:
    by_epoch: dict[int, list[Turn]] = {}
    for turn in _billed(t.turns):
        by_epoch.setdefault(turn.epoch, []).append(turn)

    out: list[Epoch] = []
    for i, key in enumerate(sorted(by_epoch)):
        ctx = [x.context for x in by_epoch[key]]
        span = max(ctx) - min(ctx)
        gaps = len(ctx) - 1
        out.append(Epoch(
            index=i,
            turns=len(ctx),
            floor=min(ctx),
            peak=max(ctx),
            mean=sum(ctx) // len(ctx),
            total=sum(ctx),
            growth_per_turn=(span / gaps) if gaps else 0.0,
        ))
    return out


def stats_of(t: Transcript) -> Stats:
    ctx = sorted(x.context for x in _billed(t.turns))
    if not ctx:
        return Stats(0, 0, 0, 0, 0, 0, 0, 0.0)
    eps = epochs_of(t)
    weighted = sum(e.growth_per_turn * e.turns for e in eps)
    total_turns = sum(e.turns for e in eps)
    return Stats(
        turns=len(ctx),
        sum_context=sum(ctx),
        mean_context=sum(ctx) // len(ctx),
        median_context=int(statistics.median(ctx)),
        p90_context=ctx[min(int(len(ctx) * 0.9), len(ctx) - 1)],
        max_context=ctx[-1],
        prefix_floor=min(e.floor for e in eps),
        growth_per_turn=(weighted / total_turns) if total_turns else 0.0,
    )
