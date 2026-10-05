"""Economics of a Claude Code session: epochs, prefix, growth, attribution."""
from __future__ import annotations

import statistics
from dataclasses import dataclass

from audit_core.transcript import Transcript, Turn, model_usage_context


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


@dataclass(frozen=True, slots=True)
class Report:
    session_id: str
    path: str
    stats: Stats
    epochs: list[Epoch]
    composition: dict[str, int]
    attribution: dict[str, int]
    prefix_term: int
    accumulation_term: int
    cost_usd: float | None
    tool_result_tokens: int
    tool_input_tokens: int
    tool_calls_by_name: dict[str, int]
    model_usage_context: int = 0


def analyze(t: Transcript) -> Report:
    stats = stats_of(t)
    eps = epochs_of(t)

    # Last billed turn index within each epoch, for residency.
    last_turn: dict[int, int] = {}
    for turn in _billed(t.turns):
        last_turn[turn.epoch] = max(last_turn.get(turn.epoch, 0), turn.index)

    composition: dict[str, int] = {}
    attribution: dict[str, int] = {}
    for a in t.additions:
        composition[a.component] = composition.get(a.component, 0) + a.tokens
        if a.epoch not in last_turn:
            continue
        resident = max(0, last_turn[a.epoch] - a.turn_index + 1)
        attribution[a.component] = attribution.get(a.component, 0) + a.tokens * resident

    prefix_term = sum(e.floor * e.turns for e in eps)
    tool_calls_by_name: dict[str, int] = {}
    for call in t.tool_calls:
        tool_calls_by_name[call.name] = tool_calls_by_name.get(call.name, 0) + 1

    return Report(
        session_id=t.session_id,
        path=t.path,
        stats=stats,
        epochs=eps,
        composition=composition,
        attribution=attribution,
        prefix_term=prefix_term,
        accumulation_term=stats.sum_context - prefix_term,
        cost_usd=t.cost_usd,
        tool_result_tokens=sum(c.result_tokens for c in t.tool_calls),
        tool_input_tokens=sum(c.input_tokens for c in t.tool_calls),
        tool_calls_by_name=tool_calls_by_name,
        model_usage_context=model_usage_context(t.model_usage),
    )


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:5.1f}%" if whole else "    - "


def render(r: Report) -> str:
    s = r.stats
    out: list[str] = []
    out.append(f"session {r.session_id}  ({r.path})")
    cost = f"${r.cost_usd:.2f}" if r.cost_usd is not None else "unknown"
    out.append(f"  cost {cost}   turns {s.turns}   epochs {len(r.epochs)}")
    out.append(f"  sum_context {s.sum_context:,}   mean {s.mean_context:,}   "
               f"median {s.median_context:,}   p90 {s.p90_context:,}   max {s.max_context:,}")
    out.append(f"  prefix_floor {s.prefix_floor:,}   growth {s.growth_per_turn:,.0f} tok/turn")
    out.append(f"  prefix term      {r.prefix_term:,} ({_pct(r.prefix_term, s.sum_context)})")
    out.append(f"  accumulation     {r.accumulation_term:,} "
               f"({_pct(r.accumulation_term, s.sum_context)})")
    ratio = (f"{s.sum_context / r.model_usage_context:.2f}x"
             if r.model_usage_context else "n/a")
    out.append(f"  reconciliation   parsed sum_context {s.sum_context:,}  vs  "
               f"modelUsage {r.model_usage_context:,}  (ratio {ratio})")
    out.append("                   modelUsage is model-reported and counts "
               "subagent usage whose turns")
    out.append("                   are not in this transcript, so a large "
               "divergence is expected there.")
    out.append("")
    out.append(f"  {'component':40s} {'added':>12s} {'share':>7s} {'attributed':>14s}")
    total_added = sum(r.composition.values())
    for name, tokens in sorted(r.composition.items(), key=lambda kv: -kv[1]):
        out.append(f"  {name:40s} {tokens:12,} {_pct(tokens, total_added)} "
                   f"{r.attribution.get(name, 0):14,}")
    out.append("")
    out.append(f"  {'epoch':>5s} {'turns':>6s} {'floor':>10s} {'peak':>10s} "
               f"{'mean':>10s} {'g/turn':>9s}")
    for e in r.epochs:
        out.append(f"  {e.index:5d} {e.turns:6d} {e.floor:10,} {e.peak:10,} "
                   f"{e.mean:10,} {e.growth_per_turn:9,.0f}")
    return "\n".join(out)
