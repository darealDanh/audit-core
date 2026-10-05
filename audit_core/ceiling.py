"""The context ceiling and its checkpoint (spec R3).

Cost is the sum of context over turns, so a session pays for its own history
on every remaining turn. Under the model context(n) = prefix + g*n, the total
over a 1,000-turn workload is flat between a 70k and a 120k ceiling and climbs
steeply above it. 100k is chosen: within 4% of the numeric minimum, and 92
turns per segment instead of 58, which matters for phase continuity.

Two limits shape this module. No client exposes the orchestrator's live
context size, so nothing here watches a number and fires; it answers how many
turns a phase gets, and records the checkpoint when one is taken. And the
linear model is an assumption, so `linearity()` ships beside `project()` as
its external check - per Stage 0's finding that a figure regenerated from a
tool is only better than a hand calculation if the tool is validated against
something it did not produce.
"""
from __future__ import annotations

from dataclasses import dataclass

from audit_core.budget import Report

CEILING_TOKENS = 100_000
CHECKPOINT_FRACTION = 0.80


@dataclass(frozen=True, slots=True)
class Projection:
    prefix: int
    growth_per_turn: float
    ceiling: int
    checkpoint_at: int
    turns_to_checkpoint: int | None
    turns_to_ceiling: int | None


def project(prefix: int, growth_per_turn: float,
            ceiling: int = CEILING_TOKENS,
            fraction: float = CHECKPOINT_FRACTION) -> Projection:
    """How many turns a phase gets before it must checkpoint.

    `None` means the limit is never reached - a session with no measurable
    growth, which is a measurement to distrust rather than a budget to spend.
    """
    checkpoint_at = int(ceiling * fraction)

    def turns(limit: int) -> int | None:
        if growth_per_turn <= 0:
            return None
        return max(0, int((limit - prefix) // growth_per_turn))

    return Projection(prefix=prefix, growth_per_turn=growth_per_turn,
                      ceiling=ceiling, checkpoint_at=checkpoint_at,
                      turns_to_checkpoint=turns(checkpoint_at),
                      turns_to_ceiling=turns(ceiling))


def _turns(value: int | None) -> str:
    return "never (no measurable growth)" if value is None else f"{value}"


def render_projection(p: Projection) -> str:
    return "\n".join([
        f"  ceiling {p.ceiling:,}   checkpoint at {p.checkpoint_at:,} "
        f"({100 * CHECKPOINT_FRACTION:.0f}%)",
        f"  measured prefix {p.prefix:,}   growth {p.growth_per_turn:,.0f} tok/turn",
        f"  turns to checkpoint {_turns(p.turns_to_checkpoint)}   "
        f"turns to ceiling {_turns(p.turns_to_ceiling)}",
    ])


@dataclass(frozen=True, slots=True)
class LinearityCheck:
    epoch: int
    turns: int
    measured_mean: int
    predicted_mean: int
    deviation: float


def linearity(report: Report, min_turns: int = 20) -> list[LinearityCheck]:
    """How well `context(n) = floor + g*n` fits a measured session.

    Under that model an epoch's mean context is floor + g*(turns-1)/2.
    Comparing a predicted PEAK to the measured peak would be an identity - g
    is defined as (peak - floor) / (turns - 1) - and would pass for any data.
    The mean is independent of that definition, so a session whose context
    jumps early and plateaus fails this and should.
    """
    out: list[LinearityCheck] = []
    for e in report.epochs:
        if e.turns < min_turns or e.mean <= 0:
            continue
        predicted = e.floor + e.growth_per_turn * (e.turns - 1) / 2
        out.append(LinearityCheck(
            epoch=e.index, turns=e.turns, measured_mean=e.mean,
            predicted_mean=int(predicted),
            deviation=abs(predicted - e.mean) / e.mean))
    return out


def render_linearity(checks: list[LinearityCheck]) -> str:
    if not checks:
        return ("  linearity: no epoch long enough to judge the growth model")
    out = [f"  {'epoch':>5s} {'turns':>6s} {'measured mean':>14s} "
           f"{'predicted mean':>15s} {'deviation':>10s}"]
    out.extend(
        f"  {c.epoch:5d} {c.turns:6d} {c.measured_mean:14,} "
        f"{c.predicted_mean:15,} {100 * c.deviation:9.1f}%"
        for c in checks)
    out.append("  A large deviation means context is not growing linearly, so "
               "the turns-to-checkpoint")
    out.append("  figure above is unreliable for this session - report it "
               "rather than widening the bound.")
    return "\n".join(out)
