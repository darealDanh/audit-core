import pathlib

from audit_core import budget, ceiling, transcript as T
from tests.fixtures import build as B


def session(tmp_path, contexts) -> pathlib.Path:
    """A one-epoch transcript whose billed turns have exactly these contexts.

    Same idiom as tests/test_budget_epochs.py: write the fixture lines to a
    file and parse it. A distinct message id per line keeps one Turn per
    record, which is the shape the C1 fix established.
    """
    p = tmp_path / "s.jsonl"
    p.write_text("".join(
        B.assistant([{"type": "text", "text": "x"}], cache_read=c,
                    message_id=f"m{i}")
        for i, c in enumerate(contexts)))
    return p


def test_the_ceiling_and_checkpoint_are_the_spec_values():
    assert ceiling.CEILING_TOKENS == 100_000
    assert ceiling.CHECKPOINT_FRACTION == 0.80
    p = ceiling.project(prefix=45_000, growth_per_turn=600)
    assert p.checkpoint_at == 80_000


def test_project_counts_turns_to_checkpoint_and_to_ceiling():
    p = ceiling.project(prefix=45_000, growth_per_turn=600)
    assert p.turns_to_checkpoint == 58       # (80000 - 45000) // 600
    assert p.turns_to_ceiling == 91          # (100000 - 45000) // 600


def test_a_prefix_already_over_the_checkpoint_gets_zero_turns():
    p = ceiling.project(prefix=85_000, growth_per_turn=600)
    assert p.turns_to_checkpoint == 0
    assert p.turns_to_ceiling == 25


def test_a_prefix_over_the_ceiling_gets_zero_everywhere():
    p = ceiling.project(prefix=120_000, growth_per_turn=600)
    assert (p.turns_to_checkpoint, p.turns_to_ceiling) == (0, 0)


def test_zero_growth_never_reaches_the_ceiling():
    p = ceiling.project(prefix=45_000, growth_per_turn=0)
    assert p.turns_to_checkpoint is None
    assert p.turns_to_ceiling is None


def test_render_projection_names_the_measured_inputs():
    out = ceiling.render_projection(ceiling.project(45_000, 600))
    assert "45,000" in out
    assert "600" in out
    assert "58" in out


def test_the_measured_tplink_prefix_and_growth_leave_a_phase_15_turns():
    """The baseline is prefix 40,926-66,010 and g 2,573 tok/turn. Against a
    100k ceiling that is the number R3 exists to change: 15 turns is not a
    phase, which is why R4 (cutting the prefix) is a prerequisite for R3."""
    p = ceiling.project(prefix=40_926, growth_per_turn=2_573)
    assert p.turns_to_checkpoint == 15


def test_linearity_fits_a_perfectly_linear_epoch(tmp_path):
    """`project()` is only meaningful if growth is roughly linear. This check
    cannot pass by construction: comparing a predicted PEAK to a measured peak
    is an identity, because g is defined as (peak - floor) / (turns - 1).
    Comparing the mean is not."""
    r = budget.analyze(T.parse(session(
        tmp_path, [10_000 + 1_000 * i for i in range(40)])))
    checks = ceiling.linearity(r, min_turns=20)
    assert len(checks) == 1
    assert checks[0].deviation < 0.01


def test_linearity_flags_a_front_loaded_epoch(tmp_path):
    """Context that jumps early and plateaus has the same floor, peak and
    therefore the same g as a linear climb, and a mean nowhere near the
    model's. That is the failure this check exists to catch."""
    r = budget.analyze(T.parse(session(tmp_path, [10_000] + [50_000] * 39)))
    checks = ceiling.linearity(r, min_turns=20)
    assert checks[0].deviation > 0.25


def test_linearity_skips_epochs_too_short_to_judge(tmp_path):
    r = budget.analyze(T.parse(session(
        tmp_path, [10_000 + 1_000 * i for i in range(5)])))
    assert ceiling.linearity(r, min_turns=20) == []


def test_render_linearity_prints_every_deviation_not_a_verdict(tmp_path):
    r = budget.analyze(T.parse(session(
        tmp_path, [10_000 + 1_000 * i for i in range(40)])))
    out = ceiling.render_linearity(ceiling.linearity(r, min_turns=20))
    assert "deviation" in out
    assert "%" in out


def test_linearity_declines_to_judge_a_short_history():
    """ceiling.py:104 - refusing to model is a result, and it has a sentence."""
    out = ceiling.render_linearity([])
    assert out == "  linearity: no epoch long enough to judge the growth model"
