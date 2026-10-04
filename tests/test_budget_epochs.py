# tests/test_budget_epochs.py
import pathlib
from audit_core import budget, transcript as T
from tests.fixtures import build as B


def write(tmp_path, *lines) -> pathlib.Path:
    p = tmp_path / "s.jsonl"
    p.write_text("".join(lines))
    return p


def test_zero_context_turns_excluded_from_floor(tmp_path):
    """Review Focus 2: continuation iterations report context 0."""
    p = write(tmp_path,
              B.assistant([], cache_read=50_000),
              B.assistant([], cache_read=0),
              B.assistant([], cache_read=70_000))
    e = budget.epochs_of(T.parse(p))
    assert len(e) == 1
    assert e[0].floor == 50_000
    assert e[0].turns == 2


def test_single_turn_epoch_has_zero_growth(tmp_path):
    """Review Focus 4: growth divides by turns - 1."""
    p = write(tmp_path, B.assistant([], cache_read=50_000))
    assert budget.epochs_of(T.parse(p))[0].growth_per_turn == 0.0


def test_growth_is_span_over_turn_gaps(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=10_000),
              B.assistant([], cache_read=20_000),
              B.assistant([], cache_read=30_000))
    assert budget.epochs_of(T.parse(p))[0].growth_per_turn == 10_000.0


def test_epoch_split_on_compaction(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=90_000),
              B.compact_summary(),
              B.assistant([], cache_read=40_000))
    e = budget.epochs_of(T.parse(p))
    assert [x.floor for x in e] == [90_000, 40_000]


def test_epoch_with_only_zero_context_turns_is_dropped(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=0),
              B.compact_summary(),
              B.assistant([], cache_read=40_000))
    assert [x.floor for x in budget.epochs_of(T.parse(p))] == [40_000]


def test_stats_prefix_floor_is_lowest_nonzero_epoch_floor(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=80_000),
              B.compact_summary(),
              B.assistant([], cache_read=45_000),
              B.assistant([], cache_read=95_000))
    s = budget.stats_of(T.parse(p))
    assert s.prefix_floor == 45_000
    assert s.sum_context == 220_000
    assert s.turns == 3
    assert s.max_context == 95_000
