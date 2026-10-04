# tests/test_budget_attribution.py
import pathlib
from audit_core import budget, transcript as T
from tests.fixtures import build as B


def write(tmp_path, *lines) -> pathlib.Path:
    p = tmp_path / "s.jsonl"
    p.write_text("".join(lines))
    return p


def test_composition_sums_additions_by_component(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a" * 400}], cache_read=1000),
              B.assistant([{"type": "text", "text": "b" * 800}], cache_read=2000))
    r = budget.analyze(T.parse(p))
    assert r.composition["assistant_text"] == 300


def test_attribution_charges_tokens_for_remaining_turns_in_epoch(tmp_path):
    """An addition on turn 0 of a 3-turn epoch is resident for 3 turns."""
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a" * 400}], cache_read=1000),
              B.assistant([], cache_read=2000),
              B.assistant([], cache_read=3000))
    r = budget.analyze(T.parse(p))
    assert r.attribution["assistant_text"] == 300


def test_attribution_resets_at_compaction(tmp_path):
    """An addition in epoch 0 is not charged for epoch 1's turns."""
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a" * 400}], cache_read=1000),
              B.compact_summary(),
              B.assistant([], cache_read=500),
              B.assistant([], cache_read=600))
    r = budget.analyze(T.parse(p))
    assert r.attribution["assistant_text"] == 100


def test_prefix_and_accumulation_partition_total_context(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=50_000),
              B.assistant([], cache_read=70_000))
    r = budget.analyze(T.parse(p))
    assert r.prefix_term == 100_000
    assert r.accumulation_term == 20_000
    assert r.prefix_term + r.accumulation_term == r.stats.sum_context


def test_tool_totals_are_split_by_direction(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "tool_use", "id": "t1", "name": "Bash",
                            "input": {"command": "x" * 200}}], cache_read=1000),
              B.user_blocks([{"type": "tool_result", "tool_use_id": "t1",
                              "content": "y" * 800}]))
    r = budget.analyze(T.parse(p))
    assert r.tool_result_tokens == 200
    assert r.tool_input_tokens > 0
    assert r.tool_calls_by_name["Bash"] == 1


def test_render_includes_every_nonzero_component(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a" * 400}], cache_read=1000),
              B.attachment("total_tokens_reminder"))
    text = budget.render(budget.analyze(T.parse(p)))
    assert "assistant_text" in text
    assert "attachment:total_tokens_reminder" in text
    assert "prefix" in text.lower()
