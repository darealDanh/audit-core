import pathlib
from audit_core import budget, transcript as T
from tests.fixtures import build as B


def write(tmp_path, *lines) -> pathlib.Path:
    p = tmp_path / "s.jsonl"
    p.write_text("".join(lines))
    return p


def test_turns_carry_context_and_epoch(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"}], cache_read=1000, output=10),
              B.assistant([{"type": "text", "text": "b"}], cache_read=2000, output=10))
    t = T.parse(p)
    assert [x.context for x in t.turns] == [1000, 2000]
    assert {x.epoch for x in t.turns} == {0}


def test_compaction_starts_a_new_epoch(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"}], cache_read=1000),
              B.compact_summary(),
              B.assistant([{"type": "text", "text": "b"}], cache_read=500))
    t = T.parse(p)
    assert [x.epoch for x in t.turns] == [0, 1]


def test_task_notification_marker_in_assistant_text_is_not_a_subagent_result(tmp_path):
    """Review Focus 1: classify by record type, never by substring."""
    p = write(tmp_path,
              B.assistant([{"type": "text",
                            "text": "I will emit <task-notification> when done"}]))
    t = T.parse(p)
    kinds = {a.component for a in t.additions}
    assert "subagent_result" not in kinds
    assert "assistant_text" in kinds


def test_task_notification_in_user_message_is_a_subagent_result(tmp_path):
    p = write(tmp_path, B.user_text("<task-notification>agent done</task-notification>"))
    t = T.parse(p)
    assert [a.component for a in t.additions] == ["subagent_result"]


def test_truncated_final_line_is_skipped(tmp_path):
    """Review Focus 3."""
    p = tmp_path / "s.jsonl"
    p.write_text(B.assistant([{"type": "text", "text": "a"}], cache_read=10)
                 + '{"type": "assistant", "mess')
    t = T.parse(p)
    assert len(t.turns) == 1


def test_tool_calls_pair_input_with_result(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "tool_use", "id": "t1", "name": "Bash",
                            "input": {"command": "ls -la /tmp"}}]),
              B.user_blocks([{"type": "tool_result", "tool_use_id": "t1",
                              "content": "a" * 400}]))
    t = T.parse(p)
    assert len(t.tool_calls) == 1
    assert t.tool_calls[0].name == "Bash"
    assert t.tool_calls[0].result_tokens == 100


def test_attachment_types_are_distinct_components(tmp_path):
    p = write(tmp_path,
              B.attachment("total_tokens_reminder"),
              B.attachment("invoked_skills"))
    t = T.parse(p)
    assert {a.component for a in t.additions} == {
        "attachment:total_tokens_reminder", "attachment:invoked_skills"}


def test_cost_state_is_read(tmp_path):
    p = write(tmp_path, B.assistant([], cache_read=1), B.cost_state(3.5))
    assert T.parse(p).cost_usd == 3.5


def test_missing_cost_state_yields_none(tmp_path):
    p = write(tmp_path, B.assistant([], cache_read=1))
    assert T.parse(p).cost_usd is None


def test_every_addition_component_is_declared(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"},
                           {"type": "thinking", "thinking": "t"},
                           {"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}]),
              B.user_text("hello"),
              B.attachment("date"))
    t = T.parse(p)
    for a in t.additions:
        assert a.component in T.COMPONENTS or a.component.startswith("attachment:")


def test_records_sharing_a_message_id_are_one_turn(tmp_path):
    """C1: Claude Code writes one record per content block, not per API call.

    Every record of such a group repeats the same `message.id` and a
    byte-identical copy of the same `usage`. Counting a Turn per record
    inflates Sigma context by the mean group size while leaving mean context
    and the prefix/accumulation split looking correct. Content blocks are
    distributed across the group and never repeated, so the block walk must
    still run on every record.
    """
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a" * 400}],
                          cache_read=1000, output=10, message_id="msg-1"),
              B.assistant([{"type": "tool_use", "id": "t1", "name": "Bash",
                            "input": {"command": "x" * 200}}],
                          cache_read=1000, output=10, message_id="msg-1"))
    t = T.parse(p)
    assert len(t.turns) == 1
    assert [x.index for x in t.turns] == [0]
    assert budget.stats_of(t).sum_context == 1000
    components = {a.component for a in t.additions}
    assert components == {"assistant_text", "tool_use_input"}
    assert all(a.turn_index == 0 for a in t.additions)


def test_records_without_a_message_id_stay_one_turn_each(tmp_path):
    """C1 fallback: no id to group on means no grouping. None observed in the
    reference transcript, but the parser must not collapse them into one."""
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"}], cache_read=1000),
              B.assistant([{"type": "text", "text": "b"}], cache_read=2000))
    t = T.parse(p)
    assert [x.context for x in t.turns] == [1000, 2000]


def test_distinct_message_ids_are_distinct_turns(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"}], cache_read=1000,
                          message_id="msg-1"),
              B.assistant([{"type": "text", "text": "b"}], cache_read=2000,
                          message_id="msg-2"))
    t = T.parse(p)
    assert [(x.index, x.context) for x in t.turns] == [(0, 1000), (1, 2000)]
