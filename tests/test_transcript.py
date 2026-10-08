import json
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
    # Content is explicit since C2: an attachment is charged for what it
    # renders into context, so one with nothing rendered has no component.
    p = write(tmp_path,
              B.attachment("total_tokens_reminder", content="r" * 400),
              B.attachment("invoked_skills", content="s" * 400))
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
              B.attachment("date", content="2026-10-05" * 40))
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


def test_attachment_charges_rendered_content_not_the_jsonl_envelope(tmp_path):
    """C2: only `rendered[*].content` reaches the model.

    The record also carries uuid, parentUuid, sessionId, timestamp, cwd,
    gitBranch, version, userType, entrypoint, isSidechain and slug. Charging
    `json.dumps(rec)` billed all of that: 8.4x over-charge on
    `total_tokens_reminder` in the reference transcript, 7.9x on `date`,
    3.9x on `environment`.
    """
    p = write(tmp_path, B.attachment("total_tokens_reminder", content="c" * 400))
    t = T.parse(p)
    assert [(a.component, a.tokens) for a in t.additions] == [
        ("attachment:total_tokens_reminder", 100)]


def test_attachment_concatenates_multiple_rendered_blocks(tmp_path):
    p = tmp_path / "s.jsonl"
    p.write_text(json.dumps({
        "type": "attachment", "sessionId": "test-session", "uuid": "u",
        "attachment": {"type": "environment"},
        "rendered": [{"content": "a" * 200}, {"content": "b" * 200}],
    }) + "\n")
    t = T.parse(p)
    assert [(a.component, a.tokens) for a in t.additions] == [
        ("attachment:environment", 100)]


def test_attachment_with_no_rendered_content_costs_nothing(tmp_path):
    """C2: `rendered: null` means nothing was injected.

    `deferred_tools_record` is the costly case: 29,460 tokens charged to
    message history for content that reaches the model through the system
    prompt, which is already inside the epoch floor -- so charging it here
    double-counted it.
    """
    p = write(tmp_path,
              B.attachment("deferred_tools_record"),
              B.attachment("hook_success"),
              B.attachment("prompt_snapshot"),
              B.attachment("command_permissions"))
    assert T.parse(p).additions == []


def test_attachment_tolerates_malformed_rendered_entries(tmp_path):
    p = tmp_path / "s.jsonl"
    p.write_text(json.dumps({
        "type": "attachment", "sessionId": "test-session",
        "attachment": {"type": "environment"},
        "rendered": ["a string, not an object", None, {"content": "d" * 400}],
    }) + "\n")
    t = T.parse(p)
    assert [(a.component, a.tokens) for a in t.additions] == [
        ("attachment:environment", 100)]


def test_model_usage_context_sums_input_and_cache_tokens_across_models(tmp_path):
    """I2: the model-reported context total, for reconciliation."""
    p = write(tmp_path, B.assistant([], cache_read=1), B.cost_state(1.0, {
        "claude-opus-5[1m]": B.model_usage(input_tokens=100, cache_read=1000,
                                           cache_creation=10, output=5000),
        "claude-haiku-4-5": B.model_usage(input_tokens=7),
    }))
    assert T.model_usage_context(T.parse(p).model_usage) == 1117


def test_model_usage_context_ignores_entries_without_token_fields(tmp_path):
    """The default cost-state shape carries only costUSD; it must not raise."""
    p = write(tmp_path, B.assistant([], cache_read=1), B.cost_state(1.0))
    assert T.model_usage_context(T.parse(p).model_usage) == 0


def test_model_usage_context_tolerates_junk_entries():
    assert T.model_usage_context({"a": None, "b": "nonsense", "c": [],
                                  "d": {"inputTokens": "x"},
                                  "e": {"inputTokens": 5}}) == 5
    assert T.model_usage_context({}) == 0


def test_a_truncated_line_is_skipped_and_the_rest_still_parses(tmp_path):
    """transcript.py:114 - the truncated tail of a live transcript."""
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"}], cache_read=1000),
              '{"type": "assistant", "mess\n',
              B.assistant([{"type": "text", "text": "b"}], cache_read=2000))
    assert [x.context for x in T.parse(p).turns] == [1000, 2000]


def test_a_non_object_assistant_block_is_skipped(tmp_path):
    """transcript.py:177 - a bare string among assistant content blocks."""
    p = write(tmp_path,
              B.assistant(["stray", {"type": "text", "text": "x" * 400}],
                          cache_read=1000))
    t = T.parse(p)
    assert [a.component for a in t.additions] == ["assistant_text"]


def test_a_non_object_user_block_is_skipped(tmp_path):
    """transcript.py:198 - a bare string among user content blocks."""
    p = write(tmp_path,
              B.user_blocks(["stray",
                             {"type": "tool_result", "tool_use_id": "t1",
                              "content": "r" * 400}]))
    t = T.parse(p)
    assert [a.component for a in t.additions] == ["tool_result"]
    assert [c.name for c in t.tool_calls] == ["?"]


def test_a_non_string_tool_result_is_measured_as_its_json(tmp_path):
    """transcript.py:202 - a list payload is billed as its JSON text."""
    payload = [{"type": "text", "text": "y" * 400}]
    p = write(tmp_path,
              B.user_blocks([{"type": "tool_result", "tool_use_id": "t1",
                              "content": payload}]))
    t = T.parse(p)
    assert t.tool_calls[0].result_tokens == T.estimate_tokens(json.dumps(payload))
    assert t.tool_calls[0].result_tokens > T.estimate_tokens("y" * 400) - 1


def test_a_user_text_block_is_classified_as_user_text(tmp_path):
    """transcript.py:206-207 - a text block in a user content list goes
    through the classifier, like a plain string would."""
    p = write(tmp_path,
              B.user_blocks([{"type": "text", "text": "hello " * 100}]))
    t = T.parse(p)
    assert [a.component for a in t.additions] == ["user_text"]


def test_blank_lines_are_skipped(tmp_path):
    """transcript.py:114 - a blank line between records is not a record."""
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"}], cache_read=1000),
              "\n   \n",
              B.assistant([{"type": "text", "text": "b"}], cache_read=2000))
    assert [x.context for x in T.parse(p).turns] == [1000, 2000]
