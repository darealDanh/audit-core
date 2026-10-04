"""Parse a Claude Code JSONL session into typed records.

Classification is by record type and attachment type only. Never search raw
line text for a marker: the system prompt is itself written into the
transcript as a `prompt_snapshot` attachment, so substring matching
misattributes system-prompt text to whatever component the marker names.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

CHARS_PER_TOKEN = 4

COMPONENTS: tuple[str, ...] = (
    "thinking_block",
    "assistant_text",
    "tool_use_input",
    "tool_result",
    "subagent_result",
    "user_text",
)

# Attachment types that are injected into the model's context. Types absent
# from this set (notably `prompt_snapshot`, which is a logging artefact of the
# system prompt) are recorded in the transcript but never charged to context.
CONTEXT_ATTACHMENTS: frozenset[str] = frozenset({
    "total_tokens_reminder", "environment", "date", "session_context",
    "instructions", "invoked_skills", "skill_listing", "deferred_tools_record",
    "deferred_tools_delta", "mcp_instructions_delta", "agent_listing_delta",
    "hook_additional_context", "hook_success", "file", "edited_text_file",
    "compact_file_reference", "queued_command", "model", "auto_mode",
    "command_permissions", "remote_session_change",
})

SUBAGENT_MARKER = "<task-notification"


def estimate_tokens(text: str) -> int:
    return len(text) // CHARS_PER_TOKEN


@dataclass(frozen=True, slots=True)
class Turn:
    index: int
    context: int
    output: int
    thinking: int
    epoch: int


@dataclass(frozen=True, slots=True)
class Addition:
    component: str
    tokens: int
    turn_index: int
    epoch: int


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    input_tokens: int
    result_tokens: int


@dataclass(frozen=True, slots=True)
class Transcript:
    path: str
    session_id: str
    turns: list[Turn] = field(default_factory=list)
    additions: list[Addition] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    cost_usd: float | None = None
    model_usage: dict = field(default_factory=dict)


def _iter_records(path: pathlib.Path):
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError:
                continue  # truncated tail of a live transcript


def parse(path: str | pathlib.Path) -> Transcript:
    path = pathlib.Path(path)
    turns: list[Turn] = []
    additions: list[Addition] = []
    tool_calls: list[ToolCall] = []
    pending: dict[str, tuple[str, int]] = {}
    seen_message_ids: set[str] = set()
    session_id = ""
    cost_usd: float | None = None
    model_usage: dict = {}
    epoch = 0
    turn_index = -1

    def add(component: str, tokens: int) -> None:
        if tokens > 0:
            additions.append(Addition(component, tokens, max(turn_index, 0), epoch))

    for rec in _iter_records(path):
        session_id = session_id or rec.get("sessionId", "")
        rtype = rec.get("type")

        if rtype == "cost-state":
            cost_usd = rec.get("totalCostUSD")
            model_usage = rec.get("modelUsage") or {}

        elif rtype == "assistant":
            msg = rec.get("message") or {}
            usage = msg.get("usage") or {}
            # Claude Code writes one record per content block, not one per API
            # response. Every record of such a group carries the same
            # `message.id` and a byte-identical copy of the same `usage`, so a
            # Turn per record would count the same billed call once per block.
            # A record with no id cannot be grouped and falls back to one turn
            # per record.
            mid = msg.get("id")
            if mid is None or mid not in seen_message_ids:
                if mid is not None:
                    seen_message_ids.add(mid)
                context = (usage.get("cache_read_input_tokens", 0)
                           + usage.get("cache_creation_input_tokens", 0)
                           + usage.get("input_tokens", 0))
                turn_index += 1
                turns.append(Turn(
                    index=turn_index,
                    context=context,
                    output=usage.get("output_tokens", 0),
                    thinking=(usage.get("output_tokens_details")
                              or {}).get("thinking_tokens", 0),
                    epoch=epoch,
                ))
            # The block walk runs on every record: blocks are distributed
            # across the group and never repeated.
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype == "text":
                        add("assistant_text", estimate_tokens(block.get("text", "")))
                    elif btype == "thinking":
                        add("thinking_block", estimate_tokens(json.dumps(block)))
                    elif btype == "tool_use":
                        n = estimate_tokens(json.dumps(block.get("input", {})))
                        add("tool_use_input", n)
                        pending[block.get("id", "")] = (block.get("name", "?"), n)

        elif rtype == "user":
            if rec.get("isCompactSummary"):
                epoch += 1
                continue
            content = (rec.get("message") or {}).get("content")
            if isinstance(content, str):
                _classify_user_text(content, add)
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_result":
                        payload = block.get("content", "")
                        n = estimate_tokens(payload if isinstance(payload, str)
                                            else json.dumps(payload))
                        add("tool_result", n)
                        name, in_tokens = pending.pop(block.get("tool_use_id", ""), ("?", 0))
                        tool_calls.append(ToolCall(name, in_tokens, n))
                    elif block.get("type") == "text":
                        _classify_user_text(block.get("text", ""), add)

        elif rtype == "attachment":
            atype = (rec.get("attachment") or {}).get("type", "?")
            if atype in CONTEXT_ATTACHMENTS:
                # Only `rendered[*].content` is injected into the model's
                # context. The rest of the record -- uuid, parentUuid,
                # sessionId, timestamp, cwd, gitBranch, version, userType,
                # entrypoint, isSidechain, slug -- is JSONL bookkeeping the
                # model never sees. A missing or null `rendered` therefore
                # costs nothing: `deferred_tools_record` and friends reach the
                # model through the system prompt, which is already inside the
                # epoch floor, so charging them here would double-count.
                rendered = rec.get("rendered") or []
                text = "".join(c.get("content", "") for c in rendered
                               if isinstance(c, dict))
                add(f"attachment:{atype}", estimate_tokens(text))

    return Transcript(str(path), session_id, turns, additions, tool_calls,
                      cost_usd, model_usage)


def _classify_user_text(text: str, add) -> None:
    component = "subagent_result" if SUBAGENT_MARKER in text else "user_text"
    add(component, estimate_tokens(text))
