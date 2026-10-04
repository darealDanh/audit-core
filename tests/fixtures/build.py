# tests/fixtures/build.py
"""Synthetic Claude Code JSONL transcripts. No real session data."""
import json


def line(obj) -> str:
    return json.dumps(obj) + "\n"


def assistant(content, cache_read=0, cache_creation=0, inp=0, output=0, thinking=0,
              message_id=None):
    """One assistant record.

    Claude Code writes one record per content block, not one per API response.
    Every record of such a group repeats the same `message.id` and a
    byte-identical copy of the same `usage`. Pass the same `message_id` to two
    calls to build that shape; the default `None` keeps the one-record-per-turn
    shape used by the older tests.
    """
    message = {
        "content": content,
        "usage": {
            "input_tokens": inp,
            "cache_read_input_tokens": cache_read,
            "cache_creation_input_tokens": cache_creation,
            "output_tokens": output,
            "output_tokens_details": {"thinking_tokens": thinking},
        },
    }
    if message_id is not None:
        message["id"] = message_id
    return line({
        "type": "assistant",
        "isSidechain": False,
        "sessionId": "test-session",
        "message": message,
    })


def user_text(text):
    return line({"type": "user", "isSidechain": False, "sessionId": "test-session",
                 "message": {"content": text}})


def user_blocks(blocks):
    return line({"type": "user", "isSidechain": False, "sessionId": "test-session",
                 "message": {"content": blocks}})


def compact_summary(text="summary"):
    return line({"type": "user", "isSidechain": False, "isCompactSummary": True,
                 "sessionId": "test-session", "message": {"content": text}})


def attachment(atype, content=None, payload="x"):
    """One attachment record, with the JSONL envelope a real one carries.

    `content` is the text the attachment actually injects into the model's
    context; it rides in top-level `rendered`, a list of `{"content": str}`.
    `None` models the types that render nothing at all (`hook_success`,
    `prompt_snapshot`, `deferred_tools_record`, `command_permissions`), which
    must cost zero. Nothing else on the record reaches the model, so the
    envelope fields below exist to be *excluded* from the token estimate.
    """
    rec = {
        "parentUuid": "00000000-0000-0000-0000-00000000dead",
        "isSidechain": False,
        "type": "attachment",
        "uuid": "00000000-0000-0000-0000-00000000beef",
        "timestamp": "2026-10-05T00:00:00.000Z",
        "userType": "external",
        "entrypoint": "cli",
        "cwd": "/Users/test/some/deeply/nested/working/directory",
        "sessionId": "test-session",
        "session_id": "test-session",
        "version": "9.9.9",
        "gitBranch": "design/audit-suite",
        "slug": "a-fairly-long-slug-that-costs-nothing",
        "attachment": {"type": atype, "payload": payload},
    }
    if content is not None:
        rec["rendered"] = [{"content": content}]
    return line(rec)


def cost_state(usd=1.25):
    return line({"type": "cost-state", "sessionId": "test-session",
                 "totalCostUSD": usd, "modelUsage": {"claude-opus-5": {"costUSD": usd}}})
