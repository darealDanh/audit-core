# tests/fixtures/build.py
"""Synthetic Claude Code JSONL transcripts. No real session data."""
import json


def line(obj) -> str:
    return json.dumps(obj) + "\n"


def assistant(content, cache_read=0, cache_creation=0, inp=0, output=0, thinking=0):
    return line({
        "type": "assistant",
        "isSidechain": False,
        "sessionId": "test-session",
        "message": {
            "content": content,
            "usage": {
                "input_tokens": inp,
                "cache_read_input_tokens": cache_read,
                "cache_creation_input_tokens": cache_creation,
                "output_tokens": output,
                "output_tokens_details": {"thinking_tokens": thinking},
            },
        },
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


def attachment(atype, payload="x"):
    return line({"type": "attachment", "isSidechain": False, "sessionId": "test-session",
                 "attachment": {"type": atype, "payload": payload}})


def cost_state(usd=1.25):
    return line({"type": "cost-state", "sessionId": "test-session",
                 "totalCostUSD": usd, "modelUsage": {"claude-opus-5": {"costUSD": usd}}})
