"""Normalization shared by finding dedup and golden scoring.

Both answer the same question - are these two records the same defect - and
both learned the same lesson from the tplink golden: a three-character
location token pairs with everything. The rule is stated once, here.
"""
from __future__ import annotations

import re

MIN_LOCATION_TOKEN = 4

_WS = re.compile(r"\s+")
_NOISE = re.compile(r"[^a-z0-9 ]+")
_TOKEN = re.compile(r"[A-Za-z0-9_]+")


def root_cause_key(value: str | None) -> str:
    """Lowercase, replace punctuation with spaces, collapse whitespace.

    Two findings written by different subagents describe the same mechanism
    in different words far more often than they describe it identically, so
    this is a coarse key by design: it is used to *propose* a duplicate, never
    to merge one.
    """
    return _WS.sub(" ", _NOISE.sub(" ", (value or "").lower())).strip()


def location_tokens(value: str | None) -> frozenset[str]:
    """Lowercased tokens of at least MIN_LOCATION_TOKEN characters.

    Shorter tokens are dropped. In the tplink golden the bare token `tss`
    matched `TssRSASecretKey` and `osal_tss_init`, producing two candidate
    pairs between entirely unrelated defects, each of which cost a human
    adjudication to reject.
    """
    return frozenset(t.lower() for t in _TOKEN.findall(value or "")
                     if len(t) >= MIN_LOCATION_TOKEN)
