"""Normalization shared by finding dedup and golden scoring.

Both answer the same question - are these two records the same defect - and
both learned the same lesson from the tplink golden: a three-character
location token pairs with everything. The rule is stated once, here.
"""
from __future__ import annotations

import re

MIN_LOCATION_TOKEN = 4

# Words that carry no identifying information in audit prose: English filler,
# plus the verbs and nouns that appear in nearly every impact statement and
# nearly every attacker position. Two callers subtract it - the identity-
# evidence rule in db.py, which must reject "the file is named <itself>", and
# the chain proposer in chains.py, where sharing "user" or "remote" between an
# impact and a precondition carries no signal.
#
# Deliberately literal and narrow, for the reason the four-character token
# floor and skill_lint's RETIRED_QUERIES are: a general rule over English
# prose fires on legitimate text and gets switched off. Do not grow this list
# to make a specific case pass without checking both callers' tests.
NOISE_WORDS = frozenset({
    "able", "about", "access", "after", "allow", "allows", "already", "also",
    "arbitrary", "attack", "attacker", "authenticated", "because", "been",
    "before", "being", "called", "cause", "causes", "contains", "control",
    "could", "data", "device", "does", "either", "execute", "execution",
    "file", "filename", "files", "found", "from", "full", "give", "gives",
    "grant", "grants", "having", "here", "holds", "input", "inside", "into",
    "itself", "just", "known", "lead", "leads", "local", "looks", "made",
    "make", "name", "named", "names", "network", "only", "over", "path",
    "position", "read", "remote", "request", "requests", "same", "seems",
    "server", "service", "simply", "since", "stack", "system", "than",
    "that", "their", "them", "then", "there", "these", "they", "this",
    "those", "through", "under", "unauthenticated", "user", "users", "value",
    "what", "when", "where", "which", "while", "with", "within", "without",
    "write", "writes", "would",
})

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
