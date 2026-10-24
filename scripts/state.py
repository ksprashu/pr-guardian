"""Round-to-round memory for a PR, kept in one bot-authored summary comment.

The summary comment is the human-facing round report (counts, nits, cost) with
the machine state appended as a hidden HTML comment:

    <!-- pr-guardian:state v1 <base64(zlib(json))> -->

Keeping state on the PR (not in an artifact) means it survives workflow
re-runs, is visible to the owner, and needs no storage outside GitHub.
"""

from __future__ import annotations

import base64
import json
import re
import zlib
from typing import Any

SUMMARY_MARKER = "<!-- pr-guardian:summary -->"
_STATE_RE = re.compile(r"<!-- pr-guardian:state v1 ([A-Za-z0-9+/=]+) -->")
FINDING_MARKER = "<!-- pr-guardian:finding id={id} severity={severity} -->"
FINDING_RE = re.compile(r"<!-- pr-guardian:finding id=([A-Z][A-Z0-9]*-[0-9]{3,}) severity=(P[0-3]|nit) -->")


def empty_state() -> dict[str, Any]:
    return {
        "round": 0,
        "findings": [],          # last round's findings document entries
        "accepted": [],          # [{"id", "file", "rule"}] pushback the reviewer accepted
        "reopen_counts": {},     # finding id -> times reopened
        "escalated": False,
        "escalation_reasons": [],
        "cost_usd": [],          # per-round estimates
        "last_reviewed_sha": "",
    }


def encode(state: dict[str, Any]) -> str:
    raw = zlib.compress(json.dumps(state, separators=(",", ":")).encode(), 9)
    return f"<!-- pr-guardian:state v1 {base64.b64encode(raw).decode()} -->"


def decode(body: str) -> dict[str, Any] | None:
    m = _STATE_RE.search(body or "")
    if not m:
        return None
    try:
        data = json.loads(zlib.decompress(base64.b64decode(m.group(1))))
    except (ValueError, zlib.error):
        return None
    state = empty_state()
    state.update(data)
    return state


def find_summary_comment(comments: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The newest bot comment carrying the summary marker."""
    mine = [c for c in comments
            if SUMMARY_MARKER in (c.get("body") or "")
            and (c.get("user") or {}).get("type") == "Bot"]
    return mine[-1] if mine else None
