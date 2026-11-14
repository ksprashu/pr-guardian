"""Round-to-round memory for a PR, kept in one bot-authored summary comment.

The summary comment is the human-facing round report (counts, nits, cost) with
the machine state appended as a hidden HTML comment:

    <!-- pr-guardian:state v1 <base64(zlib(json))> -->

Keeping state on the PR (not in an artifact) means it survives workflow
re-runs, is visible to the owner, and needs no storage outside GitHub.

State is trusted only when (GHSA-r8c3-5xg9-pqqg):
  - the comment was written by `github-actions[bot]` (not any Bot or App),
  - the marker is the last thing in the body, so text interpolated above it
    cannot shadow it,
  - it inflates to at most MAX_STATE_BYTES and parses to the expected types.
"""

from __future__ import annotations

import base64
import json
import math
import re
import zlib
from typing import Any

SUMMARY_MARKER = "<!-- pr-guardian:summary -->"
_STATE_RE = re.compile(r"<!-- pr-guardian:state v1 ([A-Za-z0-9+/=]+) -->\s*\Z")
FINDING_MARKER = "<!-- pr-guardian:finding id={id} severity={severity} -->"
FINDING_RE = re.compile(r"<!-- pr-guardian:finding id=([A-Z][A-Z0-9]*-[0-9]{3,}) severity=(P[0-3]|nit) -->")
ID_RE = re.compile(r"\A[A-Z][A-Z0-9]*-[0-9]{3,}\Z")
SEVERITIES = ("P0", "P1", "P2", "P3", "nit")
MAX_STATE_BYTES = 1024 * 1024
TRUSTED_BOT_LOGIN = "github-actions[bot]"


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
        "last_reviewed_base": "",  # base ref the last review ran against (GHSA-6h55-p37r-jc34)
    }


def encode(state: dict[str, Any]) -> str:
    raw = zlib.compress(json.dumps(state, separators=(",", ":")).encode(), 9)
    return f"<!-- pr-guardian:state v1 {base64.b64encode(raw).decode()} -->"


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} in state")


def _inflate(raw: bytes) -> bytes | None:
    """zlib-inflate at most MAX_STATE_BYTES; reject bombs, truncation and trailing data."""
    d = zlib.decompressobj()
    out = d.decompress(raw, MAX_STATE_BYTES + 1)
    if len(out) > MAX_STATE_BYTES or d.unconsumed_tail or not d.eof or d.unused_data:
        return None
    return out


def decode(body: str) -> dict[str, Any] | None:
    if not isinstance(body, str):
        return None
    m = _STATE_RE.search(body)
    if not m or len(m.group(1)) > MAX_STATE_BYTES * 2:
        return None
    try:
        out = _inflate(base64.b64decode(m.group(1), validate=True))
        if out is None:
            return None
        data = json.loads(out.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, zlib.error, RecursionError):
        return None
    return validate_state(data)


def _is_int(v: Any, minimum: int | None = None) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and (minimum is None or v >= minimum)


def _is_str_or_none(v: Any) -> bool:
    return v is None or isinstance(v, str)


def _valid_finding(f: Any) -> bool:
    if not isinstance(f, dict) or not isinstance(f.get("id"), str) or not f["id"]:
        return False
    if "severity" in f and f["severity"] not in SEVERITIES:
        return False
    if "status" in f and not isinstance(f["status"], str):
        return False
    if "prior_id" in f and not _is_str_or_none(f["prior_id"]):
        return False
    if any(k in f and not isinstance(f[k], str) for k in ("file", "rule")):
        return False
    return not any(k in f and not _is_int(f[k]) for k in ("start_line", "end_line"))


def _valid_accepted(a: Any) -> bool:
    return (isinstance(a, dict) and _is_str_or_none(a.get("id"))
            and isinstance(a.get("file"), str) and isinstance(a.get("rule"), str))


def _valid_cost(c: Any) -> bool:
    return (isinstance(c, (int, float)) and not isinstance(c, bool)
            and math.isfinite(c) and c >= 0)


_CHECKS = {
    "round": lambda v: _is_int(v, 0),
    "findings": lambda v: isinstance(v, list) and all(_valid_finding(f) for f in v),
    "accepted": lambda v: isinstance(v, list) and all(_valid_accepted(a) for a in v),
    "reopen_counts": lambda v: isinstance(v, dict) and all(
        isinstance(k, str) and _is_int(n, 0) for k, n in v.items()),
    "escalated": lambda v: isinstance(v, bool),
    "escalation_reasons": lambda v: isinstance(v, list) and all(isinstance(r, str) for r in v),
    "cost_usd": lambda v: isinstance(v, list) and all(_valid_cost(c) for c in v),
    "last_reviewed_sha": lambda v: isinstance(v, str),
    "last_reviewed_base": lambda v: isinstance(v, str),
}


def validate_state(data: Any) -> dict[str, Any] | None:
    """Type-check known keys (unknown keys are kept) and merge over empty_state()."""
    if not isinstance(data, dict):
        return None
    for key, ok in _CHECKS.items():
        if key in data and not ok(data[key]):
            return None
    state = empty_state()
    state.update(data)
    return state


def is_trusted_author(user: Any) -> bool:
    """The workflow's own GITHUB_TOKEN identity, not any Bot or installed App."""
    return (isinstance(user, dict) and user.get("type") == "Bot"
            and user.get("login") == TRUSTED_BOT_LOGIN)


def find_summary_comment(comments: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The newest github-actions[bot] comment carrying the summary marker."""
    mine = [c for c in comments or []
            if isinstance(c, dict) and isinstance(c.get("body"), str)
            and SUMMARY_MARKER in c["body"] and is_trusted_author(c.get("user"))]
    return mine[-1] if mine else None
