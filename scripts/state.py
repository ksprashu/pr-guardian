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
REV_SHA_RE = re.compile(r"\A[0-9a-f]{7,64}\Z")
GUARDIAN_REF_RE = re.compile(r"\A(?:[0-9a-f]{40})?\Z")
ENGINE_RE = re.compile(r"\A[A-Za-z0-9._:-]{0,32}\Z")
PREFIX_RE = re.compile(r"\A[A-Z][A-Z0-9]*\Z")
SEVERITIES = ("P0", "P1", "P2", "P3", "nit")
CLOSED = ("fixed", "accepted_pushback")
MAX_STATE_BYTES = 1024 * 1024
TRUSTED_BOT_LOGIN = "github-actions[bot]"

STATE_FINDING_KEYS = (
    "id", "prior_id", "thread_key", "posted", "severity", "status", "axis",
    "rule", "title", "file", "start_line", "end_line", "rationale",
    "confidence", "raised_by",
)
CLOSED_FINDING_KEYS = (
    "id", "prior_id", "thread_key", "posted", "severity", "status",
    "rule", "file", "raised_by",
)
CAPS = {
    "accepted": 200,
    "escalation_reasons": 50,
    "reviewed_shas": 20,
    "rounds_log": 20,
    "publish_failures": 20,
    "cost_usd": 50,
    "reopen_counts": 200,
}
TEXT_CAPS = {"title": 300, "rationale": 1500, "rule": 120, "file": 500, "reason": 300}


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
        "reviewed_shas": [],
        "guardian_ref": "",
        "engine": "",
        "rounds_log": [],
        "publish_incomplete": False,
        "publish_failures": [],
        "id_high_water": {},
    }


def encode(state: dict[str, Any]) -> str:
    raw = zlib.compress(json.dumps(state, separators=(",", ":")).encode(), 9)
    return f"<!-- pr-guardian:state v1 {base64.b64encode(raw).decode()} -->"


def split_state(body: str) -> tuple[str, str]:
    """Split a comment body into `(visible_text, trailing_state_marker_or_empty)`."""
    if not isinstance(body, str) or not body:
        return "", ""
    m = _STATE_RE.search(body)
    if not m:
        return body, ""
    return body[:m.start()].rstrip("\n"), body[m.start():].strip()


def _compact_finding(f: dict[str, Any], level: int) -> dict[str, Any]:
    is_closed = f.get("status") in CLOSED
    keys = CLOSED_FINDING_KEYS if (level >= 1 and is_closed) else STATE_FINDING_KEYS
    out = {k: f[k] for k in keys if k in f}
    for short_k, limit in (
        ("title", TEXT_CAPS["title"]),
        ("rule", TEXT_CAPS["rule"]),
        ("file", TEXT_CAPS["file"]),
        ("axis", 60),
        ("confidence", 40),
        ("status", 40),
        ("raised_by", 32),
        ("posted", 32),
        ("thread_key", 64),
    ):
        if short_k in out and isinstance(out[short_k], str):
            out[short_k] = out[short_k][:limit]
    if "rationale" in out and isinstance(out["rationale"], str):
        if level >= 2:
            out["rationale"] = ""
        elif level == 1:
            out["rationale"] = out["rationale"][:300]
        else:
            out["rationale"] = out["rationale"][:TEXT_CAPS["rationale"]]
    return out


def compact_state(s: dict[str, Any], *, level: int = 0) -> dict[str, Any]:
    """Pure, idempotent state compaction across levels 0, 1, and 2."""
    out: dict[str, Any] = {}
    for k, v in s.items():
        if isinstance(v, list):
            out[k] = [dict(x) if isinstance(x, dict) else x for x in v]
        elif isinstance(v, dict):
            out[k] = dict(v)
        else:
            out[k] = v

    if isinstance(s.get("findings"), list):
        out["findings"] = [
            _compact_finding(f, level) if isinstance(f, dict) else f
            for f in s["findings"]
        ]

    if isinstance(s.get("accepted"), list):
        dedup_rev: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for a in reversed(s["accepted"]):
            if not isinstance(a, dict):
                continue
            file_val = (a.get("file") or "")[:TEXT_CAPS["file"]]
            rule_val = (a.get("rule") or "")[:TEXT_CAPS["rule"]]
            key = (file_val, rule_val)
            if key in seen:
                continue
            seen.add(key)
            dedup_rev.append({"id": a.get("id"), "file": file_val, "rule": rule_val})
        dedup_rev.reverse()
        out["accepted"] = dedup_rev[-CAPS["accepted"]:]

    if isinstance(s.get("escalation_reasons"), list):
        out["escalation_reasons"] = [
            r[:1300] if isinstance(r, str) else r
            for r in s["escalation_reasons"][-CAPS["escalation_reasons"]:]
        ]

    if isinstance(s.get("cost_usd"), list):
        costs = list(s["cost_usd"])
        cap = CAPS["cost_usd"]
        if len(costs) > cap:
            head_n = len(costs) - (cap - 1)
            costs = [round(sum(costs[:head_n]), 4), *costs[head_n:]]
        out["cost_usd"] = costs

    if isinstance(s.get("reopen_counts"), dict):
        rc = s["reopen_counts"]
        if len(rc) > CAPS["reopen_counts"]:
            top = sorted(rc.items(), key=lambda kv: (-kv[1], kv[0]))[:CAPS["reopen_counts"]]
            out["reopen_counts"] = dict(top)
        else:
            out["reopen_counts"] = dict(rc)

    if isinstance(s.get("reviewed_shas"), list):
        out["reviewed_shas"] = list(s["reviewed_shas"][-CAPS["reviewed_shas"]:])

    if isinstance(s.get("rounds_log"), list):
        out["rounds_log"] = [
            dict(e) if isinstance(e, dict) else e
            for e in s["rounds_log"][-CAPS["rounds_log"]:]
        ]

    if isinstance(s.get("publish_failures"), list):
        out["publish_failures"] = [
            x[:TEXT_CAPS["reason"]] if isinstance(x, str) else x
            for x in s["publish_failures"][-CAPS["publish_failures"]:]
        ]

    return out


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
    if any(k in f and not isinstance(f[k], str)
           for k in ("file", "rule", "title", "rationale", "axis", "raised_by", "thread_key", "posted")):
        return False
    if "confidence" in f and not _is_str_or_none(f["confidence"]):
        return False
    return not any(k in f and not _is_int(f[k]) for k in ("start_line", "end_line"))


def _valid_accepted(a: Any) -> bool:
    return (isinstance(a, dict) and _is_str_or_none(a.get("id"))
            and isinstance(a.get("file"), str) and isinstance(a.get("rule"), str))


def _valid_cost(c: Any) -> bool:
    return (isinstance(c, (int, float)) and not isinstance(c, bool)
            and math.isfinite(c) and c >= 0)


def _valid_round_log(entry: Any) -> bool:
    return (
        isinstance(entry, dict)
        and _is_int(entry.get("round"), 0)
        and isinstance(entry.get("sha"), str) and len(entry["sha"]) <= 12
        and isinstance(entry.get("engine"), str) and len(entry["engine"]) <= 32
        and isinstance(entry.get("ref"), str) and len(entry["ref"]) <= 12
        and _valid_cost(entry.get("cost"))
    )


_CHECKS = {
    "round": lambda v: _is_int(v, 0),
    "sha_rounds": lambda v: _is_int(v, 0),
    "findings": lambda v: isinstance(v, list) and all(_valid_finding(f) for f in v),
    "accepted": lambda v: isinstance(v, list) and all(_valid_accepted(a) for a in v),
    "reopen_counts": lambda v: isinstance(v, dict) and all(
        isinstance(k, str) and _is_int(n, 0) for k, n in v.items()),
    "escalated": lambda v: isinstance(v, bool),
    "escalation_reasons": lambda v: isinstance(v, list) and all(isinstance(r, str) for r in v),
    "cost_usd": lambda v: isinstance(v, list) and all(_valid_cost(c) for c in v),
    "last_reviewed_sha": lambda v: isinstance(v, str),
    "last_reviewed_base": lambda v: isinstance(v, str),
    "reviewed_shas": lambda v: isinstance(v, list) and all(
        isinstance(x, str) and bool(REV_SHA_RE.match(x)) for x in v),
    "guardian_ref": lambda v: isinstance(v, str) and bool(GUARDIAN_REF_RE.match(v)),
    "engine": lambda v: isinstance(v, str) and bool(ENGINE_RE.match(v)),
    "rounds_log": lambda v: isinstance(v, list) and all(_valid_round_log(e) for e in v),
    "publish_incomplete": lambda v: isinstance(v, bool),
    "publish_failures": lambda v: isinstance(v, list) and all(
        isinstance(x, str) and len(x) <= 300 for x in v),
    "id_high_water": lambda v: isinstance(v, dict) and all(
        isinstance(k, str) and bool(PREFIX_RE.match(k)) and _is_int(n, 0) for k, n in v.items()),
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
