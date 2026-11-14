#!/usr/bin/env python3
"""Decide what a pr-guardian run should do for the triggering event.

Reads GITHUB_EVENT_NAME / GITHUB_EVENT_PATH and writes `action`, `pr`,
`head_sha`, `escalate`, `reason` and `bind_override` to GITHUB_OUTPUT (or stdout).

action:
  review   full scan + model review + publish + verdict
  verdict  recompute the verdict only (labels, escalation); no model call
  skip     nothing to do

The routing table is deliberately small. Anything unrecognised is `skip`,
because a skipped run leaves the required status pending (merge blocked),
which fails closed.

A `pull_request.edited` event is a review only when it retargets the base
(`changes.base.ref.from` is a non-empty string): the verdict is bound to the
reviewed head SHA *and* base ref, so a retarget needs a fresh review against
the new base (GHSA-6h55-p37r-jc34). Title and body edits are skipped.

bind_override is "true" only for a `human-override` label the owner (a User,
not a Bot) just applied: verdict.py then records which head SHA and base ref
that application covers (GHSA-q4j9-99qr-cfhw).
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

WRITE_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")
PR_REVIEW_TYPES = ("opened", "synchronize", "reopened", "ready_for_review")
BASE_CHANGE_TYPE = "edited"  # reviewed only when the edit retargets the base
OUTPUT_KEYS = ("action", "pr", "head_sha", "escalate", "reason", "bind_override")
OVERRIDE_LABEL = "human-override"
VALID_ACTIONS = frozenset({"review", "verdict", "skip"})
VALID_ESCALATE = frozenset({"true", "false"})
VALID_BOOL = VALID_ESCALATE

PR_REVIEW_REASONS = {
    "opened": "pull_request.opened",
    "synchronize": "pull_request.synchronize",
    "reopened": "pull_request.reopened",
    "ready_for_review": "pull_request.ready_for_review",
    "edited": "pull_request.edited",
}

SAFE_SKIP: dict[str, str] = {
    "action": "skip",
    "pr": "",
    "head_sha": "",
    "escalate": "false",
    "reason": "invalid route output",
    "bind_override": "false",
}

REASONS = frozenset({
    *PR_REVIEW_REASONS.values(),
    "human-override label applied",
    "human-override label removed",
    "label is not a pr-guardian control",
    "pull_request action does not trigger a review",
    "draft PR; review starts when marked ready",
    "external fork PR: secrets are unavailable, owner review required",
    "not a /ai-review command",
    "comment is on an issue, not a PR",
    "commenter has no write access",
    "escalated by a writer",
    "pushback from a writer",
    "only the owner can force a re-review",
    "re-review requested by owner",
    "unknown /ai-review command",
    "manual dispatch",
    "invalid workflow_dispatch pr",
    "invalid PR metadata",
    "event not handled",
    SAFE_SKIP["reason"],
})

_PR_RE = re.compile(r"\A[1-9][0-9]{0,9}\Z", re.ASCII)
# decide() accepts any lower-hex SHA up to 64 chars so existing unit fixtures
# with short SHAs keep passing, while validate_output() enforces 40 or 64 chars.
_DECIDE_SHA_RE = re.compile(r"\A[0-9a-f]{0,64}\Z", re.ASCII)
_OUTPUT_SHA_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})?\Z", re.ASCII)


def _is_valid_pr(value: Any, *, allow_empty: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    if value == "":
        return allow_empty
    return value.isascii() and value.isdigit() and bool(_PR_RE.fullmatch(value))


def _coerce_pr(raw: Any) -> str:
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        return ""
    text = str(raw)
    return text if _is_valid_pr(text) else ""


def _extract_pr_fields(pr_obj: Any) -> tuple[str, str] | None:
    if not isinstance(pr_obj, dict):
        return None
    pr_num = _coerce_pr(pr_obj.get("number"))
    head = pr_obj.get("head")
    head_sha = head.get("sha", "") if isinstance(head, dict) else ""
    if not pr_num or not isinstance(head_sha, str) or not _DECIDE_SHA_RE.fullmatch(head_sha):
        return None
    return pr_num, head_sha


def _has_base_change(event: dict[str, Any]) -> bool:
    """True when a pull_request.edited payload records a previous base ref (a retarget)."""
    changes = event.get("changes")
    base = changes.get("base") if isinstance(changes, dict) else None
    ref = base.get("ref") if isinstance(base, dict) else None
    prev = ref.get("from") if isinstance(ref, dict) else None
    return isinstance(prev, str) and bool(prev)


def _check_output(out: Any) -> str | None:
    if not isinstance(out, dict):
        return "output must be a dict"
    if tuple(out.keys()) != OUTPUT_KEYS:
        return "unexpected output keys or order"
    for key in OUTPUT_KEYS:
        val = out[key]
        if not isinstance(val, str):
            return f"non-string field: {key}"
        if "\r" in val or "\n" in val:
            return f"newline in field: {key}"
    if out["action"] not in VALID_ACTIONS:
        return "invalid action"
    if out["escalate"] not in VALID_ESCALATE:
        return "invalid escalate"
    if out["bind_override"] not in VALID_BOOL:
        return "invalid bind_override"
    if not _is_valid_pr(out["pr"], allow_empty=(out["action"] == "skip")):
        return "invalid pr"
    if not _OUTPUT_SHA_RE.fullmatch(out["head_sha"]):
        return "invalid head_sha"
    reason = out["reason"]
    if not reason or not all(0x20 <= ord(ch) <= 0x7E for ch in reason) or reason not in REASONS:
        return "invalid reason"
    return None


def validate_output(out: Any) -> dict[str, str]:
    """Enforce the GITHUB_OUTPUT schema; fail closed to SAFE_SKIP on violation."""
    err = _check_output(out)
    if err is not None:
        print(json.dumps({"error": "invalid route output", "detail": err}), file=sys.stderr)
        return dict(SAFE_SKIP)
    return {k: out[k] for k in OUTPUT_KEYS}


def decide(event_name: str, event: dict[str, Any], owner: str) -> dict[str, Any]:
    out = {"action": "skip", "pr": "", "head_sha": "", "escalate": "false", "reason": "",
           "bind_override": "false"}

    if event_name in ("pull_request", "pull_request_target"):
        pr = event.get("pull_request")
        fields = _extract_pr_fields(pr)
        if fields is None:
            out["reason"] = "invalid PR metadata"
            return out
        head_repo = pr["head"].get("repo") if isinstance(pr.get("head"), dict) else None
        base = pr.get("base")
        base_repo = base.get("repo") if isinstance(base, dict) else None
        if not isinstance(base_repo, dict) or not isinstance(base_repo.get("full_name"), str):
            out["reason"] = "invalid PR metadata"
            return out
        out["pr"], out["head_sha"] = fields
        fork = head_repo is None or not isinstance(head_repo, dict) or head_repo.get("full_name") != base_repo["full_name"]
        action = event.get("action")
        if action in ("labeled", "unlabeled"):
            label = event.get("label")
            name = label.get("name") if isinstance(label, dict) else None
            if name != OVERRIDE_LABEL:
                out["reason"] = "label is not a pr-guardian control"
                return out
            if action == "unlabeled":
                # Recompute so a success the override produced does not outlive the label (#27).
                out.update(action="verdict", reason="human-override label removed")
                return out
            sender = event.get("sender")
            sender = sender if isinstance(sender, dict) else {}
            login = sender.get("login")
            by_owner = (bool(owner) and isinstance(login, str) and login == owner
                        and sender.get("type") != "Bot")
            out.update(action="verdict", reason="human-override label applied",
                       bind_override="true" if by_owner else "false")
            return out
        retarget = action == BASE_CHANGE_TYPE and _has_base_change(event)
        if action not in PR_REVIEW_TYPES and not retarget:
            out["reason"] = "pull_request action does not trigger a review"
            return out
        if pr.get("draft"):
            out["reason"] = "draft PR; review starts when marked ready"
            return out
        if fork:
            out.update(action="verdict", reason="external fork PR: secrets are unavailable, owner review required")
            return out
        out.update(action="review", reason=PR_REVIEW_REASONS[action])
        return out

    if event_name in ("issue_comment", "pull_request_review_comment"):
        comment = event.get("comment")
        if not isinstance(comment, dict):
            out["reason"] = "not a /ai-review command"
            return out
        raw_body = comment.get("body")
        body = raw_body.strip() if isinstance(raw_body, str) else ""
        user = comment.get("user")
        user_dict = user if isinstance(user, dict) else {}
        if user_dict.get("type") == "Bot" or not body.startswith("/ai-review"):
            out["reason"] = "not a /ai-review command"
            return out
        if event_name == "issue_comment":
            issue = event.get("issue")
            if not isinstance(issue, dict) or "pull_request" not in issue:
                out["reason"] = "comment is on an issue, not a PR"
                return out
            pr_num = _coerce_pr(issue.get("number"))
            if not pr_num:
                out["reason"] = "invalid PR metadata"
                return out
            out["pr"] = pr_num
        else:
            fields = _extract_pr_fields(event.get("pull_request"))
            if fields is None:
                out["reason"] = "invalid PR metadata"
                return out
            out["pr"], out["head_sha"] = fields
        # Authorise before parsing any subcommand or reading user-controlled text.
        assoc = comment.get("author_association", "")
        if not isinstance(assoc, str) or assoc not in WRITE_ASSOCIATIONS:
            out["reason"] = "commenter has no write access"
            return out
        login = user_dict.get("login", "")
        rest = body[len("/ai-review"):].strip()
        if rest.startswith("escalate"):
            out.update(action="verdict", escalate="true", reason="escalated by a writer")
        elif rest.startswith("wontfix"):
            out.update(action="review", reason="pushback from a writer")
        elif rest == "":
            if not isinstance(login, str) or not owner or login != owner:
                out["reason"] = "only the owner can force a re-review"
                return out
            out.update(action="review", reason="re-review requested by owner")
        else:
            out["reason"] = "unknown /ai-review command"
        return out

    if event_name == "workflow_dispatch":
        inputs = event.get("inputs")
        raw_pr = inputs.get("pr", "") if isinstance(inputs, dict) else ""
        pr = _coerce_pr(raw_pr)
        if not pr:
            out["reason"] = "invalid workflow_dispatch pr"
            return out
        out.update(action="review", pr=pr, reason="manual dispatch")
        return out

    out["reason"] = "event not handled"
    return out


def main() -> int:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    owner = os.environ.get("PRG_OWNER") or os.environ.get("GITHUB_REPOSITORY_OWNER", "")
    try:
        with open(path, encoding="utf-8") as fh:
            event = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"route: cannot read event: {exc}", file=sys.stderr)
        return 2
    if not isinstance(event, dict):
        print(json.dumps({"error": "event payload must be a JSON object"}), file=sys.stderr)
        return 2
    result = validate_output(decide(event_name, event, owner))
    lines = "".join(f"{k}={v}\n" for k, v in result.items())
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(lines)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
