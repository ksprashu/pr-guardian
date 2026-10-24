#!/usr/bin/env python3
"""Decide what a pr-guardian run should do for the triggering event.

Reads GITHUB_EVENT_NAME / GITHUB_EVENT_PATH and writes `action`, `pr`,
`head_sha`, `escalate` and `reason` to GITHUB_OUTPUT (or stdout).

action:
  review   full scan + model review + publish + verdict
  verdict  recompute the verdict only (labels, escalation); no model call
  skip     nothing to do

The routing table is deliberately small. Anything unrecognised is `skip`,
because a skipped run leaves the required status pending (merge blocked),
which fails closed.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

WRITE_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")
PR_REVIEW_TYPES = ("opened", "synchronize", "reopened", "ready_for_review")


def decide(event_name: str, event: dict[str, Any], owner: str) -> dict[str, Any]:
    out = {"action": "skip", "pr": "", "head_sha": "", "escalate": "false", "reason": ""}

    if event_name in ("pull_request", "pull_request_target"):
        pr = event["pull_request"]
        out["pr"], out["head_sha"] = str(pr["number"]), pr["head"]["sha"]
        fork = pr["head"]["repo"] is None or pr["head"]["repo"]["full_name"] != pr["base"]["repo"]["full_name"]
        action = event.get("action")
        if action == "labeled":
            name = event.get("label", {}).get("name")
            if name == "human-override":
                out.update(action="verdict", reason="human-override label applied")
            else:
                out["reason"] = f"label {name} is not a pr-guardian control"
            return out
        if action not in PR_REVIEW_TYPES:
            out["reason"] = f"pull_request.{action} does not trigger a review"
            return out
        if pr.get("draft"):
            out["reason"] = "draft PR; review starts when marked ready"
            return out
        if fork:
            out.update(action="verdict", reason="external fork PR: secrets are unavailable, owner review required")
            return out
        out.update(action="review", reason=f"pull_request.{action}")
        return out

    if event_name in ("issue_comment", "pull_request_review_comment"):
        comment = event["comment"]
        body = (comment.get("body") or "").strip()
        if comment.get("user", {}).get("type") == "Bot" or not body.startswith("/ai-review"):
            out["reason"] = "not a /ai-review command"
            return out
        if event_name == "issue_comment":
            if "pull_request" not in event.get("issue", {}):
                out["reason"] = "comment is on an issue, not a PR"
                return out
            out["pr"] = str(event["issue"]["number"])
        else:
            out["pr"] = str(event["pull_request"]["number"])
            out["head_sha"] = event["pull_request"]["head"]["sha"]
        assoc = comment.get("author_association", "")
        login = comment.get("user", {}).get("login", "")
        rest = body[len("/ai-review"):].strip()
        if rest.startswith("escalate"):
            if assoc not in WRITE_ASSOCIATIONS:
                out["reason"] = f"{login} cannot escalate"
                return out
            out.update(action="verdict", escalate="true", reason=f"escalated by {login}")
        elif rest.startswith("wontfix"):
            if assoc not in WRITE_ASSOCIATIONS:
                out["reason"] = f"{login} cannot push back on findings"
                return out
            out.update(action="review", reason=f"pushback from {login}")
        elif rest == "":
            if login != owner:
                out["reason"] = "only the owner can force a re-review"
                return out
            out.update(action="review", reason="re-review requested by owner")
        else:
            out["reason"] = f"unknown command: /ai-review {rest[:40]}"
        return out

    if event_name == "workflow_dispatch":
        pr = str(event.get("inputs", {}).get("pr", ""))
        if pr:
            out.update(action="review", pr=pr, reason="manual dispatch")
        return out

    out["reason"] = f"event {event_name} not handled"
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
    result = decide(event_name, event, owner)
    lines = "".join(f"{k}={v}\n" for k, v in result.items())
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(lines)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
