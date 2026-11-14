#!/usr/bin/env python3
"""The /ai-review comment commands: one parser shared by route.py and verdict.py.

Usage (CLI):
  commands.py ack --repo owner/name    react "eyes" on the triggering command comment

Command text is untrusted. route.py authorises the commenter before parsing and
never copies any of it into its outputs; verdict.py re-reads the comment from
GITHUB_EVENT_PATH, re-authorises it, and renders any of it only through
textsafe. Every reply pr-guardian posts ends with a reply marker keyed to the
comment it answers, so a re-run never answers twice.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any

import gh
import state as st
import textsafe

PREFIX = "/ai-review"
WRITE_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")
ID_RE = re.compile(r"\A[A-Z][A-Z0-9]*-[0-9]{3,}\Z")
# override <head sha prefix, 12-64 lower hex>: <reason, at least 3 characters>
OVERRIDE_RE = re.compile(r"\A(?i:override)\s+([0-9a-f]{12,64})\s*:\s*(\S.{2,})\Z", re.S)
EXPLAIN_RE = re.compile(r"\A(?i:explain)\s+([A-Z][A-Z0-9]*-[0-9]{3,})\s*\Z")
_WORD_RE = re.compile(r"\A(help|explain|override)\b", re.ASCII | re.IGNORECASE)
REPLY_MARKER = "<!-- pr-guardian:reply to={kind}-{id} -->"
REPLY_RE = re.compile(r"<!-- pr-guardian:reply to=(issue|review)-([1-9][0-9]{0,19}) -->\s*\Z", re.ASCII)
KINDS = {"issue_comment": "issue", "pull_request_review_comment": "review"}


@dataclass(frozen=True)
class Command:
    name: str          # review | wontfix | escalate | help | explain | override | unknown
    arg: str = ""      # finding id for explain; head sha prefix for override
    text: str = ""     # reason for override / wontfix / escalate (untrusted)
    ok: bool = True    # False when the subcommand is recognised but malformed


def has_prefix(body: Any) -> bool:
    """True when body starts at index 0 with `/ai-review` (ASCII case-insensitive)."""
    return (isinstance(body, str)
            and body[:len(PREFIX)].isascii()
            and body[:len(PREFIX)].lower() == PREFIX)


def _reason(rest: str) -> str:
    return rest.lstrip().removeprefix(":").strip()


def parse(body: Any) -> Command | None:
    """The command in a comment body, or None when it is not a /ai-review command.

    Aligned with templates/pr-guardian.yml's GitHub Actions expressions: case-insensitive
    prefix and command names, no leading whitespace, exact bare `/ai-review`, and a
    single ASCII space before any subcommand.
    """
    if not has_prefix(body):
        return None
    after = body[len(PREFIX):]
    if after == "":
        return Command("review")
    if not after.startswith(" "):
        return Command("unknown")  # "/ai-reviewer ...", "/ai-reviewhelp", "/ai-review\n"
    rest = after[1:]
    if not rest or rest[0].isspace():
        return Command("unknown")  # "/ai-review ", "/ai-review  wontfix: ..."
    # escalate / wontfix keep route.py's historical prefix semantics.
    if rest[:8].isascii() and rest[:8].lower() == "escalate":
        return Command("escalate", text=_reason(rest[8:]))
    if rest[:7].isascii() and rest[:7].lower() == "wontfix":
        return Command("wontfix", text=_reason(rest[7:]))
    word = _WORD_RE.match(rest)
    if not word:
        return Command("unknown")
    kw = word.group(1).lower()
    if kw == "help":
        return Command("help")
    if kw == "explain":
        m = EXPLAIN_RE.match(rest)
        return Command("explain", arg=m.group(1)) if m else Command("explain", ok=False)
    m = OVERRIDE_RE.match(rest)
    if not m:
        return Command("override", ok=False)
    text = m.group(2).rstrip()
    # The reason must survive sanitising: "<!-- -->" alone is not a reason.
    if len(text) < 3 or len(textsafe.inline(text)) < 3:
        return Command("override", ok=False)
    return Command("override", arg=m.group(1), text=text)


def is_writer(comment: Any) -> bool:
    """A human (not a Bot) with write access, by the payload's author_association."""
    if not isinstance(comment, dict):
        return False
    user = comment.get("user")
    return (isinstance(user, dict) and user.get("type") != "Bot" and isinstance(user.get("login"), str)
            and bool(user["login"]) and comment.get("author_association") in WRITE_ASSOCIATIONS)


def is_owner(comment: Any, owner: str) -> bool:
    """The repo owner's own account: login, a User (never a Bot or App), and OWNER association."""
    if not isinstance(comment, dict) or not owner:
        return False
    user = comment.get("user")
    return (isinstance(user, dict) and user.get("type") == "User" and user.get("login") == owner
            and comment.get("author_association") == "OWNER")


def comment_ref(event_name: str, event: Any) -> tuple[str, int] | None:
    """("issue" | "review", comment id) for a comment event, else None."""
    kind = KINDS.get(event_name)
    comment = event.get("comment") if isinstance(event, dict) else None
    cid = comment.get("id") if isinstance(comment, dict) else None
    if kind is None or not isinstance(cid, int) or isinstance(cid, bool) or cid <= 0:
        return None
    return kind, cid


def event_pr(event_name: str, event: Any) -> int | None:
    """The PR number a comment event belongs to (issue_comment only when the issue is a PR)."""
    if not isinstance(event, dict):
        return None
    if event_name == "issue_comment":
        issue = event.get("issue")
        if not isinstance(issue, dict) or not isinstance(issue.get("pull_request"), dict):
            return None
        num = issue.get("number")
    elif event_name == "pull_request_review_comment":
        pr = event.get("pull_request")
        num = pr.get("number") if isinstance(pr, dict) else None
    else:
        return None
    return num if isinstance(num, int) and not isinstance(num, bool) and num > 0 else None


def reply_marker(kind: str, cid: int) -> str:
    return REPLY_MARKER.format(kind=kind, id=cid)


def replied(comments: list[dict[str, Any]] | None, kind: str, cid: int) -> bool:
    """True when github-actions[bot] already answered this comment (trailing reply marker)."""
    for c in comments or []:
        if not isinstance(c, dict) or not st.is_trusted_author(c.get("user")):
            continue
        m = REPLY_RE.search(c.get("body") or "") if isinstance(c.get("body"), str) else None
        if m and m.group(1) == kind and m.group(2) == str(cid):
            return True
    return False


def reply_target(comment: Any, cid: int) -> int:
    """The top-level review comment to reply under: GitHub rejects replies to replies (422)."""
    parent = comment.get("in_reply_to_id") if isinstance(comment, dict) else None
    return parent if isinstance(parent, int) and not isinstance(parent, bool) and parent > 0 else cid


def reply(repo: str, pr: int, kind: str, cid: int, body: str, reply_to: int | None = None) -> None:
    """Answer an issue comment on the PR conversation, or a review comment in its thread.

    The marker names the command comment (`cid`) so re-runs stay idempotent per command;
    `reply_to` is the thread's top-level comment when the command was itself a reply.
    """
    text = f"{body}\n\n{reply_marker(kind, cid)}"
    if kind == "review":
        gh.api(f"repos/{repo}/pulls/{pr}/comments/{reply_to or cid}/replies", "POST", {"body": text})
    else:
        gh.api(f"repos/{repo}/issues/{pr}/comments", "POST", {"body": text})


def react(repo: str, kind: str, cid: int, content: str = "eyes") -> None:
    """Acknowledge a command comment. Never raises: a reaction is a courtesy."""
    path = (f"repos/{repo}/pulls/comments/{cid}/reactions" if kind == "review"
            else f"repos/{repo}/issues/comments/{cid}/reactions")
    try:
        gh.api(path, "POST", {"content": content})
    except gh.GhError as exc:
        print(f"::notice::pr-guardian could not react to comment {cid}: {textsafe.inline(exc)[:200]}")


HELP_ROWS = (
    ("`/ai-review`", "owner", "PR conversation", "full re-review of the current head"),
    ("`/ai-review wontfix: <reason>`", "writer", "inside the finding's thread",
     "pushback, judged in the next round"),
    ("`/ai-review escalate: <why>`", "writer", "anywhere", "applies `needs-human`"),
    ("`/ai-review explain <ID>`", "writer", "anywhere", "explains a finding"),
    ("`/ai-review override <head-sha>: <reason>`", "owner", "PR conversation",
     "accepts this head as it stands (works for fork PRs)"),
    ("`/ai-review help`", "writer", "anywhere", "this table"),
    ("apply the `human-override` label", "owner", "PR", "accepts the labelled head"),
    ("remove the `needs-human` label", "owner", "PR",
     "acknowledges this round's escalation (not for workflow changes)"),
)


def help_text(owner: str) -> str:
    who = textsafe.inline(owner).replace("`", "'") or "the repository owner"
    rows = "\n".join(f"| {c} | {w} | {where} | {effect} |" for c, w, where, effect in HELP_ROWS)
    return ("**pr-guardian commands**\n\n| Command | Who | Where | Effect |\n| :--- | :--- | :--- | :--- |\n"
            f"{rows}\n\nWriters are the owner, org members and collaborators; the owner is `{who}`.")


def load_event() -> tuple[str, dict[str, Any]]:
    """GITHUB_EVENT_NAME and the parsed GITHUB_EVENT_PATH payload ({} when unreadable)."""
    name = os.environ.get("GITHUB_EVENT_NAME", "")
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not path:
        return name, {}
    try:
        with open(path, encoding="utf-8") as fh:
            event = json.load(fh)
    except (OSError, ValueError):
        return name, {}
    return name, event if isinstance(event, dict) else {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    ack = sub.add_parser("ack", help="react 'eyes' on the triggering /ai-review comment")
    ack.add_argument("--repo", required=True)
    args = ap.parse_args()
    if args.cmd == "ack":
        name, event = load_event()
        ref = comment_ref(name, event)
        comment = event.get("comment")
        if (ref and event_pr(name, event) is not None and is_writer(comment)
                and parse(comment.get("body")) is not None):
            react(args.repo, *ref)
    return 0


if __name__ == "__main__":
    sys.exit(main())
