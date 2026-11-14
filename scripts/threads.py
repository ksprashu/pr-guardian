"""Fetch and interpret a PR's review threads.

Thread comments are written by anyone who can comment on the PR, so nothing
here trusts a comment for what it says. A finding thread counts only when the
pr-guardian bot opened it, and each reply carries who wrote it and their
association so callers can drop outsiders (GHSA-j3g5-fvc6-rrjw).
"""

from __future__ import annotations

from typing import Any

import gh
from state import FINDING_RE

THREADS_QUERY = """
query($owner:String!, $name:String!, $pr:Int!, $cursor:String) {
  repository(owner:$owner, name:$name) {
    pullRequest(number:$pr) {
      reviewThreads(first:100, after:$cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id isResolved isOutdated path line
          comments(first:100) {
            pageInfo { hasNextPage }
            nodes { author { __typename login } authorAssociation body createdAt url }
          }
        }
      }
    }
  }
}"""

# The identity GITHUB_TOKEN posts as. Checked together with __typename == "Bot",
# because a user account can be named "github-actions"-like but is never a Bot.
BOT_LOGINS = ("github-actions", "github-actions[bot]")
WRITE_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})


def fetch(repo: str, pr: int) -> list[dict[str, Any]]:
    owner, name = repo.split("/", 1)
    nodes: list[dict[str, Any]] = []
    cursor = None
    while True:
        data = gh.graphql(THREADS_QUERY, owner=owner, name=name, pr=pr, cursor=cursor)
        page = data["repository"]["pullRequest"]["reviewThreads"]
        nodes.extend(page["nodes"])
        if not page["pageInfo"]["hasNextPage"]:
            return nodes
        cursor = page["pageInfo"]["endCursor"]


def comments(thread: dict[str, Any] | None) -> list[dict[str, Any]]:
    block = (thread or {}).get("comments")
    nodes = block.get("nodes") if isinstance(block, dict) else None
    return [c for c in nodes if isinstance(c, dict)] if isinstance(nodes, list) else []


def truncated(thread: dict[str, Any] | None) -> bool:
    """True when GitHub returned only the first page of the thread's comments."""
    block = (thread or {}).get("comments")
    info = block.get("pageInfo") if isinstance(block, dict) else None
    return isinstance(info, dict) and info.get("hasNextPage") is True


def is_bot(c: dict[str, Any]) -> bool:
    """Written by pr-guardian itself (the Actions bot), not by a user or another app."""
    author = c.get("author")
    return (isinstance(author, dict) and author.get("__typename") == "Bot"
            and author.get("login") in BOT_LOGINS)


def is_writer(c: dict[str, Any]) -> bool:
    """Written by a human with write access (owner, org member or collaborator)."""
    author = c.get("author")
    return (isinstance(author, dict) and author.get("__typename") != "Bot"
            and isinstance(author.get("login"), str) and bool(author.get("login"))
            and c.get("authorAssociation") in WRITE_ASSOCIATIONS)


def by_finding(threads: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map finding id -> thread, using the marker in a bot-opened thread's first comment.

    A thread opened by anyone else is ignored even when it carries the marker, and the
    first bot thread for an id wins, so a later decoy cannot replace it.
    """
    out: dict[str, dict[str, Any]] = {}
    for t in threads:
        nodes = comments(t)
        if not nodes or not is_bot(nodes[0]):
            continue
        m = FINDING_RE.search(nodes[0].get("body") or "")
        if m:
            out.setdefault(m.group(1), t)
    return out


def replies(thread: dict[str, Any]) -> list[dict[str, Any]]:
    """Every comment after the bot's opening comment, oldest first, with its provenance."""
    out = []
    for c in comments(thread)[1:]:
        author = c.get("author") if isinstance(c.get("author"), dict) else {}
        login = author.get("login") if isinstance(author.get("login"), str) else ""
        out.append({"author": login or "ghost", "body": c.get("body") or "", "at": c.get("createdAt", ""),
                    "login": login, "author_type": author.get("__typename") or "",
                    "association": c.get("authorAssociation") or "",
                    "is_bot": is_bot(c), "is_writer": is_writer(c)})
    return out
