"""Fetch and interpret a PR's review threads."""

from __future__ import annotations

import re
from typing import Any

import gh
from state import FINDING_RE

BOT_LOGINS = ("github-actions", "github-actions[bot]")

THREADS_QUERY = """
query($owner:String!, $name:String!, $pr:Int!, $cursor:String) {
  repository(owner:$owner, name:$name) {
    pullRequest(number:$pr) {
      reviewThreads(first:100, after:$cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id isResolved isOutdated path line
          comments(first:50) { nodes { author { login } body createdAt url } }
        }
      }
    }
  }
}"""

# Second line of finding_body(): "**P1 · security · CWE-89** · title"
_HEADLINE_RE = re.compile(r"^\*\*(?:P[0-3]|nit) · [^·\n]+ · (.+?)\*\* · ", re.M)


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


def _first(thread: dict[str, Any]) -> dict[str, Any] | None:
    nodes = thread.get("comments", {}).get("nodes", [])
    return nodes[0] if nodes else None


def is_bot(comment: dict[str, Any] | None) -> bool:
    return bool(comment) and (comment.get("author") or {}).get("login") in BOT_LOGINS


def meta(thread: dict[str, Any]) -> dict[str, Any] | None:
    """The finding a bot-opened thread belongs to, or None for any other thread.

    Only threads whose first comment the bot wrote count, so a human cannot claim a
    finding by pasting a marker, and human threads are never touched.
    """
    first = _first(thread)
    if not is_bot(first):
        return None
    body = first.get("body") or ""
    m = FINDING_RE.search(body)
    if not m:
        return None
    rule = _HEADLINE_RE.search(body)
    return {"id": m.group(1), "severity": m.group(2), "key": m.group(3) or m.group(1),
            "rule": rule.group(1) if rule else None, "url": first.get("url", "")}


def by_finding(threads: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map thread_key -> bot thread. Legacy markers (no key) map by their id, which is the key."""
    out: dict[str, dict[str, Any]] = {}
    for t in threads:
        m = meta(t)
        if m:
            out.setdefault(m["key"], t)
    return out


def url(thread: dict[str, Any] | None) -> str:
    first = _first(thread or {})
    return (first or {}).get("url", "")


def replies(thread: dict[str, Any]) -> list[dict[str, str]]:
    """Every comment after the bot's opening comment, oldest first."""
    comments = thread.get("comments", {}).get("nodes", [])[1:]
    return [{"author": (c.get("author") or {}).get("login", "ghost"),
             "body": c.get("body") or "", "at": c.get("createdAt", "")} for c in comments]
