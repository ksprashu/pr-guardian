"""Fetch and interpret a PR's review threads."""

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
          comments(first:50) { nodes { author { login } body createdAt } }
        }
      }
    }
  }
}"""


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


def by_finding(threads: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map finding id -> thread, using the marker in the thread's first comment."""
    out: dict[str, dict[str, Any]] = {}
    for t in threads:
        comments = t.get("comments", {}).get("nodes", [])
        if not comments:
            continue
        m = FINDING_RE.search(comments[0].get("body") or "")
        if m:
            out[m.group(1)] = t
    return out


def replies(thread: dict[str, Any]) -> list[dict[str, str]]:
    """Every comment after the bot's opening comment, oldest first."""
    comments = thread.get("comments", {}).get("nodes", [])[1:]
    return [{"author": (c.get("author") or {}).get("login", "ghost"),
             "body": c.get("body") or "", "at": c.get("createdAt", "")} for c in comments]
