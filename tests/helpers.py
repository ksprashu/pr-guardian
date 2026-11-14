import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


def finding(id="R-001", severity="P1", status="new", prior_id=None, file="app.py", start=3, end=3,
            rule="CWE-89", axis="security", **extra):
    f = {"id": id, "severity": severity, "axis": axis, "rule": rule, "title": f"title {id}",
         "file": file, "start_line": start, "end_line": end, "rationale": f"why {id}",
         "evidence": "", "suggestion": "", "references": [], "confidence": "high",
         "status": status, "prior_id": prior_id, "security_verdict": "confirmed"}
    f.update(extra)
    return f


def doc(*findings):
    return {"schema_version": "1", "producer": "review", "mode": "pr", "summary": "s",
            "inspected": [], "not_inspected": [], "findings": list(findings)}


BOT = "github-actions"


def comment(login="dev", body="/ai-review wontfix: because", typename=None, association=None):
    """One review-thread comment as GraphQL returns it. login=None is a deleted (ghost) user."""
    if typename is None:
        typename = "Bot" if login in (BOT, "github-actions[bot]") else "User"
    if association is None:
        association = "NONE" if typename == "Bot" else "COLLABORATOR"
    author = None if login is None else {"__typename": typename, "login": login}
    return {"author": author, "authorAssociation": association, "body": body, "createdAt": ""}


def thread(fid, tid=None, resolved=False, last_author=BOT, severity="P1", last_type=None,
           last_association=None, last_body="/ai-review wontfix: because", opener=None, replies=None,
           has_next_page=False):
    """A finding thread opened by the bot. `replies` (a list of comment()) replaces the
    default single reply from `last_author`; `opener` replaces the bot's opening comment."""
    first = opener or comment(BOT, f"<!-- pr-guardian:finding id={fid} severity={severity} -->\nbody")
    nodes = [first]
    if replies is not None:
        nodes += replies
    elif last_author != BOT:
        nodes.append(comment(last_author, last_body, last_type, last_association))
    return {"id": tid or f"T-{fid}", "isResolved": resolved, "isOutdated": False,
            "path": "app.py", "line": 3,
            "comments": {"pageInfo": {"hasNextPage": has_next_page}, "nodes": nodes}}


DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,5 @@
 import os
+import sqlite3
+q = "SELECT * FROM t WHERE id=" + uid
 x = 1
 y = 2
"""
