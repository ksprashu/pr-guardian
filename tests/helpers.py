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


def thread(fid, tid=None, resolved=False, last_author="github-actions", severity="P1"):
    nodes = [{"author": {"login": "github-actions"},
              "body": f"<!-- pr-guardian:finding id={fid} severity={severity} -->\nbody"}]
    if last_author != "github-actions":
        nodes.append({"author": {"login": last_author}, "body": "/ai-review wontfix: because"})
    return {"id": tid or f"T-{fid}", "isResolved": resolved, "isOutdated": False,
            "path": "app.py", "line": 3, "comments": {"nodes": nodes}}


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
