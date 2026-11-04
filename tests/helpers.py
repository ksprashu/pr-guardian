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


def thread(fid, tid=None, resolved=False, last_author="github-actions", severity="P1", key=None,
           path="app.py", line=3, rule="CWE-89", opener="github-actions"):
    marker = f"<!-- pr-guardian:finding id={fid} severity={severity}" + (f" key={key}" if key else "") + " -->"
    nodes = [{"author": {"login": opener}, "url": f"https://github.com/o/r/pull/1#discussion_{fid}",
              "body": f"{marker}\n**{severity} · security · {rule}** · title {fid}\n\nwhy"}]
    if last_author != "github-actions":
        nodes.append({"author": {"login": last_author}, "body": "/ai-review wontfix: because"})
    return {"id": tid or f"T-{fid}", "isResolved": resolved, "isOutdated": False,
            "path": path, "line": line, "comments": {"nodes": nodes}}


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
