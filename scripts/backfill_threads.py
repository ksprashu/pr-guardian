#!/usr/bin/env python3
"""Opt-in owner backfill CLI to resolve stale pr-guardian threads (#18).

Usage:
  backfill_threads.py --repo owner/name (--pr N | --all-open)
                      [--apply] [--include-orphans] [--max 50]

Dry-run by default: prints a JSON report of candidate threads whose marker id is
referenced only by closed findings in trusted pr-guardian state (and by no open
finding). Orphans (marker ids absent from state) are listed, and resolved only
when `--include-orphans` is passed AND the thread is `isOutdated`.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import gh
import publish_review as pub
import state as st
import threads as th


def _finding_refs(f: dict[str, Any]) -> set[str]:
    return {
        val for key in ("id", "prior_id", "thread_key")
        if isinstance(val := f.get(key), str) and val
    }


def plan_pr(pr: int, state: dict[str, Any] | None, thread_list: list[dict[str, Any]], *,
            include_orphans: bool = False) -> dict[str, Any]:
    """Identify candidate and orphan threads on `pr` from trusted `state`."""
    if state is None:
        return {"pr": pr, "has_state": False, "candidates": [], "orphans": []}

    open_refs: set[str] = set()
    closed_refs: set[str] = set()
    for f in state.get("findings", []):
        if not isinstance(f, dict):
            continue
        refs = _finding_refs(f)
        if f.get("status") in st.CLOSED:
            closed_refs |= refs
        else:
            open_refs |= refs
    for acc in state.get("accepted", []):
        if isinstance(acc, dict) and isinstance(acc.get("id"), str) and acc["id"]:
            closed_refs.add(acc["id"])

    mapped = th.by_finding(thread_list)
    candidates: list[dict[str, Any]] = []
    orphans: list[dict[str, Any]] = []

    for marker_id, t in mapped.items():
        if t.get("isResolved"):
            continue
        nodes = th.comments(t)
        url = (nodes[0].get("url") if nodes and isinstance(nodes[0], dict) else "") or ""
        outdated = bool(t.get("isOutdated"))
        if marker_id in open_refs:
            continue
        if marker_id in closed_refs:
            candidates.append({
                "pr": pr,
                "marker_id": marker_id,
                "thread": t["id"],
                "path": t.get("path"),
                "line": t.get("line"),
                "outdated": outdated,
                "url": url,
                "reason": "closed_in_state",
            })
        else:
            will_resolve = bool(include_orphans and outdated)
            orphans.append({
                "pr": pr,
                "marker_id": marker_id,
                "thread": t["id"],
                "path": t.get("path"),
                "line": t.get("line"),
                "outdated": outdated,
                "url": url,
                "will_resolve": will_resolve,
            })
            if will_resolve:
                candidates.append({
                    "pr": pr,
                    "marker_id": marker_id,
                    "thread": t["id"],
                    "path": t.get("path"),
                    "line": t.get("line"),
                    "outdated": True,
                    "url": url,
                    "reason": "outdated_orphan",
                })

    return {"pr": pr, "has_state": True, "candidates": candidates, "orphans": orphans}


def _apply_candidate(cand: dict[str, Any], thread_obj: dict[str, Any] | None) -> None:
    mid = pub._marker_id(cand["marker_id"])
    status_line = pub.STATUS_MARKER.format(id=mid, status="swept")
    body = f"{status_line}\n✅ Swept: this finding is closed in pr-guardian's state."
    if thread_obj is None or pub._tail_status(thread_obj) != status_line:
        gh.graphql(pub.REPLY, id=cand["thread"], body=body)
    gh.graphql(pub.RESOLVE, id=cand["thread"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--pr", type=int)
    target.add_argument("--all-open", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--include-orphans", action="store_true")
    ap.add_argument("--max", type=int, default=50)
    args = ap.parse_args()

    max_sweeps = max(0, args.max)
    if args.pr is not None:
        pr_numbers = [args.pr]
    else:
        pulls = gh.api(f"repos/{args.repo}/pulls?state=open&per_page=100", paginate=True) or []
        pr_numbers = [p["number"] for p in pulls if isinstance(p, dict) and isinstance(p.get("number"), int)]

    all_candidates: list[dict[str, Any]] = []
    all_orphans: list[dict[str, Any]] = []
    swept: list[dict[str, Any]] = []
    errors: list[str] = []

    for pr_num in pr_numbers:
        comments = gh.api(f"repos/{args.repo}/issues/{pr_num}/comments", paginate=True) or []
        summary = st.find_summary_comment(comments)
        decoded = st.decode(summary["body"]) if summary else None
        thread_list = th.fetch(args.repo, pr_num) if decoded is not None else []
        plan = plan_pr(pr_num, decoded, thread_list, include_orphans=args.include_orphans)
        all_candidates.extend(plan["candidates"])
        all_orphans.extend(plan["orphans"])

        if args.apply and plan["candidates"]:
            threads_by_id = {t["id"]: t for t in thread_list if isinstance(t, dict) and "id" in t}
            for cand in plan["candidates"]:
                if len(swept) >= max_sweeps:
                    break
                try:
                    _apply_candidate(cand, threads_by_id.get(cand["thread"]))
                    swept.append(cand)
                except gh.GhError as exc:
                    msg = f"PR #{pr_num} {cand['thread']}: {pub.inline(str(exc))}"[:300]
                    errors.append(msg)
                    print(f"::warning::backfill: {msg}", file=sys.stderr)

    report = {
        "mode": "apply" if args.apply else "dry-run",
        "repo": args.repo,
        "prs_checked": pr_numbers,
        "candidates": all_candidates,
        "orphans": all_orphans,
        "swept": swept,
        "errors": errors,
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
