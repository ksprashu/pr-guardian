#!/usr/bin/env python3
"""Post the required commit status `pr-guardian/verdict` on the PR head.

Usage:
  verdict.py --repo owner/name --pr N [--sha HEAD] [--escalate true|false]
             [--reason TEXT] [--review-result success|failure|cancelled|skipped]
             [--dry-run]

Decision order (first match wins):
  1. human-override label, applied by the repo owner      -> success
  2. review job did not succeed                           -> error (merge blocked)
  3. needs-human label present, or escalation this round   -> failure (+ label)
  4. no review recorded for this head SHA                 -> pending
  5. open P0-P3 findings                                  -> failure
  6. otherwise                                            -> success

An override covers only the commit it was applied to: on a new push the
workflow passes --clear-override and the label is removed before deciding.

A commit status (not a check run) is used so that runs triggered by
issue_comment, which execute on the default branch, still land on the PR head.
Fails closed: any error leaves the status non-success.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import gh
import state as st

CONTEXT = "pr-guardian/verdict"
OVERRIDE_LABEL = "human-override"
ESCALATION_LABEL = "needs-human"
BLOCKING = ("P0", "P1", "P2", "P3")
CLOSED = ("fixed", "accepted_pushback")


def override_by_owner(events: list[dict[str, Any]], labels: list[str], owner: str) -> bool:
    """True when the label is on the PR and its most recent application was by the owner."""
    if OVERRIDE_LABEL not in labels:
        return False
    applied = [e for e in events
               if e.get("event") == "labeled" and (e.get("label") or {}).get("name") == OVERRIDE_LABEL]
    return bool(applied) and (applied[-1].get("actor") or {}).get("login") == owner


def decide(*, state: dict[str, Any] | None, sha: str, labels: list[str], events: list[dict[str, Any]],
           owner: str, escalate: bool, reason: str, review_result: str, fork: bool) -> dict[str, Any]:
    s = state or st.empty_state()
    if override_by_owner(events, labels, owner):
        return {"state": "success", "description": f"Overridden by {owner} (human-override)"}
    if fork:
        return {"state": "failure",
                "description": f"External fork PR: not auto-reviewed. {owner} reviews, then applies human-override"}
    if review_result not in ("", "success", "skipped"):
        return {"state": "error", "description": f"Review job {review_result}; re-run, or comment /ai-review"}
    if ESCALATION_LABEL in labels and not escalate and not s.get("escalated"):
        return {"state": "failure", "description": f"Needs human: waiting for {owner} to apply {OVERRIDE_LABEL}"}
    if escalate or s.get("escalated"):
        why = reason or "; ".join(s.get("escalation_reasons", [])[-2:]) or "escalated"
        return {"state": "failure", "label": ESCALATION_LABEL,
                "description": f"Needs human: {why}"}
    if s.get("last_reviewed_sha") != sha:
        return {"state": "pending", "description": "Review in progress for this commit"}
    open_blocking = [f for f in s.get("findings", [])
                     if f["severity"] in BLOCKING and f.get("status") not in CLOSED]
    if open_blocking:
        counts = ", ".join(f"{sum(1 for f in open_blocking if f['severity'] == sev)} {sev}"
                           for sev in BLOCKING if any(f["severity"] == sev for f in open_blocking))
        return {"state": "failure",
                "description": f"Round {s['round']}: {counts} open. Fix or push back in the threads"}
    nits = sum(1 for f in s.get("findings", []) if f["severity"] == "nit" and f.get("status") not in CLOSED)
    return {"state": "success",
            "description": f"Round {s['round']}: clean" + (f" ({nits} nits, non-blocking)" if nits else "")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--sha", default="")
    ap.add_argument("--escalate", default="false")
    ap.add_argument("--reason", default="")
    ap.add_argument("--review-result", default="")
    ap.add_argument("--clear-override", default="false",
                    help="true on a new push: an override covers only the code it was applied to")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    owner = os.environ.get("PRG_OWNER") or args.repo.split("/", 1)[0]

    pr = gh.api(f"repos/{args.repo}/pulls/{args.pr}")
    sha = args.sha or pr["head"]["sha"]
    if sha != pr["head"]["sha"]:
        print(f"verdict: {sha[:7]} is no longer the head; a newer run owns the verdict")
        return 0
    head_repo = (pr["head"].get("repo") or {}).get("full_name")
    fork = head_repo != pr["base"]["repo"]["full_name"]
    labels = [lbl["name"] for lbl in pr.get("labels", [])]
    if args.clear_override == "true" and OVERRIDE_LABEL in labels:
        if not args.dry_run:
            gh.api(f"repos/{args.repo}/issues/{args.pr}/labels/{OVERRIDE_LABEL}", "DELETE")
        labels.remove(OVERRIDE_LABEL)
    events = gh.api(f"repos/{args.repo}/issues/{args.pr}/events", paginate=True)
    summary = st.find_summary_comment(gh.api(f"repos/{args.repo}/issues/{args.pr}/comments", paginate=True))
    state = st.decode(summary["body"]) if summary else None

    result = decide(state=state, sha=sha, labels=labels, events=events, owner=owner,
                    escalate=args.escalate == "true", reason=args.reason,
                    review_result=args.review_result, fork=fork)
    result["description"] = result["description"][:140]
    print(json.dumps(result))
    if args.dry_run:
        return 0

    if result.get("label") and ESCALATION_LABEL not in labels:
        gh.api(f"repos/{args.repo}/issues/{args.pr}/labels", "POST", {"labels": [ESCALATION_LABEL]})
        gh.api(f"repos/{args.repo}/issues/{args.pr}/comments", "POST", {"body":
               f"🙋 **Human review needed.** {result['description']}\n\n"
               f"@{owner}: read the open threads, then either push a fix, or apply "
               f"`{OVERRIDE_LABEL}` to accept the PR as it stands. The label only counts when you apply it."})
    run_url = ""
    if os.environ.get("GITHUB_RUN_ID"):
        run_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
                   f"{os.environ.get('GITHUB_REPOSITORY', args.repo)}/actions/runs/{os.environ['GITHUB_RUN_ID']}")
    body = {"state": result["state"], "context": CONTEXT, "description": result["description"]}
    if run_url:
        body["target_url"] = run_url
    gh.api(f"repos/{args.repo}/statuses/{sha}", "POST", body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
