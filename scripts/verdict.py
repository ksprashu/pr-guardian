#!/usr/bin/env python3
"""Post the required commit status `pr-guardian/verdict` on the PR head.

Usage:
  verdict.py --repo owner/name --pr N [--sha HEAD] [--escalate true|false]
             [--reason TEXT] [--review-result success|failure|cancelled|skipped]
             [--bind-override true|false] [--dry-run]

Decision order (first match wins):
  1. PR does not target the repo's default branch, or the
     PR payload does not name a default branch             -> pending
  2. human-override label, applied by the repo owner and
     bound to this head SHA and base ref                   -> success
  3. review job did not succeed                           -> error (merge blocked)
  4. needs-human label present, or escalation this round   -> failure (+ label)
  5. no review recorded for this head SHA and base ref    -> pending
  6. open P0-P3 findings                                  -> failure
  7. otherwise                                            -> success

A review covers only the head SHA and the base ref it ran against
(GHSA-6h55-p37r-jc34). Commit statuses are keyed by SHA alone, so a success
earned on a PR into another branch (a stacked PR, or one later retargeted)
would otherwise satisfy the default branch's required check for the same
commit. Rule 1 means only a PR into the default branch can ever post success
(or needs-human); rule 5 means a retarget leaves the verdict pending until a
review recorded against the new base (state `last_reviewed_base`) lands.

An override covers only the commit and base it was applied to
(GHSA-q4j9-99qr-cfhw). When the owner applies the label, the run for that
`labeled` event (--bind-override true, --sha = head at label time) posts a
github-actions[bot] comment ending in

    <!-- pr-guardian:override sha=<sha> base=<quoted base ref> event=<event id> -->

keyed to the issue event id of that label application. The override counts
only while the label is on the PR, its latest application was by the owner,
and the marker for that application names the current head and base. Any run
that finds the latest application bound to another head or base removes the
label, whatever event triggered it (ready_for_review, reopened, an
/ai-review escalate during a review, a base retarget). An application with no
marker yet is neither honoured nor removed, so an in-flight review never
deletes a label the owner just applied to the head it is reviewing.

A commit status (not a check run) is used so that runs triggered by
issue_comment, which execute on the default branch, still land on the PR head.
Fails closed: any error leaves the status non-success.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from typing import Any

import gh
import state as st
import textsafe

CONTEXT = "pr-guardian/verdict"
OVERRIDE_LABEL = "human-override"
ESCALATION_LABEL = "needs-human"
BLOCKING = ("P0", "P1", "P2", "P3")
CLOSED = ("fixed", "accepted_pushback")


OVERRIDE_MARKER = "<!-- pr-guardian:override sha={sha} base={base} event={event} -->"
_OVERRIDE_RE = re.compile(
    r"<!-- pr-guardian:override sha=([0-9a-f]{1,64}) base=([A-Za-z0-9%/._~-]{1,1024}) event=([1-9][0-9]{0,19}) -->\s*\Z",
    re.ASCII)
_BASE_SAFE = "/._-"


def latest_override_event(events: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """The most recent `labeled` issue event for the override label, or None."""
    applied = [e for e in events or []
               if isinstance(e, dict) and e.get("event") == "labeled"
               and isinstance(e.get("label"), dict) and e["label"].get("name") == OVERRIDE_LABEL]
    return applied[-1] if applied else None


def event_id(event: dict[str, Any] | None) -> int | None:
    eid = (event or {}).get("id")
    return eid if isinstance(eid, int) and not isinstance(eid, bool) and eid > 0 else None


def applied_by_owner(event: dict[str, Any] | None, owner: str) -> bool:
    actor = (event or {}).get("actor")
    return (bool(owner) and isinstance(actor, dict) and actor.get("login") == owner
            and actor.get("type") != "Bot")


def override_marker(sha: str, base_ref: str, eid: int) -> str:
    return OVERRIDE_MARKER.format(sha=sha, base=urllib.parse.quote(base_ref, safe=_BASE_SAFE), event=eid)


def override_bindings(comments: list[dict[str, Any]] | None) -> dict[int, tuple[str, str] | None]:
    """Label event id -> (sha, base_ref) from github-actions[bot] marker comments.

    Summary comments and other authors are ignored. Two markers that disagree for one
    event id map to None, which is never honoured and never acted on.
    """
    out: dict[int, tuple[str, str] | None] = {}
    for c in comments or []:
        if not isinstance(c, dict) or not st.is_trusted_author(c.get("user")):
            continue
        body = c.get("body")
        if not isinstance(body, str) or st.SUMMARY_MARKER in body:
            continue
        m = _OVERRIDE_RE.search(body)
        if not m:
            continue
        eid, bound = int(m.group(3)), (m.group(1), urllib.parse.unquote(m.group(2)))
        if eid not in out:
            out[eid] = bound
        elif out[eid] != bound:
            out[eid] = None
    return out


def latest_binding(events: list[dict[str, Any]] | None,
                   comments: list[dict[str, Any]] | None) -> tuple[str, str] | None:
    """(sha, base_ref) the latest override application was bound to, or None if unbound."""
    eid = event_id(latest_override_event(events))
    return override_bindings(comments).get(eid) if eid is not None else None


def override_by_owner(events: list[dict[str, Any]], labels: list[str], owner: str, *,
                      sha: str = "", base_ref: str = "",
                      comments: list[dict[str, Any]] | None = None) -> bool:
    """True when the label is on the PR, its latest application was by the owner, and that
    application is bound to exactly this head SHA and base ref."""
    if OVERRIDE_LABEL not in labels or not sha or not base_ref:
        return False
    if not applied_by_owner(latest_override_event(events), owner):
        return False
    return latest_binding(events, comments) == (sha, base_ref)


def stale_override(events: list[dict[str, Any]], labels: list[str], *, sha: str, base_ref: str,
                   comments: list[dict[str, Any]] | None) -> bool:
    """True when the label's latest application is bound to another head or base."""
    if OVERRIDE_LABEL not in labels or not sha or not base_ref:
        return False
    bound = latest_binding(events, comments)
    return bound is not None and bound != (sha, base_ref)


def decide(*, state: dict[str, Any] | None, sha: str, labels: list[str], events: list[dict[str, Any]],
           owner: str, escalate: bool, reason: str, review_result: str, fork: bool,
           base_ref: str = "", comments: list[dict[str, Any]] | None = None,
           default_branch: str = "", require_default: bool = False) -> dict[str, Any]:
    s = state or st.empty_state()
    if require_default and not default_branch:
        # main() always requires it: a PR payload without the repo's default branch cannot
        # prove it targets that branch, so fail closed.
        return {"state": "pending", "description": "Default branch unknown: no verdict"}
    if default_branch and base_ref != default_branch:
        # First, before any override: the status lands on the SHA, which a PR into the
        # default branch may share (GHSA-6h55-p37r-jc34).
        return {"state": "pending",
                "description": f"Targets {textsafe.inline(base_ref) or 'an unknown base'}, not "
                               f"{textsafe.inline(default_branch)}: no verdict until retargeted"}
    if override_by_owner(events, labels, owner, sha=sha, base_ref=base_ref, comments=comments):
        return {"state": "success", "description": f"Overridden by {owner} (human-override)"}
    if fork:
        return {"state": "failure",
                "description": f"External fork PR: not auto-reviewed. {owner} reviews, then applies human-override"}
    if review_result not in ("", "success", "skipped"):
        return {"state": "error", "description": f"Review job {review_result}; re-run, or comment /ai-review"}
    if ESCALATION_LABEL in labels and not escalate and not s.get("escalated"):
        return {"state": "failure", "description": f"Needs human: waiting for {owner} to apply {OVERRIDE_LABEL}"}
    if escalate or s.get("escalated"):
        # Reasons come from model-derived state and from a commenter's /ai-review escalate text:
        # one line, no HTML comments, no live @-mentions (GHSA-r8c3-5xg9-pqqg).
        reasons = [x for x in (textsafe.inline(r) for r in s.get("escalation_reasons", [])) if x]
        why = textsafe.inline(reason) or "; ".join(reasons[-2:]) or "escalated"
        return {"state": "failure", "label": ESCALATION_LABEL,
                "description": f"Needs human: {why}"}
    if (not sha or not base_ref or s.get("last_reviewed_sha") != sha
            or s.get("last_reviewed_base") != base_ref):
        return {"state": "pending", "description": "Review in progress for this commit and base"}
    # Fail closed: an unclosed finding whose severity is missing or unknown blocks.
    open_blocking = [f for f in s.get("findings", [])
                     if f.get("severity") != "nit" and f.get("status") not in CLOSED]
    if open_blocking:
        sevs = [f.get("severity") if f.get("severity") in BLOCKING else "unrecognised" for f in open_blocking]
        counts = ", ".join(f"{sevs.count(x)} {x}" for x in (*BLOCKING, "unrecognised") if x in sevs)
        return {"state": "failure",
                "description": f"Round {s['round']}: {counts} open. Fix or push back in the threads"}
    nits = sum(1 for f in s.get("findings", []) if f.get("severity") == "nit" and f.get("status") not in CLOSED)
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
    ap.add_argument("--bind-override", default="false",
                    help="true for the run of an owner's human-override labeled event: bind the "
                         "latest application to --sha and the PR base ref")
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
    base_ref = (pr.get("base") or {}).get("ref") or ""
    base_ref = base_ref if isinstance(base_ref, str) else ""
    default_branch = ((pr.get("base") or {}).get("repo") or {}).get("default_branch") or ""
    default_branch = default_branch if isinstance(default_branch, str) else ""
    # Missing default branch counts as off-default: fail closed, never bind (GHSA-6h55-p37r-jc34).
    off_default = not default_branch or base_ref != default_branch
    events = gh.api(f"repos/{args.repo}/issues/{args.pr}/events", paginate=True) or []
    comments = gh.api(f"repos/{args.repo}/issues/{args.pr}/comments", paginate=True) or []

    # Bind only the head the owner labelled: --sha comes from the labeled event payload and
    # has already been checked against the live head above, so a push that lands before
    # this run leaves the application unbound (never bound to unreviewed code).
    latest = latest_override_event(events)
    eid = event_id(latest)
    # Never bind on a PR into another branch: it can never post success anyway, and a marker
    # there would only invite confusion after a retarget (GHSA-6h55-p37r-jc34).
    if (args.bind_override == "true" and args.sha and sha == pr["head"]["sha"] and base_ref
            and not off_default and OVERRIDE_LABEL in labels and eid is not None and applied_by_owner(latest, owner)
            and eid not in override_bindings(comments)):
        body = (f"🔓 `{OVERRIDE_LABEL}` by the owner covers `{sha[:12]}` on `{textsafe.inline(base_ref)}` only; "
                f"any other head or base removes it.\n\n{override_marker(sha, base_ref, eid)}")
        if not args.dry_run:
            gh.api(f"repos/{args.repo}/issues/{args.pr}/comments", "POST", {"body": body})
        comments.append({"user": {"type": "Bot", "login": st.TRUSTED_BOT_LOGIN}, "body": body})

    if stale_override(events, labels, sha=sha, base_ref=base_ref, comments=comments):
        if not args.dry_run:
            try:
                gh.api(f"repos/{args.repo}/issues/{args.pr}/labels/{OVERRIDE_LABEL}", "DELETE")
            except gh.GhError as exc:  # already removed concurrently (404)
                print(f"verdict: could not remove stale {OVERRIDE_LABEL}: {exc}")
        labels.remove(OVERRIDE_LABEL)

    summary = st.find_summary_comment(comments)
    state = st.decode(summary["body"]) if summary else None

    result = decide(state=state, sha=sha, labels=labels, events=events, owner=owner,
                    escalate=args.escalate == "true", reason=args.reason,
                    review_result=args.review_result, fork=fork,
                    base_ref=base_ref, comments=comments, default_branch=default_branch,
                    require_default=True)
    result["description"] = textsafe.inline(result["description"])[:140]
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
