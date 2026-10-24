#!/usr/bin/env python3
"""Turn a validated findings document into PR review threads and round state.

Usage:
  publish_review.py --repo owner/name --pr N --sha HEAD --findings findings.json
                    --prior prior.json [--usage agy.json] [--dry-run]

The model never runs in this job and this job is the only one holding
`pull-requests: write`. Everything the model wrote is treated as untrusted
text: HTML comments are stripped (so it cannot forge markers), @-mentions are
defused, and fences are chosen so evidence cannot break out of its block.

Thread policy:
  new P0-P3 inside the diff     -> new inline thread (one review, event COMMENT)
  new P0-P3 outside the diff    -> listed in the review body
  still_open / reopened, thread resolved   -> unresolve + reply why
  still_open, author replied since bot     -> reply with the counter-argument
  fixed / accepted_pushback      -> reply + resolve
  prior open id missing from this round    -> kept open, flagged as unaccounted
  nit                            -> summary comment only, never a thread
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

import gh
import state as st
import threads as th

BLOCKING = ("P0", "P1", "P2", "P3")
STATUS_MARKER = "<!-- pr-guardian:status id={id} status={status} -->"
NITS_MARKER = "<!-- pr-guardian:nits -->"
BOT_LOGINS = ("github-actions", "github-actions[bot]")
REOPEN_ESCALATION = 3
ROUND_CAP = 6

# Gemini 4 Argon standard pricing, USD per 1M tokens (thinking billed as output).
PRICES = [(dt.date(2026, 12, 1), 4.0, 20.0), (dt.date(1970, 1, 1), 2.0, 10.0)]


# --- sanitising model text ---------------------------------------------------

def clean(text: str) -> str:
    text = re.sub(r"<!--.*?(-->|$)", "", text or "", flags=re.S)
    text = text.replace("<!--", "")
    return re.sub(r"(?<![\w`])@(?=[A-Za-z0-9-])", "@​", text)


def fence(text: str, lang: str = "") -> str:
    ticks = "~~~~"
    while ticks in text:
        ticks += "~"
    return f"{ticks}{lang}\n{text}\n{ticks}"


def finding_body(f: dict[str, Any], in_diff: bool) -> str:
    parts = [st.FINDING_MARKER.format(id=f["id"], severity=f["severity"]),
             f"**{f['severity']} · {f['axis']} · {clean(f['rule'])}** · {clean(f['title'])}",
             "", clean(f["rationale"])]
    if f.get("evidence"):
        parts += ["", "<details><summary>Evidence</summary>", "", fence(clean(f["evidence"])),
                  "", "</details>"]
    if in_diff and f.get("suggestion"):
        parts += ["", "```suggestion\n" + clean(f["suggestion"]).replace("```", "ʼʼʼ") + "\n```"]
    if f.get("references"):
        refs = " · ".join(f"[{clean(r['title'])}]({r['url']})" for r in f["references"]
                          if r["url"].startswith("https://"))
        parts += ["", f"References: {refs}"]
    parts += ["", f"<sub>{f['id']} · confidence {f['confidence']} · fix it, or reply "
                  "`/ai-review wontfix: <reason>` to push back</sub>"]
    return "\n".join(parts)


# --- diff geometry -----------------------------------------------------------

def commentable_lines(diff: str) -> dict[str, set[int]]:
    """RIGHT-side lines GitHub accepts review comments on, per file."""
    out: dict[str, set[int]] = {}
    path, line = None, 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else None
            if path:
                out.setdefault(path, set())
        elif raw.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", raw)
            line = int(m.group(1)) if m else 0
        elif path is None or raw.startswith("--- "):
            continue
        elif raw.startswith("+") or raw.startswith(" "):
            out[path].add(line)
            line += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue
    return out


def in_diff(f: dict[str, Any], lines: dict[str, set[int]]) -> bool:
    got = lines.get(f["file"], set())
    return all(n in got for n in range(f["start_line"], f["end_line"] + 1))


# --- planning (pure, tested) -------------------------------------------------

def last_comment_is_bot(thread: dict[str, Any]) -> bool:
    nodes = thread.get("comments", {}).get("nodes", [])
    return bool(nodes) and (nodes[-1].get("author") or {}).get("login") in BOT_LOGINS


def plan(doc: dict[str, Any], prior: dict[str, Any], thread_list: list[dict[str, Any]],
         diff: str) -> dict[str, Any]:
    lines = commentable_lines(diff)
    threads = th.by_finding(thread_list)
    actions: dict[str, Any] = {"comments": [], "outside": [], "unresolve": [], "reply": [],
                               "resolve": [], "nits": [], "signals": []}
    new_state = dict(prior)
    new_state["round"] = prior["round"] + 1
    new_state["reopen_counts"] = dict(prior["reopen_counts"])
    new_state["accepted"] = list(prior["accepted"])
    new_state["escalation_reasons"] = list(prior["escalation_reasons"])

    accepted_keys = {(a["file"], a["rule"]) for a in prior["accepted"]}
    seen_prior: set[str] = set()
    findings = [dict(f) for f in doc["findings"]]

    for f in findings:
        if f.get("prior_id"):
            seen_prior.add(f["prior_id"])
        if f["severity"] == "nit":
            if f["status"] not in st_closed():
                actions["nits"].append(f)
            continue
        thread = threads.get(f["prior_id"] or f["id"])
        status = f["status"]

        if status in st_closed():
            if thread and not thread["isResolved"]:
                verb = "Verified fixed" if status == "fixed" else "Pushback accepted"
                actions["resolve"].append({"thread": thread["id"], "body": _status(f, status)
                                           + f"✅ {verb}: {clean(f['rationale'])}"})
            if status == "accepted_pushback":
                new_state["accepted"].append({"id": f["prior_id"], "file": f["file"], "rule": f["rule"]})
            continue

        if status == "new" and (f["file"], f["rule"]) in accepted_keys:
            actions["signals"].append(f"oscillation: {f['id']} re-raises accepted pushback "
                                      f"({f['file']}, {f['rule']})")

        if thread:
            if status == "reopened":
                key = f["prior_id"]
                new_state["reopen_counts"][key] = new_state["reopen_counts"].get(key, 0) + 1
                if new_state["reopen_counts"][key] >= REOPEN_ESCALATION:
                    actions["signals"].append(f"{key} reopened {new_state['reopen_counts'][key]} times")
            if thread["isResolved"]:
                actions["unresolve"].append({"thread": thread["id"], "body": _status(f, "reopened")
                                             + f"🔁 Reopened: the code still has this problem. {clean(f['rationale'])}"})
            elif not last_comment_is_bot(thread):
                actions["reply"].append({"thread": thread["id"], "body": _status(f, "still_open")
                                         + f"Still open after your reply: {clean(f['rationale'])}"})
            continue

        target = actions["comments"] if in_diff(f, lines) else actions["outside"]
        target.append(f)

    for old in prior["findings"]:
        if (old["severity"] in BLOCKING and old.get("status") not in st_closed()
                and old["id"] not in seen_prior
                and old["id"] not in {f["id"] for f in findings}):
            carried = dict(old, status="still_open", prior_id=old["id"])
            findings.append(carried)
            actions["signals"].append(f"unaccounted: reviewer dropped {old['id']} without a status; kept open")

    if new_state["round"] >= ROUND_CAP:
        actions["signals"].append(f"round cap: {new_state['round']} rounds")

    new_state["findings"] = findings
    # Escalation is per round: the verdict turns it into the needs-human label, which is
    # the durable signal the owner clears (override) or removes.
    this_round = [x for x in actions["signals"] if not x.startswith("unaccounted")]
    new_state["escalated"] = bool(this_round)
    new_state["escalation_reasons"] += this_round
    return {"actions": actions, "state": new_state}


def _status(f: dict[str, Any], status: str) -> str:
    return STATUS_MARKER.format(id=f["prior_id"] or f["id"], status=status) + "\n"


def st_closed() -> tuple[str, ...]:
    return ("fixed", "accepted_pushback")


def cost(usage: dict[str, Any] | None, today: dt.date | None = None) -> float:
    if not usage:
        return 0.0
    today = today or dt.date.today()
    _, pin, pout = next(p for p in PRICES if today >= p[0])
    out_tokens = usage.get("output_tokens", 0) + usage.get("thinking_tokens", 0)
    return round(usage.get("input_tokens", 0) / 1e6 * pin + out_tokens / 1e6 * pout, 4)


def summary_body(doc: dict[str, Any], result: dict[str, Any], round_cost: float) -> str:
    s, a = result["state"], result["actions"]
    open_blocking = [f for f in s["findings"] if f["severity"] in BLOCKING and f["status"] not in st_closed()]
    counts = {sev: sum(1 for f in open_blocking if f["severity"] == sev) for sev in BLOCKING}
    lines = [st.SUMMARY_MARKER, NITS_MARKER, f"## pr-guardian · round {s['round']}", "",
             clean(doc["summary"]), "",
             "| P0 | P1 | P2 | P3 | nits |", "|---|---|---|---|---|",
             f"| {counts['P0']} | {counts['P1']} | {counts['P2']} | {counts['P3']} | {len(a['nits'])} |", ""]
    if a["outside"]:
        lines.append("**Findings outside the diff** (fix them; they block like threads do):")
        lines += [f"- **{f['id']} [{f['severity']}]** `{f['file']}:{f['start_line']}` {clean(f['title'])}"
                  for f in a["outside"]]
        lines.append("")
    if a["nits"]:
        lines.append(f"<details><summary>{len(a['nits'])} nits (non-blocking)</summary>\n")
        lines += [f"- `{f['file']}:{f['start_line']}` {clean(f['title'])}" for f in a["nits"]]
        lines.append("\n</details>\n")
    if doc.get("not_inspected"):
        lines.append("<details><summary>Not inspected</summary>\n")
        lines += [f"- {clean(n['what'])}: {clean(n['reason'])}" for n in doc["not_inspected"]]
        lines.append("\n</details>\n")
    if a["signals"]:
        lines.append("**Signals:** " + "; ".join(clean(x) for x in a["signals"]))
    total = round(sum(s["cost_usd"]), 2)
    lines.append(f"\n<sub>Round cost ≈ ${round_cost:.2f} · PR total ≈ ${total:.2f} · "
                 "commands: `/ai-review wontfix: <reason>` (in a thread), `/ai-review escalate: <why>`</sub>")
    lines.append(st.encode(s))
    return "\n".join(lines)


# --- execution ---------------------------------------------------------------

RESOLVE = "mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{id}}}"
UNRESOLVE = "mutation($id:ID!){unresolveReviewThread(input:{threadId:$id}){thread{id}}}"
REPLY = ("mutation($id:ID!,$body:String!){addPullRequestReviewThreadReply("
         "input:{pullRequestReviewThreadId:$id, body:$body}){comment{id}}}")


def execute(repo: str, pr: int, sha: str, doc: dict[str, Any], result: dict[str, Any],
            round_cost: float) -> None:
    a = result["actions"]
    for item in a["unresolve"]:
        gh.graphql(UNRESOLVE, id=item["thread"])
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
    for item in a["reply"]:
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
    for item in a["resolve"]:
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
        gh.graphql(RESOLVE, id=item["thread"])

    if a["comments"]:
        comments = []
        for f in a["comments"]:
            c = {"path": f["file"], "line": f["end_line"], "side": "RIGHT", "body": finding_body(f, True)}
            if f["end_line"] > f["start_line"]:
                c.update(start_line=f["start_line"], start_side="RIGHT")
            comments.append(c)
        review = {"commit_id": sha, "event": "COMMENT", "comments": comments,
                  "body": f"pr-guardian round {result['state']['round']}: "
                          f"{len(comments)} new finding(s). See the summary comment for totals."}
        try:
            gh.api(f"repos/{repo}/pulls/{pr}/reviews", "POST", review)
        except gh.GhError as exc:  # a line GitHub will not anchor: fall back to the body
            print(f"publish: inline review rejected ({exc}); listing findings in the summary", file=sys.stderr)
            a["outside"].extend(a["comments"])
            a["comments"] = []

    result["state"]["cost_usd"] = list(result["state"]["cost_usd"]) + [round_cost]
    result["state"]["last_reviewed_sha"] = sha
    body = summary_body(doc, result, round_cost)
    existing = st.find_summary_comment(gh.api(f"repos/{repo}/issues/{pr}/comments", paginate=True))
    if existing:
        gh.api(f"repos/{repo}/issues/comments/{existing['id']}", "PATCH", {"body": body})
    else:
        gh.api(f"repos/{repo}/issues/{pr}/comments", "POST", {"body": body})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--prior", required=True)
    ap.add_argument("--usage", help="agy --output-format json result, for cost")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    doc = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    prior = st.empty_state()
    prior.update(json.loads(Path(args.prior).read_text(encoding="utf-8")))
    usage = None
    if args.usage and Path(args.usage).is_file():
        usage = json.loads(Path(args.usage).read_text(encoding="utf-8")).get("usage")
    diff = gh._run(["pr", "diff", str(args.pr), "-R", args.repo])
    result = plan(doc, prior, th.fetch(args.repo, args.pr), diff)
    round_cost = cost(usage)
    if args.dry_run:
        print(json.dumps({"actions": {k: len(v) for k, v in result["actions"].items()},
                          "signals": result["actions"]["signals"], "cost": round_cost}, indent=2))
        return 0
    execute(args.repo, args.pr, args.sha, doc, result, round_cost)
    print(json.dumps({"round": result["state"]["round"], "signals": result["actions"]["signals"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
