#!/usr/bin/env python3
"""Turn a validated findings document into PR review threads and round state.

Usage:
  publish_review.py --repo owner/name --pr N --sha HEAD --findings findings.json
                    [--prior prior.json] [--usage agy.json] [--dry-run]

The model never runs in this job and this job is the only one holding
`pull-requests: write`. Everything the model wrote is treated as untrusted
text (textsafe.py): HTML comments are stripped to a fixpoint (so it cannot
forge markers), @-mentions are defused, single-line fields cannot break lines,
link targets must be plain https URLs, ids must match the marker grammar, and
fences are chosen so evidence cannot break out of its block.

Thread policy:
  new P0-P3 inside the diff     -> new inline thread (one review, event COMMENT)
  new P0-P3 outside the diff    -> listed in the review body
  still_open / reopened, thread resolved   -> unresolve + reply why
  still_open, a writer replied since bot   -> reply with the counter-argument
  fixed / accepted_pushback      -> reply + resolve
  accepted_pushback without a writer's `/ai-review wontfix` after the bot's
    last comment in the finding's thread  -> kept open (still_open), signalled
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
from textsafe import clean, inline, safe_url  # noqa: F401  (clean is re-exported as pub.clean)

BLOCKING = ("P0", "P1", "P2", "P3")
STATUS_MARKER = "<!-- pr-guardian:status id={id} status={status} -->"
NITS_MARKER = "<!-- pr-guardian:nits -->"
WONTFIX_RE = re.compile(r"\A/ai-review\s+wontfix(?:\s|:|\Z)")
UNAUTH_PUSHBACK = "unauthenticated pushback"
COERCED_NOTE = ("Still open: pushback is accepted only after someone with write access replies "
                "`/ai-review wontfix: <reason>` in this thread after pr-guardian's last comment.")
REOPEN_ESCALATION = 3
ROUND_CAP = 6

# Gemini 4 Argon standard pricing, USD per 1M tokens (thinking billed as output).
PRICES = [(dt.date(2026, 12, 1), 4.0, 20.0), (dt.date(1970, 1, 1), 2.0, 10.0)]


# --- sanitising model text ---------------------------------------------------
# clean/inline/safe_url live in textsafe.py; ids are validated, never rewritten,
# because they are also the keys threads and state are matched on.

def check_finding(f: dict[str, Any]) -> None:
    """Fail the publish when a field that lands inside a marker is not well formed."""
    if not isinstance(f.get("id"), str) or not st.ID_RE.match(f["id"]):
        raise ValueError(f"finding id {inline(f.get('id'))!r} does not match {st.ID_RE.pattern}")
    if f.get("prior_id") is not None and not (isinstance(f["prior_id"], str) and st.ID_RE.match(f["prior_id"])):
        raise ValueError(f"finding {f['id']}: prior_id {inline(f['prior_id'])!r} is not a finding id")
    if f.get("severity") not in st.SEVERITIES:
        raise ValueError(f"finding {f['id']}: unknown severity {inline(f.get('severity'))!r}")
    for key in ("file", "rule"):
        if not isinstance(f.get(key), str):
            raise ValueError(f"finding {f['id']}: {key} must be a string")
    for key in ("start_line", "end_line"):
        if not isinstance(f.get(key), int) or isinstance(f.get(key), bool):
            raise ValueError(f"finding {f['id']}: {key} must be an integer")


def _marker_id(value: Any) -> str:
    """Belt and braces for marker tokens: nothing but id characters survive."""
    return re.sub(r"[^\w.-]", "", str(value or ""))


def _ref(r: Any) -> str | None:
    if not isinstance(r, dict):
        return None
    url = safe_url(r.get("url"))
    if not url:
        return None
    title = inline(r.get("title")).replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
    return f"[{title or url}]({url})"


def fence(text: str, lang: str = "") -> str:
    ticks = "~~~~"
    while ticks in text:
        ticks += "~"
    return f"{ticks}{lang}\n{text}\n{ticks}"


def finding_body(f: dict[str, Any], in_diff: bool) -> str:
    parts = [st.FINDING_MARKER.format(id=_marker_id(f["id"]), severity=_marker_id(f["severity"])),
             f"**{inline(f['severity'])} · {inline(f['axis'])} · {inline(f['rule'])}** · {inline(f['title'])}",
             "", clean(f["rationale"])]
    if f.get("evidence"):
        parts += ["", "<details><summary>Evidence</summary>", "", fence(clean(f["evidence"])),
                  "", "</details>"]
    if in_diff and f.get("suggestion"):
        parts += ["", "```suggestion\n" + clean(f["suggestion"]).replace("```", "ʼʼʼ") + "\n```"]
    refs = [x for x in (_ref(r) for r in f.get("references") or []) if x]
    if refs:
        parts += ["", "References: " + " · ".join(refs)]
    parts += ["", f"<sub>{inline(f['id'])} · confidence {inline(f.get('confidence'))} · fix it, or reply "
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
    nodes = th.comments(thread)
    return bool(nodes) and th.is_bot(nodes[-1])


def _since_bot(thread: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Comments after pr-guardian's last comment in the thread; None when it never spoke."""
    nodes = th.comments(thread)
    last_bot_idx = max((i for i, c in enumerate(nodes) if th.is_bot(c)), default=-1)
    return None if last_bot_idx < 0 else nodes[last_bot_idx + 1:]


def writer_replied(thread: dict[str, Any]) -> bool:
    """A writer commented after pr-guardian's last comment (outsiders get no reply)."""
    after = _since_bot(thread)
    return bool(after) and any(th.is_writer(c) for c in after)


def has_writer_wontfix(thread: dict[str, Any]) -> bool:
    """A writer replied `/ai-review wontfix` after pr-guardian's last comment.

    The only evidence that lets `accepted_pushback` close a finding (GHSA-j3g5-fvc6-rrjw).
    Fails closed when the bot never spoke or GitHub truncated the comment list, since
    the bot's latest reply (which would make an older wontfix stale) may be unseen.
    """
    after = _since_bot(thread)
    if after is None or th.truncated(thread):
        return False
    return any(th.is_writer(c) and WONTFIX_RE.match((c.get("body") or "").strip()) for c in after)


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
        check_finding(f)

    for f in findings:
        if f.get("prior_id"):
            seen_prior.add(f["prior_id"])
        if f["severity"] == "nit":
            if f["status"] not in st_closed():
                actions["nits"].append(f)
            continue
        thread = threads.get(f["prior_id"] or f["id"])
        status = f["status"]
        coerced = False

        # The model's say-so is not pushback: only a writer's wontfix in the finding's own
        # thread, after the bot's last word, can close a blocking finding. Otherwise it stays
        # open (and blocking in state) and the summary says why (GHSA-j3g5-fvc6-rrjw).
        if status == "accepted_pushback" and not (f.get("prior_id") and thread and has_writer_wontfix(thread)):
            status = f["status"] = "still_open"
            coerced = True
            actions["signals"].append(f"{UNAUTH_PUSHBACK}: {inline(f['id'])} was marked accepted_pushback "
                                      "without a writer's /ai-review wontfix in its thread; kept open")

        if status in st_closed():
            if thread and not thread["isResolved"]:
                verb = "Verified fixed" if status == "fixed" else "Pushback accepted"
                actions["resolve"].append({"thread": thread["id"], "body": _status(f, status)
                                           + f"✅ {verb}: {clean(f['rationale'])}"})
            if status == "accepted_pushback":
                new_state["accepted"].append({"id": f["prior_id"], "file": f["file"], "rule": f["rule"]})
            continue

        if status == "new" and (f["file"], f["rule"]) in accepted_keys:
            actions["signals"].append(f"oscillation: {inline(f['id'])} re-raises accepted pushback "
                                      f"({inline(f['file'])}, {inline(f['rule'])})")

        if thread:
            if status == "reopened":
                key = f["prior_id"]
                new_state["reopen_counts"][key] = new_state["reopen_counts"].get(key, 0) + 1
                if new_state["reopen_counts"][key] >= REOPEN_ESCALATION:
                    actions["signals"].append(f"{inline(key)} reopened {new_state['reopen_counts'][key]} times")
            if thread["isResolved"]:
                why = COERCED_NOTE if coerced else f"the code still has this problem. {clean(f['rationale'])}"
                actions["unresolve"].append({"thread": thread["id"], "body": _status(f, "reopened")
                                             + f"🔁 Reopened: {why}"})
            elif writer_replied(thread):
                why = COERCED_NOTE if coerced else f"Still open after your reply: {clean(f['rationale'])}"
                actions["reply"].append({"thread": thread["id"], "body": _status(f, "still_open") + why})
            continue

        target = actions["comments"] if in_diff(f, lines) else actions["outside"]
        target.append(f)

    for old in prior["findings"]:
        if (old.get("severity") in BLOCKING and old.get("status") not in st_closed()
                and old["id"] not in seen_prior
                and old["id"] not in {f["id"] for f in findings}):
            carried = dict(old, status="still_open", prior_id=old["id"])
            findings.append(carried)
            actions["signals"].append(f"unaccounted: reviewer dropped {inline(old['id'])} without a status; kept open")

    if new_state["round"] >= ROUND_CAP:
        actions["signals"].append(f"round cap: {new_state['round']} rounds")

    new_state["findings"] = findings
    # Escalation is per round: the verdict turns it into the needs-human label, which is
    # the durable signal the owner clears (override) or removes. Unaccounted and unauthenticated
    # pushback keep the finding open, which already blocks, so they inform rather than escalate.
    this_round = [x for x in actions["signals"] if not x.startswith(("unaccounted", UNAUTH_PUSHBACK))]
    new_state["escalated"] = bool(this_round)
    new_state["escalation_reasons"] += this_round
    return {"actions": actions, "state": new_state}


def _status(f: dict[str, Any], status: str) -> str:
    return STATUS_MARKER.format(id=_marker_id(f["prior_id"] or f["id"]), status=_marker_id(status)) + "\n"


def st_closed() -> tuple[str, ...]:
    return ("fixed", "accepted_pushback")


def cost(usage: dict[str, Any] | None, today: dt.date | None = None) -> float:
    if not usage:
        return 0.0
    today = today or dt.date.today()
    _, pin, pout = next(p for p in PRICES if today >= p[0])
    out_tokens = usage.get("output_tokens", 0) + usage.get("thinking_tokens", 0)
    return round(usage.get("input_tokens", 0) / 1e6 * pin + out_tokens / 1e6 * pout, 4)


def round_cost_of(record: dict[str, Any]) -> tuple[float, str]:
    """Cost of this round, and a note when the Claude fallback did the review."""
    if record.get("engine") == "claude":
        return float(record.get("cost_usd") or 0.0), "Gemini was rate limited; Claude Opus 5.5 reviewed this round"
    return cost(record.get("usage")), ""


def _loc(f: dict[str, Any]) -> str:
    """`file:line` as a code span the file name cannot close or break out of."""
    return f"`{inline(f.get('file')).replace('`', '')}:{inline(f.get('start_line'))}`"


def summary_body(doc: dict[str, Any], result: dict[str, Any], round_cost: float, note: str = "") -> str:
    s, a = result["state"], result["actions"]
    open_blocking = [f for f in s["findings"] if f["severity"] in BLOCKING and f["status"] not in st_closed()]
    counts = {sev: sum(1 for f in open_blocking if f["severity"] == sev) for sev in BLOCKING}
    lines = [st.SUMMARY_MARKER, NITS_MARKER, f"## pr-guardian · round {s['round']}", "",
             clean(doc["summary"]), "",
             "| P0 | P1 | P2 | P3 | nits |", "|---|---|---|---|---|",
             f"| {counts['P0']} | {counts['P1']} | {counts['P2']} | {counts['P3']} | {len(a['nits'])} |", ""]
    if a["outside"]:
        lines.append("**Findings outside the diff** (fix them; they block like threads do):")
        lines += [f"- **{inline(f['id'])} [{inline(f['severity'])}]** {_loc(f)} {inline(f['title'])}"
                  for f in a["outside"]]
        lines.append("")
    if a["nits"]:
        lines.append(f"<details><summary>{len(a['nits'])} nits (non-blocking)</summary>\n")
        lines += [f"- {_loc(f)} {inline(f['title'])}" for f in a["nits"]]
        lines.append("\n</details>\n")
    if doc.get("not_inspected"):
        lines.append("<details><summary>Not inspected</summary>\n")
        lines += [f"- {inline(n.get('what'))}: {inline(n.get('reason'))}" for n in doc["not_inspected"]
                  if isinstance(n, dict)]
        lines.append("\n</details>\n")
    if a["signals"]:
        lines.append("**Signals:** " + "; ".join(inline(x) for x in a["signals"]))
    if note:
        lines.append(f"_{inline(note)}._")
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


def toggle(mutation: str, thread: str) -> None:
    # Thread state is advisory: the verdict counts open findings, so a failed (un)resolve
    # must not stop the summary and state from being written.
    try:
        gh.graphql(mutation, id=thread)
    except gh.GhError as exc:
        print(f"::warning::could not change thread {thread}: {exc}", file=sys.stderr)


def execute(repo: str, pr: int, sha: str, doc: dict[str, Any], result: dict[str, Any],
            round_cost: float, note: str = "", base: str = "") -> None:
    a = result["actions"]
    for item in a["unresolve"]:
        toggle(UNRESOLVE, item["thread"])
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
    for item in a["reply"]:
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
    for item in a["resolve"]:
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
        toggle(RESOLVE, item["thread"])

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
    # The base the scan diffed against, so a retarget makes verdict.py wait (GHSA-6h55-p37r-jc34).
    result["state"]["last_reviewed_base"] = base
    body = summary_body(doc, result, round_cost, note)
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
    ap.add_argument("--base", default="", help="base ref the scan reviewed against (scan job output)")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--prior", default=None, help="optional prior state JSON; defaults to live summary comment")
    ap.add_argument("--usage", help="agy --output-format json result, for cost")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    doc = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    if args.prior:
        prior = st.validate_state(json.loads(Path(args.prior).read_text(encoding="utf-8")))
        if prior is None:
            raise SystemExit(f"publish: --prior {args.prior} is not a valid pr-guardian state")
    else:
        comments = gh.api(f"repos/{args.repo}/issues/{args.pr}/comments", paginate=True) or []
        summary = st.find_summary_comment(comments)
        prior = (st.decode(summary["body"]) if summary else None) or st.empty_state()
    record: dict[str, Any] = {}
    if args.usage and Path(args.usage).is_file():
        record = json.loads(Path(args.usage).read_text(encoding="utf-8"))
    diff = gh._run(["pr", "diff", str(args.pr), "-R", args.repo])
    result = plan(doc, prior, th.fetch(args.repo, args.pr), diff)
    round_cost, reviewer = round_cost_of(record)
    if args.dry_run:
        print(json.dumps({"actions": {k: len(v) for k, v in result["actions"].items()},
                          "signals": result["actions"]["signals"], "cost": round_cost}, indent=2))
        return 0
    execute(args.repo, args.pr, args.sha, doc, result, round_cost, reviewer, base=args.base)
    print(json.dumps({"round": result["state"]["round"], "signals": result["actions"]["signals"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
