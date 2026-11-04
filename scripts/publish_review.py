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
  fixed with no thread found     -> ::warning:: + "Threads needing manual action"
  failed (un)resolve             -> ::warning:: + "Threads needing manual action"

Threads are matched by thread_key (the id that opened the thread, carried in state and
in the marker), then the prior_id chain, then file + rule + nearby line.
  prior open id missing from this round    -> kept open, flagged as unaccounted
  nit                            -> summary comment only, never a thread
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
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
    parts = [st.FINDING_MARKER.format(id=f["id"], severity=f["severity"], key=f.get("thread_key") or f["id"]),
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

NEAR_LINES = 20  # how far a renumbered finding may drift from its thread's line and still match


def last_comment_is_bot(thread: dict[str, Any]) -> bool:
    nodes = thread.get("comments", {}).get("nodes", [])
    return bool(nodes) and th.is_bot(nodes[-1])


ID_RE = re.compile(r"[A-Z][A-Z0-9]*-[0-9]{3,}")  # the finding-id grammar markers accept


def valid_id(value: Any) -> bool:
    return isinstance(value, str) and ID_RE.fullmatch(value) is not None


def _key_candidates(f: dict[str, Any], prior_by_id: dict[str, dict[str, Any]]) -> list[str]:
    """For a continuation: its thread_key, or for legacy state the prior_id chain.

    The model renumbers findings every round and prior_id points one round back, so the
    thread opened in round 1 is found through the key that state carries forward. State
    written before keys existed only has the one-hop chain (prior_id, its prior_id).
    A prior_id that names no finding from last round links to nothing.
    """
    old = prior_by_id.get(f.get("prior_id") or "")
    if not old:
        return []
    if valid_id(old.get("thread_key")):  # keyed state is authoritative: ids are round-local
        return [old["thread_key"]]
    out = [old.get("prior_id"), old["id"]]
    return [k for k in dict.fromkeys(out) if valid_id(k)]


def _near(thread: dict[str, Any], f: dict[str, Any]) -> int | None:
    """Line distance between a thread and a finding, None when they cannot be the same."""
    line = thread.get("line")
    if thread.get("path") != f["file"] or line is None:  # None: outdated, position unknown
        return None
    gap = 0 if f["start_line"] <= line <= f["end_line"] else min(
        abs(line - f["start_line"]), abs(line - f["end_line"]))
    return gap if gap <= NEAR_LINES else None


def _fallback(f: dict[str, Any], thread_list: list[dict[str, Any]], claimed: set[str]) -> dict[str, Any] | None:
    """Same file and rule, nearest line."""
    best, best_gap = None, NEAR_LINES + 1
    for t in thread_list:
        m = th.meta(t)
        if not m or t["id"] in claimed or m["rule"] != clean(f["rule"]):
            continue
        gap = _near(t, f)
        if gap is not None and gap < best_gap:
            best, best_gap = t, gap
    return best


def _fresh_key(fid: str, used: set[str]) -> str:
    """fid if no thread or earlier finding uses it as a key, else the next free number."""
    if fid not in used:
        return fid
    prefix = fid.rsplit("-", 1)[0]
    nums = [int(k.rsplit("-", 1)[1]) for k in used if k.rsplit("-", 1)[0] == prefix]
    return f"{prefix}-{max(nums) + 1:03d}"


def _legacy_ok(t: dict[str, Any], f: dict[str, Any]) -> bool:
    """A legacy chain id is round-local, so it only counts on the same file and rule."""
    m = th.meta(t)
    return bool(m) and t.get("path") == f["file"] and m["rule"] == clean(f["rule"])


def match_threads(findings: list[dict[str, Any]], prior: dict[str, Any],
                  thread_list: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """Set each finding's thread_key and return {index: thread} for the ones with a thread.

    Only a continuation (prior_id naming a finding from last round) inherits a thread.
    Lookup order: thread_key, then (legacy state only, same file + rule) the prior_id
    chain, then file + rule + nearby line (skipped for summary-only findings, and never
    taking a thread an omitted open prior finding still owns). A thread is claimed by at
    most one finding, and a key by at most one finding: a new finding, or a second
    continuation of the same prior finding, gets a key nothing else uses. Nits never
    get threads.
    """
    prior_by_id = {old["id"]: old for old in prior["findings"] if valid_id(old.get("id"))}
    by_key = th.by_finding(thread_list)
    matched: dict[int, dict[str, Any]] = {}
    claimed: set[str] = set()
    used = set(by_key) | {k for old in prior["findings"]
                          for k in (old.get("thread_key"), old.get("id")) if valid_id(k)}
    cands = [_key_candidates(f, prior_by_id) for f in findings]

    for i, f in enumerate(findings):
        if not cands[i]:
            continue
        f["thread_key"] = cands[i][0]
        old = prior_by_id[f["prior_id"]]
        legacy = not valid_id(old.get("thread_key"))
        if old.get("posted"):
            f["posted"] = old["posted"]
        if f["severity"] == "nit":
            continue
        for k in cands[i]:
            t = by_key.get(k)
            if t and t["id"] not in claimed and (not legacy or _legacy_ok(t, f)):
                matched[i], f["thread_key"] = t, k
                claimed.add(t["id"])
                break

    # Threads of prior findings this round does not reference, open or closed, belong to
    # those findings: the positional fallback must not act on them for someone else.
    referenced = {f.get("prior_id") for f in findings}
    reserved: set[str] = set()
    for old in prior_by_id.values():
        if old["id"] in referenced:
            continue
        keys = [old["thread_key"]] if valid_id(old.get("thread_key")) else [old.get("prior_id"), old["id"]]
        reserved |= {by_key[k]["id"] for k in keys if k in by_key}

    # The fallback is for legacy state only (a stored key is authoritative: no thread under
    # it means no thread), and not for a split continuation whose sibling holds the thread.
    held = {findings[i]["prior_id"] for i in matched}
    for i, f in enumerate(findings):
        if (i in matched or not cands[i] or f["severity"] == "nit" or f.get("posted") == "summary"
                or valid_id(prior_by_id[f["prior_id"]].get("thread_key")) or f["prior_id"] in held):
            continue
        t = _fallback(f, thread_list, claimed | reserved)
        if t:
            matched[i], f["thread_key"] = t, th.meta(t)["key"]
            claimed.add(t["id"])

    taken = {findings[i]["thread_key"] for i in matched}
    for i, f in enumerate(findings):
        if i in matched:
            continue
        # A key some thread already carries is not this finding's (it did not match it).
        if not f.get("thread_key") or f["thread_key"] in taken or f["thread_key"] in by_key:
            f["thread_key"] = _fresh_key(f["id"], used | taken)
        taken.add(f["thread_key"])
        used.add(f["thread_key"])
    return matched


def plan(doc: dict[str, Any], prior: dict[str, Any], thread_list: list[dict[str, Any]],
         diff: str) -> dict[str, Any]:
    lines = commentable_lines(diff)
    actions: dict[str, Any] = {"comments": [], "outside": [], "unresolve": [], "reply": [],
                               "resolve": [], "nits": [], "signals": [], "unmatched": []}
    new_state = dict(prior)
    new_state["round"] = prior["round"] + 1
    new_state["reopen_counts"] = dict(prior["reopen_counts"])
    new_state["accepted"] = list(prior["accepted"])
    new_state["escalation_reasons"] = list(prior["escalation_reasons"])

    accepted_keys = {(a["file"], a["rule"]) for a in prior["accepted"]}
    seen_prior: set[str] = set()
    # The model's output is untrusted: thread_key and posted are ours to set, never its.
    findings = [{k: v for k, v in f.items() if k not in ("thread_key", "posted")} for f in doc["findings"]]
    for f in findings:  # prior_id ends up in markers and the summary: only the id grammar passes
        if not valid_id(f.get("prior_id")):
            f["prior_id"] = None
    matched = match_threads(findings, prior, thread_list)
    prior_by_id = {old["id"]: old for old in prior["findings"]}
    held = {findings[i]["prior_id"] for i in matched if findings[i].get("prior_id")}

    for i, f in enumerate(findings):
        if f.get("prior_id"):
            seen_prior.add(f["prior_id"])
        if f["severity"] == "nit":
            if f["status"] not in st_closed():
                actions["nits"].append(f)
            continue
        thread = matched.get(i)
        key = f["thread_key"]
        status = f["status"]
        if thread:
            f["posted"] = "thread"

        if status in st_closed():
            if thread and not thread["isResolved"]:
                verb = "Verified fixed" if status == "fixed" else "Pushback accepted"
                actions["resolve"].append({"thread": thread["id"], "finding": f["id"], "key": key,
                                           "url": th.url(thread), "body": _status(f, status)
                                           + f"✅ {verb}: {clean(f['rationale'])}"})
            elif (not thread and f.get("prior_id") in prior_by_id and f["prior_id"] not in held
                  and f.get("posted") != "summary"):
                # Listed only in the summary (outside the diff) means there was never a thread;
                # an unknown prior_id links to nothing; a split sibling's thread is handled.
                actions["unmatched"].append({"finding": f["id"], "key": key, "status": status,
                                             "file": f["file"], "line": f["start_line"]})
            if status == "accepted_pushback":
                new_state["accepted"].append({"id": f["prior_id"], "file": f["file"], "rule": f["rule"]})
            continue

        if status == "new" and (f["file"], f["rule"]) in accepted_keys:
            actions["signals"].append(f"oscillation: {f['id']} re-raises accepted pushback "
                                      f"({f['file']}, {f['rule']})")

        if status == "reopened" and f.get("prior_id"):
            counts = new_state["reopen_counts"]
            legacy = not prior_by_id.get(f["prior_id"], {}).get("thread_key")
            n = counts.get(key, counts.get(f["prior_id"], 0) if legacy else 0) + 1  # legacy: keyed by prior_id
            counts[key] = n
            if n >= REOPEN_ESCALATION:
                actions["signals"].append(f"{key} reopened {n} times")

        if thread:
            if thread["isResolved"]:
                actions["unresolve"].append({"thread": thread["id"], "finding": f["id"], "key": key,
                                             "url": th.url(thread), "body": _status(f, "reopened")
                                             + f"🔁 Reopened: the code still has this problem. {clean(f['rationale'])}"})
            elif not last_comment_is_bot(thread):
                actions["reply"].append({"thread": thread["id"], "body": _status(f, "still_open")
                                         + f"Still open after your reply: {clean(f['rationale'])}"})
            continue

        inline = in_diff(f, lines)
        f["posted"] = "thread" if inline else "summary"
        (actions["comments"] if inline else actions["outside"]).append(f)

    # Ids are round-local, so only an explicit prior_id accounts for an old finding; a new
    # finding that happens to reuse its id does not. A carried finding gets an id that is
    # unique in this round, so next round's prior_by_id cannot conflate the two.
    ids = {f["id"] for f in findings}
    for old in prior["findings"]:
        if (old["severity"] in BLOCKING and old.get("status") not in st_closed()
                and old["id"] not in seen_prior):
            cid = _fresh_key(old["id"], ids)
            ids.add(cid)
            carried = dict(old, id=cid, status="still_open", prior_id=old["id"])
            if not valid_id(carried.get("thread_key")):
                # Legacy: only stamp a key that names a thread on the same file and rule;
                # otherwise stay keyless so next round still applies the legacy checks.
                carried.pop("thread_key", None)
                by_key = th.by_finding(thread_list)
                for k in (old.get("prior_id"), old["id"]):
                    if valid_id(k) and k in by_key and _legacy_ok(by_key[k], old):
                        carried["thread_key"] = k
                        break
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
    return STATUS_MARKER.format(id=f.get("thread_key") or f["prior_id"] or f["id"], status=status) + "\n"


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
    manual = manual_actions(result)
    if manual:
        lines.append("**Threads needing manual action** (resolve or check these by hand):")
        lines += [f"- {m}" for m in manual]
        lines.append("")
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


def cmd_escape(text: Any) -> str:
    """GitHub's escaping for workflow-command data, so model text or gh stderr containing a
    newline cannot start a command line of its own (`::set-output`, `::stop-commands`, ...)."""
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def toggle(mutation: str, item: dict[str, Any], errors: list[dict[str, Any]]) -> None:
    # Thread state is advisory: the verdict counts open findings, so a failed (un)resolve
    # must not stop the summary and state from being written. It is reported, not hidden.
    try:
        gh.graphql(mutation, id=item["thread"])
    except gh.GhError as exc:
        action = "resolve" if mutation is RESOLVE else "unresolve"
        errors.append({**item, "action": action, "error": str(exc)})
        print(cmd_escape(f"::warning::could not {action} thread {item['thread']} "
                         f"({item.get('finding')}): {exc}"),
              file=sys.stderr)


def manual_actions(result: dict[str, Any]) -> list[str]:
    """One markdown line per thread the bot could not handle, for the summary comment."""
    out = []
    for e in result.get("thread_errors", []):
        where = f"[thread]({e['url']})" if e.get("url", "").startswith("https://") else f"thread `{e['thread']}`"
        out.append(f"{where} for **{e.get('key') or e.get('finding')}**: could not {e['action']} it "
                   f"(`{clean(e['error'])[:200].replace('`', '')}`)")
    for u in result["actions"].get("unmatched", []):
        out.append(f"**{u['finding']}** (`{clean(u['file']).replace('`', '')}:{u['line']}`) is {u['status']}, "
                   f"but no thread for {u['key']} was found to reply on or resolve")
    return out


def warn_unmatched(result: dict[str, Any]) -> None:
    for u in result["actions"].get("unmatched", []):
        print(cmd_escape(f"::warning::{u['finding']} is {u['status']} but has no matching thread "
                         f"(thread_key {u['key']}, {u['file']}:{u['line']})"), file=sys.stderr)


def write_step_summary(result: dict[str, Any]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    manual = manual_actions(result)
    if not path or not manual:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("### pr-guardian: threads needing manual action\n\n")
        fh.write("".join(f"- {m}\n" for m in manual) + "\n")


def execute(repo: str, pr: int, sha: str, doc: dict[str, Any], result: dict[str, Any],
            round_cost: float) -> None:
    a = result["actions"]
    errors = result.setdefault("thread_errors", [])
    for item in a["unresolve"]:
        toggle(UNRESOLVE, item, errors)
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
    for item in a["reply"]:
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
    for item in a["resolve"]:
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
        toggle(RESOLVE, item, errors)

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
            print(cmd_escape(f"publish: inline review rejected ({exc}); listing findings in the summary"),
                  file=sys.stderr)
            for f in a["comments"]:
                f["posted"] = "summary"
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
    ap.add_argument("--fail-on-thread-errors", default="false",
                    help="true: exit 1 (after writing the summary) when a thread could not be "
                         "matched, resolved or unresolved")
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
    warn_unmatched(result)
    if args.dry_run:
        print(json.dumps({"actions": {k: len(v) for k, v in result["actions"].items()},
                          "signals": result["actions"]["signals"],
                          "unmatched": result["actions"]["unmatched"], "cost": round_cost}, indent=2))
        return 0
    execute(args.repo, args.pr, args.sha, doc, result, round_cost)
    write_step_summary(result)
    print(json.dumps({"round": result["state"]["round"], "signals": result["actions"]["signals"]}))
    return exit_code(result, args.fail_on_thread_errors == "true")


def exit_code(result: dict[str, Any], fail_on_thread_errors: bool) -> int:
    problems = len(result.get("thread_errors", [])) + len(result["actions"].get("unmatched", []))
    if problems and fail_on_thread_errors:
        print(f"::error::{problems} thread(s) need manual action (fail_on_thread_errors is on)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
