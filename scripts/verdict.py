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
     bound to this head SHA and base ref, or an owner
     `/ai-review override <sha>: <reason>` bound the same  -> success
  3. external fork PR                                     -> failure
  4. review job did not succeed                           -> error (merge blocked)
  5. needs-human label present, or escalation this round   -> failure (+ label)
     unless the owner removed needs-human for this head,
     base and round (never for a workflow change)
  6. no review recorded for this head SHA and base ref    -> pending
  7. open P0-P3 findings                                  -> failure
  8. otherwise                                            -> success

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

The command override (#30, #43) is for fork PRs, whose `pull_request` runs get a
read-only token and so can neither bind a label nor post a status. The owner
reviews the fork, then comments `/ai-review override <head sha, 12+ hex>: <reason>`
on the PR conversation. That issue_comment run has a write token: it re-checks
the comment from the event payload (owner login, a User, OWNER association, this
PR, the live head starts with the named SHA) and posts the audit comment

    <!-- pr-guardian:override-cmd sha=<sha> base=<quoted base ref> comment=<comment id> -->

which counts only while the owner's comment still exists with a body that names
that head, so editing or deleting it revokes the override.

Removing needs-human (#27): when the owner removes it, the run posts
`<!-- pr-guardian:ack sha= base= round= event= -->` for that issue event, and the
round's escalation stops re-applying the label. A workflow-change escalation is
never acknowledged this way; the owner must override instead.

A fork PR's `pull_request` and `pull_request_review_comment` runs are read-only:
they compute and print the verdict and write nothing. Informational commands
(help, explain, hints) are answered before the stale-head check; state changes
only after it.

A commit status (not a check run) is used so that runs triggered by
issue_comment, which execute on the default branch, still land on the PR head.
Fails closed: any error leaves the status non-success.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse
from typing import Any

import commands
import gh
import state as st
import textsafe
import threads as th

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
_SHA = r"([0-9a-f]{40}|[0-9a-f]{64})"
_BASE = r"([A-Za-z0-9%/._~-]{1,1024})"
_ID = r"([1-9][0-9]{0,19})"
CMD_OVERRIDE_MARKER = "<!-- pr-guardian:override-cmd sha={sha} base={base} comment={cid} -->"
_CMD_OVERRIDE_RE = re.compile(rf"<!-- pr-guardian:override-cmd sha={_SHA} base={_BASE} comment={_ID} -->\s*\Z",
                              re.ASCII)
ACK_MARKER = "<!-- pr-guardian:ack sha={sha} base={base} round={round} event={eid} -->"
_ACK_RE = re.compile(rf"<!-- pr-guardian:ack sha={_SHA} base={_BASE} round=(0|[1-9][0-9]{{0,9}}) event={_ID} -->\s*\Z",
                     re.ASCII)
ACK_REFUSED_MARKER = "<!-- pr-guardian:ack-refused event={eid} -->"
_ACK_REFUSED_RE = re.compile(rf"<!-- pr-guardian:ack-refused event={_ID} -->\s*\Z", re.ASCII)
NEEDS_HUMAN_MARKER = "<!-- pr-guardian:needs-human sha={sha} round={round} -->"
_NEEDS_HUMAN_RE = re.compile(rf"<!-- pr-guardian:needs-human sha={_SHA} round=(0|[1-9][0-9]{{0,9}}) -->\s*\Z",
                             re.ASCII)
WORKFLOW_SIGNAL = "workflow modified"  # publish_review.WORKFLOW_SIGNAL (GHSA-v7qp-pmhq-cf47)
INFO_REASONS = ("help requested", "explain requested", "override needs a head SHA and a reason",
                "override must be a top-level PR comment", "wontfix belongs in a finding thread")


def latest_label_event(events: list[dict[str, Any]] | None, action: str, label: str) -> dict[str, Any] | None:
    """The most recent `labeled` / `unlabeled` issue event for `label`, or None."""
    hits = [e for e in events or []
            if isinstance(e, dict) and e.get("event") == action
            and isinstance(e.get("label"), dict) and e["label"].get("name") == label]
    return hits[-1] if hits else None


def latest_override_event(events: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """The most recent `labeled` issue event for the override label, or None."""
    return latest_label_event(events, "labeled", OVERRIDE_LABEL)


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


def _quote_base(base_ref: str) -> str:
    return urllib.parse.quote(base_ref, safe=_BASE_SAFE)


def _bot_bodies(comments: list[dict[str, Any]] | None) -> list[tuple[dict[str, Any], str]]:
    """(comment, body) for github-actions[bot] comments that are not the summary."""
    out = []
    for c in comments or []:
        if not isinstance(c, dict) or not st.is_trusted_author(c.get("user")):
            continue
        body = c.get("body")
        if isinstance(body, str) and st.SUMMARY_MARKER not in body:
            out.append((c, body))
    return out


def command_override_marker(sha: str, base_ref: str, cid: int) -> str:
    return CMD_OVERRIDE_MARKER.format(sha=sha, base=_quote_base(base_ref), cid=cid)


def _cmd_override_markers(comments: list[dict[str, Any]] | None) -> dict[int, tuple[str, str] | None]:
    """Owner comment id -> (sha, base_ref) from trusted override-cmd markers; None if they disagree."""
    out: dict[int, tuple[str, str] | None] = {}
    for _, body in _bot_bodies(comments):
        m = _CMD_OVERRIDE_RE.search(body)
        if not m:
            continue
        cid, bound = int(m.group(3)), (m.group(1), urllib.parse.unquote(m.group(2)))
        if cid not in out:
            out[cid] = bound
        elif out[cid] != bound:
            out[cid] = None
    return out


def override_command(comment: Any, owner: str) -> commands.Command | None:
    """The well-formed override command in an owner's own comment, else None."""
    if not commands.is_owner(comment, owner):
        return None
    cmd = commands.parse(comment.get("body"))
    return cmd if cmd is not None and cmd.name == "override" and cmd.ok else None


def command_override_bindings(comments: list[dict[str, Any]] | None, owner: str) -> set[tuple[str, str]]:
    """(sha, base_ref) pairs an owner's /ai-review override covers.

    A trusted marker counts only while the comment it names is still on the PR, is still the
    owner's (login, User, OWNER association), and still parses as a well-formed override whose
    SHA prefix the bound head starts with. Editing or deleting that comment revokes it.
    """
    live = {c.get("id"): c for c in comments or [] if isinstance(c, dict)}
    out: set[tuple[str, str]] = set()
    for cid, bound in _cmd_override_markers(comments).items():
        cmd = override_command(live.get(cid), owner) if bound else None
        if cmd is not None and bound[0].startswith(cmd.arg):
            out.add(bound)
    return out


def ack_marker(sha: str, base_ref: str, round_: int, eid: int) -> str:
    return ACK_MARKER.format(sha=sha, base=_quote_base(base_ref), round=round_, eid=eid)


def ack_bindings(comments: list[dict[str, Any]] | None, events: list[dict[str, Any]] | None,
                 owner: str) -> set[tuple[str, str, int]]:
    """(sha, base_ref, round) acknowledged by the owner's latest removal of needs-human."""
    latest = latest_label_event(events, "unlabeled", ESCALATION_LABEL)
    eid = event_id(latest)
    if eid is None or not applied_by_owner(latest, owner):
        return set()
    out = set()
    for _, body in _bot_bodies(comments):
        m = _ACK_RE.search(body)
        if m and int(m.group(4)) == eid:
            out.add((m.group(1), urllib.parse.unquote(m.group(2)), int(m.group(3))))
    return out


def ack_refused(comments: list[dict[str, Any]] | None, eid: int) -> bool:
    return any((m := _ACK_REFUSED_RE.search(body)) and int(m.group(1)) == eid
               for _, body in _bot_bodies(comments))


def unauthorised_removal(events: list[dict[str, Any]] | None, labels: list[str], owner: str) -> bool:
    """True when needs-human is off the PR but the owner was not the last to touch it.

    Only the owner may remove needs-human. A removal by anyone else (or a label history that
    does not end in the owner's removal) is undone, whatever raised the escalation: a writer's
    /ai-review escalate, a manual label, or an earlier round.
    """
    if ESCALATION_LABEL in labels:
        return False
    hits = [e for e in events or []
            if isinstance(e, dict) and e.get("event") in ("labeled", "unlabeled")
            and isinstance(e.get("label"), dict) and e["label"].get("name") == ESCALATION_LABEL]
    return bool(hits) and not (hits[-1].get("event") == "unlabeled" and applied_by_owner(hits[-1], owner))


def workflow_escalation(state: dict[str, Any] | None) -> bool:
    """An escalation that removing needs-human must never clear (GHSA-v7qp-pmhq-cf47).

    escalation_reasons is cumulative, so a workflow signal from any earlier round counts too.
    """
    s = state or {}
    return bool(s.get("escalated")) and any(
        isinstance(r, str) and r.startswith(WORKFLOW_SIGNAL) for r in s.get("escalation_reasons") or [])


def needs_human_marker(sha: str, round_: int) -> str:
    return NEEDS_HUMAN_MARKER.format(sha=sha, round=round_)


def needs_human_posted(comments: list[dict[str, Any]] | None, sha: str, round_: int) -> bool:
    return any((m := _NEEDS_HUMAN_RE.search(body)) and m.group(1) == sha and int(m.group(2)) == round_
               for _, body in _bot_bodies(comments))


def _md(text: Any) -> str:
    """One line of untrusted text that also cannot break a code span or link label."""
    return textsafe.inline(text).replace("`", "'").replace("[", "(").replace("]", ")")


def _thread_url(thread_map: dict[str, Any], f: dict[str, Any]) -> str | None:
    """The finding's thread: under its thread key, its earlier id, or (opened this round) its id."""
    for key in (f.get("thread_key"), f.get("prior_id"), f.get("id")):
        if isinstance(key, str) and key in thread_map:
            nodes = th.comments(thread_map[key])
            return textsafe.safe_url(nodes[0].get("url")) if nodes else None
    return None


def _where(f: dict[str, Any]) -> str:
    start, end = f.get("start_line"), f.get("end_line")
    lines = f"{start}" if not end or end == start else f"{start}-{end}"
    return f"{_md(f.get('file')) or '?'}:{lines}" if start else (_md(f.get("file")) or "?")


def open_blocking(state: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [f for f in (state or {}).get("findings", [])
            if isinstance(f, dict) and f.get("severity") != "nit" and f.get("status") not in CLOSED]


def blocking_lines(state: dict[str, Any] | None, thread_map: dict[str, Any], limit: int = 20) -> list[str]:
    found = open_blocking(state)
    out = []
    for f in found[:limit]:
        label = " · ".join(x for x in (_md(f.get("id")), _md(f.get("severity")), _md(f.get("rule"))) if x)
        url = _thread_url(thread_map, f)
        head = f"[{label}]({url})" if url else label
        out.append(f"- {head} `{_where(f)}` {_md(f.get('title'))}".rstrip())
    if len(found) > limit:
        out.append(f"- … and {len(found) - limit} more")
    return out


def explain_body(state: dict[str, Any] | None, fid: str, thread_map: dict[str, Any]) -> str:
    findings = [f for f in (state or {}).get("findings", []) if isinstance(f, dict)]
    match = next((f for key in ("id", "prior_id", "thread_key") for f in findings if f.get(key) == fid), None)
    if match is None:
        ids = ", ".join(f"`{_md(f.get('id'))}`" for f in findings[:20])
        return (f"No finding `{_md(fid)}` in the latest review."
                + (f" Current ids: {ids}." if ids else " The latest review has no findings."))
    f = match
    head = " · ".join(x for x in (_md(f.get("severity")), _md(f.get("axis")), _md(f.get("rule"))) if x)
    title = _md(f.get("title"))
    lines = [f"**{_md(f.get('id'))}** · {head}" + (f": {title}" if title else ""),
             f"`{_where(f)}` · status `{_md(f.get('status')) or 'open'}`"
             + (f" · earlier id `{_md(f.get('prior_id'))}`" if f.get("prior_id") else "")]
    rationale = textsafe.clean(f.get("rationale") or "").strip()[:1500]
    if rationale:
        lines.append("\n".join("> " + ln for ln in rationale.splitlines()))
    url = _thread_url(thread_map, f)
    if url:
        lines.append(f"Thread: {url}")
    lines.append("To push back, reply inside the finding's thread with `/ai-review wontfix: <reason>`; "
                 "the next round judges it.")
    return "\n\n".join(lines)


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
           default_branch: str = "", require_default: bool = False,
           cmd_overrides: set[tuple[str, str]] | None = None, acked: bool = False) -> dict[str, Any]:
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
    if sha and base_ref and (sha, base_ref) in (cmd_overrides or ()):
        return {"state": "success", "description": f"Overridden by {owner} (/ai-review override)"}
    if fork:
        return {"state": "failure",
                "description": f"Fork PR: not auto-reviewed. {owner} reviews, then comments "
                               "/ai-review override <sha>: <reason>"}
    if review_result not in ("", "success", "skipped"):
        return {"state": "error", "description": f"Review job {review_result}; re-run, or comment /ai-review"}
    # The owner's removal of needs-human acknowledges this round's escalation (#27), but never a
    # writer's escalate in this run or a workflow change (GHSA-v7qp-pmhq-cf47). A needs-human
    # label put back after the acknowledgement still blocks.
    cleared = acked and not escalate and not workflow_escalation(s)
    if ESCALATION_LABEL in labels and not escalate and (not s.get("escalated") or cleared):
        return {"state": "failure", "description": f"Needs human: waiting for {owner} to apply {OVERRIDE_LABEL}"}
    if not escalate and not (s.get("escalated") and not cleared) and unauthorised_removal(events, labels, owner):
        return {"state": "failure", "label": ESCALATION_LABEL,
                "description": f"Needs human: only {owner} may remove {ESCALATION_LABEL}"}
    if escalate or (s.get("escalated") and not cleared):
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
    blocking = open_blocking(s)
    if blocking:
        sevs = [f.get("severity") if f.get("severity") in BLOCKING else "unrecognised" for f in blocking]
        counts = ", ".join(f"{sevs.count(x)} {x}" for x in (*BLOCKING, "unrecognised") if x in sevs)
        return {"state": "failure",
                "description": f"Round {s['round']}: {counts} open. Fix or push back in the threads"}
    nits = sum(1 for f in s.get("findings", []) if f.get("severity") == "nit" and f.get("status") not in CLOSED)
    return {"state": "success",
            "description": f"Round {s['round']}: clean" + (f" ({nits} nits, non-blocking)" if nits else "")}


def _forbidden(exc: Exception) -> bool:
    """A 403 from a read-only token (fork PR runs). Matched on text so gh.py stays as it is."""
    text = str(exc)
    return "HTTP 403" in text or "Resource not accessible by integration" in text


def _thread_map(repo: str, pr: int) -> dict[str, Any]:
    try:
        return th.by_finding(th.fetch(repo, pr))
    except (gh.GhError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"::notice::pr-guardian could not read review threads: {textsafe.inline(exc)[:200]}")
        return {}


def _state(comments: list[dict[str, Any]]) -> dict[str, Any] | None:
    summary = st.find_summary_comment(comments)
    return st.decode(summary["body"]) if summary else None


def info_reply(reason: str, cmd: commands.Command, kind: str, comment: dict[str, Any], owner: str,
               live_head: str, state_fn, threads_fn) -> str | None:
    """The answer to an informational command, or None when the payload does not match `reason`."""
    head = _md(live_head)
    if reason == "help requested" and cmd.name == "help":
        return commands.help_text(owner)
    if reason == "explain requested" and cmd.name == "explain":
        if not cmd.ok:
            return "Usage: `/ai-review explain <ID>`, for example `/ai-review explain R-001`."
        return explain_body(state_fn(), cmd.arg, threads_fn())
    if not commands.is_owner(comment, owner) and cmd.name == "override":
        return None
    if reason == "override needs a head SHA and a reason" and cmd.name == "override" and not cmd.ok \
            and kind == "issue":
        return ("Override not applied: the command needs the head SHA (at least 12 hex characters) and a "
                f"reason. To accept the current head `{head[:12]}` as it stands, comment:\n\n"
                f"`/ai-review override {head}: <reason>`")
    if reason == "override must be a top-level PR comment" and cmd.name == "override" and kind == "review":
        return ("Override not applied: an override must be a top-level comment on the PR conversation, "
                f"not a thread reply. Comment there:\n\n`/ai-review override {head}: <reason>`")
    if reason == "wontfix belongs in a finding thread" and cmd.name == "wontfix" and kind == "issue":
        return ("Pushback counts only as a reply inside the finding's thread, so this comment changes "
                "nothing. Reply to the finding you disagree with: `/ai-review wontfix: <reason>`. "
                "`/ai-review explain <ID>` describes a finding.")
    return None


def needs_human_body(*, sha: str, round_: int, description: str, owner: str, state: dict[str, Any] | None,
                     extra: list[str], thread_map_fn) -> str:
    """The escalation comment (#43): why, and every open blocking finding with its thread link."""
    s = state or {}
    why = extra + [x for x in (textsafe.inline(r)[:300] for r in (s.get("escalation_reasons") or [])[-5:]) if x]
    found = open_blocking(s)
    workflow = workflow_escalation(s)
    body = (f"🙋 **Human review needed** for `{sha[:12]}` (round {round_}). {textsafe.inline(description)[:500]}"
            f"\n\n@{owner}: push a fix, apply `{OVERRIDE_LABEL}`, or comment "
            f"`/ai-review override {sha}: <reason>` to accept this head. "
            + ("Removing `needs-human` does not clear a workflow-change escalation."
               if workflow else "Removing `needs-human` acknowledges this round's escalation."))
    if why:
        body += "\n\n**Why**\n" + "\n".join(f"- {w}" for w in why[:6])
    if found:
        body += f"\n\n**Open blocking findings ({len(found)})**\n" + "\n".join(blocking_lines(s, thread_map_fn()))
    return body + "\n\n" + needs_human_marker(sha, round_)


def _step_summary(result: dict[str, Any]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"### {CONTEXT} (read-only fork run)\n\n**{result['state']}**: {result['description']}\n")
    except OSError as exc:
        print(f"::notice::could not write the step summary: {textsafe.inline(exc)[:200]}")


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
    repo, num = args.repo, args.pr

    pr = gh.api(f"repos/{repo}/pulls/{num}")
    live_head = pr["head"]["sha"]
    sha = args.sha or live_head
    head_repo = (pr["head"].get("repo") or {}).get("full_name")
    fork = head_repo != pr["base"]["repo"]["full_name"]

    # The triggering comment, re-read from the payload and re-authorised: route.py passes only a
    # fixed reason, never command text. A comment on another PR is ignored.
    event_name, event = commands.load_event()
    cref = commands.comment_ref(event_name, event)
    if cref and commands.event_pr(event_name, event) != num:
        cref = None
    comment = event.get("comment") if cref else None
    cmd = commands.parse(comment.get("body")) if cref else None
    writer = cmd is not None and commands.is_writer(comment)
    # A fork PR's pull_request* runs hold a read-only token: decide and print, write nothing (#30).
    read_only = fork and event_name in ("pull_request", "pull_request_review_comment")
    write = not args.dry_run and not read_only

    cache: dict[str, Any] = {}

    def issue_comments() -> list[dict[str, Any]]:
        if "comments" not in cache:
            cache["comments"] = gh.api(f"repos/{repo}/issues/{num}/comments", paginate=True) or []
        return cache["comments"]

    def thread_map() -> dict[str, Any]:
        if "threads" not in cache:
            cache["threads"] = _thread_map(repo, num)
        return cache["threads"]

    # (A) Informational commands, answered even when a newer push owns the verdict.
    if writer and not read_only:
        kind, cid = cref
        if write:
            commands.react(repo, kind, cid)
        if args.reason in INFO_REASONS and write:
            seen = (issue_comments() if kind == "issue"
                    else gh.api(f"repos/{repo}/pulls/{num}/comments", paginate=True) or [])
            answer = None if commands.replied(seen, kind, cid) else info_reply(
                args.reason, cmd, kind, comment, owner, live_head, lambda: _state(issue_comments()), thread_map)
            if answer is not None:
                try:
                    commands.reply(repo, num, kind, cid, answer, reply_to=commands.reply_target(comment, cid))
                except gh.GhError as exc:
                    print(f"::notice::pr-guardian could not reply to comment {cid}: {textsafe.inline(exc)[:200]}")

    # (B) Only the run for the live head may judge it.
    if sha != live_head:
        print(f"verdict: {sha[:7]} is no longer the head; a newer run owns the verdict")
        return 0
    labels = [lbl["name"] for lbl in pr.get("labels", [])]
    base_ref = (pr.get("base") or {}).get("ref") or ""
    base_ref = base_ref if isinstance(base_ref, str) else ""
    default_branch = ((pr.get("base") or {}).get("repo") or {}).get("default_branch") or ""
    default_branch = default_branch if isinstance(default_branch, str) else ""
    # Missing default branch counts as off-default: fail closed, never bind (GHSA-6h55-p37r-jc34).
    off_default = not default_branch or base_ref != default_branch
    events = gh.api(f"repos/{repo}/issues/{num}/events", paginate=True) or []
    comments = issue_comments()
    state = _state(comments)
    round_ = (state or st.empty_state())["round"]
    can_bind = not read_only and not off_default and bool(base_ref)

    def post_comment(body: str) -> None:
        if not args.dry_run:
            gh.api(f"repos/{repo}/issues/{num}/comments", "POST", {"body": body})
        comments.append({"user": {"type": "Bot", "login": st.TRUSTED_BOT_LOGIN}, "body": body})

    # (C) State-changing commands.
    # Owner /ai-review override <sha>: <reason> on the PR conversation (#30, #43). Every check is
    # repeated here, on the payload and on the live comment, whatever route.py decided.
    if (args.reason == "override requested by owner" and event_name == "issue_comment" and can_bind
            and cref and cref[0] == "issue" and override_command(comment, owner) is not None):
        cid = cref[1]
        if not sha.startswith(cmd.arg):
            if write and not commands.replied(comments, "issue", cid):
                try:
                    commands.reply(repo, num, "issue", cid,
                                   f"Override not applied: `{cmd.arg}` is not the head, which is now `{sha[:12]}`. "
                                   f"Review that head, then comment `/ai-review override {sha}: <reason>`.")
                except gh.GhError as exc:
                    print(f"::notice::pr-guardian could not reply to comment {cid}: {textsafe.inline(exc)[:200]}")
        else:
            live = next((c for c in comments if isinstance(c, dict) and c.get("id") == cid), None)
            if (live is not None and live.get("body") == comment.get("body")
                    and override_command(live, owner) is not None and cid not in _cmd_override_markers(comments)):
                post_comment(f"🔓 Override by {_md(owner)} via `/ai-review override` for `{sha[:12]}` on "
                             f"`{_md(base_ref)}`: {_md(cmd.text)[:300]}\n\n"
                             f"{command_override_marker(sha, base_ref, cid)}")

    # Owner removed needs-human (#27): acknowledge this head, base and round, unless a workflow
    # change raised the escalation, which only an override may accept.
    if (args.reason == "needs-human label removed" and can_bind and ESCALATION_LABEL not in labels
            and state is not None and state.get("escalated")):
        latest = latest_label_event(events, "unlabeled", ESCALATION_LABEL)
        eid = event_id(latest)
        if eid is not None and applied_by_owner(latest, owner):
            if workflow_escalation(state):
                if not ack_refused(comments, eid):
                    post_comment(f"Removing `{ESCALATION_LABEL}` does not clear a workflow-change escalation, so "
                                 "the label is re-applied. Review the workflow diff, then apply "
                                 f"`{OVERRIDE_LABEL}` or comment `/ai-review override {sha}: <reason>`.\n\n"
                                 + ACK_REFUSED_MARKER.format(eid=eid))
            elif (sha, base_ref, round_) not in ack_bindings(comments, events, owner):
                post_comment(f"Escalation acknowledged by {_md(owner)} for `{sha[:12]}` round {round_}. "
                             "Open findings still decide the verdict; a new escalation re-applies the label.\n\n"
                             + ack_marker(sha, base_ref, round_, eid))

    # Bind only the head the owner labelled: --sha comes from the labeled event payload and
    # has already been checked against the live head above, so a push that lands before
    # this run leaves the application unbound (never bound to unreviewed code).
    latest = latest_override_event(events)
    eid = event_id(latest)
    # Never bind on a PR into another branch: it can never post success anyway, and a marker
    # there would only invite confusion after a retarget (GHSA-6h55-p37r-jc34).
    if (args.bind_override == "true" and args.sha and can_bind and OVERRIDE_LABEL in labels
            and eid is not None and applied_by_owner(latest, owner) and eid not in override_bindings(comments)):
        post_comment(f"🔓 `{OVERRIDE_LABEL}` by the owner covers `{sha[:12]}` on `{textsafe.inline(base_ref)}` only; "
                     f"any other head or base removes it.\n\n{override_marker(sha, base_ref, eid)}")

    if stale_override(events, labels, sha=sha, base_ref=base_ref, comments=comments):
        if write:
            try:
                gh.api(f"repos/{repo}/issues/{num}/labels/{OVERRIDE_LABEL}", "DELETE")
            except gh.GhError as exc:  # already removed concurrently (404)
                print(f"verdict: could not remove stale {OVERRIDE_LABEL}: {exc}")
        labels.remove(OVERRIDE_LABEL)

    acked = state is not None and (sha, base_ref, round_) in ack_bindings(comments, events, owner)
    result = decide(state=state, sha=sha, labels=labels, events=events, owner=owner,
                    escalate=args.escalate == "true", reason=args.reason,
                    review_result=args.review_result, fork=fork,
                    base_ref=base_ref, comments=comments, default_branch=default_branch,
                    require_default=True, cmd_overrides=command_override_bindings(comments, owner),
                    acked=acked)
    full_description = result["description"]
    result["description"] = textsafe.inline(full_description)[:140]  # the status API's limit
    print(json.dumps(result))
    if read_only:
        print(f"::notice::{CONTEXT} (read-only fork run, nothing posted): {result['state']}: {result['description']}")
        _step_summary(result)
        return 0
    if args.dry_run:
        return 0

    run_url = ""
    if os.environ.get("GITHUB_RUN_ID"):
        run_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
                   f"{os.environ.get('GITHUB_REPOSITORY', repo)}/actions/runs/{os.environ['GITHUB_RUN_ID']}")
    body = {"state": result["state"], "context": CONTEXT, "description": result["description"]}
    if run_url:
        body["target_url"] = run_url
    try:
        if result.get("label") and ESCALATION_LABEL not in labels:
            gh.api(f"repos/{repo}/issues/{num}/labels", "POST", {"labels": [ESCALATION_LABEL]})
        if result.get("label") and not needs_human_posted(comments, sha, round_):
            extra = []
            if args.escalate == "true" and writer and cmd.name == "escalate" and cmd.text:
                extra.append(f"escalated by {_md(comment['user']['login'])}: {_md(cmd.text)[:300]}")
            post_comment(needs_human_body(sha=sha, round_=round_, description=full_description, owner=owner,
                                          state=state, extra=extra, thread_map_fn=thread_map))
        gh.api(f"repos/{repo}/statuses/{sha}", "POST", body)
    except gh.GhError as exc:
        if fork and _forbidden(exc):  # belt and braces for a read-only token we did not foresee
            print(f"::notice::{CONTEXT}: token cannot write on this fork PR: {textsafe.inline(exc)[:200]}")
            return 0
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
