#!/usr/bin/env python3
"""Aggregate PR review quality, false-positive proxy, and cost ledger (#46).

Usage:
  ledger.py --repo owner/name [--repo ...] --since YYYY-MM-DD [--until YYYY-MM-DD]
            [--json out.json] [--markdown out.md] [--post-issue owner/name]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import sys
from typing import Any

import gh
import state as st
from textsafe import inline

LEDGER_MARKER = "<!-- pr-guardian:ledger -->"
LEDGER_TITLE = "pr-guardian quality & cost ledger"
BLOCKING = ("P0", "P1", "P2", "P3")


def _parse_iso_date(raw: Any) -> dt.date | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        ts = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if ts.tzinfo is not None:
            ts = ts.astimezone(dt.timezone.utc)
        return ts.date()
    except ValueError:
        return None


def _fp_proxy(fixed: int, accepted_pushback: int) -> float | None:
    denom = fixed + accepted_pushback
    return round(accepted_pushback / denom, 4) if denom > 0 else None


def _empty_bucket() -> dict[str, Any]:
    return {
        "prs": 0,
        "merged": 0,
        "_rounds_sum": 0,
        "_sha_rounds_sum": 0,
        "_escalated_sum": 0,
        "total_cost_usd": 0.0,
        "by_severity": {sev: 0 for sev in (*BLOCKING, "nit")},
        "fixed": 0,
        "accepted_pushback": 0,
        "open_at_close": 0,
    }


def _finalize_bucket(b: dict[str, Any]) -> dict[str, Any]:
    prs = b["prs"]
    return {
        "prs": prs,
        "merged": b["merged"],
        "avg_rounds": round(b["_rounds_sum"] / prs, 2) if prs > 0 else 0.0,
        "avg_sha_rounds": round(b["_sha_rounds_sum"] / prs, 2) if prs > 0 else 0.0,
        "total_cost_usd": round(b["total_cost_usd"], 4),
        "avg_cost_usd": round(b["total_cost_usd"] / prs, 4) if prs > 0 else 0.0,
        "escalation_rate": round(b["_escalated_sum"] / prs, 4) if prs > 0 else None,
        "by_severity": dict(b["by_severity"]),
        "fixed": b["fixed"],
        "accepted_pushback": b["accepted_pushback"],
        "open_at_close": b["open_at_close"],
        "false_positive_proxy": _fp_proxy(b["fixed"], b["accepted_pushback"]),
    }


def summarize_pr(repo: str, pr_meta: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    rounds = state["round"]
    sha_rounds = state.get("sha_rounds", rounds)
    pr_cost = round(sum(state.get("cost_usd", [])), 4)
    escalated_ever = bool(state.get("escalation_reasons") or state.get("escalated"))
    engine = state.get("engine") or ""
    gref = (state.get("guardian_ref") or "")[:12]

    by_severity = {sev: 0 for sev in (*BLOCKING, "nit")}
    fixed = 0
    accepted_pushback = 0
    open_at_close = 0
    finding_items: list[dict[str, Any]] = []
    seen_accepted_ids: set[str] = set()

    for f in state.get("findings", []):
        if not isinstance(f, dict):
            continue
        sev = f.get("severity") if f.get("severity") in by_severity else "P3"
        by_severity[sev] += 1
        st_val = f.get("status") or "new"
        f_engine = f.get("raised_by") or engine or "unknown"
        rule = f.get("rule") or "unknown"

        if st_val == "fixed":
            fixed += 1
        elif st_val == "accepted_pushback":
            accepted_pushback += 1
            for k in ("id", "prior_id", "thread_key"):
                if isinstance(f.get(k), str) and f[k]:
                    seen_accepted_ids.add(f[k])
        elif sev in BLOCKING:
            open_at_close += 1

        finding_items.append({
            "severity": sev,
            "status": st_val,
            "rule": rule,
            "engine": f_engine,
        })

    for acc in state.get("accepted", []):
        if not isinstance(acc, dict):
            continue
        aid = acc.get("id")
        if isinstance(aid, str) and aid in seen_accepted_ids:
            continue
        accepted_pushback += 1
        finding_items.append({
            "severity": "P3",
            "status": "accepted_pushback",
            "rule": acc.get("rule") or "unknown",
            "engine": engine or "unknown",
        })

    return {
        "repo": repo,
        "pr": pr_meta["number"],
        "closed_at": pr_meta.get("closed_at") or "",
        "merged": bool(pr_meta.get("merged_at")),
        "rounds": rounds,
        "sha_rounds": sha_rounds,
        "cost": pr_cost,
        "escalated_ever": escalated_ever,
        "engine": engine,
        "guardian_ref": gref,
        "by_severity": by_severity,
        "fixed": fixed,
        "accepted_pushback": accepted_pushback,
        "open_at_close": open_at_close,
        "false_positive_proxy": _fp_proxy(fixed, accepted_pushback),
        "_finding_items": finding_items,
    }


def collect_repo(repo: str, since: dt.date, until: dt.date | None = None) -> list[dict[str, Any]]:
    """Walk closed PRs sorted by updated desc, stopping as soon as `updated_at < since`."""
    records: list[dict[str, Any]] = []
    page = 1
    while True:
        items = gh.api(
            f"repos/{repo}/pulls?state=closed&sort=updated&direction=desc&per_page=100&page={page}"
        )
        if not isinstance(items, list) or not items:
            break
        stop = False
        for pr in items:
            if not isinstance(pr, dict) or not isinstance(pr.get("number"), int):
                continue
            updated_d = _parse_iso_date(pr.get("updated_at"))
            if updated_d is not None and updated_d < since:
                stop = True
                break
            closed_d = _parse_iso_date(pr.get("closed_at"))
            if closed_d is None or closed_d < since or (until is not None and closed_d > until):
                continue
            comments = gh.api(f"repos/{repo}/issues/{pr['number']}/comments?per_page=100", paginate=True) or []
            summary = st.find_summary_comment(comments)
            decoded = st.decode(summary["body"]) if summary else None
            if decoded is None:
                continue
            records.append(summarize_pr(repo, pr, decoded))
        if stop or len(items) < 100:
            break
        page += 1
    return records


def _add_pr_metrics(bucket: dict[str, Any], rec: dict[str, Any], *, include_findings: bool = True) -> None:
    bucket["prs"] += 1
    bucket["merged"] += 1 if rec["merged"] else 0
    bucket["_rounds_sum"] += rec["rounds"]
    bucket["_sha_rounds_sum"] += rec["sha_rounds"]
    bucket["_escalated_sum"] += 1 if rec["escalated_ever"] else 0
    bucket["total_cost_usd"] += rec["cost"]
    if include_findings:
        for sev, cnt in rec["by_severity"].items():
            bucket["by_severity"][sev] = bucket["by_severity"].get(sev, 0) + cnt
        bucket["fixed"] += rec["fixed"]
        bucket["accepted_pushback"] += rec["accepted_pushback"]
        bucket["open_at_close"] += rec["open_at_close"]


def _add_finding_item(bucket: dict[str, Any], item: dict[str, Any]) -> None:
    sev = item["severity"]
    st_val = item["status"]
    if sev in bucket["by_severity"]:
        bucket["by_severity"][sev] += 1
    if st_val == "fixed":
        bucket["fixed"] += 1
    elif st_val == "accepted_pushback":
        bucket["accepted_pushback"] += 1
    elif sev in BLOCKING:
        bucket["open_at_close"] += 1


def build_report(repos: list[str], records: list[dict[str, Any]],
                 since: dt.date, until: dt.date | None = None) -> dict[str, Any]:
    overall = _empty_bucket()
    by_repo: dict[str, dict[str, Any]] = {r: _empty_bucket() for r in repos}
    by_rule: dict[str, dict[str, Any]] = {}
    by_engine: dict[str, dict[str, Any]] = {}
    by_ref: dict[str, dict[str, Any]] = {}

    for rec in records:
        _add_pr_metrics(overall, rec, include_findings=True)
        _add_pr_metrics(by_repo.setdefault(rec["repo"], _empty_bucket()), rec, include_findings=True)

        ref_key = rec["guardian_ref"] or "unknown"
        _add_pr_metrics(by_ref.setdefault(ref_key, _empty_bucket()), rec, include_findings=True)

        eng_key = rec["engine"] or "unknown"
        _add_pr_metrics(by_engine.setdefault(eng_key, _empty_bucket()), rec, include_findings=False)

        rules_seen_in_pr: set[str] = set()
        for item in rec.get("_finding_items", []):
            f_eng = item["engine"] or eng_key
            _add_finding_item(by_engine.setdefault(f_eng, _empty_bucket()), item)
            r_key = item["rule"] or "unknown"
            r_bucket = by_rule.setdefault(r_key, _empty_bucket())
            _add_finding_item(r_bucket, item)
            rules_seen_in_pr.add(r_key)
        for r_key in rules_seen_in_pr:
            by_rule[r_key]["prs"] += 1
            by_rule[r_key]["merged"] += 1 if rec["merged"] else 0

    clean_prs = [{k: v for k, v in rec.items() if not k.startswith("_")} for rec in records]
    return {
        "since": since.isoformat(),
        "until": until.isoformat() if until else None,
        "repos": repos,
        "overall": _finalize_bucket(overall),
        "by_repo": {k: _finalize_bucket(v) for k, v in sorted(by_repo.items())},
        "by_rule": {k: _finalize_bucket(v) for k, v in sorted(by_rule.items())},
        "by_engine": {k: _finalize_bucket(v) for k, v in sorted(by_engine.items())},
        "by_guardian_ref": {k: _finalize_bucket(v) for k, v in sorted(by_ref.items())},
        "prs": clean_prs,
    }


def _cell(val: Any) -> str:
    return inline(val).replace("|", "\\|").replace("`", "")


def _fmt_rate(val: float | None) -> str:
    return f"{val * 100:.1f}%" if val is not None else "—"


def render_markdown(report: dict[str, Any]) -> str:
    ov = report["overall"]
    window = f"{report['since']} .. {report['until'] or 'present'}"
    lines = [
        LEDGER_MARKER,
        f"## pr-guardian ledger ({window})",
        "",
        f"**Overall:** {ov['prs']} PR(s) ({ov['merged']} merged) · avg rounds {ov['avg_rounds']:.2f} "
        f"· total cost ${ov['total_cost_usd']:.2f} (avg ${ov['avg_cost_usd']:.2f}) "
        f"· escalation {_fmt_rate(ov['escalation_rate'])} "
        f"· FP proxy {_fmt_rate(ov['false_positive_proxy'])}",
        "",
        "### By Repository",
        "",
        "| Repo | PRs | Merged | Avg Rounds | Total Cost | Escalation | Fixed | Pushback | Open | FP Proxy |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for repo, b in report["by_repo"].items():
        lines.append(
            f"| `{_cell(repo)}` | {b['prs']} | {b['merged']} | {b['avg_rounds']:.2f} "
            f"| ${b['total_cost_usd']:.2f} | {_fmt_rate(b['escalation_rate'])} "
            f"| {b['fixed']} | {b['accepted_pushback']} | {b['open_at_close']} "
            f"| {_fmt_rate(b['false_positive_proxy'])} |"
        )

    lines += [
        "",
        "### By Engine",
        "",
        "| Engine | PRs | Total Cost | Fixed | Pushback | Open | FP Proxy |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for eng, b in report["by_engine"].items():
        lines.append(
            f"| `{_cell(eng)}` | {b['prs']} | ${b['total_cost_usd']:.2f} "
            f"| {b['fixed']} | {b['accepted_pushback']} | {b['open_at_close']} "
            f"| {_fmt_rate(b['false_positive_proxy'])} |"
        )

    lines += [
        "",
        "### By Rule",
        "",
        "| Rule | PRs | P0 | P1 | P2 | P3 | Fixed | Pushback | Open | FP Proxy |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for rule, b in report["by_rule"].items():
        sev = b["by_severity"]
        lines.append(
            f"| `{_cell(rule)}` | {b['prs']} | {sev['P0']} | {sev['P1']} | {sev['P2']} | {sev['P3']} "
            f"| {b['fixed']} | {b['accepted_pushback']} | {b['open_at_close']} "
            f"| {_fmt_rate(b['false_positive_proxy'])} |"
        )

    lines += [
        "",
        "### By Guardian Ref",
        "",
        "| Ref | PRs | Merged | Avg Rounds | Total Cost | FP Proxy |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for ref, b in report["by_guardian_ref"].items():
        lines.append(
            f"| `{_cell(ref)}` | {b['prs']} | {b['merged']} | {b['avg_rounds']:.2f} "
            f"| ${b['total_cost_usd']:.2f} | {_fmt_rate(b['false_positive_proxy'])} |"
        )
    return "\n".join(lines) + "\n"


def _viewer_login() -> str:
    try:
        user = gh.api("user")
    except gh.GhError:
        return ""
    login = user.get("login") if isinstance(user, dict) else ""
    return login if isinstance(login, str) else ""


def _is_trusted_ledger_author(user: Any, own_login: str) -> bool:
    if st.is_trusted_author(user):
        return True
    return (
        bool(own_login)
        and isinstance(user, dict)
        and user.get("type") != "Bot"
        and user.get("login") == own_login
    )


def upsert_ledger_issue(target_repo: str, markdown: str) -> None:
    own_login = _viewer_login()
    issues = gh.api(f"repos/{target_repo}/issues?state=open&per_page=100", paginate=True) or []
    matches = [
        it for it in issues
        if isinstance(it, dict)
        and "pull_request" not in it
        and isinstance(it.get("number"), int)
        and isinstance(it.get("body"), str)
        and it["body"].lstrip().startswith(LEDGER_MARKER)
        and _is_trusted_ledger_author(it.get("user"), own_login)
    ]
    payload = {"title": LEDGER_TITLE, "body": markdown}
    if matches:
        gh.api(f"repos/{target_repo}/issues/{matches[0]['number']}", "PATCH", payload)
    else:
        gh.api(f"repos/{target_repo}/issues", "POST", payload)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", action="append", required=True, help="owner/name (repeatable)")
    ap.add_argument("--since", required=True, help="YYYY-MM-DD inclusive start date (UTC)")
    ap.add_argument("--until", default=None, help="optional YYYY-MM-DD inclusive end date (UTC)")
    ap.add_argument("--json", dest="json_out", default=None, help="write JSON report to path")
    ap.add_argument("--markdown", dest="md_out", default=None, help="write Markdown report to path")
    ap.add_argument("--post-issue", default=None, help="upsert ledger issue in owner/repo")
    args = ap.parse_args()

    since = dt.date.fromisoformat(args.since)
    until = dt.date.fromisoformat(args.until) if args.until else None
    if until is not None and since > until:
        raise SystemExit("ledger: --since must not be after --until")

    records: list[dict[str, Any]] = []
    for repo in args.repo:
        records.extend(collect_repo(repo, since, until))

    report = build_report(args.repo, records, since, until)
    md = render_markdown(report)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.md_out:
        Path(args.md_out).write_text(md, encoding="utf-8")
    if args.post_issue:
        upsert_ledger_issue(args.post_issue, md)
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
