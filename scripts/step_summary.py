#!/usr/bin/env python3
"""Render GitHub Actions job step summaries for pr-guardian jobs.

Usage:
  step_summary.py route   --action A --reason R --pr N
  step_summary.py scan    --scan scan.json --collector evidence.json
  step_summary.py review  --triage triage.json --scan scan.json --usage agy.json
                          --findings findings.json --scan-artifact OUTCOME
  step_summary.py publish --result publish.json
  step_summary.py verdict --result verdict.json

Every input value is treated as untrusted: rendered through textsafe.inline,
truncated, and pipe-escaped. No raw HTML, finding titles, or rationale text is
emitted. Always exits 0 so a summary failure never fails a workflow job.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import textsafe

MAX_CHARS = 8000
CELL_CAP = 200
TRUNC_SUFFIX = "\n\n_Summary truncated._\n"


def _cell(value: Any) -> str:
    return textsafe.inline(value)[:CELL_CAP].replace("|", "\\|")


def _load_json(path: str | None) -> Any:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _load_json_line(path: str | None, *, last: bool) -> dict[str, Any] | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    seq = reversed(lines) if last else lines
    for raw in seq:
        s = raw.strip()
        if not s or not s.startswith("{"):
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def _norm_tools(scan: dict[str, Any]) -> list[dict[str, Any]]:
    tools = scan.get("tools", {})
    if isinstance(tools, dict):
        return [
            {"tool": name, **entry} if isinstance(entry, dict)
            else {"tool": name, "status": "error"}
            for name, entry in tools.items()
        ]
    if isinstance(tools, list):
        return [
            entry if isinstance(entry, dict) else {"tool": "?", "status": "error"}
            for entry in tools
        ]
    return [{"tool": "?", "status": "error"}]


def _lead_count(entry: dict[str, Any]) -> int:
    leads = entry.get("leads")
    if isinstance(leads, list):
        return len(leads)
    if isinstance(leads, int) and not isinstance(leads, bool):
        return leads
    return 0


def _route_summary(args: argparse.Namespace) -> str:
    pr = _cell(args.pr) or "-"
    return "\n".join([
        "### pr-guardian: route",
        "",
        "| field | value |",
        "|---|---|",
        f"| action | {_cell(args.action) or '-'} |",
        f"| pr | {pr} |",
        f"| reason | {_cell(args.reason) or '-'} |",
    ])


def _scan_summary(args: argparse.Namespace) -> str:
    lines = ["### pr-guardian: scan", ""]
    scan = _load_json(args.scan)
    if not isinstance(scan, dict):
        lines.append("- scan: _not produced_")
    else:
        leads = scan.get("leads")
        total = len(leads) if isinstance(leads, list) else 0
        lines.append(f"- status: {_cell(scan.get('status') or 'unknown')} · total leads: {total}")
        tools = _norm_tools(scan)
        if tools:
            lines += ["", "| tool | status | leads |", "|---|---|---|"]
            for t in tools:
                name = _cell(t.get("tool") or t.get("name") or "?")
                status = _cell(t.get("status") or "unknown")
                lines.append(f"| {name} | {status} | {_lead_count(t)} |")
    evidence = _load_json(args.collector)
    lines.append(f"- evidence: {'produced' if evidence is not None else '_not produced_'}")
    return "\n".join(lines)


def _format_cost(usage_doc: dict[str, Any]) -> str:
    for key in ("total_cost_usd", "cost_usd"):
        val = usage_doc.get(key)
        if val is not None:
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                return f"${val:.4f}"
            return _cell(val)
    return "priced at publish"


def _review_summary(args: argparse.Namespace) -> str:
    lines = ["### pr-guardian: review", ""]
    lines.append(f"- scan artifact: {_cell(args.scan_artifact) or '_unknown_'}")

    scan = _load_json(args.scan)
    if isinstance(scan, dict):
        leads = scan.get("leads")
        total = len(leads) if isinstance(leads, list) else 0
        lines.append(f"- scan: {_cell(scan.get('status') or 'unknown')} ({total} leads)")
    else:
        lines.append("- scan: _not produced_")

    triage = _load_json(args.triage)
    if not isinstance(triage, dict):
        lines.append("- triage: _not produced_")
    else:
        parts = [f"skip_model={_cell(triage.get('skip_model'))}",
                 f"reason={_cell(triage.get('reason'))}"]
        if triage.get("escalate_reason"):
            parts.append(f"escalate_reason={_cell(triage.get('escalate_reason'))}")
        for key in ("changed_lines", "noop_rebase", "chunk_count"):
            if key in triage and triage[key] is not None:
                parts.append(f"{key}={_cell(triage[key])}")
        if isinstance(triage.get("config_warnings"), list):
            parts.append(f"config_warnings={len(triage['config_warnings'])}")
        lines.append("- triage: " + " · ".join(parts))

    usage = _load_json(args.usage)
    if not isinstance(usage, dict):
        lines.append("- usage: _not produced_")
    else:
        eng_parts = []
        for key in ("engine", "model", "attempts"):
            if usage.get(key) is not None:
                eng_parts.append(f"{key}={_cell(usage[key])}")
        if isinstance(usage.get("engines_tried"), list) and usage["engines_tried"]:
            tried = ", ".join(_cell(x) for x in usage["engines_tried"])
            eng_parts.append(f"engines_tried=[{tried}]")
        if isinstance(usage.get("failover_reasons"), list) and usage["failover_reasons"]:
            fo = "; ".join(
                f"{_cell(r.get('from'))} -> {_cell(r.get('to'))} ({_cell(r.get('category'))})"
                for r in usage["failover_reasons"] if isinstance(r, dict)
            )
            if fo:
                eng_parts.append(f"failover={fo}")
        if eng_parts:
            lines.append("- engine: " + " · ".join(eng_parts))
        if usage.get("skipped") is not None:
            lines.append(f"- skipped: {_cell(usage['skipped'])}")
        tok = usage.get("usage")
        if isinstance(tok, dict) and tok:
            tok_s = ", ".join(f"{_cell(k)}={_cell(v)}" for k, v in tok.items())
            lines.append(f"- tokens: {tok_s}")
        lines.append(f"- cost: {_format_cost(usage)}")
        errs = usage.get("errors")
        if isinstance(errs, list) and errs:
            lines.append("- errors (first 5):")
            for err in errs[:5]:
                lines.append(f"  - {_cell(err)}")
        details = usage.get("attempt_details")
        if isinstance(details, list) and details:
            lines += [
                "",
                "| label | status | turns | seconds | structured output | error |",
                "|---|---|---|---|---|---|",
            ]
            for d in details:
                if not isinstance(d, dict):
                    continue
                turns = d.get("num_turns") if "num_turns" in d else d.get("turns")
                sec = d.get("duration_seconds")
                sec_s = f"{sec:.2f}" if isinstance(sec, (int, float)) and not isinstance(sec, bool) else _cell(sec)
                lines.append(
                    f"| {_cell(d.get('label'))} | {_cell(d.get('status'))} | {_cell(turns)} | "
                    f"{sec_s} | {_cell(d.get('has_structured_output'))} | {_cell(d.get('error'))} |"
                )
        ver = usage.get("verifier")
        if isinstance(ver, dict):
            vparts = [
                f"{k}={_cell(ver.get(k))}"
                for k in ("mode", "engine", "model", "checked", "confirmed", "downgraded", "dropped")
                if ver.get(k) is not None
            ]
            if vparts:
                lines.append("- verifier: " + " · ".join(vparts))

    fdoc = _load_json(args.findings)
    if not isinstance(fdoc, dict):
        lines.append("- findings: _not produced_")
    else:
        flist = fdoc.get("findings")
        flist = [f for f in flist if isinstance(f, dict)] if isinstance(flist, list) else []
        by_sev: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for f in flist:
            sev = _cell(f.get("severity") or "unknown")
            st = _cell(f.get("status") or "new")
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_status[st] = by_status.get(st, 0) + 1
        sev_s = ", ".join(f"{k}={v}" for k, v in by_sev.items()) or "none"
        st_s = ", ".join(f"{k}={v}" for k, v in by_status.items()) or "none"
        lines.append(f"- findings ({len(flist)} total): severity [{sev_s}] · status [{st_s}]")

    return "\n".join(lines)


def _publish_summary(args: argparse.Namespace) -> str:
    lines = ["### pr-guardian: publish", ""]
    obj = _load_json_line(args.result, last=True)
    if obj is None:
        lines.append("- result: _not produced_")
    else:
        lines.append(f"- round: {_cell(obj.get('round'))}")
        signals = obj.get("signals")
        if isinstance(signals, list) and signals:
            lines.append("- signals: " + "; ".join(_cell(s) for s in signals))
        else:
            lines.append("- signals: none")
    return "\n".join(lines)


def _verdict_summary(args: argparse.Namespace) -> str:
    lines = ["### pr-guardian: verdict", ""]
    obj = _load_json_line(args.result, last=False)
    if obj is None:
        lines.append("- result: _not produced_")
    else:
        lines.append(f"- state: {_cell(obj.get('state'))}")
        lines.append(f"- description: {_cell(obj.get('description'))}")
        if obj.get("label"):
            lines.append(f"- label: {_cell(obj.get('label'))}")
    return "\n".join(lines)


def _cap(text: str) -> str:
    out = text.rstrip() + "\n"
    if len(out) <= MAX_CHARS:
        return out
    limit = MAX_CHARS - len(TRUNC_SUFFIX)
    cut = out[:limit]
    nl = cut.rfind("\n")
    if nl > 0:
        cut = cut[:nl]
    return cut + TRUNC_SUFFIX


def _write_summary(text: str) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY") or ""
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)


_HANDLERS = {
    "route": _route_summary,
    "scan": _scan_summary,
    "review": _review_summary,
    "publish": _publish_summary,
    "verdict": _verdict_summary,
}


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], exit_on_error=False)
    sub = ap.add_subparsers(dest="mode", required=True)

    p_route = sub.add_parser("route", exit_on_error=False)
    p_route.add_argument("--action", default="")
    p_route.add_argument("--reason", default="")
    p_route.add_argument("--pr", default="")

    p_scan = sub.add_parser("scan", exit_on_error=False)
    p_scan.add_argument("--scan", default="")
    p_scan.add_argument("--collector", default="")

    p_rev = sub.add_parser("review", exit_on_error=False)
    p_rev.add_argument("--triage", default="")
    p_rev.add_argument("--scan", default="")
    p_rev.add_argument("--usage", default="")
    p_rev.add_argument("--findings", default="")
    p_rev.add_argument("--scan-artifact", default="")

    p_pub = sub.add_parser("publish", exit_on_error=False)
    p_pub.add_argument("--result", default="")

    p_ver = sub.add_parser("verdict", exit_on_error=False)
    p_ver.add_argument("--result", default="")

    return ap


def main() -> int:
    try:
        args = _build_parser().parse_args()
        body = _HANDLERS[args.mode](args)
        _write_summary(_cap(body))
    except SystemExit as exc:
        if exc.code in (None, 0):
            return 0
        print(f"::warning::step summary failed: exited {exc.code}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::step summary failed: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
