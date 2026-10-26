#!/usr/bin/env python3
"""Assemble the review context the model reads.

Usage:
  build_context.py --repo owner/name --pr N --out context.md
                   [--scan scan.json] [--collector evidence.json]

Writes one markdown file containing: PR metadata, the changed-file list, the
unified diff (truncated per file past a budget, with the truncation stated),
scanner leads, linter evidence, and, from round 2 on, every prior finding
with its thread state and the author's replies. The model reads the full
files from the checked-out workspace itself; the diff is the map.

This script collects. It does not decide what is a finding.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import gh
import state as st
import threads as th

# agy resends the context on every turn, so a large diff multiplies into the per-minute
# token quota (Gemini 429 RESOURCE_EXHAUSTED). Past the budget the model reads files itself.
DIFF_BUDGET = 160_000      # characters of diff before per-file truncation, and the hard total
PER_FILE_BUDGET = 16_000
LEADS_BUDGET = 150

DOC_SUFFIXES = (".md", ".mdx", ".rst", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")
DOC_NAMES = ("LICENSE", "NOTICE", "AUTHORS", "CODEOWNERS", ".gitignore")
DEP_SCANNERS = ("osv-scanner", "npm-audit", "pip-audit", "govulncheck", "cargo-audit")


def scan_tools(scan: dict[str, Any] | None) -> list[dict[str, Any]]:
    """run_scanners.py reports tools as {name: entry}; accept a list too."""
    tools = (scan or {}).get("tools", {})
    if isinstance(tools, dict):
        return [{"tool": name, **entry} for name, entry in tools.items()]
    return list(tools)
LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "uv.lock", "poetry.lock",
             "Pipfile.lock", "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock")


def _split_diff(diff: str) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    current, buf = "", []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if buf:
                files.append((current, "".join(buf)))
            current = line.split(" b/", 1)[-1].strip()
            buf = [line]
        else:
            buf.append(line)
    if buf:
        files.append((current, "".join(buf)))
    return files


def render_diff(diff: str) -> tuple[str, list[str]]:
    if len(diff) <= DIFF_BUDGET:
        return diff, []
    out, truncated = [], []
    size = 0
    for path, chunk in _split_diff(diff):
        if size >= DIFF_BUDGET:
            truncated.append(path)
            out.append(f"diff --git a/{path} b/{path}\n… [diff omitted: over the context budget; read the file]\n")
            continue
        if len(chunk) > PER_FILE_BUDGET:
            truncated.append(path)
            chunk = chunk[:PER_FILE_BUDGET] + f"\n… [diff for {path} truncated; read the file]\n"
        out.append(chunk)
        size += len(chunk)
    return "".join(out), truncated


def _as_list(v: Any) -> list[str]:
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]


def render_leads(scan: dict[str, Any]) -> str:
    lines = []
    for tool in scan_tools(scan):
        lines.append(f"- **{tool.get('tool')}**: {tool.get('status')}"
                     + (f" ({tool.get('reason')})" if tool.get("reason") else ""))
    leads = scan.get("leads", [])
    if leads:
        lines.append("")
        lines.append(f"{len(leads)} leads (showing up to {LEADS_BUDGET}). Each is a lead, not a finding:")
        for lead in leads[:LEADS_BUDGET]:
            lines.append(f"- `{lead.get('file')}:{lead.get('line')}` [{lead.get('tool')} "
                         f"{lead.get('rule_id')}{' ' + ','.join(_as_list(lead.get('cwe'))) if lead.get('cwe') else ''}] "
                         f"{(lead.get('message') or '')[:300]}")
    return "\n".join(lines) or "_scan output unavailable_"


def render_prior(prior: dict[str, Any], threads: list[dict[str, Any]]) -> str:
    if not prior["findings"]:
        return "_first round: no prior findings_"
    by_id = th.by_finding(threads)
    lines = [f"Round {prior['round']} raised these. Account for **every** id below in this round "
             "(status still_open / reopened / fixed / accepted_pushback, with prior_id set)."]
    for f in prior["findings"]:
        if f.get("status") in ("fixed", "accepted_pushback"):
            continue
        t = by_id.get(f["id"])
        thread_state = "no thread"
        if t:
            thread_state = "RESOLVED by someone" if t["isResolved"] else "open"
            if t.get("isOutdated"):
                thread_state += ", code changed since"
        lines.append(f"\n### {f['id']} [{f['severity']}] {f['title']}\n"
                     f"`{f['file']}:{f['start_line']}-{f['end_line']}` · {f['axis']} · {f['rule']} · thread: {thread_state}\n\n"
                     f"{f['rationale']}")
        for r in th.replies(t) if t else []:
            lines.append(f"> **{r['author']}**: {r['body'][:2000]}")
    if prior["accepted"]:
        lines.append("\n### Pushback you already accepted (do not raise again)")
        for a in prior["accepted"]:
            lines.append(f"- {a['id']}: `{a['file']}` {a['rule']}")
    return "\n".join(lines)


def triage(meta: dict[str, Any], scan: dict[str, Any] | None, prior: dict[str, Any]) -> dict[str, Any]:
    """Whether the model can be skipped. Only for docs-only PRs, or lockfile-only PRs
    with a clean scan, and never while earlier blocking findings are still open."""
    paths = [f["path"] for f in meta.get("files", [])]
    open_prior = [f for f in prior["findings"]
                  if f["severity"] != "nit" and f.get("status") not in ("fixed", "accepted_pushback")]
    if not paths:
        return {"skip_model": False, "reason": "no changed files listed"}
    if open_prior:
        return {"skip_model": False, "reason": f"{len(open_prior)} prior findings still open"}
    name = lambda p: p.rsplit("/", 1)[-1]
    if all(p.lower().endswith(DOC_SUFFIXES) or name(p) in DOC_NAMES for p in paths):
        if any(name(p).lower() in ("skill.md", "agents.md", "claude.md", "gemini.md") for p in paths):
            return {"skip_model": False, "reason": "agent instruction files are executable prose"}
        return {"skip_model": True, "reason": "docs-only change"}
    if all(name(p) in LOCKFILES for p in paths):
        # osv-scanner must have run; native audits count only when relevant (not skipped).
        dep_tools = [t for t in scan_tools(scan) if t.get("tool") == "osv-scanner"
                     or (t.get("tool") in DEP_SCANNERS and t.get("status") != "skipped")]
        ran = bool(dep_tools) and all(t.get("status") == "ran" for t in dep_tools)
        if ran and not scan.get("leads"):
            return {"skip_model": True, "reason": "lockfile-only change with a clean dependency scan"}
    return {"skip_model": False, "reason": "code change"}


def build(repo: str, pr: int, scan: dict[str, Any] | None, collector: dict[str, Any] | None,
          meta: dict[str, Any], diff: str, prior: dict[str, Any],
          threads: list[dict[str, Any]]) -> str:
    body_diff, truncated = render_diff(diff)
    files = "\n".join(f"- `{f['path']}` (+{f['additions']} −{f['deletions']})" for f in meta.get("files", []))
    parts = [
        f"# PR #{pr} in {repo}: {meta.get('title', '')}",
        f"Author: {meta.get('author', {}).get('login', '?')} · base `{meta.get('baseRefName')}` ← head `{meta.get('headRefName')}`",
        "## Description\n" + ((meta.get("body") or "_no description_")[:8000]),
        "## Changed files\n" + (files or "_none_"),
        "## Scanner results\n" + (render_leads(scan) if scan else "_scan not run_"),
        "## Linter / type-checker evidence\n```json\n"
        + (json.dumps(collector, indent=1)[:60_000] if collector else "{}") + "\n```",
        "## Prior rounds\n" + render_prior(prior, threads),
        "## Diff" + (f"\nTruncated files (read them in full): {', '.join(truncated)}" if truncated else "")
        + "\n```diff\n" + body_diff + "\n```",
    ]
    return "\n\n".join(parts) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--out", required=True)
    ap.add_argument("--scan")
    ap.add_argument("--collector")
    ap.add_argument("--prior-out", help="write the decoded prior state here")
    ap.add_argument("--triage-out", help="write the model-skip decision here")
    args = ap.parse_args()

    def load(p: str | None) -> dict[str, Any] | None:
        if p and Path(p).is_file():
            try:
                return json.loads(Path(p).read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                print(f"build_context: {p} is not JSON; treating as missing", file=sys.stderr)
        return None

    meta = json.loads(gh._run(["pr", "view", str(args.pr), "-R", args.repo, "--json",
                               "title,body,author,baseRefName,headRefName,files"]))
    diff = gh._run(["pr", "diff", str(args.pr), "-R", args.repo])
    comments = gh.api(f"repos/{args.repo}/issues/{args.pr}/comments", paginate=True)
    summary = st.find_summary_comment(comments)
    prior = (st.decode(summary["body"]) if summary else None) or st.empty_state()
    thread_list = th.fetch(args.repo, args.pr)

    scan = load(args.scan)
    Path(args.out).write_text(build(args.repo, args.pr, scan, load(args.collector),
                                    meta, diff, prior, thread_list), encoding="utf-8")
    if args.triage_out:
        Path(args.triage_out).write_text(json.dumps(triage(meta, scan, prior)), encoding="utf-8")
    if args.prior_out:
        Path(args.prior_out).write_text(json.dumps(prior), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
