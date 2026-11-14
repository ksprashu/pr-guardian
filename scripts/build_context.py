#!/usr/bin/env python3
"""Assemble the review context the model reads.

Usage:
  build_context.py --repo owner/name --pr N --out context.md
                   [--scan scan.json] [--collector evidence.json]

Writes one markdown file containing: PR metadata, the changed-file list, the
unified diff (truncated per file past a budget, with the truncation stated),
scanner leads, linter evidence, and, from round 2 on, every prior finding
with its thread state and the replies of writers, the PR author and the bot
(other replies are counted, not shown). The model reads the full
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

# A docs-only PR may skip the model (GHSA-pp8w-8p9r-5f43). Only formats nothing executes:
# no .txt (requirements.txt, CMakeLists.txt), .mdx (JSX), .svg (script), CODEOWNERS or
# .gitignore (policy). Lockfiles never skip: a `resolved` URL can be swapped for another
# tarball on the same registry and every dependency scanner stays clean.
DOC_SUFFIXES = (".md", ".rst", ".png", ".jpg", ".jpeg", ".gif", ".webp")
DOC_NAMES = ("LICENSE", "NOTICE", "AUTHORS")
# Prose an agent or a workflow reads as instructions is reviewed like code: anything under
# these directories at any depth, these file names, or any name containing "instructions".
INSTRUCTION_DIRS = frozenset({".github", ".claude", ".gemini", ".cursor", ".agents",
                              "prompts", "skills", "agents"})
INSTRUCTION_NAMES = frozenset({"skill.md", "agents.md", "agents.override.md",
                               "claude.md", "claude.local.md", "gemini.md"})
FILES_API_CAP = 3000       # pulls/{n}/files returns at most this many; at the cap the list may be short
TOOL_OK = ("ran", "skipped")


def scan_tools(scan: dict[str, Any] | None) -> list[dict[str, Any]]:
    """run_scanners.py reports tools as {name: entry}; accept a list too.
    A malformed entry is reported as an errored tool, never dropped."""
    tools = scan.get("tools", {}) if isinstance(scan, dict) else {}
    if isinstance(tools, dict):
        return [{"tool": name, **entry} if isinstance(entry, dict)
                else {"tool": name, "status": "error", "reason": "malformed entry"}
                for name, entry in tools.items()]
    if isinstance(tools, list):
        return [t if isinstance(t, dict) else {"tool": "?", "status": "error", "reason": "malformed entry"}
                for t in tools]
    return [{"tool": "?", "status": "error", "reason": "malformed tools"}]


def scan_is_clean(scan: Any) -> bool:
    """True only when the scan ran, every tool ran or was skipped as not relevant / not
    installed, at least one ran, and nothing was flagged. A top-level "partial" is
    allowed: it only means a tool such as govulncheck is absent, which a docs PR cannot need."""
    if not isinstance(scan, dict) or scan.get("status") in ("error", "failed"):
        return False
    leads = scan.get("leads")
    if not isinstance(leads, list) or leads:
        return False
    tools = scan_tools(scan) if isinstance(scan.get("tools"), (dict, list)) else []
    if not tools:
        return False
    for t in tools:
        if t.get("status") not in TOOL_OK:
            return False
        n = t.get("leads")
        if isinstance(n, list) and n or isinstance(n, int) and not isinstance(n, bool) and n > 0:
            return False
    return any(t.get("status") == "ran" for t in tools)


def _segments(path: Any) -> list[str] | None:
    """A repo path as its segments, or None when it is not a plain relative file path."""
    if not isinstance(path, str) or not path or path.endswith(("/", "\\")):
        return None
    segs = [s for s in path.replace("\\", "/").split("/") if s not in ("", ".")]
    if not segs or ".." in segs:
        return None
    return segs


def is_instruction(path: Any) -> bool:
    segs = _segments(path)
    if segs is None:
        return True
    base = segs[-1].lower()
    return (any(s.lower() in INSTRUCTION_DIRS for s in segs[:-1])
            or base in INSTRUCTION_NAMES or "instructions" in base)


def is_doc_format(path: Any) -> bool:
    segs = _segments(path)
    return segs is not None and (segs[-1].lower().endswith(DOC_SUFFIXES) or segs[-1] in DOC_NAMES)


def is_pure_doc(path: Any) -> bool:
    """A file whose change cannot alter behaviour: a doc format, outside every instruction path."""
    return is_doc_format(path) and not is_instruction(path)


def file_name(f: dict[str, Any]) -> Any:
    """REST pulls/{n}/files uses `filename`; `gh pr view --json files` used `path`."""
    return f.get("filename") if "filename" in f else f.get("path")


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
    leads = [x for x in leads if isinstance(x, dict)] if isinstance(leads, list) else []
    if leads:
        lines.append("")
        lines.append(f"{len(leads)} leads (showing up to {LEADS_BUDGET}). Each is a lead, not a finding:")
        for lead in leads[:LEADS_BUDGET]:
            lines.append(f"- `{lead.get('file')}:{lead.get('line')}` [{lead.get('tool')} "
                         f"{lead.get('rule_id')}{' ' + ','.join(_as_list(lead.get('cwe'))) if lead.get('cwe') else ''}] "
                         f"{(lead.get('message') or '')[:300]}")
    return "\n".join(lines) or "_scan output unavailable_"


def trusted_reply(r: dict[str, Any], pr_author: str = "") -> bool:
    """Replies the model may read: pr-guardian's own, writers', and the PR author's.

    Anyone can reply in a thread; an outsider's reply is prompt input the repo never
    vetted, so it is omitted rather than shown (GHSA-j3g5-fvc6-rrjw).
    """
    if r.get("is_bot") or r.get("is_writer"):
        return True
    login = r.get("login") or ""
    return (r.get("author_type") != "Bot" and bool(login) and bool(pr_author)
            and pr_author != "ghost" and login == pr_author)


def render_prior(prior: dict[str, Any], threads: list[dict[str, Any]], pr_author: str = "") -> str:
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
        omitted = 0
        for r in th.replies(t) if t else []:
            if not trusted_reply(r, pr_author):
                omitted += 1
                continue
            lines.append(f"> **{r['author']}**: {r['body'][:2000]}")
        if omitted:
            lines.append(f"> _[{omitted} untrusted {'reply' if omitted == 1 else 'replies'} omitted]_")
    if prior["accepted"]:
        lines.append("\n### Pushback you already accepted (do not raise again)")
        for a in prior["accepted"]:
            lines.append(f"- {a['id']}: `{a['file']}` {a['rule']}")
    return "\n".join(lines)


def triage(meta: dict[str, Any], scan: dict[str, Any] | None, prior: dict[str, Any]) -> dict[str, Any]:
    """Whether the model can be skipped: only for a complete, docs-only file list with a
    clean scan, and never while earlier blocking findings are still open. Anything
    unexpected (a short or malformed file list, a rename from code) means review."""
    files = meta.get("files")
    if not isinstance(files, list) or not files:
        return {"skip_model": False, "reason": "no changed files listed"}
    open_prior = [f for f in prior["findings"]
                  if f["severity"] != "nit" and f.get("status") not in ("fixed", "accepted_pushback")]
    if open_prior:
        return {"skip_model": False, "reason": f"{len(open_prior)} prior findings still open"}
    count = meta.get("changedFiles")
    if not isinstance(count, int) or isinstance(count, bool):
        return {"skip_model": False, "reason": "changed-file count unknown"}
    if len(files) != count or len(files) >= FILES_API_CAP:
        return {"skip_model": False, "reason": f"file list incomplete ({len(files)} of {count})"}
    paths: list[Any] = []
    for f in files:
        if not isinstance(f, dict):
            return {"skip_model": False, "reason": "malformed file list"}
        paths.append(file_name(f))
        old = f.get("previous_filename")
        if f.get("status") in ("renamed", "copied") and not (isinstance(old, str) and old):
            return {"skip_model": False, "reason": "rename without its old path"}
        if old is not None:
            paths.append(old)
    if not all(is_pure_doc(p) for p in paths):
        if all(is_doc_format(p) for p in paths):
            return {"skip_model": False, "reason": "agent instruction files are executable prose"}
        return {"skip_model": False, "reason": "code change"}
    if not scan_is_clean(scan):
        return {"skip_model": False, "reason": "docs-only change without a clean scan"}
    return {"skip_model": True, "reason": "docs-only change with a clean scan"}


def build(repo: str, pr: int, scan: dict[str, Any] | None, collector: dict[str, Any] | None,
          meta: dict[str, Any], diff: str, prior: dict[str, Any],
          threads: list[dict[str, Any]]) -> str:
    body_diff, truncated = render_diff(diff)
    listed = [f for f in (meta.get("files") if isinstance(meta.get("files"), list) else [])
              if isinstance(f, dict)]
    lines = []
    for f in listed:
        verb = "copied" if f.get("status") == "copied" else "renamed"
        old = f" ({verb} from `{f['previous_filename']}`)" if f.get("previous_filename") else ""
        lines.append(f"- `{file_name(f)}`{old} (+{f.get('additions', 0)} −{f.get('deletions', 0)})")
    count = meta.get("changedFiles")
    if isinstance(count, int) and not isinstance(count, bool) and count != len(listed):
        lines.append(f"- _list incomplete: {len(listed)} of {count} changed files shown; "
                     "use the diff and the workspace for the rest_")
    files = "\n".join(lines)
    pr_author = (meta.get("author") or {}).get("login") or ""
    parts = [
        f"# PR #{pr} in {repo}: {meta.get('title', '')}",
        f"Author: {pr_author or '?'} · base `{meta.get('baseRefName')}` ← head `{meta.get('headRefName')}`",
        "## Description\n" + ((meta.get("body") or "_no description_")[:8000]),
        "## Changed files\n" + (files or "_none_"),
        "## Scanner results\n" + (render_leads(scan) if isinstance(scan, dict) and scan else "_scan not run_"),
        "## Linter / type-checker evidence\n```json\n"
        + (json.dumps(collector, indent=1)[:60_000] if collector else "{}") + "\n```",
        "## Prior rounds\n" + render_prior(prior, threads, pr_author=pr_author),
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
                               "title,body,author,baseRefName,headRefName,changedFiles"]))
    # `--json files` stops at 100; triage needs every file and checks the count.
    meta["files"] = gh.pr_files(args.repo, args.pr)
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
