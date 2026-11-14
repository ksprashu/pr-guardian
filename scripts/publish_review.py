#!/usr/bin/env python3
"""Turn a validated findings document into PR review threads and round state.

Usage:
  publish_review.py --repo owner/name --pr N --sha HEAD --findings findings.json
                    [--guardian-ref SHA] [--prior prior.json] [--usage agy.json]
                    [--scan scan.json] [--workdir DIR] [--dry-run]

The model never runs in this job and this job is the only one holding
`pull-requests: write`. Everything the model wrote is treated as untrusted
text (textsafe.py): HTML comments are stripped to a fixpoint (so it cannot
forge markers), @-mentions are defused, single-line fields cannot break lines,
link targets must be plain https URLs, ids must match the marker grammar, and
fences are chosen so evidence cannot break out of its block.

Thread policy:
  new P0-P3 anchorable in diff  -> new inline or file thread (exact -> clamped -> file -> summary)
  new P0-P3 outside the diff    -> listed in the summary body
  still_open / reopened, thread resolved   -> unresolve + reply why
  still_open, a writer replied since bot   -> reply with the counter-argument
  fixed / accepted_pushback      -> reply + resolve
  accepted_pushback without a writer's `/ai-review wontfix` after the bot's
    last comment in the finding's thread  -> kept open (still_open), signalled
  prior open id missing from this round    -> kept open, flagged as unaccounted
  nit                            -> summary comment only, never a thread

Workflow tripwire (GHSA-v7qp-pmhq-cf47): a PR that adds, edits, deletes or renames
anything under .github/workflows/ or .github/actions/ escalates to needs-human,
because a same-repo PR runs its own workflow files and can rewrite the checks that
judge it. The one exemption is the governor's rollout PR: the PR changes only
.github/workflows/pr-guardian.yml and its content at the reviewed SHA is byte for
byte templates/pr-guardian.yml rendered with this run's 40-hex guardian ref. This
is detection, not enforcement: a PR that edits its own caller can drop pr-guardian
from the run entirely, and any workflow in the repo can still post the status.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Iterable
import datetime as dt
import json
import math
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import gh
import state as st
import threads as th
from textsafe import clean, inline, safe_url  # noqa: F401  (clean is re-exported as pub.clean)

BLOCKING = ("P0", "P1", "P2", "P3")
STATUS_MARKER = "<!-- pr-guardian:status id={id} status={status} -->"
STATUS_RE = re.compile(r"\A<!-- pr-guardian:status id=[A-Za-z0-9_.-]+ status=[A-Za-z0-9_.-]+ -->\Z")
NITS_MARKER = "<!-- pr-guardian:nits -->"
WONTFIX_RE = re.compile(r"\A/ai-review\s+wontfix(?:\s|:|\Z)")
UNAUTH_PUSHBACK = "unauthenticated pushback"
ID_REUSE = "id reuse"
PUBLISH_INCOMPLETE = "publish incomplete"
COERCED_NOTE = ("Still open: pushback is accepted only after someone with write access replies "
                "`/ai-review wontfix: <reason>` in this thread after pr-guardian's last comment.")
REOPEN_ESCALATION = 3
ROUND_CAP = 6

ID_PARTS = re.compile(r"\A([A-Z][A-Z0-9]*)-([0-9]{3,})\Z")
SAFE_REF_RE = re.compile(r"\A(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,256}\Z")

COMMENT_LIMIT = 65_536
SUMMARY_TARGET = 64_000
STATE_BUDGET = 24_000
DOC_SUMMARY_CAP = 6_000
LIST_CAP = 50
SIGNAL_CAP = 20
SIGNAL_CHARS = 300
BODY_CAPS = {"rationale": 8_000, "evidence": 20_000, "suggestion": 10_000}
INLINE_BODY_LIMIT = 60_000
PER_COMMENT_RETRY = 30

DETAILS_CHECK = "pr-guardian/details"
ANNOTATION_BATCH = 50
MAX_ANNOTATIONS = 500

ROOT = Path(__file__).resolve().parent.parent
CALLER_PATH = ".github/workflows/pr-guardian.yml"
WORKFLOW_DIRS = ("workflows", "actions")
WORKFLOW_SIGNAL = "workflow modified"
FILES_API_CAP = 3000  # pulls/{n}/files silently stops here
SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
LISTED_PATHS = 5

# Gemini 4 Argon standard pricing, USD per 1M tokens (thinking billed as output).
PRICES = [(dt.date(2026, 12, 1), 4.0, 20.0), (dt.date(1970, 1, 1), 2.0, 10.0)]


class PublishError(RuntimeError):
    pass


# --- sanitising model text ---------------------------------------------------
# clean/inline/safe_url live in textsafe.py; ids are validated, never rewritten,
# because they are also the keys threads and state are matched on.

def check_finding(f: dict[str, Any]) -> None:
    """Fail the publish when a field that lands inside a marker is not well formed."""
    if not isinstance(f.get("id"), str) or not st.ID_RE.match(f["id"]):
        raise ValueError(f"finding id {inline(f.get('id'))!r} does not match {st.ID_RE.pattern}")
    prior_id = f.get("prior_id")
    if prior_id is not None and (not isinstance(prior_id, str) or (prior_id != "" and not st.ID_RE.match(prior_id))):
        raise ValueError(f"finding {f['id']}: prior_id {inline(prior_id)!r} is not a finding id")
    if f.get("severity") not in st.SEVERITIES:
        raise ValueError(f"finding {f['id']}: unknown severity {inline(f.get('severity'))!r}")
    for key in ("file", "rule"):
        if not isinstance(f.get(key), str):
            raise ValueError(f"finding {f['id']}: {key} must be a string")
    for key in ("title", "rationale", "axis"):
        if key in f and not isinstance(f[key], str):
            raise ValueError(f"finding {f['id']}: {key} must be a string")
    if "confidence" in f and f["confidence"] is not None and not isinstance(f["confidence"], str):
        raise ValueError(f"finding {f['id']}: confidence must be a string or null")
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
    title = inline(r.get("title"))[:200].replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
    return f"[{title or url}]({url})"


def fence(text: str, lang: str = "") -> str:
    ticks = "~~~~"
    while ticks in text:
        ticks += "~"
    return f"{ticks}{lang}\n{text}\n{ticks}"


def finding_body(f: dict[str, Any], in_diff: bool, *, note: str = "") -> str:
    marker = st.FINDING_MARKER.format(id=_marker_id(f["id"]), severity=_marker_id(f["severity"]))
    header = (f"**{inline(f['severity'])} · {inline(f.get('axis'))[:120]} · "
              f"{inline(f['rule'])[:120]}** · {inline(f.get('title'))[:300]}")
    rationale = clean(f.get("rationale"))[:BODY_CAPS["rationale"]]
    footer = (f"<sub>{inline(f['id'])} · confidence {inline(f.get('confidence'))[:40]} · fix it, or reply "
              "`/ai-review wontfix: <reason>` to push back</sub>")

    parts = [marker, header]
    if note:
        parts += ["", note]
    parts += ["", rationale]
    if f.get("evidence"):
        ev = clean(f["evidence"])[:BODY_CAPS["evidence"]]
        parts += ["", "<details><summary>Evidence</summary>", "", fence(ev), "", "</details>"]
    if in_diff and f.get("suggestion"):
        sug = clean(f["suggestion"])[:BODY_CAPS["suggestion"]].replace("```", "ʼʼʼ")
        parts += ["", f"```suggestion\n{sug}\n```"]
    refs = [x for x in (_ref(r) for r in (f.get("references") or [])[:20]) if x]
    if refs:
        parts += ["", "References: " + " · ".join(refs)]
    parts += ["", footer]
    body = "\n".join(parts)
    if len(body) > INLINE_BODY_LIMIT:
        minimal = [marker, header] + (["", note] if note else []) + ["", rationale[:4_000], "", footer]
        body = "\n".join(minimal)[:INLINE_BODY_LIMIT]
    return body


# --- diff retrieval & geometry (#22, #44) ------------------------------------

def _resolve_git_dir(workdir: str | Path | None = None) -> Path | None:
    if workdir is not None:
        p = Path(workdir)
        return p if (p / ".git").exists() else None
    for cand in (Path("src"), Path(".")):
        if (cand / ".git").exists():
            return cand
    return None


def _git_has_commit(git_dir: Path, ref: str) -> bool:
    if not ref or ref.startswith("-"):
        return False
    try:
        proc = subprocess.run(
            ["git", "-C", str(git_dir), "cat-file", "-e", f"{ref}^{{commit}}"],
            capture_output=True, shell=False, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def diff_from_files(files: list[dict[str, Any]]) -> str:
    """Reconstruct a unified diff from REST `pulls/{n}/files` entries when `gh pr diff` 406s."""
    chunks: list[str] = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        new_path = entry.get("filename")
        if not isinstance(new_path, str) or not new_path or "\n" in new_path or "\r" in new_path:
            continue
        prev = entry.get("previous_filename")
        old_path = prev if isinstance(prev, str) and prev and "\n" not in prev and "\r" not in prev else new_path
        plus = "/dev/null" if entry.get("status") == "removed" else f"b/{new_path}"
        minus = "/dev/null" if entry.get("status") == "added" else f"a/{old_path}"
        header = f"diff --git a/{old_path} b/{new_path}\n--- {minus}\n+++ {plus}\n"
        patch = entry.get("patch")
        if isinstance(patch, str) and patch:
            chunks.append(header + patch + ("" if patch.endswith("\n") else "\n"))
        else:
            chunks.append(header)
    return "".join(chunks)


def fetch_diff(repo: str, pr: int, *, sha: str = "", base_sha: str = "", base: str = "",
               files: list[dict[str, Any]] | None = None,
               workdir: str | Path | None = None) -> str:
    """Fetch PR diff via verified local git checkout, then `gh pr diff`, then `pulls/{n}/files`."""
    git_dir = _resolve_git_dir(workdir)
    if git_dir is not None and SHA_RE.match(sha or "") and _git_has_commit(git_dir, sha):
        candidates = [
            base_sha if SHA_RE.match(base_sha or "") else "",
            f"refs/remotes/origin/{base}" if SAFE_REF_RE.match(base or "") else "",
            f"refs/heads/{base}" if SAFE_REF_RE.match(base or "") else "",
        ]
        base_target = next((c for c in candidates if c and _git_has_commit(git_dir, c)), "")
        if base_target:
            try:
                proc = subprocess.run(
                    ["git", "-C", str(git_dir), "-c", "core.quotepath=false",
                     "diff", "--no-ext-diff", "--no-color", "--find-renames",
                     f"{base_target}...{sha}"],
                    capture_output=True, text=True, errors="replace", shell=False, timeout=120,
                )
                if proc.returncode == 0:
                    return proc.stdout
            except (OSError, subprocess.SubprocessError):
                pass

    try:
        return gh._run(["pr", "diff", str(pr), "-R", repo])
    except gh.GhError as exc:
        if isinstance(files, list):
            print(f"::notice::gh pr diff unavailable ({exc}); reconstructing diff from pulls/{pr}/files",
                  file=sys.stderr)
            return diff_from_files(files)
        raise


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
    s, e = f["start_line"], f["end_line"]
    if s < 1 or e < s:
        return False
    got = lines.get(f["file"], set())
    return all(n in got for n in range(s, e + 1))


def runs(lines_set: set[int]) -> list[tuple[int, int]]:
    """Contiguous `(start, end)` line intervals in `lines_set`, sorted ascending."""
    if not lines_set:
        return []
    nums = sorted(lines_set)
    out: list[tuple[int, int]] = []
    start = prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
        else:
            out.append((start, prev))
            start = prev = n
    out.append((start, prev))
    return out


def anchor(f: dict[str, Any], lines: dict[str, set[int]]) -> dict[str, Any] | None:
    """Resolve the best diff anchor for `f`: exact -> clamped -> file -> None (summary)."""
    path = f.get("file")
    if path not in lines:
        return None
    got = lines[path]
    s, e = f["start_line"], f["end_line"]
    lo, hi = (s, e) if s <= e else (e, s)
    if lo >= 1 and all(n in got for n in range(lo, hi + 1)):
        return {"mode": "exact", "start": lo, "end": hi}

    best_key: tuple[int, int, int] | None = None
    best_span: tuple[int, int] | None = None
    for ra, rb in runs(got):
        ia, ib = max(ra, lo), min(rb, hi)
        if ia <= ib:
            overlap = ib - ia + 1
            contains_end = 1 if ra <= hi <= rb else 0
            key = (overlap, contains_end, -ia)
            if best_key is None or key > best_key:
                best_key = key
                best_span = (ia, ib)
    if best_span is not None:
        return {"mode": "clamped", "start": best_span[0], "end": best_span[1]}
    return {"mode": "file"}


def anchorable(f: dict[str, Any], lines: dict[str, set[int]]) -> bool:
    return anchor(f, lines) is not None


# --- id reuse pre-pass (#20) -------------------------------------------------

def _state_used_ids(prior: dict[str, Any]) -> set[str]:
    used: set[str] = set()
    for old in prior.get("findings", []):
        if isinstance(old, dict):
            for key in ("id", "prior_id", "thread_key"):
                val = old.get(key)
                if isinstance(val, str) and st.ID_RE.match(val):
                    used.add(val)
    for acc in prior.get("accepted", []):
        if isinstance(acc, dict):
            val = acc.get("id")
            if isinstance(val, str) and st.ID_RE.match(val):
                used.add(val)
    for key in prior.get("reopen_counts", {}):
        if isinstance(key, str) and st.ID_RE.match(key):
            used.add(key)
    return used


def used_ids(prior: dict[str, Any], thread_list: list[dict[str, Any]]) -> set[str]:
    """Every id ever used across prior state, accepted pushback, reopen counts, and live threads."""
    used = _state_used_ids(prior)
    for key in th.by_finding(thread_list):
        if isinstance(key, str) and st.ID_RE.match(key):
            used.add(key)
    return used


def high_water(ids: Iterable[str], prior_hw: dict[str, int] | None = None) -> dict[str, int]:
    out: dict[str, int] = {
        k: v for k, v in (prior_hw or {}).items()
        if isinstance(k, str) and st.PREFIX_RE.match(k)
        and isinstance(v, int) and not isinstance(v, bool) and v >= 0
    }
    for fid in ids:
        if isinstance(fid, str) and (m := ID_PARTS.match(fid)):
            prefix, num = m.group(1), int(m.group(2))
            if num > out.get(prefix, 0):
                out[prefix] = num
    return out


def _can_adopt(cand: str, f: dict[str, Any], adoptable: dict[str, dict[str, Any]] | None,
               adopted: set[str]) -> bool:
    return bool(
        adoptable
        and cand in adoptable
        and cand not in adopted
        and f.get("status") == "new"
        and not f.get("prior_id")
        and adoptable[cand].get("path") == f.get("file")
    )


def reassign_ids(findings: list[dict[str, Any]], used: set[str], hw: dict[str, int], *,
                 adoptable: dict[str, dict[str, Any]] | None = None) -> list[str]:
    """Rename any finding whose id collides with `used` or an earlier finding in `findings`.

    An unresolved bot thread absent from prior state whose `path` matches a `new` finding's
    `file` (a partial-publish rerun before state was saved) is adopted instead of renamed so
    `plan()` links to the existing thread rather than posting a duplicate inline comment.
    """
    hard_used = set(used) - set(adoptable or {})
    hw_base = high_water([*hard_used, *(f.get("id", "") for f in findings)], hw)
    seen = set(hard_used)
    adopted: set[str] = set()
    signals: list[str] = []
    for f in findings:
        old = f["id"]
        if old not in seen:
            if not adoptable or old not in adoptable:
                seen.add(old)
                continue
            if _can_adopt(old, f, adoptable, adopted):
                adopted.add(old)
                seen.add(old)
                continue

        m = ID_PARTS.match(old)
        prefix = m.group(1) if m else "R"
        nxt = hw_base.get(prefix, 0) + 1
        new_id = f"{prefix}-{nxt:03d}"
        while new_id in seen or (adoptable and new_id in adoptable
                                 and not _can_adopt(new_id, f, adoptable, adopted)):
            nxt += 1
            new_id = f"{prefix}-{nxt:03d}"
        if _can_adopt(new_id, f, adoptable, adopted):
            adopted.add(new_id)
        hw_base[prefix] = max(hw_base.get(prefix, 0), nxt)
        seen.add(new_id)
        f["id"] = new_id
        signals.append(f"{ID_REUSE}: reviewer reused {inline(old)}; published as {new_id}")
    merged = high_water([*used, *(f.get("id", "") for f in findings)], hw_base)
    hw.clear()
    hw.update(merged)
    return signals


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


# --- workflow tripwire (GHSA-v7qp-pmhq-cf47) ---------------------------------

def _segments(path: Any) -> list[str] | None:
    """A repo path as its segments, or None when it is not a plain relative file path."""
    if not isinstance(path, str) or not path or path.endswith(("/", "\\")):
        return None
    segs = [s for s in path.replace("\\", "/").split("/") if s not in ("", ".")]
    if not segs or ".." in segs:
        return None
    return segs


def is_workflow_path(segs: list[str]) -> bool:
    """Under .github/workflows/ or .github/actions/, ignoring case and stray whitespace."""
    return (len(segs) >= 2 and segs[0].strip().lower() == ".github"
            and segs[1].strip().lower() in WORKFLOW_DIRS)


def _show(paths: list[str]) -> str:
    shown = [inline(p).replace("`", "")[:200] for p in paths[:LISTED_PATHS]]
    more = len(paths) - len(shown)
    return ", ".join(shown) + (f" (+{more} more)" if more > 0 else "")


def render_caller(guardian_ref: str) -> bytes:
    """The caller the governor installs for this ref (governor.render_caller), as bytes."""
    text = (ROOT / "templates" / "pr-guardian.yml").read_text(encoding="utf-8")
    return text.replace("{{REF}}", guardian_ref).encode("utf-8")


def canonical_caller_ok(repo: str, sha: str, guardian_ref: str) -> bool:
    """The PR's caller at `sha` is byte for byte the governor's caller for `guardian_ref`.

    Both refs must be full commit SHAs, so a mutable branch or tag can never vouch for
    itself. Any API error or unexpected shape means no exemption.
    """
    if not (isinstance(sha, str) and SHA_RE.match(sha)
            and isinstance(guardian_ref, str) and SHA_RE.match(guardian_ref)):
        return False
    try:
        data = gh.api(f"repos/{repo}/contents/{CALLER_PATH}?ref={sha}")
    except gh.GhError as exc:
        print(f"::warning::could not read {CALLER_PATH} at {sha}: {exc}", file=sys.stderr)
        return False
    if not (isinstance(data, dict) and data.get("type") == "file" and data.get("encoding") == "base64"
            and isinstance(data.get("content"), str)):
        return False
    try:
        # GitHub wraps the base64 at 60 columns with "\n", so no validate=True here.
        have = base64.b64decode(data["content"])
    except (binascii.Error, ValueError):
        return False
    return have == render_caller(guardian_ref)


def workflow_signals(files: Any, changed_count: Any,
                     caller_ok: Callable[[], bool] | None = None) -> list[str]:
    """Escalating signals for a PR that touches workflow or action files, or whose file
    list cannot prove that it does not. `caller_ok` is asked only for the one exemptable
    shape (the governor's caller, alone); None means nothing is exempt."""
    def sig(why: str) -> list[str]:
        return [f"{WORKFLOW_SIGNAL}: {why}; the owner must review it and apply human-override"]

    if not isinstance(files, list):
        return sig("the PR file list is unavailable or malformed, so workflow changes cannot be ruled out")
    if not isinstance(changed_count, int) or isinstance(changed_count, bool):
        return sig("the PR's changed-file count is unavailable, so workflow changes cannot be ruled out")
    if len(files) >= FILES_API_CAP:
        return sig(f"the PR changes {len(files)}+ files, past what the files API lists")
    if len(files) != changed_count:
        return sig(f"the files API listed {len(files)} files but the PR reports {changed_count}")

    hits: list[tuple[dict[str, Any], str]] = []
    bad: list[str] = []
    for entry in files:
        if not isinstance(entry, dict):
            bad.append(str(entry)[:80])
            continue
        name, prev = entry.get("filename"), entry.get("previous_filename")
        if entry.get("status") in ("renamed", "copied") and not (isinstance(prev, str) and prev):
            bad.append(str(name)[:200])
            continue
        for path in ((name, prev) if prev is not None else (name,)):
            segs = _segments(path)
            if segs is None:
                bad.append(str(path)[:200])
            elif is_workflow_path(segs):
                hits.append((entry, path))
    if bad:
        return sig(f"unreadable file entries ({_show(bad)}), so workflow changes cannot be ruled out")
    if not hits:
        return []
    if len(hits) == 1:
        entry, path = hits[0]
        if (path == CALLER_PATH and entry.get("filename") == CALLER_PATH
                and entry.get("previous_filename") is None
                and entry.get("status") in ("added", "modified")
                and caller_ok is not None and caller_ok()):
            return []
    return sig(f"this PR changes CI workflow or action files ({_show([p for _, p in hits])}), and a "
               "same-repo PR runs its own workflows, so it can rewrite the checks that judge it")


def plan(doc: dict[str, Any], prior: dict[str, Any], thread_list: list[dict[str, Any]],
         diff: str, files: Any = None, changed_count: Any = None,
         caller_ok: Callable[[], bool] | None = None, *,
         sha: str = "", engine: str = "", budget_reason: str = "") -> dict[str, Any]:
    """`files`/`changed_count` (pulls/{n}/files and the PR's changed_files) arm the workflow
    tripwire; omitting both skips it, for callers that only exercise thread planning."""
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
    prior_by_id = {old["id"]: old for old in prior.get("findings", [])
                   if isinstance(old, dict) and isinstance(old.get("id"), str)}
    seen_prior: set[str] = set()
    # Strip internal / provenance keys from untrusted model output.
    findings = [{k: v for k, v in f.items() if k not in ("raised_by", "_anchor")}
                for f in doc["findings"]]
    for f in findings:
        check_finding(f)

    state_used = _state_used_ids(prior)
    used = state_used | set(threads.keys())
    adoptable = {
        tid: t for tid, t in threads.items()
        if tid not in state_used and not t.get("isResolved")
    }
    hw = high_water(used, prior.get("id_high_water"))
    actions["signals"] += reassign_ids(findings, used, hw, adoptable=adoptable)

    has_budget_reason = bool(budget_reason and inline(budget_reason))
    eng = engine if isinstance(engine, str) and st.ENGINE_RE.match(engine) else ""
    for f in findings:
        if not has_budget_reason and f.get("rule") == "PRG-GATE" and f.get("prior_id"):
            f["status"] = "fixed"
        if f.get("status") == "new":
            if eng:
                f["raised_by"] = eng
        else:
            old_f = prior_by_id.get(f.get("prior_id") or "")
            if old_f and isinstance(old_f.get("raised_by"), str) and old_f["raised_by"]:
                f["raised_by"] = old_f["raised_by"]

    r_cap = BODY_CAPS["rationale"]
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
                                           + f"✅ {verb}: {clean(f['rationale'])[:r_cap]}"})
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
                why = COERCED_NOTE if coerced else f"the code still has this problem. {clean(f['rationale'])[:r_cap]}"
                actions["unresolve"].append({"thread": thread["id"], "body": _status(f, "reopened")
                                             + f"🔁 Reopened: {why}"})
            elif writer_replied(thread):
                why = COERCED_NOTE if coerced else f"Still open after your reply: {clean(f['rationale'])[:r_cap]}"
                actions["reply"].append({"thread": thread["id"], "body": _status(f, "still_open") + why})
            continue

        if anchorable(f, lines):
            f["_anchor"] = anchor(f, lines)
            actions["comments"].append(f)
        else:
            actions["outside"].append(f)

    has_fresh_gate = any(f.get("rule") == "PRG-GATE" and f.get("status") not in st_closed() for f in findings)
    for old in prior["findings"]:
        if (old.get("severity") in BLOCKING and old.get("status") not in st_closed()
                and old["id"] not in seen_prior
                and old["id"] not in {f["id"] for f in findings}):
            if old.get("rule") == "PRG-GATE" and (not has_budget_reason or has_fresh_gate):
                closed_gate = dict(old, status="fixed", prior_id=old["id"])
                findings.append(closed_gate)
                gate_thread = threads.get(old["id"])
                if gate_thread and not gate_thread["isResolved"]:
                    actions["resolve"].append({
                        "thread": gate_thread["id"],
                        "body": _status(closed_gate, "fixed")
                        + "✅ Verified fixed: PR gate condition cleared.",
                    })
                continue
            carried = dict(old, status="still_open", prior_id=old["id"])
            findings.append(carried)
            actions["signals"].append(f"unaccounted: reviewer dropped {inline(old['id'])} without a status; kept open")

    new_state["id_high_water"] = high_water([*used, *(f["id"] for f in findings)], hw)

    if files is not None or changed_count is not None:
        actions["signals"] += workflow_signals(files, changed_count, caller_ok)

    if has_budget_reason:
        actions["signals"].append(f"budget: {inline(budget_reason)[:SIGNAL_CHARS]}")

    valid_sha = sha if isinstance(sha, str) and st.REV_SHA_RE.match(sha) else ""
    prior_shas = list(prior.get("reviewed_shas", []))
    counted = not valid_sha or valid_sha not in prior_shas
    base_rounds = prior.get("sha_rounds", prior["round"])
    new_state["sha_rounds"] = base_rounds + (1 if counted else 0)
    if valid_sha:
        new_state["reviewed_shas"] = ([x for x in prior_shas if x != valid_sha] + [valid_sha])[-20:]
    if counted and new_state["sha_rounds"] == ROUND_CAP:
        actions["signals"].append(f"round cap: {ROUND_CAP} reviewed commits")

    new_state["findings"] = findings
    # Escalation is per round: the verdict turns it into the needs-human label, which is
    # the durable signal the owner clears (override) or removes. Unaccounted, unauthenticated
    # pushback, id reuse, and partial publishes do not escalate.
    non_escalating = ("unaccounted", UNAUTH_PUSHBACK, ID_REUSE, PUBLISH_INCOMPLETE)
    this_round = [x for x in actions["signals"] if not x.startswith(non_escalating)]
    new_state["escalated"] = bool(this_round)
    new_state["escalation_reasons"] += this_round
    return {"actions": actions, "state": st.compact_state(new_state)}


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


def _valid_finite_cost(val: Any) -> bool:
    return isinstance(val, (int, float)) and not isinstance(val, bool) and math.isfinite(val) and val >= 0


def round_cost_of(record: dict[str, Any]) -> tuple[float, str]:
    """Cost of this round, and a note when Claude ran as primary, fallback, or verifier."""
    total = record.get("total_cost_usd")
    if _valid_finite_cost(total):
        round_cost = round(float(total), 4)
    elif record.get("engine") == "claude":
        raw_cost = record.get("cost_usd")
        round_cost = round(float(raw_cost), 4) if _valid_finite_cost(raw_cost) else 0.0
    else:
        round_cost = cost(record.get("usage"))

    tried = record.get("engines_tried")
    if record.get("engine") == "claude":
        note = "Gemini was rate limited; Claude Opus 5.5 reviewed this round"
    elif isinstance(tried, list) and "claude" in tried:
        note = "Claude also ran during this round"
    else:
        note = ""
    return round_cost, note


def _loc(f: dict[str, Any]) -> str:
    """`file:line` as a code span the file name cannot close or break out of."""
    return f"`{inline(f.get('file'))[:200].replace('`', '')}:{inline(f.get('start_line'))}`"


def summary_body(doc: dict[str, Any], result: dict[str, Any], round_cost: float, note: str = "") -> str:
    s, a = result["state"], result["actions"]
    open_blocking = [f for f in s["findings"] if f["severity"] in BLOCKING and f["status"] not in st_closed()]
    counts = {sev: sum(1 for f in open_blocking if f["severity"] == sev) for sev in BLOCKING}
    lines = [st.SUMMARY_MARKER, NITS_MARKER, f"## pr-guardian · round {s['round']}", "",
             clean(doc.get("summary"))[:DOC_SUMMARY_CAP], "",
             "| P0 | P1 | P2 | P3 | nits |", "|---|---|---|---|---|",
             f"| {counts['P0']} | {counts['P1']} | {counts['P2']} | {counts['P3']} | {len(a['nits'])} |", ""]
    if a["outside"]:
        lines.append("**Findings outside the diff** (fix them; they block like threads do):")
        lines += [f"- **{inline(f['id'])} [{inline(f['severity'])}]** {_loc(f)} {inline(f.get('title'))[:300]}"
                  for f in a["outside"][:LIST_CAP]]
        if len(a["outside"]) > LIST_CAP:
            lines.append(f"- … and {len(a['outside']) - LIST_CAP} more")
        lines.append("")
    if a["nits"]:
        lines.append(f"<details><summary>{len(a['nits'])} nits (non-blocking)</summary>\n")
        lines += [f"- {_loc(f)} {inline(f.get('title'))[:300]}" for f in a["nits"][:LIST_CAP]]
        if len(a["nits"]) > LIST_CAP:
            lines.append(f"- … and {len(a['nits']) - LIST_CAP} more")
        lines.append("\n</details>\n")
    not_inspected = [n for n in (doc.get("not_inspected") or []) if isinstance(n, dict)]
    if not_inspected:
        lines.append("<details><summary>Not inspected</summary>\n")
        lines += [f"- {inline(n.get('what'))[:200]}: {inline(n.get('reason'))[:300]}"
                  for n in not_inspected[:LIST_CAP]]
        if len(not_inspected) > LIST_CAP:
            lines.append(f"- … and {len(not_inspected) - LIST_CAP} more")
        lines.append("\n</details>\n")
    if a["signals"]:
        shown_sigs = [inline(x)[:SIGNAL_CHARS] for x in a["signals"][:SIGNAL_CAP]]
        if len(a["signals"]) > SIGNAL_CAP:
            shown_sigs.append(f"… and {len(a['signals']) - SIGNAL_CAP} more")
        lines.append("**Signals:** " + "; ".join(shown_sigs))
    if note:
        lines.append(f"_{inline(note)[:SIGNAL_CHARS]}._")
    total = round(sum(s["cost_usd"]), 2)
    lines.append(f"\n<sub>Round cost ≈ ${round_cost:.2f} · PR total ≈ ${total:.2f} · "
                 "commands: `/ai-review wontfix: <reason>` (in a thread), `/ai-review escalate: <why>`</sub>")
    lines.append(st.encode(st.compact_state(s)))
    return "\n".join(lines)


def fit_summary(body: str, s: dict[str, Any]) -> str:
    """Ensure the rendered summary + trailing state marker fits within GitHub's 65,536-char cap."""
    if len(body) <= SUMMARY_TARGET:
        return body

    visible, marker_str = st.split_state(body)
    if not marker_str:
        marker_str = st.encode(st.compact_state(s, level=0))
    if len(marker_str) > STATE_BUDGET:
        for lvl in (1, 2):
            marker_str = st.encode(st.compact_state(s, level=lvl))
            if len(marker_str) <= STATE_BUDGET:
                break

    candidate = f"{visible}\n{marker_str}" if visible else marker_str
    if len(candidate) <= SUMMARY_TARGET:
        return candidate

    vis_lines = visible.splitlines()
    # Protected head: up through the counts table row (and its trailing blank line if present).
    head_end = min(len(vis_lines), 9)
    for idx, line in enumerate(vis_lines):
        if line == "|---|---|---|---|---|":
            head_end = min(len(vis_lines), idx + 2)
            if head_end < len(vis_lines) and vis_lines[head_end] == "":
                head_end += 1
            break

    # Protected tail: Signals, note, and Round cost footer.
    tail_start = len(vis_lines)
    while tail_start > head_end:
        prev = vis_lines[tail_start - 1]
        if (prev.startswith("<sub>Round cost") or prev.startswith("**Signals:**")
                or (prev.startswith("_") and prev.endswith("._")) or prev == ""):
            tail_start -= 1
        else:
            break

    head = vis_lines[:head_end]
    middle = vis_lines[head_end:tail_start]
    tail = vis_lines[tail_start:]

    def _assemble(mid: list[str]) -> str:
        extra_close = ["</details>"] if sum("<details>" in x for x in mid) > sum("</details>" in x for x in mid) else []
        kept_without_notice = "\n".join(head + mid + extra_close + tail)
        omitted = max(1, len(visible) - len(kept_without_notice))
        notice = f"_… {omitted} characters omitted to fit GitHub's 65,536-character limit; see the workflow log._"
        return "\n".join(head + mid + extra_close + ["", notice, ""] + tail + [marker_str])

    while middle and len(_assemble(middle)) > SUMMARY_TARGET:
        middle.pop()

    out = _assemble(middle)
    if len(out) > SUMMARY_TARGET:
        tail_str = "\n".join(tail)
        budget = SUMMARY_TARGET - len(marker_str) - len(tail_str) - 140
        if budget < len(st.SUMMARY_MARKER) + len(NITS_MARKER) + 10:
            raise PublishError(f"state cannot fit within {SUMMARY_TARGET} chars (got {len(marker_str)})")
        clipped_head = "\n".join(head)[:budget]
        omitted = max(1, len(visible) - len(clipped_head) - len(tail_str))
        notice = f"_… {omitted} characters omitted to fit GitHub's 65,536-character limit; see the workflow log._"
        out = "\n".join([clipped_head, "", notice, *tail, marker_str])
    if len(out) >= COMMENT_LIMIT:
        raise PublishError(f"summary exceeds {COMMENT_LIMIT} chars after truncation")
    return out


# --- details check run (#48) -------------------------------------------------

def annotations(result: dict[str, Any], scan: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Build non-blocking Check Run annotations for outside findings, nits, and scanner leads."""
    a = result["actions"]
    anns: list[dict[str, Any]] = []

    def _add_finding(f: dict[str, Any], level: str) -> None:
        if len(anns) >= MAX_ANNOTATIONS:
            return
        segs = _segments(f.get("file"))
        s_line, e_line = f.get("start_line"), f.get("end_line")
        if segs is None or not (isinstance(s_line, int) and not isinstance(s_line, bool) and s_line >= 1):
            return
        end = e_line if isinstance(e_line, int) and not isinstance(e_line, bool) and e_line >= s_line else s_line
        title = f"{inline(f.get('id'))} [{inline(f.get('severity'))}] {inline(f.get('rule'))}".strip()[:255]
        msg = (inline(f.get("title")) + "\n" + clean(f.get("rationale"))[:4000]).strip()
        anns.append({
            "path": "/".join(segs),
            "start_line": s_line,
            "end_line": end,
            "annotation_level": level,
            "title": title,
            "message": msg or title,
        })

    for f in a.get("outside", []):
        _add_finding(f, "warning")
    for f in a.get("nits", []):
        _add_finding(f, "notice")

    leads = scan.get("leads") if isinstance(scan, dict) else None
    if isinstance(leads, list):
        for lead in leads:
            if len(anns) >= MAX_ANNOTATIONS:
                break
            if not isinstance(lead, dict):
                continue
            segs = _segments(lead.get("file"))
            line = lead.get("line")
            if segs is None or not (isinstance(line, int) and not isinstance(line, bool) and line >= 1):
                continue
            end_raw = lead.get("end_line")
            end = end_raw if isinstance(end_raw, int) and not isinstance(end_raw, bool) and end_raw >= line else line
            title = f"{inline(lead.get('tool'))} {inline(lead.get('rule_id'))}".strip()[:255] or "scanner lead"
            msg = clean(lead.get("message") or title)[:4000] or title
            anns.append({
                "path": "/".join(segs),
                "start_line": line,
                "end_line": end,
                "annotation_level": "notice",
                "title": title,
                "message": msg,
            })
    return anns


def _is_forbidden(exc: gh.GhError) -> bool:
    return (exc.status == 403 or "HTTP 403" in str(exc)
            or "Resource not accessible by integration" in str(exc))


def post_details(repo: str, sha: str, anns: list[dict[str, Any]]) -> str:
    """Post neutral `pr-guardian/details` check run in batches of 50; 403 is a notice no-op."""
    if not anns or not sha:
        return "skipped"
    title = f"{len(anns)} detail annotation(s)"
    summary = f"{len(anns)} annotation(s) posted by pr-guardian (non-blocking details check)."
    payload = {
        "name": DETAILS_CHECK,
        "head_sha": sha,
        "status": "completed",
        "conclusion": "neutral",
        "output": {
            "title": title,
            "summary": summary,
            "annotations": anns[:ANNOTATION_BATCH],
        },
    }
    try:
        resp = gh.api(f"repos/{repo}/check-runs", "POST", payload)
    except gh.GhError as exc:
        if _is_forbidden(exc):
            print("::notice::pr-guardian/details skipped: the publish job lacks checks: write",
                  file=sys.stderr)
            return "forbidden"
        print(f"::warning::pr-guardian/details failed: {exc}", file=sys.stderr)
        return "error"

    for offset in range(ANNOTATION_BATCH, len(anns), ANNOTATION_BATCH):
        if not (isinstance(resp, dict) and resp.get("id")):
            print("::warning::pr-guardian/details missing check-run id for pagination", file=sys.stderr)
            return "error"
        patch = {
            "output": {
                "title": title,
                "summary": summary,
                "annotations": anns[offset:offset + ANNOTATION_BATCH],
            }
        }
        try:
            gh.api(f"repos/{repo}/check-runs/{resp['id']}", "PATCH", patch, idempotent=False)
        except gh.GhError as exc:
            if _is_forbidden(exc):
                print("::notice::pr-guardian/details skipped: the publish job lacks checks: write",
                      file=sys.stderr)
                return "forbidden"
            print(f"::warning::pr-guardian/details batch update failed: {exc}", file=sys.stderr)
            return "error"
    return "posted"


# --- execution (#24, #44, #46, #48) ------------------------------------------

RESOLVE = "mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{id}}}"
UNRESOLVE = "mutation($id:ID!){unresolveReviewThread(input:{threadId:$id}){thread{id}}}"
REPLY = ("mutation($id:ID!,$body:String!){addPullRequestReviewThreadReply("
         "input:{pullRequestReviewThreadId:$id, body:$body}){comment{id}}}")


def _tail_status(thread: dict[str, Any] | None) -> str | None:
    """First line of the thread's last comment when written by the bot and matching STATUS_MARKER."""
    nodes = th.comments(thread)
    if not nodes or not th.is_bot(nodes[-1]):
        return None
    lines = (nodes[-1].get("body") or "").splitlines()
    first = lines[0].strip() if lines else ""
    return first if STATUS_RE.match(first) else None


def _reply(item: dict[str, Any], threads_by_id: dict[str, dict[str, Any]],
           failures: list[str]) -> bool:
    want = (item["body"].splitlines() or [""])[0].strip()
    thread = threads_by_id.get(item["thread"])
    if thread is not None and want and _tail_status(thread) == want:
        return False
    try:
        gh.graphql(REPLY, id=item["thread"], body=item["body"])
        return True
    except gh.GhError as exc:
        msg = f"reply {item['thread']}: {inline(str(exc))}"[:300]
        failures.append(msg)
        print(f"::warning::{msg}", file=sys.stderr)
        return False


def toggle(mutation: str, thread: str) -> None:
    # Thread state is advisory: the verdict counts open findings, so a failed (un)resolve
    # must not stop the summary and state from being written.
    try:
        gh.graphql(mutation, id=thread)
    except gh.GhError as exc:
        print(f"::warning::could not change thread {thread}: {exc}", file=sys.stderr)


def _is_422(exc: gh.GhError) -> bool:
    return exc.status == 422 or "HTTP 422" in str(exc) or "Validation Failed" in str(exc)


def _line_comment_payload(f: dict[str, Any], anc: dict[str, Any]) -> dict[str, Any]:
    start, end = anc["start"], anc["end"]
    is_exact = anc["mode"] == "exact"
    note_str = ("" if is_exact
                else f"_Anchored to lines {start}-{end}; the finding covers {f['start_line']}-{f['end_line']}._")
    c: dict[str, Any] = {
        "path": f["file"],
        "line": end,
        "side": "RIGHT",
        "body": finding_body(f, is_exact, note=note_str),
    }
    if end > start:
        c.update(start_line=start, start_side="RIGHT")
    return c


def _file_comment_payload(f: dict[str, Any], sha: str) -> dict[str, Any]:
    note_str = f"_Lines {f['start_line']}-{f['end_line']} are outside the diff, so this comment is on the file._"
    return {
        "commit_id": sha,
        "path": f["file"],
        "subject_type": "file",
        "body": finding_body(f, False, note=note_str),
    }


def _already_posted_inline(repo: str, pr: int, sha: str) -> set[tuple[str, str]]:
    existing = gh.api(f"repos/{repo}/pulls/{pr}/comments?per_page=100", paginate=True) or []
    posted: set[tuple[str, str]] = set()
    for c in existing:
        if not isinstance(c, dict) or not st.is_trusted_author(c.get("user")):
            continue
        if c.get("commit_id") != sha or not isinstance(c.get("path"), str):
            continue
        m = st.FINDING_RE.search(c.get("body") or "")
        if m:
            posted.add((c["path"], m.group(1)))
    return posted


def execute(repo: str, pr: int, sha: str, doc: dict[str, Any], result: dict[str, Any],
            round_cost: float, note: str = "", base: str = "", *,
            thread_list: list[dict[str, Any]] | None = None,
            comments: list[dict[str, Any]] | None = None,
            guardian_ref: str = "",
            record: dict[str, Any] | None = None,
            scan: dict[str, Any] | None = None) -> None:
    a, s = result["actions"], result["state"]
    rec = record or {}
    gref = guardian_ref if isinstance(guardian_ref, str) and SHA_RE.match(guardian_ref) else ""
    eng_raw = rec.get("engine") or ("agy" if rec else "")
    eng = eng_raw if isinstance(eng_raw, str) and st.ENGINE_RE.match(eng_raw) else ""

    s["cost_usd"] = list(s["cost_usd"]) + [round_cost]
    s["last_reviewed_sha"] = sha
    # The base the scan diffed against, so a retarget makes verdict.py wait (GHSA-6h55-p37r-jc34).
    s["last_reviewed_base"] = base
    s["guardian_ref"] = gref
    s["engine"] = eng
    s["rounds_log"] = (list(s.get("rounds_log", [])) + [{
        "round": s["round"],
        "sha": sha[:12],
        "engine": eng,
        "ref": gref[:12],
        "cost": round_cost,
    }])[-20:]
    s["publish_incomplete"] = False
    s["publish_failures"] = []

    # Summary-first validation: abort before touching threads if state cannot fit.
    fit_summary(summary_body(doc, result, round_cost, note), s)

    failures: list[str] = []
    pending: BaseException | None = None
    threads_by_id = {t["id"]: t for t in (thread_list or []) if isinstance(t, dict) and "id" in t}

    try:
        for item in a["unresolve"]:
            toggle(UNRESOLVE, item["thread"])
            _reply(item, threads_by_id, failures)
        for item in a["reply"]:
            _reply(item, threads_by_id, failures)
        for item in a["resolve"]:
            _reply(item, threads_by_id, failures)
            toggle(RESOLVE, item["thread"])

        if a["comments"]:
            already = _already_posted_inline(repo, pr, sha)
            todo = [f for f in a["comments"] if (f["file"], f["id"]) not in already]
            line_items: list[tuple[dict[str, Any], dict[str, Any]]] = []
            file_items: list[dict[str, Any]] = []
            for f in todo:
                anc = f.get("_anchor") or {"mode": "exact", "start": f["start_line"], "end": f["end_line"]}
                if anc["mode"] == "file":
                    file_items.append(f)
                else:
                    line_items.append((f, anc))

            degraded_ids: set[str] = set()

            def _degrade(f_item: dict[str, Any], why: str) -> None:
                print(f"::notice::publish: {f_item['id']} ({f_item['file']}:{f_item['start_line']}) "
                      f"listed in summary ({why})", file=sys.stderr)
                if "posted" in f_item:
                    f_item["posted"] = "summary"
                a["outside"].append(f_item)
                degraded_ids.add(f_item["id"])

            if line_items:
                batch_comments = [_line_comment_payload(f, anc) for f, anc in line_items]
                review = {
                    "commit_id": sha,
                    "event": "COMMENT",
                    "comments": batch_comments,
                    "body": f"pr-guardian round {s['round']}: "
                            f"{len(batch_comments)} new finding(s). See the summary comment for totals.",
                }
                try:
                    gh.api(f"repos/{repo}/pulls/{pr}/reviews", "POST", review)
                except gh.GhError as exc:
                    if _is_422(exc):
                        print(f"publish: inline review rejected ({exc}); retrying comments individually",
                              file=sys.stderr)
                        for idx, (f, anc) in enumerate(line_items):
                            if idx >= PER_COMMENT_RETRY:
                                _degrade(f, "past per-comment retry cap")
                                continue
                            single = {"commit_id": sha, **_line_comment_payload(f, anc)}
                            try:
                                gh.api(f"repos/{repo}/pulls/{pr}/comments", "POST", single)
                            except gh.GhError as c_exc:
                                if _is_422(c_exc):
                                    file_items.append(f)
                                else:
                                    msg = f"inline {f['id']} ({f['file']}): {inline(str(c_exc))}"[:300]
                                    failures.append(msg)
                                    print(f"::warning::{msg}", file=sys.stderr)
                    else:
                        try:
                            posted_now = _already_posted_inline(repo, pr, sha)
                        except gh.GhError:
                            posted_now = set()
                        missing = [f for f, _ in line_items if (f["file"], f["id"]) not in posted_now]
                        if missing:
                            msg = f"inline review ({len(missing)} comment(s)): {inline(str(exc))}"[:300]
                            failures.append(msg)
                            print(f"::warning::{msg}", file=sys.stderr)
                        else:
                            print("publish: batch review returned error after server created comments; continuing",
                                  file=sys.stderr)

            for f in file_items:
                try:
                    gh.api(f"repos/{repo}/pulls/{pr}/comments", "POST", _file_comment_payload(f, sha))
                except gh.GhError as f_exc:
                    if _is_422(f_exc):
                        _degrade(f, "file-level anchor rejected")
                    else:
                        msg = f"file comment {f['id']} ({f['file']}): {inline(str(f_exc))}"[:300]
                        failures.append(msg)
                        print(f"::warning::{msg}", file=sys.stderr)

            if degraded_ids:
                a["comments"] = [f for f in a["comments"] if f["id"] not in degraded_ids]
    except Exception as exc:
        pending = exc
        msg = f"publish error: {inline(str(exc))}"[:300]
        failures.append(msg)
        print(f"::warning::{msg}", file=sys.stderr)

    if failures:
        s["publish_incomplete"] = True
        s["publish_failures"] = [x[:300] for x in failures[-20:]]
        sig = f"{PUBLISH_INCOMPLETE}: {len(failures)} GitHub write(s) failed; re-run the workflow to retry"
        if sig not in a["signals"]:
            a["signals"].append(sig)

    body = fit_summary(summary_body(doc, result, round_cost, note), s)
    issue_comments = comments if comments is not None else (
        gh.api(f"repos/{repo}/issues/{pr}/comments", paginate=True) or []
    )
    existing = st.find_summary_comment(issue_comments)
    if existing:
        gh.api(f"repos/{repo}/issues/comments/{existing['id']}", "PATCH", {"body": body})
    else:
        gh.api(f"repos/{repo}/issues/{pr}/comments", "POST", {"body": body})

    if pending is not None and not isinstance(pending, gh.GhError):
        raise pending

    if SHA_RE.match(sha or ""):
        anns = annotations(result, scan)
        if anns:
            post_details(repo, sha, anns)


# --- dry-run plan (#18) ------------------------------------------------------

def dry_run_plan(doc: dict[str, Any], result: dict[str, Any], thread_list: list[dict[str, Any]],
                 round_cost: float, note: str = "") -> dict[str, Any]:
    a, s = result["actions"], result["state"]
    threads_by_id = {t["id"]: t for t in thread_list if isinstance(t, dict) and "id" in t}
    planned_threads: list[dict[str, Any]] = []
    for act_name in ("unresolve", "reply", "resolve"):
        for item in a[act_name]:
            t = threads_by_id.get(item["thread"])
            nodes = th.comments(t) if t else []
            url = (nodes[0].get("url") if nodes and isinstance(nodes[0], dict) else "") or ""
            body_lines = item["body"].splitlines()
            status_line = body_lines[0].strip() if body_lines else ""
            preview = "\n".join(body_lines[1:]).strip()[:200]
            skip_reply = bool(t is not None and status_line and _tail_status(t) == status_line)
            planned_threads.append({
                "action": act_name,
                "thread": item["thread"],
                "url": url,
                "status_line": status_line,
                "skip_reply": skip_reply,
                "preview": preview,
            })

    planned_comments: list[dict[str, Any]] = []
    for f in a["comments"]:
        anc = f.get("_anchor") or {"mode": "exact", "start": f["start_line"], "end": f["end_line"]}
        anchored = "file" if anc["mode"] == "file" else f"{anc['start']}-{anc['end']}"
        planned_comments.append({
            "id": f["id"],
            "file": f["file"],
            "lines": f"{f['start_line']}-{f['end_line']}",
            "anchor": anc["mode"],
            "anchored": anchored,
        })

    prov_state = dict(s, cost_usd=list(s["cost_usd"]) + [round_cost])
    raw = summary_body(doc, {"actions": a, "state": prov_state}, round_cost, note)
    try:
        fitted = fit_summary(raw, prov_state)
        fits = True
    except PublishError:
        fitted = raw
        fits = False
    _, marker_str = st.split_state(fitted)

    return {
        "actions": {k: len(v) for k, v in a.items()},
        "round": s["round"],
        "sha_rounds": s.get("sha_rounds", s["round"]),
        "escalated": s["escalated"],
        "signals": list(a["signals"]),
        "threads": planned_threads,
        "comments": planned_comments,
        "outside": [{"id": f["id"], "file": f["file"], "line": f["start_line"]} for f in a["outside"]],
        "summary_chars": len(fitted),
        "state_chars": len(marker_str),
        "fits": fits,
        "cost": round_cost,
    }


def _load_optional_json(path_str: str | None) -> dict[str, Any] | None:
    if path_str and Path(path_str).is_file():
        try:
            data = json.loads(Path(path_str).read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            print(f"::warning::publish: {path_str} is not valid JSON; ignoring", file=sys.stderr)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--base", default="", help="base ref the scan reviewed against (scan job output)")
    ap.add_argument("--guardian-ref", default="",
                    help="pr-guardian commit this run loaded (40-hex); the governor's caller rollout is "
                         "exempt from the workflow tripwire only when it pins exactly this")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--prior", default=None, help="optional prior state JSON; defaults to live summary comment")
    ap.add_argument("--usage", help="agy --output-format json result, for cost")
    ap.add_argument("--scan", default=None, help="optional scan.json for neutral details annotations")
    ap.add_argument("--workdir", default=None, help="optional checked-out PR repository path for local git diff")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    doc = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    comments: list[dict[str, Any]] | None = None
    if args.prior:
        prior = st.validate_state(json.loads(Path(args.prior).read_text(encoding="utf-8")))
        if prior is None:
            raise SystemExit(f"publish: --prior {args.prior} is not a valid pr-guardian state")
    else:
        comments = gh.api(f"repos/{args.repo}/issues/{args.pr}/comments", paginate=True) or []
        summary = st.find_summary_comment(comments)
        prior = (st.decode(summary["body"]) if summary else None) or st.empty_state()

    record = _load_optional_json(args.usage) or {}
    scan = _load_optional_json(args.scan)
    guardian_ref = args.guardian_ref if SHA_RE.match(args.guardian_ref or "") else ""
    eng_raw = record.get("engine") or ("agy" if record else "")
    engine = eng_raw if isinstance(eng_raw, str) and st.ENGINE_RE.match(eng_raw) else ""
    budget_reason = record.get("escalate_reason") if isinstance(record.get("escalate_reason"), str) else ""

    # The tripwire's inputs come after --prior is validated, so a bad --prior makes no API call.
    pr_data = gh.api(f"repos/{args.repo}/pulls/{args.pr}")
    changed_count = pr_data.get("changed_files") if isinstance(pr_data, dict) else None
    base_obj = pr_data.get("base") if isinstance(pr_data, dict) else None
    base_sha = (base_obj.get("sha") if isinstance(base_obj, dict) and isinstance(base_obj.get("sha"), str) else "")
    files = gh.pr_files(args.repo, args.pr)
    diff = fetch_diff(
        args.repo, args.pr, sha=args.sha, base_sha=base_sha, base=args.base,
        files=files, workdir=args.workdir,
    )
    thread_list = th.fetch(args.repo, args.pr)
    result = plan(
        doc, prior, thread_list, diff, files=files, changed_count=changed_count,
        caller_ok=lambda: canonical_caller_ok(args.repo, args.sha, guardian_ref),
        sha=args.sha, engine=engine, budget_reason=budget_reason,
    )
    round_cost, reviewer = round_cost_of(record)
    if args.dry_run:
        print(json.dumps(dry_run_plan(doc, result, thread_list, round_cost, reviewer), indent=2))
        return 0
    execute(
        args.repo, args.pr, args.sha, doc, result, round_cost, reviewer, base=args.base,
        thread_list=thread_list, comments=comments, guardian_ref=guardian_ref,
        record=record, scan=scan,
    )
    print(json.dumps({"round": result["state"]["round"], "signals": result["actions"]["signals"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
