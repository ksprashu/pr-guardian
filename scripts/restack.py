#!/usr/bin/env python3
"""Post-merge stack restacker for same-repo pull requests.

Usage:
  restack.py --repo owner/name [--workdir PATH] [--merged-pr N] [--dry-run]

Runs only after a same-repo PR squash-merges into the repository's default
branch (or on a default-branch workflow_dispatch). Inspects open same-repo PRs
and, for any stacked child whose base branch just merged or that stacks on the
squashed PR (plus any open default-branch PR that now conflicts with the new
default branch tip):

  1. Retargets the PR base to the default branch if it still points at the
     merged branch.
  2. Syncs `origin/<default_branch>` with `-s ours` ONLY when the squashed PR's
     head commit (or an identical-tree first-parent sync ancestor) is already
     an ancestor of the PR head AND its tree equals `origin/<default_branch>`'s
     tree; otherwise runs a regular 3-way `git merge --no-edit`.
  3. On semantic conflict, aborts the merge cleanly and posts/updates one
     idempotent `<!-- pr-guardian:restack -->` comment listing the conflicting
     files and `/pr-review-loop` resolution steps.

Security invariants (GHSA-7p2f-fx79-f4vw / GHSA-v7qp-pmhq-cf47):
  - Keeps `review.yml` strictly read-only (`contents: read`); this script runs
    only in the separate post-merge `restack.yml` workflow on default-branch
    merge / dispatch events.
  - Strictly refuses fork / cross-repository PRs (`isCrossRepository` or
    mismatched `head.repo.full_name`).
  - Validates all repository names, commit SHAs, and branch refs (rejecting
    leading `-` option injection, `..`, `.lock`, control characters, and shell
    metacharacters) and runs every subprocess with `shell=False`, hooks
    disabled (`core.hooksPath=/dev/null`), and LFS smudge disabled.
  - Passes push credentials via ephemeral `GIT_CONFIG_*` environment headers so
    `actions/checkout` keeps `persist-credentials: false` and no token ever
    touches `.git/config` or `argv`.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any

import gh
import state as st
import textsafe

RESTACK_MARKER = "<!-- pr-guardian:restack -->"
PR_GUARDIAN_WORKFLOW = "pr-guardian.yml"
FORGE_PR_LOOP_URL = "https://github.com/ksprashu/agent-skill-forge/tree/main/skills/pr-review-loop"

REPO_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*\Z", re.ASCII)
SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z", re.ASCII)
PR_RE = re.compile(r"\A[1-9][0-9]{0,9}\Z", re.ASCII)
BRANCH_CHARS_RE = re.compile(r"\A[A-Za-z0-9._/-]{1,255}\Z", re.ASCII)
MAX_CONFLICT_FILES_SHOWN = 25
MAX_ANCESTOR_HOPS = 16


class GitError(RuntimeError):
    def __init__(self, message: str, returncode: int = 1, stdout: str = "", stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@dataclasses.dataclass(frozen=True)
class MergedPR:
    number: int
    head_ref: str
    head_sha: str
    base_ref: str
    merge_commit_sha: str = ""


def is_valid_repo(repo: Any) -> bool:
    if not isinstance(repo, str) or not REPO_RE.fullmatch(repo):
        return False
    owner, name = repo.split("/", 1)
    return owner not in (".", "..") and name not in (".", "..")


def is_safe_branch_ref(ref: Any) -> bool:
    """Validate a short branch ref name (without `refs/heads/`).

    Rejects leading `-` (CWE-88 option injection), path traversal (`..`),
    git-check-ref-format forbidden sequences, `HEAD`, `@`, and any character
    outside `[A-Za-z0-9._/-]`.
    """
    if not isinstance(ref, str) or not BRANCH_CHARS_RE.fullmatch(ref):
        return False
    if ref.startswith(("-", "/", ".")) or ref.endswith(("/", ".", ".lock")):
        return False
    if ref in ("@", "HEAD") or ".." in ref or "//" in ref or "@{" in ref:
        return False
    for seg in ref.split("/"):
        if not seg or seg.startswith(".") or seg.endswith(".lock"):
            return False
    return True


def _coerce_pr_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 10_000_000_000 else None
    if isinstance(value, str):
        text = value.strip()
        return int(text) if PR_RE.fullmatch(text) else None
    return None


def is_fork_pr(pr: dict[str, Any], repo: str) -> bool:
    """True unless `pr` is provably a same-repository pull request on `repo`."""
    if not isinstance(pr, dict) or pr.get("isCrossRepository") is True:
        return True
    head = pr.get("head")
    base = pr.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        return True
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if not isinstance(head_repo, dict) or not isinstance(base_repo, dict):
        return True
    if head_repo.get("fork") is True:
        return True
    return head_repo.get("full_name") != repo or base_repo.get("full_name") != repo


def _code_span(text: Any) -> str:
    """Render untrusted single-line text safely inside single backticks."""
    cleaned = textsafe.inline(text).replace("`", "")
    return f"`{cleaned[:240]}`"


def _redact(text: str, secrets: tuple[str, ...]) -> str:
    out = text
    for secret in secrets:
        if secret:
            out = out.replace(secret, "[REDACTED]")
            b64 = base64.b64encode(f"x-access-token:{secret}".encode("utf-8")).decode("ascii")
            out = out.replace(b64, "[REDACTED]")
    return out


class GitRepo:
    """Safe stdlib wrapper around `git` with hooks/smudge disabled and shell=False."""

    def __init__(self, workdir: Path, *, server_url: str = "https://github.com"):
        self.workdir = Path(workdir).resolve()
        clean_server = server_url.rstrip("/")
        if textsafe.safe_url(clean_server) is None:
            raise ValueError(f"unsafe git server_url (https required): {server_url[:120]!r}")
        self.server_url = clean_server

    def run(self, args: list[str], *, token: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = {
            k: v for k, v in os.environ.items()
            if not k.upper().startswith(("GIT_TRACE", "GIT_CONFIG_", "GIT_CURL_VERBOSE"))
        }
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_LFS_SKIP_SMUDGE"] = "1"
        env["GIT_CONFIG_GLOBAL"] = "/dev/null"
        secrets: tuple[str, ...] = ()
        if token:
            secrets = (token,)
            basic = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
            env["GIT_CONFIG_COUNT"] = "1"
            env["GIT_CONFIG_KEY_0"] = f"http.{self.server_url}/.extraheader"
            env["GIT_CONFIG_VALUE_0"] = f"AUTHORIZATION: basic {basic}"

        cmd = [
            "git",
            "-C", str(self.workdir),
            "-c", "core.hooksPath=/dev/null",
            "-c", "core.quotePath=false",
            "-c", "commit.gpgsign=false",
            "-c", "filter.lfs.smudge=",
            "-c", "filter.lfs.process=",
            "-c", "filter.lfs.required=false",
            "-c", "user.name=github-actions[bot]",
            "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            *args,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=120, env=env)
        if check and proc.returncode != 0:
            stderr = _redact(proc.stderr.strip()[:500], secrets)
            stdout = _redact(proc.stdout.strip()[:500], secrets)
            safe_args = " ".join(args[:4])
            raise GitError(
                f"git {safe_args} failed (exit {proc.returncode}): {stderr or stdout}",
                returncode=proc.returncode,
                stdout=_redact(proc.stdout, secrets),
                stderr=_redact(proc.stderr, secrets),
            )
        return subprocess.CompletedProcess(
            proc.args,
            proc.returncode,
            _redact(proc.stdout, secrets),
            _redact(proc.stderr, secrets),
        )

    def rev_parse(self, rev: str) -> str:
        out = self.run(["rev-parse", "--verify", "--quiet", rev]).stdout.strip()
        if not SHA_RE.fullmatch(out):
            raise GitError(f"unexpected rev-parse output for {rev!r}: {out[:80]!r}")
        return out

    def has_commit(self, sha: str) -> bool:
        if not SHA_RE.fullmatch(sha):
            return False
        proc = self.run(["cat-file", "-e", f"{sha}^{{commit}}"], check=False)
        return proc.returncode == 0

    def tree_of(self, rev: str) -> str:
        return self.rev_parse(f"{rev}^{{tree}}")

    def first_parent(self, sha: str) -> str | None:
        proc = self.run(["rev-parse", "--verify", "--quiet", f"{sha}^1"], check=False)
        out = proc.stdout.strip()
        return out if proc.returncode == 0 and SHA_RE.fullmatch(out) else None

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        proc = self.run(["merge-base", "--is-ancestor", ancestor, descendant], check=False)
        if proc.returncode in (0, 1):
            return proc.returncode == 0
        raise GitError(f"merge-base --is-ancestor failed: {proc.stderr.strip()[:300]}", proc.returncode)

    def fetch_branch(self, branch: str, *, token: str | None = None) -> str:
        if not is_safe_branch_ref(branch):
            raise ValueError(f"unsafe branch ref: {branch!r}")
        refspec = f"+refs/heads/{branch}:refs/remotes/origin/{branch}"
        self.run(["fetch", "--no-tags", "--", "origin", refspec], token=token)
        return self.rev_parse(f"refs/remotes/origin/{branch}")

    def fetch_commit_best_effort(self, sha: str, *, token: str | None = None) -> bool:
        if not SHA_RE.fullmatch(sha):
            return False
        if self.has_commit(sha):
            return True
        proc = self.run(["fetch", "--no-tags", "--", "origin", sha], token=token, check=False)
        return proc.returncode == 0 and self.has_commit(sha)

    def checkout_detached(self, sha: str) -> None:
        if not SHA_RE.fullmatch(sha):
            raise ValueError(f"unsafe commit sha: {sha!r}")
        self.run(["merge", "--abort"], check=False)
        self.run(["checkout", "--detach", "--force", sha])
        self.run(["clean", "-fdx"])

    def abort_merge(self, reset_sha: str) -> None:
        abort = self.run(["merge", "--abort"], check=False)
        if abort.returncode != 0:
            self.run(["reset", "--hard", reset_sha])
        self.run(["clean", "-fdx"])

    def unmerged_files(self) -> list[str]:
        proc = self.run(["diff", "-z", "--name-only", "--diff-filter=U"], check=False)
        paths = [p for p in proc.stdout.split("\0") if p]
        if paths:
            return sorted(set(paths))
        # Fallback to porcelain status for any unmerged state diff-filter=U omitted.
        st_proc = self.run(["status", "-z", "--porcelain=v1"], check=False)
        entries = st_proc.stdout.split("\0")
        unmerged_codes = {"DD", "AU", "UD", "UA", "DU", "AA", "UU"}
        out: list[str] = []
        for entry in entries:
            if len(entry) > 3 and entry[:2] in unmerged_codes:
                out.append(entry[3:])
        return sorted(set(out))

    def push_fast_forward(self, sha: str, branch: str, *, token: str | None = None) -> None:
        if not SHA_RE.fullmatch(sha):
            raise ValueError(f"unsafe commit sha: {sha!r}")
        if not is_safe_branch_ref(branch):
            raise ValueError(f"unsafe branch ref: {branch!r}")
        # Never pass --force or a leading '+': only fast-forward pushes are permitted.
        self.run(["push", "--", "origin", f"{sha}:refs/heads/{branch}"], token=token)


def find_squash_ancestor(git: GitRepo, merged_head_sha: str, candidate_head_sha: str) -> str | None:
    """Return an ancestor of `candidate_head_sha` with the exact tree of `merged_head_sha`.

    Checks `merged_head_sha` first, then walks first parents only while each
    parent preserves `merged_head_sha^{tree}` (which covers 3+ PR stacks where
    an intermediate PR received a `-s ours` sync merge commit before squash
    merging). Never accepts a parent whose tree differs from `merged_head_sha`.
    """
    if not (SHA_RE.fullmatch(merged_head_sha) and SHA_RE.fullmatch(candidate_head_sha)):
        return None
    if not git.has_commit(merged_head_sha):
        return None
    want_tree = git.tree_of(merged_head_sha)
    cur: str | None = merged_head_sha
    for hop in range(MAX_ANCESTOR_HOPS):
        if cur is None or not git.has_commit(cur):
            return None
        if hop > 0 and git.tree_of(cur) != want_tree:
            return None
        if git.is_ancestor(cur, candidate_head_sha):
            return cur
        cur = git.first_parent(cur)
    return None


# --- Comment formatting & idempotent persistence -----------------------------

def find_restack_comment(comments: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """Newest trusted github-actions[bot] comment carrying `RESTACK_MARKER`."""
    mine = [
        c for c in comments or []
        if isinstance(c, dict)
        and isinstance(c.get("body"), str)
        and RESTACK_MARKER in c["body"]
        and st.is_trusted_author(c.get("user"))
    ]
    return mine[-1] if mine else None


def format_conflict_comment(
    *,
    pr_number: int,
    head_ref: str,
    head_sha: str,
    default_branch: str,
    main_sha: str,
    merged: MergedPR,
    conflicts: list[str],
) -> str:
    shown = [f"- {_code_span(p)}" for p in conflicts[:MAX_CONFLICT_FILES_SHOWN]]
    extra = len(conflicts) - len(shown)
    if extra > 0:
        shown.append(f"- _(and {extra} more conflicting file(s))_")
    if not shown:
        shown.append("- _(merge failed without listing unmerged paths; inspect locally with `git merge`)_")

    safe_head_ref = textsafe.inline(head_ref).replace("`", "")
    safe_default = textsafe.inline(default_branch).replace("`", "")
    lines = [
        RESTACK_MARKER,
        "## pr-guardian · stack restack conflict",
        "",
        f"Automatic restack onto {_code_span(default_branch)} after #{merged.number} "
        f"(`{merged.head_sha[:12]}`) stopped because merging {_code_span(f'origin/{default_branch}')} "
        f"(`{main_sha[:12]}`) into {_code_span(head_ref)} (`{head_sha[:12]}`) produced semantic conflicts.",
        "",
        f"**Conflicting files ({len(conflicts)}):**",
        *shown,
        "",
        "**How to resolve:**",
        f"- With [`pr-review-loop`]({FORGE_PR_LOOP_URL}): run `/pr-review-loop` "
        f"(or `python3 <skill-dir>/scripts/restack.py --pr {pr_number} --apply`), resolve the "
        "conflicting files semantically, run the test suite, and push.",
        "- With `git`:",
        "  ```sh",
        "  git fetch origin",
        f"  git switch {safe_head_ref}",
        f"  git merge origin/{safe_default}",
        "  # resolve conflicts, run tests, then:",
        "  git commit && git push",
        "  ```",
    ]
    return "\n".join(lines)


def format_restacked_comment(
    *,
    head_ref: str,
    old_sha: str,
    new_sha: str,
    default_branch: str,
    merged: MergedPR,
    strategy: str,
    ci_needs_manual_trigger: bool,
) -> str:
    change = f"`{old_sha[:12]}`" if old_sha == new_sha else f"`{old_sha[:12]}` -> `{new_sha[:12]}`"
    lines = [
        RESTACK_MARKER,
        "## pr-guardian · stack restack complete",
        "",
        f"Restacked {_code_span(head_ref)} onto {_code_span(default_branch)} after "
        f"#{merged.number} ({change}, strategy: {_code_span(strategy)}).",
    ]
    if ci_needs_manual_trigger:
        lines += [
            "",
            "> **Checks not auto-started:** This update used `GITHUB_TOKEN`, which GitHub prevents "
            "from starting `pull_request` workflow runs, and `workflow_dispatch` on "
            "`pr-guardian.yml` could not be triggered. Comment `/ai-review` (repo owner), push an "
            "empty commit, or configure an optional repo-scoped `STACK_RESTACK_TOKEN` secret so "
            "future restacks re-trigger CI automatically.",
        ]
    return "\n".join(lines)


def upsert_restack_comment(
    repo: str,
    pr_number: int,
    body: str,
    *,
    only_if_existing: bool = False,
    token: str | None = None,
) -> str:
    """Create or update the single `<!-- pr-guardian:restack -->` comment on `pr_number`."""
    comments = gh.api(f"repos/{repo}/issues/{pr_number}/comments?per_page=100", paginate=True, token=token) or []
    existing = find_restack_comment(comments)
    if existing is None:
        if only_if_existing:
            return "none"
        gh.api(f"repos/{repo}/issues/{pr_number}/comments", "POST", {"body": body}, token=token)
        return "created"
    if existing.get("body") == body:
        return "unchanged"
    gh.api(f"repos/{repo}/issues/comments/{existing['id']}", "PATCH", {"body": body}, token=token)
    return "updated"


def dispatch_guardian_review(repo: str, default_branch: str, pr_number: int, *, token: str | None = None) -> bool:
    """Best-effort `workflow_dispatch` on `pr-guardian.yml` when pushing with `GITHUB_TOKEN`."""
    try:
        gh.api(
            f"repos/{repo}/actions/workflows/{PR_GUARDIAN_WORKFLOW}/dispatches",
            "POST",
            {"ref": default_branch, "inputs": {"pr": str(pr_number)}},
            token=token,
        )
        return True
    except gh.GhError as exc:
        print(f"::warning::could not dispatch {PR_GUARDIAN_WORKFLOW} for PR #{pr_number}: {exc}", file=sys.stderr)
        return False


# --- Event resolution & PR restack orchestration -----------------------------

def parse_merged_pr_payload(pr: Any, *, repo: str, default_branch: str) -> MergedPR | None:
    """Validate a PR object as a merged same-repo PR targeting `default_branch`."""
    if not isinstance(pr, dict) or pr.get("merged") is not True:
        return None
    if is_fork_pr(pr, repo):
        return None
    number = _coerce_pr_number(pr.get("number"))
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
    head_ref = head.get("ref")
    head_sha = head.get("sha")
    base_ref = base.get("ref")
    merge_sha = pr.get("merge_commit_sha") or ""
    if (number is None or base_ref != default_branch
            or not is_safe_branch_ref(head_ref)
            or not is_safe_branch_ref(base_ref)
            or not (isinstance(head_sha, str) and SHA_RE.fullmatch(head_sha))):
        return None
    if not (isinstance(merge_sha, str) and SHA_RE.fullmatch(merge_sha)):
        merge_sha = ""
    return MergedPR(
        number=number,
        head_ref=head_ref,
        head_sha=head_sha,
        base_ref=base_ref,
        merge_commit_sha=merge_sha,
    )


def resolve_merged_pr(
    *,
    repo: str,
    default_branch: str,
    event_name: str,
    event: dict[str, Any] | None,
    merged_pr_arg: int | None = None,
    token: str | None = None,
) -> tuple[MergedPR | None, str]:
    """Identify the merged default-branch PR from the event payload or API."""
    if merged_pr_arg is not None:
        pr = gh.api(f"repos/{repo}/pulls/{merged_pr_arg}", token=token)
        parsed = parse_merged_pr_payload(pr, repo=repo, default_branch=default_branch)
        if parsed is None:
            return None, f"PR #{merged_pr_arg} is not a merged same-repo PR into {default_branch}"
        return parsed, "explicit merged_pr"

    if event_name == "pull_request":
        if not isinstance(event, dict) or event.get("action") != "closed":
            return None, "pull_request action is not closed"
        parsed = parse_merged_pr_payload(event.get("pull_request"), repo=repo, default_branch=default_branch)
        if parsed is None:
            return None, f"closed PR was not a same-repo merge into {default_branch}"
        return parsed, "pull_request.closed"

    if event_name in ("workflow_dispatch", "push", ""):
        after_sha = ""
        if event_name == "push" and isinstance(event, dict) and isinstance(event.get("after"), str):
            after_sha = event["after"]
        quoted_base = urllib.parse.quote(default_branch, safe="")
        closed = gh.api(
            f"repos/{repo}/pulls?state=closed&base={quoted_base}&sort=updated&direction=desc&per_page=15",
            token=token,
        ) or []
        merged_candidates: list[MergedPR] = []
        for item in closed:
            if not isinstance(item, dict) or not item.get("merged_at"):
                continue
            # Pull list entries carry `merged_at` rather than `merged: true`.
            candidate = dict(item, merged=True)
            parsed = parse_merged_pr_payload(candidate, repo=repo, default_branch=default_branch)
            if parsed is not None:
                if after_sha and parsed.merge_commit_sha == after_sha:
                    return parsed, "push merge_commit_sha match"
                merged_candidates.append(parsed)
        if merged_candidates and event_name != "push":
            return merged_candidates[0], "recent merged PR lookup"
        if merged_candidates and not after_sha:
            return merged_candidates[0], "recent merged PR lookup"
        return None, f"no matching merged same-repo PR found on {default_branch}"

    return None, f"unsupported event {event_name!r}"


def process_candidate_pr(
    pr: dict[str, Any],
    *,
    repo: str,
    default_branch: str,
    merged: MergedPR,
    git: GitRepo,
    main_sha: str,
    main_tree: str,
    push_token: str | None,
    comment_token: str | None,
    scoped_token: bool,
    dry_run: bool,
) -> dict[str, Any]:
    """Evaluate and restack (or notify) one open PR."""
    number = _coerce_pr_number(pr.get("number"))
    if number is None or number == merged.number:
        return {"pr": number, "status": "skipped_self"}

    if is_fork_pr(pr, repo):
        return {"pr": number, "status": "skipped_fork", "reason": "cross-repository PR refused"}

    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
    head_ref = head.get("ref")
    base_ref = base.get("ref")
    api_head_sha = head.get("sha")
    if (not is_safe_branch_ref(head_ref) or not is_safe_branch_ref(base_ref)
            or not (isinstance(api_head_sha, str) and SHA_RE.fullmatch(api_head_sha))):
        return {"pr": number, "status": "skipped_invalid_ref"}
    if head_ref == default_branch:
        return {"pr": number, "status": "skipped_default_head"}

    is_draft = pr.get("draft") is True
    retarget_needed = base_ref == merged.head_ref
    if not retarget_needed and base_ref != default_branch:
        return {"pr": number, "status": "skipped_other_base", "base": base_ref}

    live_head_sha = git.fetch_branch(head_ref, token=push_token)

    # Already contains the new default branch tip.
    if git.is_ancestor(main_sha, live_head_sha):
        if not retarget_needed:
            return {"pr": number, "status": "already_up_to_date", "head_sha": live_head_sha}
        if dry_run:
            return {
                "pr": number,
                "status": "would_retarget_only",
                "head_sha": live_head_sha,
                "from_base": base_ref,
                "to_base": default_branch,
            }
        gh.api(f"repos/{repo}/pulls/{number}", "PATCH", {"base": default_branch}, token=push_token)
        dispatched = True
        if not scoped_token and not is_draft:
            dispatched = dispatch_guardian_review(repo, default_branch, number, token=push_token)
        body = format_restacked_comment(
            head_ref=head_ref,
            old_sha=live_head_sha,
            new_sha=live_head_sha,
            default_branch=default_branch,
            merged=merged,
            strategy="retarget-only",
            ci_needs_manual_trigger=not scoped_token and not is_draft and not dispatched,
        )
        upsert_restack_comment(
            repo,
            number,
            body,
            only_if_existing=scoped_token or is_draft or dispatched,
            token=comment_token,
        )
        return {
            "pr": number,
            "status": "retargeted",
            "strategy": "retarget-only",
            "old_sha": live_head_sha,
            "new_sha": live_head_sha,
            "retargeted": True,
            "dispatched": dispatched,
        }

    stack_ancestor = find_squash_ancestor(git, merged.head_sha, live_head_sha)
    is_stacked = retarget_needed or (stack_ancestor is not None)

    git.checkout_detached(live_head_sha)

    # Unrelated PR already targeting default_branch: never push noise when clean; notify if conflicting.
    if not is_stacked:
        trial = git.run(["merge", "--no-commit", "--no-ff", "--", f"refs/remotes/origin/{default_branch}"], check=False)
        if trial.returncode == 0:
            git.abort_merge(live_head_sha)
            return {"pr": number, "status": "skipped_clean_unrelated", "head_sha": live_head_sha}
        conflicts = git.unmerged_files()
        git.abort_merge(live_head_sha)
        if dry_run:
            return {"pr": number, "status": "would_notify_conflict", "conflicts": conflicts}
        body = format_conflict_comment(
            pr_number=number,
            head_ref=head_ref,
            head_sha=live_head_sha,
            default_branch=default_branch,
            main_sha=main_sha,
            merged=merged,
            conflicts=conflicts,
        )
        comment_action = upsert_restack_comment(repo, number, body, token=comment_token)
        return {
            "pr": number,
            "status": "conflict_notified",
            "stacked": False,
            "conflicts": conflicts,
            "comment": comment_action,
        }

    # Stacked PR: choose exact-tree `-s ours` ONLY when the ancestor tree matches identically.
    strategy = "merge"
    merge_failed = False
    conflicts: list[str] = []

    if stack_ancestor is not None and git.tree_of(stack_ancestor) == main_tree:
        strategy = "ours-tree-match"
        msg = f"chore: restack onto {default_branch} after #{merged.number} squash merge"
        git.run(["merge", "-s", "ours", "--no-edit", "-m", msg, "--", f"refs/remotes/origin/{default_branch}"])
        # Post-conditions: zero files altered on the PR head, and effective diff preserved.
        if git.tree_of("HEAD") != git.tree_of(live_head_sha) or not git.is_ancestor(main_sha, "HEAD"):
            git.run(["reset", "--hard", live_head_sha])
            raise GitError(f"ours-tree-match invariant failed on PR #{number}")
    else:
        # Optional two-step when `main` advanced past `merged.merge_commit_sha` after a tree-exact squash.
        if (stack_ancestor is not None
                and merged.merge_commit_sha
                and merged.merge_commit_sha != main_sha
                and git.has_commit(merged.merge_commit_sha)
                and git.is_ancestor(merged.merge_commit_sha, main_sha)
                and git.tree_of(stack_ancestor) == git.tree_of(merged.merge_commit_sha)):
            git.run([
                "merge", "-s", "ours", "--no-edit",
                "-m", f"chore: record #{merged.number} squash merge",
                "--", merged.merge_commit_sha,
            ])
            strategy = "ours-squash-then-merge"

        msg = f"chore: restack onto {default_branch} after #{merged.number} squash merge"
        proc = git.run(["merge", "--no-edit", "-m", msg, "--", f"refs/remotes/origin/{default_branch}"], check=False)
        if proc.returncode != 0:
            merge_failed = True
            conflicts = git.unmerged_files()
            git.abort_merge(live_head_sha)

    if merge_failed:
        if dry_run:
            return {
                "pr": number,
                "status": "would_notify_conflict",
                "stacked": True,
                "retarget_needed": retarget_needed,
                "conflicts": conflicts,
            }
        if retarget_needed:
            gh.api(f"repos/{repo}/pulls/{number}", "PATCH", {"base": default_branch}, token=push_token)
        body = format_conflict_comment(
            pr_number=number,
            head_ref=head_ref,
            head_sha=live_head_sha,
            default_branch=default_branch,
            main_sha=main_sha,
            merged=merged,
            conflicts=conflicts,
        )
        comment_action = upsert_restack_comment(repo, number, body, token=comment_token)
        return {
            "pr": number,
            "status": "conflict_notified",
            "stacked": True,
            "retargeted": retarget_needed,
            "conflicts": conflicts,
            "comment": comment_action,
        }

    new_sha = git.rev_parse("HEAD")
    if dry_run:
        git.run(["reset", "--hard", live_head_sha])
        return {
            "pr": number,
            "status": "would_restack",
            "strategy": strategy,
            "old_sha": live_head_sha,
            "new_sha": new_sha,
            "retarget_needed": retarget_needed,
        }

    # Push fast-forward first, then retarget base if needed so the final PR state has both.
    git.push_fast_forward(new_sha, head_ref, token=push_token)
    if retarget_needed:
        gh.api(f"repos/{repo}/pulls/{number}", "PATCH", {"base": default_branch}, token=push_token)

    dispatched = True
    if not scoped_token and not is_draft:
        dispatched = dispatch_guardian_review(repo, default_branch, number, token=push_token)

    body = format_restacked_comment(
        head_ref=head_ref,
        old_sha=live_head_sha,
        new_sha=new_sha,
        default_branch=default_branch,
        merged=merged,
        strategy=strategy,
        ci_needs_manual_trigger=not scoped_token and not is_draft and not dispatched,
    )
    comment_action = upsert_restack_comment(
        repo,
        number,
        body,
        only_if_existing=scoped_token or is_draft or dispatched,
        token=comment_token,
    )
    return {
        "pr": number,
        "status": "restacked",
        "strategy": strategy,
        "old_sha": live_head_sha,
        "new_sha": new_sha,
        "retargeted": retarget_needed,
        "dispatched": dispatched,
        "comment": comment_action,
    }


def restack_open_prs(
    *,
    repo: str,
    workdir: Path,
    merged: MergedPR,
    default_branch: str,
    push_token: str | None = None,
    comment_token: str | None = None,
    scoped_token: bool = False,
    dry_run: bool = False,
    server_url: str = "https://github.com",
) -> dict[str, Any]:
    if not is_valid_repo(repo):
        raise ValueError(f"invalid repository name: {repo!r}")
    if not is_safe_branch_ref(default_branch):
        raise ValueError(f"unsafe default branch ref: {default_branch!r}")

    git = GitRepo(workdir, server_url=server_url)
    main_sha = git.fetch_branch(default_branch, token=push_token)
    main_tree = git.tree_of(main_sha)
    git.fetch_commit_best_effort(merged.head_sha, token=push_token)
    if merged.merge_commit_sha:
        git.fetch_commit_best_effort(merged.merge_commit_sha, token=push_token)

    open_prs = gh.api(f"repos/{repo}/pulls?state=open&per_page=100", paginate=True, token=comment_token) or []
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for pr in sorted((p for p in open_prs if isinstance(p, dict)), key=lambda p: _coerce_pr_number(p.get("number")) or 0):
        pr_num = _coerce_pr_number(pr.get("number"))
        try:
            res = process_candidate_pr(
                pr,
                repo=repo,
                default_branch=default_branch,
                merged=merged,
                git=git,
                main_sha=main_sha,
                main_tree=main_tree,
                push_token=push_token,
                comment_token=comment_token,
                scoped_token=scoped_token,
                dry_run=dry_run,
            )
            results.append(res)
        except (gh.GhError, GitError, ValueError) as exc:
            print(f"::warning::restack failed on PR #{pr_num}: {exc}", file=sys.stderr)
            errors.append({"pr": pr_num, "error": str(exc)})

    return {
        "repo": repo,
        "default_branch": default_branch,
        "main_sha": main_sha,
        "merged_pr": merged.number,
        "token_mode": "scoped" if scoped_token else "github_token",
        "dry_run": dry_run,
        "results": results,
        "errors": errors,
    }


def _load_event(path: str) -> dict[str, Any] | None:
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True, help="owner/name repository slug")
    ap.add_argument("--workdir", default=".", help="local git checkout directory")
    ap.add_argument("--merged-pr", default="", help="merged PR number (optional for workflow_dispatch)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not is_valid_repo(args.repo):
        print(f"::error::invalid --repo {args.repo[:80]!r}", file=sys.stderr)
        return 2

    merged_pr_arg: int | None = None
    if args.merged_pr.strip():
        merged_pr_arg = _coerce_pr_number(args.merged_pr)
        if merged_pr_arg is None:
            print(f"::error::invalid --merged-pr {args.merged_pr[:40]!r}", file=sys.stderr)
            return 2

    scoped_raw = (os.environ.get("STACK_RESTACK_TOKEN") or "").strip()
    github_token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    scoped_token = bool(scoped_raw)
    push_token = scoped_raw or github_token or None
    comment_token = github_token or push_token

    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    try:
        event = _load_event(event_path)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::restack cannot read event payload: {exc}", file=sys.stderr)
        return 2

    # Fast-path event payload default_branch when present; otherwise fetch repo metadata.
    default_branch = ""
    if isinstance(event, dict):
        repo_meta = event.get("repository")
        if isinstance(repo_meta, dict) and isinstance(repo_meta.get("default_branch"), str):
            default_branch = repo_meta["default_branch"]
    if not default_branch:
        repo_data = gh.api(f"repos/{args.repo}", token=comment_token)
        if isinstance(repo_data, dict) and isinstance(repo_data.get("default_branch"), str):
            default_branch = repo_data["default_branch"]
    if not is_safe_branch_ref(default_branch):
        print(f"::error::missing or unsafe default branch {default_branch[:80]!r}", file=sys.stderr)
        return 2

    if event_name in ("workflow_dispatch", "push"):
        ref = os.environ.get("GITHUB_REF") or (event.get("ref") if isinstance(event, dict) else "") or ""
        if ref != f"refs/heads/{default_branch}":
            print(json.dumps({"action": "skip", "reason": f"{event_name} ref {ref!r} is not default branch"}))
            return 0

    merged, reason = resolve_merged_pr(
        repo=args.repo,
        default_branch=default_branch,
        event_name=event_name,
        event=event,
        merged_pr_arg=merged_pr_arg,
        token=comment_token,
    )
    if merged is None:
        print(json.dumps({"action": "skip", "reason": reason}))
        return 0

    summary = restack_open_prs(
        repo=args.repo,
        workdir=Path(args.workdir),
        merged=merged,
        default_branch=default_branch,
        push_token=push_token,
        comment_token=comment_token,
        scoped_token=scoped_token,
        dry_run=args.dry_run,
        server_url=os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
    )
    print(json.dumps(summary))
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
