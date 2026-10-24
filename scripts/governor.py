#!/usr/bin/env python3
"""Reconcile every owned repo to the PR-only + pr-guardian baseline.

Usage:
  governor.py [--dry-run] [--repos a,b,c] [--batch N] [--offset N] [--report-issue]

Needs GH_TOKEN = a fine-grained PAT on all repos with Administration, Secrets,
Contents, Pull requests and Workflows (read/write), and GEMINI_API_KEY in the
environment to distribute. PRG_REF pins the reusable workflow ref the callers use.

Per repo, in this order (so no repo ever requires a check that cannot run):
  1. settings   squash-only, delete merged branches, auto-merge on
  2. secret     GEMINI_API_KEY present (value is never compared or printed)
  3. caller     .github/workflows/pr-guardian.yml current on the default branch,
                delivered through a PR, never a direct push
  4. ruleset    "main-via-pr" on the default branch, empty bypass list, only
                once the caller is on the default branch

Empty repos (no default branch) get settings + secret only; the ruleset waits
for the first commit. Exit 0 = no drift left, 1 = drift remains (or dry run
found drift), 2 = errors.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

import gh

ROOT = Path(__file__).resolve().parent.parent
CALLER_PATH = ".github/workflows/pr-guardian.yml"
INSTALL_BRANCH = "pr-guardian/install"
RULESET_NAME = "main-via-pr"
VERDICT_CONTEXT = "pr-guardian/verdict"
ACTIONS_APP_ID = 15368
SECRET = "GEMINI_API_KEY"
HOME_REPO = "pr-guardian"

SETTINGS = {"allow_squash_merge": True, "allow_merge_commit": False, "allow_rebase_merge": False,
            "delete_branch_on_merge": True, "allow_auto_merge": True}


def desired_ruleset() -> dict[str, Any]:
    return {
        "name": RULESET_NAME, "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
            {"type": "pull_request", "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": False,
                "require_last_push_approval": False,
                "required_review_thread_resolution": True,
                "allowed_merge_methods": ["squash"]}},
            {"type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": False,
                "do_not_enforce_on_create": False,
                "required_status_checks": [{"context": VERDICT_CONTEXT, "integration_id": ACTIONS_APP_ID}]}},
        ],
    }


def _norm_rules(rules: list[dict[str, Any]]) -> list[tuple[str, str]]:
    return sorted((r["type"], json.dumps(r.get("parameters", {}), sort_keys=True)) for r in rules)


def ruleset_drift(existing: dict[str, Any] | None) -> list[str]:
    want = desired_ruleset()
    if existing is None:
        return ["ruleset missing"]
    out = []
    for key in ("enforcement", "target", "conditions", "bypass_actors"):
        if existing.get(key) != want[key]:
            out.append(f"ruleset {key} differs")
    have = {t: p for t, p in _norm_rules(existing.get("rules", []))}
    for t, p in _norm_rules(want["rules"]):
        if t not in have:
            out.append(f"ruleset rule {t} missing")
        elif _subset_mismatch(json.loads(p), json.loads(have[t])):
            out.append(f"ruleset rule {t} differs")
    return out


def _subset_mismatch(want: Any, have: Any) -> bool:
    """GitHub echoes extra defaulted fields; only the fields we set must match."""
    if isinstance(want, dict):
        return not isinstance(have, dict) or any(_subset_mismatch(v, have.get(k)) for k, v in want.items())
    if isinstance(want, list) and want and isinstance(want[0], dict):
        return not isinstance(have, list) or len(want) != len(have) or any(
            _subset_mismatch(w, h) for w, h in zip(want, have))
    return want != have


def settings_drift(repo: dict[str, Any]) -> list[str]:
    """`repo` must come from GET repos/{full}: the list endpoints omit the merge settings."""
    return [f"setting {k}={repo.get(k)}" for k, v in SETTINGS.items() if repo.get(k) != v]


def render_caller(ref: str) -> str:
    return (ROOT / "templates" / "pr-guardian.yml").read_text(encoding="utf-8").replace("{{REF}}", ref)


# --- GitHub reads -------------------------------------------------------------

def list_repos(owner: str) -> list[dict[str, Any]]:
    repos = gh.api("user/repos?affiliation=owner&per_page=100", paginate=True)
    return sorted((r for r in repos if r["owner"]["login"] == owner and not r["fork"] and not r["archived"]),
                  key=lambda r: r["name"])


def file_on_branch(full: str, path: str, ref: str) -> str | None:
    try:
        data = gh.api(f"repos/{full}/contents/{path}?ref={ref}")
    except gh.GhError as exc:
        if "404" in str(exc) or "Not Found" in str(exc):
            return None
        raise
    return base64.b64decode(data["content"]).decode("utf-8")


def find_ruleset(full: str) -> dict[str, Any] | None:
    for rs in gh.api(f"repos/{full}/rulesets?includes_parents=false", paginate=True) or []:
        if rs["name"] == RULESET_NAME:
            return gh.api(f"repos/{full}/rulesets/{rs['id']}")
    return None


def has_secret(full: str) -> bool:
    names = json.loads(gh._run(["secret", "list", "-R", full, "--json", "name"]))
    return any(n["name"] == SECRET for n in names)


# --- reconcile ------------------------------------------------------------------

def deliver_caller(full: str, default: str, content: str) -> str:
    """Open (or refresh) the install PR and queue it to merge. Returns a status note."""
    head = gh.api(f"repos/{full}/git/ref/heads/{default}")["object"]["sha"]
    try:
        gh.api(f"repos/{full}/git/refs", "POST", {"ref": f"refs/heads/{INSTALL_BRANCH}", "sha": head})
    except gh.GhError:
        gh.api(f"repos/{full}/git/refs/heads/{INSTALL_BRANCH}", "PATCH", {"sha": head, "force": True})
    body = {"message": "ci: install pr-guardian review gate", "branch": INSTALL_BRANCH,
            "content": base64.b64encode(content.encode()).decode()}
    try:
        current = gh.api(f"repos/{full}/contents/{CALLER_PATH}?ref={INSTALL_BRANCH}")
        body["sha"] = current["sha"]
    except gh.GhError:
        pass
    gh.api(f"repos/{full}/contents/{CALLER_PATH}", "PUT", body)

    prs = gh.api(f"repos/{full}/pulls?head={full.split('/')[0]}:{INSTALL_BRANCH}&state=open")
    if prs:
        number = prs[0]["number"]
    else:
        number = gh.api(f"repos/{full}/pulls", "POST", {
            "title": "ci: install pr-guardian review gate", "head": INSTALL_BRANCH, "base": default,
            "body": "Adds the caller for the pr-guardian reusable review workflow. Every PR to "
                    f"`{default}` gets an automated code and security review, and the "
                    f"`{VERDICT_CONTEXT}` status gates merging.\n\nOpened by the pr-guardian governor."})["number"]
    try:
        gh._run(["pr", "merge", str(number), "-R", full, "--squash", "--auto"])
        return f"caller PR #{number} queued for auto-merge"
    except gh.GhError:
        # No ruleset yet means nothing to wait for; auto-merge refuses, so merge now.
        gh._run(["pr", "merge", str(number), "-R", full, "--squash", "--delete-branch"])
        return f"caller PR #{number} merged"


def reconcile(repo: dict[str, Any], ref: str, dry: bool, have_key: bool) -> dict[str, Any]:
    full, default = repo["full_name"], repo.get("default_branch") or ""
    out: dict[str, Any] = {"repo": full, "drift": [], "done": [], "errors": []}

    def step(name: str, drift: list[str], fix) -> None:
        out["drift"] += drift
        if drift and not dry:
            try:
                note = fix()
                out["done"].append(note or name)
            except gh.GhError as exc:
                out["errors"].append(f"{name}: {exc}")

    step("settings", settings_drift(gh.api(f"repos/{full}")),
         lambda: gh.api(f"repos/{full}", "PATCH", SETTINGS) and "settings applied")

    if have_key:
        missing = [] if has_secret(full) else ["secret missing"]
        step("secret", missing,
             lambda: gh._run(["secret", "set", SECRET, "-R", full], stdin=os.environ[SECRET]) and "secret set")
    else:
        out["errors"].append(f"{SECRET} not in governor env; secret step skipped")

    empty = repo.get("size", 0) == 0
    if empty or not default:
        out["drift"].append("empty repo: caller and ruleset wait for the first commit")
        return out

    want = render_caller(ref)
    have = file_on_branch(full, CALLER_PATH, default)
    caller_drift = [] if have == want else ["caller missing" if have is None else "caller stale"]
    step("caller", caller_drift, lambda: deliver_caller(full, default, want))
    caller_live = have is not None or any("merged" in d for d in out["done"])

    if not caller_live:
        out["drift"].append("ruleset deferred until the caller is on the default branch")
        return out
    existing = find_ruleset(full)

    def fix_ruleset() -> str:
        if existing:
            gh.api(f"repos/{full}/rulesets/{existing['id']}", "PUT", desired_ruleset())
            return "ruleset updated"
        gh.api(f"repos/{full}/rulesets", "POST", desired_ruleset())
        return "ruleset created"

    step("ruleset", ruleset_drift(existing), fix_ruleset)
    return out


def report(results: list[dict[str, Any]], dry: bool) -> str:
    rows = ["| repo | drift | done | errors |", "|---|---|---|---|"]
    for r in results:
        if r["drift"] or r["errors"]:
            rows.append(f"| {r['repo']} | {'; '.join(r['drift']) or '—'} | "
                        f"{'; '.join(r['done']) or '—'} | {'; '.join(r['errors']) or '—'} |")
    clean = sum(1 for r in results if not r["drift"] and not r["errors"])
    head = f"**{'Dry run' if dry else 'Run'}**: {len(results)} repos, {clean} clean.\n\n"
    return head + ("\n".join(rows) if len(rows) > 2 else "No drift.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--repos", help="comma-separated repo names (default: all owned)")
    ap.add_argument("--batch", type=int, default=0)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--report-issue", action="store_true")
    args = ap.parse_args()

    owner = os.environ.get("PRG_OWNER") or gh.api("user")["login"]
    ref = os.environ.get("PRG_REF", "v1")
    repos = list_repos(owner)
    if args.repos:
        wanted = set(args.repos.split(","))
        repos = [r for r in repos if r["name"] in wanted]
    repos = repos[args.offset:]
    if args.batch:
        repos = repos[:args.batch]

    have_key = bool(os.environ.get(SECRET))
    results = []
    for repo in repos:
        try:
            results.append(reconcile(repo, ref, args.dry_run, have_key))
        except gh.GhError as exc:
            results.append({"repo": repo["full_name"], "drift": [], "done": [], "errors": [str(exc)]})
        r = results[-1]
        print(f"{r['repo']}: drift={len(r['drift'])} done={r['done']} errors={len(r['errors'])}", file=sys.stderr)

    text = report(results, args.dry_run)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text(text + "\n", encoding="utf-8")
    if args.report_issue:
        title = "Governor drift report"
        # Match on title: the label is dropped silently when the token cannot label issues.
        issues = gh.api(f"repos/{owner}/{HOME_REPO}/issues?state=open&creator={owner}", paginate=True)
        existing = min((i for i in issues if i["title"] == title and "pull_request" not in i),
                       key=lambda i: i["number"], default=None)
        if existing:
            gh.api(f"repos/{owner}/{HOME_REPO}/issues/{existing['number']}", "PATCH", {"body": text})
        else:
            gh.api(f"repos/{owner}/{HOME_REPO}/issues", "POST",
                   {"title": title, "body": text, "labels": ["governor"]})

    if any(r["errors"] for r in results):
        return 2
    remaining = [r for r in results if r["drift"] and (args.dry_run or not r["done"])]
    return 1 if remaining else 0


if __name__ == "__main__":
    sys.exit(main())
