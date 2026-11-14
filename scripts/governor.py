#!/usr/bin/env python3
"""Reconcile every owned repo to the PR-only + pr-guardian baseline.

Usage:
  governor.py [--dry-run] [--repos a,b,c] [--batch N] [--offset N] [--report-issue]
              [--rotate-secrets] [--dependabot-secrets] [--canary a,b] [--exempt a,b]
              [--promote] [--stats] [--allow-unmerged-ref]

Needs GH_TOKEN = a fine-grained PAT on all repos with Administration, Secrets,
Contents, Pull requests and Workflows (read/write) (plus Dependabot secrets
read/write when --dependabot-secrets is set), and GEMINI_API_KEY in the
environment to distribute (ANTHROPIC_API_KEY is optional and distributed when
present in the env). PRG_REF pins the reusable workflow ref the callers use
(must be a 40-hex commit SHA on pr-guardian's default branch, so the publish job
can exempt the caller rollout PR from its workflow tripwire).
PRG_VERDICT_APP_ID optionally overrides the app id the ruleset pins
pr-guardian/verdict to (default 15368, GitHub Actions; GHSA-v7qp-pmhq-cf47).

Repos with topic `pr-guardian-exempt` (or in --exempt) are skipped untouched.
Repos with topic `pr-guardian-canary` (or in --canary) prove a new PRG_REF
before the rest of the fleet upgrades (bypass with --promote).

Per repo, in this order (so no repo ever requires a check that cannot run):
  1. settings   squash-only, delete merged branches, auto-merge on
  2. secret     GEMINI_API_KEY required, ANTHROPIC_API_KEY when present in the env
                (values are never compared or printed; --dependabot-secrets also
                provisions Dependabot secrets)
  3. caller     .github/workflows/pr-guardian.yml current on the default branch,
                delivered through a PR, never a direct push
  4. ruleset    "main-via-pr" on the default branch, empty bypass list, only
                once the caller is on the default branch

Empty repos (no default branch) get settings + secret only; the ruleset waits
for the first commit. Exit 0 = no drift left, 1 = drift remains unresolved; empty
and exempt repos do not count (or dry run found drift), 2 = errors or invalid config.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
from datetime import datetime, timezone
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Sequence

import gh
import state as st
from textsafe import inline

ROOT = Path(__file__).resolve().parent.parent
CALLER_PATH = ".github/workflows/pr-guardian.yml"
INSTALL_BRANCH = "pr-guardian/install"
RULESET_NAME = "main-via-pr"
VERDICT_CONTEXT = "pr-guardian/verdict"
ACTIONS_APP_ID = 15368
APP_ID_RE = re.compile(r"\A[1-9][0-9]*\Z")
REF_RE = re.compile(r"\A[0-9a-f]{40}\Z")  # same grammar as publish_review.SHA_RE
PIN_RE = re.compile(r"/\.github/workflows/review\.yml@([0-9A-Za-z._/-]{1,100})")
SECRETS = (("GEMINI_API_KEY", True), ("ANTHROPIC_API_KEY", False))  # (name, required)
SECRET = SECRETS[0][0]  # kept: main() and existing tests use g.SECRET
HOME_REPO = "pr-guardian"
STUCK_DAYS = 2
CANARY_TOPIC = "pr-guardian-canary"
EXEMPT_TOPIC = "pr-guardian-exempt"
STATS_PR_CAP = 50
REPORT_CAP = 60_000
_TRUNC_NOTE = "\n\n_Report truncated._"

SETTINGS = {"allow_squash_merge": True, "allow_merge_commit": False, "allow_rebase_merge": False,
            "delete_branch_on_merge": True, "allow_auto_merge": True}


@dataclasses.dataclass
class Install:
    """What is already open for the caller rollout. Built from reads only."""

    pr: dict[str, Any] | None = None
    text: str | None = None
    blob: str | None = None
    caller_only: bool = False
    current: bool = False
    blockers: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Delivery:
    """Outcome of delivering the caller workflow to a governed repo."""

    note: str
    merged: bool


@dataclasses.dataclass
class Config:
    """Run-wide reconciliation options and read cache passed into reconcile()."""

    rotate: bool = False
    dependabot: bool = False
    canaries: frozenset[str] = frozenset()
    held: bool = False
    hold_reason: str = ""
    now: datetime | None = None
    caller_cache: dict[str, str | None] = dataclasses.field(default_factory=dict)


def _exc(exc: Exception) -> str:
    if isinstance(exc, gh.GhError):
        return str(exc)[:500]
    return f"{type(exc).__name__}: {str(exc)[:300]}"


def _blank(full: str) -> dict[str, Any]:
    return {
        "repo": full,
        "drift": [],
        "done": [],
        "errors": [],
        "pending": [],
        "waiting": [],
        "info": [],
        "optional": [],
        "pinned": "",
    }


def _names(csv: str | None) -> set[str]:
    return {x.strip() for x in (csv or "").split(",") if x.strip()}


def _env_flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() == "true"


def _cell(text: Any) -> str:
    return inline(text)[:400].replace("|", "\\|")


def _short_ref(ref: str) -> str:
    if not ref:
        return "—"
    return ref[:7] if REF_RE.match(ref) else _cell(ref)[:20]


def pinned_ref(text: str | None) -> str:
    m = PIN_RE.search(text or "")
    return m.group(1) if m else ""


def verdict_app_id() -> int:
    """The integration the ruleset requires pr-guardian/verdict from.

    PRG_VERDICT_APP_ID unset or blank keeps GitHub Actions (15368), which any workflow in
    the repo shares (GHSA-v7qp-pmhq-cf47); set it only once a dedicated app posts the
    verdict, or every governed PR waits on a status nobody sends. Raises ValueError on
    anything but a positive ASCII integer.
    """
    raw = (os.environ.get("PRG_VERDICT_APP_ID") or "").strip()
    if not raw:
        return ACTIONS_APP_ID
    if not APP_ID_RE.match(raw):
        raise ValueError(f"PRG_VERDICT_APP_ID={raw[:40]!r} is not a positive integer app id")
    return int(raw)


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
                "required_status_checks": [{"context": VERDICT_CONTEXT, "integration_id": verdict_app_id()}]}},
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


def repo_topics(repo: dict[str, Any]) -> set[str]:
    """Topics from the list payload; one GET when the payload has no topics key at all."""
    t = repo.get("topics")
    if "topics" not in repo:
        resp = gh.api(f"repos/{repo['full_name']}/topics")
        t = resp.get("names") if isinstance(resp, dict) else None
    return {x for x in t if isinstance(x, str)} if isinstance(t, list) else set()


def _file_with_sha(full: str, path: str, ref: str) -> tuple[str | None, str | None]:
    try:
        data = gh.api(f"repos/{full}/contents/{path}?ref={urllib.parse.quote(ref, safe='')}")
    except gh.GhError as exc:
        if "404" in str(exc) or "Not Found" in str(exc):
            return None, None
        raise
    if not (isinstance(data, dict) and data.get("type") == "file"
            and data.get("encoding") == "base64" and isinstance(data.get("content"), str)):
        raise gh.GhError(f"{path} at {ref} is not a regular file (directory, symlink, submodule or over 1 MB)")
    try:
        text = base64.b64decode(data["content"]).decode("utf-8")
    except (binascii.Error, ValueError) as exc:
        raise gh.GhError(f"{path} at {ref} is not UTF-8 text: {exc}") from None
    sha = data.get("sha") if isinstance(data.get("sha"), str) else None
    return text, sha


def file_on_branch(full: str, path: str, ref: str) -> str | None:
    text, _ = _file_with_sha(full, path, ref)
    return text


def caller_blob(full: str, branch: str) -> tuple[str | None, str | None]:
    return _file_with_sha(full, CALLER_PATH, branch)


def find_ruleset(full: str) -> dict[str, Any] | None:
    for rs in gh.api(f"repos/{full}/rulesets?includes_parents=false", paginate=True) or []:
        if rs["name"] == RULESET_NAME:
            return gh.api(f"repos/{full}/rulesets/{rs['id']}")
    return None


def has_branch(full: str, branch: str) -> bool:
    # size counts uploaded objects, so a repo with no refs can still report a size.
    if not branch:
        return False
    try:
        gh.api(f"repos/{full}/branches/{urllib.parse.quote(branch, safe='/')}")
        return True
    except gh.GhError as exc:
        if "404" in str(exc) or "409" in str(exc):
            return False
        raise


def secret_names(full: str, app: str = "actions") -> set[str]:
    args = ["secret", "list", "-R", full, "--json", "name"]
    if app != "actions":
        args += ["--app", app]
    data = json.loads(gh._run(args))
    return {n["name"] for n in data if isinstance(n, dict) and isinstance(n.get("name"), str)}


def set_secret(full: str, name: str, value: str, app: str = "actions") -> None:
    args = ["secret", "set", name, "-R", full]
    if app != "actions":
        args += ["--app", app]
    gh._run(args, stdin=value)  # value on stdin only: never argv, never printed


def has_secret(full: str) -> bool:  # kept for compatibility
    return SECRET in secret_names(full)


# --- Ref and canary gates -----------------------------------------------------

def _check_ref(owner: str, ref: str) -> tuple[str | None, bool]:
    """Return (problem, unmerged_only). unmerged_only=True iff commit exists but is not on default."""
    home = f"{owner}/{HOME_REPO}"
    try:
        commit = gh.api(f"repos/{home}/commits/{ref}")
        if not (isinstance(commit, dict) and commit.get("sha") == ref):
            return f"PRG_REF {ref[:12]} is not a commit in {home}", False
        repo_info = gh.api(f"repos/{home}")
        default = repo_info["default_branch"]
        if not isinstance(default, str) or not default:
            raise gh.GhError(f"{home} has no default_branch")
        cmp = gh.api(f"repos/{home}/compare/{ref}...{urllib.parse.quote(default, safe='/')}")
    except (gh.GhError, KeyError, TypeError) as exc:
        return f"PRG_REF {ref[:12]} could not be verified in {home}: {_exc(exc)}", False
    if not isinstance(cmp, dict) or cmp.get("status") not in ("ahead", "identical"):
        status = cmp.get("status") if isinstance(cmp, dict) else "?"
        return f"PRG_REF {ref[:12]} is not on {home}@{default} (compare status {status})", True
    return None, False


def verify_ref(owner: str, ref: str) -> str | None:
    """None when ref is a commit on pr-guardian's default branch, else the problem."""
    problem, _ = _check_ref(owner, ref)
    return problem


def canary_proof(repo: dict[str, Any], ref: str, want: str, cache: dict[str, str | None]) -> tuple[bool, str]:
    """(proven, why). Proven = the canary's default branch carries the caller for `ref` and
    the install PR that delivered it got a success verdict from GitHub Actions on its head."""
    full, default = repo["full_name"], repo.get("default_branch") or ""
    if not has_branch(full, default):
        return False, "empty repo"
    have = cache[full] = file_on_branch(full, CALLER_PATH, default)
    if have != want:
        return False, "caller not on the new ref yet"
    owner = full.split("/")[0]
    prs = gh.api(f"repos/{full}/pulls?state=closed&head={owner}:{INSTALL_BRANCH}"
                 "&sort=updated&direction=desc&per_page=10") or []
    merged = [p for p in prs if isinstance(p, dict) and p.get("merged_at")]
    if not merged:
        return False, "no merged install PR"
    sha = merged[0]["head"]["sha"]
    if file_on_branch(full, CALLER_PATH, sha) != want:
        return False, f"install PR #{merged[0]['number']} delivered another ref"
    statuses = gh.api(f"repos/{full}/commits/{sha}/statuses?per_page=100") or []
    verdict = next((s for s in statuses if isinstance(s, dict) and s.get("context") == VERDICT_CONTEXT), None)
    if not verdict:
        return False, f"no {VERDICT_CONTEXT} on install PR #{merged[0]['number']}"
    by = (verdict.get("creator") or {}).get("login")
    # Phase 2 (#50): the verdict app's login when PRG_VERDICT_APP_ID overrides Actions.
    if verdict.get("state") != "success" or by != "github-actions[bot]":
        return False, f"{VERDICT_CONTEXT} is {verdict.get('state')} on install PR #{merged[0]['number']}"
    return True, f"install PR #{merged[0]['number']} passed"


def _safe_proof(repo: dict[str, Any], ref: str, want: str, cache: dict[str, str | None]) -> tuple[bool, str]:
    try:
        return canary_proof(repo, ref, want, cache)
    except Exception as exc:  # noqa: BLE001
        return False, _exc(exc)


def canary_gate(repos: list[dict[str, Any]], canaries: set[str] | frozenset[str],
                ref: str, want: str, promote: bool, cache: dict[str, str | None]) -> tuple[bool, str]:
    """(held, reason). held=True keeps the caller off non-canary repos this run."""
    ring = [r for r in repos if r["name"] in canaries]
    if not ring:
        return False, "no canary ring"
    if promote:
        return False, "promoted explicitly"
    proofs = {r["name"]: _safe_proof(r, ref, want, cache) for r in ring}
    if all(ok for ok, _ in proofs.values()):
        return False, f"canary ring proven ({len(ring)}/{len(ring)})"
    for r in repos:  # an earlier promotion leaves this trace so new repos are not held
        if r["name"] in canaries:
            continue
        full, default = r["full_name"], r.get("default_branch") or ""
        if full not in cache:
            try:
                cache[full] = file_on_branch(full, CALLER_PATH, default) if default else None
            except Exception:  # noqa: BLE001
                continue  # leave uncached: reconcile() reads it again and records the error
        if cache[full] == want:
            return False, f"ref already promoted (seen on {r['name']})"
    waiting = "; ".join(f"{n}: {why}" for n, (ok, why) in sorted(proofs.items()) if not ok)
    return True, f"waiting on {waiting}"[:300]


# --- Install PR inspection & delivery -----------------------------------------

def classic_protection(full: str, default: str) -> list[str]:
    """Classic branch protection that can block the install PR. [] when there is none."""
    try:
        p = gh.api(f"repos/{full}/branches/{urllib.parse.quote(default, safe='/')}/protection")
    except gh.GhError as exc:
        if "404" in str(exc) or "not protected" in str(exc).lower():
            return []
        return [f"classic branch protection on {default} could not be read"]
    if not isinstance(p, dict):
        return []
    out = []
    n = (p.get("required_pull_request_reviews") or {}).get("required_approving_review_count") or 0
    if n:
        out.append(f"classic protection on {default} requires {n} approving review(s); "
                   "approve the install PR or move the branch to the ruleset")
    rsc = p.get("required_status_checks") or {}
    checks = rsc.get("contexts") or []
    if not checks and isinstance(rsc.get("checks"), list):
        checks = [c.get("context") for c in rsc["checks"] if isinstance(c, dict)]
    other = [c for c in checks if isinstance(c, str) and c != VERDICT_CONTEXT]
    if other:
        out.append(f"classic protection on {default} requires checks: {', '.join(sorted(other))[:200]}")
    if (p.get("restrictions") or None) is not None:
        out.append(f"classic protection on {default} restricts who can push")
    return out


def _open_install_prs(full: str, default: str) -> list[dict[str, Any]]:
    owner = full.split("/")[0]
    prs = gh.api(f"repos/{full}/pulls?head={owner}:{INSTALL_BRANCH}&state=open&per_page=10") or []
    return [
        p for p in prs
        if isinstance(p, dict)
        and (p.get("base") or {}).get("ref") == default
        and (p.get("head") or {}).get("ref") == INSTALL_BRANCH
        and ((p.get("head") or {}).get("repo") or {}).get("full_name") == full
    ]


def inspect_install(full: str, default: str, content: str, now: datetime | None = None) -> Install:
    """Inspect any open install PR and blocking protections. Reads only."""
    matches = _open_install_prs(full, default)
    if not matches:
        return Install()
    n = matches[0]["number"]
    detail = gh.api(f"repos/{full}/pulls/{n}")
    if not isinstance(detail, dict):
        raise gh.GhError(f"pulls/{n}: expected object, got {type(detail).__name__}")
    caller_only = False
    if detail.get("changed_files") == 1:
        files = gh.pr_files(full, n)
        caller_only = [f["filename"] for f in files] == [CALLER_PATH] and not files[0].get("previous_filename")
    text, blob = caller_blob(full, INSTALL_BRANCH)
    current = text == content and caller_only
    blockers: list[str] = []
    ref_now = now or datetime.now(timezone.utc)
    if ref_now.tzinfo is None:
        ref_now = ref_now.replace(tzinfo=timezone.utc)
    created_raw = detail.get("created_at")
    if isinstance(created_raw, str) and created_raw:
        created_at = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        age = (ref_now - created_at).days
        if age >= STUCK_DAYS:
            state = detail.get("mergeable_state") or "unknown"
            blockers.append(f"install PR #{n} open {age}d, merge state {state}")
    blockers.extend(classic_protection(full, default))
    return Install(pr=detail, text=text, blob=blob, caller_only=caller_only,
                   current=current, blockers=blockers)


def _merge_install_pr(full: str, number: int, head: str) -> Delivery:
    match = ["--match-head-commit", head]
    try:
        gh._run(["pr", "merge", str(number), "-R", full, "--squash", "--auto", *match])
        return Delivery(f"caller PR #{number} queued for auto-merge", merged=False)
    except gh.GhError:
        # No ruleset yet means nothing to wait for; auto-merge refuses, so merge now.
        gh._run(["pr", "merge", str(number), "-R", full, "--squash", "--delete-branch", *match])
        return Delivery(f"caller PR #{number} merged", merged=True)


def _put_caller(full: str, content: str, blob: str | None) -> str:
    body: dict[str, Any] = {
        "message": "ci: install pr-guardian review gate",
        "branch": INSTALL_BRANCH,
        "content": base64.b64encode(content.encode()).decode(),
    }
    if blob:
        body["sha"] = blob
    put = gh.api(f"repos/{full}/contents/{CALLER_PATH}", "PUT", body)
    return put["commit"]["sha"]


def deliver_caller(full: str, default: str, content: str, inst: Install | None = None) -> Delivery:
    """Idempotently update/open the install PR and queue or complete its merge."""
    inst = inst or inspect_install(full, default, content)
    if inst.pr and inst.current and inst.pr.get("auto_merge"):
        return Delivery(f"caller PR #{inst.pr['number']} waiting (auto-merge queued)", merged=False)
    if inst.pr and inst.current:
        return _merge_install_pr(full, inst.pr["number"], inst.pr["head"]["sha"])
    if inst.pr and inst.caller_only:
        head = _put_caller(full, content, inst.blob)
        return _merge_install_pr(full, inst.pr["number"], head)

    base_sha = gh.api(f"repos/{full}/git/ref/heads/{urllib.parse.quote(default, safe='/')}")["object"]["sha"]
    try:
        gh.api(f"repos/{full}/git/refs", "POST", {"ref": f"refs/heads/{INSTALL_BRANCH}", "sha": base_sha})
    except gh.GhError:
        gh.api(f"repos/{full}/git/refs/heads/{INSTALL_BRANCH}", "PATCH", {"sha": base_sha, "force": True})
    _, blob = caller_blob(full, INSTALL_BRANCH)
    head = _put_caller(full, content, blob)

    # A force-reset closes any foreign-content PR on GitHub; re-check before opening.
    prs = _open_install_prs(full, default) if inst.pr else []
    if prs:
        number = prs[0]["number"]
    else:
        number = gh.api(f"repos/{full}/pulls", "POST", {
            "title": "ci: install pr-guardian review gate", "head": INSTALL_BRANCH, "base": default,
            "body": "Adds the caller for the pr-guardian reusable review workflow. Every PR to "
                    f"`{default}` gets an automated code and security review, and the "
                    f"`{VERDICT_CONTEXT}` status gates merging.\n\nOpened by the pr-guardian governor."})["number"]
    return _merge_install_pr(full, number, head)


# --- reconcile ----------------------------------------------------------------

def _reconcile_secrets(full: str, dry: bool, have_key: bool, cfg: Config,
                       out: dict[str, Any], step: Callable[..., Any]) -> None:
    if not have_key:
        out["errors"].append(f"{SECRET} not in governor env; secret step skipped")
        return
    apps = ("actions", "dependabot") if cfg.dependabot else ("actions",)
    for app in apps:
        prefix = "" if app == "actions" else f"{app} "
        try:
            names = secret_names(full, app)
        except Exception as exc:  # noqa: BLE001
            out["errors"].append(f"{prefix}secret list: {_exc(exc)}")
            continue
        for name, required in SECRETS:
            value = os.environ.get(name) or ""
            label = f"{prefix}secret {name}"
            if not value:
                if not required and app == "actions" and name not in names:
                    out["optional"].append(name)
                continue
            if name not in names:
                step(label, [f"{label} missing"],
                     lambda n=name, v=value, a=app, lab=label: set_secret(full, n, v, a) or f"{lab} set")
            elif cfg.rotate and dry:
                out["info"].append(f"would rotate {label}")
            elif cfg.rotate:
                try:
                    set_secret(full, name, value, app)
                    out["done"].append(f"{label} rotated")
                except Exception as exc:  # noqa: BLE001
                    out["errors"].append(f"{label}: {_exc(exc)}")


def _reconcile_ruleset(full: str, step: Callable[..., Any]) -> None:
    existing = find_ruleset(full)

    def fix_ruleset() -> str:
        if existing:
            gh.api(f"repos/{full}/rulesets/{existing['id']}", "PUT", desired_ruleset())
            return "ruleset updated"
        gh.api(f"repos/{full}/rulesets", "POST", desired_ruleset())
        return "ruleset created"

    step("ruleset", ruleset_drift(existing), fix_ruleset)


def reconcile(repo: dict[str, Any], ref: str, dry: bool, have_key: bool,
              cfg: Config | None = None) -> dict[str, Any]:
    cfg = cfg or Config()
    full, default = repo["full_name"], repo.get("default_branch") or ""
    out = _blank(full)

    def step(name: str, drift: list[str], fix: Callable[[], Any]) -> Any:
        """Record drift; in apply mode run fix(). fix() returns a note, or (note, resolved)."""
        out["drift"] += drift
        if not drift:
            return None
        if dry:
            out["pending"] += drift
            return None
        try:
            res = fix()
        except Exception as exc:  # noqa: BLE001  (#28: TimeoutExpired, KeyError, JSON errors)
            out["errors"].append(f"{name}: {_exc(exc)}")
            out["pending"] += drift
            return None
        note, resolved = res if isinstance(res, tuple) else (res, True)
        out["done"].append(note or name)
        if not resolved:
            out["pending"] += drift
        return res

    step("settings", settings_drift(gh.api(f"repos/{full}")),
         lambda: gh.api(f"repos/{full}", "PATCH", SETTINGS) and "settings applied")

    _reconcile_secrets(full, dry, have_key, cfg, out, step)

    if not has_branch(full, default):  # has_branch("") is already False
        out["waiting"].append("empty repo: caller and ruleset wait for the first commit")
        return out

    want = render_caller(ref)
    have = cfg.caller_cache[full] if full in cfg.caller_cache else file_on_branch(full, CALLER_PATH, default)
    out["pinned"] = pinned_ref(have)
    caller_drift = [] if have == want else ["caller missing" if have is None else "caller stale"]
    merged = False
    if caller_drift and cfg.held and repo["name"] not in cfg.canaries:
        out["drift"] += caller_drift
        out["pending"] += [f"{caller_drift[0]}: held for the canary ring ({cfg.hold_reason})"]
    elif caller_drift:
        try:
            inst = inspect_install(full, default, want, now=cfg.now)
        except Exception as exc:  # noqa: BLE001
            out["drift"] += caller_drift
            out["pending"] += caller_drift
            out["errors"].append(f"caller: {_exc(exc)}")
        else:
            res = step("caller", caller_drift,
                       lambda: (lambda d: (d.note, d.merged))(deliver_caller(full, default, want, inst)))
            merged = bool(res and res[1])
            if not merged:
                out["pending"] += inst.blockers

    caller_live = have is not None or merged
    if not caller_live:
        msg = "ruleset deferred until the caller is on the default branch"
        out["drift"].append(msg)
        out["pending"].append(msg)
        return out

    _reconcile_ruleset(full, step)
    return out


# --- Fleet stats & reporting --------------------------------------------------

def _repo_stats(full: str) -> tuple[int, int, int, int, float, int, int]:
    prs = (gh.api(f"repos/{full}/pulls?state=open&per_page=100", paginate=True) or [])[:STATS_PR_CAP]
    if not prs:
        return (0, 0, 0, 0, 0.0, 0, 0)
    reviewed = rounds_sum = rounds_max = needs_human = open_blocking = 0
    cost = 0.0
    for pr in prs:
        labels = pr.get("labels") or []
        if any(isinstance(lb, dict) and lb.get("name") == "needs-human" for lb in labels):
            needs_human += 1
        comments = gh.api(f"repos/{full}/issues/{pr['number']}/comments?per_page=100", paginate=True) or []
        summary = st.find_summary_comment(comments)
        decoded = st.decode(summary["body"]) if summary else None
        if not decoded:
            continue
        reviewed += 1
        rnd = decoded.get("round")
        if isinstance(rnd, int) and not isinstance(rnd, bool):
            rounds_sum += rnd
            rounds_max = max(rounds_max, rnd)
        for c in decoded.get("cost_usd") or []:
            if isinstance(c, (int, float)) and not isinstance(c, bool):
                cost += float(c)
        for f in decoded.get("findings") or []:
            if isinstance(f, dict) and f.get("severity") != "nit" and f.get("status") not in ("fixed", "accepted_pushback"):
                open_blocking += 1
    return (len(prs), reviewed, rounds_sum, rounds_max, cost, needs_human, open_blocking)


def fleet_stats(results_repos: list[dict[str, Any]]) -> str:
    """Markdown section: open PRs with pr-guardian state, per repo. Reads only."""
    eligible = [r["repo"] for r in results_repos if not r.get("errors") and r.get("pinned")]
    if not eligible:
        return "## Fleet stats\n\nNo repos with callers."
    rows: list[str] = []
    tot_open = tot_rev = tot_rounds = tot_max = tot_human = tot_blocking = zero_open = 0
    tot_cost = 0.0
    for full in eligible:
        try:
            open_n, rev, r_sum, r_max, cost, human, blocking = _repo_stats(full)
        except Exception as exc:  # noqa: BLE001
            rows.append(f"| {_cell(full)} | {_cell(f'stats unavailable: {_exc(exc)}')} | — | — | — | — | — |")
            continue
        if open_n == 0:
            zero_open += 1
            continue
        tot_open += open_n
        tot_rev += rev
        tot_rounds += r_sum
        tot_max = max(tot_max, r_max)
        tot_cost += cost
        tot_human += human
        tot_blocking += blocking
        rows.append(f"| {_cell(full)} | {open_n} | {rev} | {r_sum} ({r_max}) | {cost:.2f} | {human} | {blocking} |")

    parts = ["## Fleet stats"]
    if rows:
        header = [
            "| repo | open PRs | reviewed | rounds (max) | cost $ | needs-human | open blocking |",
            "|---|---|---|---|---|---|---|",
        ]
        total_row = (f"| **Total** | {tot_open} | {tot_rev} | {tot_rounds} ({tot_max}) "
                     f"| {tot_cost:.2f} | {tot_human} | {tot_blocking} |")
        parts.append("\n".join(header + rows + [total_row]))
    if zero_open:
        parts.append(f"{zero_open} repo{'s' if zero_open != 1 else ''} with no open PRs.")
    return "\n\n".join(parts)


def report(results: list[dict[str, Any]], dry: bool, *, ref: str = "",
           ref_problem: str | None = None, gate: str = "",
           exempt: Sequence[str] = (), stats: str = "") -> str:
    waiting_repos = [r["repo"] for r in results if r.get("waiting")]
    clean = sum(1 for r in results
                if not r["drift"] and not r["pending"] and not r["errors"] and not r.get("waiting"))
    pending_n = sum(1 for r in results if r["pending"])
    err_n = sum(1 for r in results if r["errors"])
    total = len(results) + len(exempt)

    head_bits = [
        f"{total} repos",
        f"{clean} clean",
        f"{pending_n} pending",
        f"{err_n} error{'s' if err_n != 1 else ''}",
    ]
    if waiting_repos:
        head_bits.append(f"{len(waiting_repos)} waiting")
    if exempt:
        head_bits.append(f"{len(exempt)} exempt")
    if ref:
        head_bits.append(f"ref `{_short_ref(ref)}`")
    if gate:
        head_bits.append(f"canary: {inline(gate)[:400]}")

    sections = [f"**{'Dry run' if dry else 'Run'}**: {' · '.join(head_bits)}"]
    if ref_problem:
        sections.append(f"> ⚠️ {inline(ref_problem)[:400]}")

    rows = ["| repo | pinned | drift | done | pending | errors |", "|---|---|---|---|---|---|"]
    for r in results:
        done_items = list(r["done"])
        for info in r.get("info") or ():
            done_items.append(f"(dry run) {info}" if dry else info)
        if r["drift"] or r["pending"] or r["errors"] or r.get("info"):
            pin = f"`{_short_ref(r.get('pinned') or '')}`" if r.get("pinned") else "—"
            rows.append(
                f"| {_cell(r['repo'])} | {pin} | {_cell('; '.join(r['drift'])) or '—'} | "
                f"{_cell('; '.join(done_items)) or '—'} | {_cell('; '.join(r['pending'])) or '—'} | "
                f"{_cell('; '.join(r['errors'])) or '—'} |"
            )
    sections.append("\n".join(rows) if len(rows) > 2 else "No drift.")

    if waiting_repos:
        sections.append(f"<details><summary>Waiting for a first commit ({len(waiting_repos)})</summary>\n\n"
                        f"{', '.join(_cell(x) for x in waiting_repos)}\n\n</details>")
    if exempt:
        sections.append(f"<details><summary>Exempt ({EXEMPT_TOPIC}) ({len(exempt)})</summary>\n\n"
                        f"{', '.join(_cell(x) for x in exempt)}\n\n</details>")

    for name, _ in SECRETS:
        missing_on = [r["repo"] for r in results if name in (r.get("optional") or ())]
        if missing_on:
            shown = [_cell(x) for x in missing_on[:10]]
            more = len(missing_on) - len(shown)
            tail = f", ... (+{more} more)" if more else ""
            sections.append(f"Optional secret `{name}` is not in the governor env and is missing on "
                            f"{len(missing_on)} repo{'s' if len(missing_on) != 1 else ''}: {', '.join(shown)}{tail}")

    if stats:
        sections.append(stats)

    text = "\n\n".join(sections)
    if len(text) > REPORT_CAP:
        limit = REPORT_CAP - len(_TRUNC_NOTE)
        cut = text.rfind("\n", 0, limit + 1)
        text = (text[:cut] if cut > 0 else text[:limit]) + _TRUNC_NOTE
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--repos", help="comma-separated repo names (default: all owned)")
    ap.add_argument("--batch", type=int, default=0)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--report-issue", action="store_true")
    ap.add_argument("--rotate-secrets", action="store_true", default=_env_flag("PRG_ROTATE_SECRETS"))
    ap.add_argument("--dependabot-secrets", action="store_true", default=_env_flag("PRG_DEPENDABOT_SECRETS"))
    ap.add_argument("--canary", default=os.environ.get("PRG_CANARY", ""))
    ap.add_argument("--exempt", default=os.environ.get("PRG_EXEMPT", ""))
    ap.add_argument("--promote", action="store_true", default=_env_flag("PRG_PROMOTE"))
    ap.add_argument("--stats", action="store_true", default=_env_flag("PRG_STATS"))
    ap.add_argument("--allow-unmerged-ref", action="store_true", default=_env_flag("PRG_ALLOW_UNMERGED_REF"))
    args = ap.parse_args()

    try:  # once, before any repo is touched: a bad id must not half-apply a ruleset
        verdict_app_id()
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    ref = (os.environ.get("PRG_REF") or "v1").strip()
    ref_problem = None if REF_RE.match(ref) else (
        f"PRG_REF={ref[:60]!r} is not a 40-hex commit SHA; callers pinned to a tag or branch are "
        "never exempt from the workflow tripwire, so every rollout PR would need human-override")
    if ref_problem and not args.dry_run:
        print(f"::error::{ref_problem}", file=sys.stderr)
        return 2
    if ref_problem:
        print(f"::warning::{ref_problem} (dry run: continuing)", file=sys.stderr)

    owner = os.environ.get("PRG_OWNER") or gh.api("user")["login"]
    if not ref_problem:
        verify_problem, unmerged = _check_ref(owner, ref)
        if verify_problem:
            if not args.dry_run and not (unmerged and args.allow_unmerged_ref):
                print(f"::error::{verify_problem}", file=sys.stderr)
                return 2
            ref_problem = verify_problem
            why = "dry run" if args.dry_run else "--allow-unmerged-ref"
            print(f"::warning::{verify_problem} ({why}: continuing)", file=sys.stderr)

    repos = list_repos(owner)
    fleet_names = {r["name"] for r in repos}
    want_exempt, want_canary = _names(args.exempt), _names(args.canary)
    unknown = sorted((want_exempt | want_canary) - fleet_names)
    if unknown:
        print(f"::error::unknown repo(s) in --canary/--exempt: {', '.join(unknown)}", file=sys.stderr)
        return 2
    try:
        topics_by_name = {r["name"]: repo_topics(r) for r in repos}
    except gh.GhError as exc:
        print(f"::error::could not read repository topics: {_exc(exc)}", file=sys.stderr)
        return 2
    exempt = {name for name, t in topics_by_name.items() if EXEMPT_TOPIC in t} | want_exempt
    canaries = {name for name, t in topics_by_name.items() if CANARY_TOPIC in t} | want_canary
    overlap = sorted(exempt & canaries)
    if overlap:
        print(f"::error::repo(s) cannot be both canary and exempt: {', '.join(overlap)}", file=sys.stderr)
        return 2

    exempt_repos = [r["full_name"] for r in repos if r["name"] in exempt]
    fleet = [r for r in repos if r["name"] not in exempt]
    want = render_caller(ref)
    cache: dict[str, str | None] = {}
    held, gate = canary_gate(fleet, canaries, ref, want, args.promote, cache)

    target = fleet
    if args.repos:
        wanted = _names(args.repos)
        target = [r for r in target if r["name"] in wanted]
    target = target[args.offset:]
    if args.batch:
        target = target[:args.batch]

    cfg = Config(
        rotate=args.rotate_secrets,
        dependabot=args.dependabot_secrets,
        canaries=frozenset(canaries),
        held=held,
        hold_reason=gate if held else "",
        caller_cache=cache,
    )
    have_key = bool(os.environ.get(SECRET))
    results = []
    for repo in target:
        try:
            results.append(reconcile(repo, ref, args.dry_run, have_key, cfg))
        except Exception as exc:  # noqa: BLE001
            r = _blank(repo["full_name"])
            r["errors"].append(_exc(exc))
            results.append(r)
        r = results[-1]
        print(f"{r['repo']}: drift={len(r['drift'])} done={r['done']} errors={len(r['errors'])}", file=sys.stderr)

    stats = fleet_stats(results) if args.stats else ""
    text = report(results, args.dry_run, ref=ref, ref_problem=ref_problem,
                  gate=gate, exempt=exempt_repos, stats=stats)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text(text + "\n", encoding="utf-8")

    partial = bool(args.repos or args.batch or args.offset)
    if args.report_issue and (args.dry_run or partial):
        why = "dry run" if args.dry_run else "partial run (--repos/--batch/--offset)"
        print(f"::notice::drift report issue not updated: {why}", file=sys.stderr)
    elif args.report_issue:
        title = "Governor drift report"
        # The workflow token writes the report, so GOVERNOR_TOKEN needs no Issues access.
        token = os.environ.get("REPORT_TOKEN") or None
        # Match on title and a trusted author: the label is dropped silently when the token
        # cannot label issues, and the report was first opened with the PAT.
        authors = {owner, "github-actions[bot]"}
        issues = gh.api(f"repos/{owner}/{HOME_REPO}/issues?state=open", paginate=True, token=token)
        existing = min((i for i in issues if i["title"] == title and "pull_request" not in i
                        and i["user"]["login"] in authors),
                       key=lambda i: i["number"], default=None)
        if existing:
            gh.api(f"repos/{owner}/{HOME_REPO}/issues/{existing['number']}", "PATCH", {"body": text},
                   token=token)
        else:
            gh.api(f"repos/{owner}/{HOME_REPO}/issues", "POST",
                   {"title": title, "body": text, "labels": ["governor"]}, token=token)

    if any(r["errors"] for r in results):
        return 2
    return 1 if any(r["pending"] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
