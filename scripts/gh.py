"""Thin wrappers over the `gh` CLI. stdlib only, shell=False, no secrets in argv."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from typing import Any


class GhError(RuntimeError):
    def __init__(self, msg: str, *, status: int | None = None, transient: bool = False):
        super().__init__(msg)
        self.status = status
        self.transient = transient


class GhTimeout(GhError):
    def __init__(self, msg: str, *, status: int | None = None, transient: bool = True):
        super().__init__(msg, status=status, transient=transient)


TIMEOUT_S = 120
RETRY_DELAYS = (2.0, 5.0, 10.0)        # 5xx / network / timeout (idempotent calls only)
RATE_LIMIT_DELAYS = (15.0, 30.0)       # 429 / primary or secondary rate limit (any call)
MAX_ELAPSED_S = 240.0                  # never retry past this per call (publish job is 10 min)
_sleep = time.sleep                    # patched in tests
_HTTP_RE = re.compile(r"\(HTTP (\d{3})\)|HTTP (\d{3}):?")
_RATE_RE = re.compile(r"rate limit|HTTP 429|was submitted too quickly|abuse detection", re.I)
_NET_RE = re.compile(
    r"connection (reset|refused)|i/o timeout|TLS handshake timeout|EOF|"
    r"could not resolve host|temporary failure in name resolution",
    re.I,
)
IDEMPOTENT_MUTATIONS = ("resolveReviewThread", "unresolveReviewThread")


def _classify(stderr: str) -> tuple[int | None, str]:
    text = stderr or ""
    m = _HTTP_RE.search(text)
    status = int(m.group(1) or m.group(2)) if m else None
    if status == 429 or _RATE_RE.search(text):
        return status, "rate"
    if status is not None and 500 <= status <= 599:
        return status, "server"
    if status is not None and 400 <= status < 500:
        return status, "fatal"
    if _NET_RE.search(text):
        return status, "network"
    return status, "fatal"


def _run(args: list[str], stdin: str | None = None, token: str | None = None, *,
         idempotent: bool = True) -> str:
    env = {**os.environ, "GH_TOKEN": token} if token else None
    start = time.monotonic()
    attempt = 0
    while True:
        try:
            proc = subprocess.run(
                ["gh", *args], input=stdin, capture_output=True, text=True,
                shell=False, timeout=TIMEOUT_S, env=env,
            )
        except subprocess.TimeoutExpired as exc:
            status, kind = None, "timeout"
            err_msg = f"gh {' '.join(args[:3])}… timed out after {TIMEOUT_S}s"
            timeout_exc: subprocess.TimeoutExpired | None = exc
        else:
            if proc.returncode == 0:
                return proc.stdout
            status, kind = _classify(proc.stderr)
            err_msg = f"gh {' '.join(args[:3])}… failed: {proc.stderr.strip()[:500]}"
            timeout_exc = None

        can_retry = kind == "rate" or (idempotent and kind in ("server", "network", "timeout"))
        delays = RATE_LIMIT_DELAYS if kind == "rate" else RETRY_DELAYS
        if can_retry and attempt < len(delays):
            delay = delays[attempt]
            if (time.monotonic() - start) + delay <= MAX_ELAPSED_S:
                attempt += 1
                print(f"::notice::gh retry {attempt}/{len(delays)} after {kind} ({status})",
                      file=sys.stderr)
                _sleep(delay)
                continue

        if timeout_exc is not None:
            raise GhTimeout(err_msg, status=status, transient=True) from timeout_exc
        raise GhError(err_msg, status=status, transient=kind != "fatal")


def api(path: str, method: str = "GET", body: dict[str, Any] | None = None,
        paginate: bool = False, token: str | None = None, *,
        idempotent: bool | None = None) -> Any:
    args = ["api", path, "-X", method, "-H", "Accept: application/vnd.github+json"]
    if paginate:
        args += ["--paginate", "--slurp"]
    stdin = None
    if body is not None:
        args += ["--input", "-"]
        stdin = json.dumps(body)
    if idempotent is None:
        idempotent = method.upper() in ("GET", "HEAD", "PUT", "PATCH", "DELETE")
    out = _run(args, stdin, token, idempotent=idempotent)
    if not out.strip():
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise GhError(f"gh {' '.join(args[:3])}… returned invalid JSON: {exc}", transient=True) from exc
    if paginate:  # --slurp wraps pages in an outer list
        flat: list[Any] = []
        for page in data:
            flat.extend(page if isinstance(page, list) else [page])
        return flat
    return data


def pr_files(repo: str, pr: int, token: str | None = None) -> list[dict[str, Any]]:
    """Every changed file of a PR, all pages, as REST returns them.

    Each entry keeps `filename`, `previous_filename` (renames), `status`, `additions` and
    `deletions`. `gh pr view --json files` stops at 100 files; this does not, though the
    API itself stops at 3000. A malformed page raises rather than yielding a short list.
    """
    data = api(f"repos/{repo}/pulls/{pr}/files?per_page=100", paginate=True, token=token)
    if data is None:
        return []
    if not isinstance(data, list):
        raise GhError(f"pulls/{pr}/files: expected a list, got {type(data).__name__}")
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
            raise GhError(f"pulls/{pr}/files: malformed entry {str(item)[:200]}")
    return data


def _is_graphql_rate_limit(errors: Any) -> bool:
    if not isinstance(errors, list) or not errors:
        return False
    return all(
        isinstance(e, dict) and (
            e.get("type") == "RATE_LIMITED" or bool(_RATE_RE.search(str(e.get("message") or "")))
        )
        for e in errors
    )


def graphql(query: str, *, idempotent: bool | None = None, **variables: Any) -> Any:
    if idempotent is None:
        stripped = query.lstrip()
        idempotent = (
            stripped.startswith(("query", "{"))
            or (
                any(m in stripped for m in IDEMPOTENT_MUTATIONS)
                and "addPullRequestReviewThreadReply" not in stripped
            )
        )
    payload = json.dumps({"query": query, "variables": variables})
    start = time.monotonic()
    attempt = 0
    while True:
        out = _run(["api", "graphql", "--input", "-"], payload, idempotent=idempotent)
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise GhError(f"graphql: invalid JSON: {exc}", transient=True) from exc
        if not isinstance(data, dict):
            raise GhError(f"graphql: expected object, got {type(data).__name__}")
        errors = data.get("errors")
        if errors:
            if _is_graphql_rate_limit(errors):
                if attempt < len(RATE_LIMIT_DELAYS):
                    delay = RATE_LIMIT_DELAYS[attempt]
                    if (time.monotonic() - start) + delay <= MAX_ELAPSED_S:
                        attempt += 1
                        print(f"::notice::gh retry {attempt}/{len(RATE_LIMIT_DELAYS)} after rate (graphql)",
                              file=sys.stderr)
                        _sleep(delay)
                        continue
                raise GhError(f"graphql: {errors}", status=429, transient=True)
            raise GhError(f"graphql: {errors}", transient=False)
        if "data" not in data:
            raise GhError("graphql: response missing 'data' key")
        return data["data"]
