"""Thin wrappers over the `gh` CLI. stdlib only, shell=False, no secrets in argv."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any


class GhError(RuntimeError):
    pass


def _run(args: list[str], stdin: str | None = None, token: str | None = None) -> str:
    env = {**os.environ, "GH_TOKEN": token} if token else None
    proc = subprocess.run(["gh", *args], input=stdin, capture_output=True, text=True,
                          shell=False, timeout=120, env=env)
    if proc.returncode != 0:
        raise GhError(f"gh {' '.join(args[:3])}… failed: {proc.stderr.strip()[:500]}")
    return proc.stdout


def api(path: str, method: str = "GET", body: dict[str, Any] | None = None,
        paginate: bool = False, token: str | None = None) -> Any:
    args = ["api", path, "-X", method, "-H", "Accept: application/vnd.github+json"]
    if paginate:
        args += ["--paginate", "--slurp"]
    stdin = None
    if body is not None:
        args += ["--input", "-"]
        stdin = json.dumps(body)
    out = _run(args, stdin, token)
    if not out.strip():
        return None
    data = json.loads(out)
    if paginate:  # --slurp wraps pages in an outer list
        flat: list[Any] = []
        for page in data:
            flat.extend(page if isinstance(page, list) else [page])
        return flat
    return data


def graphql(query: str, **variables: Any) -> Any:
    body = {"query": query, "variables": variables}
    out = _run(["api", "graphql", "--input", "-"], json.dumps(body))
    data = json.loads(out)
    if data.get("errors"):
        raise GhError(f"graphql: {data['errors']}")
    return data["data"]
