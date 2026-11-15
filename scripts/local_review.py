#!/usr/bin/env python3
"""Run the pr-guardian chain against a real PR without writing anything to GitHub."""
from __future__ import annotations

import argparse
import copy
import io
import json
import os
import re
import sys
import tempfile
import urllib.parse
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import build_context  # noqa: E402
import gh  # noqa: E402
import publish_review  # noqa: E402
import run_model  # noqa: E402
import verdict  # noqa: E402

READ_CLI = {("pr", "view"), ("pr", "diff"), ("pr", "list"), ("pr", "checks"), ("repo", "view")}


def classify(args: list[str], stdin: str | None) -> str:
    """'read' or 'write'. Anything not positively recognised as a read is a write."""
    if args[:1] == ["api"]:
        if args[1:2] == ["graphql"]:
            try:
                query = json.loads(stdin or "{}").get("query", "")
            except ValueError:
                return "write"
            return "read" if isinstance(query, str) and re.match(r"\s*(query\b|\{)", query) else "write"
        if "-X" in args and args[args.index("-X") + 1 : args.index("-X") + 2] == ["GET"]:
            return "read"
        return "write"
    return "read" if tuple(args[:2]) in READ_CLI else "write"


def _rest_method(args: list[str]) -> str:
    if "-X" in args:
        idx = args.index("-X")
        if idx + 1 < len(args):
            return args[idx + 1].upper()
    return "POST"


def _parse_stdin(stdin: str | None) -> Any:
    if stdin is None or stdin == "":
        return None
    try:
        return json.loads(stdin)
    except ValueError:
        return stdin


def decode(args: list[str], stdin: str | None) -> dict[str, Any]:
    """Decode a captured gh invocation for reporting."""
    if args[:1] == ["api"]:
        if args[1:2] == ["graphql"]:
            return {
                "kind": "graphql",
                "method": "GRAPHQL",
                "path": "graphql",
                "body": _parse_stdin(stdin),
                "args": list(args),
            }
        path = args[1] if len(args) > 1 else ""
        return {
            "kind": "rest",
            "method": _rest_method(args),
            "path": path,
            "body": _parse_stdin(stdin),
            "args": list(args),
        }
    return {
        "kind": "cli",
        "method": args[0] if args else "cli",
        "path": " ".join(args),
        "body": stdin,
        "args": list(args),
    }


class Overlay:
    """Track dry-run writes so later GET reads see the updated state."""

    def __init__(self, repo: str, pr: int) -> None:
        self.repo = repo
        self.pr = pr
        self._next_id = -1
        self._added_comments: list[dict[str, Any]] = []
        self._patched_comments: dict[int, str] = {}
        self._label_ops: list[tuple[str, list[str]]] = []
        self._comment_patch_re = re.compile(rf"repos/{re.escape(repo)}/issues/comments/(-?\d+)")
        self._label_del_re = re.compile(rf"repos/{re.escape(repo)}/issues/{pr}/labels/(.+)")

    def record(self, args: list[str], stdin: str | None) -> None:
        if args[:1] != ["api"] or args[1:2] == ["graphql"] or len(args) < 2:
            return
        path = args[1].split("?", 1)[0]
        method = _rest_method(args)
        payload = _parse_stdin(stdin)
        if not isinstance(payload, dict):
            payload = {}

        if method == "POST" and path == f"repos/{self.repo}/issues/{self.pr}/comments":
            body = payload.get("body", "")
            cid = self._next_id
            self._next_id -= 1
            self._added_comments.append(
                {
                    "id": cid,
                    "body": body,
                    "user": {"login": "github-actions[bot]", "type": "Bot"},
                }
            )
            return

        m_patch = self._comment_patch_re.fullmatch(path) if method == "PATCH" else None
        if m_patch:
            cid = int(m_patch.group(1))
            body = str(payload.get("body", ""))
            self._patched_comments[cid] = body
            for item in self._added_comments:
                if item["id"] == cid:
                    item["body"] = body
            return

        if method == "POST" and path == f"repos/{self.repo}/issues/{self.pr}/labels":
            labels = payload.get("labels", [])
            if isinstance(labels, list):
                self._label_ops.append(("add", [str(x) for x in labels]))
            return

        m_del = self._label_del_re.fullmatch(path) if method == "DELETE" else None
        if m_del:
            name = urllib.parse.unquote(m_del.group(1))
            self._label_ops.append(("remove", [name]))

    def _patch_comment_list(self, items: list[Any]) -> None:
        for item in items:
            if isinstance(item, dict):
                cid = item.get("id")
                if isinstance(cid, int) and cid in self._patched_comments:
                    item["body"] = self._patched_comments[cid]

    def apply(self, args: list[str], raw: str) -> str:
        if args[:1] != ["api"] or args[1:2] == ["graphql"] or len(args) < 2:
            return raw
        if classify(args, None) != "read":
            return raw
        path = args[1].split("?", 1)[0]

        if path == f"repos/{self.repo}/issues/{self.pr}/comments":
            if not self._added_comments and not self._patched_comments:
                return raw
            paginated = "--paginate" in args
            if not raw.strip():
                data: Any = [[]] if paginated else []
            else:
                data = json.loads(raw)
            if paginated:
                if not isinstance(data, list) or not data:
                    data = [[]]
                for page in data:
                    if isinstance(page, list):
                        self._patch_comment_list(page)
                    elif isinstance(page, dict):
                        self._patch_comment_list([page])
                added = copy.deepcopy(self._added_comments)
                if isinstance(data[-1], list):
                    data[-1].extend(added)
                else:
                    data.append(added)
            elif isinstance(data, list):
                self._patch_comment_list(data)
                data.extend(copy.deepcopy(self._added_comments))
            return json.dumps(data)

        if path == f"repos/{self.repo}/pulls/{self.pr}":
            if not self._label_ops or not raw.strip():
                return raw
            pr_obj = json.loads(raw)
            if not isinstance(pr_obj, dict):
                return raw
            labels = list(pr_obj.get("labels") or [])
            for op, names in self._label_ops:
                if op == "add":
                    for name in names:
                        if not any(isinstance(l, dict) and l.get("name") == name for l in labels):
                            labels.append({"name": name})
                elif op == "remove":
                    drop = set(names)
                    labels = [l for l in labels if not (isinstance(l, dict) and l.get("name") in drop)]
            pr_obj["labels"] = labels
            return json.dumps(pr_obj)

        return raw


class Capture:
    """Context manager patching `gh._run` so writes are recorded locally and never sent."""

    def __init__(self, repo: str, pr: int) -> None:
        self.real = gh._run
        self.writes: list[dict[str, Any]] = []
        self.overlay = Overlay(repo, pr)
        self._patcher: Any = None

    def _run(
        self,
        args: list[str],
        stdin: str | None = None,
        token: str | None = None,
        *,
        idempotent: bool | None = None,
    ) -> str:
        if classify(args, stdin) == "read":
            call_kw = {"idempotent": idempotent} if idempotent is not None else {}
            return self.overlay.apply(args, self.real(args, stdin, token, **call_kw))
        self.writes.append(decode(args, stdin))
        self.overlay.record(args, stdin)
        return '{"data": {}}' if args[1:2] == ["graphql"] else ("{}" if args[:1] == ["api"] else "")

    def __enter__(self) -> "Capture":
        self._patcher = mock.patch.object(gh, "_run", side_effect=self._run)
        self._patcher.__enter__()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._patcher is not None:
            self._patcher.__exit__(*exc)
            self._patcher = None


class StageError(RuntimeError):
    pass


def _run_stage(name: str, fn: Any, argv: list[str], env_extra: dict[str, str] | None = None) -> str:
    buf = io.StringIO()
    old_argv = sys.argv
    old_env = {k: os.environ.get(k) for k in (env_extra or {})}
    try:
        sys.argv = list(argv)
        if env_extra:
            os.environ.update(env_extra)
        with redirect_stdout(buf):
            rc = fn()
        if rc not in (0, None):
            raise StageError(f"{name} exited {rc}")
    except StageError:
        raise
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise StageError(f"{name} exited {exc.code}") from None
    except Exception as exc:
        raise StageError(f"{name} raised {type(exc).__name__}: {exc}") from exc
    finally:
        sys.argv = old_argv
        for k, prev in old_env.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev
    return buf.getvalue()


def _tilde_fence(text: str) -> str:
    runs = re.findall(r"~+", text)
    width = max([4] + [len(r) + 1 for r in runs])
    return "~" * width


def _render_write(index: int, write: dict[str, Any]) -> str:
    lines = [f"### {index}. {write['method']} {write['path']}"]
    body = write.get("body")
    if isinstance(body, dict):
        if list(body.keys()) == ["body"] and isinstance(body["body"], str):
            fence = _tilde_fence(body["body"])
            lines.append(fence)
            lines.append(body["body"])
            lines.append(fence)
        else:
            rendered = json.dumps(body, indent=2)
            fence = _tilde_fence(rendered)
            lines.append(f"{fence}json")
            lines.append(rendered)
            lines.append(fence)
            if isinstance(body.get("body"), str):
                bf = _tilde_fence(body["body"])
                lines.append(bf)
                lines.append(body["body"])
                lines.append(bf)
            for c in body.get("comments") or []:
                if isinstance(c, dict) and isinstance(c.get("body"), str):
                    loc = f"{c.get('path', '?')}:{c.get('line', '?')}"
                    lines.append(f"Inline `{loc}`:")
                    cf = _tilde_fence(c["body"])
                    lines.append(cf)
                    lines.append(c["body"])
                    lines.append(cf)
    elif isinstance(body, str) and body:
        fence = _tilde_fence(body)
        lines.append(fence)
        lines.append(body)
        lines.append(fence)
    return "\n".join(lines)


def _dry_run_findings() -> dict[str, Any]:
    return {
        "schema_version": "1",
        "producer": "review",
        "mode": "pr",
        "summary": "local dry run: model not run",
        "inspected": [],
        "not_inspected": [{"what": "model review", "reason": "local dry run"}],
        "findings": [],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Dry-run pr-guardian locally against a PR without writing.")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--findings")
    ap.add_argument("--scan")
    ap.add_argument("--collector")
    ap.add_argument("--engine", choices=("none", "agy", "claude"), default="none")
    ap.add_argument("--forge")
    ap.add_argument("--workdir")
    ap.add_argument("--guardian-ref", default="")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args(argv)

    scan_path = str(Path(args.scan).resolve()) if args.scan else None
    collector_path = str(Path(args.collector).resolve()) if args.collector else None
    findings_override = Path(args.findings).resolve() if args.findings else None
    forge_dir = Path(args.forge).resolve() if args.forge else None
    workdir = Path(args.workdir).resolve() if args.workdir else None

    if not findings_override and args.engine != "none" and (not forge_dir or not workdir):
        print("local_review: --engine agy|claude requires --forge and --workdir", file=sys.stderr)
        return 1

    tmp_ctx = None if args.out else tempfile.TemporaryDirectory(prefix="prg-local-")
    work_out = Path(args.out).resolve() if args.out else Path(tmp_ctx.name)
    work_out.mkdir(parents=True, exist_ok=True)

    try:
        with Capture(args.repo, args.pr) as cap:
            try:
                raw_view = gh._run(
                    ["pr", "view", str(args.pr), "-R", args.repo, "--json", "headRefOid,baseRefName"]
                )
                view = json.loads(raw_view)
                head = view["headRefOid"]
                base = view["baseRefName"]
            except Exception as exc:
                print(f"local_review: stage pr view failed: {exc}", file=sys.stderr)
                return 1

            context_path = work_out / "context.md"
            triage_path = work_out / "triage.json"
            ctx_argv = [
                "build_context.py",
                "--repo",
                args.repo,
                "--pr",
                str(args.pr),
                "--out",
                str(context_path),
                "--triage-out",
                str(triage_path),
            ]
            if scan_path:
                ctx_argv += ["--scan", scan_path]
            if collector_path:
                ctx_argv += ["--collector", collector_path]

            orig_cwd = os.getcwd()
            try:
                if workdir is not None:
                    os.chdir(workdir)
                _run_stage("build_context", build_context.main, ctx_argv)
            except StageError as exc:
                print(f"local_review: {exc}", file=sys.stderr)
                return 1
            finally:
                os.chdir(orig_cwd)

            findings_path = findings_override or (work_out / "findings.json")
            usage_path = work_out / "usage.json"
            if findings_override:
                usage_arg: str | None = None
            elif args.engine == "none":
                findings_path.write_text(json.dumps(_dry_run_findings(), indent=2), encoding="utf-8")
                usage_arg = None
            else:
                findings_lib = forge_dir / "skills" / "review" / "scripts" / "findings.py"
                rm_argv = [
                    "run_model.py",
                    "--context",
                    str(context_path),
                    "--triage",
                    str(triage_path),
                    "--findings-lib",
                    str(findings_lib),
                    "--out",
                    str(findings_path),
                    "--usage-out",
                    str(usage_path),
                    "--workdir",
                    str(workdir),
                ]
                try:
                    _run_stage("run_model", run_model.main, rm_argv, env_extra={"PRG_ENGINES": args.engine})
                except StageError as exc:
                    print(f"local_review: {exc}", file=sys.stderr)
                    return 1
                usage_arg = str(usage_path) if usage_path.is_file() else None

            pub_argv = [
                "publish_review.py",
                "--repo",
                args.repo,
                "--pr",
                str(args.pr),
                "--sha",
                head,
                f"--base={base}",
                f"--guardian-ref={args.guardian_ref}",
                "--findings",
                str(findings_path),
            ]
            if usage_arg:
                pub_argv += ["--usage", usage_arg]
            try:
                _run_stage("publish_review", publish_review.main, pub_argv)
            except StageError as exc:
                print(f"local_review: {exc}", file=sys.stderr)
                return 1

            ver_argv = [
                "verdict.py",
                "--repo",
                args.repo,
                "--pr",
                str(args.pr),
                "--sha",
                head,
                "--review-result",
                "success",
                "--bind-override",
                "false",
            ]
            try:
                ver_stdout = _run_stage("verdict", verdict.main, ver_argv)
            except StageError as exc:
                print(f"local_review: {exc}", file=sys.stderr)
                return 1

        triage_data = json.loads(triage_path.read_text(encoding="utf-8"))
        context_text = context_path.read_text(encoding="utf-8")
        verdict_lines = [ln for ln in ver_stdout.splitlines() if ln.strip()]
        verdict_data: Any = ver_stdout.strip()
        if verdict_lines:
            try:
                verdict_data = json.loads(verdict_lines[-1])
            except ValueError:
                pass

        if args.as_json:
            print(
                json.dumps(
                    {
                        "repo": args.repo,
                        "pr": args.pr,
                        "head": head,
                        "base": base,
                        "triage": triage_data,
                        "context_bytes": len(context_text.encode("utf-8")),
                        "writes": cap.writes,
                        "verdict": verdict_data,
                    },
                    indent=2,
                )
            )
        else:
            print(f"Triage: {json.dumps(triage_data)}")
            print(f"Context size: {len(context_text.encode('utf-8'))} bytes ({len(context_text.splitlines())} lines)")
            for idx, w in enumerate(cap.writes, 1):
                print(_render_write(idx, w))
            print(f"Verdict: {json.dumps(verdict_data) if isinstance(verdict_data, dict) else verdict_data}")
        return 0
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
