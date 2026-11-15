"""Shared in-memory GitHub fake for unit and integration tests.

Patches `gh._run` only so `gh.api`, `gh.graphql`, `gh.pr_files`, and direct CLI
callers all exercise their real serialization, pagination, and error checks.
"""
from __future__ import annotations

import collections
import json
import re
from typing import Any
from unittest import mock

import tests.helpers  # noqa: F401
import gh

Call = collections.namedtuple("Call", "kind method path body args token")


class Pages(list):
    """Wrap a response in Pages([...page items...]) to simulate --paginate --slurp pages."""


def _rest_method(args: list[str], stdin: str | None) -> str:
    if "-X" in args:
        idx = args.index("-X")
        if idx + 1 < len(args):
            return args[idx + 1].upper()
    if "--input" in args or "-f" in args or "-F" in args or stdin is not None:
        return "POST"
    return "GET"


def _parse_json_or_raw(stdin: str | None) -> Any:
    if stdin is None:
        return None
    try:
        return json.loads(stdin)
    except ValueError:
        return stdin


class FakeGh:
    READ_CLI = {
        ("pr", "view"),
        ("pr", "diff"),
        ("pr", "list"),
        ("pr", "checks"),
        ("repo", "view"),
        ("secret", "list"),
    }

    def __init__(self, strict: bool = True) -> None:
        self.strict = strict
        self.calls: list[Call] = []
        self._rest: list[tuple[str, re.Pattern[str], Any]] = []
        self._graphql: list[tuple[str, Any]] = []
        self._cli: list[tuple[tuple[str, ...], Any]] = []
        self._patcher: Any = None

    def on(self, method: str, path_regex: str, response: Any) -> "FakeGh":
        self._rest.append((method.upper(), re.compile(path_regex), response))
        return self

    def on_graphql(self, needle: str, response: Any) -> "FakeGh":
        self._graphql.append((needle, response))
        return self

    def on_cli(self, prefix: tuple[str, ...] | list[str], response: Any) -> "FakeGh":
        self._cli.append((tuple(prefix), response))
        return self

    def __enter__(self) -> "FakeGh":
        self._patcher = mock.patch.object(gh, "_run", side_effect=self._run)
        self._patcher.__enter__()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._patcher is not None:
            self._patcher.__exit__(*exc)
            self._patcher = None

    @property
    def writes(self) -> list[Call]:
        out: list[Call] = []
        for c in self.calls:
            if c.kind == "rest" and c.method != "GET":
                out.append(c)
            elif c.kind == "graphql" and c.method == "mutation":
                out.append(c)
            elif c.kind == "cli" and tuple(c.args[:2]) not in self.READ_CLI:
                out.append(c)
        return out

    def assert_no_writes(self) -> None:
        w = self.writes
        if w:
            summary = ", ".join(f"{c.kind}:{c.method}:{c.path}" for c in w)
            raise AssertionError(f"unexpected GitHub writes: {summary}")

    def _run(self, args: list[str], stdin: str | None = None, token: str | None = None) -> str:
        args_tuple = tuple(args)
        if args[:2] == ["api", "graphql"]:
            payload = _parse_json_or_raw(stdin)
            query = payload.get("query", "") if isinstance(payload, dict) else ""
            method = "mutation" if query.lstrip().startswith("mutation") else "query"
            call = Call("graphql", method, query, payload, args_tuple, token)
            self.calls.append(call)
            matched, resp = self._match_graphql(query)
            if not matched:
                if self.strict:
                    raise AssertionError(f"unexpected graphql call: {query[:120]!r}")
                return '{"data": {}}'
            val = self._eval(resp, call)
            if isinstance(val, dict) and ("data" in val or "errors" in val):
                return json.dumps(val)
            return json.dumps({"data": val})

        if args[:1] == ["api"]:
            path = args[1] if len(args) > 1 else ""
            method = _rest_method(args, stdin)
            body = _parse_json_or_raw(stdin)
            call = Call("rest", method, path, body, args_tuple, token)
            self.calls.append(call)
            matched, resp = self._match_rest(method, path)
            if not matched:
                if self.strict:
                    raise AssertionError(f"unexpected REST call: {method} {path}")
                return ""
            val = self._eval(resp, call)
            if val is None:
                return ""
            if "--paginate" in args:
                if isinstance(val, Pages):
                    return json.dumps(list(val))
                return json.dumps([val])
            if isinstance(val, Pages):
                return json.dumps(list(val))
            return json.dumps(val)

        method = args[0] if args else ""
        path = " ".join(args[:2])
        call = Call("cli", method, path, stdin, args_tuple, token)
        self.calls.append(call)
        matched, resp = self._match_cli(args_tuple)
        if not matched:
            if self.strict:
                raise AssertionError(f"unexpected CLI call: {list(args)}")
            return ""
        val = self._eval(resp, call)
        if val is None:
            return ""
        if isinstance(val, str):
            return val
        return json.dumps(val)

    def _match_rest(self, method: str, path: str) -> tuple[bool, Any]:
        for r_method, pat, resp in reversed(self._rest):
            if r_method == method and pat.fullmatch(path):
                return True, resp
        return False, None

    def _match_graphql(self, query: str) -> tuple[bool, Any]:
        for needle, resp in reversed(self._graphql):
            if needle in query:
                return True, resp
        return False, None

    def _match_cli(self, args: tuple[str, ...]) -> tuple[bool, Any]:
        for prefix, resp in reversed(self._cli):
            if args[: len(prefix)] == prefix:
                return True, resp
        return False, None

    @staticmethod
    def _eval(resp: Any, call: Call) -> Any:
        val = resp(call) if callable(resp) else resp
        if isinstance(val, BaseException):
            raise val
        return val
