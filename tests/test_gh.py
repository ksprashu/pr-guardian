import io
import json
import subprocess
import unittest
from unittest import mock

import tests.helpers  # noqa: F401  (adds scripts/ to sys.path)
import gh


def proc(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["gh"], returncode, stdout=stdout, stderr=stderr)


class GhRetryTest(unittest.TestCase):
    def test_502_then_success_on_get_retries_once(self):
        sleeps = []
        err = io.StringIO()
        side = [
            proc(1, stderr="gh: Bad Gateway (HTTP 502)"),
            proc(0, stdout='{"ok": true}'),
        ]
        with mock.patch.object(gh.subprocess, "run", side_effect=side) as run, \
                mock.patch.object(gh, "_sleep", side_effect=sleeps.append), \
                mock.patch("sys.stderr", err):
            out = gh.api("repos/o/r")
        self.assertEqual(out, {"ok": True})
        self.assertEqual(run.call_count, 2)
        self.assertEqual(sleeps, [2.0])
        self.assertIn("::notice::gh retry 1/3 after server (502)", err.getvalue())

    def test_network_errors_retry_on_get_only(self):
        for msg in ("dial tcp: connection reset by peer", "TLS handshake timeout", "unexpected EOF"):
            sleeps = []
            side = [proc(1, stderr=msg), proc(0, stdout='{"ok": 1}')]
            with self.subTest(msg=msg), \
                    mock.patch.object(gh.subprocess, "run", side_effect=side), \
                    mock.patch.object(gh, "_sleep", side_effect=sleeps.append), \
                    mock.patch("sys.stderr"):
                self.assertEqual(gh.api("repos/o/r"), {"ok": 1})
                self.assertEqual(sleeps, [2.0])

    def test_502_on_post_does_not_retry(self):
        sleeps = []
        with mock.patch.object(gh.subprocess, "run", return_value=proc(1, stderr="HTTP 502: Bad Gateway")) as run, \
                mock.patch.object(gh, "_sleep", side_effect=sleeps.append):
            with self.assertRaises(gh.GhError) as ctx:
                gh.api("repos/o/r/issues", "POST", {"title": "t"})
        self.assertEqual(run.call_count, 1)
        self.assertEqual(sleeps, [])
        self.assertEqual(ctx.exception.status, 502)
        self.assertTrue(ctx.exception.transient)
        self.assertIn("gh api repos/o/r/issues -X… failed:", str(ctx.exception))

    def test_rate_limit_retries_on_post_and_exhausts(self):
        for stderr, want_status in (
            ("gh: Too Many Requests (HTTP 429)", 429),
            ("gh: You have exceeded a secondary rate limit. (HTTP 403)", 403),
            ("gh: content was submitted too quickly (HTTP 403)", 403),
        ):
            sleeps = []
            with self.subTest(stderr=stderr):
                with mock.patch.object(gh.subprocess, "run", return_value=proc(1, stderr=stderr)) as run, \
                        mock.patch.object(gh, "_sleep", side_effect=sleeps.append), \
                        mock.patch("sys.stderr"):
                    with self.assertRaises(gh.GhError) as ctx:
                        gh.api("repos/o/r/issues", "POST", {"title": "t"})
                self.assertEqual(sleeps, [15.0, 30.0])
                self.assertEqual(run.call_count, 3)
                self.assertEqual(ctx.exception.status, want_status)
                self.assertTrue(ctx.exception.transient)

    def test_fatal_4xx_never_retried(self):
        cases = [
            ("gh: Not Found (HTTP 404) unexpected EOF in body", 404),
            ("gh: Validation Failed (HTTP 422)", 422),
            ("gh: Resource not accessible by integration (HTTP 403)", 403),
            ("gh: PullRequest.diff too_large (HTTP 406)", 406),
        ]
        for stderr, want_status in cases:
            sleeps = []
            with self.subTest(status=want_status):
                with mock.patch.object(gh.subprocess, "run", return_value=proc(1, stderr=stderr)) as run, \
                        mock.patch.object(gh, "_sleep", side_effect=sleeps.append):
                    with self.assertRaises(gh.GhError) as ctx:
                        gh.api("repos/o/r")
                self.assertEqual(run.call_count, 1)
                self.assertEqual(sleeps, [])
                self.assertEqual(ctx.exception.status, want_status)
                self.assertFalse(ctx.exception.transient)

    def test_timeout_retries_on_get_and_fails_fast_on_post(self):
        sleeps = []
        to = subprocess.TimeoutExpired(cmd=["gh"], timeout=120)
        with mock.patch.object(gh.subprocess, "run", side_effect=[to, to, proc(0, stdout='{"ok": 2}')]), \
                mock.patch.object(gh, "_sleep", side_effect=sleeps.append), \
                mock.patch("sys.stderr"):
            self.assertEqual(gh.api("repos/o/r"), {"ok": 2})
        self.assertEqual(sleeps, [2.0, 5.0])

        sleeps.clear()
        with mock.patch.object(gh.subprocess, "run", side_effect=to) as run, \
                mock.patch.object(gh, "_sleep", side_effect=sleeps.append):
            with self.assertRaises(gh.GhTimeout) as ctx:
                gh.api("repos/o/r/issues", "POST", {"title": "t"})
        self.assertIsInstance(ctx.exception, gh.GhError)
        self.assertTrue(ctx.exception.transient)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(sleeps, [])

    def test_max_elapsed_budget_stops_retries(self):
        sleeps = []
        # start=0.0, after first failure monotonic() returns 239.0 -> 239.0 + 2.0 > 240.0 -> no retry
        clock = iter([0.0, 239.0, 250.0])
        with mock.patch.object(gh.subprocess, "run", return_value=proc(1, stderr="(HTTP 503)")) as run, \
                mock.patch.object(gh, "_sleep", side_effect=sleeps.append), \
                mock.patch.object(gh.time, "monotonic", side_effect=lambda: next(clock)):
            with self.assertRaises(gh.GhError):
                gh.api("repos/o/r")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(sleeps, [])

    def test_graphql_idempotent_vs_non_idempotent_mutations(self):
        resolve_q = "mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{id}}}"
        reply_q = ("mutation($id:ID!,$body:String!){addPullRequestReviewThreadReply("
                   "input:{pullRequestReviewThreadId:$id, body:$body}){comment{id}}}")

        sleeps = []
        side = [proc(1, stderr="(HTTP 502)"), proc(0, stdout='{"data": {"resolveReviewThread": {"thread": {"id": "T"}}}}')]
        with mock.patch.object(gh.subprocess, "run", side_effect=side), \
                mock.patch.object(gh, "_sleep", side_effect=sleeps.append), \
                mock.patch("sys.stderr"):
            res = gh.graphql(resolve_q, id="T")
        self.assertEqual(res["resolveReviewThread"]["thread"]["id"], "T")
        self.assertEqual(sleeps, [2.0])

        sleeps.clear()
        with mock.patch.object(gh.subprocess, "run", return_value=proc(1, stderr="(HTTP 502)")) as run, \
                mock.patch.object(gh, "_sleep", side_effect=sleeps.append):
            with self.assertRaises(gh.GhError):
                gh.graphql(reply_q, id="T", body="resolveReviewThread mentioned in body")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(sleeps, [])

    def test_graphql_rate_limited_body_errors_retry_while_other_errors_raise(self):
        reply_q = ("mutation($id:ID!,$body:String!){addPullRequestReviewThreadReply("
                   "input:{pullRequestReviewThreadId:$id, body:$body}){comment{id}}}")
        sleeps = []
        side = [
            proc(0, stdout=json.dumps({"errors": [{"type": "RATE_LIMITED", "message": "API rate limit exceeded"}]})),
            proc(0, stdout=json.dumps({"data": {"addPullRequestReviewThreadReply": {"comment": {"id": "C1"}}}})),
        ]
        with mock.patch.object(gh.subprocess, "run", side_effect=side), \
                mock.patch.object(gh, "_sleep", side_effect=sleeps.append), \
                mock.patch("sys.stderr"):
            data = gh.graphql(reply_q, id="T", body="hi")
        self.assertEqual(data["addPullRequestReviewThreadReply"]["comment"]["id"], "C1")
        self.assertEqual(sleeps, [15.0])

        sleeps.clear()
        other_err = proc(0, stdout=json.dumps({"errors": [{"type": "NOT_FOUND", "message": "Could not resolve"}]}))
        with mock.patch.object(gh.subprocess, "run", return_value=other_err) as run, \
                mock.patch.object(gh, "_sleep", side_effect=sleeps.append):
            with self.assertRaises(gh.GhError) as ctx:
                gh.graphql("query { viewer { login } }")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(sleeps, [])
        self.assertFalse(ctx.exception.transient)

    def test_token_is_passed_via_env_only_never_argv(self):
        secret = "ghs_super_secret_token_value"
        with mock.patch.object(gh.subprocess, "run", return_value=proc(0, stdout='{"ok": 1}')) as run:
            gh.api("repos/o/r", token=secret)
        cmd = run.call_args[0][0]
        kwargs = run.call_args[1]
        self.assertTrue(all(secret not in str(a) for a in cmd))
        self.assertEqual(kwargs["env"]["GH_TOKEN"], secret)


if __name__ == "__main__":
    unittest.main()
