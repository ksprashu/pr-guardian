import subprocess
import unittest
from unittest import mock

import tests.helpers  # noqa: F401
import gh
from tests.fake_gh import FakeGh, Pages


class FakeGhApiTests(unittest.TestCase):
    def test_get_and_post_with_body_and_empty_reply(self):
        with FakeGh() as fake:
            fake.on("GET", r"repos/o/r/pulls/1", {"number": 1, "state": "open"})
            fake.on("POST", r"repos/o/r/issues/1/comments", {"id": 42})
            fake.on("DELETE", r"repos/o/r/issues/1/labels/stale", None)

            pr = gh.api("repos/o/r/pulls/1")
            created = gh.api("repos/o/r/issues/1/comments", method="POST", body={"body": "hi"})
            deleted = gh.api("repos/o/r/issues/1/labels/stale", method="DELETE")

        self.assertEqual(pr, {"number": 1, "state": "open"})
        self.assertEqual(created, {"id": 42})
        self.assertIsNone(deleted)
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(fake.calls[1].body, {"body": "hi"})
        self.assertEqual(fake.calls[1].method, "POST")
        self.assertEqual(len(fake.writes), 2)

    def test_pagination_three_pages_and_dict_page(self):
        with FakeGh() as fake:
            fake.on(
                "GET",
                r"repos/o/r/issues/1/comments",
                Pages([[{"id": 1}], [{"id": 2}, {"id": 3}], {"id": 4}]),
            )
            items = gh.api("repos/o/r/issues/1/comments", paginate=True)

        self.assertEqual(items, [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}])

    def test_graphql_data_and_errors(self):
        with FakeGh() as fake:
            fake.on_graphql("reviewThreads", {"repository": {"pullRequest": {"id": "PR_1"}}})
            data = gh.graphql("query($n: Int!) { repository { pullRequest(number: $n) { reviewThreads } } }", n=1)
        self.assertEqual(data, {"repository": {"pullRequest": {"id": "PR_1"}}})

        with FakeGh() as fake:
            fake.on_graphql("badQuery", {"errors": [{"message": "bad field"}], "data": None})
            with self.assertRaises(gh.GhError):
                gh.graphql("query { badQuery }")

    def test_pr_files_valid_malformed_and_non_list(self):
        with FakeGh() as fake:
            fake.on(
                "GET",
                r"repos/o/r/pulls/5/files\?per_page=100",
                Pages([[{"filename": "a.py"}], [{"filename": "b.py"}]]),
            )
            self.assertEqual(len(gh.pr_files("o/r", 5)), 2)

        with FakeGh() as fake:
            fake.on("GET", r"repos/o/r/pulls/5/files\?per_page=100", [{"status": "modified"}])
            with self.assertRaises(gh.GhError):
                gh.pr_files("o/r", 5)

        with FakeGh() as fake:
            fake.on("GET", r"repos/o/r/pulls/5/files\?per_page=100", ["not-a-dict"])
            with self.assertRaises(gh.GhError):
                gh.pr_files("o/r", 5)

        with mock.patch.object(gh, "api", return_value={"message": "unexpected dict"}):
            with self.assertRaises(gh.GhError):
                gh.pr_files("o/r", 5)

    def test_writes_classification_and_assert_no_writes(self):
        with FakeGh() as fake:
            fake.on("GET", r"repos/o/r/pulls/1", {})
            fake.on("POST", r"repos/o/r/statuses/abc", {"state": "pending"})
            fake.on("PATCH", r"repos/o/r/issues/comments/1", {"id": 1})
            fake.on("PUT", r"repos/o/r/pulls/1/merge", {"merged": True})
            fake.on("DELETE", r"repos/o/r/issues/1/labels/foo", None)
            fake.on_graphql("query {", {"ok": True})
            fake.on_graphql("resolveReviewThread", {"thread": {"isResolved": True}})
            fake.on_cli(("pr", "view"), '{"title": "t"}')
            fake.on_cli(("pr", "diff"), "diff --git a/x b/x\n")
            fake.on_cli(("pr", "merge"), "merged")

            gh.api("repos/o/r/pulls/1")
            gh.graphql("query { viewer { login } }")
            gh._run(["pr", "view", "1"])
            gh._run(["pr", "diff", "1"])
            fake.assert_no_writes()

            gh.api("repos/o/r/statuses/abc", method="POST", body={"state": "pending"})
            gh.api("repos/o/r/issues/comments/1", method="PATCH", body={"body": "x"})
            gh.api("repos/o/r/pulls/1/merge", method="PUT", body={})
            gh.api("repos/o/r/issues/1/labels/foo", method="DELETE")
            gh.graphql("mutation { resolveReviewThread(input: {}) { clientMutationId } }")
            gh._run(["pr", "merge", "1"])

            with self.assertRaises(AssertionError):
                fake.assert_no_writes()
        self.assertEqual(len(fake.writes), 6)

    def test_strict_failure_override_order_and_exceptions(self):
        with FakeGh(strict=True) as fake:
            with self.assertRaises(AssertionError):
                gh.api("repos/o/r/unregistered")

        with FakeGh() as fake:
            fake.on("GET", r"repos/o/r/item", {"v": 1})
            fake.on("GET", r"repos/o/r/item", {"v": 2})
            fake.on("GET", r"repos/o/r/fail", gh.GhError("simulated 500"))
            fake.on("GET", r"repos/o/r/dyn", lambda call: {"method": call.method, "path": call.path})

            self.assertEqual(gh.api("repos/o/r/item"), {"v": 2})
            self.assertEqual(gh.api("repos/o/r/dyn"), {"method": "GET", "path": "repos/o/r/dyn"})
            with self.assertRaises(gh.GhError):
                gh.api("repos/o/r/fail")

    def test_non_strict_allows_unmatched(self):
        with FakeGh(strict=False) as fake:
            self.assertIsNone(gh.api("repos/o/r/anything"))
            self.assertEqual(gh.graphql("query { anything }"), {})
            self.assertEqual(gh._run(["pr", "view", "1"]), "")
            self.assertEqual(len(fake.calls), 3)


class RealGhRunTests(unittest.TestCase):
    def test_nonzero_exit_raises_gh_error(self):
        failed = subprocess.CompletedProcess(
            args=["gh", "api", "repos/o/r"],
            returncode=1,
            stdout="",
            stderr="gh: Not Found (HTTP 404)",
        )
        with (
            mock.patch("subprocess.run", return_value=failed),
            mock.patch("time.sleep", return_value=None),
        ):
            with self.assertRaises(gh.GhError) as ctx:
                gh._run(["api", "repos/o/r"])
        self.assertIn("404", str(ctx.exception))

    def test_token_passed_as_gh_token_env(self):
        captured_envs = []

        def fake_subproc(cmd, **kwargs):
            captured_envs.append(kwargs.get("env"))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='{"ok": true}', stderr="")

        with (
            mock.patch("subprocess.run", side_effect=fake_subproc),
            mock.patch("time.sleep", return_value=None),
        ):
            out = gh._run(["api", "user"], token="tok-12345")

        self.assertEqual(out, '{"ok": true}')
        self.assertTrue(captured_envs)
        self.assertEqual(captured_envs[-1]["GH_TOKEN"], "tok-12345")


if __name__ == "__main__":
    unittest.main()
