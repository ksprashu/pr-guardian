import os
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import tests.helpers as helpers
import build_context
import gh
import local_review
import run_model
import state as st
from tests.fake_gh import FakeGh, Pages

HEAD_SHA = "1" * 40


def _wire_pr7(fake: FakeGh, *, pr_files=None, diff: str = helpers.DIFF) -> None:
    files = pr_files if pr_files is not None else [{"filename": "app.py", "status": "modified", "additions": 2, "deletions": 0}]
    fake.on_cli(
        ("pr", "view"),
        json.dumps(
            {
                "headRefOid": HEAD_SHA,
                "baseRefName": "main",
                "title": "Demo PR",
                "body": "Fixes bug",
                "author": {"login": "alice"},
                "headRefName": "feat",
                "changedFiles": len(files),
            }
        ),
    )
    fake.on_cli(("pr", "diff"), diff)
    fake.on(
        "GET",
        r"repos/o/r/pulls/7",
        {
            "head": {"sha": HEAD_SHA, "repo": {"full_name": "o/r"}},
            "base": {"ref": "main", "repo": {"full_name": "o/r", "default_branch": "main"}},
            "changed_files": len(files),
            "labels": [],
        },
    )
    fake.on("GET", r"repos/o/r/pulls/7/files\?per_page=100", files)
    fake.on("GET", r"repos/o/r/issues/7/comments", Pages([[]]))
    fake.on("GET", r"repos/o/r/issues/7/events", Pages([[]]))
    fake.on_graphql(
        "reviewThreads",
        {"repository": {"pullRequest": {"reviewThreads": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}}}},
    )


class ClassifyTest(unittest.TestCase):
    def test_classify_table(self):
        cases = [
            (["api", "repos/o/r/pulls/1", "-X", "GET"], None, "read"),
            (["api", "repos/o/r/pulls/1", "-X", "POST"], '{"a":1}', "write"),
            (["api", "repos/o/r/issues/comments/1", "-X", "PATCH"], '{"body":"x"}', "write"),
            (["api", "repos/o/r/pulls/1", "-X", "PUT"], "{}", "write"),
            (["api", "repos/o/r/issues/1/labels/foo", "-X", "DELETE"], None, "write"),
            (["api", "repos/o/r/issues/1/comments"], None, "write"),
            (["api", "graphql"], json.dumps({"query": "query { viewer { login } }"}), "read"),
            (["api", "graphql"], json.dumps({"query": "  { viewer { login } }"}), "read"),
            (["api", "graphql"], json.dumps({"query": "mutation { resolveReviewThread(input:{}) { id } }"}), "write"),
            (["api", "graphql"], "{not json", "write"),
            (["pr", "view", "7"], None, "read"),
            (["pr", "diff", "7"], None, "read"),
            (["pr", "merge", "7"], None, "write"),
            (["secret", "set", "KEY"], None, "write"),
            (["issue", "create", "--title", "x"], None, "write"),
            (["label", "create", "foo"], None, "write"),
            ([], None, "write"),
        ]
        for args, stdin, expected in cases:
            with self.subTest(args=args, stdin=stdin):
                self.assertEqual(local_review.classify(args, stdin), expected)


class ChainTest(unittest.TestCase):
    def test_end_to_end_chain_with_p1_finding_and_no_real_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            fpath = Path(tmp) / "findings.json"
            fpath.write_text(json.dumps(helpers.doc(helpers.finding())), encoding="utf-8")
            with FakeGh() as fake:
                _wire_pr7(fake)
                out = io.StringIO()
                with redirect_stdout(out):
                    rc = local_review.main(["--repo", "o/r", "--pr", "7", "--findings", str(fpath)])

        self.assertEqual(rc, 0)
        self.assertEqual(fake.writes, [])
        text = out.getvalue()
        self.assertIn("POST repos/o/r/pulls/7/reviews", text)
        self.assertIn(st.SUMMARY_MARKER, text)
        verdict_line = [ln for ln in text.splitlines() if ln.startswith("Verdict: ")][-1]
        verdict_obj = json.loads(verdict_line[len("Verdict: ") :])
        self.assertEqual(verdict_obj["state"], "failure")


class NoModelTest(unittest.TestCase):
    def test_default_engine_none_posts_summary_and_success_without_writes(self):
        with FakeGh() as fake:
            _wire_pr7(fake)
            out = io.StringIO()
            with redirect_stdout(out):
                rc = local_review.main(["--repo", "o/r", "--pr", "7", "--json"])

        self.assertEqual(rc, 0)
        self.assertEqual(fake.writes, [])
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["verdict"]["state"], "success")
        comments = [w for w in payload["writes"] if w["path"] == "repos/o/r/issues/7/comments"]
        self.assertEqual(len(comments), 1)
        self.assertIn(st.SUMMARY_MARKER, comments[0]["body"]["body"])


class StageFailureTest(unittest.TestCase):
    def test_failing_stage_exits_one_names_stage_and_writes_nothing(self):
        with FakeGh() as fake:
            _wire_pr7(fake)
            err = io.StringIO()
            with (
                mock.patch.object(build_context, "main", side_effect=RuntimeError("boom")),
                redirect_stderr(err),
            ):
                rc = local_review.main(["--repo", "o/r", "--pr", "7"])

        self.assertEqual(rc, 1)
        self.assertIn("build_context", err.getvalue())
        self.assertEqual(fake.writes, [])


class OverlayTest(unittest.TestCase):
    def test_overlay_comments_patch_and_labels(self):
        with FakeGh() as fake:
            fake.on(
                "GET",
                r"repos/o/r/pulls/7",
                {
                    "head": {"sha": HEAD_SHA, "repo": {"full_name": "o/r"}},
                    "base": {"ref": "main", "repo": {"full_name": "o/r", "default_branch": "main"}},
                    "labels": [{"name": "existing"}],
                },
            )
            fake.on("GET", r"repos/o/r/issues/7/comments", Pages([[{"id": 10, "body": "old"}]]))

            with local_review.Capture("o/r", 7) as cap:
                gh.api("repos/o/r/issues/7/comments", "POST", {"body": "new summary ~~~~ test"})
                after_post = gh.api("repos/o/r/issues/7/comments", paginate=True)
                self.assertEqual(len(after_post), 2)
                self.assertEqual(after_post[1]["user"]["login"], "github-actions[bot]")
                self.assertEqual(after_post[1]["body"], "new summary ~~~~ test")

                gh.api("repos/o/r/issues/comments/10", "PATCH", {"body": "updated old"})
                gh.api(f"repos/o/r/issues/comments/{after_post[1]['id']}", "PATCH", {"body": "updated summary"})
                after_patch = gh.api("repos/o/r/issues/7/comments", paginate=True)
                self.assertEqual([c["body"] for c in after_patch], ["updated old", "updated summary"])

                gh.api("repos/o/r/issues/7/labels", "POST", {"labels": ["human-review-needed"]})
                gh.api("repos/o/r/issues/7/labels/existing", "DELETE")
                pr = gh.api("repos/o/r/pulls/7")
                self.assertEqual([lbl["name"] for lbl in pr["labels"]], ["human-review-needed"])

        self.assertEqual(fake.writes, [])
        self.assertEqual(len(cap.writes), 5)
        self.assertEqual(local_review._tilde_fence("a ~~~~ b"), "~~~~~")


class ModelEngineTest(unittest.TestCase):
    def test_engine_agy_invokes_run_model_with_workdir_and_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            forge = root / "forge"
            workdir = root / "work"
            out_dir = root / "out"
            workdir.mkdir()
            (forge / "skills" / "review" / "scripts").mkdir(parents=True)
            seen = {}

            def fake_run_model():
                seen["cwd"] = os.getcwd()
                seen["engines"] = os.environ.get("PRG_ENGINES")
                argv = local_review.sys.argv
                out_p = Path(argv[argv.index("--out") + 1])
                usage_p = Path(argv[argv.index("--usage-out") + 1])
                out_p.write_text(json.dumps(helpers.doc()), encoding="utf-8")
                usage_p.write_text(json.dumps({"total_cost_usd": 0.01, "engine": "agy"}), encoding="utf-8")
                return 0

            with FakeGh() as fake:
                _wire_pr7(fake)
                out = io.StringIO()
                with (
                    mock.patch.object(run_model, "main", side_effect=fake_run_model),
                    redirect_stdout(out),
                ):
                    rc = local_review.main(
                        [
                            "--repo",
                            "o/r",
                            "--pr",
                            "7",
                            "--engine",
                            "agy",
                            "--forge",
                            str(forge),
                            "--workdir",
                            str(workdir),
                            "--out",
                            str(out_dir),
                        ]
                    )

        self.assertEqual(rc, 0)
        self.assertEqual(seen["engines"], "agy")
        self.assertEqual(fake.writes, [])
        self.assertIn("Triage:", out.getvalue())

    def test_engine_without_forge_or_workdir_errors(self):
        with redirect_stderr(io.StringIO()):
            rc = local_review.main(["--repo", "o/r", "--pr", "7", "--engine", "agy"])
        self.assertEqual(rc, 1)

    def test_decode_graphql_cli_and_stage_failures(self):
        g = local_review.decode(["api", "graphql"], json.dumps({"query": "mutation { x }"}))
        self.assertEqual(g["kind"], "graphql")
        c = local_review.decode(["pr", "merge", "7"], "stdin-text")
        self.assertEqual(c["kind"], "cli")
        self.assertIn("stdin-text", local_review._render_write(1, c))
        self.assertEqual(local_review._parse_stdin("{bad"), "{bad")
        self.assertEqual(local_review._rest_method(["api", "repos/o/r"]), "POST")

        with FakeGh() as fake:
            fake.on_cli(("pr", "view"), gh.GhError("nope"))
            with redirect_stderr(io.StringIO()):
                self.assertEqual(local_review.main(["--repo", "o/r", "--pr", "7"]), 1)

        with FakeGh() as fake:
            _wire_pr7(fake)
            with (
                mock.patch("publish_review.main", side_effect=SystemExit(2)),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(local_review.main(["--repo", "o/r", "--pr", "7"]), 1)

        with FakeGh() as fake:
            _wire_pr7(fake)
            with (
                mock.patch("verdict.main", return_value=3),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(local_review.main(["--repo", "o/r", "--pr", "7"]), 1)


if __name__ == "__main__":
    unittest.main()
