import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

import tests.helpers  # noqa: F401  (puts scripts/ on sys.path)
import commands as c

SHA12, SHA40, SHA64 = "a" * 12, "0123456789abcdef" * 2 + "01234567", "f" * 64
BOT = {"type": "Bot", "login": "github-actions[bot]"}


class ParseTest(unittest.TestCase):
    def test_not_commands(self):
        for body in (None, 7, "", "lgtm", "please /ai-review", " ai-review", "  /ai-review \n",
                     "  /ai-review help", "\n/ai-review", "/ai-reviewer", "/ai-reviewhelp",
                     "/ai-reviewescalate", "/ai-review ", "/ai-review  ", "/ai-review\n",
                     "/ai-review\r\n", "/ai-review  wontfix: fp", "/ai-review\twontfix: fp",
                     "/ai-review\nwontfix: fp", "/ai-review  help"):
            with self.subTest(body=body):
                cmd = c.parse(body)
                self.assertIn(cmd, (None, c.Command("unknown")))
        self.assertIsNone(c.parse("lgtm"))
        self.assertIsNone(c.parse("  /ai-review \n"))
        self.assertFalse(c.has_prefix("  /ai-review"))
        self.assertTrue(c.has_prefix("/AI-REVIEW help"))
        self.assertEqual(c.parse("/ai-reviewer"), c.Command("unknown"))
        self.assertEqual(c.parse("/ai-review  "), c.Command("unknown"))
        self.assertEqual(c.parse("/ai-review\r\n"), c.Command("unknown"))
        self.assertEqual(c.parse("/ai-review  wontfix: fp"), c.Command("unknown"))

    def test_table(self):
        cases = {
            "/ai-review": c.Command("review"),
            "/AI-REVIEW": c.Command("review"),
            "/Ai-Review": c.Command("review"),
            "/ai-review wontfix: false positive": c.Command("wontfix", text="false positive"),
            "/AI-REVIEW WONTFIX: False Positive": c.Command("wontfix", text="False Positive"),
            "/ai-review wontfix": c.Command("wontfix"),
            "/ai-review WONTFIX": c.Command("wontfix"),
            "/ai-review wontfix   because": c.Command("wontfix", text="because"),
            "/ai-review escalate: loops": c.Command("escalate", text="loops"),
            "/AI-REVIEW ESCALATE: loops": c.Command("escalate", text="loops"),
            "/ai-review escalate": c.Command("escalate"),
            "/ai-review help": c.Command("help"),
            "/AI-REVIEW HELP": c.Command("help"),
            "/ai-review help please": c.Command("help"),
            "/ai-review explain R-001": c.Command("explain", arg="R-001"),
            "/AI-REVIEW EXPLAIN R-001": c.Command("explain", arg="R-001"),
            "/ai-review explain SEC-1234": c.Command("explain", arg="SEC-1234"),
            "/ai-review explain r-001": c.Command("explain", ok=False),
            "/ai-review explain R-01": c.Command("explain", ok=False),
            "/ai-review explain": c.Command("explain", ok=False),
            "/ai-review EXPLAIN": c.Command("explain", ok=False),
            "/ai-review explain R-001 R-002": c.Command("explain", ok=False),
            f"/ai-review override {SHA12}: reviewed by hand": c.Command("override", SHA12, "reviewed by hand"),
            f"/AI-REVIEW OVERRIDE {SHA12}: Reviewed By Hand": c.Command("override", SHA12, "Reviewed By Hand"),
            f"/ai-review override {SHA40}:ok!": c.Command("override", SHA40, "ok!"),
            f"/ai-review override {SHA40}: ok!  \n": c.Command("override", SHA40, "ok!"),
            f"/ai-review override {SHA64} : fine as is": c.Command("override", SHA64, "fine as is"),
            "/ai-review override": c.Command("override", ok=False),
            "/ai-review OVERRIDE": c.Command("override", ok=False),
            "/ai-review override: because": c.Command("override", ok=False),
            f"/ai-review override {SHA12}": c.Command("override", ok=False),
            f"/ai-review override {SHA12}: ab": c.Command("override", ok=False),
            f"/ai-review override {SHA12}: ab\n": c.Command("override", ok=False),
            "/ai-review override " + "a" * 11 + ": because": c.Command("override", ok=False),
            "/ai-review override " + "a" * 65 + ": because": c.Command("override", ok=False),
            "/ai-review override " + "A" * 12 + ": because": c.Command("override", ok=False),
            f"/ai-review override {SHA12} because": c.Command("override", ok=False),
            f"/ai-review override {SHA12}: <!-- -->": c.Command("override", ok=False),
            f"/ai-review override {SHA12}: <!---->x": c.Command("override", ok=False),
            "/ai-review frobnicate": c.Command("unknown"),
            "/ai-review overrides": c.Command("unknown"),
            "/ai-review helpme": c.Command("unknown"),
        }
        for body, want in cases.items():
            with self.subTest(body=body):
                self.assertEqual(c.parse(body), want)

    def test_line_breaks_stay_inside_text(self):
        cmd = c.parse(f"/ai-review override {SHA12}: line one\r\naction=review\n<!-- x -->")
        self.assertEqual((cmd.name, cmd.arg, cmd.ok), ("override", SHA12, True))
        self.assertEqual(cmd.text, "line one\r\naction=review\n<!-- x -->")
        cmd = c.parse("/ai-review explain R-001\naction=review")
        self.assertEqual(cmd, c.Command("explain", ok=False))
        cmd = c.parse(f"/ai-review override {SHA12}\n: reason here")
        self.assertEqual((cmd.arg, cmd.text), (SHA12, "reason here"))


class AuthorTest(unittest.TestCase):
    def test_is_writer(self):
        ok = {"user": {"login": "c", "type": "User"}, "author_association": "COLLABORATOR"}
        self.assertTrue(c.is_writer(ok))
        for bad in (None, {}, {**ok, "author_association": "CONTRIBUTOR"}, {**ok, "user": {"login": "c", "type": "Bot"}},
                    {**ok, "user": {"login": "", "type": "User"}}, {**ok, "user": "c"}):
            with self.subTest(bad=bad):
                self.assertFalse(c.is_writer(bad))

    def test_is_owner(self):
        ok = {"user": {"login": "o", "type": "User"}, "author_association": "OWNER"}
        self.assertTrue(c.is_owner(ok, "o"))
        for comment, owner in ((ok, ""), (ok, "O"), ({**ok, "author_association": "MEMBER"}, "o"),
                               ({**ok, "user": {"login": "o", "type": "Bot"}}, "o"),
                               ({**ok, "user": {"login": "o"}}, "o"), (None, "o")):
            with self.subTest(comment=comment, owner=owner):
                self.assertFalse(c.is_owner(comment, owner))


class RefTest(unittest.TestCase):
    def test_comment_ref_and_event_pr(self):
        ic = {"comment": {"id": 11}, "issue": {"number": 7, "pull_request": {}}}
        rc = {"comment": {"id": 12}, "pull_request": {"number": 7}}
        self.assertEqual(c.comment_ref("issue_comment", ic), ("issue", 11))
        self.assertEqual(c.comment_ref("pull_request_review_comment", rc), ("review", 12))
        self.assertEqual((c.event_pr("issue_comment", ic), c.event_pr("pull_request_review_comment", rc)), (7, 7))
        for name, ev in (("pull_request", ic), ("issue_comment", {"comment": {"id": "11"}}),
                         ("issue_comment", {"comment": {"id": True}}), ("issue_comment", {"comment": {"id": 0}}),
                         ("issue_comment", {}), ("issue_comment", None)):
            with self.subTest(name=name, ev=ev):
                self.assertIsNone(c.comment_ref(name, ev))
        self.assertIsNone(c.event_pr("issue_comment", {"issue": {"number": 7}}))
        self.assertIsNone(c.event_pr("issue_comment", {"issue": {"number": 7, "pull_request": None}}))
        self.assertIsNone(c.event_pr("issue_comment", {"issue": {"number": "7", "pull_request": {}}}))


class ReplyTest(unittest.TestCase):
    def test_replied_needs_trusted_trailing_marker(self):
        mk = c.reply_marker("issue", 11)
        self.assertTrue(c.replied([{"user": BOT, "body": "hi\n\n" + mk + "\n"}], "issue", 11))
        self.assertFalse(c.replied([{"user": BOT, "body": "hi\n\n" + mk}], "review", 11))
        self.assertFalse(c.replied([{"user": BOT, "body": "hi\n\n" + mk}], "issue", 12))
        for user in ({"type": "User", "login": "o"}, {"type": "Bot", "login": "evil[bot]"},
                     {"type": "User", "login": "github-actions[bot]"}, None):
            with self.subTest(user=user):
                self.assertFalse(c.replied([{"user": user, "body": mk}], "issue", 11))
        self.assertFalse(c.replied([{"user": BOT, "body": mk + "\ntrailing"}], "issue", 11))
        self.assertFalse(c.replied([{"user": BOT, "body": None}, "x", None], "issue", 11))

    def test_reply_endpoints_and_marker(self):
        calls = []
        with mock.patch.object(c.gh, "api", side_effect=lambda *a, **k: calls.append(a)):
            c.reply("o/r", 7, "issue", 11, "hello")
            c.reply("o/r", 7, "review", 12, "hello")
        self.assertEqual([(p, m) for p, m, _ in calls],
                         [("repos/o/r/issues/7/comments", "POST"), ("repos/o/r/pulls/7/comments/12/replies", "POST")])
        self.assertTrue(calls[0][2]["body"].endswith(c.reply_marker("issue", 11)))
        self.assertTrue(calls[1][2]["body"].endswith(c.reply_marker("review", 12)))
        self.assertTrue(c.replied([{"user": BOT, "body": calls[1][2]["body"]}], "review", 12))

    def test_reply_to_a_reply_goes_under_the_top_level_comment(self):
        self.assertEqual(c.reply_target({"in_reply_to_id": 500}, 901), 500)
        for comment in ({}, None, {"in_reply_to_id": None}, {"in_reply_to_id": True}, {"in_reply_to_id": "500"},
                        {"in_reply_to_id": 0}):
            with self.subTest(comment=comment):
                self.assertEqual(c.reply_target(comment, 901), 901)
        calls = []
        with mock.patch.object(c.gh, "api", side_effect=lambda *a, **k: calls.append(a)):
            c.reply("o/r", 7, "review", 901, "hello", reply_to=500)
        self.assertEqual(calls[0][0], "repos/o/r/pulls/7/comments/500/replies")
        self.assertTrue(calls[0][2]["body"].endswith(c.reply_marker("review", 901)))

    def test_react_endpoints_and_swallows_errors(self):
        calls = []
        with mock.patch.object(c.gh, "api", side_effect=lambda *a, **k: calls.append(a)):
            c.react("o/r", "issue", 11)
            c.react("o/r", "review", 12, "+1")
        self.assertEqual(calls, [("repos/o/r/issues/comments/11/reactions", "POST", {"content": "eyes"}),
                                 ("repos/o/r/pulls/comments/12/reactions", "POST", {"content": "+1"})])
        with mock.patch.object(c.gh, "api", side_effect=c.gh.GhError("HTTP 403 nope")), \
                redirect_stdout(io.StringIO()) as out:
            c.react("o/r", "issue", 11)
        self.assertIn("::notice::", out.getvalue())

    def test_help_text_is_inline_safe(self):
        text = c.help_text("o@x<!--")
        self.assertNotIn("<!--", text)
        self.assertNotRegex(text, r"@[A-Za-z0-9-]")
        for cmd in ("/ai-review explain <ID>", "/ai-review override <head-sha>: <reason>", "/ai-review help",
                    "needs-human", "human-override"):
            self.assertIn(cmd, text)


class AckCliTest(unittest.TestCase):
    def run_ack(self, event_name, event):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "event.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(event, fh)
            calls = []
            env = {"GITHUB_EVENT_NAME": event_name, "GITHUB_EVENT_PATH": path}
            with mock.patch.dict(os.environ, env), \
                    mock.patch.object(c.sys, "argv", ["commands.py", "ack", "--repo", "o/r"]), \
                    mock.patch.object(c.gh, "api", side_effect=lambda *a, **k: calls.append(a)):
                self.assertEqual(c.main(), 0)
            return calls

    def event(self, body="/ai-review help", assoc="MEMBER", user_type="User"):
        return {"comment": {"id": 11, "body": body, "author_association": assoc,
                            "user": {"login": "m", "type": user_type}},
                "issue": {"number": 7, "pull_request": {}}}

    def test_reacts_to_writer_commands_only(self):
        self.assertEqual(self.run_ack("issue_comment", self.event()),
                         [("repos/o/r/issues/comments/11/reactions", "POST", {"content": "eyes"})])
        for ev in (self.event(assoc="NONE"), self.event(user_type="Bot"), self.event(body="lgtm")):
            with self.subTest(ev=ev):
                self.assertEqual(self.run_ack("issue_comment", ev), [])
        self.assertEqual(self.run_ack("pull_request", self.event()), [])


if __name__ == "__main__":
    unittest.main()
