import unittest

from tests.helpers import *  # noqa: F401,F403  (sets sys.path)
import route


def pr_event(action="opened", draft=False, fork=False, label=None):
    base = {"full_name": "o/r"}
    ev = {"action": action, "pull_request": {
        "number": 7, "draft": draft, "head": {"sha": "abc", "repo": {"full_name": "x/r" if fork else "o/r"}},
        "base": {"repo": base}}}
    if label:
        ev["label"] = {"name": label}
    return ev


def comment_event(body, assoc="OWNER", login="o", bot=False, kind="issue_comment"):
    c = {"body": body, "author_association": assoc, "user": {"login": login, "type": "Bot" if bot else "User"}}
    if kind == "issue_comment":
        return {"comment": c, "issue": {"number": 7, "pull_request": {}}}
    return {"comment": c, "pull_request": {"number": 7, "head": {"sha": "abc"}}}


class RouteTest(unittest.TestCase):
    def test_pr_events(self):
        self.assertEqual(route.decide("pull_request", pr_event(), "o")["action"], "review")
        self.assertEqual(route.decide("pull_request", pr_event("synchronize"), "o")["action"], "review")
        self.assertEqual(route.decide("pull_request", pr_event(draft=True), "o")["action"], "skip")
        self.assertEqual(route.decide("pull_request", pr_event("closed"), "o")["action"], "skip")

    def test_fork_never_reaches_the_model(self):
        r = route.decide("pull_request", pr_event(fork=True), "o")
        self.assertEqual(r["action"], "verdict")
        self.assertIn("fork", r["reason"])

    def test_labels(self):
        self.assertEqual(route.decide("pull_request", pr_event("labeled", label="human-override"), "o")["action"],
                         "verdict")
        self.assertEqual(route.decide("pull_request", pr_event("labeled", label="bug"), "o")["action"], "skip")

    def test_commands(self):
        d = lambda *a, **k: route.decide("issue_comment", comment_event(*a, **k), "o")
        self.assertEqual(d("/ai-review")["action"], "review")
        self.assertEqual(d("/ai-review", login="mallory", assoc="NONE")["action"], "skip")
        self.assertEqual(d("/ai-review", login="collab", assoc="COLLABORATOR")["action"], "skip")
        esc = d("/ai-review escalate: reviewer loops")
        self.assertEqual((esc["action"], esc["escalate"]), ("verdict", "true"))
        self.assertEqual(d("/ai-review escalate: x", assoc="NONE", login="m")["action"], "skip")
        self.assertEqual(d("lgtm")["action"], "skip")
        self.assertEqual(d("/ai-review", bot=True)["action"], "skip")
        self.assertEqual(d("/ai-review frobnicate")["action"], "skip")

    def test_wontfix_in_thread(self):
        r = route.decide("pull_request_review_comment",
                         comment_event("/ai-review wontfix: intended", kind="review"), "o")
        self.assertEqual((r["action"], r["head_sha"]), ("review", "abc"))
        r = route.decide("pull_request_review_comment",
                         comment_event("/ai-review wontfix: x", assoc="NONE", login="m", kind="review"), "o")
        self.assertEqual(r["action"], "skip")

    def test_comment_on_plain_issue(self):
        ev = comment_event("/ai-review")
        del ev["issue"]["pull_request"]
        self.assertEqual(route.decide("issue_comment", ev, "o")["action"], "skip")

    def test_dispatch_and_unknown(self):
        self.assertEqual(route.decide("workflow_dispatch", {"inputs": {"pr": "3"}}, "o")["pr"], "3")
        self.assertEqual(route.decide("push", {}, "o")["action"], "skip")


if __name__ == "__main__":
    unittest.main()
