import json
import os
import tempfile
import unittest
from unittest import mock

from tests.helpers import finding, thread
import state as st
import verdict as v

BOT = {"type": "Bot", "login": "github-actions[bot]"}


def state(*findings, sha="abc", base="main", **kw):
    s = st.empty_state()
    s.update(round=2, findings=list(findings), last_reviewed_sha=sha, last_reviewed_base=base, **kw)
    return s


def decide(s=None, labels=(), events=(), escalate=False, result="success", fork=False, sha="abc",
           base_ref="main", comments=(), default_branch="main"):
    return v.decide(state=s, sha=sha, labels=list(labels), events=list(events), owner="o",
                    escalate=escalate, reason="", review_result=result, fork=fork,
                    base_ref=base_ref, comments=list(comments), default_branch=default_branch)


def labeled(by, eid=1, user_type="User"):
    return {"id": eid, "event": "labeled", "label": {"name": "human-override"},
            "actor": {"login": by, "type": user_type}}


def unlabeled(by, eid):
    return {"id": eid, "event": "unlabeled", "label": {"name": "human-override"},
            "actor": {"login": by, "type": "User"}}


def marker(sha="abc", base="main", eid=1, user=BOT, prefix="bound\n\n"):
    return {"user": user, "body": prefix + v.override_marker(sha, base, eid)}


class VerdictTest(unittest.TestCase):
    def test_clean_and_nits_pass(self):
        self.assertEqual(decide(state())["state"], "success")
        r = decide(state(finding(severity="nit")))
        self.assertEqual(r["state"], "success")
        self.assertIn("1 nits", r["description"])

    def test_open_blocking_fails(self):
        r = decide(state(finding(severity="P2"), finding("R-002", severity="P2")))
        self.assertEqual(r["state"], "failure")
        self.assertIn("2 P2", r["description"])

    def test_closed_findings_do_not_block(self):
        self.assertEqual(decide(state(finding(status="fixed", prior_id="R-000")))["state"], "success")

    def test_stale_or_missing_review_is_pending(self):
        self.assertEqual(decide(state(sha="old"))["state"], "pending")
        self.assertEqual(decide(None)["state"], "pending")

    def test_failed_review_is_error(self):
        self.assertEqual(decide(state(), result="failure")["state"], "error")
        self.assertEqual(decide(state(), result="cancelled")["state"], "error")

    def test_escalation(self):
        r = decide(state(), escalate=True)
        self.assertEqual((r["state"], r.get("label")), ("failure", "needs-human"))
        self.assertEqual(decide(state(escalated=True))["label"], "needs-human")
        self.assertEqual(decide(state(), labels=["needs-human"])["state"], "failure")

    def test_override_only_counts_from_owner(self):
        bound = [marker(eid=1), marker(eid=2)]
        self.assertEqual(decide(state(finding()), labels=["human-override"], events=[labeled("o")],
                                comments=bound)["state"], "success")
        self.assertEqual(decide(state(finding()), labels=["human-override"], events=[labeled("mallory")],
                                comments=bound)["state"], "failure")
        # Owner applied, someone else re-applied later: the latest application decides.
        self.assertEqual(decide(state(finding()), labels=["human-override"],
                                events=[labeled("o"), labeled("mallory", eid=2)], comments=bound)["state"],
                         "failure")
        # Event without the label still on the PR does not count.
        self.assertEqual(decide(state(finding()), events=[labeled("o")], comments=bound)["state"], "failure")
        # A bot whose login matches is not the owner.
        self.assertEqual(decide(state(finding()), labels=["human-override"],
                                events=[labeled("o", user_type="Bot")], comments=bound)["state"], "failure")

    def test_fork(self):
        self.assertEqual(decide(None, fork=True)["state"], "failure")
        self.assertEqual(decide(None, fork=True, labels=["human-override"], events=[labeled("o")],
                                comments=[marker()])["state"], "success")
        self.assertEqual(decide(None, fork=True, labels=["human-override"], events=[labeled("o")])["state"],
                         "failure")


A, B = "a" * 40, "b" * 40
OVR = ["human-override"]


class OverrideBindingDecideTest(unittest.TestCase):
    """GHSA-q4j9-99qr-cfhw: an override counts only for the head SHA and base it was bound to."""

    def ok(self, **kw):
        kw.setdefault("labels", OVR)
        kw.setdefault("events", [labeled("o")])
        return decide(state(finding(), sha=kw.pop("sha", A)), sha=A, **kw)["state"] == "success"

    def test_bound_override_is_honoured(self):
        self.assertTrue(self.ok(comments=[marker(A)]))

    def test_unbound_override_is_not_honoured(self):
        self.assertFalse(self.ok(comments=[]))
        # Back-compatible callers that pass no comments never honour an override.
        self.assertEqual(v.decide(state=state(finding(), sha=A), sha=A, labels=OVR, events=[labeled("o")],
                                  owner="o", escalate=False, reason="", review_result="success",
                                  fork=False, base_ref="main")["state"], "failure")
        # ...and callers that also omit base_ref fail closed to pending (GHSA-6h55-p37r-jc34).
        self.assertEqual(v.decide(state=state(finding(), sha=A), sha=A, labels=OVR, events=[labeled("o")],
                                  owner="o", escalate=False, reason="", review_result="success",
                                  fork=False)["state"], "pending")

    def test_sha_base_or_event_mismatch_is_not_honoured(self):
        self.assertFalse(self.ok(comments=[marker(B)]))
        self.assertFalse(self.ok(comments=[marker(A, base="stage")]))
        self.assertFalse(self.ok(comments=[marker(A, eid=2)]))
        self.assertFalse(self.ok(comments=[marker(A)], base_ref=""))
        # Latest application (id 3) is unbound even though an older one matched.
        self.assertFalse(self.ok(events=[labeled("o"), unlabeled("o", 2), labeled("o", eid=3)],
                                 comments=[marker(A, eid=1)]))

    def test_untrusted_marker_authors_are_ignored(self):
        for user in ({"type": "Bot", "login": "evil-app[bot]"}, {"type": "User", "login": "o"},
                     {"type": "User", "login": "github-actions[bot]"}, None):
            with self.subTest(user=user):
                self.assertFalse(self.ok(comments=[marker(A, user=user)]))

    def test_marker_in_summary_or_not_last_is_ignored(self):
        self.assertFalse(self.ok(comments=[marker(A, prefix=st.SUMMARY_MARKER + "\n")]))
        tail = marker(A)
        tail["body"] += "\ntrailing text"
        self.assertFalse(self.ok(comments=[tail]))

    def test_conflicting_markers_for_one_event_are_ignored(self):
        self.assertFalse(self.ok(comments=[marker(A), marker(B)]))
        self.assertFalse(self.ok(comments=[marker(A), marker(A, base="stage")]))
        self.assertTrue(self.ok(comments=[marker(A), marker(A)]))

    def test_base_ref_round_trips_through_marker(self):
        for base in ("release/1.0", "feat_x-y.z", "we ird-->ref", "a%2Fb", "~tilde"):
            with self.subTest(base=base):
                m = v.override_marker(A, base, 9)
                self.assertNotIn(" ", m.split("base=", 1)[1].split(" ", 1)[0])
                self.assertEqual(m.count("-->"), 1)
                self.assertTrue(self.ok(base_ref=base, default_branch=base, events=[labeled("o", eid=9)],
                                        comments=[marker(A, base, 9)]))
        self.assertIn("base=release/1.0 ", v.override_marker(A, "release/1.0", 1))

    def test_stale_override_helper(self):
        st_ = lambda comments, labels=OVR, sha=A, base="main": v.stale_override(
            [labeled("o")], list(labels), sha=sha, base_ref=base, comments=comments)
        self.assertTrue(st_([marker(B)]))
        self.assertTrue(st_([marker(A, base="stage")]))
        self.assertFalse(st_([marker(A)]))
        self.assertFalse(st_([]))  # unbound: never removed
        self.assertFalse(st_([marker(B)], labels=[]))
        self.assertFalse(st_([marker(B)], sha=""))
        self.assertFalse(st_([marker(B)], base=""))
        self.assertFalse(st_([marker(A), marker(B)]))  # ambiguous: left alone, never honoured


FORBIDDEN = "gh api … failed: HTTP 403 Resource not accessible by integration"


class FakeGitHub:
    def __init__(self, head=B, base="main", labels=OVR, events=(), comments=(), review_state=None,
                 delete_error=False, default_branch="main", fork=False, event_name="", event=None,
                 threads=(), review_comments=(), forbid_writes=False):
        self.pr = {"head": {"sha": head, "repo": {"full_name": "x/r" if fork else "o/r"}},
                   "base": {"ref": base, "repo": {"full_name": "o/r", "default_branch": default_branch}},
                   "labels": [{"name": n} for n in labels]}
        self.events, self.comments = list(events), list(comments)
        self.review_comments = list(review_comments)
        if review_state is not None:
            self.comments.insert(0, {"id": 1, "user": BOT,
                                     "body": st.SUMMARY_MARKER + "\n" + st.encode(review_state)})
        self.delete_error, self.calls = delete_error, []
        self.event_name, self.event, self.threads = event_name, event, list(threads)
        self.forbid_writes, self.printed, self.next_id = forbid_writes, [], 5000

    def api(self, path, method="GET", body=None, paginate=False, token=None):
        self.calls.append((path, method, body))
        if method != "GET" and self.forbid_writes:
            raise v.gh.GhError(FORBIDDEN)
        if path.endswith("/pulls/7"):
            return self.pr
        if path.endswith("/events"):
            return list(self.events)
        if path.endswith("/issues/7/comments") and method == "GET":
            return list(self.comments)
        if path.endswith("/pulls/7/comments") and method == "GET":
            return list(self.review_comments)
        if method == "DELETE" and self.delete_error:
            raise v.gh.GhError("gh api … failed: HTTP 404 Label does not exist")
        if method == "POST" and (path.endswith("/issues/7/comments") or path.endswith("/replies")):
            self.next_id += 1
            target = self.comments if path.endswith("/issues/7/comments") else self.review_comments
            target.append({"id": self.next_id, "user": BOT, "body": body["body"]})
        return {}

    def run(self, sha="", bind="false", escalate="false", reason="", result="success", summary=None):
        argv = ["verdict.py", "--repo", "o/r", "--pr", "7", "--sha", sha, "--escalate", escalate,
                "--reason", reason, "--review-result", result, "--bind-override", bind]
        with tempfile.TemporaryDirectory() as tmp:
            env = {"PRG_OWNER": "o", "GITHUB_EVENT_NAME": self.event_name, "GITHUB_EVENT_PATH": "",
                   "GITHUB_STEP_SUMMARY": summary or ""}
            if self.event is not None:
                env["GITHUB_EVENT_PATH"] = os.path.join(tmp, "event.json")
                with open(env["GITHUB_EVENT_PATH"], "w", encoding="utf-8") as fh:
                    json.dump(self.event, fh)
            with mock.patch.object(v.gh, "api", side_effect=self.api), \
                    mock.patch.object(v.th, "fetch", side_effect=lambda repo, pr: list(self.threads)), \
                    mock.patch.object(v.sys, "argv", argv), \
                    mock.patch.dict(os.environ, env, clear=False), \
                    mock.patch("builtins.print", side_effect=lambda *a, **k: self.printed.append(" ".join(map(str, a)))):
                return v.main()

    @property
    def writes(self):
        return [(p, m) for p, m, _ in self.calls if m != "GET"]

    @property
    def posted(self):
        """Bodies of every comment and reply pr-guardian posted."""
        return [b["body"] for p, m, b in self.calls
                if m == "POST" and (p.endswith("/issues/7/comments") or p.endswith("/replies"))]

    @property
    def replies(self):
        return [(p, b["body"]) for p, m, b in self.calls if m == "POST" and "pr-guardian:reply" in (b or {}).get("body", "")]

    @property
    def reactions(self):
        return [p for p, m, _ in self.calls if m == "POST" and p.endswith("/reactions")]

    @property
    def status_bodies(self):
        return [b for p, m, b in self.calls if "/statuses/" in p]

    @property
    def statuses(self):
        return [(p.rsplit("/", 1)[1], b["state"]) for p, m, b in self.calls if "/statuses/" in p]

    @property
    def deletes(self):
        return [p for p, m, _ in self.calls if m == "DELETE"]

    @property
    def markers(self):
        return [b["body"] for p, m, b in self.calls
                if m == "POST" and p.endswith("/comments") and "pr-guardian:override" in b["body"]]

    @property
    def label_posts(self):
        return [b for p, m, b in self.calls if m == "POST" and p.endswith("/labels")]


class OverrideBindingMainTest(unittest.TestCase):
    """End to end through main(): the exploit paths and defects in GHSA-q4j9-99qr-cfhw and #27."""

    BLOCKED = staticmethod(lambda sha: state(finding(severity="P1"), sha=sha))

    def test_owner_label_binds_to_event_head_and_base(self):
        gh = FakeGitHub(head=A, events=[labeled("o", eid=41)], review_state=self.BLOCKED(A))
        self.assertEqual(gh.run(sha=A, bind="true"), 0)
        self.assertEqual(len(gh.markers), 1)
        self.assertTrue(gh.markers[0].endswith(v.override_marker(A, "main", 41)))
        self.assertNotIn("@", gh.markers[0])
        self.assertEqual((gh.statuses, gh.deletes), ([(A, "success")], []))

    def test_rerun_does_not_duplicate_marker(self):
        gh = FakeGitHub(head=A, events=[labeled("o", eid=41)], comments=[marker(A, eid=41)])
        gh.run(sha=A, bind="true")
        self.assertEqual((gh.markers, gh.statuses), ([], [(A, "success")]))

    def test_bind_never_binds_unless_owner_label_on_live_event_head(self):
        cases = {
            "stale --sha": (dict(head=B, events=[labeled("o")]), dict(sha=A, bind="true")),
            "empty --sha": (dict(head=B, events=[labeled("o")]), dict(sha="", bind="true")),
            "bind false": (dict(head=A, events=[labeled("o")]), dict(sha=A, bind="false")),
            "mallory latest": (dict(head=A, events=[labeled("o"), labeled("mallory", 2)]), dict(sha=A, bind="true")),
            "bot actor": (dict(head=A, events=[labeled("o", user_type="Bot")]), dict(sha=A, bind="true")),
            "label gone": (dict(head=A, labels=[], events=[labeled("o")]), dict(sha=A, bind="true")),
            "no event id": (dict(head=A, events=[{**labeled("o"), "id": None}]), dict(sha=A, bind="true")),
            "no base": (dict(head=A, base="", events=[labeled("o")]), dict(sha=A, bind="true")),
        }
        for name, (setup, run) in cases.items():
            with self.subTest(name):
                gh = FakeGitHub(review_state=self.BLOCKED(setup.get("head", B)), **setup)
                gh.run(**run)
                self.assertEqual(gh.markers, [])
                self.assertNotIn("success", [s for _, s in gh.statuses])
        gh = FakeGitHub(head=B, events=[labeled("o")])
        gh.run(sha=A, bind="true")
        self.assertEqual(gh.calls[1:], [], "a stale --sha must not read, bind, delete or post anything")

    def test_draft_ready_and_close_reopen_do_not_carry_override(self):
        """Paths (a) and (b): bound to A, B pushed while draft/closed, then ready/reopened."""
        for reason in ("pull_request.ready_for_review", "pull_request.reopened", "pull_request.opened"):
            for review in (self.BLOCKED(B), state(sha=A)):
                with self.subTest(reason=reason, reviewed=review["last_reviewed_sha"]):
                    gh = FakeGitHub(head=B, events=[labeled("o")], comments=[marker(A)], review_state=review)
                    gh.run(sha=B, reason=reason)
                    self.assertEqual(gh.deletes, ["repos/o/r/issues/7/labels/human-override"])
                    self.assertEqual(len(gh.statuses), 1)
                    self.assertEqual(gh.statuses[0][0], B)
                    self.assertIn(gh.statuses[0][1], ("failure", "pending"))

    def test_escalate_during_review_of_new_push_does_not_pass(self):
        """Path (c): /ai-review escalate (no head SHA) while B is still being reviewed."""
        gh = FakeGitHub(head=B, events=[labeled("o")], comments=[marker(A)], review_state=state(sha=A))
        gh.run(sha="", escalate="true", reason="escalated by a writer")
        self.assertEqual(gh.deletes, ["repos/o/r/issues/7/labels/human-override"])
        self.assertEqual(gh.statuses, [(B, "failure")])

    def test_in_flight_synchronize_keeps_fresh_owner_override(self):
        """Owner labels B mid-review; the synchronize run for B must not delete it."""
        gh = FakeGitHub(head=B, events=[labeled("o", eid=5)], comments=[marker(A, eid=1), marker(B, eid=5)],
                        review_state=self.BLOCKED(B))
        gh.run(sha=B, reason="pull_request.synchronize")
        self.assertEqual((gh.deletes, gh.statuses), ([], [(B, "success")]))
        # Synchronize finishing before the labeled run binds: not honoured, not deleted.
        gh = FakeGitHub(head=B, events=[labeled("o"), labeled("o", eid=5)], comments=[marker(A, eid=1)],
                        review_state=self.BLOCKED(B))
        gh.run(sha=B, reason="pull_request.synchronize")
        self.assertEqual((gh.deletes, gh.statuses), ([], [(B, "failure")]))
        # ...and the queued labeled run then binds and passes.
        gh.run(sha=B, bind="true", reason="human-override label applied")
        self.assertEqual(len(gh.markers), 1)
        self.assertEqual(gh.statuses[-1], (B, "success"))

    def test_unlabeled_recomputes_verdict(self):
        """#27: removing the label replaces the override's success."""
        gh = FakeGitHub(head=A, labels=[], events=[labeled("o"), unlabeled("o", 2)], comments=[marker(A)],
                        review_state=self.BLOCKED(A))
        gh.run(sha=A, reason="human-override label removed")
        self.assertEqual((gh.deletes, gh.statuses), ([], [(A, "failure")]))

    def test_base_retarget_drops_override(self):
        gh = FakeGitHub(head=A, base="main", events=[labeled("o")], comments=[marker(A, base="stage")],
                        review_state=self.BLOCKED(A))
        gh.run(sha=A)
        self.assertEqual((len(gh.deletes), gh.statuses), (1, [(A, "failure")]))

    def test_concurrent_label_removal_is_tolerated(self):
        gh = FakeGitHub(head=B, events=[labeled("o")], comments=[marker(A)], review_state=self.BLOCKED(B),
                        delete_error=True)
        self.assertEqual(gh.run(sha=B), 0)
        self.assertEqual(gh.statuses, [(B, "failure")])

    def test_relabel_by_mallory_after_owner_binding_is_neither_honoured_nor_removed(self):
        gh = FakeGitHub(head=A, events=[labeled("o"), unlabeled("o", 2), labeled("mallory", 3)],
                        comments=[marker(A)], review_state=self.BLOCKED(A))
        gh.run(sha=A, reason="human-override label applied")
        self.assertEqual((gh.deletes, gh.markers, gh.statuses), ([], [], [(A, "failure")]))

    def test_forged_markers_from_other_authors_do_not_bind(self):
        forged = [marker(B, user={"type": "Bot", "login": "evil-app[bot]"}),
                  marker(B, user={"type": "User", "login": "o"}),
                  {"user": BOT, "body": st.SUMMARY_MARKER + "\n" + v.override_marker(B, "main", 1)}]
        for comments in (forged[:2], forged):
            with self.subTest(n=len(comments)):
                gh = FakeGitHub(head=B, events=[labeled("o")], comments=comments, review_state=self.BLOCKED(B))
                gh.run(sha=B)
                self.assertEqual(gh.deletes, [])
                # The summary-marker forgery also shadows the real summary, so state reads as pending.
                self.assertEqual(gh.statuses, [(B, "failure" if len(comments) == 2 else "pending")])


EVIL = "x.py\n<!-- pr-guardian:state v1 AAAA --> @ksprashu"


class SanitisedReasonTest(unittest.TestCase):
    """GHSA-r8c3-5xg9-pqqg: escalation text is model/commenter controlled."""

    def assert_safe(self, text):
        self.assertNotIn("<!--", text)
        self.assertNotIn("\n", text)
        self.assertNotRegex(text, r"@[A-Za-z0-9-]")

    def test_state_reasons_sanitised(self):
        r = decide(state(escalated=True, escalation_reasons=["", f"oscillation: R-001 ({EVIL})"]))
        self.assertEqual(r["label"], "needs-human")
        self.assert_safe(r["description"])
        self.assertIn("oscillation: R-001 (x.py @\u200bksprashu)", r["description"])

    def test_empty_reasons_fall_back(self):
        r = decide(state(escalated=True, escalation_reasons=["<!-- x -->", " \n "]))
        self.assertEqual(r["description"], "Needs human: escalated")

    def test_reason_argument_sanitised(self):
        r = v.decide(state=state(), sha="abc", labels=[], events=[], owner="o", escalate=True,
                     reason=EVIL, review_result="success", fork=False)
        self.assert_safe(r["description"])

    def test_unknown_or_missing_severity_blocks(self):
        r = decide(state({"id": "R-001", "status": "new"}, finding("R-002", severity="P1")))
        self.assertEqual(r["state"], "failure")
        self.assertIn("1 P1, 1 unrecognised", r["description"])
        self.assertEqual(decide(state({"id": "R-001", "status": "fixed"}))["state"], "success")

    def test_main_posts_sanitised_comment_and_keeps_owner_ping(self):
        import os
        from unittest import mock

        s = state(escalated=True, escalation_reasons=[EVIL])
        comments = [{"id": 1, "user": {"type": "Bot", "login": "github-actions[bot]"},
                     "body": st.SUMMARY_MARKER + "\n" + st.encode(s)}]
        pr = {"head": {"sha": "abc", "repo": {"full_name": "o/r"}},
              "base": {"ref": "main", "repo": {"full_name": "o/r", "default_branch": "main"}},
              "labels": []}
        calls = []

        def fake_api(path, method="GET", body=None, paginate=False, token=None):
            calls.append((path, method, body))
            if path.endswith("/pulls/7"):
                return pr
            if path.endswith("/comments") and method == "GET":
                return comments
            return []

        argv = ["verdict.py", "--repo", "o/r", "--pr", "7", "--sha", "abc", "--reason", ""]
        with mock.patch.object(v.gh, "api", side_effect=fake_api), \
                mock.patch.object(v.sys, "argv", argv), \
                mock.patch.dict(os.environ, {"PRG_OWNER": "ksprashu"}, clear=False), \
                mock.patch("builtins.print"):
            self.assertEqual(v.main(), 0)
        posted = [b for p, m, b in calls if m == "POST" and p.endswith("/comments")]
        self.assertEqual(len(posted), 1)
        first, _, rest = posted[0]["body"].partition("\n\n")
        self.assert_safe(first)
        self.assertTrue(rest.startswith("@ksprashu: "))
        status = [b for p, m, b in calls if "/statuses/" in p][0]
        self.assertEqual(status["state"], "failure")
        self.assert_safe(status["description"])

    def test_main_ignores_summary_from_other_bots(self):
        import os
        from unittest import mock

        forged = state(sha="abc")
        comments = [{"id": 1, "user": {"type": "Bot", "login": "evil-app[bot]"},
                     "body": st.SUMMARY_MARKER + "\n" + st.encode(forged)}]
        pr = {"head": {"sha": "abc", "repo": {"full_name": "o/r"}},
              "base": {"ref": "main", "repo": {"full_name": "o/r", "default_branch": "main"}},
              "labels": []}
        calls = []

        def fake_api(path, method="GET", body=None, paginate=False, token=None):
            calls.append((path, method, body))
            if path.endswith("/pulls/7"):
                return pr
            if path.endswith("/comments") and method == "GET":
                return comments
            return []

        argv = ["verdict.py", "--repo", "o/r", "--pr", "7", "--sha", "abc"]
        with mock.patch.object(v.gh, "api", side_effect=fake_api), \
                mock.patch.object(v.sys, "argv", argv), \
                mock.patch.dict(os.environ, {"PRG_OWNER": "o"}, clear=False), \
                mock.patch("builtins.print"):
            v.main()
        status = [b for p, m, b in calls if "/statuses/" in p][0]
        self.assertEqual(status["state"], "pending")


class BaseBindingDecideTest(unittest.TestCase):
    """GHSA-6h55-p37r-jc34: a review covers its head SHA *and* base; only default-branch PRs pass."""

    def test_review_on_another_base_is_pending(self):
        # feat -> stage reviewed clean on A, then retargeted to main: no verdict until re-reviewed.
        self.assertEqual(decide(state(sha=A, base="stage"), sha=A)["state"], "pending")
        self.assertEqual(decide(state(sha=A, base="main"), sha=A)["state"], "success")
        # Case matters: GitHub refs are case-sensitive.
        self.assertEqual(decide(state(sha=A, base="Main"), sha=A)["state"], "pending")

    def test_missing_or_empty_last_reviewed_base_fails_closed(self):
        legacy = {k: val for k, val in state(sha=A).items() if k != "last_reviewed_base"}
        restored = st.validate_state(legacy)
        self.assertEqual(restored["last_reviewed_base"], "")
        self.assertEqual(decide(restored, sha=A)["state"], "pending")
        self.assertEqual(decide(state(sha=A, base=""), sha=A)["state"], "pending")
        self.assertEqual(decide(state(sha=A, base=None), sha=A)["state"], "pending")

    def test_empty_sha_or_base_ref_fails_closed(self):
        self.assertEqual(decide(state(sha=""), sha="")["state"], "pending")
        self.assertEqual(decide(state(sha=A, base=""), sha=A, base_ref="", default_branch="")["state"],
                         "pending")

    def test_non_default_base_never_succeeds_even_with_owner_override(self):
        bound = [marker(A, base="stage")]
        for kw in (dict(), dict(labels=OVR, events=[labeled("o")], comments=bound),
                   dict(fork=True, labels=OVR, events=[labeled("o")], comments=bound)):
            with self.subTest(kw=kw):
                r = decide(state(sha=A, base="stage"), sha=A, base_ref="stage", **kw)
                self.assertEqual(r["state"], "pending")
                self.assertIn("not main", r["description"])

    def test_non_default_base_never_escalates_or_errors(self):
        for kw in (dict(escalate=True), dict(labels=["needs-human"]), dict(result="failure"), dict(fork=True)):
            with self.subTest(kw=kw):
                r = decide(state(finding(), sha=A, base="stage", escalated=True), sha=A, base_ref="stage", **kw)
                self.assertEqual(r["state"], "pending")
                self.assertNotIn("label", r)

    def test_non_default_description_is_sanitised(self):
        r = decide(state(sha=A), sha=A, base_ref="x<!--\n@ksprashu")
        self.assertEqual(r["state"], "pending")
        self.assertNotIn("<!--", r["description"])
        self.assertNotIn("\n", r["description"])
        self.assertNotRegex(r["description"], r"@[A-Za-z0-9-]")
        self.assertIn("an unknown base", decide(state(sha=A), sha=A, base_ref="")["description"])

    def test_default_branch_check_precedes_reviewed_check(self):
        r = decide(state(sha=A, base="main"), sha=A, base_ref="main", default_branch="trunk")
        self.assertEqual(r["state"], "pending")
        self.assertEqual(decide(state(sha=A, base="trunk"), sha=A, base_ref="trunk",
                                default_branch="trunk")["state"], "success")


class BaseBindingMainTest(unittest.TestCase):
    """End to end through main(): stacked PRs and base retargets (GHSA-6h55-p37r-jc34)."""

    def test_stacked_pr_into_stage_posts_pending_not_success(self):
        """feat -> stage reviewed clean on A must not put success on A for feat -> main."""
        gh = FakeGitHub(head=A, base="stage", labels=[], review_state=state(sha=A, base="stage"))
        gh.run(sha=A, reason="pull_request.opened")
        self.assertEqual(gh.statuses, [(A, "pending")])

    def test_stacked_pr_owner_override_neither_binds_nor_passes(self):
        gh = FakeGitHub(head=A, base="stage", events=[labeled("o", eid=41)],
                        review_state=state(finding(severity="P1"), sha=A, base="stage"))
        gh.run(sha=A, bind="true", reason="human-override label applied")
        self.assertEqual((gh.markers, gh.statuses), ([], [(A, "pending")]))
        # A marker bound to stage from before the fix is not honoured either.
        gh = FakeGitHub(head=A, base="stage", events=[labeled("o", eid=41)], comments=[marker(A, "stage", 41)],
                        review_state=state(sha=A, base="stage"))
        gh.run(sha=A)
        self.assertEqual(gh.statuses, [(A, "pending")])

    def test_stacked_pr_escalation_adds_no_label(self):
        gh = FakeGitHub(head=A, base="stage", labels=[], review_state=state(sha=A, base="stage", escalated=True))
        gh.run(sha=A, escalate="true", reason="escalated by a writer")
        self.assertEqual((gh.label_posts, gh.statuses), ([], [(A, "pending")]))

    def test_retarget_to_main_is_pending_until_reviewed_against_main(self):
        stage_review = state(sha=A, base="stage")
        gh = FakeGitHub(head=A, base="main", labels=[], review_state=stage_review)
        gh.run(sha=A, reason="pull_request.edited")
        self.assertEqual(gh.statuses, [(A, "pending")])
        gh = FakeGitHub(head=A, base="main", labels=[], review_state=state(sha=A, base="main"))
        gh.run(sha=A, reason="pull_request.edited")
        self.assertEqual(gh.statuses, [(A, "success")])

    def test_missing_default_branch_fails_closed_in_main(self):
        """A payload that cannot prove the PR targets the default branch never passes or binds."""
        for default in (None, "", 0, False, ["main"]):
            for base in ("stage", "main"):
                with self.subTest(default=default, base=base):
                    gh = FakeGitHub(head=A, base=base, labels=[], default_branch=default,
                                    review_state=state(sha=A, base=base))
                    gh.run(sha=A)
                    self.assertEqual(gh.statuses, [(A, "pending")])
                    gh = FakeGitHub(head=A, base=base, events=[labeled("o", eid=41)], default_branch=default,
                                    review_state=state(sha=A, base=base, escalated=True))
                    gh.run(sha=A, bind="true", escalate="true", reason="human-override label applied")
                    self.assertEqual((gh.markers, gh.label_posts, gh.statuses), ([], [], [(A, "pending")]))
        gh = FakeGitHub(head=A, labels=[], review_state=state(sha=A))
        del gh.pr["base"]["repo"]["default_branch"]
        gh.run(sha=A)
        self.assertEqual(gh.statuses, [(A, "pending")])

    def test_decide_require_default(self):
        self.assertEqual(v.decide(state=state(sha=A), sha=A, labels=[], events=[], owner="o", escalate=False,
                                  reason="", review_result="success", fork=False, base_ref="main",
                                  require_default=True)["state"], "pending")
        self.assertEqual(decide(state(sha=A), sha=A, default_branch="")["state"], "success")


OWNER_USER = {"login": "o", "type": "User"}


def nh_event(action, by="o", eid=50, user_type="User"):
    return {"id": eid, "event": action, "label": {"name": "needs-human"}, "actor": {"login": by, "type": user_type}}


def owner_comment(body, cid=900, login="o", assoc="OWNER", user_type="User"):
    return {"id": cid, "body": body, "author_association": assoc, "user": {"login": login, "type": user_type}}


def issue_event(body, cid=900, pr=7, **kw):
    return {"action": "created", "issue": {"number": pr, "pull_request": {"url": "u"}},
            "comment": owner_comment(body, cid, **kw)}


def review_event(body, cid=901, **kw):
    return {"action": "created", "pull_request": {"number": 7, "head": {"sha": A}},
            "comment": owner_comment(body, cid, **kw)}


def finding_thread(fid, n=1):
    t = thread(fid)
    t["comments"]["nodes"][0]["url"] = f"https://github.com/o/r/pull/7#discussion_r{n}"
    return t


def ovr(sha_prefix=A[:12], reason="reviewed the fork by hand"):
    return f"/ai-review override {sha_prefix}: {reason}"


class ForkReadOnlyTest(unittest.TestCase):
    """#30: a fork PR's pull_request* runs hold a read-only token, so they write nothing."""

    def test_fork_pull_request_run_writes_nothing(self):
        for name, extra in (("plain", {}),
                            ("stale label", dict(events=[labeled("o")], comments=[marker(B)])),
                            ("bind", dict(events=[labeled("o", eid=41)]))):
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                summary = os.path.join(tmp, "summary.md")
                kw = dict(head=A, fork=True, event_name="pull_request", event={"action": "opened"},
                          review_state=state(sha=A, escalated=True))
                kw.update(extra)
                gh = FakeGitHub(**kw)
                self.assertEqual(gh.run(sha=A, bind="true" if name == "bind" else "false",
                                        reason="external fork PR: secrets are unavailable, owner review required",
                                        summary=summary), 0)
                self.assertEqual(gh.writes, [])
                self.assertTrue(any('"state": "failure"' in line for line in gh.printed))
                self.assertTrue(any(line.startswith("::notice::") for line in gh.printed))
                with open(summary, encoding="utf-8") as fh:
                    self.assertIn("read-only fork run", fh.read())

    def test_fork_review_comment_run_writes_nothing(self):
        gh = FakeGitHub(head=A, fork=True, event_name="pull_request_review_comment",
                        event=review_event("/ai-review help"), labels=[])
        self.assertEqual(gh.run(sha=A, reason="help requested"), 0)
        self.assertEqual(gh.writes, [])

    def test_forbidden_status_on_fork_exits_zero_elsewhere_raises(self):
        gh = FakeGitHub(head=A, fork=True, labels=[], event_name="issue_comment",
                        event=issue_event("/ai-review escalate: x", login="c", assoc="COLLABORATOR"),
                        forbid_writes=True)
        self.assertEqual(gh.run(escalate="true", reason="escalated by a writer"), 0)
        self.assertTrue(any("cannot write" in line for line in gh.printed))
        gh = FakeGitHub(head=A, labels=[], review_state=state(sha=A), forbid_writes=True)
        with self.assertRaises(v.gh.GhError):
            gh.run(sha=A)

    def test_fork_description_names_the_command(self):
        r = decide(None, fork=True)
        self.assertEqual(r["state"], "failure")
        self.assertIn("/ai-review override", r["description"])


class CommandOverrideTest(unittest.TestCase):
    """#30 / #43: owner `/ai-review override <sha>: <reason>`, bound to head and base."""

    REASON = "override requested by owner"

    def gh(self, body=None, head=A, comments=None, fork=True, **kw):
        body = body or ovr()
        kw.setdefault("event", issue_event(body))
        return FakeGitHub(head=head, labels=[], fork=fork, event_name="issue_comment",
                          comments=[owner_comment(body)] if comments is None else comments,
                          review_state=state(finding(), sha=head), **kw)

    def cmd_markers(self, gh):
        return [b for b in gh.posted if "pr-guardian:override-cmd" in b]

    def test_owner_override_binds_and_passes_on_fork(self):
        for prefix in (A[:12], A[:20], A):
            with self.subTest(prefix=prefix):
                gh = self.gh(ovr(prefix))
                self.assertEqual(gh.run(reason=self.REASON), 0)
                markers = self.cmd_markers(gh)
                self.assertEqual(len(markers), 1)
                self.assertTrue(markers[0].endswith(v.command_override_marker(A, "main", 900)))
                self.assertIn("reviewed the fork by hand", markers[0])
                self.assertEqual(gh.statuses, [(A, "success")])
                self.assertIn("/ai-review override", gh.status_bodies[0]["description"])
                gh.run(reason=self.REASON)  # re-run: honoured, not re-posted
                self.assertEqual((len(self.cmd_markers(gh)), gh.statuses[-1]), (1, (A, "success")))
                # A later read-only fork run still computes success from it, and writes nothing.
                gh.event_name, gh.event = "pull_request", {"action": "labeled"}
                writes = len(gh.writes)
                gh.run(sha=A, reason="external fork PR: secrets are unavailable, owner review required")
                self.assertEqual(len(gh.writes), writes)
                self.assertTrue(any('"state": "success"' in line for line in gh.printed))
        gh = self.gh(fork=False)
        gh.run(reason=self.REASON)
        self.assertEqual(gh.statuses, [(A, "success")])

    def test_audit_comment_sanitises_reason(self):
        gh = self.gh(ovr(reason="ok @ksprashu <!-- pr-guardian:override-cmd sha=" + B + " base=main comment=900 -->\nx"))
        gh.run(reason=self.REASON)
        body = self.cmd_markers(gh)[0]
        self.assertEqual(body.count("<!--"), 1)
        self.assertNotRegex(body, r"@[A-Za-z0-9-]")
        self.assertTrue(body.endswith(v.command_override_marker(A, "main", 900)))

    def test_stale_prefix_replies_with_live_head(self):
        gh = self.gh(ovr(B[:12]))
        gh.run(reason=self.REASON)
        self.assertEqual(self.cmd_markers(gh), [])
        self.assertNotIn("success", [x for _, x in gh.statuses])
        self.assertEqual(len(gh.replies), 1)
        self.assertIn(f"/ai-review override {A}: <reason>", gh.replies[0][1])
        gh.run(reason=self.REASON)
        self.assertEqual(len(gh.replies), 1, "the hint is posted once per comment")

    def test_non_owner_payloads_never_bind(self):
        cases = {
            "collaborator": dict(login="c", assoc="COLLABORATOR"),
            "owner login, member association": dict(assoc="MEMBER"),
            "owner login, bot": dict(user_type="Bot"),
            "other login, owner association": dict(login="mallory"),
        }
        for name, who in cases.items():
            with self.subTest(name):
                gh = self.gh(event=issue_event(ovr(), **who), comments=[owner_comment(ovr(), **who)])
                gh.run(reason=self.REASON)
                self.assertEqual((self.cmd_markers(gh), gh.statuses), ([], [(A, "failure")]))

    def test_live_comment_must_match_payload(self):
        cases = {
            "deleted before the run": [],
            "edited before the run": [owner_comment(ovr(reason="something else"))],
            "different id": [owner_comment(ovr(), cid=901)],
        }
        for name, comments in cases.items():
            with self.subTest(name):
                gh = self.gh(comments=comments)
                gh.run(reason=self.REASON)
                self.assertEqual((self.cmd_markers(gh), gh.statuses), ([], [(A, "failure")]))

    def test_comment_on_other_pr_or_wrong_route_reason_never_binds(self):
        gh = self.gh(event=issue_event(ovr(), pr=8))
        gh.run(reason=self.REASON)
        self.assertEqual(self.cmd_markers(gh), [])
        for reason in ("", "help requested", "escalated by a writer"):
            with self.subTest(reason=reason):
                gh = self.gh()
                gh.run(reason=reason)
                self.assertEqual(self.cmd_markers(gh), [])

    def test_off_default_base_never_binds(self):
        gh = self.gh(base="stage")
        gh.run(reason=self.REASON)
        self.assertEqual((self.cmd_markers(gh), gh.statuses), ([], [(A, "pending")]))

    def test_marker_revoked_by_edit_or_delete_or_other_head(self):
        bound = {"user": BOT, "body": "ok\n\n" + v.command_override_marker(A, "main", 900)}
        live = owner_comment(ovr())
        def ok(comments, sha=A, base="main"):
            return v.decide(state=state(finding(), sha=sha), sha=sha, labels=[], events=[], owner="o",
                            escalate=False, reason="", review_result="success", fork=True, base_ref=base,
                            comments=comments, default_branch=base,
                            cmd_overrides=v.command_override_bindings(comments, "o"))
        ov = lambda comments: v.command_override_bindings(comments, "o")
        self.assertEqual(ov([live, bound]), {(A, "main")})
        self.assertEqual(ov([bound]), set(), "source comment deleted")
        self.assertEqual(ov([owner_comment(ovr(reason="changed my mind")), bound]), {(A, "main")})
        self.assertEqual(ov([owner_comment("thanks"), bound]), set(), "edited away")
        self.assertEqual(ov([owner_comment(ovr(B[:12])), bound]), set(), "edited to another head")
        self.assertEqual(ov([owner_comment(ovr(), assoc="MEMBER"), bound]), set())
        self.assertEqual(ov([owner_comment(ovr(), login="mallory"), bound]), set())
        forged = {"user": {"type": "User", "login": "o"}, "body": bound["body"]}
        self.assertEqual(ov([live, forged]), set())
        self.assertEqual(ov([live, {"user": {"type": "Bot", "login": "evil[bot]"}, "body": bound["body"]}]), set())
        self.assertEqual(ov([live, {**bound, "body": bound["body"] + "\ntrailing"}]), set())
        self.assertEqual(ov([live, bound, {"user": BOT, "body": v.command_override_marker(A, "stage", 900)}]), set())
        self.assertEqual(ok([live, bound])["state"], "success")
        self.assertEqual(ok([live, bound], sha=B)["state"], "failure")
        self.assertEqual(ok([live, bound], base="stage")["state"], "failure")


class NeedsHumanAckTest(unittest.TestCase):
    """#27: removing needs-human acknowledges the round's escalation only for the owner."""

    REASON = "needs-human label removed"

    def gh(self, s, events=None, labels=(), comments=(), **kw):
        return FakeGitHub(head=A, labels=list(labels), review_state=s, comments=comments,
                          events=[nh_event("labeled", by="github-actions[bot]", eid=40, user_type="Bot"),
                                  nh_event("unlabeled")] if events is None else events,
                          event_name="pull_request", event={"action": "unlabeled"}, **kw)

    def acks(self, gh):
        return [b for b in gh.posted if "pr-guardian:ack " in b]

    def test_owner_removal_acknowledges_and_falls_through(self):
        for findings, want in (((finding(),), "failure"), ((), "success")):
            with self.subTest(want=want):
                s = state(*findings, sha=A, escalated=True, escalation_reasons=["round cap: 5 rounds"])
                gh = self.gh(s)
                gh.run(sha=A, reason=self.REASON)
                self.assertEqual(len(self.acks(gh)), 1)
                self.assertTrue(self.acks(gh)[0].endswith(v.ack_marker(A, "main", 2, 50)))
                self.assertEqual((gh.label_posts, gh.statuses), ([], [(A, want)]))
                self.assertNotIn("Needs human", gh.status_bodies[0]["description"])
                gh.run(sha=A, reason="help requested")  # later runs keep honouring it, no re-post
                self.assertEqual((len(self.acks(gh)), gh.label_posts, gh.statuses[-1]), (1, [], (A, want)))

    def test_next_round_escalation_reapplies(self):
        ack = {"user": BOT, "body": "ok\n\n" + v.ack_marker(A, "main", 2, 50)}
        s = state(sha=A, escalated=True, escalation_reasons=["round cap: 5 rounds"])
        s["round"] = 3
        gh = self.gh(s, comments=[ack])
        gh.run(sha=A, reason="pull_request.synchronize")
        self.assertEqual((len(gh.label_posts), gh.statuses), (1, [(A, "failure")]))

    def test_writer_escalate_or_relabel_after_ack_still_blocks(self):
        ack = {"user": BOT, "body": "ok\n\n" + v.ack_marker(A, "main", 2, 50)}
        s = state(sha=A, escalated=True, escalation_reasons=["round cap: 5 rounds"])
        gh = self.gh(s, comments=[ack])
        gh.run(escalate="true", reason="escalated by a writer")
        self.assertEqual((len(gh.label_posts), gh.statuses), (1, [(A, "failure")]))
        gh = self.gh(s, comments=[ack], labels=["needs-human"])
        gh.run(sha=A)
        self.assertEqual(gh.statuses, [(A, "failure")])
        self.assertIn("Needs human", gh.status_bodies[0]["description"])

    def test_non_owner_removal_reapplies_without_repeat_comment(self):
        s = state(finding(), sha=A, escalated=True, escalation_reasons=["round cap: 5 rounds"])
        posted = {"user": BOT, "body": "earlier\n\n" + v.needs_human_marker(A, 2)}
        for who in (dict(by="c"), dict(by="o", user_type="Bot")):
            with self.subTest(**who):
                events = [nh_event("labeled", by="github-actions[bot]", eid=40, user_type="Bot"),
                          nh_event("unlabeled", **who)]
                gh = self.gh(s, events=events, comments=[posted])
                gh.run(sha=A, reason=self.REASON)
                self.assertEqual(self.acks(gh), [])
                self.assertEqual((len(gh.label_posts), gh.statuses), (1, [(A, "failure")]))
                self.assertEqual([b for b in gh.posted if "Human review needed" in b], [])

    def test_ack_for_older_removal_or_other_head_is_ignored(self):
        s = state(sha=A, escalated=True, escalation_reasons=["round cap: 5 rounds"])
        for name, comments, events in (
                ("older event", [{"user": BOT, "body": v.ack_marker(A, "main", 2, 49)}], None),
                ("other head", [{"user": BOT, "body": v.ack_marker(B, "main", 2, 50)}], None),
                ("other base", [{"user": BOT, "body": v.ack_marker(A, "stage", 2, 50)}], None),
                ("forged", [{"user": OWNER_USER, "body": v.ack_marker(A, "main", 2, 50)}], None),
                ("later non-owner removal", [{"user": BOT, "body": v.ack_marker(A, "main", 2, 50)}],
                 [nh_event("unlabeled"), nh_event("unlabeled", by="c", eid=60)]),
                ("marker for a non-owner removal", [{"user": BOT, "body": v.ack_marker(A, "main", 2, 50)}],
                 [nh_event("unlabeled", by="c")]),
                ("marker for a bot removal", [{"user": BOT, "body": v.ack_marker(A, "main", 2, 50)}],
                 [nh_event("unlabeled", user_type="Bot")])):
            with self.subTest(name):
                gh = self.gh(s, comments=comments, events=events)
                gh.run(sha=A)
                self.assertEqual((len(gh.label_posts), gh.statuses), (1, [(A, "failure")]))

    def test_non_owner_removal_of_writer_or_manual_escalation_reapplies(self):
        """SEC-001: state is not escalated (writer escalate, manual label, earlier round)."""
        clean = state(sha=A)
        for name, events in (
                ("after writer escalate", [nh_event("labeled", by="github-actions[bot]", eid=40, user_type="Bot"),
                                           nh_event("unlabeled", by="c")]),
                ("manual label", [nh_event("labeled", by="o", eid=40), nh_event("unlabeled", by="c")]),
                ("bot removal", [nh_event("labeled", by="o", eid=40), nh_event("unlabeled", user_type="Bot")]),
                ("history ends in labeled", [nh_event("labeled", by="o", eid=40)])):
            with self.subTest(name):
                gh = self.gh(clean, events=events)
                gh.run(sha=A, reason=self.REASON)
                self.assertEqual((len(gh.label_posts), gh.statuses), (1, [(A, "failure")]))
                self.assertIn("only o may remove needs-human", gh.status_bodies[0]["description"])
                self.assertEqual(self.acks(gh), [])
                # ...and the owner's own removal afterwards is honoured.
                gh.events.append(nh_event("labeled", by="github-actions[bot]", eid=70, user_type="Bot"))
                gh.events.append(nh_event("unlabeled", eid=71))
                gh.run(sha=A, reason=self.REASON)
                self.assertEqual((len(gh.label_posts), gh.statuses[-1]), (1, (A, "success")))
        # An earlier round escalated, this round did not: same rule.
        earlier = state(sha=A, escalated=False, escalation_reasons=["round cap: 5 rounds"])
        gh = self.gh(earlier, events=[nh_event("labeled", by="github-actions[bot]", eid=40, user_type="Bot"),
                                      nh_event("unlabeled", by="c")])
        gh.run(sha=A, reason=self.REASON)
        self.assertEqual((len(gh.label_posts), gh.statuses), (1, [(A, "failure")]))
        # An override still accepts the head whoever removed the label.
        self.assertEqual(decide(clean, sha=A, labels=OVR, events=[labeled("o"), nh_event("unlabeled", by="c")],
                                comments=[marker(A)])["state"], "success")
        # No needs-human history at all: nothing to undo.
        self.assertFalse(v.unauthorised_removal([labeled("o")], [], "o"))

    def test_queued_removal_run_does_not_ack_a_relabelled_pr(self):
        s = state(sha=A, escalated=True, escalation_reasons=["round cap: 5 rounds"])
        gh = self.gh(s, labels=["needs-human"])
        gh.run(sha=A, reason=self.REASON)
        self.assertEqual(self.acks(gh), [])
        self.assertEqual(gh.statuses, [(A, "failure")])

    def test_workflow_escalation_is_never_acknowledged(self):
        wf = "workflow modified: this PR changes CI workflow or action files (.github/workflows/x.yml)"
        for reasons in ([wf], [wf, "round cap: 5 rounds"]):
            with self.subTest(reasons=reasons):
                s = state(sha=A, escalated=True, escalation_reasons=reasons)
                gh = self.gh(s)
                gh.run(sha=A, reason=self.REASON)
                self.assertEqual(self.acks(gh), [])
                refusals = [b for b in gh.posted if "pr-guardian:ack-refused" in b]
                self.assertEqual(len(refusals), 1)
                self.assertEqual((len(gh.label_posts), gh.statuses), (1, [(A, "failure")]))
                gh.pr["labels"] = []
                gh.run(sha=A, reason=self.REASON)
                self.assertEqual(len([b for b in gh.posted if "pr-guardian:ack-refused" in b]), 1)
        # Even a forged-into-place ack cannot clear it.
        s = state(sha=A, escalated=True, escalation_reasons=[wf])
        self.assertEqual(decide(s, sha=A, events=[nh_event("unlabeled")])["state"], "failure")
        r = v.decide(state=s, sha=A, labels=[], events=[], owner="o", escalate=False, reason="",
                     review_result="success", fork=False, base_ref="main", default_branch="main", acked=True)
        self.assertEqual(r.get("label"), "needs-human")

    def test_workflow_escalation_helper(self):
        wf = "workflow modified: x"
        self.assertTrue(v.workflow_escalation(state(escalated=True, escalation_reasons=["a", wf])))
        self.assertFalse(v.workflow_escalation(state(escalated=False, escalation_reasons=[wf])))
        self.assertFalse(v.workflow_escalation(state(escalated=True, escalation_reasons=["round cap: x"])))
        self.assertFalse(v.workflow_escalation(None))


class NeedsHumanCommentTest(unittest.TestCase):
    """#43: the escalation comment lists blocking threads, is not capped at 140, and is posted once."""

    def test_comment_lists_blocking_threads(self):
        findings = [finding("R-001", severity="P1", title="SQL `injection` @ksprashu <!-- x -->"),
                    finding("R-002", severity="P2", prior_id="R-000", start=4, end=9),
                    finding("R-003", severity="nit"),
                    finding("R-004", severity="P0", status="fixed")]
        s = state(*findings, sha=A, escalated=True, escalation_reasons=["round cap: 5 rounds"])
        gh = FakeGitHub(head=A, labels=[], review_state=s,
                        threads=[finding_thread("R-001", 1), finding_thread("R-000", 2)])
        gh.run(sha=A)
        bodies = [b for b in gh.posted if "Human review needed" in b]
        self.assertEqual(len(bodies), 1)
        body = bodies[0]
        self.assertGreater(len(body), 140)
        self.assertTrue(body.endswith(v.needs_human_marker(A, 2)))
        self.assertIn("**Open blocking findings (2)**", body)
        self.assertIn("(https://github.com/o/r/pull/7#discussion_r1)", body)
        self.assertIn("(https://github.com/o/r/pull/7#discussion_r2)", body)
        self.assertIn("`app.py:4-9`", body)
        self.assertNotIn("R-003", body)
        self.assertNotIn("R-004", body)
        self.assertIn("round cap: 5 rounds", body)
        self.assertIn(f"/ai-review override {A}: <reason>", body)
        self.assertEqual(body.count("<!--"), 1)
        self.assertNotIn("@ksprashu", body)
        self.assertLessEqual(len(gh.status_bodies[0]["description"]), 140)
        gh.run(sha=A)
        self.assertEqual(len([b for b in gh.posted if "Human review needed" in b]), 1)

    def test_thread_fetch_failure_degrades_to_plain_list(self):
        s = state(finding(), sha=A, escalated=True)
        gh = FakeGitHub(head=A, labels=[], review_state=s)
        with mock.patch.object(v.th, "fetch", side_effect=v.gh.GhError("graphql down")), \
                mock.patch("builtins.print"):
            body = v.needs_human_body(sha=A, round_=2, description="d", owner="o", state=s, extra=[],
                                      thread_map_fn=lambda: v._thread_map("o/r", 7))
        self.assertIn("- R-001 · P1 · CWE-89 `app.py:3` title R-001", body)
        del gh

    def test_writer_escalate_text_is_quoted_safely(self):
        gh = FakeGitHub(head=A, labels=[], review_state=state(sha=A), event_name="issue_comment",
                        event=issue_event("/ai-review escalate: loops on @ksprashu <!-- y -->", login="c",
                                          assoc="COLLABORATOR"))
        gh.run(escalate="true", reason="escalated by a writer")
        body = [b for b in gh.posted if "Human review needed" in b][0]
        self.assertIn("escalated by c: loops on @\u200bksprashu", body)
        self.assertEqual(body.count("<!--"), 1)

    def test_blocking_lines_cap(self):
        s = state(*[finding(f"R-{i:03d}") for i in range(1, 26)])
        lines = v.blocking_lines(s, {}, limit=20)
        self.assertEqual(len(lines), 21)
        self.assertEqual(lines[-1], "- … and 5 more")


class InfoCommandTest(unittest.TestCase):
    """#39: help, explain and hint replies, reactions, idempotent across re-runs."""

    def gh(self, body, reason_state=None, kind="issue", head=A, **who):
        event = issue_event(body, **who) if kind == "issue" else review_event(body, **who)
        return FakeGitHub(head=head, labels=[], review_state=reason_state or state(finding(), sha=head),
                          event_name="issue_comment" if kind == "issue" else "pull_request_review_comment",
                          event=event, threads=[finding_thread("R-001", 1)])

    def test_help_reply_once_and_reaction(self):
        gh = self.gh("/ai-review help", login="c", assoc="COLLABORATOR")
        gh.run(reason="help requested")
        self.assertEqual(len(gh.replies), 1)
        path, body = gh.replies[0]
        self.assertEqual(path, "repos/o/r/issues/7/comments")
        self.assertIn("/ai-review override <head-sha>: <reason>", body)
        self.assertTrue(body.endswith(v.commands.reply_marker("issue", 900)))
        self.assertEqual(gh.reactions, ["repos/o/r/issues/comments/900/reactions"])
        self.assertEqual(gh.statuses, [(A, "failure")])
        gh.run(reason="help requested")
        self.assertEqual(len(gh.replies), 1)

    def test_explain_by_id_prior_id_and_unknown(self):
        s = state(finding("R-002", prior_id="R-001", rationale="because\n<!-- x --> @ksprashu"), sha=A)
        for arg, want in (("R-002", "**R-002**"), ("R-001", "**R-002**"), ("R-404", "Current ids: `R-002`")):
            with self.subTest(arg=arg):
                gh = self.gh(f"/ai-review explain {arg}", reason_state=s)
                gh.run(reason="explain requested")
                self.assertEqual(len(gh.replies), 1)
                body = gh.replies[0][1]
                self.assertIn(want, body)
                self.assertEqual(body.count("<!--"), 1)
                self.assertNotRegex(body, r"@[A-Za-z0-9-]")
                if arg != "R-404":
                    self.assertIn("> because", body)
                    self.assertIn("https://github.com/o/r/pull/7#discussion_r1", body)
        gh = self.gh("/ai-review explain r-1")
        gh.run(reason="explain requested")
        self.assertIn("Usage: `/ai-review explain <ID>`", gh.replies[0][1])

    def test_reply_to_a_thread_reply_targets_the_top_level_comment(self):
        gh = self.gh("/ai-review explain R-001", kind="review")
        gh.event["comment"]["in_reply_to_id"] = 500
        gh.run(sha=A, reason="explain requested")
        self.assertEqual([p for p, _ in gh.replies], ["repos/o/r/pulls/7/comments/500/replies"])
        self.assertTrue(gh.replies[0][1].endswith(v.commands.reply_marker("review", 901)))
        self.assertEqual(gh.reactions, ["repos/o/r/pulls/comments/901/reactions"])
        gh.run(sha=A, reason="explain requested")
        self.assertEqual(len(gh.replies), 1)

    def test_rerun_does_not_recompute_answer(self):
        gh = self.gh("/ai-review explain R-001")
        gh.run(reason="explain requested")
        with mock.patch.object(v, "explain_body", side_effect=AssertionError("recomputed")):
            gh.run(reason="explain requested")
        self.assertEqual(len(gh.replies), 1)

    def test_review_comment_explain_replies_in_thread(self):
        gh = self.gh("/ai-review explain R-001", kind="review", login="m", assoc="MEMBER")
        gh.run(sha=A, reason="explain requested")
        self.assertEqual([p for p, _ in gh.replies], ["repos/o/r/pulls/7/comments/901/replies"])
        self.assertEqual(gh.reactions, ["repos/o/r/pulls/comments/901/reactions"])
        gh.run(sha=A, reason="explain requested")
        self.assertEqual(len(gh.replies), 1)

    def test_replies_happen_even_when_sha_is_stale(self):
        gh = self.gh("/ai-review help", kind="review")
        gh.run(sha=B, reason="help requested")
        self.assertEqual(len(gh.replies), 1)
        self.assertEqual(gh.statuses, [])

    def test_hints(self):
        cases = (("/ai-review override", "issue", "override needs a head SHA and a reason",
                  f"/ai-review override {A}: <reason>"),
                 (ovr(), "review", "override must be a top-level PR comment", f"/ai-review override {A}: <reason>"),
                 ("/ai-review wontfix: fp", "issue", "wontfix belongs in a finding thread", "inside the finding's thread"))
        for body, kind, reason, want in cases:
            with self.subTest(reason=reason):
                gh = self.gh(body, kind=kind)
                gh.run(reason=reason)
                self.assertEqual(len(gh.replies), 1)
                self.assertIn(want, gh.replies[0][1])

    def test_payload_must_match_reason_and_author(self):
        cases = (("/ai-review help", "explain requested", {}),
                 ("/ai-review help", "help requested", dict(login="mallory", assoc="NONE")),
                 ("/ai-review help", "help requested", dict(user_type="Bot")),
                 ("/ai-review override", "override needs a head SHA and a reason", dict(login="c", assoc="COLLABORATOR")),
                 ("/ai-review wontfix: x", "wontfix belongs in a finding thread", {}))
        for body, reason, who in cases:
            with self.subTest(body=body, reason=reason, who=who):
                kind = "review" if body.startswith("/ai-review wontfix") else "issue"
                gh = self.gh(body, kind=kind, **who)
                gh.run(reason=reason)
                self.assertEqual(gh.replies, [])
        gh = self.gh("/ai-review help", login="mallory", assoc="NONE")
        gh.run(reason="help requested")
        self.assertEqual(gh.reactions, [])

    def test_dry_run_writes_nothing(self):
        gh = self.gh("/ai-review help")
        argv = ["verdict.py", "--repo", "o/r", "--pr", "7", "--reason", "help requested", "--dry-run"]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "e.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(gh.event, fh)
            with mock.patch.object(v.gh, "api", side_effect=gh.api), \
                    mock.patch.object(v.th, "fetch", return_value=[]), \
                    mock.patch.object(v.sys, "argv", argv), \
                    mock.patch.dict(os.environ, {"PRG_OWNER": "o", "GITHUB_EVENT_NAME": "issue_comment",
                                                 "GITHUB_EVENT_PATH": path}), \
                    mock.patch("builtins.print"):
                self.assertEqual(v.main(), 0)
        self.assertEqual(gh.writes, [])


class ExplainBodyTest(unittest.TestCase):
    def test_thread_link_falls_back_to_current_id(self):
        f = finding("R-002", prior_id="R-001")
        body = v.explain_body(state(f), "R-002", {"R-002": finding_thread("R-002", 7)})
        self.assertIn("https://github.com/o/r/pull/7#discussion_r7", body)
        body = v.explain_body(state(f), "R-002", {"R-001": finding_thread("R-001", 3),
                                                  "R-002": finding_thread("R-002", 7)})
        self.assertIn("#discussion_r3", body)
        self.assertTrue(v.blocking_lines(state(f), {"R-002": finding_thread("R-002", 7)})[0].startswith(
            "- [R-002 · P1 · CWE-89](https://github.com/o/r/pull/7#discussion_r7)"))

    def test_missing_title_leaves_no_dangling_colon(self):
        body = v.explain_body(state(finding(title="")), "R-001", {})
        self.assertIn("**R-001** · P1 · security · CWE-89\n", body)

    def test_graceful_without_rationale_or_threads(self):
        f = finding("R-001", rationale="")
        body = v.explain_body(state(f), "R-001", {})
        self.assertIn("**R-001** · P1 · security · CWE-89: title R-001", body)
        self.assertNotIn("> ", body)
        self.assertIn("No finding `R-009`", v.explain_body(state(f), "R-009", {}))
        self.assertIn("no findings", v.explain_body(None, "R-001", {}))
        self.assertIn("**R-001**", v.explain_body(state({**f, "thread_key": "K-001"}), "K-001", {}))

    def test_rationale_is_clipped(self):
        body = v.explain_body(state(finding(rationale="x" * 5000)), "R-001", {})
        self.assertLess(len(body), 2000)


if __name__ == "__main__":
    unittest.main()
