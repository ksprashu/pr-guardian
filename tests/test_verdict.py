import os
import unittest
from unittest import mock

from tests.helpers import finding
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


class FakeGitHub:
    def __init__(self, head=B, base="main", labels=OVR, events=(), comments=(), review_state=None,
                 delete_error=False, default_branch="main"):
        self.pr = {"head": {"sha": head, "repo": {"full_name": "o/r"}},
                   "base": {"ref": base, "repo": {"full_name": "o/r", "default_branch": default_branch}},
                   "labels": [{"name": n} for n in labels]}
        self.events, self.comments = list(events), list(comments)
        if review_state is not None:
            self.comments.insert(0, {"id": 1, "user": BOT,
                                     "body": st.SUMMARY_MARKER + "\n" + st.encode(review_state)})
        self.delete_error, self.calls = delete_error, []

    def api(self, path, method="GET", body=None, paginate=False, token=None):
        self.calls.append((path, method, body))
        if path.endswith("/pulls/7"):
            return self.pr
        if path.endswith("/events"):
            return list(self.events)
        if path.endswith("/comments") and method == "GET":
            return list(self.comments)
        if method == "DELETE" and self.delete_error:
            raise v.gh.GhError("gh api … failed: HTTP 404 Label does not exist")
        return {}

    def run(self, sha="", bind="false", escalate="false", reason="", result="success"):
        argv = ["verdict.py", "--repo", "o/r", "--pr", "7", "--sha", sha, "--escalate", escalate,
                "--reason", reason, "--review-result", result, "--bind-override", bind]
        with mock.patch.object(v.gh, "api", side_effect=self.api), \
                mock.patch.object(v.sys, "argv", argv), \
                mock.patch.dict(os.environ, {"PRG_OWNER": "o"}, clear=False), \
                mock.patch("builtins.print"):
            return v.main()

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


if __name__ == "__main__":
    unittest.main()
