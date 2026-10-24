import unittest

from tests.helpers import finding
import state as st
import verdict as v


def state(*findings, sha="abc", **kw):
    s = st.empty_state()
    s.update(round=2, findings=list(findings), last_reviewed_sha=sha, **kw)
    return s


def decide(s=None, labels=(), events=(), escalate=False, result="success", fork=False, sha="abc"):
    return v.decide(state=s, sha=sha, labels=list(labels), events=list(events), owner="o",
                    escalate=escalate, reason="", review_result=result, fork=fork)


def labeled(by):
    return {"event": "labeled", "label": {"name": "human-override"}, "actor": {"login": by}}


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
        self.assertEqual(decide(state(finding()), labels=["human-override"], events=[labeled("o")])["state"],
                         "success")
        self.assertEqual(decide(state(finding()), labels=["human-override"], events=[labeled("mallory")])["state"],
                         "failure")
        # Owner applied, someone else re-applied later: the latest application decides.
        self.assertEqual(decide(state(finding()), labels=["human-override"],
                                events=[labeled("o"), labeled("mallory")])["state"], "failure")
        # Event without the label still on the PR does not count.
        self.assertEqual(decide(state(finding()), events=[labeled("o")])["state"], "failure")

    def test_fork(self):
        self.assertEqual(decide(None, fork=True)["state"], "failure")
        self.assertEqual(decide(None, fork=True, labels=["human-override"], events=[labeled("o")])["state"],
                         "success")


if __name__ == "__main__":
    unittest.main()
