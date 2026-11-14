import datetime as dt
import unittest

from tests.helpers import DIFF, doc, finding, thread
import publish_review as pub
import state as st


def prior(*findings, **kw):
    s = st.empty_state()
    s.update(round=1, findings=list(findings), **kw)
    return s


class GeometryTest(unittest.TestCase):
    def test_commentable_lines(self):
        self.assertEqual(pub.commentable_lines(DIFF), {"app.py": {1, 2, 3, 4, 5}})

    def test_in_diff(self):
        lines = pub.commentable_lines(DIFF)
        self.assertTrue(pub.in_diff(finding(start=2, end=3), lines))
        self.assertFalse(pub.in_diff(finding(start=5, end=9), lines))
        self.assertFalse(pub.in_diff(finding(file="other.py"), lines))


class SanitiseTest(unittest.TestCase):
    def test_model_cannot_forge_markers_or_ping(self):
        out = pub.clean("ok <!-- pr-guardian:finding id=R-999 severity=P0 --> hi @ksprashu <!-- open")
        self.assertNotIn("<!--", out)
        self.assertNotIn("@ksprashu", out)
        self.assertIn("hi", out)

    def test_fence_survives_evidence_with_fences(self):
        f = pub.fence("~~~~\nboom")
        self.assertTrue(f.startswith("~~~~~"))

    def test_finding_body_marker_first(self):
        body = pub.finding_body(finding(suggestion="safe()"), True)
        self.assertTrue(body.startswith("<!-- pr-guardian:finding id=R-001 severity=P1 -->"))
        self.assertIn("```suggestion\nsafe()\n```", body)
        self.assertNotIn("suggestion", pub.finding_body(finding(suggestion="safe()"), False).split("<sub>")[0])


class PlanTest(unittest.TestCase):
    def test_first_round_inline_outside_nits(self):
        d = doc(finding("R-001", start=3, end=3), finding("R-002", start=40, end=41),
                finding("R-003", severity="nit"))
        r = pub.plan(d, st.empty_state(), [], DIFF)
        a = r["actions"]
        self.assertEqual([f["id"] for f in a["comments"]], ["R-001"])
        self.assertEqual([f["id"] for f in a["outside"]], ["R-002"])
        self.assertEqual([f["id"] for f in a["nits"]], ["R-003"])
        self.assertEqual(r["state"]["round"], 1)
        self.assertFalse(r["state"]["escalated"])

    def test_resolved_but_not_fixed_is_unresolved(self):
        d = doc(finding("R-010", status="reopened", prior_id="R-001"))
        r = pub.plan(d, prior(finding("R-001")), [thread("R-001", resolved=True)], DIFF)
        self.assertEqual(r["actions"]["unresolve"][0]["thread"], "T-R-001")
        self.assertIn("status=reopened", r["actions"]["unresolve"][0]["body"])
        self.assertEqual(r["state"]["reopen_counts"], {"R-001": 1})
        self.assertEqual(r["actions"]["comments"], [])

    def test_fixed_and_accepted_are_resolved(self):
        d = doc(finding("R-010", status="fixed", prior_id="R-001"),
                finding("R-011", status="accepted_pushback", prior_id="R-002", file="b.py", rule="CWE-20"))
        r = pub.plan(d, prior(finding("R-001"), finding("R-002")),
                     [thread("R-001"), thread("R-002")], DIFF)
        self.assertEqual({x["thread"] for x in r["actions"]["resolve"]}, {"T-R-001", "T-R-002"})
        self.assertEqual(r["state"]["accepted"], [{"id": "R-002", "file": "b.py", "rule": "CWE-20"}])

    def test_rejected_pushback_gets_a_reply(self):
        d = doc(finding("R-010", status="still_open", prior_id="R-001"))
        r = pub.plan(d, prior(finding("R-001")), [thread("R-001", last_author="dev")], DIFF)
        self.assertEqual(len(r["actions"]["reply"]), 1)
        r = pub.plan(d, prior(finding("R-001")), [thread("R-001")], DIFF)
        self.assertEqual(r["actions"]["reply"], [])  # no reply when the bot spoke last

    def test_dropped_prior_finding_is_kept_open(self):
        r = pub.plan(doc(), prior(finding("R-001")), [thread("R-001")], DIFF)
        carried = [f for f in r["state"]["findings"] if f.get("prior_id") == "R-001"]
        self.assertEqual(carried[0]["status"], "still_open")
        self.assertTrue(any(s.startswith("unaccounted") for s in r["actions"]["signals"]))
        self.assertFalse(r["state"]["escalated"])

    def test_oscillation_escalates(self):
        p = prior(accepted=[{"id": "R-001", "file": "app.py", "rule": "CWE-89"}])
        r = pub.plan(doc(finding("R-020")), p, [], DIFF)
        self.assertTrue(r["state"]["escalated"])

    def test_repeated_reopen_escalates(self):
        p = prior(finding("R-001"), reopen_counts={"R-001": 2})
        r = pub.plan(doc(finding("R-030", status="reopened", prior_id="R-001")), p,
                     [thread("R-001", resolved=True)], DIFF)
        self.assertTrue(r["state"]["escalated"])

    def test_round_cap(self):
        p = prior()
        p["round"] = 5
        self.assertTrue(pub.plan(doc(), p, [], DIFF)["state"]["escalated"])

    def test_escalation_is_per_round(self):
        p = prior(escalated=True)
        self.assertFalse(pub.plan(doc(), p, [], DIFF)["state"]["escalated"])


class CostAndSummaryTest(unittest.TestCase):
    def test_price_change(self):
        u = {"input_tokens": 1_000_000, "output_tokens": 100_000}
        self.assertEqual(pub.cost(u, dt.date(2026, 11, 30)), 3.0)
        self.assertEqual(pub.cost(u, dt.date(2026, 12, 1)), 6.0)
        self.assertEqual(pub.cost(None), 0.0)

    def test_claude_round_uses_reported_cost_and_says_so(self):
        cost, note = pub.round_cost_of({"engine": "claude", "cost_usd": 1.23, "usage": {"input_tokens": 9}})
        self.assertEqual(cost, 1.23)
        self.assertIn("Claude", note)
        u = {"input_tokens": 1_000_000}
        self.assertEqual(pub.round_cost_of({"usage": u}), (pub.cost(u), ""))
        r = pub.plan(doc(), st.empty_state(), [], DIFF)
        self.assertIn("Claude Opus 5.5 reviewed", pub.summary_body(doc(), r, 1.23, note))
        self.assertFalse(r["actions"]["signals"])

    def test_summary_has_markers_and_state(self):
        r = pub.plan(doc(finding("R-001"), finding("R-002", severity="nit")), st.empty_state(), [], DIFF)
        r["state"]["cost_usd"] = [0.5]
        body = pub.summary_body(doc(), r, 0.5)
        self.assertIn(st.SUMMARY_MARKER, body)
        self.assertIn(pub.NITS_MARKER, body)
        self.assertEqual(st.decode(body)["round"], 1)
        self.assertIn("| 0 | 1 | 0 | 0 | 1 |", body)


if __name__ == "__main__":
    unittest.main()
