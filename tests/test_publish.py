import datetime as dt
import os
import tempfile
import unittest
from unittest import mock

from tests.helpers import DIFF, doc, finding, thread
import gh
import publish_review as pub
import state as st
import threads as th


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
        self.assertTrue(body.startswith("<!-- pr-guardian:finding id=R-001 severity=P1 key=R-001 -->"))
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
                     [thread("R-001"), thread("R-002", path="b.py", rule="CWE-20")], DIFF)
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


def next_round(result):
    """What the next round's build_context hands publish as prior state."""
    return st.decode(st.encode(result["state"]))


class DriftTest(unittest.TestCase):
    """Ids are renumbered every round; prior_id only points one round back (#15)."""

    def test_three_round_drift_resolves_the_original_thread(self):
        t = [thread("R-001")]
        r1 = pub.plan(doc(finding("R-001")), st.empty_state(), [], DIFF)
        self.assertEqual(r1["state"]["findings"][0]["thread_key"], "R-001")
        r2 = pub.plan(doc(finding("R-005", status="still_open", prior_id="R-001")), next_round(r1), t, DIFF)
        self.assertEqual(r2["actions"]["comments"], [])
        self.assertEqual(r2["state"]["findings"][0]["thread_key"], "R-001")
        r3 = pub.plan(doc(finding("R-003", status="fixed", prior_id="R-005")), next_round(r2), t, DIFF)
        self.assertEqual([x["thread"] for x in r3["actions"]["resolve"]], ["T-R-001"])
        self.assertIn("status=fixed", r3["actions"]["resolve"][0]["body"])
        self.assertIn("id=R-001", r3["actions"]["resolve"][0]["body"])
        self.assertEqual(r3["actions"]["unmatched"], [])

    def test_drift_does_not_open_a_duplicate_thread(self):
        t = [thread("S-001", rule="CWE-78")]
        r1 = pub.plan(doc(finding("S-001", rule="CWE-78")), st.empty_state(), [], DIFF)
        r2 = pub.plan(doc(finding("S-002", status="still_open", prior_id="S-001", rule="CWE-78")),
                      next_round(r1), t, DIFF)
        r3 = pub.plan(doc(finding("S-003", status="still_open", prior_id="S-002", rule="CWE-78")),
                      next_round(r2), t, DIFF)
        self.assertEqual(r3["actions"]["comments"], [])
        self.assertEqual(r3["actions"]["outside"], [])

    def test_reopen_count_survives_drift(self):
        t = [thread("R-001", resolved=True)]
        p = prior(finding("R-001", thread_key="R-001"))
        for n, new_id in enumerate(["R-004", "R-007", "R-002"], start=1):
            prev = p["findings"][0]["id"]
            r = pub.plan(doc(finding(new_id, status="reopened", prior_id=prev)), p, t, DIFF)
            self.assertEqual(r["state"]["reopen_counts"]["R-001"], n)
            p = next_round(r)
        self.assertTrue(r["state"]["escalated"])

    def test_new_thread_marker_carries_the_key(self):
        # Outside the diff in round 1 (no thread), inside it in round 2: the marker keeps the key.
        r1 = pub.plan(doc(finding("R-002", start=40, end=41)), st.empty_state(), [], DIFF)
        r2 = pub.plan(doc(finding("R-009", status="still_open", prior_id="R-002")), next_round(r1), [], DIFF)
        body = pub.finding_body(r2["actions"]["comments"][0], True)
        self.assertIn("id=R-009 severity=P1 key=R-002", body)
        r3 = pub.plan(doc(finding("R-004", status="fixed", prior_id="R-009")), next_round(r2),
                      [thread("R-009", key="R-002")], DIFF)
        self.assertEqual([x["thread"] for x in r3["actions"]["resolve"]], ["T-R-009"])

    def test_legacy_state_uses_the_prior_id_chain(self):
        # State written before thread_key existed: findings only carry one prior_id hop.
        p = prior(finding("R-005", status="still_open", prior_id="R-001"))
        r = pub.plan(doc(finding("R-003", status="fixed", prior_id="R-005")), p, [thread("R-001")], DIFF)
        self.assertEqual([x["thread"] for x in r["actions"]["resolve"]], ["T-R-001"])

    def test_file_rule_line_fallback(self):
        # Chain lost entirely (state from a round that never saw R-001): match on file + rule + line.
        p = prior(finding("R-008", status="still_open", prior_id="R-006", start=5, end=5))
        t = [thread("R-001", line=4), thread("R-002", line=4, rule="CWE-79"), thread("R-003", path="b.py")]
        r = pub.plan(doc(finding("R-010", status="fixed", prior_id="R-008", start=6, end=6)), p, t, DIFF)
        self.assertEqual([x["thread"] for x in r["actions"]["resolve"]], ["T-R-001"])
        self.assertEqual(r["state"]["findings"][0]["thread_key"], "R-001")

    def test_fallback_skips_far_lines_and_new_findings(self):
        p = prior(finding("R-008", prior_id="R-006"))
        far = [thread("R-001", line=300)]
        r = pub.plan(doc(finding("R-010", status="fixed", prior_id="R-008")), p, far, DIFF)
        self.assertEqual(r["actions"]["resolve"], [])
        r = pub.plan(doc(finding("R-011")), st.empty_state(), [thread("R-001")], DIFF)
        self.assertEqual(len(r["actions"]["comments"]), 1)  # "new" never borrows a thread

    def test_a_thread_is_claimed_once(self):
        p = prior(finding("R-001", thread_key="R-001"))
        d = doc(finding("R-002", status="fixed", prior_id="R-001"),
                finding("R-003", status="fixed", prior_id="R-001"))
        r = pub.plan(d, p, [thread("R-001")], DIFF)
        self.assertEqual(len(r["actions"]["resolve"]), 1)

    def test_human_threads_and_markers_are_ignored(self):
        forged = thread("R-001", opener="mallory")
        self.assertEqual(th.by_finding([forged]), {})
        p = prior(finding("R-001", thread_key="R-001"))
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id="R-001")), p, [forged], DIFF)
        self.assertEqual(r["actions"]["resolve"], [])

    def test_model_cannot_set_thread_key(self):
        d = doc(finding("R-001", thread_key="R-999", posted="summary"))
        r = pub.plan(d, st.empty_state(), [], DIFF)
        self.assertEqual(r["state"]["findings"][0]["thread_key"], "R-001")
        self.assertEqual(r["state"]["findings"][0]["posted"], "thread")

    # --- review follow-ups (Copilot on #19) ---

    def test_forged_prior_id_cannot_reach_markers_or_summary(self):
        forged = "R-001 --><!-- pr-guardian:state v1 AAAA -->"
        p = prior(finding("R-001", thread_key="R-001", posted="thread"))
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id=forged)), p, [], DIFF)
        self.assertIsNone(r["state"]["findings"][0]["prior_id"])
        r["state"]["cost_usd"] = []
        body = pub.summary_body(doc(), dict(r, thread_errors=[]), 0.0)
        self.assertNotIn("AAAA", body)
        self.assertEqual(st.decode(body)["round"], 2)

    def test_reused_id_does_not_take_another_findings_thread(self):
        # Round 3: R-009 (key R-002) continues; the model also raises an unrelated new R-002.
        p = prior(finding("R-009", status="still_open", prior_id="R-002", thread_key="R-002", posted="thread"))
        p["round"] = 2
        t = [thread("R-009", key="R-002")]
        d = doc(finding("R-002", rule="CWE-79"), finding("R-004", status="fixed", prior_id="R-009"))
        r = pub.plan(d, p, t, DIFF)
        self.assertEqual([x["thread"] for x in r["actions"]["resolve"]], ["T-R-009"])
        new = r["actions"]["comments"][0]
        self.assertEqual(new["id"], "R-002")
        self.assertNotEqual(new["thread_key"], "R-002")
        self.assertIn(f"key={new['thread_key']}", pub.finding_body(new, True))

    def test_nit_never_claims_a_thread(self):
        p = prior(finding("R-001", thread_key="R-001"))
        d = doc(finding("R-005", severity="nit", status="still_open", prior_id="R-001"),
                finding("R-006", status="fixed", prior_id="R-001"))
        r = pub.plan(d, p, [thread("R-001")], DIFF)
        self.assertEqual([x["thread"] for x in r["actions"]["resolve"]], ["T-R-001"])

    def test_unknown_prior_id_links_to_nothing(self):
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id="R-001")), st.empty_state(),
                     [thread("R-001")], DIFF)
        self.assertEqual(r["actions"]["resolve"], [])

    def test_outdated_thread_without_line_is_not_a_fallback_match(self):
        p = prior(finding("R-008", prior_id="R-006"))
        t = [thread("R-001", line=None)]
        r = pub.plan(doc(finding("R-010", status="fixed", prior_id="R-008")), p, t, DIFF)
        self.assertEqual(r["actions"]["resolve"], [])

    def test_summary_only_finding_skips_the_fallback(self):
        p = prior(finding("R-008", prior_id="R-006", posted="summary"))
        r = pub.plan(doc(finding("R-010", status="fixed", prior_id="R-008")), p, [thread("R-001")], DIFF)
        self.assertEqual(r["actions"]["resolve"], [])
        self.assertEqual(r["actions"]["unmatched"], [])

    def test_keyed_summary_finding_does_not_match_on_its_round_local_id(self):
        # R-002 was summary-only under key R-002... renumbered to R-005; another thread is keyed R-005.
        p = prior(finding("R-005", status="still_open", prior_id="R-002", thread_key="R-002", posted="summary"))
        t = [thread("R-007", key="R-005")]
        r = pub.plan(doc(finding("R-001", status="fixed", prior_id="R-005")), p, t, DIFF)
        self.assertEqual(r["actions"]["resolve"], [])

    def test_keyed_reopen_does_not_read_another_findings_legacy_counter(self):
        p = prior(finding("R-001", status="still_open", prior_id="R-004", thread_key="R-002"),
                  reopen_counts={"R-001": 2})
        r = pub.plan(doc(finding("R-009", status="reopened", prior_id="R-001")), p,
                     [thread("R-010", key="R-002", resolved=True)], DIFF)
        self.assertEqual(r["state"]["reopen_counts"]["R-002"], 1)
        self.assertFalse(r["state"]["escalated"])

    def test_dropped_finding_survives_its_id_being_reused(self):
        # Round 2 renumbers from R-001: fixes old R-002 as R-001 and silently drops old R-001.
        p = prior(finding("R-001", thread_key="R-001"), finding("R-002", thread_key="R-002"))
        r = pub.plan(doc(finding("R-001", status="fixed", prior_id="R-002")), p,
                     [thread("R-001"), thread("R-002")], DIFF)
        carried = [f for f in r["state"]["findings"] if f.get("prior_id") == "R-001"]
        self.assertEqual(len(carried), 1)
        self.assertEqual(carried[0]["status"], "still_open")
        self.assertEqual(carried[0]["thread_key"], "R-001")
        self.assertNotEqual(carried[0]["id"], "R-001")  # ids stay unique within a round
        self.assertEqual(len({f["id"] for f in r["state"]["findings"]}), 2)
        self.assertTrue(any("dropped R-001" in x for x in r["actions"]["signals"]))

    def test_legacy_chain_id_needs_same_file_and_rule(self):
        p = prior(finding("R-008", status="still_open", prior_id="R-005"))  # legacy: no thread_key
        other = thread("R-005", path="other.py", rule="CWE-79", line=300)
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id="R-008")), p, [other], DIFF)
        self.assertEqual(r["actions"]["resolve"], [])

    def test_fallback_does_not_take_an_omitted_findings_thread(self):
        # Prior R-001 (thread R-001) is omitted this round; R-008 has lost its chain.
        p = prior(finding("R-001", thread_key="R-001"),
                  finding("R-008", status="still_open", prior_id="R-006", start=4, end=4))
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id="R-008", start=4, end=4)), p,
                     [thread("R-001")], DIFF)
        self.assertEqual(r["actions"]["resolve"], [])
        self.assertTrue(any("dropped R-001" in x for x in r["actions"]["signals"]))

    def test_second_continuation_of_one_finding_gets_its_own_key(self):
        p = prior(finding("R-001", thread_key="R-001"))
        d = doc(finding("R-002", status="still_open", prior_id="R-001"),
                finding("R-003", status="still_open", prior_id="R-001", start=2, end=2))
        r = pub.plan(d, p, [thread("R-001")], DIFF)
        keys = [f["thread_key"] for f in r["state"]["findings"]]
        self.assertEqual(keys[0], "R-001")
        self.assertEqual(len(set(keys)), 2)
        self.assertEqual(len(r["actions"]["comments"]), 1)

    def test_rejected_legacy_key_is_not_reused_for_a_new_thread(self):
        # Legacy R-008 -> R-005; the R-005 thread is another file's, so it is rejected.
        p = prior(finding("R-008", status="still_open", prior_id="R-005"))
        other = thread("R-005", path="other.py", rule="CWE-79", line=300)
        r2 = pub.plan(doc(finding("R-002", status="still_open", prior_id="R-008")), p, [other], DIFF)
        new = r2["actions"]["comments"][0]
        self.assertNotEqual(new["thread_key"], "R-005")
        # Next round: the continuation is fixed; only its own new thread is resolved.
        mine = thread("R-002", key=new["thread_key"], tid="T-mine")
        r3 = pub.plan(doc(finding("R-001", status="fixed", prior_id="R-002")), next_round(r2),
                      [other, mine], DIFF)
        self.assertEqual([x["thread"] for x in r3["actions"]["resolve"]], ["T-mine"])

    # --- pr-guardian round 4 on #19 ---

    def test_keyed_finding_never_uses_the_fallback(self):
        p = prior(finding("R-001", thread_key="R-007", posted="thread"))  # its R-007 thread is gone
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id="R-001")), p, [thread("R-003")], DIFF)
        self.assertEqual(r["actions"]["resolve"], [])
        self.assertEqual(len(r["actions"]["unmatched"]), 1)

    def test_split_continuation_does_not_fall_back_to_a_nearby_thread(self):
        p = prior(finding("R-008", status="still_open", prior_id="R-001"))  # legacy
        t = [thread("R-001"), thread("R-004", line=4)]
        d = doc(finding("R-002", status="still_open", prior_id="R-008"),
                finding("R-003", status="fixed", prior_id="R-008", start=4, end=4))
        r = pub.plan(d, p, t, DIFF)
        self.assertEqual(r["actions"]["resolve"], [])
        self.assertEqual(r["actions"]["unmatched"], [])  # its sibling holds the thread

    def test_closed_prior_findings_threads_are_reserved(self):
        p = prior(finding("R-001", status="fixed", thread_key="R-001"),
                  finding("R-008", status="still_open", prior_id="R-006", start=4, end=4))
        r = pub.plan(doc(finding("R-002", status="still_open", prior_id="R-008", start=4, end=4)), p,
                     [thread("R-001", resolved=True)], DIFF)
        self.assertEqual(r["actions"]["unresolve"], [])

    def test_unknown_prior_id_is_not_reported_unmatched(self):
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id="R-001")), st.empty_state(), [], DIFF)
        self.assertEqual(r["actions"]["unmatched"], [])

    def test_carried_legacy_finding_gets_only_a_verified_key(self):
        p = prior(finding("R-008", status="still_open", prior_id="R-005"))  # legacy, app.py CWE-89
        other = thread("R-005", path="other.py", rule="CWE-79", line=300)
        r3 = pub.plan(doc(), p, [other], DIFF)
        self.assertNotEqual(r3["state"]["findings"][0].get("thread_key"), "R-005")
        carried = r3["state"]["findings"][0]["id"]
        r4 = pub.plan(doc(finding("R-002", status="fixed", prior_id=carried)), next_round(r3), [other], DIFF)
        self.assertEqual(r4["actions"]["resolve"], [])


class ThreadErrorTest(unittest.TestCase):
    """Unmatched findings and failed (un)resolves are reported, not swallowed (#16)."""

    def test_fixed_finding_without_thread_is_unmatched(self):
        p = prior(finding("R-001", thread_key="R-001", posted="thread"))
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id="R-001")), p, [], DIFF)
        self.assertEqual(r["actions"]["unmatched"][0]["finding"], "R-002")
        self.assertIn("no thread for R-001", "\n".join(pub.manual_actions(r)))

    def test_summary_only_finding_is_not_unmatched(self):
        p = prior(finding("R-001", thread_key="R-001", posted="summary"))
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id="R-001")), p, [], DIFF)
        self.assertEqual(r["actions"]["unmatched"], [])

    def _run(self, fail=False):
        p = prior(finding("R-001", thread_key="R-001", posted="thread"))
        d = doc(finding("R-002", status="fixed", prior_id="R-001"))
        r = pub.plan(d, p, [thread("R-001")], DIFF)
        calls = []

        def graphql(query, **v):
            calls.append(query)
            if query is pub.RESOLVE:
                raise gh.GhError("graphql: Resource not accessible by integration")
            return {}

        posted = {}

        def api(path, method="GET", body=None, paginate=False):
            if method in ("POST", "PATCH"):
                posted["body"] = body["body"]
            return []

        with tempfile.NamedTemporaryFile("r", suffix=".md") as summary, \
                mock.patch.object(gh, "graphql", graphql), mock.patch.object(gh, "api", api), \
                mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": summary.name}), \
                mock.patch("sys.stderr") as err:
            pub.execute("o/r", 1, "sha", d, r, 0.0)
            pub.write_step_summary(r)
            step = summary.read()
        warnings = "".join(c.args[0] for c in err.write.call_args_list)
        return r, calls, posted["body"], step, warnings

    def test_failed_resolve_is_warned_and_listed(self):
        r, calls, body, step, warnings = self._run()
        self.assertEqual(calls, [pub.REPLY, pub.RESOLVE])  # the reply still lands
        self.assertIn("::warning::could not resolve thread T-R-001", warnings)
        self.assertIn("Threads needing manual action", body)
        self.assertIn("(https://github.com/o/r/pull/1#discussion_R-001)", body)
        self.assertIn("Resource not accessible by integration", step)
        self.assertEqual(pub.exit_code(r, False), 0)
        self.assertEqual(pub.exit_code(r, True), 1)

    def test_clean_run_exits_zero_even_when_strict(self):
        r = pub.plan(doc(finding("R-001")), st.empty_state(), [], DIFF)
        self.assertEqual(pub.exit_code(r, True), 0)
        self.assertNotIn("manual action", pub.summary_body(doc(), dict(r, thread_errors=[]), 0.0))

    def test_warnings_cannot_inject_workflow_commands(self):
        p = prior(finding("R-001", thread_key="R-001", posted="thread", file="a.py\n::stop-commands::x"))
        r = pub.plan(doc(finding("R-002", status="fixed", prior_id="R-001",
                                 file="a.py\n::stop-commands::x")), p, [], DIFF)
        with mock.patch("sys.stderr") as err:
            pub.warn_unmatched(r)
        out = "".join(c.args[0] for c in err.write.call_args_list)
        self.assertEqual(out.count("\n"), 1)  # only print's own line end
        self.assertIn("%0A::stop-commands", out)


class CostAndSummaryTest(unittest.TestCase):
    def test_price_change(self):
        u = {"input_tokens": 1_000_000, "output_tokens": 100_000}
        self.assertEqual(pub.cost(u, dt.date(2026, 11, 30)), 3.0)
        self.assertEqual(pub.cost(u, dt.date(2026, 12, 1)), 6.0)
        self.assertEqual(pub.cost(None), 0.0)

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
