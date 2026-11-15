import io
import json
import unittest
from unittest import mock

from tests.helpers import BOT, comment, finding, thread
import state as st

TRUSTED_USER = {"type": "Bot", "login": "github-actions[bot]"}


def summary_comment(state_dict, user=TRUSTED_USER):
    return {"id": 1, "user": user, "body": f"{st.SUMMARY_MARKER}\n{st.encode(state_dict)}"}


class BackfillThreadsTest(unittest.TestCase):
    def test_default_dry_run_identifies_closed_candidates_and_lists_orphans_without_writes(self):
        import backfill_threads as bf

        s = st.empty_state()
        s.update(round=2, findings=[
            finding("R-010", status="fixed", prior_id="R-001"),
            finding("R-011", status="still_open", prior_id="R-002"),
            # R-003 referenced by both a closed and an open finding -> must NOT sweep!
            finding("R-012", status="fixed", prior_id="R-003"),
            finding("R-013", status="reopened", prior_id="R-003"),
        ])
        threads = [
            thread("R-001", resolved=False),                           # closed -> candidate
            thread("R-002", resolved=False),                           # open -> skip
            thread("R-003", resolved=False),                           # mixed open+closed -> skip
            thread("R-004", resolved=True),                            # already resolved -> skip
            dict(thread("R-090", resolved=False), isOutdated=True),    # outdated orphan
            dict(thread("R-091", resolved=False), isOutdated=False),   # non-outdated orphan
            # Decoy opened by human -> ignored completely
            thread("R-001", tid="DECOY", opener=comment("mallory", "<!-- pr-guardian:finding id=R-001 severity=P1 -->",
                                                        association="NONE")),
        ]

        out = io.StringIO()
        with mock.patch.object(bf.gh, "api", return_value=[summary_comment(s)]), \
                mock.patch.object(bf.th, "fetch", return_value=threads), \
                mock.patch.object(bf.gh, "graphql") as gql, \
                mock.patch.object(bf.sys, "argv", ["backfill_threads.py", "--repo", "o/r", "--pr", "7"]), \
                mock.patch("sys.stdout", out):
            self.assertEqual(bf.main(), 0)
            gql.assert_not_called()

        report = json.loads(out.getvalue())
        self.assertEqual(report["mode"], "dry-run")
        self.assertEqual([c["marker_id"] for c in report["candidates"]], ["R-001"])
        self.assertEqual({o["marker_id"] for o in report["orphans"]}, {"R-090", "R-091"})
        self.assertEqual(report["swept"], [])

    def test_include_orphans_only_sweeps_outdated_orphans(self):
        import backfill_threads as bf

        s = dict(st.empty_state(), round=1, findings=[])
        threads = [
            dict(thread("R-090", resolved=False), isOutdated=True),
            dict(thread("R-091", resolved=False), isOutdated=False),
        ]
        plan = bf.plan_pr(7, s, threads, include_orphans=True)
        self.assertEqual([c["marker_id"] for c in plan["candidates"]], ["R-090"])
        self.assertEqual(len(plan["orphans"]), 2)

    def test_apply_posts_swept_marker_idempotently_resolves_and_honours_max_cap(self):
        import backfill_threads as bf
        import publish_review as pub

        s = dict(st.empty_state(), round=2, findings=[
            finding("R-010", status="fixed", prior_id="R-001"),
            finding("R-011", status="accepted_pushback", prior_id="R-002"),
            finding("R-012", status="fixed", prior_id="R-003"),
        ])
        threads = [
            # R-001 already has the swept status marker as its last bot comment -> skip REPLY, only RESOLVE!
            thread("R-001", replies=[comment(
                BOT,
                "<!-- pr-guardian:status id=R-001 status=swept -->\n✅ Swept: this finding is closed in pr-guardian's state.",
            )]),
            thread("R-002"),
            thread("R-003"),
        ]
        gql_calls = []
        out = io.StringIO()
        with mock.patch.object(bf.gh, "api", return_value=[summary_comment(s)]), \
                mock.patch.object(bf.th, "fetch", return_value=threads), \
                mock.patch.object(bf.gh, "graphql", side_effect=lambda q, **v: gql_calls.append((q, v))), \
                mock.patch.object(bf.sys, "argv", ["backfill_threads.py", "--repo", "o/r", "--pr", "7",
                                                   "--apply", "--max", "2"]), \
                mock.patch("sys.stdout", out):
            self.assertEqual(bf.main(), 0)

        report = json.loads(out.getvalue())
        self.assertEqual(report["mode"], "apply")
        self.assertEqual([x["marker_id"] for x in report["swept"]], ["R-001", "R-002"])
        # T-R-001 skipped REPLY (1 call: RESOLVE); T-R-002 did REPLY + RESOLVE (2 calls); T-R-003 stopped by --max 2
        self.assertEqual(gql_calls, [
            (pub.RESOLVE, {"id": "T-R-001"}),
            (pub.REPLY, {
                "id": "T-R-002",
                "body": "<!-- pr-guardian:status id=R-002 status=swept -->\n"
                        "✅ Swept: this finding is closed in pr-guardian's state.",
            }),
            (pub.RESOLVE, {"id": "T-R-002"}),
        ])

    def test_forged_or_missing_state_never_sweeps_anything_and_all_open_walks_prs(self):
        import backfill_threads as bf

        forged = summary_comment(dict(st.empty_state(), round=1), user={"type": "User", "login": "mallory"})

        def fake_api(path, method="GET", body=None, paginate=False, token=None):
            if "pulls?state=open" in path:
                return [{"number": 3}, {"number": 4}]
            if "issues/3/comments" in path:
                return [forged]
            if "issues/4/comments" in path:
                return [summary_comment(dict(st.empty_state(), round=2,
                                             findings=[finding("R-010", status="fixed", thread_key="R-005")]))]
            return []

        out = io.StringIO()
        with mock.patch.object(bf.gh, "api", side_effect=fake_api), \
                mock.patch.object(bf.th, "fetch", side_effect=lambda repo, pr: [thread("R-005")]), \
                mock.patch.object(bf.gh, "graphql") as gql, \
                mock.patch.object(bf.sys, "argv", ["backfill_threads.py", "--repo", "o/r", "--all-open",
                                                   "--include-orphans"]), \
                mock.patch("sys.stdout", out):
            self.assertEqual(bf.main(), 0)
            gql.assert_not_called()

        report = json.loads(out.getvalue())
        # PR #3 had only a forged comment -> has_state False, 0 candidates; PR #4 matched R-005 via thread_key!
        self.assertEqual([(c["pr"], c["marker_id"]) for c in report["candidates"]], [(4, "R-005")])

    def test_earlier_round_fixed_finding_survives_subsequent_round_for_backfill(self):
        import backfill_threads as bf
        import publish_review as pub
        from tests.helpers import DIFF, doc

        r1 = pub.plan(
            doc(finding("R-001", start=2, end=2), finding("R-002", start=3, end=3)),
            st.empty_state(),
            [],
            DIFF,
        )
        r2 = pub.plan(
            doc(finding("R-010", status="fixed", prior_id="R-001"),
                finding("R-011", status="still_open", prior_id="R-002")),
            r1["state"],
            [thread("R-001"), thread("R-002")],
            DIFF,
        )
        r3 = pub.plan(
            doc(finding("R-020", status="fixed", prior_id="R-011")),
            r2["state"],
            [thread("R-001", resolved=False), thread("R-002", resolved=False)],
            DIFF,
        )
        plan = bf.plan_pr(7, r3["state"], [thread("R-001", resolved=False), thread("R-002", resolved=False)])
        self.assertEqual({c["marker_id"] for c in plan["candidates"]}, {"R-001", "R-002"})
        self.assertEqual(plan["orphans"], [])


if __name__ == "__main__":
    unittest.main()
