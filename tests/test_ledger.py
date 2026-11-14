import datetime as dt
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import finding
import state as st

TRUSTED = {"type": "Bot", "login": "github-actions[bot]"}


def bot_summary(s):
    return {"id": 1, "user": TRUSTED, "body": f"{st.SUMMARY_MARKER}\n{st.encode(s)}"}


class LedgerTest(unittest.TestCase):
    def _fixture_api(self, existing_issues=None, viewer="owner"):
        # PR #1: forged summary by non-bot user -> must be ignored completely!
        forged_state = dict(st.empty_state(), round=99, cost_usd=[999.0])
        forged_comment = {
            "id": 9,
            "user": {"type": "User", "login": "mallory"},
            "body": f"{st.SUMMARY_MARKER}\n{st.encode(forged_state)}",
        }

        # PR #2: legacy state without sha_rounds, guardian_ref, engine, rounds_log, or raised_by
        legacy_state = {
            "round": 2,
            "findings": [
                finding("R-001", severity="P1", status="fixed", rule="CWE-89"),
                finding("R-002", severity="P2", status="still_open", rule="CWE-79"),
            ],
            "accepted": [],
            "reopen_counts": {},
            "escalated": False,
            "escalation_reasons": [],
            "cost_usd": [0.25, 0.15],
            "last_reviewed_sha": "abc",
            "last_reviewed_base": "main",
        }

        # PR #3: modern state with guardian_ref, engine, sha_rounds, escalation_reasons, and raised_by
        modern_state = st.empty_state()
        modern_state.update(
            round=4,
            sha_rounds=2,
            guardian_ref="0123456789abcdef0123456789abcdef01234567",
            engine="agy",
            escalation_reasons=["round cap: 6 reviewed commits"],
            cost_usd=[0.50, 0.30],
            findings=[
                finding("R-010", severity="P1", status="fixed", rule="CWE-89", raised_by="claude"),
                finding("R-011", severity="P2", status="accepted_pushback", rule="CWE-89", raised_by="agy"),
                finding("R-012", severity="nit", status="new", rule="style", raised_by="agy"),
            ],
            accepted=[{"id": "R-011", "file": "app.py", "rule": "CWE-89"}],
        )

        # PR #4: outside window (closed before --since, updated before --since -> stops pagination!)
        pulls = [
            {"number": 3, "updated_at": "2026-11-12T10:00:00Z", "closed_at": "2026-11-12T09:00:00Z",
             "merged_at": "2026-11-12T09:00:00Z"},
            {"number": 2, "updated_at": "2026-11-10T10:00:00Z", "closed_at": "2026-11-10T09:00:00Z",
             "merged_at": None},
            {"number": 1, "updated_at": "2026-11-09T10:00:00Z", "closed_at": "2026-11-09T09:00:00Z",
             "merged_at": "2026-11-09T09:00:00Z"},
            # Updated in window, closed BEFORE window -> filtered out, continues scanning
            {"number": 5, "updated_at": "2026-11-08T10:00:00Z", "closed_at": "2026-10-20T09:00:00Z",
             "merged_at": None},
            # Updated BEFORE --since -> stops early without fetching comments for PR #4!
            {"number": 4, "updated_at": "2026-10-01T10:00:00Z", "closed_at": "2026-10-01T09:00:00Z",
             "merged_at": "2026-10-01T09:00:00Z"},
        ]

        calls = []

        def fake_api(path, method="GET", body=None, paginate=False, token=None):
            calls.append((path, method, body))
            if path == "user":
                return {"login": viewer}
            if path.startswith("repos/o/r/pulls?state=closed"):
                return pulls
            if "issues/1/comments" in path:
                return [forged_comment]
            if "issues/2/comments" in path:
                return [bot_summary(legacy_state)]
            if "issues/3/comments" in path:
                return [bot_summary(modern_state)]
            if "issues/4/comments" in path or "issues/5/comments" in path:
                raise AssertionError(f"should not fetch comments for out-of-window PR: {path}")
            if method == "GET" and path.startswith("repos/o/gov/issues"):
                return existing_issues or []
            return {"number": 42, "id": 42}

        return fake_api, calls

    def test_collection_window_filtering_forged_exclusion_and_aggregations(self):
        import ledger

        fake_api, _ = self._fixture_api()
        with mock.patch.object(ledger.gh, "api", side_effect=fake_api):
            records = ledger.collect_repo("o/r", dt.date(2026, 11, 1), dt.date(2026, 11, 14))

        # Only PR #3 and PR #2 survive (PR #1 forged ignored, PR #5 closed before window, PR #4 stopped)
        self.assertEqual([r["pr"] for r in records], [3, 2])
        by_pr = {r["pr"]: r for r in records}
        self.assertEqual(by_pr[2]["sha_rounds"], 2)  # legacy fallback to round
        self.assertAlmostEqual(by_pr[2]["cost"], 0.40, places=4)
        self.assertFalse(by_pr[2]["escalated_ever"])
        self.assertTrue(by_pr[3]["merged"])
        self.assertEqual(by_pr[3]["sha_rounds"], 2)
        self.assertAlmostEqual(by_pr[3]["cost"], 0.80, places=4)
        self.assertTrue(by_pr[3]["escalated_ever"])

        report = ledger.build_report(["o/r"], records, dt.date(2026, 11, 1), dt.date(2026, 11, 14))
        overall = report["overall"]
        self.assertEqual(overall["prs"], 2)
        self.assertEqual(overall["merged"], 1)
        self.assertAlmostEqual(overall["total_cost_usd"], 1.20, places=4)
        self.assertAlmostEqual(overall["avg_cost_usd"], 0.60, places=4)
        self.assertAlmostEqual(overall["escalation_rate"], 0.5, places=4)
        # CWE-89: 2 fixed (PR #2 R-001, PR #3 R-010) + 1 accepted_pushback (PR #3 R-011) -> FP proxy = 1/3
        cwe89 = report["by_rule"]["CWE-89"]
        self.assertEqual((cwe89["fixed"], cwe89["accepted_pushback"], cwe89["open_at_close"]), (2, 1, 0))
        self.assertAlmostEqual(cwe89["false_positive_proxy"], round(1 / 3, 4), places=4)
        # CWE-79: 0 fixed, 0 accepted_pushback, 1 open -> FP proxy is None (denominator 0)
        cwe79 = report["by_rule"]["CWE-79"]
        self.assertEqual(cwe79["open_at_close"], 1)
        self.assertIsNone(cwe79["false_positive_proxy"])
        # Engine attribution: R-010 raised_by claude (fixed=1 -> fp_proxy 0.0); R-011 raised_by agy (accepted=1 -> 1.0)
        self.assertEqual(report["by_engine"]["claude"]["fixed"], 1)
        self.assertEqual(report["by_engine"]["claude"]["false_positive_proxy"], 0.0)
        self.assertEqual(report["by_engine"]["agy"]["accepted_pushback"], 1)
        self.assertEqual(report["by_engine"]["agy"]["false_positive_proxy"], 1.0)
        # Guardian ref 12-char key
        self.assertIn("0123456789ab", report["by_guardian_ref"])

        md = ledger.render_markdown(report)
        self.assertTrue(md.startswith(ledger.LEDGER_MARKER + "\n"))
        self.assertIn("| Repo | PRs |", md)
        self.assertIn("| Rule |", md)
        self.assertIn("`CWE-89`", md)

    def test_cli_json_markdown_and_idempotent_issue_upsert(self):
        import ledger

        # 1) Forged marker issue by mallory -> ignored, creates new issue via POST!
        forged_issue = {"number": 9, "user": {"type": "User", "login": "mallory"},
                        "body": f"{ledger.LEDGER_MARKER}\nfake"}
        fake_api_post, calls_post = self._fixture_api(existing_issues=[forged_issue], viewer="owner")
        with tempfile.TemporaryDirectory() as tmp:
            jpath = Path(tmp, "out.json")
            mpath = Path(tmp, "out.md")
            argv = ["ledger.py", "--repo", "o/r", "--since", "2026-11-01", "--until", "2026-11-14",
                    "--json", str(jpath), "--markdown", str(mpath), "--post-issue", "o/gov"]
            with mock.patch.object(ledger.gh, "api", side_effect=fake_api_post), \
                    mock.patch.object(ledger.sys, "argv", argv):
                self.assertEqual(ledger.main(), 0)
            self.assertTrue(jpath.is_file())
            self.assertTrue(mpath.read_text(encoding="utf-8").startswith(ledger.LEDGER_MARKER))

        issue_writes = [c for c in calls_post if c[0].startswith("repos/o/gov/issues") and c[1] in ("POST", "PATCH")]
        self.assertEqual(len(issue_writes), 1)
        self.assertEqual(issue_writes[0][1], "POST")
        self.assertEqual(issue_writes[0][0], "repos/o/gov/issues")

        # 2) Existing trusted issue (by github-actions[bot] or token's own login) -> PATCHes in place!
        trusted_issue = {"number": 15, "user": TRUSTED, "body": f"{ledger.LEDGER_MARKER}\nold"}
        fake_api_patch, calls_patch = self._fixture_api(existing_issues=[forged_issue, trusted_issue], viewer="owner")
        argv_patch = ["ledger.py", "--repo", "o/r", "--since", "2026-11-01", "--post-issue", "o/gov"]
        with mock.patch.object(ledger.gh, "api", side_effect=fake_api_patch), \
                mock.patch.object(ledger.sys, "argv", argv_patch):
            self.assertEqual(ledger.main(), 0)
        issue_writes_2 = [c for c in calls_patch if c[0].startswith("repos/o/gov/issues") and c[1] in ("POST", "PATCH")]
        self.assertEqual(len(issue_writes_2), 1)
        self.assertEqual(issue_writes_2[0][1], "PATCH")
        self.assertEqual(issue_writes_2[0][0], "repos/o/gov/issues/15")

    def test_markdown_sanitises_untrusted_rule_names_and_owner_login_issue_matches(self):
        import ledger

        s = dict(st.empty_state(), round=1, findings=[
            finding("R-001", rule="CWE-89 | @owner <!-- pr-guardian:ledger -->\nx", status="fixed"),
        ])
        rec = ledger.summarize_pr("o/r", {"number": 1, "closed_at": "2026-11-10T00:00:00Z", "merged_at": None}, s)
        rep = ledger.build_report(["o/r"], [rec], dt.date(2026, 11, 1), None)
        md = ledger.render_markdown(rep)
        self.assertEqual(md.count("<!--"), 1)  # only the top ledger marker
        self.assertNotIn("@owner", md)

        owner_issue = {"number": 21, "user": {"type": "User", "login": "owner"},
                       "body": f"{ledger.LEDGER_MARKER}\nprev"}
        fake_api, calls = self._fixture_api(existing_issues=[owner_issue], viewer="owner")
        with mock.patch.object(ledger.gh, "api", side_effect=fake_api):
            ledger.upsert_ledger_issue("o/gov", md)
        writes = [c for c in calls if c[1] in ("POST", "PATCH")]
        self.assertEqual(writes[0][:2], ("repos/o/gov/issues/21", "PATCH"))


if __name__ == "__main__":
    unittest.main()
