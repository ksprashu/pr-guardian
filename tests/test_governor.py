import copy
import unittest
from unittest import mock

from tests.helpers import *  # noqa: F401,F403
import governor as g


class GovernorTest(unittest.TestCase):
    def test_missing_ruleset(self):
        self.assertEqual(g.ruleset_drift(None), ["ruleset missing"])

    def test_echoed_ruleset_with_defaults_is_clean(self):
        have = copy.deepcopy(g.desired_ruleset())
        have.update(id=1, source="o/r", source_type="Repository")
        have["rules"][3]["parameters"]["automatic_copilot_code_review_enabled"] = False
        have["rules"].reverse()
        self.assertEqual(g.ruleset_drift(have), [])

    def test_drift_detected(self):
        for mutate, needle in [
            (lambda r: r.update(enforcement="disabled"), "enforcement"),
            (lambda r: r.update(bypass_actors=[{"actor_id": 5, "actor_type": "RepositoryRole"}]), "bypass"),
            (lambda r: r["rules"].pop(0), "deletion"),
            (lambda r: r["rules"][3]["parameters"].update(required_review_thread_resolution=False), "pull_request"),
            (lambda r: r["rules"][4]["parameters"]["required_status_checks"][0].update(integration_id=1),
             "required_status_checks"),
        ]:
            have = copy.deepcopy(g.desired_ruleset())
            mutate(have)
            drift = g.ruleset_drift(have)
            self.assertTrue(any(needle in d for d in drift), (needle, drift))

    def test_settings_drift(self):
        repo = dict(g.SETTINGS)
        self.assertEqual(g.settings_drift(repo), [])
        repo["allow_merge_commit"] = True
        self.assertEqual(g.settings_drift(repo), ["setting allow_merge_commit=True"])

    def test_caller_render(self):
        text = g.render_caller("0123abc")
        self.assertIn("review.yml@0123abc", text)
        self.assertIn("guardian_ref: 0123abc", text)
        self.assertNotIn("{{REF}}", text)


if __name__ == "__main__":
    unittest.main()


class ReconcileSettingsTest(unittest.TestCase):
    """user/repos list entries omit the merge settings; reconcile must read the full repo."""

    def test_settings_read_from_full_repo_not_list_entry(self):
        listed = {"full_name": "o/r", "default_branch": "", "size": 0}  # list shape: no allow_* keys
        full = dict(listed, **g.SETTINGS)
        with mock.patch.object(g.gh, "api", side_effect=lambda path, *a, **k: full if path == "repos/o/r" else []):
            out = g.reconcile(listed, "v1", dry=True, have_key=False)
        self.assertFalse([d for d in out["drift"] if d.startswith("setting ")], out["drift"])


class DriftReportTest(unittest.TestCase):
    """The report is written with REPORT_TOKEN (the workflow token), not the governor PAT."""

    def run_main(self, issues):
        calls = []

        def api(path, method="GET", body=None, paginate=False, token=None):
            calls.append((path, method, token))
            return issues if path.startswith("repos/o/pr-guardian/issues?") else None

        env = {"PRG_OWNER": "o", "REPORT_TOKEN": "wf-token", "GEMINI_API_KEY": ""}
        with mock.patch.dict(g.os.environ, env), mock.patch.object(g.gh, "api", side_effect=api), \
                mock.patch.object(g, "list_repos", return_value=[]), \
                mock.patch.object(g.sys, "argv", ["governor.py", "--dry-run", "--report-issue"]), \
                mock.patch("builtins.print"):
            g.main()
        return [c for c in calls if c[0].startswith("repos/o/pr-guardian/issues")]

    def test_updates_trusted_report_with_workflow_token(self):
        issues = [{"number": 9, "title": "Governor drift report", "user": {"login": "mallory"}},
                  {"number": 1, "title": "Governor drift report", "user": {"login": "o"}}]
        calls = self.run_main(issues)
        self.assertEqual(calls[-1], ("repos/o/pr-guardian/issues/1", "PATCH", "wf-token"))
        self.assertTrue(all(token == "wf-token" for _, _, token in calls))

    def test_creates_report_when_only_untrusted_match(self):
        issues = [{"number": 9, "title": "Governor drift report", "user": {"login": "mallory"}}]
        self.assertEqual(self.run_main(issues)[-1], ("repos/o/pr-guardian/issues", "POST", "wf-token"))


class GitlessRepoTest(unittest.TestCase):
    """A repo with a size but no branches (yo-angular-express-seed) waits like an empty repo."""

    def test_size_without_branch_is_empty(self):
        repo = {"full_name": "o/r", "default_branch": "master", "size": 56}

        def api(path, *a, **k):
            if path == "repos/o/r":
                return dict(repo, **g.SETTINGS)
            if path == "repos/o/r/branches/master":
                raise g.gh.GhError("gh api repos/o/r/branches/master… failed: Git Repository is empty. (HTTP 409)")
            return []

        with mock.patch.object(g.gh, "api", side_effect=api):
            out = g.reconcile(repo, "v1", dry=True, have_key=False)
        self.assertIn("empty repo: caller and ruleset wait for the first commit", out["drift"])
        self.assertFalse(out["errors"][1:], out["errors"])


class VerdictAppIdTest(unittest.TestCase):
    """GHSA-v7qp-pmhq-cf47: the verdict's required integration is configurable, validated up front."""

    def env(self, value):
        env = {k: v for k, v in g.os.environ.items() if k != "PRG_VERDICT_APP_ID"}
        if value is not None:
            env["PRG_VERDICT_APP_ID"] = value
        return mock.patch.dict(g.os.environ, env, clear=True)

    def pinned(self):
        return g.desired_ruleset()["rules"][4]["parameters"]["required_status_checks"]

    def test_unset_or_blank_keeps_github_actions(self):
        for value in (None, "", "   ", "\n"):
            with self.subTest(value=value), self.env(value):
                self.assertEqual(g.verdict_app_id(), g.ACTIONS_APP_ID)
                self.assertEqual(self.pinned(), [{"context": g.VERDICT_CONTEXT, "integration_id": 15368}])

    def test_positive_integer_overrides_dynamically(self):
        for value, want in (("123456", 123456), (" 987\n", 987), ("1", 1)):
            with self.subTest(value=value), self.env(value):
                self.assertEqual(g.verdict_app_id(), want)
                self.assertEqual(self.pinned()[0]["integration_id"], want)

    def test_override_makes_actions_pinned_ruleset_drift(self):
        with self.env(None):
            have = copy.deepcopy(g.desired_ruleset())
        with self.env("123456"):
            self.assertIn("ruleset rule required_status_checks differs", g.ruleset_drift(have))
        with self.env(None):
            self.assertEqual(g.ruleset_drift(have), [])

    def test_invalid_values_raise(self):
        for value in ("0", "00", "007", "-5", "+5", "1.5", "1e3", "1_000", "0x10", "12a", "abc",
                      "١٢٣", "²", "１２", "1 2", "15368;", "None"):
            with self.subTest(value=value), self.env(value), self.assertRaises(ValueError):
                g.verdict_app_id()

    def test_main_exits_2_before_any_api_call(self):
        with self.env("not-an-id"), mock.patch.object(g.gh, "api") as api, \
                mock.patch.object(g, "list_repos") as lr, \
                mock.patch.object(g.sys, "argv", ["governor.py", "--dry-run"]), \
                mock.patch("sys.stderr"), mock.patch("builtins.print"):
            self.assertEqual(g.main(), 2)
        api.assert_not_called()
        lr.assert_not_called()

    def test_main_runs_with_valid_override(self):
        with self.env("123456"), mock.patch.dict(g.os.environ, {"PRG_OWNER": "o", "GEMINI_API_KEY": ""}), \
                mock.patch.object(g, "list_repos", return_value=[]) as lr, \
                mock.patch.object(g.sys, "argv", ["governor.py", "--dry-run"]), \
                mock.patch("builtins.print"):
            self.assertEqual(g.main(), 0)
        lr.assert_called_once_with("o")
