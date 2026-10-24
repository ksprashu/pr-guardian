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
