import unittest

from tests.helpers import finding
import build_context as bc
import state as st


def meta(*paths):
    return {"files": [{"path": p, "additions": 1, "deletions": 0} for p in paths]}


class TriageTest(unittest.TestCase):
    def test_docs_only_skips(self):
        self.assertTrue(bc.triage(meta("README.md", "docs/x.png"), None, st.empty_state())["skip_model"])

    def test_agent_instructions_are_reviewed(self):
        self.assertFalse(bc.triage(meta("skills/x/SKILL.md"), None, st.empty_state())["skip_model"])

    def test_code_runs(self):
        self.assertFalse(bc.triage(meta("README.md", "app.py"), None, st.empty_state())["skip_model"])

    def test_open_prior_findings_force_review(self):
        s = st.empty_state()
        s["findings"] = [finding()]
        self.assertFalse(bc.triage(meta("README.md"), None, s)["skip_model"])

    def test_lockfile_needs_clean_scan(self):
        clean = {"tools": [{"tool": "osv-scanner", "status": "ran"}], "leads": []}
        dirty = {"tools": [{"tool": "osv-scanner", "status": "ran"}], "leads": [{"file": "uv.lock"}]}
        missing = {"tools": [{"tool": "osv-scanner", "status": "skipped"}], "leads": []}
        self.assertTrue(bc.triage(meta("uv.lock"), clean, st.empty_state())["skip_model"])
        self.assertFalse(bc.triage(meta("uv.lock"), dirty, st.empty_state())["skip_model"])
        self.assertFalse(bc.triage(meta("uv.lock"), missing, st.empty_state())["skip_model"])
        self.assertFalse(bc.triage(meta("uv.lock"), None, st.empty_state())["skip_model"])
        self.assertFalse(bc.triage(meta("uv.lock"), {"tools": [], "leads": []}, st.empty_state())["skip_model"])


class ScanShapeTest(unittest.TestCase):
    def test_run_scanners_dict_shape(self):
        scan = {"tools": {"osv-scanner": {"status": "ran", "reason": "", "leads": 1},
                          "semgrep": {"status": "skipped", "reason": "not installed", "leads": 0}},
                "leads": [{"tool": "osv-scanner", "rule_id": "GHSA-x", "file": "uv.lock", "line": None,
                           "message": "vuln", "cwe": ["CWE-79", "CWE-80"]}]}
        text = bc.render_leads(scan)
        self.assertIn("**semgrep**: skipped (not installed)", text)
        self.assertIn("GHSA-x CWE-79,CWE-80", text)
        clean = {"tools": {"osv-scanner": {"status": "ran"}, "semgrep": {"status": "ran"}}, "leads": []}
        self.assertTrue(bc.triage(meta("uv.lock"), clean, st.empty_state())["skip_model"])
        broken = {"tools": {"osv-scanner": {"status": "timeout"}}, "leads": []}
        self.assertFalse(bc.triage(meta("uv.lock"), broken, st.empty_state())["skip_model"])


class DiffTest(unittest.TestCase):
    def test_truncation_is_stated(self):
        big = "diff --git a/a.py b/a.py\n" + "+x\n" * 300_000
        out, truncated = bc.render_diff(big)
        self.assertEqual(truncated, ["a.py"])
        self.assertIn("truncated", out)
        self.assertLess(len(out), bc.PER_FILE_BUDGET + 200)


if __name__ == "__main__":
    unittest.main()
