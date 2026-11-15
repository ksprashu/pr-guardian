"""Unit tests for scripts/step_summary.py."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tests.helpers  # noqa: F401
import step_summary as ss
import textsafe


def _run(argv, env=None):
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with mock.patch.object(sys, "argv", ["step_summary.py", *argv]), \
            mock.patch.dict(os.environ, env or {}, clear=False), \
            contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        rc = ss.main()
    return rc, buf_out.getvalue(), buf_err.getvalue()


class StepSummaryModesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.env_clean = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}

    def test_route_mode_stdout_and_append(self):
        with mock.patch.dict(os.environ, self.env_clean, clear=True):
            rc, out, _ = _run(["route", "--action", "review", "--reason", "pull_request.opened", "--pr", "42"])
        self.assertEqual(rc, 0)
        self.assertIn("review", out)
        self.assertIn("42", out)
        self.assertIn("pull_request.opened", out)

        summary_file = self.dir / "summary.md"
        summary_file.write_text("# Existing\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {**self.env_clean, "GITHUB_STEP_SUMMARY": str(summary_file)}, clear=True):
            rc, out, _ = _run(["route", "--action", "verdict", "--reason", "manual", "--pr", "7"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")
        text = summary_file.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# Existing\n"))
        self.assertIn("verdict", text)

    def test_scan_dict_and_list_tools(self):
        scan_dict = self.dir / "scan_dict.json"
        scan_dict.write_text(json.dumps({
            "status": "partial",
            "leads": [{"file": "a.py", "message": "secret title"}],
            "tools": {
                "semgrep": {"status": "ran", "leads": [{"id": 1}]},
                "trivy": {"status": "skipped", "leads": 0},
                "bad": "not-a-dict",
            },
        }), encoding="utf-8")
        ev = self.dir / "evidence.json"
        ev.write_text("{}", encoding="utf-8")
        with mock.patch.dict(os.environ, self.env_clean, clear=True):
            rc, out, _ = _run(["scan", "--scan", str(scan_dict), "--collector", str(ev)])
        self.assertEqual(rc, 0)
        self.assertIn("| semgrep | ran | 1 |", out)
        self.assertIn("| trivy | skipped | 0 |", out)
        self.assertIn("| bad | error | 0 |", out)
        self.assertIn("total leads: 1", out)
        self.assertIn("evidence: produced", out)

        scan_list = self.dir / "scan_list.json"
        scan_list.write_text(json.dumps({
            "status": "ok",
            "leads": [],
            "tools": [{"tool": "gitleaks", "status": "ran", "leads": 2}],
        }), encoding="utf-8")
        with mock.patch.dict(os.environ, self.env_clean, clear=True):
            rc, out, _ = _run(["scan", "--scan", str(scan_list), "--collector", str(self.dir / "missing.json")])
        self.assertEqual(rc, 0)
        self.assertIn("| gitleaks | ran | 2 |", out)
        self.assertIn("evidence: _not produced_", out)

    def test_review_with_all_108_keys_and_no_finding_titles(self):
        triage = self.dir / "triage.json"
        triage.write_text(json.dumps({
            "skip_model": False,
            "reason": "code change",
            "escalate_reason": "diff too big",
            "changed_lines": 1200,
            "noop_rebase": False,
            "chunk_count": 3,
            "config_warnings": ["w1", "w2"],
        }), encoding="utf-8")
        scan = self.dir / "scan.json"
        scan.write_text(json.dumps({"status": "ok", "leads": []}), encoding="utf-8")
        usage = self.dir / "agy.json"
        usage.write_text(json.dumps({
            "engine": "claude",
            "model": "claude-opus-5-5",
            "attempts": 2,
            "engines_tried": ["agy", "claude"],
            "failover_reasons": [{"from": "agy", "to": "claude", "category": "rate_limit", "reason": "429"}],
            "usage": {"input_tokens": 1000, "output_tokens": 200},
            "total_cost_usd": 0.42,
            "cost_usd": 0.30,
            "skipped": None,
            "errors": [f"err-{i}" for i in range(7)],
            "attempt_details": [
                {"label": "1", "status": "FAILED", "num_turns": 3, "duration_seconds": 12.5,
                 "has_structured_output": False, "error": "rate limited"},
                {"label": "2", "status": "SUCCESS", "num_turns": 5, "duration_seconds": 25.0,
                 "has_structured_output": True, "error": None},
            ],
            "verifier": {"mode": "cross", "engine": "agy", "model": "argon",
                         "checked": 2, "confirmed": 1, "downgraded": 1, "dropped": 0},
        }), encoding="utf-8")
        findings = self.dir / "findings.json"
        findings.write_text(json.dumps({
            "findings": [
                {"id": "S-001", "severity": "P1", "status": "new",
                 "title": "SECRET_TITLE_SHOULD_NOT_APPEAR", "rationale": "SECRET_RATIONALE"},
                {"id": "R-001", "severity": "nit", "status": "still_open",
                 "title": "ANOTHER_SECRET_TITLE", "rationale": "MORE_RATIONALE"},
            ]
        }), encoding="utf-8")

        with mock.patch.dict(os.environ, self.env_clean, clear=True):
            rc, out, _ = _run([
                "review", "--triage", str(triage), "--scan", str(scan),
                "--usage", str(usage), "--findings", str(findings), "--scan-artifact", "success",
            ])
        self.assertEqual(rc, 0)
        self.assertIn("escalate_reason=diff too big", out)
        self.assertIn("changed_lines=1200", out)
        self.assertIn("noop_rebase=False", out)
        self.assertIn("chunk_count=3", out)
        self.assertIn("config_warnings=2", out)
        self.assertIn("agy -> claude (rate_limit)", out)
        self.assertIn("$0.4200", out)
        self.assertIn("err-4", out)
        self.assertNotIn("err-5", out)
        self.assertIn("| 1 | FAILED | 3 | 12.50 | False | rate limited |", out)
        self.assertIn("verifier: mode=cross", out)
        self.assertIn("P1=1, nit=1", out)
        self.assertNotIn("SECRET_TITLE_SHOULD_NOT_APPEAR", out)
        self.assertNotIn("SECRET_RATIONALE", out)

    def test_review_cost_fallback_and_skipped(self):
        usage_agy = self.dir / "u1.json"
        usage_agy.write_text(json.dumps({"engine": "agy", "usage": {"input_tokens": 10}}), encoding="utf-8")
        with mock.patch.dict(os.environ, self.env_clean, clear=True):
            rc, out, _ = _run(["review", "--usage", str(usage_agy)])
        self.assertEqual(rc, 0)
        self.assertIn("priced at publish", out)

        usage_skip = self.dir / "u2.json"
        usage_skip.write_text(json.dumps({"cost_usd": 0.125, "skipped": "docs-only"}), encoding="utf-8")
        with mock.patch.dict(os.environ, self.env_clean, clear=True):
            rc, out, _ = _run(["review", "--usage", str(usage_skip)])
        self.assertEqual(rc, 0)
        self.assertIn("$0.1250", out)
        self.assertIn("skipped: docs-only", out)

    def test_publish_last_json_line_and_verdict_first_json_line(self):
        pub = self.dir / "publish.json"
        pub.write_text(
            '{"round": 1, "signals": ["stale"]}\n'
            'diagnostic log line\n'
            '{"round": 3, "signals": ["round cap: 6"]}\n'
            'trailing noise\n',
            encoding="utf-8",
        )
        ver = self.dir / "verdict.json"
        ver.write_text(
            'first non-json line\n'
            '{"state": "failure", "description": "Round 3: 1 P1 open", "label": "needs-human"}\n'
            '{"state": "success", "description": "wrong second json"}\n',
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, self.env_clean, clear=True):
            rc1, out1, _ = _run(["publish", "--result", str(pub)])
            rc2, out2, _ = _run(["verdict", "--result", str(ver)])
        self.assertEqual(rc1, 0)
        self.assertIn("round: 3", out1)
        self.assertIn("round cap: 6", out1)
        self.assertNotIn("stale", out1)

        self.assertEqual(rc2, 0)
        self.assertIn("state: failure", out2)
        self.assertIn("label: needs-human", out2)
        self.assertNotIn("wrong second json", out2)

    def test_missing_and_garbage_json(self):
        garbage = self.dir / "garbage.json"
        garbage.write_text("{not valid json\n", encoding="utf-8")
        with mock.patch.dict(os.environ, self.env_clean, clear=True):
            for args in (
                ["scan", "--scan", str(garbage), "--collector", str(self.dir / "nope")],
                ["review", "--triage", str(garbage), "--usage", str(garbage), "--findings", str(garbage)],
                ["publish", "--result", str(garbage)],
                ["verdict", "--result", str(self.dir / "nope")],
            ):
                rc, out, _ = _run(args)
                self.assertEqual(rc, 0)
                self.assertIn("_not produced_", out)

    def test_hostile_strings_neutralised_and_capped(self):
        hostile = "<!-- hidden --> @owner | col2\nline2 " + ("x" * 10000)
        with mock.patch.dict(os.environ, self.env_clean, clear=True):
            rc, out, _ = _run(["route", "--action", "review", "--reason", hostile, "--pr", "1"])
        self.assertEqual(rc, 0)
        self.assertNotIn("<!--", out)
        self.assertNotIn("@owner", out)
        self.assertIn("@" + textsafe.ZWSP + "owner", out)
        self.assertIn("\\|", out)
        self.assertLess(len(out), 1000)

        huge = "\n".join(f"line-{i}-" + ("a" * 80) for i in range(200))
        capped = ss._cap(huge)
        self.assertLessEqual(len(capped), ss.MAX_CHARS)
        self.assertTrue(capped.endswith(ss.TRUNC_SUFFIX))

    def test_handler_exception_still_exits_zero(self):
        with mock.patch.dict(ss._HANDLERS, {"route": mock.MagicMock(side_effect=RuntimeError("boom"))}):
            rc, _, err = _run(["route", "--action", "review", "--reason", "ok", "--pr", "1"])
        self.assertEqual(rc, 0)
        self.assertIn("::warning::step summary failed: boom", err)


if __name__ == "__main__":
    unittest.main()
