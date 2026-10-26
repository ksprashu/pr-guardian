import unittest

from tests.helpers import *  # noqa: F401,F403
import run_model as rm


class ExtractTest(unittest.TestCase):
    def test_structured_output_wins(self):
        self.assertEqual(rm.extract({"structured_output": {"a": 1}, "response": "x"}), {"a": 1})

    def test_fenced_and_prose_wrapped_json(self):
        self.assertEqual(rm.extract({"response": "```json\n{\"a\": 3}\n```"}), {"a": 3})
        self.assertEqual(rm.extract({"response": "Here it is:\n{\"a\": 2}\nDone."}), {"a": 2})

    def test_empty_response_is_a_clear_error(self):
        with self.assertRaisesRegex(ValueError, "empty response"):
            rm.extract({"response": ""})


class FinalizeTest(unittest.TestCase):
    """An empty SUCCESS turn is finished in the same conversation, not re-run from scratch."""

    def run_main(self, results, tmp):
        from pathlib import Path
        from unittest import mock
        calls = []

        def fake_run(prompt, schema, model, workdir, extra_dir, conversation=None):
            calls.append(conversation)
            return results.pop(0)

        lib = mock.Mock(build_schema=lambda: {}, validate=lambda doc: [])
        Path(tmp, "ctx.md").write_text("x")
        Path(tmp, "triage.json").write_text("{}")
        argv = ["run_model.py", "--context", f"{tmp}/ctx.md", "--triage", f"{tmp}/triage.json",
                "--findings-lib", "unused", "--out", f"{tmp}/f.json", "--usage-out", f"{tmp}/u.json"]
        with mock.patch.object(rm, "run_agy", side_effect=fake_run), \
                mock.patch.object(rm, "load_findings_lib", return_value=lib), \
                mock.patch.object(rm.sys, "argv", argv), mock.patch("builtins.print"):
            code = rm.main()
        return code, calls

    def test_empty_turn_is_finalized_in_same_conversation(self):
        import tempfile
        doc = {"findings": []}
        with tempfile.TemporaryDirectory() as tmp:
            code, calls = self.run_main([{"status": "SUCCESS", "response": "", "conversation_id": "c1"},
                                         {"status": "SUCCESS", "structured_output": doc}], tmp)
        self.assertEqual((code, calls), (0, [None, "c1"]))

    def test_non_empty_turn_is_not_finalized(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            code, calls = self.run_main([{"status": "SUCCESS", "structured_output": {"findings": []},
                                          "conversation_id": "c1"}], tmp)
        self.assertEqual((code, calls), (0, [None]))


class RateLimitTest(unittest.TestCase):
    def test_quota_exhaustion_waits_but_spending_cap_does_not(self):
        self.assertTrue(rm.is_rate_limited("Error 429, Message: Resource has been exhausted, Status: RESOURCE_EXHAUSTED"))
        self.assertFalse(rm.is_rate_limited(
            "Error 429, Message: Your billing account has exceeded its monthly spending cap, Status: RESOURCE_EXHAUSTED"))
        self.assertFalse(rm.is_rate_limited("agy ERROR (exit 3): authentication failed"))


class ClaudeFallbackTest(unittest.TestCase):
    """A Gemini rate limit hands the retry to Claude Code when ANTHROPIC_API_KEY is set."""

    def run_main(self, tmp, env):
        import json
        from pathlib import Path
        from unittest import mock
        quota = RuntimeError("agy ERROR (exit 3): Error 429, Status: RESOURCE_EXHAUSTED")
        claude = {"status": "SUCCESS", "structured_output": {"findings": []},
                  "usage": {"input_tokens": 10, "output_tokens": 5}, "cost_usd": 0.42}
        lib = mock.Mock(build_schema=lambda: {}, validate=lambda doc: [])
        Path(tmp, "ctx.md").write_text("x")
        Path(tmp, "triage.json").write_text("{}")
        argv = ["run_model.py", "--context", f"{tmp}/ctx.md", "--triage", f"{tmp}/triage.json",
                "--findings-lib", "unused", "--out", f"{tmp}/f.json", "--usage-out", f"{tmp}/u.json"]
        with mock.patch.dict(rm.os.environ, env, clear=True), \
                mock.patch.object(rm, "run_agy", side_effect=[quota, quota]) as agy, \
                mock.patch.object(rm, "run_claude", return_value=claude) as cc, \
                mock.patch.object(rm.time, "sleep") as sleep, \
                mock.patch.object(rm, "load_findings_lib", return_value=lib), \
                mock.patch.object(rm.sys, "argv", argv), mock.patch("builtins.print"):
            code = rm.main()
        return code, agy.call_count, cc.call_count, sleep.call_count, json.loads(Path(tmp, "u.json").read_text())

    def test_rate_limit_falls_back_to_claude_with_key(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            code, agy, cc, slept, usage = self.run_main(tmp, {"ANTHROPIC_API_KEY": "k"})
        self.assertEqual((code, agy, cc, slept), (0, 1, 1, 0))
        self.assertEqual((usage["engine"], usage["cost_usd"]), ("claude", 0.42))

    def test_rate_limit_without_key_waits_and_retries_gemini(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            code, agy, cc, slept, usage = self.run_main(tmp, {})
        self.assertEqual((code, agy, cc, slept), (1, 2, 0, 1))
        self.assertEqual(usage["engine"], "agy")

    def test_claude_result_is_normalised_to_agy_shape(self):
        import json
        from unittest import mock
        raw = {"is_error": False, "result": "{}", "structured_output": {"findings": []}, "num_turns": 3,
               "duration_ms": 2000, "total_cost_usd": 0.5,
               "usage": {"input_tokens": 2, "cache_read_input_tokens": 100, "cache_creation_input_tokens": 50,
                         "output_tokens": 7}}
        proc = mock.Mock(returncode=0, stdout=json.dumps(raw), stderr="")
        with mock.patch.object(rm.subprocess, "run", return_value=proc) as run, \
                mock.patch.object(rm.Path, "read_text", return_value="{}"):
            out = rm.run_claude("p", "s.json", "claude-opus-5-5", ".", "/ctx")
        cmd = run.call_args.args[0]
        self.assertNotIn("Bash", cmd[cmd.index("--allowedTools"):cmd.index("--disallowedTools")])
        self.assertEqual(out["status"], "SUCCESS")
        self.assertEqual(out["usage"], {"input_tokens": 152, "output_tokens": 7})
        self.assertEqual(out["cost_usd"], 0.5)

    def test_claude_error_raises(self):
        import json
        from unittest import mock
        proc = mock.Mock(returncode=0, stdout=json.dumps({"is_error": True, "result": "overloaded"}), stderr="")
        with mock.patch.object(rm.subprocess, "run", return_value=proc), \
                mock.patch.object(rm.Path, "read_text", return_value="{}"):
            with self.assertRaisesRegex(RuntimeError, "overloaded"):
                rm.run_claude("p", "s.json", "claude-opus-5-5", ".", "/ctx")
