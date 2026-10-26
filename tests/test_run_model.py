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
