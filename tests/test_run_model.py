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
