import unittest

from tests.helpers import *  # noqa: F401,F403
import state as st


class StateTest(unittest.TestCase):
    def test_roundtrip(self):
        s = st.empty_state()
        s.update(round=3, findings=[{"id": "R-001"}], cost_usd=[0.4])
        body = "text\n" + st.encode(s)
        self.assertEqual(st.decode(body), s)

    def test_decode_garbage(self):
        self.assertIsNone(st.decode("no state"))
        self.assertIsNone(st.decode("<!-- pr-guardian:state v1 Zm9v -->"))

    def test_summary_must_be_bot_authored(self):
        human = {"body": st.SUMMARY_MARKER + st.encode(st.empty_state()), "user": {"type": "User"}}
        bot = {"id": 2, "body": st.SUMMARY_MARKER, "user": {"type": "Bot"}}
        self.assertIsNone(st.find_summary_comment([human]))
        self.assertEqual(st.find_summary_comment([bot, human])["id"], 2)

    def test_finding_marker_regex(self):
        m = st.FINDING_RE.search(st.FINDING_MARKER.format(id="SEC-012", severity="P0"))
        self.assertEqual(m.groups(), ("SEC-012", "P0"))


if __name__ == "__main__":
    unittest.main()
