import base64
import json
import unittest
import zlib

from tests.helpers import *  # noqa: F401,F403
import state as st

TRUSTED = {"type": "Bot", "login": "github-actions[bot]"}


def marker(raw: bytes) -> str:
    return f"<!-- pr-guardian:state v1 {base64.b64encode(raw).decode()} -->"


def marker_json(text: str) -> str:
    return marker(zlib.compress(text.encode()))


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
        bot = {"id": 2, "body": st.SUMMARY_MARKER, "user": {"type": "Bot", "login": "github-actions[bot]"}}
        self.assertIsNone(st.find_summary_comment([human]))
        self.assertEqual(st.find_summary_comment([bot, human])["id"], 2)

    def test_finding_marker_regex(self):
        m = st.FINDING_RE.search(st.FINDING_MARKER.format(id="SEC-012", severity="P0"))
        self.assertEqual(m.groups(), ("SEC-012", "P0"))


class MarkerAnchoringTest(unittest.TestCase):
    """GHSA-r8c3-5xg9-pqqg: only the marker that ends the body counts."""

    def setUp(self):
        forged = st.empty_state()
        forged.update(round=9, last_reviewed_sha="abc")
        real = st.empty_state()
        real.update(round=2, findings=[{"id": "R-001", "severity": "P0", "status": "new"}])
        self.forged, self.real = st.encode(forged), st.encode(real)

    def test_earlier_forged_marker_is_ignored(self):
        body = f"- `docs/a.md {self.forged}` title\n{self.real}"
        self.assertEqual(st.decode(body)["round"], 2)

    def test_marker_not_at_end_is_ignored(self):
        self.assertIsNone(st.decode(f"{self.forged}\ntext after"))
        self.assertEqual(st.decode(f"{self.real}\n  \n")["round"], 2)

    def test_non_string_body(self):
        self.assertIsNone(st.decode(None))
        self.assertIsNone(st.decode(123))


class BoundedInflateTest(unittest.TestCase):
    def _sized(self, n: int) -> bytes:
        # A JSON object whose serialisation is exactly n bytes.
        pad = n - len('{"pad":""}')
        text = '{"pad":"' + "a" * pad + '"}'
        self.assertEqual(len(text), n)
        return text.encode()

    def test_exact_limit_accepted_and_one_over_rejected(self):
        ok = st.decode(marker(zlib.compress(self._sized(st.MAX_STATE_BYTES))))
        self.assertIsNotNone(ok)
        self.assertEqual(len(ok["pad"]), st.MAX_STATE_BYTES - len('{"pad":""}'))
        self.assertIsNone(st.decode(marker(zlib.compress(self._sized(st.MAX_STATE_BYTES + 1)))))

    def test_bomb_rejected(self):
        bomb = zlib.compress(b'{"pad":"' + b"a" * (64 * 1024 * 1024) + b'"}', 9)
        self.assertLess(len(bomb), 200_000)
        self.assertIsNone(st.decode(marker(bomb)))

    def test_truncated_stream_rejected(self):
        raw = zlib.compress(json.dumps(st.empty_state()).encode())
        self.assertIsNone(st.decode(marker(raw[:-4])))  # Adler-32 missing

    def test_trailing_data_rejected(self):
        raw = zlib.compress(json.dumps(st.empty_state()).encode())
        self.assertIsNone(st.decode(marker(raw + b"x")))
        self.assertIsNone(st.decode(marker(raw + raw)))

    def test_oversized_base64_rejected_before_decode(self):
        self.assertIsNone(st.decode("<!-- pr-guardian:state v1 " + "A" * (st.MAX_STATE_BYTES * 2 + 4) + " -->"))


class SchemaTest(unittest.TestCase):
    def test_rejects_non_finite_and_non_objects(self):
        for text in ('{"cost_usd":[NaN]}', '{"round":Infinity}', "null", "3", "[]",
                     '[["round",1]]', '"x"'):
            with self.subTest(text=text):
                self.assertIsNone(st.decode(marker_json(text)))

    def test_rejects_wrong_types(self):
        bad = [
            {"round": "0"}, {"round": True}, {"round": -1},
            {"findings": "x"}, {"findings": [{}]}, {"findings": [{"id": ""}]}, {"findings": [{"id": 1}]},
            {"findings": [{"id": "R-001", "severity": "P9"}]},
            {"findings": [{"id": "R-001", "status": 1}]},
            {"findings": [{"id": "R-001", "prior_id": 5}]},
            {"findings": [{"id": "R-001", "file": ["a"]}]},
            {"findings": [{"id": "R-001", "start_line": True}]},
            {"accepted": [{"id": "R-1"}]}, {"accepted": "x"},
            {"reopen_counts": {"R-001": -1}}, {"reopen_counts": []},
            {"escalated": "false"}, {"escalation_reasons": [1]},
            {"cost_usd": [-1]}, {"cost_usd": [True]}, {"last_reviewed_sha": None},
            {"last_reviewed_base": None}, {"last_reviewed_base": 0}, {"last_reviewed_base": ["main"]},
        ]
        for data in bad:
            with self.subTest(data=data):
                self.assertIsNone(st.validate_state(data))
                self.assertIsNone(st.decode(marker_json(json.dumps(data))))

    def test_preserves_unknown_keys(self):
        s = st.empty_state()
        s.update(thread_key="t", findings=[{"id": "R-001", "thread_key": "PRRT_1", "prior_id": None}])
        out = st.decode(st.encode(s))
        self.assertEqual(out["thread_key"], "t")
        self.assertEqual(out["findings"][0]["thread_key"], "PRRT_1")

    def test_minimal_and_partial_state_merges_defaults(self):
        self.assertEqual(st.validate_state({}), st.empty_state())
        self.assertEqual(st.validate_state({"findings": [{"id": "R-001"}]})["round"], 0)

    def test_last_reviewed_base_defaults_empty_and_round_trips(self):
        """GHSA-6h55-p37r-jc34: state written before the fix decodes with an empty base."""
        self.assertEqual(st.empty_state()["last_reviewed_base"], "")
        legacy = {k: v for k, v in st.empty_state().items() if k != "last_reviewed_base"}
        legacy["last_reviewed_sha"] = "abc"
        self.assertEqual(st.decode(st.encode(legacy))["last_reviewed_base"], "")
        s = dict(st.empty_state(), last_reviewed_sha="abc", last_reviewed_base="release/1.0")
        self.assertEqual(st.decode(st.encode(s))["last_reviewed_base"], "release/1.0")


class TrustedAuthorTest(unittest.TestCase):
    def test_only_github_actions_bot(self):
        self.assertTrue(st.is_trusted_author(TRUSTED))
        for user in ({"type": "Bot", "login": "dependabot[bot]"}, {"type": "Bot"},
                     {"type": "User", "login": "github-actions[bot]"}, None, "github-actions[bot]",
                     {"type": "Bot", "login": "github-actions"}):
            with self.subTest(user=user):
                self.assertFalse(st.is_trusted_author(user))

    def test_other_bot_summary_is_ignored(self):
        real = {"id": 1, "body": st.SUMMARY_MARKER + st.encode(st.empty_state()), "user": TRUSTED}
        forged = {"id": 2, "body": st.SUMMARY_MARKER + st.encode(st.empty_state()),
                  "user": {"type": "Bot", "login": "evil-app[bot]"}}
        self.assertEqual(st.find_summary_comment([real, forged])["id"], 1)
        self.assertIsNone(st.find_summary_comment([forged, {"body": None, "user": TRUSTED}, "x"]))


if __name__ == "__main__":
    unittest.main()
