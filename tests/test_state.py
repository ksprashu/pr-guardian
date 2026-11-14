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


class NewFieldsAndCompactionTest(unittest.TestCase):
    def test_new_fields_roundtrip_and_invalid_values_reject_state(self):
        s = st.empty_state()
        s.update(
            round=4,
            sha_rounds=3,
            reviewed_shas=["1847db4", "a" * 40],
            guardian_ref="b" * 40,
            engine="claude",
            rounds_log=[{"round": 4, "sha": "1847db4", "engine": "claude", "ref": "bbbbbbbbbbbb", "cost": 0.42}],
            publish_incomplete=True,
            publish_failures=["reply T1: HTTP 502"],
            id_high_water={"R": 12, "SEC": 4},
            findings=[{
                "id": "R-012",
                "prior_id": "R-003",
                "thread_key": "R-001",
                "posted": "thread",
                "severity": "P1",
                "status": "still_open",
                "file": "app.py",
                "rule": "CWE-89",
                "start_line": 3,
                "end_line": 5,
                "raised_by": "agy",
            }],
        )
        decoded = st.decode("summary\n" + st.encode(s))
        self.assertEqual(decoded, s)

        bad_cases = [
            {"sha_rounds": -1},
            {"sha_rounds": True},
            {"sha_rounds": "2"},
            {"reviewed_shas": ["xyz"]},
            {"reviewed_shas": ["123456"]},     # < 7 hex chars
            {"reviewed_shas": ["ABCDEF12"]},   # uppercase rejected
            {"guardian_ref": "not-a-sha"},
            {"engine": "x" * 33},
            {"engine": 123},
            {"rounds_log": [{"round": 1, "sha": "abc", "engine": "agy", "ref": "def", "cost": -1}]},
            {"rounds_log": [{"round": 1, "sha": "a" * 13, "engine": "agy", "ref": "def", "cost": 0.1}]},
            {"publish_incomplete": "yes"},
            {"publish_failures": ["x" * 301]},
            {"publish_failures": [123]},
            {"id_high_water": {"r": 1}},
            {"id_high_water": {"R": -1}},
            {"id_high_water": {"R": True}},
            {"findings": [{"id": "R-001", "raised_by": 5}]},
            {"findings": [{"id": "R-001", "thread_key": 5}]},
            {"findings": [{"id": "R-001", "posted": ["thread"]}]},
        ]
        for bad in bad_cases:
            with self.subTest(bad=bad):
                self.assertIsNone(st.validate_state(bad))
                self.assertIsNone(st.decode(marker_json(json.dumps(bad))))

    def test_legacy_state_decodes_without_sha_rounds(self):
        legacy = {
            "round": 3,
            "findings": [{"id": "R-001"}],
            "accepted": [],
            "reopen_counts": {},
            "escalated": False,
            "escalation_reasons": [],
            "cost_usd": [0.1],
            "last_reviewed_sha": "abc",
            "last_reviewed_base": "main",
        }
        out = st.decode(st.encode(legacy))
        self.assertIsNotNone(out)
        self.assertNotIn("sha_rounds", out)
        self.assertEqual(out["reviewed_shas"], [])
        self.assertEqual(out["id_high_water"], {})

    def test_compact_state_levels_idempotency_and_cost_sum(self):
        open_f = finding(
            "R-001", severity="P1", status="still_open",
            title="T" * 500, rationale="Why " * 500,
            evidence="big evidence", suggestion="big suggestion",
            references=[{"title": "t", "url": "https://example.com"}],
            thread_key="R-001", posted="thread", raised_by="agy", _anchor={"mode": "exact"},
        )
        closed_f = finding(
            "R-002", severity="P2", status="fixed", prior_id="R-000",
            rationale="Fixed " * 400, evidence="ev",
            thread_key="R-000", posted="thread", raised_by="claude",
        )
        orig = st.empty_state()
        orig.update(
            round=10,
            findings=[open_f, closed_f],
            accepted=[{"id": f"R-{i:03d}", "file": "dup.py", "rule": "CWE-89"} for i in range(5)]
            + [{"id": f"S-{i:03d}", "file": f"f{i}.py", "rule": "CWE-20"} for i in range(210)],
            escalation_reasons=["r" * 400 for _ in range(60)],
            cost_usd=[0.1234 for _ in range(60)],
            reopen_counts={f"R-{i:03d}": i for i in range(220)},
            reviewed_shas=[f"{i:07x}" for i in range(25)],
            rounds_log=[{"round": i, "sha": "1847db4", "engine": "agy", "ref": "1847db4", "cost": 0.1}
                        for i in range(25)],
            publish_failures=["f" * 400 for _ in range(25)],
        )
        snapshot = json.loads(json.dumps(orig))

        render_prior_keys = {"id", "severity", "title", "file", "start_line", "end_line", "axis", "rule", "rationale"}
        for lvl in (0, 1, 2):
            with self.subTest(level=lvl):
                c1 = st.compact_state(orig, level=lvl)
                c2 = st.compact_state(c1, level=lvl)
                self.assertEqual(c1, c2, "compact_state must be idempotent")
                self.assertEqual(orig, snapshot, "compact_state must never mutate input")

                f0 = c1["findings"][0]
                for dropped in ("evidence", "suggestion", "references", "security_verdict", "_anchor"):
                    self.assertNotIn(dropped, f0)
                self.assertTrue(render_prior_keys.issubset(f0.keys()))
                self.assertEqual((f0["thread_key"], f0["posted"], f0["raised_by"]), ("R-001", "thread", "agy"))

                f1 = c1["findings"][1]
                self.assertEqual((f1["thread_key"], f1["posted"], f1["raised_by"]), ("R-000", "thread", "claude"))
                if lvl >= 1:
                    self.assertNotIn("rationale", f1)
                    self.assertNotIn("title", f1)
                if lvl == 1:
                    self.assertEqual(len(f0["rationale"]), 300)
                if lvl == 2:
                    self.assertEqual(f0["rationale"], "")

                self.assertEqual(len(c1["cost_usd"]), 50)
                self.assertAlmostEqual(sum(c1["cost_usd"]), sum(orig["cost_usd"]), places=4)
                self.assertLessEqual(len(c1["accepted"]), 200)
                self.assertEqual(len(c1["reopen_counts"]), 200)
                self.assertIn("R-219", c1["reopen_counts"])
                self.assertNotIn("R-000", c1["reopen_counts"])
                self.assertEqual(len(c1["reviewed_shas"]), 20)
                self.assertEqual(len(c1["rounds_log"]), 20)
                self.assertEqual(len(c1["publish_failures"]), 20)
                self.assertEqual(len(c1["publish_failures"][0]), 300)
                self.assertIsNotNone(st.validate_state(c1))

        # Check accepted dedup keeps latest entry for (file, rule)
        dup_state = dict(st.empty_state(), accepted=[
            {"id": "R-001", "file": "a.py", "rule": "CWE-89"},
            {"id": "R-002", "file": "b.py", "rule": "CWE-20"},
            {"id": "R-009", "file": "a.py", "rule": "CWE-89"},
        ])
        compacted_acc = st.compact_state(dup_state)["accepted"]
        self.assertEqual(compacted_acc, [
            {"id": "R-002", "file": "b.py", "rule": "CWE-20"},
            {"id": "R-009", "file": "a.py", "rule": "CWE-89"},
        ])

    def test_split_state_handles_missing_and_non_trailing_markers(self):
        self.assertEqual(st.split_state(""), ("", ""))
        self.assertEqual(st.split_state("plain text"), ("plain text", ""))
        m1 = st.encode(dict(st.empty_state(), round=1))
        m2 = st.encode(dict(st.empty_state(), round=2))
        self.assertEqual(st.split_state(f"{m1}\ntext after"), (f"{m1}\ntext after", ""))
        vis, tail = st.split_state(f"header {m1}\n{m2}\n")
        self.assertEqual(vis, f"header {m1}")
        self.assertEqual(tail, m2)


if __name__ == "__main__":
    unittest.main()
