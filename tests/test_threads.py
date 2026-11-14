"""Thread provenance: only pr-guardian's own threads count (GHSA-j3g5-fvc6-rrjw)."""

import unittest

from tests.helpers import BOT, comment, thread
import threads as th


def marker(fid, severity="P1"):
    return f"<!-- pr-guardian:finding id={fid} severity={severity} -->\nbody"


class IdentityTest(unittest.TestCase):
    def test_is_bot_needs_bot_type_and_actions_login(self):
        self.assertTrue(th.is_bot(comment(BOT)))
        self.assertTrue(th.is_bot(comment("github-actions[bot]")))
        self.assertFalse(th.is_bot(comment(BOT, typename="User")))       # a user named github-actions
        self.assertFalse(th.is_bot(comment("evil-app[bot]", typename="Bot")))  # another app
        self.assertFalse(th.is_bot(comment(None)))                        # ghost
        self.assertFalse(th.is_bot({"body": "x"}))

    def test_is_writer_needs_write_association_and_a_human(self):
        for assoc in ("OWNER", "MEMBER", "COLLABORATOR"):
            self.assertTrue(th.is_writer(comment("dev", association=assoc)), assoc)
        for assoc in ("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "NONE", ""):
            self.assertFalse(th.is_writer(comment("dev", association=assoc)), assoc)
        self.assertFalse(th.is_writer(dict(comment("dev"), authorAssociation=None)))
        self.assertFalse(th.is_writer({k: v for k, v in comment("dev").items() if k != "authorAssociation"}))
        self.assertFalse(th.is_writer(comment("app[bot]", typename="Bot", association="MEMBER")))
        self.assertFalse(th.is_writer(comment(None, association="OWNER")))
        self.assertFalse(th.is_writer(dict(comment("dev"), author={"__typename": "User", "login": ""})))

    def test_query_fetches_provenance(self):
        for field in ("__typename", "authorAssociation", "comments(first:100)", "hasNextPage"):
            self.assertIn(field, th.THREADS_QUERY)


class ByFindingTest(unittest.TestCase):
    def test_bot_thread_is_mapped(self):
        self.assertEqual(th.by_finding([thread("R-001")])["R-001"]["id"], "T-R-001")

    def test_user_named_like_the_bot_cannot_open_a_finding_thread(self):
        decoy = thread("R-001", tid="DECOY", resolved=True,
                       opener=comment(BOT, marker("R-001"), typename="User", association="NONE"))
        self.assertEqual(th.by_finding([decoy]), {})
        self.assertEqual(th.by_finding([thread("R-001"), decoy])["R-001"]["id"], "T-R-001")

    def test_other_bots_and_humans_are_ignored(self):
        app = thread("R-001", tid="APP", opener=comment("evil-app[bot]", marker("R-001"), typename="Bot"))
        human = thread("R-001", tid="HUMAN", opener=comment("dev", marker("R-001"), association="OWNER"))
        self.assertEqual(th.by_finding([app, human]), {})

    def test_first_bot_thread_wins(self):
        out = th.by_finding([thread("R-001", tid="FIRST"), thread("R-001", tid="SECOND", resolved=True)])
        self.assertEqual(out["R-001"]["id"], "FIRST")

    def test_tolerates_missing_comments(self):
        self.assertEqual(th.by_finding([{"id": "X"}, {"id": "Y", "comments": None},
                                        {"id": "Z", "comments": {"nodes": []}}]), {})


class RepliesTest(unittest.TestCase):
    def test_replies_carry_provenance(self):
        t = thread("R-001", replies=[comment("dev", "hi", association="MEMBER"),
                                     comment("rando", "x", association="NONE"),
                                     comment(BOT, "counter"),
                                     comment(None, "gone")])
        r = th.replies(t)
        self.assertEqual([x["author"] for x in r], ["dev", "rando", BOT, "ghost"])
        self.assertEqual([x["login"] for x in r], ["dev", "rando", BOT, ""])
        self.assertEqual([x["is_writer"] for x in r], [True, False, False, False])
        self.assertEqual([x["is_bot"] for x in r], [False, False, True, False])
        self.assertEqual(r[0]["association"], "MEMBER")
        self.assertEqual(r[2]["author_type"], "Bot")
        self.assertEqual(set(r[0]) >= {"author", "body", "at"}, True)

    def test_truncated(self):
        self.assertTrue(th.truncated(thread("R-001", has_next_page=True)))
        self.assertFalse(th.truncated(thread("R-001")))
        self.assertFalse(th.truncated({"comments": {"nodes": []}}))


if __name__ == "__main__":
    unittest.main()
