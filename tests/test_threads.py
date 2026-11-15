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
        comments_block = th.THREADS_QUERY.split("comments(first:100)", 1)[1]
        self.assertIn("endCursor", comments_block)


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


class CommentPaginationTest(unittest.TestCase):
    def _thread_page(self, nodes, has_next=True, cursor="c1"):
        return {
            "repository": {
                "pullRequest": {
                    "reviewThreads": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [{
                            "id": "T-R-001",
                            "isResolved": False,
                            "isOutdated": False,
                            "path": "app.py",
                            "line": 3,
                            "comments": {
                                "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                                "nodes": list(nodes),
                            },
                        }],
                    }
                }
            }
        }

    def _comment_page(self, nodes, has_next=False, cursor=None):
        return {
            "node": {
                "comments": {
                    "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                    "nodes": list(nodes),
                }
            }
        }

    def test_fetch_paginates_100_plus_37_comments_in_order(self):
        from unittest import mock
        first_100 = [comment(BOT, marker("R-001"))] + [comment("dev", f"msg-{i}") for i in range(1, 100)]
        next_37 = [comment("dev", f"msg-{i}") for i in range(100, 137)]
        calls = []

        def fake_graphql(query, **variables):
            calls.append((query, variables))
            if "reviewThreads" in query:
                return self._thread_page(first_100, has_next=True, cursor="cur-100")
            self.assertEqual(variables, {"id": "T-R-001", "cursor": "cur-100"})
            return self._comment_page(next_37, has_next=False, cursor=None)

        with mock.patch.object(th.gh, "graphql", side_effect=fake_graphql):
            fetched = th.fetch("o/r", 7)
        self.assertEqual(len(fetched), 1)
        self.assertFalse(th.truncated(fetched[0]))
        all_nodes = th.comments(fetched[0])
        self.assertEqual(len(all_nodes), 137)
        self.assertEqual([c["body"] for c in all_nodes[1:4]], ["msg-1", "msg-2", "msg-3"])
        self.assertEqual(all_nodes[-1]["body"], "msg-136")
        self.assertEqual(len(calls), 2)

    def test_writer_wontfix_on_comment_130_is_honoured_after_pagination(self):
        from unittest import mock
        import publish_review as pub

        first_100 = [comment(BOT, marker("R-001"))] + [comment("rando", "noise", association="NONE") for _ in range(99)]
        next_35 = (
            [comment(BOT, "still open")]
            + [comment("rando", "more", association="NONE") for _ in range(28)]
            + [comment("dev", "/ai-review wontfix: false positive", association="OWNER")]
            + [comment("rando", "after", association="NONE") for _ in range(5)]
        )  # wontfix is comment index 130 (131st comment)

        def fake_graphql(query, **variables):
            if "reviewThreads" in query:
                return self._thread_page(first_100, has_next=True, cursor="c1")
            return self._comment_page(next_35, has_next=False)

        with mock.patch.object(th.gh, "graphql", side_effect=fake_graphql):
            fetched = th.fetch("o/r", 7)
        self.assertFalse(th.truncated(fetched[0]))
        self.assertTrue(pub.has_writer_wontfix(fetched[0]))

    def test_pagination_gh_error_or_malformed_page_fails_closed(self):
        import io
        from unittest import mock
        import publish_review as pub

        first_100 = [comment(BOT, marker("R-001")), comment("dev", "/ai-review wontfix: ok", association="OWNER")]

        for name, second in (
            ("gh-error", th.gh.GhError("HTTP 502")),
            ("malformed-node", {"node": None}),
            ("missing-cursor", "no-cursor"),
        ):
            err = io.StringIO()

            def fake_graphql(query, _second=second, **variables):
                if "reviewThreads" in query:
                    cur = None if _second == "no-cursor" else "c1"
                    return self._thread_page(first_100, has_next=True, cursor=cur)
                if isinstance(_second, Exception):
                    raise _second
                return _second

            with self.subTest(name=name), \
                    mock.patch.object(th.gh, "graphql", side_effect=fake_graphql), \
                    mock.patch("sys.stderr", err):
                fetched = th.fetch("o/r", 7)
                self.assertTrue(th.truncated(fetched[0]))
                self.assertFalse(pub.has_writer_wontfix(fetched[0]))
                self.assertIn("::warning::", err.getvalue())

    def test_cap_stops_at_max_comment_pages_and_fails_closed(self):
        import io
        from unittest import mock
        import publish_review as pub

        first_100 = [comment(BOT, marker("R-001"))] + [comment("dev", "x") for _ in range(99)]
        extra_calls = 0

        def fake_graphql(query, **variables):
            nonlocal extra_calls
            if "reviewThreads" in query:
                return self._thread_page(first_100, has_next=True, cursor="c-0")
            extra_calls += 1
            has_more = extra_calls < 12  # 12 extra pages available > MAX_COMMENT_PAGES (10)
            batch = [comment("dev", "/ai-review wontfix: late", association="OWNER")] + [
                comment("dev", f"p{extra_calls}-{i}") for i in range(99)
            ]
            return self._comment_page(batch, has_next=has_more, cursor=f"c-{extra_calls}")

        err = io.StringIO()
        with mock.patch.object(th.gh, "graphql", side_effect=fake_graphql), \
                mock.patch("sys.stderr", err):
            fetched = th.fetch("o/r", 7)
        self.assertEqual(extra_calls, th.MAX_COMMENT_PAGES)
        self.assertEqual(len(th.comments(fetched[0])), 100 + 100 * th.MAX_COMMENT_PAGES)
        self.assertTrue(th.truncated(fetched[0]))
        self.assertFalse(pub.has_writer_wontfix(fetched[0]))
        self.assertIn("::warning::", err.getvalue())

    def test_thread_page_cap_raises_gh_error_instead_of_truncating_silently(self):
        from unittest import mock

        page = {
            "repository": {
                "pullRequest": {
                    "reviewThreads": {
                        "pageInfo": {"hasNextPage": True, "endCursor": "cur-next"},
                        "nodes": [thread("R-001")],
                    }
                }
            }
        }
        with mock.patch.object(th.gh, "graphql", return_value=page) as gql:
            with self.assertRaises(th.gh.GhError) as ctx:
                th.fetch("o/r", 7)
        self.assertEqual(gql.call_count, th.MAX_THREAD_PAGES)
        self.assertIn("more than", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
