import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from tests.helpers import *  # noqa: F401,F403  (sets sys.path)
import route

VALID_SHA = "a" * 40
VALID_SHA256 = "0123456789abcdef" * 4


def parse_github_output(raw: str) -> dict[str, str]:
    """Simulate the GitHub Actions GITHUB_OUTPUT parser (CR/LF split + <<EOF heredocs)."""
    outputs: dict[str, str] = {}
    lines = re.split(r"\r\n|\r|\n", raw)
    if lines and lines[-1] == "":
        lines.pop()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if "<<" in line:
            key, delim = line.split("<<", 1)
            idx += 1
            buf: list[str] = []
            while idx < len(lines) and lines[idx] != delim:
                buf.append(lines[idx])
                idx += 1
            outputs[key] = "\n".join(buf)
        elif "=" in line:
            key, val = line.split("=", 1)
            outputs[key] = val
        idx += 1
    return outputs


def pr_event(action="opened", draft=False, fork=False, label=None, sender=None):
    base = {"full_name": "o/r"}
    ev = {"action": action, "pull_request": {
        "number": 7, "draft": draft, "head": {"sha": "abc", "repo": {"full_name": "x/r" if fork else "o/r"}},
        "base": {"repo": base}}}
    if label:
        ev["label"] = {"name": label}
    if sender is not None:
        ev["sender"] = sender
    return ev


def retarget_event(prev="stage", **kw):
    ev = pr_event("edited", **kw)
    ev["changes"] = {"base": {"ref": {"from": prev}, "sha": {"from": "f" * 40}}}
    return ev


def comment_event(body, assoc="OWNER", login="o", bot=False, kind="issue_comment"):
    c = {"body": body, "author_association": assoc, "user": {"login": login, "type": "Bot" if bot else "User"}}
    if kind == "issue_comment":
        return {"comment": c, "issue": {"number": 7, "pull_request": {}}}
    return {"comment": c, "pull_request": {"number": 7, "head": {"sha": "abc"}}}


class RouteTest(unittest.TestCase):
    def test_pr_events(self):
        self.assertEqual(route.decide("pull_request", pr_event(), "o")["action"], "review")
        self.assertEqual(route.decide("pull_request", pr_event("synchronize"), "o")["action"], "review")
        self.assertEqual(route.decide("pull_request", pr_event(draft=True), "o")["action"], "skip")
        self.assertEqual(route.decide("pull_request", pr_event("closed"), "o")["action"], "skip")

    def test_fork_never_reaches_the_model(self):
        r = route.decide("pull_request", pr_event(fork=True), "o")
        self.assertEqual(r["action"], "verdict")
        self.assertIn("fork", r["reason"])

    def test_labels(self):
        r = route.decide("pull_request", pr_event("labeled", label="human-override"), "o")
        self.assertEqual((r["action"], r["bind_override"]), ("verdict", "false"))
        self.assertEqual(route.decide("pull_request", pr_event("labeled", label="bug"), "o")["action"], "skip")


class OverrideRouteTest(unittest.TestCase):
    """GHSA-q4j9-99qr-cfhw / #27: label application binds, removal recomputes."""

    OWNER = {"login": "o", "type": "User"}

    def d(self, action, label="human-override", sender=None, owner="o", **kw):
        return route.decide("pull_request", pr_event(action, label=label, sender=sender, **kw), owner)

    def test_owner_application_binds_with_head_sha(self):
        r = self.d("labeled", sender=self.OWNER)
        self.assertEqual((r["action"], r["head_sha"], r["bind_override"], r["reason"]),
                         ("verdict", "abc", "true", "human-override label applied"))

    def test_non_owner_bot_or_missing_sender_never_binds(self):
        for sender in (None, {"login": "mallory", "type": "User"}, {"login": "o", "type": "Bot"},
                       {"login": "O", "type": "User"}, {"type": "User"}, {"login": ["o"]}, "o", []):
            with self.subTest(sender=sender):
                r = self.d("labeled", sender=sender)
                self.assertEqual((r["action"], r["head_sha"], r["bind_override"]), ("verdict", "abc", "false"))
        r = self.d("labeled", sender={"login": "", "type": "User"}, owner="")
        self.assertEqual(r["bind_override"], "false")

    def test_removal_recomputes_and_never_binds(self):
        r = self.d("unlabeled", sender=self.OWNER)
        self.assertEqual((r["action"], r["head_sha"], r["bind_override"], r["reason"]),
                         ("verdict", "abc", "false", "human-override label removed"))

    def test_other_labels_skip_on_both_actions(self):
        for action in ("labeled", "unlabeled"):
            for label in ("needs-human", "bug", None, "Human-Override", "Needs-Human"):
                if (action, label) == ("unlabeled", "needs-human"):
                    continue  # NeedsHumanUnlabeledTest
                with self.subTest(action=action, label=label):
                    r = self.d(action, label=label, sender=self.OWNER)
                    self.assertEqual((r["action"], r["bind_override"]), ("skip", "false"))

    def test_draft_and_fork_label_events_still_reach_verdict(self):
        for kw in ({"draft": True}, {"fork": True}):
            with self.subTest(**kw):
                self.assertEqual(self.d("labeled", sender=self.OWNER, **kw)["bind_override"], "true")
                self.assertEqual(self.d("unlabeled", sender=self.OWNER, **kw)["action"], "verdict")

    def test_bind_override_false_everywhere_else(self):
        for ev in (pr_event(), pr_event("synchronize"), pr_event("ready_for_review"), pr_event("reopened"),
                   pr_event(fork=True), pr_event(draft=True)):
            self.assertEqual(route.decide("pull_request", ev, "o")["bind_override"], "false")
        self.assertEqual(route.decide("issue_comment", comment_event("/ai-review escalate"), "o")["bind_override"],
                         "false")
        self.assertEqual(route.decide("workflow_dispatch", {"inputs": {"pr": "3"}}, "o")["bind_override"], "false")

    def test_commands(self):
        d = lambda *a, **k: route.decide("issue_comment", comment_event(*a, **k), "o")
        self.assertEqual(d("/ai-review")["action"], "review")
        self.assertEqual(d("/ai-review", login="mallory", assoc="NONE")["action"], "skip")
        self.assertEqual(d("/ai-review", login="collab", assoc="COLLABORATOR")["action"], "skip")
        esc = d("/ai-review escalate: reviewer loops")
        self.assertEqual((esc["action"], esc["escalate"]), ("verdict", "true"))
        self.assertEqual(d("/ai-review escalate: x", assoc="NONE", login="m")["action"], "skip")
        self.assertEqual(d("lgtm")["action"], "skip")
        self.assertEqual(d("/ai-review", bot=True)["action"], "skip")
        self.assertEqual(d("/ai-review frobnicate")["action"], "skip")

    def test_wontfix_in_thread(self):
        r = route.decide("pull_request_review_comment",
                         comment_event("/ai-review wontfix: intended", kind="review"), "o")
        self.assertEqual((r["action"], r["head_sha"]), ("review", "abc"))
        r = route.decide("pull_request_review_comment",
                         comment_event("/ai-review wontfix: x", assoc="NONE", login="m", kind="review"), "o")
        self.assertEqual(r["action"], "skip")

    def test_comment_on_plain_issue(self):
        ev = comment_event("/ai-review")
        del ev["issue"]["pull_request"]
        self.assertEqual(route.decide("issue_comment", ev, "o")["action"], "skip")

        for non_pr in (None, False, "https://api.github.com/repos/o/r/pulls/7", 7):
            with self.subTest(pull_request=non_pr):
                ev_null = comment_event("/ai-review")
                ev_null["issue"]["pull_request"] = non_pr
                res = route.decide("issue_comment", ev_null, "o")
                self.assertEqual(res["action"], "skip")
                self.assertEqual(res["pr"], "")
                self.assertEqual(res["reason"], "comment is on an issue, not a PR")

    def test_empty_or_missing_head_sha_rejected_on_pr_events(self):
        bad_heads = (None, "abc", {}, {"sha": ""}, {"sha": None})
        for event_name in ("pull_request", "pull_request_target"):
            for head in bad_heads:
                with self.subTest(event_name=event_name, head=head):
                    ev = pr_event()
                    if head is None:
                        del ev["pull_request"]["head"]
                    else:
                        ev["pull_request"]["head"] = head
                    res = route.decide(event_name, ev, "o")
                    self.assertEqual(res["action"], "skip")
                    self.assertEqual(res["pr"], "")
                    self.assertEqual(res["head_sha"], "")
                    self.assertEqual(res["reason"], "invalid PR metadata")

        for head in bad_heads:
            with self.subTest(event_name="pull_request_review_comment", head=head):
                ev = comment_event("/ai-review wontfix: intended", kind="review")
                if head is None:
                    del ev["pull_request"]["head"]
                else:
                    ev["pull_request"]["head"] = head
                res = route.decide("pull_request_review_comment", ev, "o")
                self.assertEqual(res["action"], "skip")
                self.assertEqual(res["pr"], "")
                self.assertEqual(res["head_sha"], "")
                self.assertEqual(res["reason"], "invalid PR metadata")

    def test_dispatch_and_unknown(self):
        self.assertEqual(route.decide("workflow_dispatch", {"inputs": {"pr": "3"}}, "o")["pr"], "3")
        self.assertEqual(route.decide("push", {}, "o")["action"], "skip")


class RouteSecurityTest(unittest.TestCase):
    def _run_main(self, event_name, event, owner="o"):
        with tempfile.TemporaryDirectory() as tmp:
            ev_path = os.path.join(tmp, "event.json")
            out_path = os.path.join(tmp, "github_output.txt")
            with open(ev_path, "w", encoding="utf-8") as fh:
                json.dump(event, fh)
            env = {
                "GITHUB_EVENT_NAME": event_name,
                "GITHUB_EVENT_PATH": ev_path,
                "GITHUB_OUTPUT": out_path,
                "PRG_OWNER": owner,
                "GITHUB_REPOSITORY_OWNER": "",
            }
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, env, clear=False), \
                 contextlib.redirect_stdout(stdout), \
                 contextlib.redirect_stderr(stderr):
                rc = route.main()
            raw_out = ""
            if os.path.exists(out_path):
                with open(out_path, encoding="utf-8", newline="") as fh:
                    raw_out = fh.read()
        return rc, raw_out, parse_github_output(raw_out), stdout.getvalue(), stderr.getvalue()

    def test_comment_injection_payloads_through_main(self):
        payloads = [
            ("/ai-review x\naction=verdict\npr=99\nescalate=true", "unknown"),
            ("/ai-review x\raction=verdict\rpr=99\rescalate=true", "unknown"),
            ("/ai-review x\r\naction=review\r\npr=99\r\nreason=pull_request.synchronize", "unknown"),
            ("/ai-review x\naction<<EOF\nverdict\nEOF\npr<<EOF\n99\nEOF", "unknown"),
            ("/ai-review escalate: x\naction=skip\npr=99", "escalate"),
            ("/ai-review wontfix: x\r\naction=verdict\nescalate=true", "wontfix"),
        ]
        for kind in ("issue_comment", "pull_request_review_comment"):
            for assoc, login in (("NONE", "mallory"), ("OWNER", "o")):
                for body, cmd_kind in payloads:
                    with self.subTest(kind=kind, assoc=assoc, cmd_kind=cmd_kind, body=body):
                        ev = comment_event(body, assoc=assoc, login=login, kind=kind)
                        if kind == "pull_request_review_comment":
                            ev["pull_request"]["head"]["sha"] = VALID_SHA
                        rc, raw_out, parsed, _, _ = self._run_main(kind, ev)
                        self.assertEqual(rc, 0)
                        self.assertNotIn("\r", raw_out)
                        lines = raw_out.splitlines()
                        self.assertEqual(len(lines), len(route.OUTPUT_KEYS))
                        self.assertEqual([ln.split("=", 1)[0] for ln in lines], list(route.OUTPUT_KEYS))
                        self.assertEqual(list(parsed.keys()), list(route.OUTPUT_KEYS))
                        self.assertIn(parsed["reason"], route.REASONS)
                        for leaked in ("99", "EOF", "mallory", "pull_request.synchronize"):
                            self.assertNotIn(leaked, raw_out)
                        self.assertEqual(parsed["pr"], "7")
                        expected_sha = VALID_SHA if kind == "pull_request_review_comment" else ""
                        self.assertEqual(parsed["head_sha"], expected_sha)
                        if assoc == "NONE":
                            self.assertEqual(parsed["action"], "skip")
                            self.assertEqual(parsed["escalate"], "false")
                            self.assertIn("no write access", parsed["reason"])
                        elif cmd_kind == "unknown":
                            self.assertEqual(parsed["action"], "skip")
                            self.assertEqual(parsed["escalate"], "false")
                            self.assertEqual(parsed["reason"], "unknown /ai-review command")
                        elif cmd_kind == "escalate":
                            self.assertEqual(parsed["action"], "verdict")
                            self.assertEqual(parsed["escalate"], "true")
                        elif kind == "issue_comment":
                            # A top-level wontfix gets a hint, not a model round (#39).
                            self.assertEqual((parsed["action"], parsed["reason"], parsed["mode"]),
                                             ("verdict", "wontfix belongs in a finding thread", ""))
                            self.assertEqual(parsed["escalate"], "false")
                        else:
                            self.assertEqual((parsed["action"], parsed["mode"]), ("review", "wontfix_only"))
                            self.assertEqual(parsed["escalate"], "false")

    def test_main_writes_bind_override_line(self):
        ev = pr_event("labeled", label="human-override", sender={"login": "o", "type": "User"})
        ev["pull_request"]["head"]["sha"] = VALID_SHA
        rc, raw_out, parsed, _, _ = self._run_main("pull_request", ev)
        self.assertEqual(rc, 0)
        self.assertEqual(raw_out.splitlines()[-2:], ["bind_override=true", "mode="])
        self.assertEqual((parsed["action"], parsed["head_sha"]), ("verdict", VALID_SHA))

    def test_auth_runs_before_parsing(self):
        for kind in ("issue_comment", "pull_request_review_comment"):
            ev = comment_event("/ai-review frobnicate", assoc="NONE", login="mallory", kind=kind)
            res = route.decide(kind, ev, "o")
            self.assertEqual(res["action"], "skip")
            self.assertIn("no write access", res["reason"])
            self.assertNotIn("unknown", res["reason"])

        collab_unknown = route.decide(
            "issue_comment", comment_event("/ai-review frobnicate", assoc="COLLABORATOR", login="c"), "o"
        )
        self.assertEqual(collab_unknown["action"], "skip")
        self.assertEqual(collab_unknown["reason"], "unknown /ai-review command")

        collab_bare = route.decide(
            "issue_comment", comment_event("/ai-review", assoc="COLLABORATOR", login="c"), "o"
        )
        self.assertEqual(collab_bare["action"], "skip")
        self.assertEqual(collab_bare["reason"], "only the owner can force a re-review")

        empty_owner = route.decide(
            "issue_comment", comment_event("/ai-review", assoc="OWNER", login=""), ""
        )
        self.assertEqual(empty_owner["action"], "skip")

    def test_malicious_label_and_event_names(self):
        for label in ("bug\naction=verdict\nescalate=true", "x\raction=review", "x\naction<<EOF\nverdict\nEOF"):
            ev = pr_event("labeled", label=label)
            ev["pull_request"]["head"]["sha"] = VALID_SHA
            rc, raw_out, parsed, _, _ = self._run_main("pull_request", ev)
            self.assertEqual(rc, 0)
            self.assertEqual(len(raw_out.splitlines()), len(route.OUTPUT_KEYS))
            self.assertEqual(parsed["action"], "skip")
            self.assertEqual(parsed["escalate"], "false")
            self.assertEqual(parsed["reason"], "label is not a pr-guardian control")
            self.assertNotIn("bug", raw_out)
            self.assertNotIn("EOF", raw_out)

        bad_action = route.decide("pull_request", pr_event("closed\naction=review"), "o")
        self.assertEqual(bad_action["action"], "skip")
        self.assertIn(bad_action["reason"], route.REASONS)
        self.assertNotIn("closed", bad_action["reason"])

        bad_event = route.decide("push\naction=verdict", {}, "o")
        self.assertEqual(bad_event["action"], "skip")
        self.assertIn(bad_event["reason"], route.REASONS)
        self.assertNotIn("push", bad_event["reason"])

    def test_workflow_dispatch_pr_validation(self):
        bad_prs = [
            "3\naction=verdict",
            "3\r\naction=verdict",
            "3\n",
            "0",
            "07",
            "-1",
            "--repo=x/y",
            "abc",
            "",
            " 3 ",
            "\u0663",  # Arabic-Indic digit 3
            "\u00b2",  # Superscript 2
            "12345678901",
            None,
            True,
            0,
            -5,
        ]
        for bad in bad_prs:
            with self.subTest(bad=bad):
                res = route.decide("workflow_dispatch", {"inputs": {"pr": bad}}, "o")
                self.assertEqual(res["action"], "skip")
                self.assertEqual(res["pr"], "")
                self.assertEqual(res["escalate"], "false")
                self.assertIn(res["reason"], route.REASONS)

        for payload in ("3\naction=verdict", "\u0663", "--repo=x/y"):
            rc, raw_out, parsed, _, _ = self._run_main("workflow_dispatch", {"inputs": {"pr": payload}})
            self.assertEqual(rc, 0)
            self.assertEqual(len(raw_out.splitlines()), len(route.OUTPUT_KEYS))
            self.assertEqual(parsed["action"], "skip")
            self.assertEqual(parsed["pr"], "")
            self.assertNotIn("verdict", raw_out)

        self.assertEqual(route.decide("workflow_dispatch", {"inputs": None}, "o")["action"], "skip")
        for good, expected in (("3", "3"), ("9999999999", "9999999999"), (42, "42")):
            res = route.decide("workflow_dispatch", {"inputs": {"pr": good}}, "o")
            self.assertEqual((res["action"], res["pr"], res["reason"], res["mode"]),
                             ("review", expected, "manual dispatch", "full"))

    def test_validate_output_rejects_bad_fields_to_safe_skip(self):
        base = {
            "action": "review",
            "pr": "7",
            "head_sha": VALID_SHA,
            "escalate": "false",
            "reason": "manual dispatch",
            "bind_override": "false",
            "mode": "full",
        }
        # Valid 40-char and 64-char SHAs pass untouched.
        self.assertEqual(route.validate_output(base), base)
        base_256 = {**base, "head_sha": VALID_SHA256}
        self.assertEqual(route.validate_output(base_256), base_256)
        bind = {**base, "action": "verdict", "reason": "human-override label applied", "bind_override": "true",
                "mode": ""}
        self.assertEqual(route.validate_output(bind), bind)
        wontfix = {**base, "reason": "pushback from a writer", "mode": "wontfix_only"}
        self.assertEqual(route.validate_output(wontfix), wontfix)

        bad_cases = [
            None,
            ["skip"],
            {"action": "skip", "pr": "", "head_sha": "", "escalate": "false"},  # missing key
            {**base, "extra": "SECRET_MARKER"},
            {"pr": "7", "action": "review", "head_sha": VALID_SHA, "escalate": "false", "reason": "manual dispatch"},
            {**base, "pr": 7},
            {**base, "escalate": True},
            {**base, "action": "approve"},
            {**base, "action": "review\nSECRET_MARKER"},
            {**base, "escalate": "yes"},
            {**base, "pr": "0"},
            {**base, "pr": "07"},
            {**base, "pr": "-1"},
            {**base, "pr": "\u0663"},
            {**base, "pr": "12345678901"},
            {**base, "pr": "7\nSECRET_MARKER"},
            {**base, "pr": ""},  # non-empty required for review
            {**base, "action": "verdict", "pr": ""},  # non-empty required for verdict
            {**base, "head_sha": "abc"},
            {**base, "head_sha": "a" * 39},
            {**base, "head_sha": "a" * 41},
            {**base, "head_sha": "a" * 63},
            {**base, "head_sha": "a" * 65},
            {**base, "head_sha": "A" * 40},
            {**base, "head_sha": "g" * 40},
            {**base, "head_sha": VALID_SHA + "\nSECRET_MARKER"},
            {**base, "reason": ""},
            {**base, "reason": "SECRET_MARKER_UNKNOWN"},
            {**base, "reason": "manual dispatch\nSECRET_MARKER"},
            {**base, "reason": "manual dispatch\rSECRET_MARKER"},
            {**base, "reason": "manual dispatch\x00"},
            {**base, "reason": "manual dispatch\x1b"},
            {**base, "reason": "manual dispatch \u2014 ok"},
            {k: v for k, v in base.items() if k != "bind_override"},
            {**base, "bind_override": True},
            {**base, "bind_override": "yes"},
            {**base, "bind_override": "TRUE"},
            {**base, "bind_override": ""},
            {**base, "bind_override": "true\nSECRET_MARKER"},
            {k: v for k, v in base.items() if k != "mode"},
            {**base, "mode": ""},  # a review always names its mode
            {**base, "mode": "FULL"},
            {**base, "mode": "fast"},
            {**base, "mode": "full\nSECRET_MARKER"},
            {**base, "mode": None},
            {**bind, "mode": "full"},  # mode only on review
            {**bind, "mode": "wontfix_only"},
            {**base, "action": "skip", "pr": "", "head_sha": "", "reason": "event not handled"},
            {**base, "mode": "full", "extra": "x"},
        ]
        for bad in bad_cases:
            with self.subTest(bad=bad):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    out = route.validate_output(bad)
                self.assertEqual(out, route.SAFE_SKIP)
                err_line = stderr.getvalue().strip()
                parsed_err = json.loads(err_line)
                self.assertEqual(parsed_err["error"], "invalid route output")
                self.assertNotIn("SECRET_MARKER", err_line)

        # End-to-end main() fallback when decide() yields invalid output or short fixture SHA.
        with mock.patch.object(route, "decide", return_value={**base, "reason": "bad\naction=verdict"}):
            rc, raw_out, parsed, stdout_val, stderr_val = self._run_main("push", {})
        self.assertEqual(rc, 0)
        self.assertEqual(parsed, route.SAFE_SKIP)
        self.assertEqual(json.loads(stdout_val), route.SAFE_SKIP)
        self.assertEqual(len(raw_out.splitlines()), len(route.OUTPUT_KEYS))
        self.assertIn("invalid route output", json.loads(stderr_val)["error"])

        rc, _, parsed_short, _, stderr_short = self._run_main("pull_request", pr_event())
        self.assertEqual(rc, 0)
        self.assertEqual(parsed_short, route.SAFE_SKIP)
        self.assertEqual(json.loads(stderr_short)["detail"], "invalid head_sha")

    def test_synchronize_reason_and_closed_reasons_set(self):
        sync = route.decide("pull_request", pr_event("synchronize"), "o")
        self.assertEqual(sync["reason"], "pull_request.synchronize")

        for reason in route.REASONS:
            self.assertTrue(reason)
            self.assertTrue(all(0x20 <= ord(ch) <= 0x7E for ch in reason))

        issue_only = comment_event("/ai-review")
        del issue_only["issue"]["pull_request"]
        samples = [
            route.decide("pull_request", pr_event("opened"), "o"),
            sync,
            route.decide("pull_request", pr_event("reopened"), "o"),
            route.decide("pull_request", pr_event("ready_for_review"), "o"),
            route.decide("pull_request", pr_event("labeled", label="human-override"), "o"),
            route.decide("pull_request", pr_event("unlabeled", label="human-override"), "o"),
            route.decide("pull_request", pr_event("labeled", label="bug"), "o"),
            route.decide("pull_request", pr_event("closed"), "o"),
            route.decide("pull_request", retarget_event(), "o"),
            route.decide("pull_request", pr_event("edited"), "o"),
            route.decide("pull_request", pr_event(draft=True), "o"),
            route.decide("pull_request", pr_event(fork=True), "o"),
            route.decide("pull_request", {"action": "opened", "pull_request": {"number": "7\nfoo", "head": {"sha": "abc"}, "base": {"repo": {"full_name": "o/r"}}}}, "o"),
            route.decide("issue_comment", comment_event("lgtm"), "o"),
            route.decide("issue_comment", comment_event("/ai-review", bot=True), "o"),
            route.decide("issue_comment", issue_only, "o"),
            route.decide("issue_comment", comment_event("/ai-review", assoc="NONE", login="m"), "o"),
            route.decide("issue_comment", comment_event("/ai-review escalate"), "o"),
            route.decide("issue_comment", comment_event("/ai-review wontfix"), "o"),
            route.decide("issue_comment", comment_event("/ai-review", assoc="COLLABORATOR", login="c"), "o"),
            route.decide("issue_comment", comment_event("/ai-review"), "o"),
            route.decide("issue_comment", comment_event("/ai-review nope"), "o"),
            route.decide("pull_request", pr_event("unlabeled", label="needs-human"), "o"),
            route.decide("issue_comment", comment_event("/ai-review help"), "o"),
            route.decide("issue_comment", comment_event("/ai-review explain R-001"), "o"),
            route.decide("issue_comment", comment_event("/ai-review explain"), "o"),
            route.decide("issue_comment", comment_event("/ai-review override " + "a" * 12 + ": ok then"), "o"),
            route.decide("issue_comment", comment_event("/ai-review override"), "o"),
            route.decide("issue_comment", comment_event("/ai-review override " + "a" * 12 + ": ok then",
                                                        assoc="COLLABORATOR", login="c"), "o"),
            route.decide("pull_request_review_comment",
                         comment_event("/ai-review override " + "a" * 12 + ": ok then", kind="review"), "o"),
            route.decide("workflow_dispatch", {"inputs": {"pr": "3"}}, "o"),
            route.decide("workflow_dispatch", {"inputs": {"pr": "0"}}, "o"),
            route.decide("push", {}, "o"),
            route.SAFE_SKIP,
        ]
        for res in samples:
            self.assertIn(res["reason"], route.REASONS)


class BaseRetargetRouteTest(unittest.TestCase):
    """GHSA-6h55-p37r-jc34: a base retarget is re-reviewed; other edits are not."""

    def test_retarget_reviews(self):
        for prev in ("stage", "0", "release/1.0", "main"):
            with self.subTest(prev=prev):
                r = route.decide("pull_request", retarget_event(prev), "o")
                self.assertEqual((r["action"], r["reason"], r["head_sha"], r["pr"], r["bind_override"]),
                                 ("review", "pull_request.edited", "abc", "7", "false"))
                ev = retarget_event(prev)
                ev["pull_request"]["head"]["sha"] = VALID_SHA
                full = route.decide("pull_request", ev, "o")
                self.assertEqual(route.validate_output(full), full)

    def test_title_body_and_malformed_edits_skip(self):
        changes = (None, {}, [], "base", {"title": {"from": "old"}}, {"body": {"from": "old"}},
                   {"base": None}, {"base": {}}, {"base": []}, {"base": {"ref": None}}, {"base": {"ref": {}}},
                   {"base": {"ref": "stage"}}, {"base": {"ref": {"from": ""}}}, {"base": {"ref": {"from": None}}},
                   {"base": {"ref": {"from": 0}}}, {"base": {"ref": {"from": ["stage"]}}},
                   {"base": {"sha": {"from": "f" * 40}}})
        for ch in changes:
            with self.subTest(changes=ch):
                ev = pr_event("edited")
                if ch is not None:
                    ev["changes"] = ch
                r = route.decide("pull_request", ev, "o")
                self.assertEqual((r["action"], r["reason"]),
                                 ("skip", "pull_request action does not trigger a review"))

    def test_retarget_of_draft_or_fork(self):
        r = route.decide("pull_request", retarget_event(draft=True), "o")
        self.assertEqual((r["action"], r["reason"]), ("skip", "draft PR; review starts when marked ready"))
        r = route.decide("pull_request", retarget_event(fork=True), "o")
        self.assertEqual(r["action"], "verdict")
        self.assertIn("fork", r["reason"])

    def test_base_change_payload_on_other_actions_changes_nothing(self):
        ev = retarget_event()
        ev["action"] = "closed"
        self.assertEqual(route.decide("pull_request", ev, "o")["action"], "skip")
        ev["action"] = "synchronize"
        self.assertEqual(route.decide("pull_request", ev, "o")["reason"], "pull_request.synchronize")


OVR_CMD = "/ai-review override " + "a" * 12 + ": reviewed the fork by hand"


class CommandRouteTest(unittest.TestCase):
    """#39 / #43: help, explain, override, wontfix placement and the review mode."""

    def d(self, body, kind="issue_comment", **kw):
        ev = comment_event(body, kind=kind, **kw)
        return route.decide(kind, ev, "o")

    def check(self, res, action, reason, mode="", escalate="false"):
        self.assertEqual((res["action"], res["reason"], res["mode"], res["escalate"], res["bind_override"]),
                         (action, reason, mode, escalate, "false"))
        self.assertIn(res["reason"], route.REASONS)

    def test_writer_info_commands_route_to_verdict(self):
        for kind in ("issue_comment", "pull_request_review_comment"):
            for assoc, login in (("OWNER", "o"), ("MEMBER", "m"), ("COLLABORATOR", "c")):
                with self.subTest(kind=kind, assoc=assoc):
                    self.check(self.d("/ai-review help", kind, assoc=assoc, login=login), "verdict", "help requested")
                    self.check(self.d("/ai-review help me", kind, assoc=assoc, login=login),
                               "verdict", "help requested")
                    self.check(self.d("/ai-review explain R-001", kind, assoc=assoc, login=login),
                               "verdict", "explain requested")
                    # Malformed ids still reach verdict, which replies with the usage.
                    for bad in ("/ai-review explain", "/ai-review explain r-001", "/ai-review explain R-1"):
                        self.check(self.d(bad, kind, assoc=assoc, login=login), "verdict", "explain requested")

    def test_owner_override_on_conversation(self):
        self.check(self.d(OVR_CMD), "verdict", "override requested by owner")
        for bad in ("/ai-review override", "/ai-review override: because", "/ai-review override abc: because",
                    "/ai-review override " + "a" * 12, "/ai-review override " + "a" * 12 + ": x",
                    "/ai-review override " + "A" * 12 + ": because"):
            with self.subTest(body=bad):
                self.check(self.d(bad), "verdict", "override needs a head SHA and a reason")

    def test_override_owner_check(self):
        for assoc, login in (("COLLABORATOR", "c"), ("MEMBER", "m"), ("COLLABORATOR", "o"), ("MEMBER", "o"),
                             ("OWNER", "O"), ("OWNER", "not-o")):
            for kind in ("issue_comment", "pull_request_review_comment"):
                with self.subTest(assoc=assoc, login=login, kind=kind):
                    self.check(self.d(OVR_CMD, kind, assoc=assoc, login=login), "skip", "only the owner can override")
        self.check(route.decide("issue_comment", comment_event(OVR_CMD, login=""), ""),
                   "skip", "only the owner can override")

    def test_owner_override_in_thread_gets_a_hint(self):
        self.check(self.d(OVR_CMD, "pull_request_review_comment"),
                   "verdict", "override must be a top-level PR comment")

    def test_wontfix_placement(self):
        for body in ("/ai-review wontfix: fp", "/ai-review wontfix"):
            self.check(self.d(body), "verdict", "wontfix belongs in a finding thread")
            res = self.d(body, "pull_request_review_comment", assoc="COLLABORATOR", login="c")
            self.check(res, "review", "pushback from a writer", mode="wontfix_only")

    def test_review_modes(self):
        self.check(self.d("/ai-review"), "review", "re-review requested by owner", mode="full")
        self.check(self.d("/ai-review", "pull_request_review_comment"), "review", "re-review requested by owner",
                   mode="full")
        for assoc in ("MEMBER", "COLLABORATOR"):  # the owner's login alone is not enough
            self.check(self.d("/ai-review", assoc=assoc), "skip", "only the owner can force a re-review")
        self.assertEqual(route.decide("pull_request", pr_event(), "o")["mode"], "full")
        self.assertEqual(route.decide("pull_request", retarget_event(), "o")["mode"], "full")
        self.assertEqual(route.decide("workflow_dispatch", {"inputs": {"pr": "3"}}, "o")["mode"], "full")
        self.check(self.d("/ai-review escalate: loops"), "verdict", "escalated by a writer", escalate="true")

    def test_outsiders_and_bots_stay_skipped(self):
        for body in ("/ai-review help", "/ai-review explain R-001", OVR_CMD, "/ai-review wontfix: x"):
            for kind in ("issue_comment", "pull_request_review_comment"):
                with self.subTest(body=body, kind=kind):
                    self.check(self.d(body, kind, assoc="NONE", login="o"), "skip", "commenter has no write access")
                    self.check(self.d(body, kind, assoc="CONTRIBUTOR", login="mallory"),
                               "skip", "commenter has no write access")
                    self.check(self.d(body, kind, bot=True), "skip", "not a /ai-review command")

    def test_unknown_subcommands_still_skip(self):
        for body in ("/ai-review frobnicate", "/ai-review helpme", "/ai-review overrides " + "a" * 12 + ": x y z",
                     "/ai-reviewhelp", "/ai-review explainR-001", "/ai-review ", "/ai-review  ",
                     "/ai-review\r\n", "/ai-review  wontfix: fp", "/ai-review\twontfix: fp",
                     "/ai-review\nwontfix: fp", "/ai-review  help"):
            with self.subTest(body=body):
                self.check(self.d(body), "skip", "unknown /ai-review command")
                self.check(self.d(body, "pull_request_review_comment"), "skip", "unknown /ai-review command")

    def test_case_and_leading_whitespace_match_caller_gate(self):
        """R-001: route agrees with GitHub Actions case-insensitive == and startsWith without trim."""
        for body in ("/AI-REVIEW", "/Ai-Review"):
            self.check(self.d(body), "review", "re-review requested by owner", mode="full")
            self.check(self.d(body, "pull_request_review_comment"), "review",
                       "re-review requested by owner", mode="full")
        for body in ("/AI-REVIEW wontfix: fp", "/ai-review WONTFIX: fp", "/AI-REVIEW WONTFIX: fp"):
            self.check(self.d(body), "verdict", "wontfix belongs in a finding thread")
            self.check(self.d(body, "pull_request_review_comment", assoc="COLLABORATOR", login="c"),
                       "review", "pushback from a writer", mode="wontfix_only")
        self.check(self.d("/AI-REVIEW HELP"), "verdict", "help requested")
        self.check(self.d("/AI-REVIEW EXPLAIN R-001"), "verdict", "explain requested")
        self.check(self.d("/AI-REVIEW ESCALATE: stuck"), "verdict", "escalated by a writer", escalate="true")
        self.check(self.d("/AI-REVIEW OVERRIDE " + "a" * 12 + ": reviewed by hand"),
                   "verdict", "override requested by owner")
        for body in ("  /ai-review", "\n/ai-review", "  /ai-review help", " /ai-review wontfix: fp"):
            for kind in ("issue_comment", "pull_request_review_comment"):
                self.check(self.d(body, kind), "skip", "not a /ai-review command")

    def test_command_text_never_reaches_outputs(self):
        body = "/ai-review override " + "a" * 12 + ": SECRET\naction=review\nmode=full\npr=99"
        res = route.validate_output(route.decide("issue_comment", comment_event(body), "o"))
        self.assertEqual(res["reason"], "override requested by owner")
        self.assertNotIn("SECRET", json.dumps(res))
        self.assertEqual((res["pr"], res["mode"]), ("7", ""))


class NeedsHumanUnlabeledTest(unittest.TestCase):
    """#27: removing needs-human recomputes the verdict; applying it never starts a run."""

    def test_unlabeled_needs_human_routes_to_verdict(self):
        for sender in ({"login": "o", "type": "User"}, {"login": "c", "type": "User"}, None):
            for kw in ({}, {"draft": True}, {"fork": True}):
                with self.subTest(sender=sender, **kw):
                    ev = pr_event("unlabeled", label="needs-human", sender=sender, **kw)
                    ev["pull_request"]["head"]["sha"] = VALID_SHA
                    res = route.decide("pull_request", ev, "o")
                    self.assertEqual((res["action"], res["reason"], res["head_sha"], res["bind_override"], res["mode"]),
                                     ("verdict", "needs-human label removed", VALID_SHA, "false", ""))
                    self.assertEqual(route.validate_output(res), res)

    def test_labeled_needs_human_skips(self):
        res = route.decide("pull_request", pr_event("labeled", label="needs-human"), "o")
        self.assertEqual((res["action"], res["reason"]), ("skip", "label is not a pr-guardian control"))

    def test_human_override_removal_unchanged(self):
        res = route.decide("pull_request", pr_event("unlabeled", label="human-override"), "o")
        self.assertEqual((res["action"], res["reason"]), ("verdict", "human-override label removed"))


if __name__ == "__main__":
    unittest.main()
