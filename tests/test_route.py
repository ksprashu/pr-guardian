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


def pr_event(action="opened", draft=False, fork=False, label=None):
    base = {"full_name": "o/r"}
    ev = {"action": action, "pull_request": {
        "number": 7, "draft": draft, "head": {"sha": "abc", "repo": {"full_name": "x/r" if fork else "o/r"}},
        "base": {"repo": base}}}
    if label:
        ev["label"] = {"name": label}
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
        self.assertEqual(route.decide("pull_request", pr_event("labeled", label="human-override"), "o")["action"],
                         "verdict")
        self.assertEqual(route.decide("pull_request", pr_event("labeled", label="bug"), "o")["action"], "skip")

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
                        self.assertEqual(len(lines), 5)
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
                        else:
                            self.assertEqual(parsed["action"], "review")
                            self.assertEqual(parsed["escalate"], "false")

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
            self.assertEqual(len(raw_out.splitlines()), 5)
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
            self.assertEqual(len(raw_out.splitlines()), 5)
            self.assertEqual(parsed["action"], "skip")
            self.assertEqual(parsed["pr"], "")
            self.assertNotIn("verdict", raw_out)

        self.assertEqual(route.decide("workflow_dispatch", {"inputs": None}, "o")["action"], "skip")
        for good, expected in (("3", "3"), ("9999999999", "9999999999"), (42, "42")):
            res = route.decide("workflow_dispatch", {"inputs": {"pr": good}}, "o")
            self.assertEqual((res["action"], res["pr"], res["reason"]), ("review", expected, "manual dispatch"))

    def test_validate_output_rejects_bad_fields_to_safe_skip(self):
        base = {
            "action": "review",
            "pr": "7",
            "head_sha": VALID_SHA,
            "escalate": "false",
            "reason": "manual dispatch",
        }
        # Valid 40-char and 64-char SHAs pass untouched.
        self.assertEqual(route.validate_output(base), base)
        base_256 = {**base, "head_sha": VALID_SHA256}
        self.assertEqual(route.validate_output(base_256), base_256)

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
        self.assertEqual(len(raw_out.splitlines()), 5)
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
            route.decide("pull_request", pr_event("labeled", label="bug"), "o"),
            route.decide("pull_request", pr_event("closed"), "o"),
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
            route.decide("workflow_dispatch", {"inputs": {"pr": "3"}}, "o"),
            route.decide("workflow_dispatch", {"inputs": {"pr": "0"}}, "o"),
            route.decide("push", {}, "o"),
            route.SAFE_SKIP,
        ]
        for res in samples:
            self.assertIn(res["reason"], route.REASONS)


if __name__ == "__main__":
    unittest.main()
