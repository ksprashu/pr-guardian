import base64
import copy
from datetime import datetime, timezone
import json
import subprocess
import unittest
from unittest import mock

from tests.helpers import *  # noqa: F401,F403
import governor as g
import state as st


class GovernorTest(unittest.TestCase):
    def test_missing_ruleset(self):
        self.assertEqual(g.ruleset_drift(None), ["ruleset missing"])

    def test_echoed_ruleset_with_defaults_is_clean(self):
        have = copy.deepcopy(g.desired_ruleset())
        have.update(id=1, source="o/r", source_type="Repository")
        have["rules"][3]["parameters"]["automatic_copilot_code_review_enabled"] = False
        have["rules"].reverse()
        self.assertEqual(g.ruleset_drift(have), [])

    def test_drift_detected(self):
        for mutate, needle in [
            (lambda r: r.update(enforcement="disabled"), "enforcement"),
            (lambda r: r.update(bypass_actors=[{"actor_id": 5, "actor_type": "RepositoryRole"}]), "bypass"),
            (lambda r: r["rules"].pop(0), "deletion"),
            (lambda r: r["rules"][3]["parameters"].update(required_review_thread_resolution=False), "pull_request"),
            (lambda r: r["rules"][4]["parameters"]["required_status_checks"][0].update(integration_id=1),
             "required_status_checks"),
        ]:
            have = copy.deepcopy(g.desired_ruleset())
            mutate(have)
            drift = g.ruleset_drift(have)
            self.assertTrue(any(needle in d for d in drift), (needle, drift))

    def test_settings_drift(self):
        repo = dict(g.SETTINGS)
        self.assertEqual(g.settings_drift(repo), [])
        repo["allow_merge_commit"] = True
        self.assertEqual(g.settings_drift(repo), ["setting allow_merge_commit=True"])

    def test_caller_render(self):
        text = g.render_caller("0123abc")
        self.assertIn("review.yml@0123abc", text)
        self.assertIn("guardian_ref: 0123abc", text)
        self.assertNotIn("{{REF}}", text)


class ReconcileSettingsTest(unittest.TestCase):
    """user/repos list entries omit the merge settings; reconcile must read the full repo."""

    def test_settings_read_from_full_repo_not_list_entry(self):
        listed = {"full_name": "o/r", "default_branch": "", "size": 0}  # list shape: no allow_* keys
        full = dict(listed, **g.SETTINGS)
        with mock.patch.object(g.gh, "api", side_effect=lambda path, *a, **k: full if path == "repos/o/r" else []):
            out = g.reconcile(listed, "v1", dry=True, have_key=False)
        self.assertFalse([d for d in out["drift"] if d.startswith("setting ")], out["drift"])


class DriftReportTest(unittest.TestCase):
    """The report is written with REPORT_TOKEN (the workflow token), not the governor PAT."""

    def run_main(self, issues):
        calls = []
        ref = "a" * 40

        def api(path, method="GET", body=None, paginate=False, token=None):
            calls.append((path, method, token))
            if path == f"repos/o/pr-guardian/commits/{ref}":
                return {"sha": ref}
            if path == "repos/o/pr-guardian":
                return {"default_branch": "main"}
            if path == f"repos/o/pr-guardian/compare/{ref}...main":
                return {"status": "identical"}
            return issues if path.startswith("repos/o/pr-guardian/issues?") else None

        env = {"PRG_OWNER": "o", "REPORT_TOKEN": "wf-token", "GEMINI_API_KEY": "", "PRG_REF": ref}
        with mock.patch.dict(g.os.environ, env, clear=True), mock.patch.object(g.gh, "api", side_effect=api), \
                mock.patch.object(g, "list_repos", return_value=[]), \
                mock.patch.object(g.sys, "argv", ["governor.py", "--report-issue"]), \
                mock.patch("builtins.print"):
            g.main()
        return [c for c in calls if c[0].startswith("repos/o/pr-guardian/issues")]

    def test_updates_trusted_report_with_workflow_token(self):
        issues = [{"number": 9, "title": "Governor drift report", "user": {"login": "mallory"}},
                  {"number": 1, "title": "Governor drift report", "user": {"login": "o"}}]
        calls = self.run_main(issues)
        self.assertEqual(calls[-1], ("repos/o/pr-guardian/issues/1", "PATCH", "wf-token"))
        self.assertTrue(all(token == "wf-token" for _, _, token in calls))

    def test_creates_report_when_only_untrusted_match(self):
        issues = [{"number": 9, "title": "Governor drift report", "user": {"login": "mallory"}}]
        self.assertEqual(self.run_main(issues)[-1], ("repos/o/pr-guardian/issues", "POST", "wf-token"))


class GitlessRepoTest(unittest.TestCase):
    """A repo with a size but no branches (yo-angular-express-seed) waits like an empty repo."""

    def test_size_without_branch_is_empty(self):
        repo = {"full_name": "o/r", "default_branch": "master", "size": 56}

        def api(path, *a, **k):
            if path == "repos/o/r":
                return dict(repo, **g.SETTINGS)
            if path == "repos/o/r/branches/master":
                raise g.gh.GhError("gh api repos/o/r/branches/master… failed: Git Repository is empty. (HTTP 409)")
            return []

        with mock.patch.object(g.gh, "api", side_effect=api):
            out = g.reconcile(repo, "v1", dry=True, have_key=False)
        msg = "empty repo: caller and ruleset wait for the first commit"
        self.assertIn(msg, out["waiting"])
        self.assertNotIn(msg, out["drift"])
        self.assertFalse(out["errors"][1:], out["errors"])


class VerdictAppIdTest(unittest.TestCase):
    """GHSA-v7qp-pmhq-cf47: the verdict's required integration is configurable, validated up front."""

    def env(self, value):
        env = {k: v for k, v in g.os.environ.items() if k != "PRG_VERDICT_APP_ID"}
        if value is not None:
            env["PRG_VERDICT_APP_ID"] = value
        return mock.patch.dict(g.os.environ, env, clear=True)

    def pinned(self):
        return g.desired_ruleset()["rules"][4]["parameters"]["required_status_checks"]

    def test_unset_or_blank_keeps_github_actions(self):
        for value in (None, "", "   ", "\n"):
            with self.subTest(value=value), self.env(value):
                self.assertEqual(g.verdict_app_id(), g.ACTIONS_APP_ID)
                self.assertEqual(self.pinned(), [{"context": g.VERDICT_CONTEXT, "integration_id": 15368}])

    def test_positive_integer_overrides_dynamically(self):
        for value, want in (("123456", 123456), (" 987\n", 987), ("1", 1)):
            with self.subTest(value=value), self.env(value):
                self.assertEqual(g.verdict_app_id(), want)
                self.assertEqual(self.pinned()[0]["integration_id"], want)

    def test_override_makes_actions_pinned_ruleset_drift(self):
        with self.env(None):
            have = copy.deepcopy(g.desired_ruleset())
        with self.env("123456"):
            self.assertIn("ruleset rule required_status_checks differs", g.ruleset_drift(have))
        with self.env(None):
            self.assertEqual(g.ruleset_drift(have), [])

    def test_invalid_values_raise(self):
        for value in ("0", "00", "007", "-5", "+5", "1.5", "1e3", "1_000", "0x10", "12a", "abc",
                      "١٢٣", "²", "１２", "1 2", "15368;", "None"):
            with self.subTest(value=value), self.env(value), self.assertRaises(ValueError):
                g.verdict_app_id()

    def test_main_exits_2_before_any_api_call(self):
        with self.env("not-an-id"), mock.patch.object(g.gh, "api") as api, \
                mock.patch.object(g, "list_repos") as lr, \
                mock.patch.object(g.sys, "argv", ["governor.py", "--dry-run"]), \
                mock.patch("sys.stderr"), mock.patch("builtins.print"):
            self.assertEqual(g.main(), 2)
        api.assert_not_called()
        lr.assert_not_called()

    def test_main_runs_with_valid_override(self):
        with self.env("123456"), mock.patch.dict(g.os.environ, {"PRG_OWNER": "o", "GEMINI_API_KEY": ""}), \
                mock.patch.object(g, "list_repos", return_value=[]) as lr, \
                mock.patch.object(g.sys, "argv", ["governor.py", "--dry-run"]), \
                mock.patch("builtins.print"):
            self.assertEqual(g.main(), 0)
        lr.assert_called_once_with("o")


class Api:
    """Routes for g.gh.api and g.gh._run. Unknown GETs return []; every call is recorded."""

    def __init__(self, routes=None, run=None):
        self.routes, self.run_routes, self.calls, self.runs = routes or {}, run or {}, [], []

    def api(self, path, method="GET", body=None, paginate=False, token=None):
        self.calls.append((method, path, body))
        hit = self.routes.get((method, path), self.routes.get(path))
        if isinstance(hit, Exception):
            raise hit
        return hit(body) if callable(hit) else ([] if hit is None and method == "GET" else hit)

    def _run(self, args, stdin=None, token=None):
        self.runs.append((tuple(args), stdin))
        hit = self.run_routes.get(tuple(args[:2]))
        if isinstance(hit, Exception):
            raise hit
        return hit(args) if callable(hit) else (hit if hit is not None else "[]")

    @property
    def writes(self):
        return [c for c in self.calls if c[0] != "GET"] + [r for r in self.runs if r[0][:2] != ("secret", "list")]


REF = "a" * 40


def _b64_file(text, sha="blob1"):
    return {"type": "file", "encoding": "base64", "sha": sha,
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii")}


def _repo(name="r", owner="o", default="main", topics=(), size=10):
    return {"name": name, "full_name": f"{owner}/{name}", "owner": {"login": owner},
            "fork": False, "archived": False, "default_branch": default,
            "topics": list(topics), "size": size}


def _clean_routes(repos, ref=REF, owner="o", secrets=("GEMINI_API_KEY",)):
    want = g.render_caller(ref)
    routes = {
        "user": {"login": owner},
        "user/repos?affiliation=owner&per_page=100": repos,
        f"repos/{owner}/{g.HOME_REPO}/commits/{ref}": {"sha": ref},
        f"repos/{owner}/{g.HOME_REPO}": {"default_branch": "main"},
        f"repos/{owner}/{g.HOME_REPO}/compare/{ref}...main": {"status": "identical"},
    }
    for r in repos:
        full = r["full_name"]
        default = r.get("default_branch") or ""
        routes[f"repos/{full}"] = dict(r, **g.SETTINGS)
        if default:
            routes[f"repos/{full}/branches/{default}"] = {"name": default}
            routes[f"repos/{full}/contents/{g.CALLER_PATH}?ref={default}"] = _b64_file(want)
            routes[f"repos/{full}/contents/{g.CALLER_PATH}?ref=pr-guardian%2Finstall"] = g.gh.GhError("404 Not Found")
            routes[f"repos/{full}/rulesets?includes_parents=false"] = [{"id": 1, "name": g.RULESET_NAME}]
            routes[f"repos/{full}/rulesets/1"] = dict(copy.deepcopy(g.desired_ruleset()), id=1)
    sec_json = json.dumps([{"name": s} for s in secrets])
    return routes, {("secret", "list"): sec_json}


def _run_main(fake, argv, env=None):
    base_env = {"PRG_OWNER": "o", "PRG_REF": REF, "GEMINI_API_KEY": "g-key"}
    if env is not None:
        base_env.update(env)
    with mock.patch.dict(g.os.environ, base_env, clear=True), \
            mock.patch.object(g.gh, "api", side_effect=fake.api), \
            mock.patch.object(g.gh, "_run", side_effect=fake._run), \
            mock.patch.object(g.sys, "argv", ["governor.py", *argv]), \
            mock.patch("sys.stderr"), mock.patch("builtins.print") as pr:
        code = g.main()
    printed = "\n".join(" ".join(str(a) for a in c.args) for c in pr.call_args_list)
    return code, printed


class ExitCodeTest(unittest.TestCase):
    """#28: exit code is driven by unresolved `pending`, never by `done` or empty repos."""

    def test_apply_queued_automerge_and_deferred_ruleset_exits_1(self):
        r = _repo("a")
        routes, runs = _clean_routes([r])
        routes[f"repos/o/a/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        routes[f"repos/o/a/git/ref/heads/main"] = {"object": {"sha": "head0"}}
        routes[("PUT", f"repos/o/a/contents/{g.CALLER_PATH}")] = {"commit": {"sha": "put1"}}
        routes[("POST", "repos/o/a/pulls")] = {"number": 7}
        fake = Api(routes, runs)
        code, _ = _run_main(fake, [])
        self.assertEqual(code, 1)

    def test_apply_all_fixes_resolve_exits_0(self):
        r = _repo("a")
        routes, runs = _clean_routes([r])
        routes["repos/o/a"]["allow_merge_commit"] = True
        routes[f"repos/o/a/git/ref/heads/main"] = {"object": {"sha": "head0"}}
        routes[("PUT", f"repos/o/a/contents/{g.CALLER_PATH}")] = {"commit": {"sha": "put1"}}
        routes[("POST", "repos/o/a/pulls")] = {"number": 7}
        routes[f"repos/o/a/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        del routes["repos/o/a/rulesets/1"]
        routes["repos/o/a/rulesets?includes_parents=false"] = []
        runs[("pr", "merge")] = lambda args: (_ for _ in ()).throw(g.gh.GhError("no ruleset")) if "--auto" in args else ""
        fake = Api(routes, runs)
        code, _ = _run_main(fake, [])
        self.assertEqual(code, 0)

    def test_dry_run_with_drift_exits_1(self):
        r = _repo("a")
        routes, runs = _clean_routes([r])
        routes["repos/o/a"]["allow_merge_commit"] = True
        fake = Api(routes, runs)
        code, _ = _run_main(fake, ["--dry-run"])
        self.assertEqual(code, 1)
        self.assertEqual(fake.writes, [])

    def test_only_empty_repo_exits_0(self):
        r = _repo("empty", default="main", size=0)
        routes, runs = _clean_routes([r])
        routes["repos/o/empty/branches/main"] = g.gh.GhError("HTTP 409 empty")
        fake = Api(routes, runs)
        code, _ = _run_main(fake, [])
        self.assertEqual(code, 0)

    def test_fix_raising_gh_error_exits_2(self):
        r = _repo("a")
        routes, runs = _clean_routes([r])
        routes["repos/o/a"]["allow_merge_commit"] = True
        routes[("PATCH", "repos/o/a")] = g.gh.GhError("HTTP 403")
        fake = Api(routes, runs)
        code, _ = _run_main(fake, [])
        self.assertEqual(code, 2)


class BroadExceptionTest(unittest.TestCase):
    """#28: non-GhError exceptions per-repo and per-step never abort the fleet."""

    def test_timeout_on_one_repo_still_reconciles_next(self):
        r1, r2 = _repo("a"), _repo("b")
        routes, runs = _clean_routes([r1, r2])
        routes["repos/o/a"] = subprocess.TimeoutExpired(["gh"], 120)
        fake = Api(routes, runs)
        code, printed = _run_main(fake, [])
        self.assertEqual(code, 2)
        self.assertIn("o/a", printed)
        self.assertIn("TimeoutExpired", printed)
        self.assertIn("2 repos · 1 clean · 0 pending · 1 error", printed)

    def test_contents_directory_listing_and_symlink_become_repo_errors(self):
        r1, r2 = _repo("dir"), _repo("link")
        routes, runs = _clean_routes([r1, r2])
        routes[f"repos/o/dir/contents/{g.CALLER_PATH}?ref=main"] = [{"name": "a.yml", "type": "file"}]
        routes[f"repos/o/link/contents/{g.CALLER_PATH}?ref=main"] = {"type": "symlink", "encoding": "base64", "content": ""}
        fake = Api(routes, runs)
        code, printed = _run_main(fake, [])
        self.assertEqual(code, 2)
        self.assertIn("not a regular file", printed)

    def test_step_key_error_does_not_abort_later_steps(self):
        r = _repo("a")
        routes, runs = _clean_routes([r])
        routes["repos/o/a"]["allow_merge_commit"] = True
        routes[("PATCH", "repos/o/a")] = KeyError("boom")
        runs[("secret", "list")] = "[]"
        fake = Api(routes, runs)
        with mock.patch.dict(g.os.environ, {"GEMINI_API_KEY": "secret-val"}, clear=True), \
                mock.patch.object(g.gh, "api", side_effect=fake.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake._run):
            out = g.reconcile(r, REF, dry=False, have_key=True)
        self.assertTrue(any("KeyError" in e for e in out["errors"]), out["errors"])
        self.assertIn("secret GEMINI_API_KEY set", out["done"])

    def test_file_errors_and_inspect_install_exception_do_not_abort_repo(self):
        # 500 error and invalid UTF-8 in file_on_branch both raise GhError
        fake_500 = Api({"repos/o/a/contents/x?ref=main": g.gh.GhError("500")})
        with mock.patch.object(g.gh, "api", side_effect=fake_500.api), self.assertRaises(g.gh.GhError):
            g.file_on_branch("o/a", "x", "main")
        bad_utf8 = {"type": "file", "encoding": "base64", "content": base64.b64encode(b"\xff\xfe").decode()}
        fake_utf8 = Api({"repos/o/a/contents/x?ref=main": bad_utf8})
        with mock.patch.object(g.gh, "api", side_effect=fake_utf8.api), self.assertRaises(g.gh.GhError):
            g.file_on_branch("o/a", "x", "main")

        # inspect_install raising when caller is stale does not skip ruleset update
        r = _repo("a")
        routes, runs = _clean_routes([r])
        routes[f"repos/o/a/contents/{g.CALLER_PATH}?ref=main"] = _b64_file("old")
        routes[f"repos/o/a/pulls?head=o:{g.INSTALL_BRANCH}&state=open&per_page=10"] = g.gh.GhError("502")
        routes["repos/o/a/rulesets/1"]["enforcement"] = "disabled"
        fake = Api(routes, runs)
        with mock.patch.dict(g.os.environ, {"GEMINI_API_KEY": "k"}, clear=True), \
                mock.patch.object(g.gh, "api", side_effect=fake.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake._run):
            out = g.reconcile(r, REF, dry=False, have_key=True)
        self.assertTrue(any("502" in e for e in out["errors"]), out["errors"])
        self.assertIn("ruleset updated", out["done"])


class EmptyRepoTest(unittest.TestCase):
    """#28: size=0 with an existing default branch is governed, not treated as empty."""

    def test_zero_size_with_branch_is_reconciled(self):
        r = _repo("small", default="main", size=0)
        routes, runs = _clean_routes([r])
        routes[f"repos/o/small/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        fake = Api(routes, runs)
        with mock.patch.dict(g.os.environ, {}, clear=True), \
                mock.patch.object(g.gh, "api", side_effect=fake.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake._run):
            out = g.reconcile(r, REF, dry=True, have_key=True)
        self.assertEqual(out["waiting"], [])
        self.assertIn("caller missing", out["drift"])


class PartialReportTest(unittest.TestCase):
    """#28: --report-issue only writes on full-fleet apply runs."""

    def test_partial_and_dry_runs_skip_issue_write_but_full_apply_patches(self):
        r = _repo("a")
        for extra in (["--dry-run"], ["--repos", "a"], ["--batch", "1"], ["--offset", "1"]):
            with self.subTest(extra=extra):
                routes, runs = _clean_routes([r])
                fake = Api(routes, runs)
                code, _ = _run_main(fake, ["--report-issue", *extra])
                self.assertEqual(code, 0)
                issue_calls = [c for c in fake.calls if "issues" in c[1]]
                self.assertEqual(issue_calls, [])

        routes, runs = _clean_routes([r])
        routes[f"repos/o/{g.HOME_REPO}/issues?state=open"] = [
            {"number": 3, "title": "Governor drift report", "user": {"login": "o"}},
        ]
        fake = Api(routes, runs)
        code, _ = _run_main(fake, ["--report-issue"])
        self.assertEqual(code, 0)
        patches = [c for c in fake.calls if c[0] == "PATCH" and c[1] == f"repos/o/{g.HOME_REPO}/issues/3"]
        self.assertEqual(len(patches), 1)


class InstallPrTest(unittest.TestCase):
    """#29 and #40: idempotent install PR state machine and --match-head-commit."""

    def _pr(self, number=12, changed_files=1, auto_merge=None, head_sha="prhead1",
            created_at="2026-11-14T10:00:00Z", mergeable_state="clean", fork_repo="o/r"):
        return {
            "number": number,
            "changed_files": changed_files,
            "auto_merge": auto_merge,
            "created_at": created_at,
            "mergeable_state": mergeable_state,
            "base": {"ref": "main"},
            "head": {"ref": g.INSTALL_BRANCH, "sha": head_sha, "repo": {"full_name": fork_repo}},
        }

    def test_state_a_auto_merge_queued_makes_zero_writes_across_two_runs(self):
        want = g.render_caller(REF)
        pr = self._pr(auto_merge={"merge_method": "squash"})
        r = _repo("r")
        routes, runs = _clean_routes([r])
        routes[f"repos/o/r/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        routes[f"repos/o/r/pulls?head=o:{g.INSTALL_BRANCH}&state=open&per_page=10"] = [pr]
        routes["repos/o/r/pulls/12"] = pr
        routes["repos/o/r/pulls/12/files?per_page=100"] = [{"filename": g.CALLER_PATH}]
        routes[f"repos/o/r/contents/{g.CALLER_PATH}?ref={g.urllib.parse.quote(g.INSTALL_BRANCH, safe='')}"] = _b64_file(want, "b1")
        routes["repos/o/r/branches/main/protection"] = g.gh.GhError("404 Not Found")
        fake = Api(routes, runs)
        with mock.patch.dict(g.os.environ, {}, clear=True), \
                mock.patch.object(g.gh, "api", side_effect=fake.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake._run):
            out1 = g.reconcile(r, REF, dry=False, have_key=True)
            out2 = g.reconcile(r, REF, dry=False, have_key=True)
        self.assertEqual(fake.writes, [])
        self.assertIn("caller PR #12 waiting (auto-merge queued)", out1["done"])
        self.assertIn("caller missing", out1["pending"])
        self.assertEqual(out1["done"], out2["done"])

    def test_state_b_same_content_no_automerge_only_merges_with_head_sha(self):
        want = g.render_caller(REF)
        pr = self._pr(head_sha="sha_b")
        routes = {
            f"repos/o/r/pulls?head=o:{g.INSTALL_BRANCH}&state=open&per_page=10": [pr],
            "repos/o/r/pulls/12": pr,
            "repos/o/r/pulls/12/files?per_page=100": [{"filename": g.CALLER_PATH}],
            f"repos/o/r/contents/{g.CALLER_PATH}?ref={g.urllib.parse.quote(g.INSTALL_BRANCH, safe='')}": _b64_file(want, "b1"),
            "repos/o/r/branches/main/protection": g.gh.GhError("404"),
        }
        fake = Api(routes)
        with mock.patch.object(g.gh, "api", side_effect=fake.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake._run):
            d = g.deliver_caller("o/r", "main", want)
        self.assertFalse(d.merged)
        self.assertIn("queued for auto-merge", d.note)
        self.assertEqual([c for c in fake.calls if c[0] != "GET"], [])
        self.assertEqual(len(fake.runs), 1)
        self.assertEqual(
            fake.runs[0][0],
            ("pr", "merge", "12", "-R", "o/r", "--squash", "--auto", "--match-head-commit", "sha_b"),
        )

    def test_state_c_content_differs_commits_on_top_without_reset(self):
        want = g.render_caller(REF)
        pr = self._pr(head_sha="old_pr_head")
        routes = {
            f"repos/o/r/pulls?head=o:{g.INSTALL_BRANCH}&state=open&per_page=10": [pr],
            "repos/o/r/pulls/12": pr,
            "repos/o/r/pulls/12/files?per_page=100": [{"filename": g.CALLER_PATH}],
            f"repos/o/r/contents/{g.CALLER_PATH}?ref={g.urllib.parse.quote(g.INSTALL_BRANCH, safe='')}": _b64_file("old", "blob_old"),
            "repos/o/r/branches/main/protection": g.gh.GhError("404"),
            ("PUT", f"repos/o/r/contents/{g.CALLER_PATH}"): {"commit": {"sha": "put_c"}},
        }
        fake = Api(routes)
        with mock.patch.object(g.gh, "api", side_effect=fake.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake._run):
            d = g.deliver_caller("o/r", "main", want)
        self.assertFalse(d.merged)
        writes = [c for c in fake.calls if c[0] != "GET"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][0], "PUT")
        self.assertEqual(writes[0][2]["sha"], "blob_old")
        self.assertFalse(any("git/ref" in c[1] for c in fake.calls))
        self.assertIn("--match-head-commit", fake.runs[0][0])
        self.assertEqual(fake.runs[0][0][-1], "put_c")

    def test_state_d_no_pr_and_automerge_fallback_to_direct_merge(self):
        want = g.render_caller(REF)
        routes = {
            f"repos/o/r/pulls?head=o:{g.INSTALL_BRANCH}&state=open&per_page=10": [],
            "repos/o/r/git/ref/heads/main": {"object": {"sha": "base0"}},
            f"repos/o/r/contents/{g.CALLER_PATH}?ref={g.urllib.parse.quote(g.INSTALL_BRANCH, safe='')}": g.gh.GhError("404"),
            ("PUT", f"repos/o/r/contents/{g.CALLER_PATH}"): {"commit": {"sha": "put_d"}},
            ("POST", "repos/o/r/pulls"): {"number": 15},
        }
        runs = {("pr", "merge"): lambda args: (_ for _ in ()).throw(g.gh.GhError("no ruleset")) if "--auto" in args else ""}
        fake = Api(routes, runs)
        with mock.patch.object(g.gh, "api", side_effect=fake.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake._run):
            d = g.deliver_caller("o/r", "main", want)
        self.assertTrue(d.merged)
        self.assertEqual(d.note, "caller PR #15 merged")
        self.assertEqual(fake.runs[1][0], ("pr", "merge", "15", "-R", "o/r", "--squash", "--delete-branch", "--match-head-commit", "put_d"))

    def test_state_d_foreign_files_force_resets_and_ignores_fork_prs(self):
        want = g.render_caller(REF)
        fork_pr = self._pr(number=99, fork_repo="mallory/r")
        foreign_pr = self._pr(number=12, changed_files=2)
        list_calls = {"n": 0}

        def pulls_list(_):
            list_calls["n"] += 1
            return [fork_pr, foreign_pr] if list_calls["n"] == 1 else []

        routes = {
            f"repos/o/r/pulls?head=o:{g.INSTALL_BRANCH}&state=open&per_page=10": pulls_list,
            "repos/o/r/pulls/12": foreign_pr,
            f"repos/o/r/contents/{g.CALLER_PATH}?ref={g.urllib.parse.quote(g.INSTALL_BRANCH, safe='')}": _b64_file("old", "b_after"),
            "repos/o/r/branches/main/protection": g.gh.GhError("404"),
            "repos/o/r/git/ref/heads/main": {"object": {"sha": "base0"}},
            ("POST", "repos/o/r/git/refs"): g.gh.GhError("422 exists"),
            ("PUT", f"repos/o/r/contents/{g.CALLER_PATH}"): {"commit": {"sha": "put_d2"}},
            ("POST", "repos/o/r/pulls"): {"number": 16},
        }
        fake = Api(routes)
        with mock.patch.object(g.gh, "api", side_effect=fake.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake._run):
            d = g.deliver_caller("o/r", "main", want)
        self.assertEqual(d.note, "caller PR #16 queued for auto-merge")
        self.assertTrue(any(c[0] == "PATCH" and c[1] == f"repos/o/r/git/refs/heads/{g.INSTALL_BRANCH}" and c[2]["force"] is True for c in fake.calls))

    def test_state_d_single_foreign_file_or_rename_force_resets_instead_of_state_c(self):
        want = g.render_caller(REF)
        for pr_files in (
            [{"filename": "src/backdoor.py"}],
            [{"filename": g.CALLER_PATH, "previous_filename": "evil.yml"}],
        ):
            with self.subTest(pr_files=pr_files):
                pr = self._pr(number=12, changed_files=1, head_sha="foreign_sha")
                list_calls = {"n": 0}

                def pulls_list(_):
                    list_calls["n"] += 1
                    return [pr] if list_calls["n"] == 1 else []

                routes = {
                    f"repos/o/r/pulls?head=o:{g.INSTALL_BRANCH}&state=open&per_page=10": pulls_list,
                    "repos/o/r/pulls/12": pr,
                    "repos/o/r/pulls/12/files?per_page=100": pr_files,
                    f"repos/o/r/contents/{g.CALLER_PATH}?ref={g.urllib.parse.quote(g.INSTALL_BRANCH, safe='')}": _b64_file(want, "b_want"),
                    "repos/o/r/branches/main/protection": g.gh.GhError("404"),
                    "repos/o/r/git/ref/heads/main": {"object": {"sha": "base0"}},
                    ("POST", "repos/o/r/git/refs"): g.gh.GhError("422 exists"),
                    ("PUT", f"repos/o/r/contents/{g.CALLER_PATH}"): {"commit": {"sha": "put_reset"}},
                    ("POST", "repos/o/r/pulls"): {"number": 17},
                }
                fake = Api(routes)
                with mock.patch.object(g.gh, "api", side_effect=fake.api), \
                        mock.patch.object(g.gh, "_run", side_effect=fake._run):
                    d = g.deliver_caller("o/r", "main", want)
                self.assertEqual(d.note, "caller PR #17 queued for auto-merge")
                self.assertTrue(any(c[0] == "PATCH" and c[1] == f"repos/o/r/git/refs/heads/{g.INSTALL_BRANCH}" and c[2]["force"] is True for c in fake.calls))
                self.assertFalse(any("foreign_sha" in r[0] for r in fake.runs))


class StuckInstallTest(unittest.TestCase):
    """#29: stuck PR age, merge state, and dry-run surfacing."""

    def _run_stuck(self, age_days, dry):
        now = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
        created = f"2026-11-{14 - age_days:02d}T12:00:00Z"
        want = g.render_caller(REF)
        pr = {
            "number": 12, "changed_files": 1, "auto_merge": {"merge_method": "squash"},
            "created_at": created, "mergeable_state": "blocked",
            "base": {"ref": "main"}, "head": {"ref": g.INSTALL_BRANCH, "sha": "h1", "repo": {"full_name": "o/r"}},
        }
        r = _repo("r")
        routes, runs = _clean_routes([r])
        routes[f"repos/o/r/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        routes[f"repos/o/r/pulls?head=o:{g.INSTALL_BRANCH}&state=open&per_page=10"] = [pr]
        routes["repos/o/r/pulls/12"] = pr
        routes["repos/o/r/pulls/12/files?per_page=100"] = [{"filename": g.CALLER_PATH}]
        routes[f"repos/o/r/contents/{g.CALLER_PATH}?ref={g.urllib.parse.quote(g.INSTALL_BRANCH, safe='')}"] = _b64_file(want, "b1")
        routes["repos/o/r/branches/main/protection"] = g.gh.GhError("404")
        fake = Api(routes, runs)
        cfg = g.Config(now=now)
        with mock.patch.dict(g.os.environ, {}, clear=True), \
                mock.patch.object(g.gh, "api", side_effect=fake.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake._run):
            return g.reconcile(r, REF, dry=dry, have_key=True, cfg=cfg)

    def test_three_day_stuck_pr_reports_pending_in_apply_and_dry(self):
        for dry in (False, True):
            with self.subTest(dry=dry):
                out = self._run_stuck(3, dry)
                self.assertTrue(any("open 3d, merge state blocked" in p for p in out["pending"]), out["pending"])

    def test_one_day_pr_has_no_stuck_line(self):
        out = self._run_stuck(1, dry=True)
        self.assertFalse(any("open " in p for p in out["pending"]), out["pending"])


class ClassicProtectionTest(unittest.TestCase):
    """#29: classic branch protection blockers are detected cleanly."""

    def _check(self, response):
        fake = Api({"repos/o/r/branches/main/protection": response})
        with mock.patch.object(g.gh, "api", side_effect=fake.api):
            return g.classic_protection("o/r", "main")

    def test_404_returns_empty(self):
        self.assertEqual(self._check(g.gh.GhError("HTTP 404 Branch not protected")), [])

    def test_required_reviews_checks_and_restrictions(self):
        out = self._check({
            "required_pull_request_reviews": {"required_approving_review_count": 1},
            "required_status_checks": {"contexts": [g.VERDICT_CONTEXT, "ci/build", "lint"]},
            "restrictions": {"users": [], "teams": []},
        })
        self.assertEqual(len(out), 3)
        self.assertIn("requires 1 approving review(s)", out[0])
        self.assertIn("ci/build, lint", out[1])
        self.assertIn("restricts who can push", out[2])

    def test_verdict_context_alone_returns_empty(self):
        out = self._check({"required_status_checks": {"contexts": [g.VERDICT_CONTEXT]}, "restrictions": None})
        self.assertEqual(out, [])

    def test_403_returns_unreadable_note(self):
        self.assertEqual(self._check(g.gh.GhError("HTTP 403 Forbidden")),
                         ["classic branch protection on main could not be read"])


class SecretsTest(unittest.TestCase):
    """#32 and #31: multi-secret provisioning, optional secret reporting, rotation, Dependabot."""

    def test_both_secrets_set_via_stdin_never_in_argv_or_report(self):
        r = _repo("a")
        routes, runs = _clean_routes([r], secrets=())
        fake = Api(routes, runs)
        code, printed = _run_main(fake, [], env={"GEMINI_API_KEY": "secret-gem-123", "ANTHROPIC_API_KEY": "secret-ant-456"})
        self.assertEqual(code, 0)
        sets = [run for run in fake.runs if run[0][:2] == ("secret", "set")]
        self.assertEqual(len(sets), 2)
        for args, stdin in sets:
            self.assertNotIn("secret-gem-123", " ".join(args))
            self.assertNotIn("secret-ant-456", " ".join(args))
            self.assertIn(stdin, ("secret-gem-123", "secret-ant-456"))
        self.assertNotIn("secret-gem-123", printed)
        self.assertNotIn("secret-ant-456", printed)

    def test_optional_secret_absent_not_drift_and_listed_in_footer(self):
        r = _repo("a")
        routes, runs = _clean_routes([r], secrets=("GEMINI_API_KEY",))
        fake = Api(routes, runs)
        code, printed = _run_main(fake, [])
        self.assertEqual(code, 0)
        self.assertIn("Optional secret `ANTHROPIC_API_KEY` is not in the governor env and is missing on 1 repo: o/a", printed)

    def test_rotate_apply_and_dry(self):
        r = _repo("a")
        routes, runs = _clean_routes([r], secrets=("GEMINI_API_KEY", "ANTHROPIC_API_KEY"))
        fake_dry = Api(routes, runs)
        code_dry, printed_dry = _run_main(fake_dry, ["--rotate-secrets", "--dry-run"], env={"ANTHROPIC_API_KEY": "ant"})
        self.assertEqual(code_dry, 0)
        self.assertEqual(fake_dry.writes, [])
        self.assertIn("(dry run) would rotate secret GEMINI_API_KEY", printed_dry)

        fake_apply = Api(routes, runs)
        code_apply, printed_apply = _run_main(fake_apply, [], env={"PRG_ROTATE_SECRETS": "true", "ANTHROPIC_API_KEY": "ant"})
        self.assertEqual(code_apply, 0)
        sets = [run for run in fake_apply.runs if run[0][:2] == ("secret", "set")]
        self.assertEqual(len(sets), 2)
        self.assertIn("secret GEMINI_API_KEY rotated", printed_apply)

    def test_dependabot_secrets_flag_and_have_key_false(self):
        r = _repo("a")
        routes, runs = _clean_routes([r], secrets=())
        fake = Api(routes, runs)
        code, _ = _run_main(fake, ["--dependabot-secrets"])
        self.assertEqual(code, 0)
        lists = [run[0] for run in fake.runs if run[0][:2] == ("secret", "list")]
        sets = [run[0] for run in fake.runs if run[0][:2] == ("secret", "set")]
        self.assertTrue(any("--app" in a and "dependabot" in a for a in lists))
        self.assertTrue(any("--app" in a and "dependabot" in a for a in sets))

        fake2 = Api(routes, runs)
        with mock.patch.dict(g.os.environ, {}, clear=True), \
                mock.patch.object(g.gh, "api", side_effect=fake2.api), \
                mock.patch.object(g.gh, "_run", side_effect=fake2._run):
            out = g.reconcile(r, REF, dry=False, have_key=False)
        self.assertEqual(out["errors"], ["GEMINI_API_KEY not in governor env; secret step skipped"])
        self.assertEqual([run for run in fake2.runs if run[0][0] == "secret"], [])

    def test_secret_list_and_rotate_errors_are_recorded(self):
        r = _repo("a")
        routes, _ = _clean_routes([r], secrets=("GEMINI_API_KEY",))
        fake_list_err = Api(routes, {("secret", "list"): g.gh.GhError("403 dependabot")})
        code, printed = _run_main(fake_list_err, ["--dependabot-secrets"])
        self.assertEqual(code, 2)
        self.assertIn("secret list:", printed)

        fake_rot_err = Api(routes, {("secret", "list"): '[{"name": "GEMINI_API_KEY"}]',
                                    ("secret", "set"): g.gh.GhError("403 write denied")})
        code2, printed2 = _run_main(fake_rot_err, ["--rotate-secrets"])
        self.assertEqual(code2, 2)
        self.assertIn("secret GEMINI_API_KEY:", printed2)


class RefValidationTest(unittest.TestCase):
    """#40: PRG_REF must be a 40-hex SHA on pr-guardian's default branch."""

    def test_invalid_refs_exit_2_before_any_api_call_in_apply_mode(self):
        for bad in ("v1", "abcdef0", "a" * 39, "a" * 41, "A" * 40, "a" * 40 + "\nx"):
            with self.subTest(ref=bad):
                fake = Api()
                with mock.patch.dict(g.os.environ, {"PRG_REF": bad}, clear=True), \
                        mock.patch.object(g.gh, "api", side_effect=fake.api), \
                        mock.patch.object(g, "list_repos") as lr, \
                        mock.patch.object(g.sys, "argv", ["governor.py"]), \
                        mock.patch("sys.stderr"):
                    self.assertEqual(g.main(), 2)
                self.assertEqual(fake.calls, [])
                lr.assert_not_called()

    def test_trailing_newline_is_stripped_and_accepted(self):
        routes, runs = _clean_routes([])
        fake = Api(routes, runs)
        code, _ = _run_main(fake, [], env={"PRG_REF": REF + "\n"})
        self.assertEqual(code, 0)

    def test_dry_run_with_v1_warns_and_continues(self):
        routes, runs = _clean_routes([])
        fake = Api(routes, runs)
        code, printed = _run_main(fake, ["--dry-run"], env={"PRG_REF": "v1"})
        self.assertEqual(code, 0)
        self.assertIn("not a 40-hex commit SHA", printed)

    def test_missing_commit_exits_2_even_with_allow_unmerged_ref(self):
        routes, runs = _clean_routes([])
        routes[f"repos/o/{g.HOME_REPO}/commits/{REF}"] = g.gh.GhError("404 Not Found")
        fake = Api(routes, runs)
        code, _ = _run_main(fake, ["--allow-unmerged-ref"])
        self.assertEqual(code, 2)

    def test_compare_statuses(self):
        routes, runs = _clean_routes([])
        routes[f"repos/o/{g.HOME_REPO}/compare/{REF}...main"] = {"status": "diverged"}
        self.assertEqual(_run_main(Api(routes, runs), [])[0], 2)
        self.assertEqual(_run_main(Api(routes, runs), ["--allow-unmerged-ref"])[0], 0)

        for status in ("ahead", "identical"):
            routes[f"repos/o/{g.HOME_REPO}/compare/{REF}...main"] = {"status": status}
            self.assertEqual(_run_main(Api(routes, runs), [])[0], 0)

    def test_verify_ref_rejects_bad_sha_and_missing_default_branch(self):
        fake = Api({f"repos/o/{g.HOME_REPO}/commits/{REF}": {"sha": "other"}})
        with mock.patch.object(g.gh, "api", side_effect=fake.api):
            self.assertIn("not a commit", g.verify_ref("o", REF))
        fake2 = Api({f"repos/o/{g.HOME_REPO}/commits/{REF}": {"sha": REF}, f"repos/o/{g.HOME_REPO}": {}})
        with mock.patch.object(g.gh, "api", side_effect=fake2.api):
            self.assertIn("could not be verified", g.verify_ref("o", REF))


class ExemptTest(unittest.TestCase):
    """#40: exempt repos via topic or --exempt, plus topics fallback GET."""

    def test_topic_exempt_repo_makes_zero_per_repo_calls_and_is_listed(self):
        ex = _repo("skipme", topics=[g.EXEMPT_TOPIC])
        ok = _repo("keepme")
        routes, runs = _clean_routes([ex, ok])
        del routes["repos/o/skipme"]
        fake = Api(routes, runs)
        code, printed = _run_main(fake, [])
        self.assertEqual(code, 0)
        self.assertFalse(any("o/skipme" in c[1] for c in fake.calls))
        self.assertIn("Exempt (pr-guardian-exempt) (1)", printed)
        self.assertIn("o/skipme", printed)

    def test_exempt_cli_and_unknown_name_and_topics_fallback(self):
        r1 = _repo("a")
        del r1["topics"]
        routes, runs = _clean_routes([r1])
        routes["repos/o/a/topics"] = {"names": []}
        fake = Api(routes, runs)
        code, printed = _run_main(fake, ["--exempt", "a"])
        self.assertEqual(code, 0)
        self.assertIn("o/a", printed)
        self.assertIn(("GET", "repos/o/a/topics", None), fake.calls)

        fake_bad = Api(routes, runs)
        code_bad, _ = _run_main(fake_bad, ["--exempt", "nonexistent"])
        self.assertEqual(code_bad, 2)

        routes["repos/o/a/topics"] = g.gh.GhError("500 topics error")
        self.assertEqual(_run_main(Api(routes, runs), [])[0], 2)


class CanaryTest(unittest.TestCase):
    """#40: canary ring proof, hold gate, promotion, and overlap rejection."""

    def _canary_proven_routes(self, canary, other, creator="github-actions[bot]", state="success", delivered_want=True):
        want = g.render_caller(REF)
        routes, runs = _clean_routes([canary, other])
        routes[f"repos/o/{other['name']}/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        pr = {"number": 5, "merged_at": "2026-11-10T00:00:00Z", "head": {"sha": "c_sha"}}
        routes[f"repos/o/{canary['name']}/pulls?state=closed&head=o:{g.INSTALL_BRANCH}&sort=updated&direction=desc&per_page=10"] = [pr]
        routes[f"repos/o/{canary['name']}/contents/{g.CALLER_PATH}?ref=c_sha"] = _b64_file(want if delivered_want else "old")
        routes[f"repos/o/{canary['name']}/commits/c_sha/statuses?per_page=100"] = [
            {"context": g.VERDICT_CONTEXT, "state": state, "creator": {"login": creator}},
        ]
        return routes, runs

    def test_unproven_ring_holds_non_canary_but_delivers_canary(self):
        can, app = _repo("can", topics=[g.CANARY_TOPIC]), _repo("app")
        routes, runs = _clean_routes([can, app])
        routes[f"repos/o/can/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        routes[f"repos/o/app/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        routes["repos/o/can/git/ref/heads/main"] = {"object": {"sha": "h0"}}
        routes[("PUT", f"repos/o/can/contents/{g.CALLER_PATH}")] = {"commit": {"sha": "put_can"}}
        routes[("POST", "repos/o/can/pulls")] = {"number": 4}
        fake = Api(routes, runs)
        code, printed = _run_main(fake, [])
        self.assertEqual(code, 1)
        self.assertIn("held for the canary ring", printed)
        self.assertFalse(any("o/app/pulls" in c[1] for c in fake.calls))
        self.assertTrue(any("o/can/pulls" in c[1] for c in fake.calls))

    def test_proven_ring_promote_and_already_promoted_open_gate(self):
        can, app = _repo("can", topics=[g.CANARY_TOPIC]), _repo("app")
        routes, runs = self._canary_proven_routes(can, app)
        routes[f"repos/o/app/git/ref/heads/main"] = {"object": {"sha": "h0"}}
        routes[("PUT", f"repos/o/app/contents/{g.CALLER_PATH}")] = {"commit": {"sha": "put_app"}}
        routes[("POST", "repos/o/app/pulls")] = {"number": 8}
        fake = Api(routes, runs)
        code, printed = _run_main(fake, [])
        self.assertEqual(code, 1)
        self.assertIn("canary ring proven (1/1)", printed)
        self.assertTrue(any(c[0] == "POST" and c[1] == "repos/o/app/pulls" for c in fake.calls))

        # Unproven canary + --promote opens gate
        routes2, runs2 = _clean_routes([can, app])
        routes2[f"repos/o/can/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        routes2[f"repos/o/app/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        for name in ("can", "app"):
            routes2[f"repos/o/{name}/git/ref/heads/main"] = {"object": {"sha": "h0"}}
            routes2[("PUT", f"repos/o/{name}/contents/{g.CALLER_PATH}")] = {"commit": {"sha": "put"}}
            routes2[("POST", f"repos/o/{name}/pulls")] = {"number": 9}
        fake2 = Api(routes2, runs2)
        code2, printed2 = _run_main(fake2, ["--promote"])
        self.assertEqual(code2, 1)
        self.assertIn("promoted explicitly", printed2)
        self.assertTrue(any(c[0] == "POST" and c[1] == "repos/o/app/pulls" for c in fake2.calls))

        # Non-canary already on want opens gate
        app2 = _repo("app2")
        routes3, runs3 = _clean_routes([can, app, app2])
        routes3[f"repos/o/can/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        routes3[f"repos/o/app/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")
        routes3["repos/o/can/git/ref/heads/main"] = {"object": {"sha": "h0"}}
        routes3[("PUT", f"repos/o/can/contents/{g.CALLER_PATH}")] = {"commit": {"sha": "put"}}
        routes3[("POST", "repos/o/can/pulls")] = {"number": 9}
        routes3["repos/o/app/git/ref/heads/main"] = {"object": {"sha": "h0"}}
        routes3[("PUT", f"repos/o/app/contents/{g.CALLER_PATH}")] = {"commit": {"sha": "put"}}
        routes3[("POST", "repos/o/app/pulls")] = {"number": 10}
        fake3 = Api(routes3, runs3)
        code3, printed3 = _run_main(fake3, [])
        self.assertEqual(code3, 1)
        self.assertIn("ref already promoted (seen on app2)", printed3)

    def test_proof_rejections_exception_and_overlap(self):
        can, app = _repo("can", topics=[g.CANARY_TOPIC]), _repo("app")
        want = g.render_caller(REF)
        # Verdict failure, wrong creator, missing verdict, empty canary, another ref delivered, no merged PR
        for mutate, expected in [
            (lambda r: r.update({f"repos/o/can/commits/c_sha/statuses?per_page=100": [
                {"context": g.VERDICT_CONTEXT, "state": "failure", "creator": {"login": "github-actions[bot]"}}]}), "failure"),
            (lambda r: r.update({f"repos/o/can/commits/c_sha/statuses?per_page=100": [
                {"context": g.VERDICT_CONTEXT, "state": "success", "creator": {"login": "mallory"}}]}), "success"),
            (lambda r: r.update({f"repos/o/can/commits/c_sha/statuses?per_page=100": []}), f"no {g.VERDICT_CONTEXT}"),
            (lambda r: r.update({"repos/o/can/branches/main": g.gh.GhError("409 empty")}), "empty repo"),
            (lambda r: r.update({f"repos/o/can/contents/{g.CALLER_PATH}?ref=c_sha": _b64_file("old")}), "delivered another ref"),
            (lambda r: r.update({f"repos/o/can/pulls?state=closed&head=o:{g.INSTALL_BRANCH}&sort=updated&direction=desc&per_page=10": []}), "no merged install PR"),
            (lambda r: r.update({f"repos/o/can/contents/{g.CALLER_PATH}?ref=main": _b64_file("old")}), "not on the new ref yet"),
            (lambda r: r.update({f"repos/o/can/pulls?state=closed&head=o:{g.INSTALL_BRANCH}&sort=updated&direction=desc&per_page=10": g.gh.GhError("500")}), "500"),
        ]:
            with self.subTest(expected=expected):
                routes, _ = self._canary_proven_routes(can, app)
                mutate(routes)
                fake = Api(routes)
                with mock.patch.object(g.gh, "api", side_effect=fake.api):
                    held, reason = g.canary_gate([can, app], {"can"}, REF, want, False, {})
                self.assertTrue(held)
                self.assertIn(expected, reason)

        # Overlap between canary and exempt exits 2
        both = _repo("both", topics=[g.CANARY_TOPIC, g.EXEMPT_TOPIC])
        routes_ov, runs_ov = _clean_routes([both])
        self.assertEqual(_run_main(Api(routes_ov, runs_ov), [])[0], 2)


class StatsTest(unittest.TestCase):
    """#38: --stats aggregates open PR state safely and never affects exit code."""

    def test_fleet_stats_aggregation_and_error_isolation(self):
        bot = {"type": "Bot", "login": "github-actions[bot]"}
        human = {"type": "User", "login": "mallory"}
        s1 = {
            "round": 2,
            "cost_usd": [0.5, 0.25],
            "findings": [
                {"id": "R-001", "severity": "P1", "status": "new"},
                {"id": "R-002", "severity": "P2", "status": "fixed"},
                {"id": "R-003", "severity": "nit", "status": "new"},
            ],
        }
        s2 = {
            "round": 3,
            "cost_usd": [1.0],
            "findings": [{"id": "R-004", "severity": "P2", "status": "accepted_pushback"}],
        }
        spoof = {"round": 99, "cost_usd": [999.0], "findings": [{"id": "R-999", "severity": "P0", "status": "new"}]}

        def comment(user, encoded):
            return {"user": user, "body": f"{g.st.SUMMARY_MARKER}\n{encoded}"}

        r_a, r_b, r_c, r_d = _repo("a"), _repo("b"), _repo("c"), _repo("d")
        routes, runs = _clean_routes([r_a, r_b, r_c, r_d])
        routes["repos/o/a/pulls?state=open&per_page=100"] = [
            {"number": 1, "labels": [{"name": "needs-human"}]},
            {"number": 2, "labels": []},
            {"number": 3, "labels": []},
            {"number": 4, "labels": []},
        ]
        routes["repos/o/a/issues/1/comments?per_page=100"] = [comment(bot, g.st.encode(s1))]
        routes["repos/o/a/issues/2/comments?per_page=100"] = [comment(bot, g.st.encode(s2))]
        routes["repos/o/a/issues/3/comments?per_page=100"] = [comment(human, g.st.encode(spoof))]
        routes["repos/o/a/issues/4/comments?per_page=100"] = [{"user": bot, "body": "plain"}]
        routes["repos/o/b/pulls?state=open&per_page=100"] = []
        routes["repos/o/c/pulls?state=open&per_page=100"] = g.gh.GhError("500")
        routes[f"repos/o/d/contents/{g.CALLER_PATH}?ref=main"] = g.gh.GhError("404 Not Found")  # no caller -> not in stats

        fake = Api(routes, runs)
        code, printed = _run_main(fake, ["--dry-run", "--stats"])
        self.assertEqual(code, 1)  # only dry-run drift on o/d, not stats error on o/c
        self.assertIn("## Fleet stats", printed)
        self.assertIn("| o/a | 4 | 2 | 5 (3) | 1.75 | 1 | 1 |", printed)
        self.assertIn("stats unavailable:", printed)
        self.assertIn("1 repo with no open PRs.", printed)


class ReportTest(unittest.TestCase):
    """Report formatting, cell neutralisation, footers, and truncation."""

    def test_report_formatting_sanitisation_and_truncation(self):
        results = [
            {"repo": "o/a|b\n@mallory<!--x-->", "drift": ["d1"], "done": [],
             "pending": ["p1"], "errors": [], "waiting": [], "info": ["info1"],
             "optional": ["ANTHROPIC_API_KEY"], "pinned": REF},
            {"repo": "o/w", "drift": [], "done": [], "pending": [], "errors": [],
             "waiting": ["empty"], "info": [], "optional": [], "pinned": ""},
        ]
        for i in range(11):
            results.append({"repo": f"o/opt{i}", "drift": [], "done": [], "pending": [], "errors": [],
                            "waiting": [], "info": [], "optional": ["ANTHROPIC_API_KEY"], "pinned": "v1"})
        text = g.report(results, True, ref=REF, ref_problem="bad\n@evil", gate="ring", exempt=["o/ex"],
                        stats="## Fleet stats\n\nok")
        self.assertIn(f"`{REF[:7]}`", text)
        self.assertIn("> ⚠️ bad @\u200bevil", text)
        self.assertIn("o/a\\|b @\u200bmallory", text)
        self.assertNotIn("<!--x-->", text)
        self.assertIn("(dry run) info1", text)
        self.assertIn("Waiting for a first commit (1)", text)
        self.assertIn("Exempt (pr-guardian-exempt) (1)", text)
        self.assertIn("missing on 12 repos:", text)
        self.assertIn("(+2 more)", text)
        self.assertIn("## Fleet stats", text)

        huge = [{"repo": f"o/r{i}", "drift": ["x" * 300], "done": [], "pending": ["y" * 300],
                 "errors": [], "waiting": [], "info": [], "optional": [], "pinned": REF}
                for i in range(200)]
        capped = g.report(huge, False, ref=REF)
        self.assertLessEqual(len(capped), g.REPORT_CAP)
        self.assertTrue(capped.endswith("_Report truncated._"))

    def test_step_summary_written_when_env_set(self):
        import tempfile
        from pathlib import Path
        routes, runs = _clean_routes([])
        fake = Api(routes, runs)
        with tempfile.TemporaryDirectory() as tmp:
            summary_path = Path(tmp) / "summary.md"
            code, _ = _run_main(fake, [], env={"GITHUB_STEP_SUMMARY": str(summary_path)})
            self.assertEqual(code, 0)
            self.assertIn("**Run**:", summary_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
