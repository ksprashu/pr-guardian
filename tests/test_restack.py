"""Tests for post-merge stacked PR restacking, security guards, and workflow gates."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tests.helpers  # noqa: F401  (puts scripts/ on sys.path)
import governor as gov
import restack as rs
import state as st
from tests import test_workflows as tw

SHA1 = "1" * 40
SHA2 = "2" * 40
SHA3 = "3" * 40
REPO = "o/r"


def _pr_payload(
    number: int,
    *,
    head_ref: str = "feat/two",
    head_sha: str = SHA2,
    base_ref: str = "main",
    head_repo: str | None = REPO,
    base_repo: str = REPO,
    fork: bool = False,
    cross: bool = False,
    merged: bool | None = None,
    merged_at: str | None = None,
    merge_commit_sha: str = "",
) -> dict:
    h_repo = None if head_repo is None else {"full_name": head_repo, "fork": fork}
    b_repo = {"full_name": base_repo, "default_branch": "main"}
    out = {
        "number": number,
        "isCrossRepository": cross,
        "head": {"ref": head_ref, "sha": head_sha, "repo": h_repo},
        "base": {"ref": base_ref, "repo": b_repo},
    }
    if merged is not None:
        out["merged"] = merged
    if merged_at is not None:
        out["merged_at"] = merged_at
    if merge_commit_sha:
        out["merge_commit_sha"] = merge_commit_sha
    return out


class RefAndRepoValidationTest(unittest.TestCase):
    def test_valid_branch_refs_accepted(self):
        for ref in ("main", "master", "feat/stack-restack", "pr-guardian/install-restack",
                    "release/v1.2.3", "fix_123", "a/b/c-1.2"):
            with self.subTest(ref=ref):
                self.assertTrue(rs.is_safe_branch_ref(ref))

    def test_dash_prefixed_branch_refs_rejected(self):
        for ref in ("-", "-f", "--force", "--upload-pack=touch /tmp/pwn",
                    "-oProxyCommand=evil", "-main", "--delete"):
            with self.subTest(ref=ref):
                self.assertFalse(rs.is_safe_branch_ref(ref))

    def test_malformed_and_dangerous_branch_refs_rejected(self):
        bad = (
            "", None, 123, True, "HEAD", "@", "..", "a..b", "../main", "feat/../main",
            "/feat", "feat/", ".feat", "feat.", "feat/.hidden", "feat/x.lock", "feat.lock",
            "feat//x", "feat@{0}", "feat branch", "feat\nmain", "feat\tmain",
            "feat`id`", "feat$(id)", "feat;id", "feat<!--", "a" * 256, "feat/🚀",
        )
        for ref in bad:
            with self.subTest(ref=ref):
                self.assertFalse(rs.is_safe_branch_ref(ref))

    def test_repo_slug_validation(self):
        for good in ("ksprashu/pr-guardian", "o/r", "org-1/my.repo_2"):
            self.assertTrue(rs.is_valid_repo(good), good)
        for bad in ("", None, 42, "o", "o/r/x", "-o/r", "o/-r", "../r", "o/..", "./r", "o/.", "o/r\n"):
            self.assertFalse(rs.is_valid_repo(bad), repr(bad))

    def test_fork_pr_detection_fails_closed(self):
        self.assertFalse(rs.is_fork_pr(_pr_payload(2), REPO))
        self.assertTrue(rs.is_fork_pr(_pr_payload(2, cross=True), REPO))
        self.assertTrue(rs.is_fork_pr(_pr_payload(2, fork=True), REPO))
        self.assertTrue(rs.is_fork_pr(_pr_payload(2, head_repo="mallory/r"), REPO))
        self.assertTrue(rs.is_fork_pr(_pr_payload(2, head_repo=None), REPO))
        self.assertTrue(rs.is_fork_pr(_pr_payload(2, base_repo="other/r"), REPO))
        self.assertTrue(rs.is_fork_pr({"number": 2}, REPO))


class _GitHarness:
    """Isolated local bare `origin` + author clone + runner workdir for real git tests."""

    def __init__(self, tmp: str):
        self.root = Path(tmp)
        self.origin = self.root / "origin.git"
        self.author = self.root / "author"
        self.workdir = self.root / "workdir"
        self._git(self.root, "init", "--bare", "--initial-branch=main", str(self.origin))
        self._git(self.root, "clone", str(self.origin), str(self.author))
        self.write(self.author, "README.md", "# test repo\n")
        self.commit_all(self.author, "initial commit")
        self._git(self.author, "push", "-u", "origin", "main")
        self._git(self.root, "clone", str(self.origin), str(self.workdir))

    def _git(self, cwd: Path, *args: str) -> str:
        env = {
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.root),
            "TMPDIR": str(self.root),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        cmd = [
            "git", "-C", str(cwd),
            "-c", "commit.gpgsign=false",
            "-c", "user.name=Test",
            "-c", "user.email=test@example.com",
            *args,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, shell=False, check=True, env=env)
        return proc.stdout.strip()

    def write(self, repo_dir: Path, rel: str, content: str) -> None:
        target = repo_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def commit_all(self, repo_dir: Path, msg: str) -> str:
        self._git(repo_dir, "add", "-A")
        self._git(repo_dir, "commit", "-m", msg)
        return self._git(repo_dir, "rev-parse", "HEAD")

    def branch(self, name: str, start: str = "main") -> None:
        self._git(self.author, "checkout", "-b", name, start)

    def push(self, branch: str) -> str:
        self._git(self.author, "push", "-u", "origin", branch)
        return self._git(self.author, "rev-parse", "HEAD")

    def squash_merge_to_main(self, branch: str, *, delete_remote_branch: bool = True) -> str:
        self._git(self.author, "checkout", "main")
        self._git(self.author, "pull", "--ff-only", "origin", "main")
        self._git(self.author, "merge", "--squash", branch)
        squash_sha = self._git(self.author, "commit", "-m", f"squash {branch}") and self._git(self.author, "rev-parse", "HEAD")
        self._git(self.author, "push", "origin", "main")
        if delete_remote_branch:
            self._git(self.author, "push", "origin", "--delete", branch)
        return squash_sha

    def origin_sha(self, branch: str) -> str:
        return self._git(self.origin, "rev-parse", f"refs/heads/{branch}")

    def show_origin_file(self, branch: str, path: str) -> str:
        return self._git(self.origin, "show", f"refs/heads/{branch}:{path}")


class FakeGitHub:
    """In-memory GitHub REST API stub tracking pulls, comments, and workflow dispatches."""

    def __init__(self, open_prs: list[dict], comments: dict[int, list[dict]] | None = None,
                 dispatch_error: Exception | None = None):
        self.open_prs = [copy.deepcopy(p) for p in open_prs]
        self.comments: dict[int, list[dict]] = {k: copy.deepcopy(v) for k, v in (comments or {}).items()}
        self.dispatch_error = dispatch_error
        self.calls: list[tuple[str, str, object, str | None]] = []
        self._next_comment_id = 500

    def api(self, path: str, method: str = "GET", body: dict | None = None,
            paginate: bool = False, token: str | None = None):
        self.calls.append((path, method, copy.deepcopy(body), token))
        if method == "GET" and path.startswith(f"repos/{REPO}/pulls?state=open"):
            return copy.deepcopy(self.open_prs)
        if method == "PATCH" and path.startswith(f"repos/{REPO}/pulls/"):
            num = int(path.rsplit("/", 1)[1])
            for pr in self.open_prs:
                if pr["number"] == num and body and "base" in body:
                    pr["base"]["ref"] = body["base"]
                    return copy.deepcopy(pr)
        if method == "GET" and path.startswith(f"repos/{REPO}/issues/") and "/comments" in path:
            num = int(path.split("/issues/", 1)[1].split("/", 1)[0])
            return copy.deepcopy(self.comments.get(num, []))
        if method == "POST" and path.startswith(f"repos/{REPO}/issues/") and path.endswith("/comments"):
            num = int(path.split("/issues/", 1)[1].split("/", 1)[0])
            cid = self._next_comment_id
            self._next_comment_id += 1
            entry = {
                "id": cid,
                "user": {"type": "Bot", "login": st.TRUSTED_BOT_LOGIN},
                "body": (body or {}).get("body", ""),
            }
            self.comments.setdefault(num, []).append(entry)
            return copy.deepcopy(entry)
        if method == "PATCH" and path.startswith(f"repos/{REPO}/issues/comments/"):
            cid = int(path.rsplit("/", 1)[1])
            for items in self.comments.values():
                for item in items:
                    if item["id"] == cid:
                        item["body"] = (body or {}).get("body", "")
                        return copy.deepcopy(item)
        if method == "POST" and path.endswith(f"/actions/workflows/{rs.PR_GUARDIAN_WORKFLOW}/dispatches"):
            if self.dispatch_error is not None:
                raise self.dispatch_error
            return None
        if method == "GET" and path == f"repos/{REPO}":
            return {"full_name": REPO, "default_branch": "main"}
        raise AssertionError(f"unexpected gh.api call: {method} {path}")


class RealGitStackRestackTest(unittest.TestCase):
    def test_squash_merge_exact_tree_uses_ours_and_avoids_spurious_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            h.branch("feat/one", "main")
            h.write(h.author, "calc.py", "def add(a, b):\n    return a + b\n")
            h1 = h.commit_all(h.author, "feat: add calc")
            h.push("feat/one")

            # PR #2 stacks on feat/one and edits the exact line PR #1 added.
            h.branch("feat/two", "feat/one")
            h.write(h.author, "calc.py", "def add(a, b):\n    return int(a) + int(b)\n")
            h.write(h.author, "extra.py", "EXTRA = True\n")
            h2 = h.commit_all(h.author, "feat: coerce ints in calc")
            h.push("feat/two")

            squash_sha = h.squash_merge_to_main("feat/one", delete_remote_branch=True)

            # Confirm naive 3-way git merge of origin/main into feat/two WOULD conflict.
            h._git(h.author, "checkout", "feat/two")
            naive = subprocess.run(
                ["git", "-C", str(h.author), "merge", "--no-commit", "--no-ff", "origin/main"],
                capture_output=True, text=True, shell=False,
            )
            self.assertNotEqual(naive.returncode, 0, "expected naive 3-way merge to conflict on calc.py")
            h._git(h.author, "merge", "--abort")

            fake = FakeGitHub([_pr_payload(2, head_ref="feat/two", head_sha=h2, base_ref="feat/one")])
            merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=h1, base_ref="main",
                                 merge_commit_sha=squash_sha)
            with mock.patch.object(rs.gh, "api", side_effect=fake.api):
                out = rs.restack_open_prs(
                    repo=REPO,
                    workdir=h.workdir,
                    merged=merged,
                    default_branch="main",
                    push_token="scoped-pat",
                    comment_token="gh-tok",
                    scoped_token=True,
                )

            self.assertEqual(out["errors"], [])
            res = out["results"][0]
            self.assertEqual(res["status"], "restacked")
            self.assertEqual(res["strategy"], "ours-tree-match")
            self.assertTrue(res["retargeted"])
            new_tip = h.origin_sha("feat/two")
            self.assertEqual(res["new_sha"], new_tip)
            self.assertNotEqual(new_tip, h2)
            # origin/main is now an ancestor of origin/feat/two, and PR #2's files are intact.
            git = rs.GitRepo(h.origin)
            self.assertTrue(git.is_ancestor(squash_sha, new_tip))
            self.assertIn("int(a) + int(b)", h.show_origin_file("feat/two", "calc.py"))
            self.assertEqual(h.show_origin_file("feat/two", "extra.py"), "EXTRA = True")
            # Effective diff vs main covers only calc.py and extra.py as modified by PR #2.
            changed = h._git(h.origin, "diff", "--name-only", f"{squash_sha}...{new_tip}").splitlines()
            self.assertEqual(sorted(changed), ["calc.py", "extra.py"])
            self.assertEqual(fake.open_prs[0]["base"]["ref"], "main")
            # Scoped token with no prior conflict comment posts no noisy comment.
            self.assertEqual(fake.comments, {})

    def test_diverged_main_tree_never_uses_ours_and_preserves_main_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            h.branch("feat/one", "main")
            h.write(h.author, "a.py", "A = 1\n")
            h1 = h.commit_all(h.author, "feat: add a")
            h.push("feat/one")

            h.branch("feat/two", "feat/one")
            h.write(h.author, "b.py", "B = 2\n")
            h2 = h.commit_all(h.author, "feat: add b")
            h.push("feat/two")

            # Land an independent commit on main BEFORE squash-merging feat/one so H1^{tree} != main^{tree}.
            h._git(h.author, "checkout", "main")
            h.write(h.author, "hotfix.py", "HOTFIX = True\n")
            h.commit_all(h.author, "fix: urgent hotfix")
            h.push("main")

            squash_sha = h.squash_merge_to_main("feat/one", delete_remote_branch=True)

            fake = FakeGitHub([_pr_payload(2, head_ref="feat/two", head_sha=h2, base_ref="main")])
            merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=h1, base_ref="main",
                                 merge_commit_sha=squash_sha)
            with mock.patch.object(rs.gh, "api", side_effect=fake.api):
                out = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="scoped-pat", comment_token="gh-tok", scoped_token=True,
                )

            res = out["results"][0]
            self.assertEqual(res["status"], "restacked")
            self.assertEqual(res["strategy"], "merge", "-s ours must not run when H1^{tree} != main^{tree}")
            self.assertEqual(h.show_origin_file("feat/two", "hotfix.py"), "HOTFIX = True")
            self.assertEqual(h.show_origin_file("feat/two", "a.py"), "A = 1")
            self.assertEqual(h.show_origin_file("feat/two", "b.py"), "B = 2")

    def test_main_advanced_after_tree_exact_squash_uses_two_step_sync(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            h.branch("feat/one", "main")
            h.write(h.author, "calc.py", "VALUE = 1\n")
            h1 = h.commit_all(h.author, "feat: calc v1")
            h.push("feat/one")

            h.branch("feat/two", "feat/one")
            h.write(h.author, "calc.py", "VALUE = 2\n")
            h2 = h.commit_all(h.author, "feat: calc v2")
            h.push("feat/two")

            squash_sha = h.squash_merge_to_main("feat/one", delete_remote_branch=True)
            # Another commit lands on main right after the squash merge.
            h._git(h.author, "checkout", "main")
            h.write(h.author, "notes.txt", "concurrent commit\n")
            h.commit_all(h.author, "docs: add notes")
            main_tip = h.push("main")

            fake = FakeGitHub([_pr_payload(2, head_ref="feat/two", head_sha=h2, base_ref="main")])
            merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=h1, base_ref="main",
                                 merge_commit_sha=squash_sha)
            with mock.patch.object(rs.gh, "api", side_effect=fake.api):
                out = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="scoped-pat", comment_token="gh-tok", scoped_token=True,
                )

            res = out["results"][0]
            self.assertEqual(res["status"], "restacked")
            self.assertEqual(res["strategy"], "ours-squash-then-merge")
            new_tip = h.origin_sha("feat/two")
            self.assertTrue(rs.GitRepo(h.origin).is_ancestor(main_tip, new_tip))
            self.assertEqual(h.show_origin_file("feat/two", "calc.py"), "VALUE = 2")
            self.assertEqual(h.show_origin_file("feat/two", "notes.txt"), "concurrent commit")

    def test_three_pr_stack_cascades_cleanly_across_sequential_merges(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            h.branch("feat/p1", "main")
            h.write(h.author, "pipe.py", "STEP = 1\n")
            h1 = h.commit_all(h.author, "p1")
            h.push("feat/p1")

            h.branch("feat/p2", "feat/p1")
            h.write(h.author, "pipe.py", "STEP = 2\n")
            h2 = h.commit_all(h.author, "p2")
            h.push("feat/p2")

            h.branch("feat/p3", "feat/p2")
            h.write(h.author, "pipe.py", "STEP = 3\n")
            h3 = h.commit_all(h.author, "p3")
            h.push("feat/p3")

            # Merge 1: feat/p1 squash-merges into main.
            s1 = h.squash_merge_to_main("feat/p1", delete_remote_branch=True)
            fake1 = FakeGitHub([
                _pr_payload(2, head_ref="feat/p2", head_sha=h2, base_ref="feat/p1"),
                _pr_payload(3, head_ref="feat/p3", head_sha=h3, base_ref="feat/p2"),
            ])
            with mock.patch.object(rs.gh, "api", side_effect=fake1.api):
                out1 = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir,
                    merged=rs.MergedPR(number=1, head_ref="feat/p1", head_sha=h1, base_ref="main",
                                       merge_commit_sha=s1),
                    default_branch="main", push_token="scoped-pat", comment_token="gh-tok", scoped_token=True,
                )
            by_pr1 = {r["pr"]: r for r in out1["results"]}
            self.assertEqual(by_pr1[2]["status"], "restacked")
            self.assertEqual(by_pr1[2]["strategy"], "ours-tree-match")
            # PR #3 still targets feat/p2 (an open PR), so it must not be collapsed onto main early.
            self.assertEqual(by_pr1[3]["status"], "skipped_other_base")
            h2_restacked = by_pr1[2]["new_sha"]

            # Refresh author's feat/p2 ref to match restacked origin/feat/p2, then squash-merge PR #2.
            h._git(h.author, "fetch", "origin", "feat/p2")
            h._git(h.author, "checkout", "feat/p2")
            h._git(h.author, "reset", "--hard", "origin/feat/p2")
            # Keep h2_restacked reachable in h.workdir (as GitHub keeps refs/pull/2/head) even after delete.
            s2 = h.squash_merge_to_main("feat/p2", delete_remote_branch=True)

            fake2 = FakeGitHub([_pr_payload(3, head_ref="feat/p3", head_sha=h3, base_ref="feat/p2")])
            with mock.patch.object(rs.gh, "api", side_effect=fake2.api):
                out2 = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir,
                    merged=rs.MergedPR(number=2, head_ref="feat/p2", head_sha=h2_restacked, base_ref="main",
                                       merge_commit_sha=s2),
                    default_branch="main", push_token="scoped-pat", comment_token="gh-tok", scoped_token=True,
                )
            res3 = out2["results"][0]
            self.assertEqual(res3["status"], "restacked")
            self.assertEqual(res3["strategy"], "ours-tree-match")
            self.assertEqual(h.show_origin_file("feat/p3", "pipe.py"), "STEP = 3")
            self.assertTrue(rs.GitRepo(h.origin).is_ancestor(s2, res3["new_sha"]))

    def test_semantic_conflict_aborts_cleanly_and_posts_idempotent_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            h.branch("feat/one", "main")
            h.write(h.author, "shared.py", "MODE = 'one'\n")
            h1 = h.commit_all(h.author, "feat: mode one")
            h.push("feat/one")

            h.branch("feat/two", "feat/one")
            h.write(h.author, "other.py", "OTHER = 1\n")
            h2 = h.commit_all(h.author, "feat: other")
            h.push("feat/two")

            # Diverge main on the same file `other.py` so merging main into feat/two conflicts semantically.
            h._git(h.author, "checkout", "main")
            h.write(h.author, "other.py", "OTHER = 999\n")
            h.commit_all(h.author, "main conflicting edit")
            h.push("main")
            s1 = h.squash_merge_to_main("feat/one", delete_remote_branch=True)

            # Plant an untrusted user comment carrying the marker; must be ignored (never PATCHed).
            spoof = {"id": 77, "user": {"type": "User", "login": "mallory"}, "body": f"{rs.RESTACK_MARKER}\nspoof"}
            fake = FakeGitHub(
                [_pr_payload(2, head_ref="feat/two", head_sha=h2, base_ref="feat/one")],
                comments={2: [spoof]},
            )
            merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=h1, base_ref="main", merge_commit_sha=s1)
            with mock.patch.object(rs.gh, "api", side_effect=fake.api):
                out1 = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="scoped-pat", comment_token="gh-tok", scoped_token=True,
                )
                # Second run with identical state does not create a duplicate comment.
                out2 = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="scoped-pat", comment_token="gh-tok", scoped_token=True,
                )

            r1 = out1["results"][0]
            self.assertEqual(r1["status"], "conflict_notified")
            self.assertEqual(r1["conflicts"], ["other.py"])
            self.assertEqual(r1["comment"], "created")
            self.assertEqual(out2["results"][0]["comment"], "unchanged")
            # Remote feat/two was never force-pushed or mutated, and workdir is clean.
            self.assertEqual(h.origin_sha("feat/two"), h2)
            self.assertEqual(h._git(h.workdir, "status", "--porcelain"), "")
            # Spoof comment untouched; exactly one trusted bot comment created.
            self.assertEqual(len(fake.comments[2]), 2)
            self.assertEqual(fake.comments[2][0]["body"], f"{rs.RESTACK_MARKER}\nspoof")
            bot_body = fake.comments[2][1]["body"]
            self.assertTrue(bot_body.startswith(rs.RESTACK_MARKER))
            self.assertIn("`other.py`", bot_body)
            self.assertIn("pr-review-loop", bot_body)

            # Advance main again: existing bot comment is PATCHed in place (still 2 comments total).
            h._git(h.author, "checkout", "main")
            h.write(h.author, "README.md", "# updated\n")
            h.commit_all(h.author, "docs update")
            h.push("main")
            with mock.patch.object(rs.gh, "api", side_effect=fake.api):
                out3 = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="scoped-pat", comment_token="gh-tok", scoped_token=True,
                )
            self.assertEqual(out3["results"][0]["comment"], "updated")
            self.assertEqual(len(fake.comments[2]), 2)

    def test_unrelated_clean_pr_skipped_and_unrelated_conflicting_pr_notified(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            # Unrelated clean PR #8
            h.branch("feat/clean", "main")
            h.write(h.author, "clean.py", "CLEAN = 1\n")
            h_clean = h.commit_all(h.author, "clean")
            h.push("feat/clean")

            # Unrelated conflicting PR #9
            h.branch("feat/collide", "main")
            h.write(h.author, "shared.py", "V = 'collide'\n")
            h_collide = h.commit_all(h.author, "collide")
            h.push("feat/collide")

            # Merged PR #1 touches shared.py
            h.branch("feat/one", "main")
            h.write(h.author, "shared.py", "V = 'one'\n")
            h1 = h.commit_all(h.author, "one")
            h.push("feat/one")
            s1 = h.squash_merge_to_main("feat/one", delete_remote_branch=True)

            fake = FakeGitHub([
                _pr_payload(8, head_ref="feat/clean", head_sha=h_clean, base_ref="main"),
                _pr_payload(9, head_ref="feat/collide", head_sha=h_collide, base_ref="main"),
            ])
            merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=h1, base_ref="main", merge_commit_sha=s1)
            with mock.patch.object(rs.gh, "api", side_effect=fake.api):
                out = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="scoped-pat", comment_token="gh-tok", scoped_token=True,
                )
            by_pr = {r["pr"]: r for r in out["results"]}
            self.assertEqual(by_pr[8]["status"], "skipped_clean_unrelated")
            self.assertEqual(h.origin_sha("feat/clean"), h_clean)
            self.assertNotIn(8, fake.comments)

            self.assertEqual(by_pr[9]["status"], "conflict_notified")
            self.assertFalse(by_pr[9]["stacked"])
            self.assertEqual(by_pr[9]["conflicts"], ["shared.py"])
            self.assertEqual(len(fake.comments[9]), 1)

    def test_dry_run_performs_zero_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            h.branch("feat/one", "main")
            h.write(h.author, "calc.py", "X = 1\n")
            h1 = h.commit_all(h.author, "one")
            h.push("feat/one")

            h.branch("feat/two", "feat/one")
            h.write(h.author, "calc.py", "X = 2\n")
            h2 = h.commit_all(h.author, "two")
            h.push("feat/two")
            s1 = h.squash_merge_to_main("feat/one", delete_remote_branch=True)

            fake = FakeGitHub([_pr_payload(2, head_ref="feat/two", head_sha=h2, base_ref="feat/one")])
            merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=h1, base_ref="main", merge_commit_sha=s1)
            with mock.patch.object(rs.gh, "api", side_effect=fake.api):
                out = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="scoped-pat", comment_token="gh-tok", scoped_token=True, dry_run=True,
                )
            self.assertEqual(out["results"][0]["status"], "would_restack")
            self.assertEqual(h.origin_sha("feat/two"), h2)
            self.assertTrue(all(method == "GET" for _, method, _, _ in fake.calls))


class SecurityAndTokenBehaviorTest(unittest.TestCase):
    def test_fork_and_dash_ref_prs_refused_before_any_branch_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            s1 = h.origin_sha("main")
            fake = FakeGitHub([
                _pr_payload(2, head_ref="feat/fork", head_sha=SHA2, base_ref="feat/one", head_repo="evil/r"),
                _pr_payload(3, head_ref="feat/cross", head_sha=SHA2, base_ref="main", cross=True),
                _pr_payload(4, head_ref="--upload-pack=evil", head_sha=SHA2, base_ref="main"),
                _pr_payload(5, head_ref="feat/ok", head_sha=SHA2, base_ref="-bad-base"),
            ])
            merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=SHA1, base_ref="main", merge_commit_sha=s1)
            fetched_branches: list[str] = []
            orig_fetch = rs.GitRepo.fetch_branch

            def spy_fetch(self_git, branch: str, *, token: str | None = None) -> str:
                fetched_branches.append(branch)
                return orig_fetch(self_git, branch, token=token)

            with mock.patch.object(rs.gh, "api", side_effect=fake.api), \
                    mock.patch.object(rs.GitRepo, "fetch_branch", spy_fetch):
                out = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="tok", comment_token="tok", scoped_token=True,
                )

            by_pr = {r["pr"]: r["status"] for r in out["results"]}
            self.assertEqual(by_pr, {
                2: "skipped_fork",
                3: "skipped_fork",
                4: "skipped_invalid_ref",
                5: "skipped_invalid_ref",
            })
            # Only the default branch (`main`) was fetched; no untrusted/fork/dash ref reached git.
            self.assertEqual(fetched_branches, ["main"])

    def test_github_token_fallback_dispatches_review_or_posts_status_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            h.branch("feat/one", "main")
            h.write(h.author, "calc.py", "X = 1\n")
            h1 = h.commit_all(h.author, "one")
            h.push("feat/one")

            h.branch("feat/two", "feat/one")
            h.write(h.author, "calc.py", "X = 2\n")
            h2 = h.commit_all(h.author, "two")
            h.push("feat/two")

            h.branch("feat/three", "feat/one")
            h.write(h.author, "calc.py", "X = 3\n")
            h3 = h.commit_all(h.author, "three")
            h.push("feat/three")

            s1 = h.squash_merge_to_main("feat/one", delete_remote_branch=True)
            merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=h1, base_ref="main", merge_commit_sha=s1)

            # Case A: workflow_dispatch succeeds -> no fallback warning comment needed.
            fake_ok = FakeGitHub([_pr_payload(2, head_ref="feat/two", head_sha=h2, base_ref="main")])
            with mock.patch.object(rs.gh, "api", side_effect=fake_ok.api):
                out_ok = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="ghs_token", comment_token="ghs_token", scoped_token=False,
                )
            self.assertTrue(out_ok["results"][0]["dispatched"])
            dispatch_calls = [c for c in fake_ok.calls if c[0].endswith("/dispatches")]
            self.assertEqual(len(dispatch_calls), 1)
            self.assertEqual(dispatch_calls[0][2], {"ref": "main", "inputs": {"pr": "2"}})
            self.assertEqual(fake_ok.comments, {})

            # Case B: workflow_dispatch fails (403) -> restack still succeeds and posts status comment.
            fake_blocked = FakeGitHub(
                [_pr_payload(3, head_ref="feat/three", head_sha=h3, base_ref="main")],
                dispatch_error=rs.gh.GhError("HTTP 403 Resource not accessible by integration"),
            )
            with mock.patch.object(rs.gh, "api", side_effect=fake_blocked.api), \
                    contextlib.redirect_stderr(io.StringIO()):
                out_blocked = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="ghs_token", comment_token="ghs_token", scoped_token=False,
                )
            self.assertEqual(out_blocked["errors"], [])
            res = out_blocked["results"][0]
            self.assertEqual(res["status"], "restacked")
            self.assertFalse(res["dispatched"])
            self.assertEqual(res["comment"], "created")
            note = fake_blocked.comments[3][0]["body"]
            self.assertTrue(note.startswith(rs.RESTACK_MARKER))
            self.assertIn("STACK_RESTACK_TOKEN", note)
            self.assertIn("/ai-review", note)

            # Case C: Draft PR restacks cleanly without prematurely dispatching pr-guardian review.
            h.branch("feat/four", "feat/one")
            h.write(h.author, "calc.py", "X = 4\n")
            h4 = h.commit_all(h.author, "four")
            h.push("feat/four")
            draft_pr = dict(_pr_payload(4, head_ref="feat/four", head_sha=h4, base_ref="main"), draft=True)
            fake_draft = FakeGitHub([draft_pr])
            with mock.patch.object(rs.gh, "api", side_effect=fake_draft.api):
                out_draft = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="ghs_token", comment_token="ghs_token", scoped_token=False,
                )
            self.assertEqual(out_draft["results"][0]["status"], "restacked")
            self.assertFalse([c for c in fake_draft.calls if c[0].endswith("/dispatches")])
            self.assertEqual(fake_draft.comments, {})

    def test_clean_restack_clears_stale_conflict_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = _GitHarness(tmp)
            h.branch("feat/one", "main")
            h.write(h.author, "calc.py", "X = 1\n")
            h1 = h.commit_all(h.author, "one")
            h.push("feat/one")

            h.branch("feat/two", "feat/one")
            h.write(h.author, "calc.py", "X = 2\n")
            h2 = h.commit_all(h.author, "two")
            h.push("feat/two")
            s1 = h.squash_merge_to_main("feat/one", delete_remote_branch=True)

            prior_conflict = {
                "id": 88,
                "user": {"type": "Bot", "login": st.TRUSTED_BOT_LOGIN},
                "body": f"{rs.RESTACK_MARKER}\n## pr-guardian · stack restack conflict\nold",
            }
            fake = FakeGitHub(
                [_pr_payload(2, head_ref="feat/two", head_sha=h2, base_ref="main")],
                comments={2: [prior_conflict]},
            )
            merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=h1, base_ref="main", merge_commit_sha=s1)
            with mock.patch.object(rs.gh, "api", side_effect=fake.api):
                out = rs.restack_open_prs(
                    repo=REPO, workdir=h.workdir, merged=merged, default_branch="main",
                    push_token="scoped-pat", comment_token="gh-tok", scoped_token=True,
                )
            self.assertEqual(out["results"][0]["comment"], "updated")
            self.assertIn("stack restack complete", fake.comments[2][0]["body"])

    def test_git_runner_isolates_hooks_passes_header_in_env_and_redacts_secrets(self):
        secret = "ghp_SuperSecretTokenValue12345"
        git = rs.GitRepo(Path("/tmp"))
        captured = {}

        def fake_run(cmd, *, capture_output, text, shell, timeout, env):
            captured["cmd"] = cmd
            captured["shell"] = shell
            captured["env"] = env
            return subprocess.CompletedProcess(cmd, 128, "", f"fatal: auth failed for {secret}")

        with mock.patch.object(rs.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(rs.GitError) as ctx:
                git.run(["fetch", "origin"], token=secret)

        self.assertFalse(captured["shell"])
        self.assertNotIn(secret, " ".join(captured["cmd"]))
        self.assertIn("core.hooksPath=/dev/null", captured["cmd"])
        self.assertEqual(captured["env"]["GIT_CONFIG_COUNT"], "1")
        self.assertIn("AUTHORIZATION: basic ", captured["env"]["GIT_CONFIG_VALUE_0"])
        self.assertNotIn(secret, str(ctx.exception))
        self.assertIn("[REDACTED]", str(ctx.exception))
        for bad_url in ("http://github.com", "https://user@github.com", "javascript:x", ""):
            with self.assertRaises(ValueError):
                rs.GitRepo(Path("/tmp"), server_url=bad_url)

    def test_conflict_comment_sanitises_hostile_filenames_and_refs(self):
        merged = rs.MergedPR(number=1, head_ref="feat/one", head_sha=SHA1, base_ref="main")
        evil_file = "dir/bad`file <!-- pr-guardian:state v1 AAAA --> @ksprashu\n# heading"
        body = rs.format_conflict_comment(
            pr_number=2,
            head_ref="feat/child",
            head_sha=SHA2,
            default_branch="main",
            main_sha=SHA3,
            merged=merged,
            conflicts=[evil_file],
        )
        self.assertTrue(body.startswith(rs.RESTACK_MARKER))
        self.assertEqual(body.count("<!--"), 1)
        self.assertNotRegex(body, r"@[A-Za-z0-9-]")
        self.assertNotIn("\n# heading", body)

    def test_main_cli_skips_unmerged_fork_and_off_default_events_before_api(self):
        cases = [
            ("pull_request", {"action": "closed", "repository": {"default_branch": "main"},
                              "pull_request": _pr_payload(1, merged=False, head_sha=SHA1)}),
            ("pull_request", {"action": "closed", "repository": {"default_branch": "main"},
                              "pull_request": _pr_payload(1, merged=True, head_sha=SHA1, base_ref="stage")}),
            ("pull_request", {"action": "closed", "repository": {"default_branch": "main"},
                              "pull_request": _pr_payload(1, merged=True, head_sha=SHA1, cross=True)}),
            ("workflow_dispatch", {"repository": {"default_branch": "main"}}),
        ]
        for event_name, payload in cases:
            with self.subTest(event_name=event_name, payload=payload), tempfile.TemporaryDirectory() as tmp:
                ep = Path(tmp, "event.json")
                ep.write_text(json.dumps(payload), encoding="utf-8")
                env = {
                    "GITHUB_EVENT_NAME": event_name,
                    "GITHUB_EVENT_PATH": str(ep),
                    "GITHUB_REF": "refs/heads/feat/not-main",
                    "GITHUB_TOKEN": "tok",
                }
                buf = io.StringIO()
                with mock.patch.dict(rs.os.environ, env, clear=True), \
                        mock.patch.object(rs.gh, "api") as api, \
                        mock.patch.object(rs.sys, "argv", ["restack.py", "--repo", REPO, "--workdir", tmp]), \
                        contextlib.redirect_stdout(buf):
                    self.assertEqual(rs.main(), 0)
                    api.assert_not_called()
                    printed = json.loads(buf.getvalue().strip())
                    self.assertEqual(printed["action"], "skip")


class RestackWorkflowAndGovernorTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent
    RESTACK_WF = ROOT / ".github" / "workflows" / "restack.yml"
    RESTACK_TPL = ROOT / "templates" / "stack-restack.yml"
    REVIEW_WF = ROOT / ".github" / "workflows" / "review.yml"

    def _event_ctx(self, event_name: str, *, action: str = "closed", merged: bool = True,
                   base_ref: str = "main", head_repo: str = REPO, ref: str = "refs/heads/main") -> dict:
        return {
            "github": {
                "event_name": event_name,
                "repository": REPO,
                "ref": ref,
                "event": {
                    "action": action,
                    "repository": {"default_branch": "main"},
                    "pull_request": {
                        "merged": merged,
                        "base": {"ref": base_ref},
                        "head": {"repo": {"full_name": head_repo}},
                    },
                },
            },
            "inputs": {"merged_pr": ""},
        }

    def test_caller_and_reusable_if_guards_enforce_default_branch_same_repo_merge(self):
        caller_if = tw.yaml_get(self.RESTACK_TPL.read_text(encoding="utf-8"), "jobs", "restack", "if")
        reusable_if = tw.yaml_get(self.RESTACK_WF.read_text(encoding="utf-8"), "jobs", "restack", "if")

        for label, cond in (("template", caller_if), ("reusable", reusable_if)):
            with self.subTest(source=label):
                # Allowed: merged same-repo PR into default branch, or workflow_dispatch on default branch.
                self.assertTrue(tw.eval_if(cond, self._event_ctx("pull_request")))
                self.assertTrue(tw.eval_if(cond, self._event_ctx("workflow_dispatch", ref="refs/heads/main")))
                # Blocked: unmerged close, off-default base, fork PR, open/synchronize PR, branch dispatch.
                self.assertFalse(tw.eval_if(cond, self._event_ctx("pull_request", merged=False)))
                self.assertFalse(tw.eval_if(cond, self._event_ctx("pull_request", base_ref="feat/one")))
                self.assertFalse(tw.eval_if(cond, self._event_ctx("pull_request", head_repo="evil/r")))
                self.assertFalse(tw.eval_if(cond, self._event_ctx("pull_request", action="opened")))
                self.assertFalse(tw.eval_if(cond, self._event_ctx("pull_request", action="synchronize")))
                self.assertFalse(tw.eval_if(cond, self._event_ctx("workflow_dispatch", ref="refs/heads/feat")))
                self.assertFalse(tw.eval_if(cond, self._event_ctx("workflow_dispatch", ref="")))
                self.assertFalse(tw.eval_if(cond, self._event_ctx("issue_comment")))

    def test_review_workflow_stays_read_only_and_restack_lacks_statuses_write(self):
        review_text = self.REVIEW_WF.read_text(encoding="utf-8")
        self.assertNotIn("contents: write", review_text)
        for path in (self.RESTACK_WF, self.RESTACK_TPL):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("statuses: write", text, path.name)
            self.assertNotIn("pull_request_target", text, path.name)

    def test_restack_template_pins_ref_twice_and_queues_concurrency(self):
        tpl = self.RESTACK_TPL.read_text(encoding="utf-8")
        self.assertIn("restack.yml@{{REF}}\n", tpl)
        self.assertIn("guardian_ref: {{REF}}\n", tpl)
        self.assertEqual(tpl.count("{{REF}}"), 2)
        self.assertEqual(tw.yaml_get(tpl, "jobs", "restack", "concurrency", "cancel-in-progress"), "false")
        wf = self.RESTACK_WF.read_text(encoding="utf-8")
        self.assertIn("--merged-pr=$MERGED_PR", wf)
        self.assertNotIn("inputs.merged_pr", wf.split("run: |", 1)[1])
        self.assertNotIn("inputs.guardian_ref", wf.split("run: |", 1)[1])

    def test_governor_opt_in_restack_uses_separate_branch_and_default_is_off(self):
        ref = "0123456789abcdef0123456789abcdef01234567"
        rendered_caller = gov.render_caller(ref)
        rendered_restack = gov.render_restack_caller(ref)
        self.assertIn(f"restack.yml@{ref}", rendered_restack)
        self.assertNotIn("{{REF}}", rendered_restack)

        repo = {"full_name": REPO, "name": "r", "default_branch": "main", "size": 10}
        ruleset = copy.deepcopy(gov.desired_ruleset())
        ruleset["id"] = 1

        def _b64_doc(text: str, sha: str = "blob1") -> dict:
            return {
                "type": "file",
                "encoding": "base64",
                "sha": sha,
                "content": __import__("base64").b64encode(text.encode()).decode(),
            }

        def fake_api(path: str, method: str = "GET", body: dict | None = None, **kw):
            if path == f"repos/{REPO}":
                return dict(repo, **gov.SETTINGS)
            if path == f"repos/{REPO}/branches/main":
                return {"name": "main"}
            if path == f"repos/{REPO}/contents/{gov.CALLER_PATH}?ref=main":
                return _b64_doc(rendered_caller)
            if path == f"repos/{REPO}/contents/{gov.RESTACK_CALLER_PATH}?ref=main":
                raise gov.gh.GhError("HTTP 404 Not Found")
            if path.startswith(f"repos/{REPO}/rulesets"):
                return [ruleset] if "includes_parents" in path else ruleset
            return []

        with mock.patch.object(gov.gh, "api", side_effect=fake_api), \
                mock.patch.object(gov, "secret_names", return_value={gov.SECRET}):
            # Default (restack=False): clean, never asks for stack-restack.yml.
            off = gov.reconcile(repo, ref, dry=True, have_key=True)
            self.assertEqual(off["drift"], [])
            # Opt-in (restack=True or Config.restack_repos): reports restack caller missing cleanly.
            on = gov.reconcile(repo, ref, dry=True, have_key=True, restack=True)
            self.assertEqual(on["drift"], ["restack caller missing"])
            self.assertEqual(on["pending"], ["restack caller missing"])
            held_cfg = gov.Config(restack_repos=frozenset({"r"}), held=True, hold_reason="canary pending")
            held_out = gov.reconcile(repo, ref, dry=False, have_key=True, cfg=held_cfg)
            self.assertIn("held for the canary ring", held_out["pending"][0])

        # Idempotent deliver_restack_caller: existing current PR with auto_merge makes zero writes.
        open_pr = {
            "number": 12,
            "head": {"ref": gov.RESTACK_INSTALL_BRANCH, "sha": "h12", "repo": {"full_name": REPO}},
            "base": {"ref": "main"},
            "changed_files": 1,
            "auto_merge": {"merge_method": "squash"},
            "created_at": "2026-11-15T00:00:00Z",
        }
        idem_calls: list[tuple[str, str]] = []

        def idem_api(path: str, method: str = "GET", body: dict | None = None, **kw):
            idem_calls.append((method, path))
            if path.startswith(f"repos/{REPO}/pulls?head=o:{gov.RESTACK_INSTALL_BRANCH}"):
                return [open_pr]
            if path == f"repos/{REPO}/pulls/12":
                return open_pr
            if path.startswith(f"repos/{REPO}/pulls/12/files"):
                return [{"filename": gov.RESTACK_CALLER_PATH, "status": "added"}]
            if path.startswith(f"repos/{REPO}/contents/{gov.RESTACK_CALLER_PATH}?ref="):
                return _b64_doc(rendered_restack, sha="rb1")
            if path.endswith("/protection"):
                raise gov.gh.GhError("HTTP 404 Not Found")
            raise AssertionError(f"unexpected call {method} {path}")

        with mock.patch.object(gov.gh, "api", side_effect=idem_api), \
                mock.patch.object(gov.gh, "_run") as gh_run:
            d = gov.deliver_restack_caller(REPO, "main", rendered_restack)
        self.assertFalse(d.merged)
        self.assertIn("restack caller PR #12 waiting (auto-merge queued)", d.note)
        self.assertTrue(all(m == "GET" for m, _ in idem_calls))
        gh_run.assert_not_called()

        self.assertNotEqual(gov.INSTALL_BRANCH, gov.RESTACK_INSTALL_BRANCH)
        self.assertEqual(gov.restack_repo_names(" a , b ,, "), {"a", "b"})


if __name__ == "__main__":
    unittest.main()
