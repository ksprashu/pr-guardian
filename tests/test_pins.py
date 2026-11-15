import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import tests.helpers  # noqa: F401
import check_pins
import gh


REPO_ROOT = Path(__file__).resolve().parent.parent
VALID_SHA40 = "a" * 40
VALID_SHA64 = "b" * 64
VALID_SHA128 = "c" * 128


def _make_clean_repo(root: Path) -> None:
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "scripts").mkdir(parents=True)
    (root / "config" / "claude-code").mkdir(parents=True)

    (root / ".github" / "workflows" / "review.yml").write_text(
        f"env:\n  FORGE_REPO: owner/forge\n  FORGE_REF: {VALID_SHA40} # pinned\n"
        f"jobs:\n  test:\n    steps:\n      - uses: actions/checkout@{VALID_SHA40}\n",
        encoding="utf-8",
    )
    (root / "scripts" / "install_scanners.sh").write_text(
        "#!/usr/bin/env bash\n"
        "python3 -m pip install --quiet --user --require-hashes --only-binary=:all: -r \"$HERE/requirements-scanners.txt\"\n",
        encoding="utf-8",
    )
    (root / "scripts" / "requirements-scanners.in").write_text("semgrep==1.2.3\n", encoding="utf-8")
    (root / "scripts" / "requirements-scanners.txt").write_text(
        f"semgrep==1.2.3 \\\n    --hash=sha256:{VALID_SHA64}\n",
        encoding="utf-8",
    )
    (root / "scripts" / "requirements-dev.in").write_text("coverage==7.*\n", encoding="utf-8")
    (root / "scripts" / "requirements-dev.txt").write_text(
        f"coverage==7.17.3 \\\n    --hash=sha256:{VALID_SHA64}\n",
        encoding="utf-8",
    )
    (root / "scripts" / "install_agy.sh").write_text(
        "#!/usr/bin/env bash\n"
        "AGY_VERSION=1.5.9\n"
        f"AGY_URL=\"{check_pins.AGY_STORAGE_PREFIX}1.5.9-123/linux-x64/cli_linux_x64.tar.gz\"\n"
        f"AGY_SHA512={VALID_SHA128}\n"
        "AGY_MANIFEST=\"https://antigravity.example/manifests/linux_amd64.json\"\n",
        encoding="utf-8",
    )
    (root / "config" / "claude-code" / "package.json").write_text(
        json.dumps({"name": "cc", "dependencies": {"@anthropic-ai/claude-code": "2.1.280"}}),
        encoding="utf-8",
    )
    (root / "config" / "claude-code" / "package-lock.json").write_text("{}", encoding="utf-8")


class CheckPinsTest(unittest.TestCase):
    def test_real_repo_passes_offline(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_pins.main(["--root", str(REPO_ROOT)])
        self.assertEqual(rc, 0, msg=buf.getvalue())
        self.assertEqual(buf.getvalue(), "")

    def test_synthetic_tree_passes_and_supports_wildcard_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_clean_repo(root)
            self.assertEqual(check_pins.main(["--root", tmp]), 0)

    def test_invalid_forge_ref_variants(self):
        for bad in ("main", "a" * 39, "A" * 40):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                _make_clean_repo(root)
                wf = root / ".github" / "workflows" / "review.yml"
                wf.write_text(
                    wf.read_text(encoding="utf-8").replace(VALID_SHA40, bad, 1),
                    encoding="utf-8",
                )
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = check_pins.main(["--root", tmp])
                self.assertEqual(rc, 1)
                self.assertIn("::error::", buf.getvalue())

    def test_unpinned_workflow_uses_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_clean_repo(root)
            (root / ".github" / "workflows" / "extra.yml").write_text(
                "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = check_pins.main(["--root", tmp])
            self.assertEqual(rc, 1)
            self.assertIn("unpinned uses", buf.getvalue())

    def test_requirement_without_hash_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_clean_repo(root)
            (root / "scripts" / "requirements-scanners.txt").write_text(
                "semgrep==1.2.3\n", encoding="utf-8"
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = check_pins.main(["--root", tmp])
            self.assertEqual(rc, 1)
            self.assertIn("hash", buf.getvalue())

    def test_in_pin_missing_from_txt_or_mismatched_fails(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            redirect_stdout(io.StringIO()),
        ):
            root = Path(tmp)
            _make_clean_repo(root)
            (root / "scripts" / "requirements-scanners.in").write_text(
                "semgrep==1.2.3\nzizmor==1.31.1\n", encoding="utf-8"
            )
            self.assertEqual(check_pins.main(["--root", tmp]), 1)

        with (
            tempfile.TemporaryDirectory() as tmp,
            redirect_stdout(io.StringIO()),
        ):
            root = Path(tmp)
            _make_clean_repo(root)
            (root / "scripts" / "requirements-dev.txt").write_text(
                f"coverage==8.0.0 \\\n    --hash=sha256:{VALID_SHA64}\n",
                encoding="utf-8",
            )
            self.assertEqual(check_pins.main(["--root", tmp]), 1)

    def test_install_scanners_missing_flags_fails(self):
        for bad_cmd in (
            "pip install --only-binary=:all: -r req.txt\n",
            "pip install --require-hashes -r req.txt\n",
        ):
            with (
                self.subTest(bad_cmd=bad_cmd),
                tempfile.TemporaryDirectory() as tmp,
                redirect_stdout(io.StringIO()),
            ):
                root = Path(tmp)
                _make_clean_repo(root)
                (root / "scripts" / "install_scanners.sh").write_text(bad_cmd, encoding="utf-8")
                self.assertEqual(check_pins.main(["--root", tmp]), 1)

    def test_agy_url_prefix_and_version_checks(self):
        for url in (
            "https://evil.example/1.5.9-1/cli.tar.gz",
            f"{check_pins.AGY_STORAGE_PREFIX}1.5.8-1/cli.tar.gz",
        ):
            with (
                self.subTest(url=url),
                tempfile.TemporaryDirectory() as tmp,
                redirect_stdout(io.StringIO()),
            ):
                root = Path(tmp)
                _make_clean_repo(root)
                (root / "scripts" / "install_agy.sh").write_text(
                    f"AGY_VERSION=1.5.9\nAGY_URL=\"{url}\"\nAGY_SHA512={VALID_SHA128}\n",
                    encoding="utf-8",
                )
                self.assertEqual(check_pins.main(["--root", tmp]), 1)

    def test_package_json_range_and_missing_lockfile_fail(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            root = Path(tmp)
            _make_clean_repo(root)
            (root / "config" / "claude-code" / "package.json").write_text(
                json.dumps({"dependencies": {"@anthropic-ai/claude-code": "^2.1.280"}}),
                encoding="utf-8",
            )
            self.assertEqual(check_pins.main(["--root", tmp]), 1)

        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            root = Path(tmp)
            _make_clean_repo(root)
            (root / "config" / "claude-code" / "package-lock.json").unlink()
            self.assertEqual(check_pins.main(["--root", tmp]), 1)

    def test_non_https_refused(self):
        with self.assertRaises(ValueError):
            check_pins._https_request("http://example.com/manifest.json")

    def test_online_diverged_forge_warns_and_exits_zero(self):
        class _Resp:
            status = 200
            def __init__(self, body=b"{}"): self._body = body
            def read(self): return self._body
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_api(path, **_kw):
            if "compare/" in path:
                return {"status": "diverged", "behind_by": 50}
            return {"default_branch": "main"}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_clean_repo(root)
            buf = io.StringIO()
            with (
                mock.patch.object(gh, "api", side_effect=fake_api),
                mock.patch.object(
                    check_pins.urllib.request,
                    "urlopen",
                    return_value=_Resp(json.dumps({"version": "1.5.9"}).encode()),
                ),
                redirect_stdout(buf),
            ):
                rc = check_pins.main(["--root", tmp, "--online"])
            self.assertEqual(rc, 0)
            self.assertIn("::warning::", buf.getvalue())
            self.assertIn("not reachable", buf.getvalue())

    def test_online_gh_error_warns_and_exits_zero(self):
        class _Resp:
            status = 200
            def read(self): return json.dumps({"version": "1.6.0"}).encode()
            def __enter__(self): return self
            def __exit__(self, *a): return False

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_clean_repo(root)
            buf = io.StringIO()
            with (
                mock.patch.object(gh, "api", side_effect=gh.GhError("rate limited")),
                mock.patch.object(check_pins.urllib.request, "urlopen", return_value=_Resp()),
                redirect_stdout(buf),
            ):
                rc = check_pins.main(["--root", tmp, "--online"])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("::warning::online FORGE_REF check failed", out)
            self.assertIn("::warning::agy pin 1.5.9 is behind current 1.6.0", out)

    def test_online_head_not_200_warns_and_exits_zero(self):
        class _Resp:
            def __init__(self, status, body=b""):
                self.status = status
                self._body = body
            def read(self): return self._body
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=10):
            if req.get_method() == "HEAD":
                return _Resp(404)
            return _Resp(200, json.dumps({"version": "1.5.9"}).encode())

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_clean_repo(root)
            buf = io.StringIO()
            with (
                mock.patch.object(gh, "api", return_value={"status": "ahead", "ahead_by": 2, "default_branch": "main"}),
                mock.patch.object(check_pins.urllib.request, "urlopen", side_effect=fake_urlopen),
                redirect_stdout(buf),
            ):
                rc = check_pins.main(["--root", tmp, "--online"])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("::notice::FORGE_REF is 2 commits behind main", out)
            self.assertIn("::warning::pinned agy build is no longer downloadable", out)

    def test_missing_files_and_extra_failure_paths(self):
        with tempfile.TemporaryDirectory() as empty_tmp, redirect_stdout(io.StringIO()):
            self.assertEqual(check_pins.main(["--root", empty_tmp]), 1)

        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            root = Path(tmp)
            _make_clean_repo(root)
            (root / ".github" / "workflows" / "local.yml").write_text(
                "# comment uses: x\njobs:\n  a:\n    steps:\n      - uses: ./local-action\n",
                encoding="utf-8",
            )
            (root / "scripts" / "requirements-empty.txt").write_text("", encoding="utf-8")
            (root / "scripts" / "requirements-badpin.txt").write_text("foo>=1.0\n", encoding="utf-8")
            (root / "scripts" / "requirements-badin.in").write_text("foo>=1.0\n", encoding="utf-8")
            (root / "scripts" / "requirements-badin.txt").write_text(
                f"foo==1.0 \\\n    --hash=sha256:{VALID_SHA64}\n", encoding="utf-8"
            )
            self.assertEqual(check_pins.main(["--root", tmp]), 1)

        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            root = Path(tmp)
            _make_clean_repo(root)
            (root / "config" / "claude-code" / "package.json").write_text("{bad json", encoding="utf-8")
            (root / "scripts" / "install_agy.sh").write_text(
                "AGY_VERSION=bad\nAGY_URL=\"https://x\"\nAGY_SHA512=123\n",
                encoding="utf-8",
            )
            (root / "scripts" / "install_scanners.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
            self.assertEqual(check_pins.main(["--root", tmp]), 1)

        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            root = Path(tmp)
            _make_clean_repo(root)
            (root / "config" / "claude-code" / "package.json").write_text(
                json.dumps({"name": "cc", "dependencies": {}}), encoding="utf-8"
            )
            self.assertEqual(check_pins.main(["--root", tmp]), 1)

    def test_online_network_http_errors_stay_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_clean_repo(root)
            buf = io.StringIO()
            err_404 = urllib.error.HTTPError("https://x", 404, "Not Found", {}, None)
            with (
                mock.patch.object(gh, "api", return_value="not-a-dict"),
                mock.patch.object(
                    check_pins.urllib.request,
                    "urlopen",
                    side_effect=[urllib.error.URLError("offline"), err_404],
                ),
                redirect_stdout(buf),
            ):
                rc = check_pins.main(["--root", tmp, "--online"])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("unexpected payload", out)
            self.assertIn("online agy manifest check failed", out)
            self.assertIn("no longer downloadable (HTTP 404)", out)


if __name__ == "__main__":
    unittest.main()
