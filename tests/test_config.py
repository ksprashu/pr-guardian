import base64
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import *  # noqa: F401,F403
import config as cfg
import gh
from textsafe import ZWSP


def _git_env() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=_git_env(),
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return proc.stdout.strip()


def _init_repo(repo: Path) -> None:
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Tester")


class YamlSubsetParserTest(unittest.TestCase):
    def test_empty_and_comments_only(self):
        self.assertEqual(cfg.parse_yaml_subset(""), {})
        self.assertEqual(cfg.parse_yaml_subset("  \n# only comments\n  # two\n"), {})
        self.assertEqual(cfg.parse_yaml_subset("---\n# leading doc marker\n"), {})

    def test_json_fast_path_and_rejections(self):
        parsed = cfg.parse_yaml_subset('  {"round_cap": 4, "block_on": ["P0", "P1"]}')
        self.assertEqual(parsed, {"round_cap": 4, "block_on": ["P0", "P1"]})
        for bad in (
            '{"round_cap": 4, "round_cap": 5}',
            '{"max_pr_cost_usd": NaN}',
            '{"max_pr_cost_usd": Infinity}',
            '{"round_cap": 4',
            '["P0"]',
        ):
            with self.assertRaises(cfg.ConfigError, msg=bad):
                cfg.parse_yaml_subset(bad)

    def test_block_and_flow_lists_and_scalars(self):
        text = """\
---
# pr-guardian config
block_on: ["P0", "P1"] # inline comment
ignore_paths:
  - "vendor/**"
  - '**/*.pb.go' # single quoted glob with #
docs_paths:
- docs/*.txt
- 'notes/it''s #1.txt'
round_cap: 5
diff_budget: 120_000
max_pr_cost_usd: 4.25
max_changed_lines: null
verifier: off
engines: [agy, "claude:claude-opus-5-5"]
"""
        parsed = cfg.parse_yaml_subset(text)
        self.assertEqual(parsed["block_on"], ["P0", "P1"])
        self.assertEqual(parsed["ignore_paths"], ["vendor/**", "**/*.pb.go"])
        self.assertEqual(parsed["docs_paths"], ["docs/*.txt", "notes/it's #1.txt"])
        self.assertEqual(parsed["round_cap"], 5)
        self.assertEqual(parsed["diff_budget"], 120000)
        self.assertEqual(parsed["max_pr_cost_usd"], 4.25)
        self.assertIsNone(parsed["max_changed_lines"])
        self.assertEqual(parsed["verifier"], "off")
        self.assertIsInstance(parsed["verifier"], str)
        self.assertEqual(parsed["engines"], ["agy", "claude:claude-opus-5-5"])

    def test_quotes_and_inline_comments(self):
        text = (
            'extra_instructions: "Use #1 \\"strict\\" rule" # trailing\n'
            "verifier: 'cross' # comment\n"
            "max_changed_lines: ~\n"
        )
        parsed = cfg.parse_yaml_subset(text)
        self.assertEqual(parsed["extra_instructions"], 'Use #1 "strict" rule')
        self.assertEqual(parsed["verifier"], "cross")
        self.assertIsNone(parsed["max_changed_lines"])

    def test_literal_and_folded_block_scalars(self):
        lit = "extra_instructions: |\n  # keep hash\n  line 1\n\n  line 2\nround_cap: 4\n"
        self.assertEqual(
            cfg.parse_yaml_subset(lit)["extra_instructions"],
            "# keep hash\nline 1\n\nline 2\n",
        )
        lit_strip = "extra_instructions: |-\n  line 1\n  \tline 2\n\nround_cap: 4\n"
        self.assertEqual(
            cfg.parse_yaml_subset(lit_strip)["extra_instructions"],
            "line 1\n\tline 2",
        )
        folded = "extra_instructions: >\n  first\n  second\n\n  para 2\n"
        self.assertEqual(
            cfg.parse_yaml_subset(folded)["extra_instructions"],
            "first second\npara 2\n",
        )
        folded_strip = "extra_instructions: >-\n  first\n  second\n\n  para 2\n"
        self.assertEqual(
            cfg.parse_yaml_subset(folded_strip)["extra_instructions"],
            "first second\npara 2",
        )

    def test_forbidden_yaml_constructs_rejected(self):
        cases = [
            "\tround_cap: 4\n",
            "ignore_paths:\n\t- vendor/**\n",
            "round_cap: &a 4\n",
            "round_cap: *a\n",
            "engines: [*a]\n",
            "extra_instructions: !!python/object:os.system x\n",
            "round_cap: !custom 4\n",
            "<<: *base\n",
            "round_cap: 4\n---\nround_cap: 5\n",
            "round_cap: 4\n...\n",
            'extra_instructions: "unclosed\n',
            "extra_instructions: 'unclosed\n",
            'block_on: ["P0"\n',
            'block_on: [["P0"]]\n',
            "round_cap: 3\nround_cap: 5\n",
            "ignore_paths:\n  - a\n    - b\n",
            "ignore_paths:\n    - a\n  - b\n",
            "- item\n",
            "x" * (cfg.MAX_CONFIG_BYTES + 1),
        ]
        for bad in cases:
            with self.assertRaises(cfg.ConfigError, msg=repr(bad[:80])):
                cfg.parse_yaml_subset(bad)


class ValidateConfigTest(unittest.TestCase):
    def test_defaults_and_valid_overrides(self):
        base = cfg.validate_config({})
        self.assertEqual(base, cfg.default_config())
        out = cfg.validate_config({
            "block_on": ["P2", "P0", "P2"],
            "verifier": True,
            "max_changed_lines": None,
            "max_pr_cost_usd": None,
            "engines": ["agy:gemini-4-argon-high", "claude"],
            "extra_instructions": "  Hi <!-- a --> <!-- b --> @dev  ",
        })
        self.assertEqual(out["block_on"], ["P0", "P2"])
        self.assertEqual(out["verifier"], "self")
        self.assertIsNone(out["max_changed_lines"])
        self.assertIsNone(out["max_pr_cost_usd"])
        self.assertEqual(out["extra_instructions"], f"Hi   @{ZWSP}dev")

        nested = cfg.validate_config({"extra_instructions": "<!<!-- b -->-- c -->"})
        self.assertNotIn("<!--", nested["extra_instructions"])

        self.assertEqual(cfg.validate_config({"verifier": False})["verifier"], "off")

    def test_invalid_schema_values_rejected(self):
        bad_cases = [
            {"unknown_key": 1},
            {"round_cap": True},
            {"reopen_escalation": False},
            {"max_changed_lines": True},
            {"max_pr_cost_usd": True},
            {"round_cap": 0},
            {"round_cap": 21},
            {"reopen_escalation": 0},
            {"reopen_escalation": 11},
            {"block_on": []},
            {"block_on": ["P1", "P2"]},  # omits P0
            {"block_on": ["P0", "nit"]},
            {"diff_budget": 9_999},
            {"per_file_budget": 999},
            {"diff_budget": 10_000, "per_file_budget": 20_000},
            {"leads_budget": 5},
            {"max_changed_lines": 50},
            {"max_changed_lines": 500_001},
            {"max_pr_cost_usd": -1.0},
            {"max_pr_cost_usd": 0.01},
            {"max_pr_cost_usd": 501.0},
            {"max_pr_cost_usd": float("nan")},
            {"max_pr_cost_usd": float("inf")},
            {"engines": []},
            {"engines": ["openai"]},
            {"engines": ["agy:bad slug"]},
            {"engines": ["agy:-leading"]},
            {"verifier": "yes"},
            {"verifier": "on"},
            {"chunk_threshold_chars": 10_000},
            {"max_chunks": 0},
            {"max_chunks": 11},
            {"ignore_paths": ["../secret"]},
            {"ignore_paths": ["/etc/passwd"]},
            {"ignore_paths": ["a\\b"]},
            {"docs_paths": ["docs/"]},
            {"docs_paths": ["docs//a.md"]},
            {"docs_paths": ["bad\x01path"]},
            {"ignore_paths": [f"f{i}.py" for i in range(101)]},
            {"extra_instructions": "x" * 4001},
        ]
        for bad in bad_cases:
            with self.assertRaises(cfg.ConfigError, msg=repr(bad)):
                cfg.validate_config(bad)


class BaseRefIsolationTest(unittest.TestCase):
    def test_reads_config_exclusively_from_base_not_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo)
            cfg_file = repo / ".github" / "pr-guardian.yml"
            cfg_file.parent.mkdir(parents=True)
            cfg_file.write_text("max_changed_lines: 5000\nround_cap: 3\n", encoding="utf-8")
            _git(repo, "add", ".github/pr-guardian.yml")
            _git(repo, "commit", "-m", "base")
            base_sha = _git(repo, "rev-parse", "HEAD")

            # PR head tampers with config in commit and worktree
            _git(repo, "checkout", "-b", "pr-head")
            cfg_file.write_text(
                'max_changed_lines: 999999\nignore_paths: ["src/**"]\nround_cap: 20\n',
                encoding="utf-8",
            )
            _git(repo, "add", ".github/pr-guardian.yml")
            _git(repo, "commit", "-m", "tamper head")
            cfg_file.write_text("round_cap: 1\n", encoding="utf-8")

            loaded, warnings = cfg.load_from_base(repo, base_sha=base_sha)
            self.assertEqual(warnings, [])
            self.assertEqual(loaded["max_changed_lines"], 5000)
            self.assertEqual(loaded["round_cap"], 3)
            self.assertEqual(loaded["ignore_paths"], [])

            # Also verify origin/<base_ref> resolution when base_sha is empty.
            _git(repo, "update-ref", "refs/remotes/origin/main", base_sha)
            loaded_ref, warnings_ref = cfg.load_from_base(repo, base_ref="main")
            self.assertEqual(warnings_ref, [])
            self.assertEqual(loaded_ref["max_changed_lines"], 5000)
            self.assertEqual(loaded_ref["round_cap"], 3)

    def test_absent_config_on_base_returns_defaults_even_if_head_adds_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo)
            (repo / "README.md").write_text("hi\n", encoding="utf-8")
            _git(repo, "add", "README.md")
            _git(repo, "commit", "-m", "base")
            base_sha = _git(repo, "rev-parse", "HEAD")

            _git(repo, "checkout", "-b", "pr-head")
            (repo / ".github").mkdir()
            (repo / ".github" / "pr-guardian.yml").write_text("max_changed_lines: 500000\n", encoding="utf-8")
            _git(repo, "add", ".github/pr-guardian.yml")
            _git(repo, "commit", "-m", "head adds config")

            with mock.patch.object(gh, "api", side_effect=AssertionError("must not fall back to API")):
                loaded, warnings = cfg.load_from_base(repo, base_sha=base_sha, repo="o/r")
            self.assertEqual(loaded, cfg.default_config())
            self.assertEqual(warnings, [])

    def test_corrupt_base_config_strict_and_non_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo)
            (repo / ".github").mkdir()
            (repo / ".github" / "pr-guardian.yml").write_text("unknown_field: 1\n", encoding="utf-8")
            _git(repo, "add", ".github/pr-guardian.yml")
            _git(repo, "commit", "-m", "bad config")
            base_sha = _git(repo, "rev-parse", "HEAD")

            with self.assertRaises(cfg.ConfigError):
                cfg.load_from_base(repo, base_sha=base_sha, strict=True)

            err_buf = io.StringIO()
            with mock.patch.object(cfg.sys, "stderr", err_buf):
                loaded, warnings = cfg.load_from_base(repo, base_sha=base_sha, strict=False)
            self.assertEqual(loaded, cfg.default_config())
            self.assertEqual(len(warnings), 1)
            self.assertIn("unknown_field", warnings[0])
            self.assertIn("::warning::", err_buf.getvalue())

    def test_api_fallback_when_no_git_dir(self):
        payload = base64.b64encode(b"round_cap: 9\n").decode("ascii")
        api_resp = {"type": "file", "encoding": "base64", "content": payload, "size": 13}
        with mock.patch.object(gh, "api", return_value=api_resp) as m:
            loaded, warnings = cfg.load_from_base(None, base_sha="a" * 40, repo="o/r")
        self.assertEqual(warnings, [])
        self.assertEqual(loaded["round_cap"], 9)
        self.assertIn("ref=" + "a" * 40, m.call_args[0][0])

    def test_api_fallback_oversized_none_encoding_fails_closed(self):
        # GitHub Contents API returns encoding="none" and content="" for >1 MB files.
        api_resp = {"type": "file", "encoding": "none", "content": "", "size": 2_000_000}
        with mock.patch.object(gh, "api", return_value=api_resp):
            with self.assertRaises(cfg.ConfigError):
                cfg.load_from_base(None, base_sha="a" * 40, repo="o/r", strict=True)
            err_buf = io.StringIO()
            with mock.patch.object(cfg.sys, "stderr", err_buf):
                loaded, warnings = cfg.load_from_base(None, base_sha="a" * 40, repo="o/r", strict=False)
            self.assertEqual(loaded, cfg.default_config())
            self.assertEqual(len(warnings), 1)
            self.assertIn("exceeds", warnings[0])
            self.assertIsNone(
                cfg.read_base_file(
                    None, "AGENTS.md", base_sha="a" * 40, repo="o/r",
                    max_bytes=256 * 1024, strict_size=False, strict_decode=False,
                )
            )


class GlobMatcherTest(unittest.TestCase):
    def test_single_star_does_not_cross_slash(self):
        self.assertTrue(cfg.path_matches_any("docs/a.md", ["docs/*.md"]))
        self.assertFalse(cfg.path_matches_any("docs/.github/workflows/x.md", ["docs/*.md"]))
        self.assertFalse(cfg.path_matches_any("docs/sub/a.md", ["docs/*.md"]))

    def test_double_star_matches_zero_or_more_dirs(self):
        self.assertTrue(cfg.path_matches_any("vendor/a.py", ["vendor/**"]))
        self.assertTrue(cfg.path_matches_any("vendor/a/b/c.py", ["vendor/**"]))
        self.assertFalse(cfg.path_matches_any("vendor", ["vendor/**"]))
        self.assertFalse(cfg.path_matches_any("vendor2/a.py", ["vendor/**"]))

        self.assertTrue(cfg.path_matches_any("foo.pb.go", ["**/*.pb.go"]))
        self.assertTrue(cfg.path_matches_any("a/foo.pb.go", ["**/*.pb.go"]))
        self.assertTrue(cfg.path_matches_any("a/b/c/foo.pb.go", ["**/*.pb.go"]))
        self.assertFalse(cfg.path_matches_any("a/foo.pb.gox", ["**/*.pb.go"]))

        self.assertTrue(cfg.path_matches_any("docs/a.md", ["docs/**/*.md"]))
        self.assertTrue(cfg.path_matches_any("docs/x/y/a.md", ["docs/**/*.md"]))
        self.assertFalse(cfg.path_matches_any("other/a.md", ["docs/**/*.md"]))

    def test_malformed_paths_never_match(self):
        for p in ("", None, "../a.md", "/etc/passwd", "docs/", "C:\\a.md"):
            self.assertFalse(cfg.path_matches_any(p, ["**", "*.md"]), repr(p))


if __name__ == "__main__":
    unittest.main()
