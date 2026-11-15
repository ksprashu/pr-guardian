import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import tests.helpers as helpers

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_eval_module():
    spec = importlib.util.spec_from_file_location("prg_eval", REPO_ROOT / "scripts" / "eval.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


eval_mod = _load_eval_module()


def _copy_case(dst_root: Path, case_name: str) -> Path:
    src = REPO_ROOT / "evals" / "cases" / case_name
    dst = dst_root / "evals" / "cases" / case_name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)
    return dst


def _make_mini_repo(root: Path, *, copy_ref: bool = False) -> None:
    (root / "prompts").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO_ROOT / "prompts" / "review.md", root / "prompts" / "review.md")
    shutil.copy2(REPO_ROOT / ".github" / "workflows" / "review.yml", root / ".github" / "workflows" / "review.yml")
    _copy_case(root, "sqli-string-concat")
    _copy_case(root, "clean-parameterised-query")
    if copy_ref:
        ref_dst = root / "evals" / "recorded" / "reference"
        ref_dst.mkdir(parents=True, exist_ok=True)
        for fname in ("meta.json", "sqli-string-concat.findings.json", "clean-parameterised-query.findings.json"):
            shutil.copy2(REPO_ROOT / "evals" / "recorded" / "reference" / fname, ref_dst / fname)


class ScorerTests(unittest.TestCase):
    def test_line_matching_and_tolerance(self):
        exp = {"label": "sqli", "file": "app.py", "start_line": 10, "end_line": 12, "rules": ["CWE-89"], "axes": ["security"]}
        self.assertTrue(eval_mod.matches(helpers.finding(file="app.py", start=10, end=12, rule="CWE-89"), exp))
        self.assertTrue(eval_mod.matches(helpers.finding(file="app.py", start=7, end=7, rule="CWE-89"), exp))
        self.assertTrue(eval_mod.matches(helpers.finding(file="app.py", start=15, end=15, rule="CWE-89"), exp))
        self.assertFalse(eval_mod.matches(helpers.finding(file="app.py", start=6, end=6, rule="CWE-89"), exp))
        self.assertFalse(eval_mod.matches(helpers.finding(file="app.py", start=16, end=16, rule="CWE-89"), exp))

    def test_rule_axis_and_open_location_matching(self):
        exp_rule = {"label": "x", "file": "app.py", "start_line": 3, "end_line": 3, "rules": ["CWE-89"], "axes": ["security"]}
        self.assertTrue(eval_mod.matches(helpers.finding(rule="cwe-89 injection", axis="other"), exp_rule))
        self.assertTrue(eval_mod.matches(helpers.finding(rule="", axis="security"), exp_rule))
        self.assertFalse(eval_mod.matches(helpers.finding(rule="CWE-78", axis="correctness"), exp_rule))

        exp_loc = {"label": "loc", "file": "app.py", "start_line": 3, "end_line": 3}
        self.assertTrue(eval_mod.matches(helpers.finding(rule="anything", axis="reliability"), exp_loc))

    def test_nit_fixed_one_to_one_clean_fp_and_underrated(self):
        expected = {
            "clean": False,
            "expect": [
                {"label": "a", "file": "app.py", "start_line": 3, "end_line": 3, "rules": ["CWE-89"], "axes": ["security"], "min_severity": "P1"},
                {"label": "b", "file": "app.py", "start_line": 3, "end_line": 4, "rules": ["CWE-89"], "axes": ["security"], "min_severity": "P1"},
            ],
        }
        fdoc = helpers.doc(
            helpers.finding(id="1", severity="nit", status="new", start=3, end=3),
            helpers.finding(id="2", severity="P1", status="fixed", start=3, end=3),
            helpers.finding(id="3", severity="P2", status="new", start=3, end=3),
        )
        res = eval_mod.score_case("c1", expected, fdoc)
        self.assertEqual(res["hit"], 1)
        self.assertEqual(res["missed"], ["b"])
        self.assertEqual(res["false_positives"], 0)
        self.assertEqual(res["underrated"], [{"label": "a", "expected": "P1", "got": "P2"}])

        clean_res = eval_mod.score_case("c2", {"clean": True, "expect": []}, helpers.doc(helpers.finding(severity="P2")))
        self.assertEqual(clean_res["false_positives"], 1)

    def test_thresholds_and_nothing_to_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_mini_repo(root, copy_ref=False)
            (root / "evals" / "recorded").mkdir(parents=True, exist_ok=True)
            out = io.StringIO()
            with redirect_stdout(out):
                rc = eval_mod.main(["score", "--root", tmp, "--recorded", "all"])
            self.assertEqual(rc, 0)
            self.assertIn("no eval recordings", out.getvalue())

            fdir = root / "f"
            fdir.mkdir()
            (fdir / "sqli-string-concat.findings.json").write_text(json.dumps(helpers.doc()), encoding="utf-8")
            (fdir / "clean-parameterised-query.findings.json").write_text(
                json.dumps(helpers.doc(helpers.finding(severity="P1", file="app/users.py", start=12, end=12))),
                encoding="utf-8",
            )
            with redirect_stdout(io.StringIO()):
                rc_recall_fail = eval_mod.main(["score", "--root", tmp, "--findings-dir", str(fdir), "--min-recall", "0.5"])
                rc_fp_fail = eval_mod.main(
                    ["score", "--root", tmp, "--findings-dir", str(fdir), "--min-recall", "0.0", "--max-clean-fp", "0"]
                )
                rc_pass = eval_mod.main(
                    ["score", "--root", tmp, "--findings-dir", str(fdir), "--min-recall", "0.0", "--max-clean-fp", "1"]
                )
            self.assertEqual(rc_recall_fail, 1)
            self.assertEqual(rc_fp_fail, 1)
            self.assertEqual(rc_pass, 0)


@unittest.skipUnless(shutil.which("git"), "git binary required")
class LintTests(unittest.TestCase):
    def test_committed_cases_lint_clean(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = eval_mod.main(["lint", "--root", str(REPO_ROOT)])
        self.assertEqual(rc, 0, msg=buf.getvalue())
        self.assertIn("11 case(s) valid", buf.getvalue())

    def test_lint_defect_variants_fail(self):
        def expect_lint_fail(mutator):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cdir = _copy_case(root, "sqli-string-concat")
                mutator(cdir)
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(eval_mod.main(["lint", "--root", tmp]), 1)

        # 1. Patch does not apply
        expect_lint_fail(lambda cdir: (cdir / "diff.patch").write_text("--- a/nope.py\n+++ b/nope.py\n@@ -1 +1 @@\n-foo\n+bar\n", encoding="utf-8"))

        # 2. Expected line past end of file
        def past_end(cdir: Path):
            exp = json.loads((cdir / "expected.json").read_text(encoding="utf-8"))
            exp["expect"][0]["end_line"] = 999
            (cdir / "expected.json").write_text(json.dumps(exp), encoding="utf-8")

        expect_lint_fail(past_end)

        # 3. Expected file not in patch
        def wrong_file(cdir: Path):
            exp = json.loads((cdir / "expected.json").read_text(encoding="utf-8"))
            exp["expect"][0]["file"] = "app/other.py"
            (cdir / "expected.json").write_text(json.dumps(exp), encoding="utf-8")

        expect_lint_fail(wrong_file)

        # 4. clean: true with expectations
        def clean_with_exp(cdir: Path):
            exp = json.loads((cdir / "expected.json").read_text(encoding="utf-8"))
            exp["clean"] = True
            (cdir / "expected.json").write_text(json.dumps(exp), encoding="utf-8")

        expect_lint_fail(clean_with_exp)

        # 5. Duplicate label
        def dup_label(cdir: Path):
            exp = json.loads((cdir / "expected.json").read_text(encoding="utf-8"))
            exp["expect"].append(dict(exp["expect"][0]))
            (cdir / "expected.json").write_text(json.dumps(exp), encoding="utf-8")

        expect_lint_fail(dup_label)


class ReferenceAndFreshnessTests(unittest.TestCase):
    def test_reference_recording_scores_perfectly(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = eval_mod.main(
                [
                    "score",
                    "--root",
                    str(REPO_ROOT),
                    "--recorded",
                    "reference",
                    "--min-recall",
                    "1.0",
                    "--max-clean-fp",
                    "0",
                    "--check-fresh",
                    "--json",
                ]
            )
        self.assertEqual(rc, 0)
        data = json.loads(out.getvalue())["labels"][0]
        self.assertEqual(data["recall"], 1.0)
        self.assertEqual(data["clean_false_positives"], 0)
        self.assertEqual(data["stale"], [])

    def test_freshness_warning_strict_and_reference_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_mini_repo(root, copy_ref=True)
            rec = root / "evals" / "recorded" / "agy-test"
            rec.mkdir(parents=True)
            for fname in ("sqli-string-concat.findings.json", "clean-parameterised-query.findings.json"):
                shutil.copy2(REPO_ROOT / "evals" / "recorded" / "reference" / fname, rec / fname)
            ref_meta = json.loads((root / "evals" / "recorded" / "reference" / "meta.json").read_text(encoding="utf-8"))
            (rec / "meta.json").write_text(
                json.dumps(
                    {
                        "engine": "agy",
                        "model": "gemini-4-argon-high",
                        "forge_ref": ref_meta["forge_ref"],
                        "prompt_sha256": ref_meta["prompt_sha256"],
                        "recorded_at": "2026-11-14T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )

            # Mutate prompt so prompt_sha256 changes.
            (root / "prompts" / "review.md").write_text("changed prompt\n", encoding="utf-8")

            warn_buf = io.StringIO()
            with redirect_stdout(warn_buf):
                rc_warn = eval_mod.main(["score", "--root", tmp, "--recorded", "agy-test", "--check-fresh"])
            self.assertEqual(rc_warn, 0)
            self.assertIn("::warning::recorded evals \"agy-test\" are stale", warn_buf.getvalue())

            with redirect_stdout(io.StringIO()):
                rc_strict = eval_mod.main(["score", "--root", tmp, "--recorded", "agy-test", "--strict-fresh"])
                rc_ref = eval_mod.main(["score", "--root", tmp, "--recorded", "reference", "--strict-fresh"])
            self.assertEqual(rc_strict, 1)
            self.assertEqual(rc_ref, 0)


@unittest.skipUnless(shutil.which("git"), "git binary required")
class RunTests(unittest.TestCase):
    def test_run_records_meta_and_isolates_git_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_mini_repo(root, copy_ref=False)
            forge = root / "forge"
            flib = forge / "skills" / "review" / "scripts" / "findings.py"
            flib.parent.mkdir(parents=True)
            flib.write_text("# stub\n", encoding="utf-8")

            recorded_git_calls = []
            real_subproc = subprocess.run

            def spy_subproc(cmd, **kwargs):
                recorded_git_calls.append((list(cmd), dict(kwargs.get("env") or {})))
                return real_subproc(cmd, **kwargs)

            def fake_run_model():
                argv = eval_mod.sys.argv
                out_p = Path(argv[argv.index("--out") + 1])
                usage_p = Path(argv[argv.index("--usage-out") + 1])
                name = out_p.name[: -len(".findings.json")]
                if name == "sqli-string-concat":
                    doc = json.loads((REPO_ROOT / "evals" / "recorded" / "reference" / "sqli-string-concat.findings.json").read_text())
                else:
                    doc = helpers.doc()
                out_p.write_text(json.dumps(doc), encoding="utf-8")
                usage_p.write_text(
                    json.dumps({"total_cost_usd": 0.02, "attempt_details": [{"duration_seconds": 1.5}]}),
                    encoding="utf-8",
                )
                return 0

            out_buf = io.StringIO()
            with (
                mock.patch.object(eval_mod.run_model, "main", side_effect=fake_run_model),
                mock.patch.object(eval_mod.subprocess, "run", side_effect=spy_subproc),
                redirect_stdout(out_buf),
            ):
                rc = eval_mod.main(
                    [
                        "run",
                        "--root",
                        tmp,
                        "--engine",
                        "agy",
                        "--forge",
                        str(forge),
                        "--model",
                        "argon-test",
                        "--record",
                        "demo-label",
                    ]
                )

        self.assertEqual(rc, 0)
        self.assertIn("Totals (`demo-label`)", out_buf.getvalue())
        self.assertIn("$0.0200", out_buf.getvalue())
        self.assertTrue(recorded_git_calls)
        for cmd, env in recorded_git_calls:
            self.assertIn("GIT_CONFIG_GLOBAL", env)
            if "commit" in cmd:
                self.assertIn("commit.gpgsign=false", cmd)

    def test_run_writes_expected_prompt_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_mini_repo(root, copy_ref=False)
            forge = root / "forge"
            flib = forge / "skills" / "review" / "scripts" / "findings.py"
            flib.parent.mkdir(parents=True)
            flib.write_text("# stub\n", encoding="utf-8")

            def fake_run_model():
                argv = eval_mod.sys.argv
                out_p = Path(argv[argv.index("--out") + 1])
                doc = helpers.doc(helpers.finding(file="app/search.py", start=10, end=11, rule="CWE-89"))
                out_p.write_text(json.dumps(doc), encoding="utf-8")
                return 0

            with (
                mock.patch.object(eval_mod.run_model, "main", side_effect=fake_run_model),
                redirect_stdout(io.StringIO()),
            ):
                rc = eval_mod.main(
                    [
                        "run",
                        "--root",
                        tmp,
                        "--engine",
                        "claude",
                        "--forge",
                        str(forge),
                        "--cases",
                        "sqli-string-concat",
                        "--record",
                        "claude-smoke",
                    ]
                )
            self.assertEqual(rc, 0)
            meta = json.loads((root / "evals" / "recorded" / "claude-smoke" / "meta.json").read_text(encoding="utf-8"))
            expected_sha = hashlib.sha256((root / "prompts" / "review.md").read_bytes()).hexdigest()
            self.assertEqual(meta["prompt_sha256"], expected_sha)
            self.assertEqual(meta["engine"], "claude")

    def test_cli_error_paths_and_markdown_scorecard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_mini_repo(root, copy_ref=True)
            out = io.StringIO()
            with redirect_stdout(out):
                rc_md = eval_mod.main(["score", "--root", tmp, "--recorded", "reference"])
            self.assertEqual(rc_md, 0)
            self.assertIn("## Eval scorecard: reference", out.getvalue())

            with redirect_stdout(io.StringIO()):
                self.assertEqual(eval_mod.main(["lint", "--root", tmp, "--cases", "nonexistent"]), 1)
                self.assertEqual(eval_mod.main(["lint", "--root", str(root / "empty")]), 1)

            with redirect_stderr(io.StringIO()):
                self.assertEqual(eval_mod.main(["score", "--root", tmp, "--recorded", "missing-label"]), 1)
                self.assertEqual(eval_mod.main(["score", "--root", tmp, "--findings-dir", str(root / "nope")]), 1)
                self.assertEqual(eval_mod.main(["score", "--root", tmp, "--cases", "nonexistent"]), 1)
                self.assertEqual(
                    eval_mod.main(["run", "--root", tmp, "--engine", "agy", "--forge", str(root / "noforge")]),
                    1,
                )


if __name__ == "__main__":
    unittest.main()
