"""Workflow and supply-chain wiring checks added by Track 6 (#25, #31, #38, #41, #42, #47, governor env)."""
import re
import unittest
from pathlib import Path

from tests.test_workflows import (  # noqa: F401
    ROOT,
    WORKFLOW_FILES,
    _job_block,
    _step_env,
    _tokens,
    eval_if,
    logical_lines,
    yaml_get,
)

REVIEW = ROOT / ".github" / "workflows" / "review.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
GOVERNOR = ROOT / ".github" / "workflows" / "governor.yml"


def _steps(job_block: str) -> list[str]:
    m = re.search(r"(?m)^\s{4}steps:\s*\n(.*)$", job_block, re.S)
    if not m:
        return []
    return re.split(r"(?m)^(?=\s{6}- )", m.group(1))


def _mapping_keys(block: str, section: str) -> dict[str, str]:
    m = re.search(rf"(?m)^(\s+){re.escape(section)}:\s*\n(.*?)(?=^\1[A-Za-z_][\w-]*:|\Z)", block, re.S)
    if not m:
        return {}
    base_indent = len(m.group(1))
    out: dict[str, str] = {}
    for line in m.group(2).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= base_indent:
            break
        kv = re.match(r"^\s+([A-Za-z_][\w-]*):\s*(.*?)\s*$", line)
        if kv:
            val = kv.group(2).split("#", 1)[0].strip()
            out[kv.group(1)] = val
    return out


class Track6WorkflowWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.review = REVIEW.read_text(encoding="utf-8")
        cls.ci = CI.read_text(encoding="utf-8")
        cls.dependabot = DEPENDABOT.read_text(encoding="utf-8")
        cls.governor = GOVERNOR.read_text(encoding="utf-8")

    def test_scan_artifact_download_resilience(self):
        review_steps = _steps(_job_block(self.review, "review"))
        scan_dl = [s for s in review_steps if "download-artifact@" in s and "prg-scan" in s]
        self.assertEqual(len(scan_dl), 1)
        self.assertRegex(scan_dl[0], r"(?m)^\s+continue-on-error:\s+true\b")
        self.assertRegex(scan_dl[0], r"(?m)^\s+id:\s+scan_artifact\b")

        publish_steps = _steps(_job_block(self.review, "publish"))
        pub_dl = [s for s in publish_steps if "download-artifact@" in s and "prg-review" in s]
        self.assertEqual(len(pub_dl), 1)
        self.assertNotIn("continue-on-error", pub_dl[0])

    def test_announce_shape_and_isolation(self):
        self.assertEqual(yaml_get(self.review, "jobs", "announce", "needs"), "route")
        cond = yaml_get(self.review, "jobs", "announce", "if")
        mk_ctx = lambda act: {"needs": {"route": {"result": "success", "outputs": {"action": act}}}}
        self.assertTrue(eval_if(cond, mk_ctx("review")))
        self.assertFalse(eval_if(cond, mk_ctx("verdict")))
        self.assertFalse(eval_if(cond, mk_ctx("skip")))

        block = _job_block(self.review, "announce")
        perms = _mapping_keys(block, "permissions")
        self.assertEqual(perms, {"pull-requests": "read", "statuses": "write"})
        self.assertNotIn("actions/checkout", block)
        self.assertNotIn("secrets.", block)
        self.assertNotIn("python3", block)

    def test_pending_status_only(self):
        states = re.findall(r"-f\s+state=([A-Za-z_]+)", self.review)
        self.assertEqual(states, ["pending"])

    def test_verdict_needs_ordering(self):
        needs = yaml_get(self.review, "jobs", "verdict", "needs")
        for dep in ("announce", "route", "scan", "review", "publish"):
            self.assertIn(dep, needs)

    def test_scan_stays_read_only(self):
        perms = _mapping_keys(_job_block(self.review, "scan"), "permissions")
        self.assertEqual(perms, {"contents": "read", "pull-requests": "read"})

    def test_skip_gating_on_install_and_review(self):
        review_block = _job_block(self.review, "review")
        steps = _steps(review_block)
        install_steps = [s for s in steps if "Install Antigravity CLI" in s or "Install Claude Code" in s]
        self.assertEqual(len(install_steps), 2)
        for step in install_steps:
            self.assertIn("if: steps.context.outputs.skip_model != 'true'", step)

        self.assertEqual(_step_env(review_block, "SKIP_MODEL"), "${{ steps.context.outputs.skip_model }}")
        self.assertIn(".skip_model == true", self.review)
        self.assertIn("--dependabot-secrets", review_block)

    def test_review_preflight_allows_anthropic_only_and_premodel_escalation(self):
        import json
        import os
        import subprocess
        import tempfile

        review_block = _job_block(self.review, "review")
        review_steps = [s for s in _steps(review_block) if "run_model.py" in s]
        self.assertEqual(len(review_steps), 1)
        m = re.search(r"(?m)^\s+run:\s*\|\n(.*)$", review_steps[0], re.S)
        self.assertIsNotNone(m)
        script = "\n".join(line[10:] if line.startswith(" " * 10) else line for line in m.group(1).splitlines())

        def run_preflight(triage: dict, *, gemini: str = "", anthropic: str = "",
                          skip: str = "false", actor: str = "dev"):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                rtemp = root / "rt"
                bin_dir = root / "bin"
                (rtemp / "ctx").mkdir(parents=True)
                (rtemp / "out").mkdir(parents=True)
                (root / ".prg" / "scripts").mkdir(parents=True)
                (root / ".forge" / "skills" / "review" / "scripts").mkdir(parents=True)
                (root / "src").mkdir()
                bin_dir.mkdir()
                (rtemp / "triage.json").write_text(json.dumps(triage), encoding="utf-8")
                agy_log = root / "agy.log"
                rm_log = root / "rm.log"
                agy_bin = bin_dir / "agy"
                agy_bin.write_text(f"#!/usr/bin/env bash\necho \"$*\" >> {str(agy_log)!r}\n", encoding="utf-8")
                agy_bin.chmod(0o755)
                (root / ".prg" / "scripts" / "run_model.py").write_text(
                    f"import pathlib, sys\npathlib.Path({str(rm_log)!r}).write_text(' '.join(sys.argv[1:]))\n",
                    encoding="utf-8",
                )
                env = {
                    "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
                    "RUNNER_TEMP": str(rtemp),
                    "SKIP_MODEL": skip,
                    "GEMINI_API_KEY": gemini,
                    "ANTHROPIC_API_KEY": anthropic,
                    "GITHUB_ACTOR": actor,
                }
                proc = subprocess.run(["bash", "-eo", "pipefail", "-c", script],
                                      cwd=str(root), env=env, capture_output=True, text=True, check=False)
                return (
                    proc.returncode,
                    proc.stdout + proc.stderr,
                    agy_log.read_text(encoding="utf-8") if agy_log.exists() else "",
                    rm_log.exists(),
                )

        # 1. Missing both keys on normal review fails closed (normal actor & Dependabot).
        rc, out, agy_calls, rm_ran = run_preflight({"skip_model": False})
        self.assertEqual((rc, agy_calls, rm_ran), (1, "", False))
        self.assertIn("ANTHROPIC_API_KEY", out)

        rc_dep, out_dep, _, rm_dep = run_preflight({"skip_model": False}, actor="dependabot[bot]")
        self.assertEqual((rc_dep, rm_dep), (1, False))
        self.assertIn("--dependabot-secrets", out_dep)

        # 2. Whitespace-only or boolean escalate_reason still requires an API key.
        for non_esc in ({"escalate_reason": "   "}, {"escalate_reason": True}):
            rc_ws, _, _, rm_ws = run_preflight(non_esc)
            self.assertEqual((rc_ws, rm_ws), (1, False), non_esc)

        # 3. ANTHROPIC_API_KEY-only passes preflight without calling `agy models`.
        rc_cc, _, agy_cc, rm_cc = run_preflight({"skip_model": False}, anthropic="sk-ant-test")
        self.assertEqual((rc_cc, agy_cc, rm_cc), (0, "", True))

        # 4. Pre-model triage escalations reach run_model.py without API keys or `agy models`.
        for esc_triage in (
            {"skip_model": False, "escalate_reason": "PR size limit exceeded"},
            {"skip_model": False, "size_exceeded": True},
            {"skip_model": False, "cost_exceeded": True},
        ):
            rc_esc, _, agy_esc, rm_esc = run_preflight(esc_triage, actor="dependabot[bot]")
            self.assertEqual((rc_esc, agy_esc, rm_esc), (0, "", True), esc_triage)

        # 5. GEMINI_API_KEY normal run executes `agy models` preflight and reaches run_model.py.
        rc_gem, _, agy_gem, rm_gem = run_preflight({"skip_model": False}, gemini="g-key")
        self.assertEqual((rc_gem, agy_gem.strip(), rm_gem), (0, "models", True))

    def test_no_pipe_to_shell_in_any_workflow(self):
        for wf in WORKFLOW_FILES:
            text = wf.read_text(encoding="utf-8")
            self.assertIsNone(
                re.search(r"curl[^\n]*\|\s*(ba)?sh\b", text),
                msg=f"pipe-to-shell found in {wf}",
            )
        self.assertIn(".prg/scripts/install_agy.sh", self.review)

    def test_step_summaries_cannot_fail_jobs(self):
        found = 0
        for job_match in re.finditer(r"(?m)^  ([A-Za-z_][\w-]*):\n", self.review):
            job_name = job_match.group(1)
            for step in _steps(_job_block(self.review, job_name)):
                if "step_summary.py" in step:
                    found += 1
                    self.assertRegex(step, r"(?m)^\s+continue-on-error:\s+true\b", msg=f"{job_name}: {step}")
                    self.assertRegex(step, r"(?m)^\s+if:\s+\$\{\{\s*!cancelled\(\)\s*\}\}", msg=f"{job_name}: {step}")
        self.assertGreaterEqual(found, 5)

    def test_tee_steps_use_bash_pipefail(self):
        for wf in WORKFLOW_FILES:
            text = wf.read_text(encoding="utf-8")
            for job_match in re.finditer(r"(?m)^  ([A-Za-z_][\w-]*):\n", text):
                job_name = job_match.group(1)
                for step in _steps(_job_block(text, job_name)):
                    if re.search(r"\|\s*tee\b", step):
                        self.assertRegex(
                            step,
                            r"(?m)^\s+shell:\s+bash\b",
                            msg=f"{wf.name}:{job_name} pipes to tee without shell: bash",
                        )

    def test_ci_gates_present(self):
        for needle in ("--fail-under=", "scripts/check_pins.py", "scripts/eval.py lint", "--require-hashes"):
            self.assertIn(needle, self.ci)

    def test_dependabot_three_ecosystems_with_cooldown(self):
        chunks = re.split(r"(?m)^\s*-\s+package-ecosystem:\s+", self.dependabot)[1:]
        self.assertEqual(len(chunks), 3)
        ecosystems = [c.splitlines()[0].strip() for c in chunks]
        self.assertEqual(ecosystems, ["github-actions", "npm", "pip"])
        for eco, chunk in zip(ecosystems, chunks):
            self.assertRegex(chunk, r"(?m)^\s+cooldown:\s*\n", msg=f"{eco} missing cooldown")

    def test_governor_env_wiring(self):
        reconcile = _job_block(self.governor, "reconcile")
        self.assertEqual(_step_env(reconcile, "ANTHROPIC_API_KEY"), "${{ secrets.ANTHROPIC_API_KEY }}")
        self.assertEqual(_step_env(reconcile, "PRG_ROTATE_SECRETS"), "${{ inputs.rotate_secrets || false }}")
        self.assertEqual(_step_env(reconcile, "PRG_PROMOTE"), "${{ inputs.promote || false }}")
        self.assertEqual(_step_env(reconcile, "PRG_STATS"), "${{ inputs.stats || vars.PRG_STATS || false }}")
        self.assertEqual(_step_env(reconcile, "PRG_CANARY"), "${{ vars.PRG_CANARY }}")
        self.assertEqual(_step_env(reconcile, "PRG_EXEMPT"), "${{ vars.PRG_EXEMPT }}")
        self.assertEqual(_step_env(reconcile, "PRG_DEPENDABOT_SECRETS"), "${{ vars.PRG_DEPENDABOT_SECRETS || false }}")
        for inp in ("rotate_secrets", "promote", "stats"):
            self.assertRegex(self.governor, rf"(?m)^\s+{inp}:\s*$")


if __name__ == "__main__":
    unittest.main()
