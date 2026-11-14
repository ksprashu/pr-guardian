import unittest

from tests.helpers import *  # noqa: F401,F403
import run_model as rm


class ExtractTest(unittest.TestCase):
    def test_structured_output_wins(self):
        self.assertEqual(rm.extract({"structured_output": {"a": 1}, "response": "x"}), {"a": 1})

    def test_fenced_and_prose_wrapped_json(self):
        self.assertEqual(rm.extract({"response": "```json\n{\"a\": 3}\n```"}), {"a": 3})
        self.assertEqual(rm.extract({"response": "Here it is:\n{\"a\": 2}\nDone."}), {"a": 2})

    def test_empty_response_is_a_clear_error(self):
        with self.assertRaisesRegex(ValueError, "empty response"):
            rm.extract({"response": ""})


class FinalizeTest(unittest.TestCase):
    """An empty SUCCESS turn is finished in the same conversation, not re-run from scratch."""

    def run_main(self, results, tmp):
        from pathlib import Path
        from unittest import mock
        calls = []

        def fake_run(prompt, schema, model, workdir, extra_dir, conversation=None):
            calls.append(conversation)
            return results.pop(0)

        lib = mock.Mock(build_schema=lambda: {}, validate=lambda doc: [])
        Path(tmp, "ctx.md").write_text("x")
        Path(tmp, "triage.json").write_text("{}")
        argv = ["run_model.py", "--context", f"{tmp}/ctx.md", "--triage", f"{tmp}/triage.json",
                "--findings-lib", "unused", "--out", f"{tmp}/f.json", "--usage-out", f"{tmp}/u.json"]
        with mock.patch.object(rm, "run_agy", side_effect=fake_run), \
                mock.patch.object(rm, "load_findings_lib", return_value=lib), \
                mock.patch.object(rm.sys, "argv", argv), mock.patch("builtins.print"):
            code = rm.main()
        return code, calls

    def test_empty_turn_is_finalized_in_same_conversation(self):
        import tempfile
        doc = {"findings": []}
        with tempfile.TemporaryDirectory() as tmp:
            code, calls = self.run_main([{"status": "SUCCESS", "response": "", "conversation_id": "c1"},
                                         {"status": "SUCCESS", "structured_output": doc}], tmp)
        self.assertEqual((code, calls), (0, [None, "c1"]))

    def test_non_empty_turn_is_not_finalized(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            code, calls = self.run_main([{"status": "SUCCESS", "structured_output": {"findings": []},
                                          "conversation_id": "c1"}], tmp)
        self.assertEqual((code, calls), (0, [None]))


class RateLimitTest(unittest.TestCase):
    def test_quota_exhaustion_waits_but_spending_cap_does_not(self):
        self.assertTrue(rm.is_rate_limited("Error 429, Message: Resource has been exhausted, Status: RESOURCE_EXHAUSTED"))
        self.assertFalse(rm.is_rate_limited(
            "Error 429, Message: Your billing account has exceeded its monthly spending cap, Status: RESOURCE_EXHAUSTED"))
        self.assertFalse(rm.is_rate_limited("agy ERROR (exit 3): authentication failed"))


class ClaudeFallbackTest(unittest.TestCase):
    """A Gemini rate limit hands the retry to Claude Code when ANTHROPIC_API_KEY is set."""

    def run_main(self, tmp, env, *, which="/usr/bin/claude", agy_side_effect=None,
                 claude_side_effect=None, validate_side_effect=None):
        import json
        from pathlib import Path
        from unittest import mock
        quota = RuntimeError("agy ERROR (exit 3): Error 429, Status: RESOURCE_EXHAUSTED")
        claude = {"status": "SUCCESS", "structured_output": {"findings": []},
                  "usage": {"input_tokens": 10, "output_tokens": 5}, "cost_usd": 0.42}
        lib = mock.Mock(build_schema=lambda: {},
                        validate=validate_side_effect or (lambda doc: []))
        Path(tmp, "ctx.md").write_text("x")
        Path(tmp, "triage.json").write_text("{}")
        argv = ["run_model.py", "--context", f"{tmp}/ctx.md", "--triage", f"{tmp}/triage.json",
                "--findings-lib", "unused", "--out", f"{tmp}/f.json", "--usage-out", f"{tmp}/u.json"]
        with mock.patch.dict(rm.os.environ, env, clear=True), \
                mock.patch.object(rm.shutil, "which", return_value=which), \
                mock.patch.object(rm, "run_agy", side_effect=agy_side_effect or [quota, quota]) as agy, \
                mock.patch.object(rm, "run_claude", side_effect=claude_side_effect or [claude]) as cc, \
                mock.patch.object(rm.time, "sleep") as sleep, \
                mock.patch.object(rm, "load_findings_lib", return_value=lib), \
                mock.patch.object(rm.sys, "argv", argv), mock.patch("builtins.print"):
            code = rm.main()
        return code, agy, cc, sleep.call_count, json.loads(Path(tmp, "u.json").read_text())

    def test_rate_limit_falls_back_to_claude_with_key(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            code, agy, cc, slept, usage = self.run_main(tmp, {"ANTHROPIC_API_KEY": "k"})
        self.assertEqual((code, agy.call_count, cc.call_count, slept), (0, 1, 1, 0))
        self.assertEqual((usage["engine"], usage["cost_usd"]), ("claude", 0.42))

    def test_rate_limit_without_key_waits_and_retries_gemini(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            code, agy, cc, slept, usage = self.run_main(tmp, {})
        self.assertEqual((code, agy.call_count, cc.call_count, slept), (1, 2, 0, 1))
        self.assertEqual(usage["engine"], "agy")
        self.assertNotIn("failed validation", agy.call_args_list[1].args[0])

    def test_missing_claude_binary_falls_back_to_gemini_wait(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            code, agy, cc, slept, usage = self.run_main(tmp, {"ANTHROPIC_API_KEY": "k"}, which=None)
        self.assertEqual((code, agy.call_count, cc.call_count, slept), (1, 2, 0, 1))
        self.assertEqual(usage["engine"], "agy")

    def test_claude_fallback_gets_its_own_validation_retry_and_clean_prompt(self):
        import tempfile
        quota = RuntimeError("agy ERROR (exit 3): Error 429, Status: RESOURCE_EXHAUSTED")
        agy_bad = {"status": "SUCCESS", "structured_output": {"findings": []}}
        cc_bad = {"status": "SUCCESS", "structured_output": {"findings": []}, "cost_usd": 0.2}
        cc_good = {"status": "SUCCESS", "structured_output": {"findings": []}, "cost_usd": 0.3}
        validations = iter([["agy-schema-err"], ["claude-schema-err"], []])
        with tempfile.TemporaryDirectory() as tmp:
            code, agy, cc, slept, usage = self.run_main(
                tmp, {"ANTHROPIC_API_KEY": "k"},
                agy_side_effect=[agy_bad, quota],
                claude_side_effect=[cc_bad, cc_good],
                validate_side_effect=lambda doc: next(validations),
            )
        self.assertEqual((code, agy.call_count, cc.call_count, slept), (0, 2, 2, 0))
        self.assertNotIn("agy-schema-err", cc.call_args_list[0].args[0])
        self.assertIn("claude-schema-err", cc.call_args_list[1].args[0])
        self.assertNotIn("agy-schema-err", cc.call_args_list[1].args[0])
        self.assertEqual(usage["cost_usd"], 0.5)

    def test_finalize_rate_limit_falls_back_to_claude(self):
        import tempfile
        empty = {"status": "SUCCESS", "response": "", "conversation_id": "c1"}
        quota = RuntimeError("agy ERROR (exit 3): Error 429, Status: RESOURCE_EXHAUSTED")
        with tempfile.TemporaryDirectory() as tmp:
            code, agy, cc, slept, usage = self.run_main(
                tmp, {"ANTHROPIC_API_KEY": "k"}, agy_side_effect=[empty, quota]
            )
        self.assertEqual((code, agy.call_count, cc.call_count, slept), (0, 2, 1, 0))
        self.assertEqual(usage["engine"], "claude")

    def test_claude_result_is_normalised_to_agy_shape(self):
        import json
        from unittest import mock
        raw = {"is_error": False, "result": "{}", "structured_output": {"findings": []}, "num_turns": 3,
               "duration_ms": 2000, "total_cost_usd": 0.5,
               "usage": {"input_tokens": 2, "cache_read_input_tokens": 100, "cache_creation_input_tokens": 50,
                         "output_tokens": 7}}
        proc = mock.Mock(returncode=0, stdout=json.dumps(raw), stderr="")
        with mock.patch.object(rm.subprocess, "run", return_value=proc) as run, \
                mock.patch.object(rm.Path, "read_text", return_value="{}"):
            out = rm.run_claude("p", "s.json", "claude-opus-5-5", ".", "/ctx")
        cmd = run.call_args.args[0]
        self.assertIn("--bare", cmd)
        self.assertLess(cmd.index("--bare"), cmd.index("--add-dir"))
        self.assertIn("--restricted", cmd)
        self.assertIn("--strict-mcp-config", cmd)
        self.assertEqual(cmd[cmd.index("--tools") + 1], "Read,Grep,Glob")
        self.assertEqual(cmd[cmd.index("--add-dir") + 1:cmd.index("--add-dir") + 3],
                         ["/ctx", str(rm.CLAUDE_SKILLS)])
        self.assertIn("review/SKILL.md", cmd[cmd.index("-p") + 1])
        self.assertEqual(out["status"], "SUCCESS")
        self.assertEqual(out["usage"], {"input_tokens": 152, "output_tokens": 7})
        self.assertEqual(out["cost_usd"], 0.5)

    def test_claude_error_raises_from_result_or_errors_or_stderr(self):
        import json
        from unittest import mock
        for payload, stderr, expected in [
            ({"is_error": True, "result": "overloaded"}, "", "overloaded"),
            ({"is_error": True, "errors": ["bad schema"]}, "", "bad schema"),
            ({"is_error": True}, "fatal stderr", "fatal stderr"),
        ]:
            proc = mock.Mock(returncode=1, stdout=json.dumps(payload), stderr=stderr)
            with mock.patch.object(rm.subprocess, "run", return_value=proc), \
                    mock.patch.object(rm.Path, "read_text", return_value="{}"):
                with self.assertRaisesRegex(RuntimeError, expected):
                    rm.run_claude("p", "s.json", "claude-opus-5-5", ".", "/ctx")


class EngineEnvTest(unittest.TestCase):
    """Model subprocesses get only safe passlist vars and their own engine API key."""

    SAFE_ENV = {
        "PATH": "/usr/bin",
        "HOME": "/home/runner",
        "USER": "runner",
        "LOGNAME": "runner",
        "SHELL": "/bin/bash",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LC_CTYPE": "C.UTF-8",
        "TZ": "UTC",
        "TMPDIR": "/tmp",
        "TERM": "xterm-256color",
        "HTTPS_PROXY": "http://proxy:8080",
        "HTTP_PROXY": "http://proxy:8080",
        "NO_PROXY": "localhost",
        "SSL_CERT_FILE": "/etc/ssl/cert.pem",
        "SSL_CERT_DIR": "/etc/ssl/certs",
        "REQUESTS_CA_BUNDLE": "/etc/ssl/cert.pem",
        "NODE_EXTRA_CA_CERTS": "/etc/ssl/extra.pem",
        "XDG_CONFIG_HOME": "/home/runner/.config",
        "XDG_CACHE_HOME": "/home/runner/.cache",
        "XDG_DATA_HOME": "/home/runner/.local/share",
        "XDG_STATE_HOME": "/home/runner/.local/state",
        "XDG_RUNTIME_DIR": "/run/user/1000",
    }
    SECRET_ENV = {
        "GEMINI_API_KEY": "gem-secret",
        "ANTHROPIC_API_KEY": "ant-secret",
        "ANTHROPIC_AUTH_TOKEN": "ant-auth-secret",
        "ANTHROPIC_BASE_URL": "https://evil.example",
        "CLAUDE_CODE_OAUTH_TOKEN": "cc-oauth-secret",
        "CLAUDE_CONFIG_DIR": "/tmp/evil-claude",
        "GOOGLE_API_KEY": "goog-secret",
        "GITHUB_TOKEN": "ghs_secret",
        "GITHUB_ENV": "/tmp/_runner_file_commands/set_env",
        "GITHUB_PATH": "/tmp/_runner_file_commands/add_path",
        "GITHUB_OUTPUT": "/tmp/_runner_file_commands/set_output",
        "GH_TOKEN": "ghp_secret",
        "ACTIONS_RUNTIME_TOKEN": "art-secret",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-secret",
        "RUNNER_TEMP": "/tmp/runner",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "NODE_OPTIONS": "--require /tmp/evil.js",
        "LD_PRELOAD": "/tmp/evil.so",
        "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
        "PYTHONPATH": "/tmp/evil_py",
        "PYTHONSTARTUP": "/tmp/evil_startup.py",
        "BASH_ENV": "/tmp/evil_bash.sh",
        "ENV": "/tmp/evil_sh.sh",
        "GIT_SSH_COMMAND": "sh -c evil",
        "XDG_EVIL_TOKEN": "ghp_xdg_evil",
    }

    def test_engine_env_agy_isolates_keys_and_secrets(self):
        from unittest import mock
        full = {**self.SAFE_ENV, **self.SECRET_ENV, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"}
        with mock.patch.dict(rm.os.environ, full, clear=True):
            env = rm._engine_env("agy")
            env["MUTATED"] = "yes"
            fresh = rm._engine_env("agy")
        self.assertEqual(fresh, {**self.SAFE_ENV, "GEMINI_API_KEY": "gem-secret"})
        self.assertNotIn("XDG_EVIL_TOKEN", fresh)
        self.assertNotIn("MUTATED", rm.os.environ)

        with mock.patch.dict(rm.os.environ, self.SAFE_ENV, clear=True):
            self.assertEqual(rm._engine_env("agy"), self.SAFE_ENV)

    def test_engine_env_claude_isolates_keys_and_forces_nonessential_off(self):
        from unittest import mock
        full = {**self.SAFE_ENV, **self.SECRET_ENV, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "0"}
        with mock.patch.dict(rm.os.environ, full, clear=True):
            env = rm._engine_env("claude")
        self.assertEqual(env, {
            **self.SAFE_ENV,
            "ANTHROPIC_API_KEY": "ant-secret",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        })
        self.assertNotIn("XDG_EVIL_TOKEN", env)

        with mock.patch.dict(rm.os.environ, self.SAFE_ENV, clear=True):
            self.assertEqual(rm._engine_env("claude"), {
                **self.SAFE_ENV,
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            })

    def test_engine_env_rejects_unknown_engine(self):
        for bad in ("unknown", "", "codex"):
            with self.assertRaisesRegex(ValueError, f"unknown engine: {bad}"):
                rm._engine_env(bad)

    def test_run_agy_passes_filtered_env_to_subprocess(self):
        import json
        from unittest import mock
        full = {**self.SAFE_ENV, **self.SECRET_ENV}
        proc = mock.Mock(returncode=0, stdout=json.dumps({"status": "SUCCESS", "structured_output": {"findings": []}}),
                         stderr="")
        with mock.patch.dict(rm.os.environ, full, clear=True), \
                mock.patch.object(rm.subprocess, "run", return_value=proc) as run:
            rm.run_agy("p", "s.json", "gemini-4-argon-high", ".", "/ctx")
        sent = run.call_args.kwargs["env"]
        self.assertIsNotNone(sent)
        self.assertEqual(sent, {**self.SAFE_ENV, "GEMINI_API_KEY": "gem-secret"})
        for prefix in ("ANTHROPIC_", "GOOGLE_", "CLAUDE_", "GITHUB_", "GH_", "ACTIONS_", "RUNNER_"):
            self.assertFalse(any(k.startswith(prefix) for k in sent), prefix)

    def test_run_claude_passes_filtered_env_and_bare_to_subprocess(self):
        import json
        from unittest import mock
        full = {**self.SAFE_ENV, **self.SECRET_ENV}
        proc = mock.Mock(returncode=0, stdout=json.dumps({"is_error": False, "result": "{}"}), stderr="")
        with mock.patch.dict(rm.os.environ, full, clear=True), \
                mock.patch.object(rm.subprocess, "run", return_value=proc) as run, \
                mock.patch.object(rm.Path, "read_text", return_value="{}"):
            rm.run_claude("p", "s.json", "claude-opus-5-5", ".", "/ctx")
        cmd = run.call_args.args[0]
        self.assertIn("--bare", cmd)
        self.assertLess(cmd.index("--bare"), cmd.index("--add-dir"))
        sent = run.call_args.kwargs["env"]
        self.assertIsNotNone(sent)
        self.assertEqual(sent, {
            **self.SAFE_ENV,
            "ANTHROPIC_API_KEY": "ant-secret",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        })
        for prefix in ("GEMINI_", "GOOGLE_", "GITHUB_", "GH_", "ACTIONS_", "RUNNER_"):
            self.assertFalse(any(k.startswith(prefix) for k in sent), prefix)
