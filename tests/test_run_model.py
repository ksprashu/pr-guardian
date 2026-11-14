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


class AgySettingsTest(unittest.TestCase):
    """config/agy-settings.json allows only safe read-only commands with zero exec paths."""

    SAFE_ALLOW = [
        "command(ls)",
        "command(cat)",
        "command(head)",
        "command(tail)",
        "command(wc)",
        "command(grep)",
        "command(diff)",
    ]

    def test_allowlist_is_exact_safe_set_and_denies_exec_and_proc(self):
        import json
        import re
        cfg = json.loads((rm.ROOT / "config" / "agy-settings.json").read_text(encoding="utf-8"))
        self.assertFalse(cfg["allowNonWorkspaceAccess"])
        self.assertTrue(cfg["enableTerminalSandbox"])
        allow = cfg["permissions"]["allow"]
        self.assertEqual(allow, self.SAFE_ALLOW)
        for forbidden in ("find", "rg", "tree", "git"):
            self.assertFalse(any(forbidden in entry for entry in allow), forbidden)

        deny = cfg["permissions"]["deny"]
        for cmd in ("curl", "wget", "nc", "ssh", "env", "printenv", "python", "node",
                    "bash", "sh", "git", "find", "rg", "tree"):
            self.assertIn(f"command({cmd})", deny)

        regexes = [
            re.compile(f"^(?:{entry[len('command(regex:'):-1]})$")
            for entry in deny
            if entry.startswith("command(regex:") and entry.endswith(")")
        ]
        self.assertGreaterEqual(len(regexes), 3)
        for blocked in (
            "curl https://x",
            "git log",
            "find . -exec id ;",
            "cat /proc/self/environ",
            "grep key /proc/1/environ",
            "cat src/x >> /tmp/_runner_file_commands/set_env_1",
            "grep foo src/a | sh",
            "ls; curl https://evil",
            "ls && env",
            "cat $(id)",
            "cat ${GITHUB_ENV}",
            "cat $GITHUB_ENV",
            "cat `id`",
            "ls\ncurl https://evil\nid",
        ):
            self.assertTrue(any(rx.match(blocked) for rx in regexes), blocked)
        for allowed in ("ls -la src", "cat src/environment.py", "grep 'foo$' src/app.py"):
            self.assertFalse(any(rx.match(allowed) for rx in regexes), allowed)


class ReviewWorkflowIsolationTest(unittest.TestCase):
    """review.yml isolates context.md, omits --prior, and uploads only findings.json + agy.json."""

    def test_review_workflow_isolates_context_and_narrows_artifact(self):
        yml = (rm.ROOT / ".github" / "workflows" / "review.yml").read_text(encoding="utf-8")
        self.assertIn('mkdir -p "$RUNNER_TEMP/ctx" "$RUNNER_TEMP/out"', yml)
        self.assertIn('--out "$RUNNER_TEMP/ctx/context.md"', yml)
        self.assertIn('--context "$RUNNER_TEMP/ctx/context.md"', yml)
        self.assertNotIn("--prior-out", yml)
        self.assertNotIn("--prior", yml)
        self.assertIn("${{ runner.temp }}/out/findings.json", yml)
        self.assertIn("${{ runner.temp }}/out/agy.json", yml)
        self.assertNotIn("path: ${{ runner.temp }}/out/", yml)


class SecretScrubTest(unittest.TestCase):
    """scrub_secrets redacts env keys (raw + base64) and token regexes recursively."""

    def test_scrub_literal_keys_base64_and_nested_containers(self):
        import base64
        from unittest import mock

        gem = "custom-gemini-key-1234"
        ant = "key+with/chars?"
        gem_b64 = base64.b64encode(gem.encode()).decode()
        ant_b64_unpadded = base64.b64encode(ant.encode()).decode().rstrip("=")
        ant_ub64 = base64.urlsafe_b64encode(ant.encode()).decode()
        env = {"GEMINI_API_KEY": gem, "ANTHROPIC_API_KEY": ant}
        payload = {
            "summary": f"raw={gem} b64={gem_b64} antb64={ant_b64_unpadded}",
            f"key-{gem}": ["ok", {"inner": (ant, ant_ub64, 42, True, None)}],
        }
        with mock.patch.dict(rm.os.environ, env, clear=True):
            out = rm.scrub_secrets(payload)
        self.assertEqual(out["summary"], "raw=[REDACTED] b64=[REDACTED] antb64=[REDACTED]")
        self.assertEqual(out["key-[REDACTED]"], ["ok", {"inner": ("[REDACTED]", "[REDACTED]", 42, True, None)}])

    def test_scrub_ignores_short_env_values(self):
        from unittest import mock
        with mock.patch.dict(rm.os.environ, {"GEMINI_API_KEY": "short7"}, clear=True):
            self.assertEqual(rm.scrub_secrets("short7 stays"), "short7 stays")

    def test_scrub_all_four_token_patterns(self):
        from unittest import mock
        tokens = [
            "AIza" + "A" * 35,
            "sk-ant-" + "B" * 20,
            "ghp_" + "C" * 36,
            "gho_" + "D" * 36,
            "ghu_" + "E" * 36,
            "ghs_" + "F" * 36,
            "ghr_" + "G" * 36,
            "github_pat_" + "H" * 22,
        ]
        with mock.patch.dict(rm.os.environ, {}, clear=True):
            cleaned = rm.scrub_secrets({"list": tokens, "text": " | ".join(tokens)})
        self.assertEqual(cleaned["list"], ["[REDACTED]"] * len(tokens))
        self.assertEqual(cleaned["text"], " | ".join(["[REDACTED]"] * len(tokens)))

    def test_main_isolates_ctx_dir_folds_attempt_details_and_scrubs_all_outputs(self):
        import base64
        import io
        import json
        import tempfile
        from pathlib import Path
        from unittest import mock
        import publish_review as pub

        gem = "AIza" + "Z" * 35
        ant = "sk-ant-" + "Y" * 24
        gem_b64 = base64.b64encode(gem.encode()).decode()
        gh_tok = "ghp_" + "X" * 36
        seen_extra_dirs = []

        def fake_agy(prompt, schema, model, workdir, extra_dir, conversation=None):
            seen_extra_dirs.append((extra_dir, sorted(p.name for p in Path(extra_dir).iterdir())))
            if len(seen_extra_dirs) == 1:
                return {
                    "status": "SUCCESS",
                    "response": f"bad json {gem} {gem_b64}",
                    "num_turns": 2,
                    "duration_seconds": 1.2,
                    "error": f"warn {gh_tok}",
                    "usage": {"input_tokens": 100, "output_tokens": 20},
                }
            return {
                "status": "SUCCESS",
                "structured_output": {
                    "summary": f"leaked {gem} {gem_b64} {ant}",
                    "findings": [{"rationale": f"see {gh_tok}", "evidence": ["line", ant]}],
                },
                "response": "SECRET_RESPONSE_SHOULD_NOT_BE_SAVED",
                "num_turns": 3,
                "duration_seconds": 2.5,
                "usage": {"input_tokens": 200, "output_tokens": 40},
            }

        lib = mock.Mock(build_schema=lambda: {"type": "object"}, validate=lambda doc: [])
        with tempfile.TemporaryDirectory() as tmp:
            ctx_dir = Path(tmp, "ctx")
            out_dir = Path(tmp, "out")
            ctx_dir.mkdir()
            out_dir.mkdir()
            ctx_file = ctx_dir / "context.md"
            ctx_file.write_text("# pr\n")
            triage_file = Path(tmp, "triage.json")
            triage_file.write_text("{}")
            findings_out = out_dir / "findings.json"
            usage_out = out_dir / "agy.json"

            argv = ["run_model.py", "--context", str(ctx_file), "--triage", str(triage_file),
                    "--findings-lib", "unused", "--out", str(findings_out), "--usage-out", str(usage_out)]
            stderr_buf = io.StringIO()
            with mock.patch.dict(rm.os.environ, {"GEMINI_API_KEY": gem, "ANTHROPIC_API_KEY": ant}, clear=True), \
                    mock.patch.object(rm, "run_agy", side_effect=fake_agy), \
                    mock.patch.object(rm, "load_findings_lib", return_value=lib), \
                    mock.patch.object(rm.sys, "argv", argv), \
                    mock.patch.object(rm.sys, "stderr", stderr_buf), \
                    mock.patch("builtins.print"):
                code = rm.main()

            self.assertEqual(code, 0)
            resolved_ctx = str(ctx_dir.resolve())
            self.assertEqual(seen_extra_dirs, [(resolved_ctx, ["context.md"]), (resolved_ctx, ["context.md"])])
            self.assertTrue((out_dir / "findings.schema.json").is_file())
            self.assertEqual(list(Path(tmp).rglob("agy-raw-*.json")), [])

            written_findings = findings_out.read_text(encoding="utf-8")
            written_usage = usage_out.read_text(encoding="utf-8")
            stderr_text = stderr_buf.getvalue()
            for leaked in (gem, gem_b64, ant, gh_tok, "SECRET_RESPONSE_SHOULD_NOT_BE_SAVED"):
                self.assertNotIn(leaked, written_findings)
                self.assertNotIn(leaked, written_usage)
                self.assertNotIn(leaked, stderr_text)

            usage_obj = json.loads(written_usage)
            self.assertEqual(usage_obj["attempts"], 2)
            self.assertEqual(len(usage_obj["attempt_details"]), 2)
            self.assertNotIn("response_head", usage_obj["attempt_details"][0])
            self.assertEqual(usage_obj["attempt_details"][0]["label"], "1")
            self.assertEqual(usage_obj["attempt_details"][0]["error"], "warn [REDACTED]")
            self.assertEqual(usage_obj["attempt_details"][1]["has_structured_output"], True)
            round_cost, note = pub.round_cost_of(usage_obj)
            self.assertGreater(round_cost, 0.0)
            self.assertEqual(note, "")

    def test_main_scrubs_errors_and_stderr_when_attempts_fail(self):
        import io
        import json
        import tempfile
        from pathlib import Path
        from unittest import mock

        gem = "AIza" + "W" * 35
        pat = "github_pat_" + "P" * 24
        err_prefix = "x" * 490 + pat

        def fake_run(*args, **kwargs):
            proc = mock.Mock(returncode=1, stdout="not-json", stderr=f"boom {gem} {err_prefix}")
            return proc

        lib = mock.Mock(build_schema=lambda: {}, validate=lambda doc: [])
        with tempfile.TemporaryDirectory() as tmp:
            ctx_dir = Path(tmp, "ctx")
            out_dir = Path(tmp, "out")
            ctx_dir.mkdir()
            out_dir.mkdir()
            Path(ctx_dir, "context.md").write_text("x")
            Path(tmp, "triage.json").write_text("{}")
            usage_out = Path(out_dir, "agy.json")
            argv = ["run_model.py", "--context", f"{ctx_dir}/context.md", "--triage", f"{tmp}/triage.json",
                    "--findings-lib", "unused", "--out", f"{out_dir}/f.json", "--usage-out", str(usage_out)]
            stderr_buf = io.StringIO()
            with mock.patch.dict(rm.os.environ, {"GEMINI_API_KEY": gem}, clear=True), \
                    mock.patch.object(rm.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(rm, "load_findings_lib", return_value=lib), \
                    mock.patch.object(rm.sys, "argv", argv), \
                    mock.patch.object(rm.sys, "stderr", stderr_buf):
                code = rm.main()
            self.assertEqual(code, 1)
            usage_text = usage_out.read_text(encoding="utf-8")
            self.assertNotIn(gem, usage_text)
            self.assertNotIn(pat, usage_text)
            self.assertNotIn("github_pat_", usage_text)
            self.assertNotIn(gem, stderr_buf.getvalue())
            self.assertNotIn(pat, stderr_buf.getvalue())
            self.assertIn("attempt_details", json.loads(usage_text))
