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


# --- Track 4: Configurable engine chain, deadline/cost hardening & verifier ---

_FINDING_REQUIRED_KEYS = {
    "id", "severity", "axis", "rule", "title", "file", "start_line",
    "end_line", "rationale", "evidence", "suggestion", "references",
    "confidence", "status", "prior_id", "security_verdict",
}
_DOC_REQUIRED_KEYS = {
    "schema_version", "producer", "mode", "summary", "inspected",
    "not_inspected", "findings",
}
_AXES = frozenset({
    "scope-architecture", "correctness", "security", "reliability",
    "performance", "data-integrity", "tests", "observability", "style",
})
_SEVERITIES = frozenset({"P0", "P1", "P2", "P3", "nit"})
_STATUSES = frozenset({"new", "still_open", "reopened", "fixed", "accepted_pushback"})
_CONFIDENCE = frozenset({"high", "medium", "low"})
_SECURITY_VERDICTS = frozenset({"confirmed", "needs_validation", "n/a"})


def _strict_findings_validate(doc):
    """Exact stdlib mirror of forge findings.py schema + semantic rules for CI."""
    import re
    from pathlib import Path
    errors = []
    if not isinstance(doc, dict):
        return ["$: expected object"]
    for key in sorted(_DOC_REQUIRED_KEYS):
        if key not in doc:
            errors.append(f"$: missing {key}")
    for key in doc:
        if key not in _DOC_REQUIRED_KEYS:
            errors.append(f"$: unexpected field {key}")
    if doc.get("schema_version") != "1":
        errors.append("$.schema_version: invalid")
    if doc.get("producer") not in ("review", "security-review"):
        errors.append("$.producer: invalid")
    if doc.get("mode") not in ("pr", "diff", "repo"):
        errors.append("$.mode: invalid")
    if not isinstance(doc.get("summary"), str) or not doc["summary"]:
        errors.append("$.summary: invalid")
    if not isinstance(doc.get("inspected"), list) or not all(isinstance(x, str) for x in doc["inspected"]):
        errors.append("$.inspected: invalid")
    ni = doc.get("not_inspected")
    if not isinstance(ni, list):
        errors.append("$.not_inspected: expected array")
    else:
        for idx, item in enumerate(ni):
            if not isinstance(item, dict) or set(item.keys()) != {"what", "reason"}:
                errors.append(f"$.not_inspected[{idx}]: invalid object")
            elif not all(isinstance(item[k], str) and item[k] for k in ("what", "reason")):
                errors.append(f"$.not_inspected[{idx}]: empty field")
    findings = doc.get("findings")
    if not isinstance(findings, list):
        errors.append("$.findings: expected array")
        return errors

    seen_ids = set()
    id_rx = re.compile(r"^[A-Z][A-Z0-9]*-[0-9]{3,}$")
    sec_rx = re.compile(
        r"^(CWE-[0-9]+|CVE-[0-9]{4}-[0-9]+|GHSA(-[23456789cfghjmpqrvwx]{4}){3}"
        r"|OSV-.+|ASI[0-9]{2}|LLM[0-9]{2}|API[0-9]{1,2})"
    )
    for i, f in enumerate(findings):
        where = f"$.findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{where}: expected object")
            continue
        for key in sorted(_FINDING_REQUIRED_KEYS):
            if key not in f:
                errors.append(f"{where}: missing {key}")
        for key in f:
            if key not in _FINDING_REQUIRED_KEYS:
                errors.append(f"{where}: unexpected field {key}")
        fid = f.get("id", "")
        if not isinstance(fid, str) or not id_rx.search(fid):
            errors.append(f"{where}.id: invalid")
        elif fid in seen_ids:
            errors.append(f"{where}: duplicate id {fid}")
        else:
            seen_ids.add(fid)
        if f.get("severity") not in _SEVERITIES:
            errors.append(f"{where}.severity: invalid")
        if f.get("axis") not in _AXES:
            errors.append(f"{where}.axis: invalid")
        if f.get("confidence") not in _CONFIDENCE:
            errors.append(f"{where}.confidence: invalid")
        if f.get("status") not in _STATUSES:
            errors.append(f"{where}.status: invalid")
        if f.get("security_verdict") not in _SECURITY_VERDICTS:
            errors.append(f"{where}.security_verdict: invalid")
        title = f.get("title", "")
        if not isinstance(title, str) or not title or len(title) > 120:
            errors.append(f"{where}.title: invalid")
        for s_key in ("rule", "rationale"):
            if not isinstance(f.get(s_key), str) or not f[s_key]:
                errors.append(f"{where}.{s_key}: invalid")
        for s_key in ("evidence", "suggestion", "prior_id"):
            if not isinstance(f.get(s_key), str):
                errors.append(f"{where}.{s_key}: invalid")
        refs = f.get("references")
        if not isinstance(refs, list):
            errors.append(f"{where}.references: invalid")
        else:
            for j, r in enumerate(refs):
                if (not isinstance(r, dict) or set(r.keys()) != {"title", "url"}
                        or not isinstance(r["title"], str) or not r["title"]
                        or not isinstance(r["url"], str) or not r["url"].startswith("https://")):
                    errors.append(f"{where}.references[{j}]: invalid")
        start, end = f.get("start_line"), f.get("end_line")
        if (not isinstance(start, int) or isinstance(start, bool) or start < 1
                or not isinstance(end, int) or isinstance(end, bool) or end < 1 or end < start):
            errors.append(f"{where}: invalid line range")
        fpath = f.get("file", "")
        if (not isinstance(fpath, str) or not fpath or fpath.startswith("/")
                or re.match(r"^[A-Za-z]:", fpath) or ".." in Path(fpath).parts or "\\" in fpath):
            errors.append(f"{where}: file must be repo-relative POSIX")
        if f.get("severity") in ("P0", "P1"):
            if len(str(f.get("evidence", "")).strip()) < 20:
                errors.append(f"{where}: {f.get('severity')} needs concrete evidence (>= 20 chars)")
            if f.get("confidence") == "low":
                errors.append(f"{where}: {f.get('severity')} cannot be low confidence")
        if f.get("axis") == "style" and not refs:
            errors.append(f"{where}: style findings must cite reference")
        if f.get("axis") == "security":
            if not sec_rx.match(str(f.get("rule", ""))):
                errors.append(f"{where}: invalid security rule")
            sv = f.get("security_verdict")
            if sv not in ("confirmed", "needs_validation"):
                errors.append(f"{where}: security finding needs confirmed or needs_validation")
            if sv == "needs_validation" and f.get("severity") in ("P0", "P1"):
                errors.append(f"{where}: needs_validation cannot be {f.get('severity')}")
        if f.get("status") in ("still_open", "reopened", "fixed", "accepted_pushback") and not f.get("prior_id"):
            errors.append(f"{where}: status needs prior_id")
    return errors


def _valid_finding(fid="R-001", *, severity="P1", axis="correctness", rule="logic:bug",
                   status="new", prior_id="", security_verdict="n/a",
                   evidence="Concrete reproduction showing bug at line 3 in app.py"):
    return {
        "id": fid,
        "severity": severity,
        "axis": axis,
        "rule": rule,
        "title": f"Issue {fid}",
        "file": "app.py",
        "start_line": 3,
        "end_line": 4,
        "rationale": f"Detailed rationale for {fid}",
        "evidence": evidence,
        "suggestion": "",
        "references": [],
        "confidence": "high",
        "status": status,
        "prior_id": prior_id,
        "security_verdict": security_verdict,
    }


def _valid_doc(*findings):
    return {
        "schema_version": "1",
        "producer": "review",
        "mode": "pr",
        "summary": "Review completed.",
        "inspected": ["app.py"],
        "not_inspected": [],
        "findings": list(findings),
    }


def _run_main_cli(tmp, *, env=None, argv_extra=(), triage=None, which_map=None,
                  agy_side_effect=None, claude_side_effect=None, lib=None):
    import io
    import json
    from pathlib import Path
    from types import SimpleNamespace
    from unittest import mock

    ctx_dir = Path(tmp, "ctx")
    out_dir = Path(tmp, "out")
    ctx_dir.mkdir(exist_ok=True)
    out_dir.mkdir(exist_ok=True)
    ctx_file = ctx_dir / "context.md"
    ctx_file.write_text("# PR\n", encoding="utf-8")
    triage_file = Path(tmp, "triage.json")
    triage_file.write_text(json.dumps(triage if triage is not None else {}), encoding="utf-8")
    findings_out = out_dir / "findings.json"
    usage_out = out_dir / "agy.json"

    if lib is None:
        lib = SimpleNamespace(build_schema=lambda: {"type": "object"}, validate=_strict_findings_validate)
    if which_map is None:
        which_fn = lambda name: f"/usr/bin/{name}"
    elif callable(which_map):
        which_fn = which_map
    else:
        which_fn = lambda name: which_map.get(name)

    argv = [
        "run_model.py", "--context", str(ctx_file), "--triage", str(triage_file),
        "--findings-lib", "unused", "--out", str(findings_out), "--usage-out", str(usage_out),
        *argv_extra,
    ]
    stderr_buf = io.StringIO()
    with mock.patch.dict(rm.os.environ, env if env is not None else {}, clear=True), \
            mock.patch.object(rm.shutil, "which", side_effect=which_fn), \
            mock.patch.object(rm, "run_agy", side_effect=agy_side_effect) as agy, \
            mock.patch.object(rm, "run_claude", side_effect=claude_side_effect) as cc, \
            mock.patch.object(rm.time, "sleep") as sleep, \
            mock.patch.object(rm, "load_findings_lib", return_value=lib), \
            mock.patch.object(rm.sys, "argv", argv), \
            mock.patch.object(rm.sys, "stderr", stderr_buf), \
            mock.patch("builtins.print"):
        code = rm.main()

    f_doc = json.loads(findings_out.read_text(encoding="utf-8")) if findings_out.is_file() else None
    u_doc = json.loads(usage_out.read_text(encoding="utf-8")) if usage_out.is_file() else None
    return SimpleNamespace(
        code=code, agy=agy, cc=cc, sleep=sleep, findings=f_doc, usage=u_doc,
        stderr=stderr_buf.getvalue(), findings_path=findings_out, usage_path=usage_out,
    )


class DeadlineAndFlagContractTest(unittest.TestCase):
    """#26: per-attempt timeout, Claude CLI flag ordering before --add-dir, and job deadline."""

    def test_timeout_constant_and_claude_flag_ordering(self):
        import json
        from unittest import mock

        self.assertEqual(rm.TIMEOUT_S, 20 * 60)
        self.assertEqual(rm.JOB_DEADLINE_S, 45 * 60)
        self.assertEqual(rm.MIN_ATTEMPT_BUDGET_S, 60)

        proc = mock.Mock(returncode=0, stdout=json.dumps({"is_error": False, "result": "{}"}), stderr="")
        with mock.patch.object(rm.subprocess, "run", return_value=proc) as run, \
                mock.patch.object(rm.Path, "read_text", return_value="{}"):
            rm.run_claude("p", "s.json", "claude-opus-5-5", ".", "/ctx")

        cmd = run.call_args.args[0]
        add_idx = cmd.index("--add-dir")
        for flag in ("--bare", "--restricted", "--strict-mcp-config",
                     "--max-turns", "--max-budget-usd", "--tools"):
            self.assertIn(flag, cmd)
            self.assertLess(cmd.index(flag), add_idx, f"{flag} must appear before variadic --add-dir")
        self.assertEqual(cmd[cmd.index("--max-turns") + 1], str(rm.CLAUDE_MAX_TURNS))
        self.assertEqual(cmd[cmd.index("--max-budget-usd") + 1], f"{rm.CLAUDE_MAX_BUDGET_USD:.2f}")
        self.assertEqual(cmd[cmd.index("--tools") + 1], "Read,Grep,Glob")
        self.assertFalse(any(tok.startswith("--") for tok in cmd[add_idx + 1:]))
        self.assertEqual(run.call_args.kwargs["timeout"], rm.TIMEOUT_S)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_claude_verifier_scope_overrides_turns_budget_and_timeout(self):
        import json
        from unittest import mock

        proc = mock.Mock(returncode=0, stdout=json.dumps({"is_error": False, "result": "{}"}), stderr="")
        with rm._deadline_scope(cap_s=rm.VERIFIER_TIMEOUT_S, claude_turns=rm.VERIFIER_CLAUDE_MAX_TURNS,
                                claude_budget=rm.VERIFIER_CLAUDE_MAX_BUDGET_USD), \
                mock.patch.object(rm.subprocess, "run", return_value=proc) as run, \
                mock.patch.object(rm.Path, "read_text", return_value="{}"):
            rm.run_claude("p", "s.json", "claude-opus-5-5", ".", "/ctx")

        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--max-turns") + 1], str(rm.VERIFIER_CLAUDE_MAX_TURNS))
        self.assertEqual(cmd[cmd.index("--max-budget-usd") + 1], f"{rm.VERIFIER_CLAUDE_MAX_BUDGET_USD:.2f}")
        self.assertEqual(run.call_args.kwargs["timeout"], rm.VERIFIER_TIMEOUT_S)

    def test_run_agy_print_timeout_tracks_effective_timeout(self):
        import json
        from unittest import mock

        proc = mock.Mock(returncode=0, stdout=json.dumps({"status": "SUCCESS", "structured_output": {"findings": []}}),
                         stderr="")
        with mock.patch.object(rm.subprocess, "run", return_value=proc) as run:
            rm.run_agy("p", "s.json", "gemini-4-argon-high", ".", "/ctx")
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--print-timeout") + 1], f"{rm.TIMEOUT_S - 60}s")
        self.assertEqual(run.call_args.kwargs["timeout"], rm.TIMEOUT_S)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_job_deadline_caps_timeout_and_aborts_when_under_min_budget(self):
        import json
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest import mock

        clock = [1000.0]
        timeouts = []

        def fake_subproc(cmd, **kwargs):
            timeouts.append(kwargs["timeout"])
            clock[0] += 160.0  # leaves 40s < MIN_ATTEMPT_BUDGET_S (60s)
            return mock.Mock(returncode=0, stdout=json.dumps({"status": "SUCCESS", "response": "not-json"}), stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "ctx").mkdir()
            Path(tmp, "out").mkdir()
            Path(tmp, "ctx/context.md").write_text("# PR\n")
            Path(tmp, "triage.json").write_text("{}")
            lib = SimpleNamespace(build_schema=lambda: {}, validate=lambda d: [])
            argv = [
                "run_model.py", "--context", f"{tmp}/ctx/context.md", "--triage", f"{tmp}/triage.json",
                "--findings-lib", "unused", "--out", f"{tmp}/out/f.json", "--usage-out", f"{tmp}/out/u.json",
                "--job-timeout", "200",
            ]
            with mock.patch.object(rm.time, "monotonic", side_effect=lambda: clock[0]), \
                    mock.patch.object(rm.subprocess, "run", side_effect=fake_subproc), \
                    mock.patch.object(rm, "load_findings_lib", return_value=lib), \
                    mock.patch.object(rm.sys, "argv", argv), \
                    mock.patch.object(rm.sys, "stderr"), \
                    mock.patch("builtins.print"):
                code = rm.main()
            u_obj = json.loads(Path(tmp, "out/u.json").read_text())

        self.assertEqual(code, 1)
        self.assertEqual(timeouts, [200])
        self.assertEqual(u_obj["attempts"], 1)

    def test_job_deadline_caps_second_attempt_timeout_when_budget_permits(self):
        import json
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest import mock

        clock = [500.0]
        timeouts = []

        def fake_subproc(cmd, **kwargs):
            timeouts.append(kwargs["timeout"])
            clock[0] += 50.0  # leaves 150s >= 60s
            return mock.Mock(returncode=0, stdout=json.dumps({"status": "SUCCESS", "response": "bad"}), stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "ctx").mkdir()
            Path(tmp, "out").mkdir()
            Path(tmp, "ctx/context.md").write_text("# PR\n")
            Path(tmp, "triage.json").write_text("{}")
            lib = SimpleNamespace(build_schema=lambda: {}, validate=lambda d: [])
            argv = [
                "run_model.py", "--context", f"{tmp}/ctx/context.md", "--triage", f"{tmp}/triage.json",
                "--findings-lib", "unused", "--out", f"{tmp}/out/f.json", "--usage-out", f"{tmp}/out/u.json",
                "--job-timeout", "200",
            ]
            with mock.patch.object(rm.time, "monotonic", side_effect=lambda: clock[0]), \
                    mock.patch.object(rm.subprocess, "run", side_effect=fake_subproc), \
                    mock.patch.object(rm, "load_findings_lib", return_value=lib), \
                    mock.patch.object(rm.sys, "argv", argv), \
                    mock.patch.object(rm.sys, "stderr"), \
                    mock.patch("builtins.print"):
                code = rm.main()

        self.assertEqual(code, 1)
        self.assertEqual(timeouts, [200, 150])


class MultiEngineCostPreservationTest(unittest.TestCase):
    """#26: failed primary agy and non-zero claude exit usage/cost preservation."""

    def test_failed_agy_spend_is_preserved_after_claude_failover(self):
        import datetime as dt
        import tempfile
        import publish_review as pub

        agy_bad = {
            "status": "SUCCESS",
            "structured_output": _valid_doc(),
            "usage": {"input_tokens": 100_000, "output_tokens": 10_000},
        }
        quota = RuntimeError("agy ERROR (exit 3): Error 429, Status: RESOURCE_EXHAUSTED")
        cc_good = {
            "status": "SUCCESS",
            "structured_output": _valid_doc(),
            "usage": {"input_tokens": 5_000, "output_tokens": 800},
            "cost_usd": 0.42,
        }
        validations = iter([["bad-field"], []])

        with tempfile.TemporaryDirectory() as tmp:
            from types import SimpleNamespace
            lib = SimpleNamespace(build_schema=lambda: {}, validate=lambda d: next(validations))
            res = _run_main_cli(
                tmp,
                env={"GEMINI_API_KEY": "g-key", "ANTHROPIC_API_KEY": "a-key"},
                agy_side_effect=[agy_bad, quota],
                claude_side_effect=[cc_good],
                lib=lib,
            )

        expected_agy = pub.cost({"input_tokens": 100_000, "output_tokens": 10_000})
        expected_total = round(expected_agy + 0.42, 4)

        self.assertEqual(res.code, 0)
        self.assertEqual(res.usage["engine"], "claude")
        self.assertEqual(res.usage["usage_by_engine"]["agy"], {"input_tokens": 100_000, "output_tokens": 10_000})
        self.assertEqual(res.usage["usage_by_engine"]["claude"], {"input_tokens": 5_000, "output_tokens": 800})
        self.assertEqual(res.usage["total_cost_usd"], expected_total)
        self.assertEqual(res.usage["cost_usd"], expected_total)
        self.assertEqual(pub.round_cost_of(res.usage)[0], expected_total)
        # Verify post-Dec-2026 Argon tier pricing agrees with publish_review ($0.60 + $0.42 = $1.02).
        dec_cost = rm.agy_cost({"input_tokens": 100_000, "output_tokens": 10_000}, today=dt.date(2026, 12, 1))
        self.assertEqual(dec_cost, 0.60)
        self.assertEqual(round(dec_cost + 0.42, 4), 1.02)

    def test_claude_nonzero_exit_preserves_partial_cost_and_usage(self):
        import json
        import tempfile
        from unittest import mock

        payload = {
            "is_error": True,
            "subtype": "error_max_turns",
            "num_turns": 30,
            "duration_ms": 18500,
            "total_cost_usd": 0.85,
            "usage": {"input_tokens": 1000, "cache_read_input_tokens": 500, "output_tokens": 200},
        }
        proc = mock.Mock(returncode=1, stdout=json.dumps(payload), stderr="")
        with mock.patch.object(rm.subprocess, "run", return_value=proc), \
                mock.patch.object(rm.Path, "read_text", return_value="{}"):
            with self.assertRaises(rm.ModelInvocationError) as ctx:
                rm.run_claude("p", "s.json", "claude-opus-5-5", ".", "/ctx")

        self.assertIsNotNone(ctx.exception.partial)
        self.assertEqual(ctx.exception.partial["cost_usd"], 0.85)
        self.assertEqual(ctx.exception.partial["usage"], {"input_tokens": 1500, "output_tokens": 200})

        with tempfile.TemporaryDirectory() as tmp:
            err = rm.ModelInvocationError("claude error (exit 1): error_max_turns", partial={
                "status": "ERROR",
                "usage": {"input_tokens": 1500, "output_tokens": 200},
                "num_turns": 30,
                "duration_seconds": 18.5,
                "cost_usd": 0.85,
                "error": "claude error (exit 1): error_max_turns",
            })
            res = _run_main_cli(
                tmp,
                argv_extra=["--engines", "claude"],
                claude_side_effect=[err, err],
            )

        self.assertEqual(res.code, 1)
        self.assertEqual(res.usage["engine"], "claude")
        self.assertEqual(res.usage["total_cost_usd"], 1.7)
        self.assertEqual(res.usage["cost_usd"], 1.7)
        self.assertEqual(len(res.usage["attempt_details"]), 2)
        self.assertEqual(res.usage["attempt_details"][0]["cost_usd"], 0.85)
        self.assertEqual(res.usage["attempt_details"][0]["engine"], "claude")

    def test_agy_nonzero_exit_preserves_partial_usage_and_cost(self):
        import json
        from unittest import mock

        payload = {
            "status": "ERROR",
            "error": "Error 429, Status: RESOURCE_EXHAUSTED",
            "num_turns": 2,
            "duration_seconds": 4.5,
            "usage": {"input_tokens": 50_000, "output_tokens": 5_000},
        }
        proc = mock.Mock(returncode=3, stdout=json.dumps(payload), stderr="")
        with mock.patch.object(rm.subprocess, "run", return_value=proc):
            with self.assertRaises(rm.ModelInvocationError) as ctx:
                rm.run_agy("p", "s.json", "gemini-4-argon-high", ".", "/ctx")
        self.assertEqual(ctx.exception.partial["usage"], {"input_tokens": 50_000, "output_tokens": 5_000})


class EngineChainAndClassifierTest(unittest.TestCase):
    """#33: configurable --engines chain, precedence, error classifier, and failover matrix."""

    def test_cli_engines_claude_skips_agy_completely(self):
        import tempfile

        cc_good = {"status": "SUCCESS", "structured_output": _valid_doc(), "cost_usd": 0.25}
        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(tmp, argv_extra=["--engines", "claude"], claude_side_effect=[cc_good])
        self.assertEqual((res.code, res.agy.call_count, res.cc.call_count), (0, 0, 1))
        self.assertEqual(res.usage["engines_tried"], ["claude"])
        self.assertEqual(res.usage["engine"], "claude")

    def test_env_prg_engines_claude_then_agy_failover(self):
        import tempfile

        agy_good = {
            "status": "SUCCESS",
            "structured_output": _valid_doc(),
            "usage": {"input_tokens": 1000, "output_tokens": 100},
        }
        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(
                tmp,
                env={"PRG_ENGINES": "claude,agy", "GEMINI_API_KEY": "g-key"},
                claude_side_effect=[RuntimeError("claude error (exit 1): 529 overloaded_error")],
                agy_side_effect=[agy_good],
            )
        self.assertEqual((res.code, res.cc.call_count, res.agy.call_count, res.sleep.call_count), (0, 1, 1, 0))
        self.assertEqual(res.usage["engines_tried"], ["claude", "agy"])
        self.assertEqual(res.usage["engine"], "agy")
        self.assertEqual(res.usage["failover_reasons"][0]["from"], "claude")
        self.assertEqual(res.usage["failover_reasons"][0]["to"], "agy")
        self.assertEqual(res.usage["failover_reasons"][0]["category"], "rate_limit")

    def test_custom_model_slugs_and_triage_config_precedence(self):
        import tempfile

        agy_good = {"status": "SUCCESS", "structured_output": _valid_doc()}
        cc_good = {"status": "SUCCESS", "structured_output": _valid_doc(), "cost_usd": 0.1}

        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(
                tmp,
                argv_extra=["--engines", "agy:gemini-4-carbon-high,claude:claude-opus-5-5"],
                env={"ANTHROPIC_API_KEY": "a-key"},
                agy_side_effect=[RuntimeError("HTTP 503 UNAVAILABLE")],
                claude_side_effect=[cc_good],
            )
        self.assertEqual(res.code, 0)
        self.assertEqual(res.agy.call_args.args[2], "gemini-4-carbon-high")
        self.assertEqual(res.cc.call_args.args[2], "claude-opus-5-5")
        self.assertEqual(res.usage["model"], "claude-opus-5-5")

        # Lowest-priority triage config fallback
        with tempfile.TemporaryDirectory() as tmp:
            res_cfg = _run_main_cli(
                tmp,
                triage={"config": {"engines": "claude,agy"}},
                claude_side_effect=[cc_good],
            )
        self.assertEqual((res_cfg.code, res_cfg.cc.call_count, res_cfg.agy.call_count), (0, 1, 0))

        # PRG_ENGINES overrides config; CLI --engines overrides PRG_ENGINES
        with tempfile.TemporaryDirectory() as tmp:
            res_cli = _run_main_cli(
                tmp,
                argv_extra=["--engines", "agy"],
                env={"PRG_ENGINES": "claude"},
                triage={"config": {"engines": "claude"}},
                agy_side_effect=[agy_good],
            )
        self.assertEqual((res_cli.code, res_cli.agy.call_count, res_cli.cc.call_count), (0, 1, 0))

    def test_failover_matrix_all_categories_both_directions(self):
        import subprocess
        import tempfile

        tok = "sk-ant-" + "S" * 24
        cases = [
            ("missing_binary", FileNotFoundError("No such file or directory: 'agy'")),
            ("auth", RuntimeError(f"agy ERROR (exit 3): HTTP 401 API_KEY_INVALID {tok}")),
            ("quota_cap", RuntimeError("agy ERROR (exit 3): Error 429 monthly spending cap RESOURCE_EXHAUSTED")),
            ("rate_limit", RuntimeError("agy ERROR (exit 3): Error 429 RESOURCE_EXHAUSTED")),
            ("timeout", subprocess.TimeoutExpired(cmd="agy", timeout=1200)),
            ("server_error", RuntimeError("agy ERROR (exit 3): HTTP 503 Service Unavailable")),
        ]
        for expected_cat, exc in cases:
            self.assertEqual(rm.classify_error(exc), expected_cat)
            # agy -> claude
            with tempfile.TemporaryDirectory() as tmp:
                res = _run_main_cli(
                    tmp,
                    env={"GEMINI_API_KEY": "g", "ANTHROPIC_API_KEY": tok},
                    agy_side_effect=[exc],
                    claude_side_effect=[{"status": "SUCCESS", "structured_output": _valid_doc(), "cost_usd": 0.1}],
                )
                self.assertEqual((res.code, res.agy.call_count, res.cc.call_count, res.sleep.call_count),
                                 (0, 1, 1, 0), expected_cat)
                self.assertEqual(res.usage["failover_reasons"][0]["category"], expected_cat)
                self.assertNotIn(tok, res.usage["failover_reasons"][0]["reason"])

            # claude -> agy
            with tempfile.TemporaryDirectory() as tmp:
                res = _run_main_cli(
                    tmp,
                    argv_extra=["--engines", "claude,agy"],
                    env={"GEMINI_API_KEY": "g", "ANTHROPIC_API_KEY": tok},
                    claude_side_effect=[exc],
                    agy_side_effect=[{"status": "SUCCESS", "structured_output": _valid_doc()}],
                )
                self.assertEqual((res.code, res.cc.call_count, res.agy.call_count, res.sleep.call_count),
                                 (0, 1, 1, 0), f"reverse {expected_cat}")
                self.assertEqual(res.usage["failover_reasons"][0]["from"], "claude")
                self.assertEqual(res.usage["failover_reasons"][0]["to"], "agy")
                self.assertEqual(res.usage["failover_reasons"][0]["category"], expected_cat)

    def test_no_retry_categories_abort_without_fallback(self):
        import tempfile

        for exc in (
            FileNotFoundError("agy not found"),
            RuntimeError("HTTP 401 UNAUTHENTICATED"),
            RuntimeError("Error 429 spending cap exceeded RESOURCE_EXHAUSTED"),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                res = _run_main_cli(tmp, env={}, agy_side_effect=[exc, exc])
            self.assertEqual((res.code, res.agy.call_count, res.sleep.call_count), (1, 1, 0))

    def test_stderr_no_such_file_still_retries_same_engine(self):
        import tempfile

        for shell_err in (
            "bash: agy: command not found",
            "/bin/sh: 1: claude: not found",
        ):
            self.assertEqual(rm.classify_error(RuntimeError(shell_err)), "missing_binary")

        for non_missing in (
            "agy exited 1: open /home/runner/.agy/cache/state.json: no such file or directory",
            "agy exited 1: open /x/state.json: file not found",
            "agy ERROR (exit 3): model gemini-x not found",
            "claude error (exit 1): 404 Not Found",
        ):
            self.assertEqual(rm.classify_error(RuntimeError(non_missing)), "runtime_error")

        io_err = RuntimeError("agy exited 1: open /home/runner/.agy/cache/state.json: no such file or directory")
        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(
                tmp, env={}, agy_side_effect=[io_err, {"status": "SUCCESS", "structured_output": _valid_doc()}]
            )
        self.assertEqual((res.code, res.agy.call_count, res.cc.call_count), (0, 2, 0))

    def test_validation_failure_retries_once_then_fails_over_with_clean_prompt(self):
        import tempfile
        from types import SimpleNamespace

        bad_agy = {"status": "SUCCESS", "response": "not-json"}
        good_cc = {"status": "SUCCESS", "structured_output": _valid_doc(), "cost_usd": 0.2}
        with tempfile.TemporaryDirectory() as tmp:
            lib = SimpleNamespace(build_schema=lambda: {}, validate=lambda d: [])
            res = _run_main_cli(
                tmp,
                env={"ANTHROPIC_API_KEY": "a-key"},
                agy_side_effect=[bad_agy, bad_agy],
                claude_side_effect=[good_cc],
                lib=lib,
            )
        self.assertEqual((res.code, res.agy.call_count, res.cc.call_count), (0, 2, 1))
        self.assertIn("failed validation", res.agy.call_args_list[1].args[0])
        self.assertNotIn("failed validation", res.cc.call_args_list[0].args[0])
        self.assertEqual(res.usage["failover_reasons"][0]["category"], "validation_failure")

    def test_rejects_unknown_or_malformed_engine_chains(self):
        import tempfile

        for bad in ("codex", "", "agy:", "agy:--bad-flag", "claude,unknown"):
            with self.assertRaises(ValueError):
                rm.parse_engine_chain(bad, agy_model=rm.DEFAULT_MODEL, claude_model=rm.FALLBACK_MODEL)

        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(tmp, argv_extra=["--engines", "codex"])
        self.assertNotEqual(res.code, 0)
        self.assertEqual((res.agy.call_count, res.cc.call_count), (0, 0))

        deduped = rm.parse_engine_chain("agy, agy, claude, agy", agy_model="m1", claude_model="m2")
        self.assertEqual(deduped, [rm.EngineSpec("agy", "m1"), rm.EngineSpec("claude", "m2")])


class TriageEscalationAndCarryForwardTest(unittest.TestCase):
    """#36 & #37: pre-model escalation and no-op rebase carry-forward."""

    def test_escalation_precedes_skip_model_and_writes_valid_p2_doc(self):
        import tempfile

        tok = "ghp_" + "Q" * 36
        triage = {
            "skip_model": True,
            "reason": "should not win over escalation",
            "size_exceeded": True,
            "escalate_reason": f"Diff has 400k chars {tok}",
            "reserved_ids": ["R-999"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(tmp, triage=triage)

        self.assertEqual(res.code, 0)
        self.assertEqual((res.agy.call_count, res.cc.call_count), (0, 0))
        self.assertEqual(_strict_findings_validate(res.findings), [])
        self.assertEqual(len(res.findings["findings"]), 1)
        f = res.findings["findings"][0]
        self.assertEqual((f["id"], f["severity"], f["axis"], f["rule"]),
                         ("R-998", "P2", "scope-architecture", "prg:review-budget-exceeded"))
        self.assertEqual(f["file"], ".github/pr-guardian.yml")
        self.assertTrue(res.usage["escalated"])
        self.assertIn("[REDACTED]", res.usage["escalate_reason"])
        self.assertNotIn(tok, res.usage["escalate_reason"])
        self.assertEqual(res.usage["total_cost_usd"], 0.0)

    def test_cost_exceeded_without_reason_escalates_cleanly(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(tmp, triage={"cost_exceeded": True})
        self.assertEqual(res.code, 0)
        self.assertEqual((res.agy.call_count, res.cc.call_count), (0, 0))
        self.assertEqual(_strict_findings_validate(res.findings), [])
        self.assertTrue(res.usage["escalated"])

    def test_noop_rebase_carry_forward_and_invalid_fallback(self):
        import tempfile

        carried = _valid_finding("R-010", status="still_open", prior_id="R-001")
        triage_ok = {
            "skip_model": True,
            "noop_rebase": True,
            "reason": "no-op rebase",
            "carry_forward_findings": [carried],
        }
        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(tmp, triage=triage_ok)
        self.assertEqual((res.code, res.agy.call_count, res.cc.call_count), (0, 0, 0))
        self.assertEqual(_strict_findings_validate(res.findings), [])
        self.assertEqual(len(res.findings["findings"]), 1)
        self.assertEqual(res.findings["findings"][0]["id"], "R-010")
        self.assertTrue(res.usage["noop_rebase"])
        self.assertEqual(res.usage["total_cost_usd"], 0.0)

        # Invalid carried finding falls back safely to empty_doc
        triage_bad = {
            "skip_model": True,
            "noop_rebase": True,
            "reason": "no-op rebase",
            "carry_forward_findings": [{"id": "bad"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            res_bad = _run_main_cli(tmp, triage=triage_bad)
        self.assertEqual(res_bad.code, 0)
        self.assertEqual(_strict_findings_validate(res_bad.findings), [])
        self.assertEqual(res_bad.findings["findings"], [])


class BlockingFindingVerifierTest(unittest.TestCase):
    """#45: optional self/cross-engine adversarial verifier pass for P0/P1 findings."""

    def test_default_verify_off_never_spawns_verifier(self):
        import tempfile

        p1 = _valid_finding("S-001", severity="P1", axis="security", rule="CWE-89", security_verdict="confirmed")
        primary = {"status": "SUCCESS", "structured_output": _valid_doc(p1),
                   "usage": {"input_tokens": 1000, "output_tokens": 100}}
        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(tmp, agy_side_effect=[primary])
        self.assertEqual((res.code, res.agy.call_count, res.cc.call_count), (0, 1, 0))
        self.assertIsNone(res.usage["verifier"])

    def test_verifier_mode_precedence_and_aliases(self):
        self.assertEqual(rm.resolve_verifier_mode(), "off")
        self.assertEqual(rm.resolve_verifier_mode(None, "1", "cross"), "self")
        self.assertEqual(rm.resolve_verifier_mode(None, "0", "cross"), "off")
        self.assertEqual(rm.resolve_verifier_mode("cross", "self", "off"), "cross")
        self.assertEqual(rm.resolve_verifier_mode(None, "", "auto"), "auto")
        self.assertEqual(rm.resolve_verifier_mode(None, None, True), "self")
        with self.assertRaises(ValueError):
            rm.resolve_verifier_mode(None, "bogus", None)

    def test_self_verifier_confirms_downgrades_drops_and_preserves_prior_id(self):
        import tempfile

        tok = "sk-ant-" + "V" * 24
        s1 = _valid_finding("S-001", severity="P1", axis="security", rule="CWE-89", security_verdict="confirmed")
        s2 = _valid_finding("S-002", severity="P1", axis="security", rule="CWE-79", security_verdict="confirmed")
        r3 = _valid_finding("R-003", severity="P0", axis="correctness", status="new", prior_id="")
        r4 = _valid_finding("R-004", severity="P0", axis="correctness", status="reopened", prior_id="R-001")
        r5 = _valid_finding("R-005", severity="P2", axis="correctness", status="new", prior_id="")

        primary = {
            "status": "SUCCESS",
            "structured_output": _valid_doc(s1, s2, r3, r4, r5),
            "usage": {"input_tokens": 2000, "output_tokens": 200},
        }
        verdicts = {
            "status": "SUCCESS",
            "structured_output": {
                "verdicts": [
                    {"id": "S-001", "verdict": "confirmed", "action": "keep", "explanation": "Real SQLi"},
                    {"id": "S-002", "verdict": "refuted", "action": "downgrade_nit",
                     "explanation": f"Sanitized upstream {tok}"},
                    {"id": "R-003", "verdict": "refuted", "action": "drop", "explanation": "Dead branch"},
                    {"id": "R-004", "verdict": "refuted", "action": "drop", "explanation": "Guarded caller"},
                    {"id": "R-005", "verdict": "refuted", "action": "drop", "explanation": "Should be ignored"},
                ]
            },
            "usage": {"input_tokens": 500, "output_tokens": 100},
        }
        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(
                tmp,
                argv_extra=["--verify", "self"],
                agy_side_effect=[primary, verdicts],
            )

        self.assertEqual((res.code, res.agy.call_count, res.cc.call_count), (0, 2, 0))
        self.assertEqual(_strict_findings_validate(res.findings), [])

        by_id = {f["id"]: f for f in res.findings["findings"]}
        self.assertNotIn("R-003", by_id)
        self.assertEqual(by_id["S-001"]["severity"], "P1")
        self.assertEqual(by_id["S-001"]["security_verdict"], "confirmed")
        self.assertEqual(by_id["S-002"]["severity"], "nit")
        self.assertEqual(by_id["S-002"]["security_verdict"], "needs_validation")
        self.assertIn("[Verifier downgraded from P1:", by_id["S-002"]["rationale"])
        self.assertNotIn(tok, by_id["S-002"]["rationale"])
        # Continued finding with prior_id must downgrade rather than drop
        self.assertEqual(by_id["R-004"]["severity"], "nit")
        self.assertEqual(by_id["R-004"]["prior_id"], "R-001")
        # Non-candidate P2 untouched
        self.assertEqual(by_id["R-005"]["severity"], "P2")

        self.assertEqual(res.usage["verifier"]["checked"], ["S-001", "S-002", "R-003", "R-004"])
        self.assertEqual(res.usage["verifier"]["confirmed"], ["S-001"])
        self.assertEqual(res.usage["verifier"]["downgraded"], ["S-002", "R-004"])
        self.assertEqual(res.usage["verifier"]["dropped"], ["R-003"])
        self.assertEqual(res.usage["usage"], {"input_tokens": 2500, "output_tokens": 300})
        self.assertEqual(res.usage["attempt_details"][1]["label"], "verifier")

    def test_p2_only_findings_skip_verifier_subprocess(self):
        import tempfile

        p2 = _valid_finding("R-001", severity="P2")
        still = _valid_finding("R-002", severity="P1", status="still_open", prior_id="R-000")
        primary = {"status": "SUCCESS", "structured_output": _valid_doc(p2, still)}
        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(tmp, argv_extra=["--verify", "self"], agy_side_effect=[primary])
        self.assertEqual((res.code, res.agy.call_count, res.cc.call_count), (0, 1, 0))
        self.assertEqual(res.usage["verifier"]["checked"], [])

    def test_refuted_with_keep_action_does_not_downgrade(self):
        p0 = _valid_finding("R-001", severity="P0")
        doc = _valid_doc(p0)
        mut, summary = rm.apply_verifier_verdicts(
            doc, [p0], [{"id": "R-001", "verdict": "refuted", "action": "keep", "explanation": "ambiguous"}],
        )
        self.assertEqual(mut["findings"][0]["severity"], "P0")
        self.assertEqual(summary["confirmed"], ["R-001"])
        self.assertEqual(summary["downgraded"], [])
        self.assertEqual(summary["dropped"], [])

    def test_cross_verifier_routes_to_claude_falls_back_and_degrades_gracefully(self):
        import tempfile

        p1 = _valid_finding("R-001", severity="P1")
        primary = {"status": "SUCCESS", "structured_output": _valid_doc(p1),
                   "usage": {"input_tokens": 100_000, "output_tokens": 10_000}}
        cc_verify = {
            "status": "SUCCESS",
            "structured_output": {"verdicts": [{"id": "R-001", "verdict": "confirmed", "action": "keep",
                                                "explanation": "Confirmed"}]},
            "usage": {"input_tokens": 300, "output_tokens": 50},
            "cost_usd": 0.15,
        }

        # Cross-family agy -> claude when ANTHROPIC_API_KEY + claude binary exist
        with tempfile.TemporaryDirectory() as tmp:
            res = _run_main_cli(
                tmp,
                argv_extra=["--verify", "cross"],
                env={"ANTHROPIC_API_KEY": "a-key"},
                agy_side_effect=[primary],
                claude_side_effect=[cc_verify],
            )
        self.assertEqual((res.code, res.agy.call_count, res.cc.call_count), (0, 1, 1))
        self.assertEqual(res.usage["verifier"]["mode"], "cross")
        self.assertEqual(res.usage["verifier"]["engine"], "claude")
        self.assertAlmostEqual(res.usage["total_cost_usd"],
                               round(rm.agy_cost(primary["usage"]) + 0.15, 4), places=4)

        # Fallback to self when claude unavailable
        with tempfile.TemporaryDirectory() as tmp:
            res_fb = _run_main_cli(
                tmp,
                argv_extra=["--verify", "cross"],
                env={},
                agy_side_effect=[primary, cc_verify],
            )
        self.assertEqual((res_fb.code, res_fb.agy.call_count, res_fb.cc.call_count), (0, 2, 0))
        self.assertEqual(res_fb.usage["verifier"]["mode"], "self_fallback")

        # Verifier timeout/error preserves partial verifier cost and keeps primary findings intact (exit 0)
        partial_err = rm.ModelInvocationError("claude verifier timed out", partial={
            "status": "ERROR", "usage": {"input_tokens": 100, "output_tokens": 20},
            "cost_usd": 0.08, "error": "timed out",
        })
        with tempfile.TemporaryDirectory() as tmp:
            res_err = _run_main_cli(
                tmp,
                argv_extra=["--verify", "cross"],
                env={"ANTHROPIC_API_KEY": "a-key"},
                agy_side_effect=[primary],
                claude_side_effect=[partial_err],
            )
        self.assertEqual(res_err.code, 0)
        self.assertEqual(len(res_err.findings["findings"]), 1)
        self.assertEqual(res_err.findings["findings"][0]["severity"], "P1")
        self.assertIn("error", res_err.usage["verifier"])
        self.assertAlmostEqual(res_err.usage["total_cost_usd"],
                               round(rm.agy_cost(primary["usage"]) + 0.08, 4), places=4)

        # Post-mutation validation failure reverts cleanly to pre-verifier primary findings
        with tempfile.TemporaryDirectory() as tmp:
            calls = [0]

            def val_side(doc):
                calls[0] += 1
                return [] if calls[0] == 1 else ["forced post-mutation failure"]

            from types import SimpleNamespace
            lib = SimpleNamespace(build_schema=lambda: {}, validate=val_side)
            res_rev = _run_main_cli(
                tmp,
                argv_extra=["--verify", "self"],
                agy_side_effect=[primary, {
                    "status": "SUCCESS",
                    "structured_output": {"verdicts": [{"id": "R-001", "verdict": "refuted",
                                                        "action": "downgrade_nit", "explanation": "nope"}]},
                }],
                lib=lib,
            )
        self.assertEqual(res_rev.code, 0)
        self.assertEqual(res_rev.findings["findings"][0]["severity"], "P1")
        self.assertTrue(res_rev.usage["verifier"]["reverted"])
