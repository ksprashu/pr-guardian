#!/usr/bin/env python3
"""Run the Antigravity CLI review and leave a validated findings document.

Usage:
  run_model.py --context context.md --triage triage.json --findings-lib findings.py
               --out findings.json --usage-out agy.json [--model SLUG] [--workdir DIR]

The model gets the prompt in prompts/review.md plus the path to the context file.
Its structured output is validated with the forge's findings.py; one retry is
allowed with the validation errors fed back. When Gemini is rate limited and
ANTHROPIC_API_KEY is set, the retry runs Claude Code headless instead (same skills,
prompt and schema); without the key it waits out the per-minute quota. If the second attempt still fails,
this exits 1 and the verdict job fails closed. When triage says the model can be
skipped, an empty, valid document is written instead and the reason is recorded.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_S = 40 * 60
DEFAULT_MODEL = "gemini-4-argon-high"  # agy's slug for Gemini 4 Argon (High)
RATE_LIMIT_WAIT_S = 120
# The fallback reviewer. agy serves Claude only to Google-account logins, not API keys,
# so the fallback runs through Claude Code instead.
FALLBACK_MODEL = "claude-opus-5-5"
# --bare skips CLAUDE.md auto-discovery, hooks, plugins, auto-memory and keychain reads.
# --restricted ignores user, project and local settings files, so hooks, apiKeyHelper or
# permissions a PR adds under .claude/ never load, and it removes the code-running tools.
# It also drops user skills, so the prompt points Claude at the skill files instead.
CLAUDE_TOOLS = "Read,Grep,Glob"
CLAUDE_SKILLS = Path.home() / ".claude" / "skills"
CLAUDE_SKILLS_NOTE = ("\n\nThe skills are not loaded as tools in this session. Read {d}/review/SKILL.md and "
                      "{d}/security-review/SKILL.md first, with the references they point to, and "
                      "follow them exactly as if they had been invoked.\n")
RUN_ERRORS = (RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired, OSError)
_BASE_ENV_KEYS = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "SHELL",
    "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TERM",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
})
_ENGINE_KEY = {"agy": "GEMINI_API_KEY", "claude": "ANTHROPIC_API_KEY"}


def _engine_env(engine: str) -> dict[str, str]:
    """Build a minimal subprocess env for the chosen engine with only its own API key."""
    if engine not in _ENGINE_KEY:
        raise ValueError(f"unknown engine: {engine}")
    env = {k: v for k, v in os.environ.items() if k in _BASE_ENV_KEYS}
    key = _ENGINE_KEY[engine]
    if key in os.environ:
        env[key] = os.environ[key]
    if engine == "claude":
        env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    return env


_SECRET_PATTERNS = (
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"sk-ant-[0-9A-Za-z_-]{20,}"),
    re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    re.compile(r"github_pat_[0-9A-Za-z_]{22,}"),
)


def _literal_secrets() -> list[str]:
    vals: list[str] = []
    for env_name in ("GEMINI_API_KEY", "ANTHROPIC_API_KEY"):
        val = os.environ.get(env_name, "")
        if len(val) < 8:
            continue
        raw = val.encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        ub64 = base64.urlsafe_b64encode(raw).decode("ascii")
        for candidate in (val, b64, b64.rstrip("="), ub64, ub64.rstrip("=")):
            if candidate and candidate not in vals:
                vals.append(candidate)
    vals.sort(key=len, reverse=True)
    return vals


def scrub_secrets(obj: Any) -> Any:
    """Recursively replace env model keys (and base64 forms) and token patterns with [REDACTED]."""
    literals = _literal_secrets()
    lit_re = re.compile("|".join(re.escape(s) for s in literals)) if literals else None

    def _walk(item: Any) -> Any:
        if isinstance(item, str):
            text = lit_re.sub("[REDACTED]", item) if lit_re else item
            for pat in _SECRET_PATTERNS:
                text = pat.sub("[REDACTED]", text)
            return text
        if isinstance(item, list):
            return [_walk(x) for x in item]
        if isinstance(item, tuple):
            return tuple(_walk(x) for x in item)
        if isinstance(item, dict):
            return {
                (_walk(k) if isinstance(k, str) else k): _walk(v)
                for k, v in item.items()
            }
        return item

    return _walk(obj)


def _err(msg: str) -> None:
    print(scrub_secrets(msg), file=sys.stderr)


def load_findings_lib(path: str):
    spec = importlib.util.spec_from_file_location("forge_findings", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def empty_doc(reason: str) -> dict[str, Any]:
    return {"schema_version": "1", "producer": "review", "mode": "pr",
            "summary": f"Model review skipped: {reason}. Scanners ran; no blocking findings.",
            "inspected": ["scanner output"],
            "not_inspected": [{"what": "model review", "reason": reason}], "findings": []}


def extract(result: dict[str, Any]) -> Any:
    if isinstance(result.get("structured_output"), dict):
        return result["structured_output"]
    text = (result.get("response") or "").strip()
    if not text:
        raise ValueError("empty response and no structured_output (the turn ended without a final answer)")
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(text[start:end + 1])  # JSON wrapped in prose


FINALIZE = ("Your previous turn ended without a final answer. Do not investigate further and do not "
            "call tools. Return the complete findings JSON document for the review you just did.")


def run_agy(prompt: str, schema: str, model: str, workdir: str, extra_dir: str,
            conversation: str | None = None) -> dict[str, Any]:
    # The Argon slugs carry their effort (-high/-medium/-low); agy rejects --effort with them.
    cmd = ["agy", "-p", prompt, "--add-dir", extra_dir, "--model", model,
           "--output-format", "json", "--json-schema", schema, "--sandbox", "--disable-slash-commands",
           "--print-timeout", f"{TIMEOUT_S - 60}s"]
    if conversation:
        cmd += ["--conversation", conversation]
    proc = subprocess.run(cmd, capture_output=True, text=True, shell=False, cwd=workdir,
                          env=_engine_env("agy"), timeout=TIMEOUT_S)
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        stderr = scrub_secrets(proc.stderr).strip()[-1500:]
        raise RuntimeError(f"agy exited {proc.returncode}: {stderr}") from None
    if proc.returncode != 0 or result.get("status") != "SUCCESS":
        # agy prints a structured AGY_ERROR {...} line on stderr; it carries the real cause.
        detail = [ln for ln in scrub_secrets(proc.stderr).splitlines() if ln.startswith("AGY_ERROR")]
        err_msg = scrub_secrets(str(result.get("error")))[:1000]
        raise RuntimeError(f"agy {result.get('status')} (exit {proc.returncode}): "
                           f"{err_msg} {' '.join(detail)[:1000]}".rstrip())
    return result


def run_claude(prompt: str, schema: str, model: str, workdir: str, extra_dir: str) -> dict[str, Any]:
    """Run Claude Code read-only and return the result in agy's shape."""
    cmd = ["claude", "-p", prompt + CLAUDE_SKILLS_NOTE.format(d=CLAUDE_SKILLS), "--model", model,
           "--output-format", "json", "--json-schema", Path(schema).read_text(encoding="utf-8"),
           "--bare", "--restricted", "--strict-mcp-config", "--tools", CLAUDE_TOOLS,
           "--add-dir", extra_dir, str(CLAUDE_SKILLS)]
    proc = subprocess.run(cmd, capture_output=True, text=True, shell=False, cwd=workdir,
                          env=_engine_env("claude"), timeout=TIMEOUT_S)
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError:
        stderr = scrub_secrets(proc.stderr).strip()[-1500:]
        raise RuntimeError(f"claude exited {proc.returncode}: {stderr}") from None
    if proc.returncode != 0 or raw.get("is_error"):
        detail = raw.get("result") or raw.get("errors") or proc.stderr.strip()
        raise RuntimeError(f"claude error (exit {proc.returncode}): {scrub_secrets(str(detail))[:1000]}")
    u = raw.get("usage") or {}
    return {"status": "SUCCESS", "structured_output": raw.get("structured_output"),
            "response": raw.get("result"), "num_turns": raw.get("num_turns"),
            "duration_seconds": (raw.get("duration_ms") or 0) / 1000,
            "usage": {"input_tokens": u.get("input_tokens", 0) + u.get("cache_read_input_tokens", 0)
                      + u.get("cache_creation_input_tokens", 0),
                      "output_tokens": u.get("output_tokens", 0)},
            "cost_usd": raw.get("total_cost_usd")}


def can_fall_back() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY") and shutil.which("claude"))


def is_rate_limited(error: str) -> bool:
    # A spending cap is also a 429 but does not refill within minutes, so do not wait on it.
    return "RESOURCE_EXHAUSTED" in error and "spending cap" not in error


def is_empty(result: dict[str, Any]) -> bool:
    return not isinstance(result.get("structured_output"), dict) and not (result.get("response") or "").strip()


def attempt_meta(label: str, result: dict[str, Any]) -> dict[str, Any]:
    """Return scrubbed per-attempt metadata without raw response text."""
    err = result.get("error")
    return scrub_secrets({
        "label": label,
        "status": result.get("status"),
        "num_turns": result.get("num_turns"),
        "duration_seconds": result.get("duration_seconds"),
        "has_structured_output": isinstance(result.get("structured_output"), dict),
        "error": scrub_secrets(str(err))[:500] if err is not None else None,
        "usage": result.get("usage"),
    })


def add_usage(total: dict[str, int], usage: dict[str, Any] | None) -> None:
    for k, v in (usage or {}).items():
        if isinstance(v, (int, float)):
            total[k] = total.get(k, 0) + v


def usage_record(usage: dict[str, int], engine: str, cost_usd: float, **extra: Any) -> dict[str, Any]:
    # Claude Code reports its own cost; publish_review prices agy usage at Gemini rates.
    rec: dict[str, Any] = {"usage": usage, "engine": engine, **extra}
    if engine == "claude":
        rec["cost_usd"] = round(cost_usd, 4)
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--context", required=True)
    ap.add_argument("--triage", required=True)
    ap.add_argument("--findings-lib", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--usage-out", required=True)
    ap.add_argument("--model", default=os.environ.get("PRG_MODEL") or DEFAULT_MODEL)
    ap.add_argument("--workdir", default=".")
    args = ap.parse_args()

    lib = load_findings_lib(args.findings_lib)
    triage = json.loads(Path(args.triage).read_text(encoding="utf-8"))
    usage: dict[str, int] = {}
    if triage.get("skip_model"):
        Path(args.out).write_text(json.dumps(scrub_secrets(empty_doc(triage["reason"]))), encoding="utf-8")
        Path(args.usage_out).write_text(
            json.dumps(scrub_secrets({"usage": usage, "skipped": triage["reason"]})),
            encoding="utf-8",
        )
        print(scrub_secrets(f"run_model: skipped ({triage['reason']})"))
        return 0

    schema = Path(args.out).with_name("findings.schema.json")
    schema.write_text(json.dumps(lib.build_schema()), encoding="utf-8")
    base = (ROOT / "prompts" / "review.md").read_text(encoding="utf-8")
    base_prompt = f"{base}\n\nContext file: {Path(args.context).resolve()}\n"

    errors: list[str] = []
    fix_errors: list[str] = []
    attempt_details: list[dict[str, Any]] = []
    engine = "agy"
    cost_usd = 0.0
    ctx_dir = str(Path(args.context).resolve().parent)
    attempt, last = 0, 2
    while attempt < last:
        attempt += 1
        prompt = (base_prompt + "\n\nYour previous output failed validation. Fix exactly these problems and "
                  "return the whole document again:\n- " + "\n- ".join(fix_errors[:40])
                  if fix_errors else base_prompt)
        try:
            if engine == "claude":
                result = run_claude(prompt, str(schema), FALLBACK_MODEL, args.workdir, ctx_dir)
            else:
                result = run_agy(prompt, str(schema), args.model, args.workdir, ctx_dir)
        except RUN_ERRORS as exc:
            errors, fix_errors = [scrub_secrets(f"run failed: {exc}")], []
            _err(f"run_model: attempt {attempt}: {exc}")
            if engine == "agy" and is_rate_limited(str(exc)):
                if can_fall_back():
                    engine, errors, last = "claude", [], attempt + 2  # a fresh reviewer with its own retry
                    _err(f"run_model: rate limited; falling back to {FALLBACK_MODEL}")
                elif attempt == 1:
                    # Per-minute quotas (RESOURCE_EXHAUSTED) refill; an immediate retry just fails again.
                    _err(f"run_model: rate limited; waiting {RATE_LIMIT_WAIT_S}s")
                    time.sleep(RATE_LIMIT_WAIT_S)
            continue
        add_usage(usage, result.get("usage"))
        cost_usd += result.get("cost_usd") or 0.0
        attempt_details.append(attempt_meta(str(attempt), result))
        if engine == "agy" and is_empty(result) and result.get("conversation_id"):
            # Seen in CI: status SUCCESS, thousands of output tokens, but no final message.
            # Ask the same conversation for the answer instead of paying for a fresh review.
            try:
                result = run_agy(FINALIZE, str(schema), args.model, args.workdir, ctx_dir,
                                 result["conversation_id"])
                add_usage(usage, result.get("usage"))
                attempt_details.append(attempt_meta(f"{attempt}-finalize", result))
            except RUN_ERRORS as exc:
                _err(f"run_model: attempt {attempt}: finalize failed: {exc}")
                if is_rate_limited(str(exc)):
                    if can_fall_back():
                        engine, errors, fix_errors, last = "claude", [], [], attempt + 2
                        _err(f"run_model: rate limited; falling back to {FALLBACK_MODEL}")
                        continue
                    if attempt == 1:
                        errors, fix_errors = [scrub_secrets(f"finalize failed: {exc}")], []
                        _err(f"run_model: rate limited; waiting {RATE_LIMIT_WAIT_S}s")
                        time.sleep(RATE_LIMIT_WAIT_S)
                        continue
        try:
            doc = scrub_secrets(extract(result))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            errors = fix_errors = [scrub_secrets(
                f"output is not a JSON document: {exc}. End your final turn with only the "
                "complete findings JSON object, no prose and no tool calls"
            )]
            _err(f"run_model: attempt {attempt}: {exc}")
            continue
        errors = fix_errors = scrub_secrets(lib.validate(doc))
        if not errors:
            Path(args.out).write_text(json.dumps(doc, indent=1), encoding="utf-8")
            rec = scrub_secrets(usage_record(usage, engine, cost_usd, attempts=attempt,
                                             attempt_details=attempt_details))
            Path(args.usage_out).write_text(json.dumps(rec), encoding="utf-8")
            print(f"run_model: {len(doc['findings'])} findings after {attempt} attempt(s); usage {usage}")
            return 0
        _err(f"run_model: attempt {attempt}: {len(errors)} validation errors")

    rec = scrub_secrets(usage_record(usage, engine, cost_usd, errors=errors[:40],
                                     attempt_details=attempt_details))
    Path(args.usage_out).write_text(json.dumps(rec), encoding="utf-8")
    _err("run_model: no valid findings document after "
         f"{attempt} attempts:\n- " + "\n- ".join(errors[:20]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
