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
import importlib.util
import json
import os
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
CLAUDE_TOOLS = ["Read", "Grep", "Glob", "Skill"]
CLAUDE_DENIED = ["Bash", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch", "Task"]


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
                          timeout=TIMEOUT_S)
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"agy exited {proc.returncode}: {proc.stderr.strip()[-1500:]}") from None
    if proc.returncode != 0 or result.get("status") != "SUCCESS":
        # agy prints a structured AGY_ERROR {...} line on stderr; it carries the real cause.
        detail = [ln for ln in proc.stderr.splitlines() if ln.startswith("AGY_ERROR")]
        raise RuntimeError(f"agy {result.get('status')} (exit {proc.returncode}): "
                           f"{str(result.get('error'))[:1000]} {' '.join(detail)[:1000]}".rstrip())
    return result


def run_claude(prompt: str, schema: str, model: str, workdir: str, extra_dir: str) -> dict[str, Any]:
    """Run Claude Code read-only and return the result in agy's shape."""
    cmd = ["claude", "-p", prompt, "--model", model, "--output-format", "json",
           "--json-schema", Path(schema).read_text(encoding="utf-8"), "--add-dir", extra_dir,
           "--allowedTools", *CLAUDE_TOOLS, "--disallowedTools", *CLAUDE_DENIED]
    proc = subprocess.run(cmd, capture_output=True, text=True, shell=False, cwd=workdir,
                          timeout=TIMEOUT_S)
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"claude exited {proc.returncode}: {proc.stderr.strip()[-1500:]}") from None
    if proc.returncode != 0 or raw.get("is_error"):
        raise RuntimeError(f"claude error (exit {proc.returncode}): {str(raw.get('result'))[:1000]}")
    u = raw.get("usage") or {}
    return {"status": "SUCCESS", "structured_output": raw.get("structured_output"),
            "response": raw.get("result"), "num_turns": raw.get("num_turns"),
            "duration_seconds": (raw.get("duration_ms") or 0) / 1000,
            "usage": {"input_tokens": u.get("input_tokens", 0) + u.get("cache_read_input_tokens", 0)
                      + u.get("cache_creation_input_tokens", 0),
                      "output_tokens": u.get("output_tokens", 0)},
            "cost_usd": raw.get("total_cost_usd")}


def is_rate_limited(error: str) -> bool:
    # A spending cap is also a 429 but does not refill within minutes, so do not wait on it.
    return "RESOURCE_EXHAUSTED" in error and "spending cap" not in error


def is_empty(result: dict[str, Any]) -> bool:
    return not isinstance(result.get("structured_output"), dict) and not (result.get("response") or "").strip()


def record_raw(out: str, label: str, result: dict[str, Any]) -> None:
    raw = {k: result.get(k) for k in ("status", "num_turns", "duration_seconds", "error", "usage")}
    raw["response_head"] = (result.get("response") or "")[:4000]
    raw["has_structured_output"] = isinstance(result.get("structured_output"), dict)
    Path(out).with_name(f"agy-raw-{label}.json").write_text(json.dumps(raw, indent=1))


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
        Path(args.out).write_text(json.dumps(empty_doc(triage["reason"])), encoding="utf-8")
        Path(args.usage_out).write_text(json.dumps({"usage": usage, "skipped": triage["reason"]}))
        print(f"run_model: skipped ({triage['reason']})")
        return 0

    schema = Path(args.out).with_name("findings.schema.json")
    schema.write_text(json.dumps(lib.build_schema()), encoding="utf-8")
    base = (ROOT / "prompts" / "review.md").read_text(encoding="utf-8")
    prompt = f"{base}\n\nContext file: {Path(args.context).resolve()}\n"

    errors: list[str] = []
    engine = "agy"
    cost_usd = 0.0
    for attempt in (1, 2):
        if errors:
            prompt += ("\n\nYour previous output failed validation. Fix exactly these problems and "
                       "return the whole document again:\n- " + "\n- ".join(errors[:40]))
        try:
            if engine == "claude":
                result = run_claude(prompt, str(schema), FALLBACK_MODEL, args.workdir,
                                    str(Path(args.context).resolve().parent))
            else:
                result = run_agy(prompt, str(schema), args.model, args.workdir,
                                 str(Path(args.context).resolve().parent))
        except (RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            errors = [f"run failed: {exc}"]
            print(f"run_model: attempt {attempt}: {exc}", file=sys.stderr)
            if attempt == 1 and is_rate_limited(str(exc)):
                if os.environ.get("ANTHROPIC_API_KEY"):
                    engine = "claude"
                    errors = []  # a fresh reviewer, not a correction
                    print(f"run_model: rate limited; falling back to {FALLBACK_MODEL}", file=sys.stderr)
                else:
                    # Per-minute quotas (RESOURCE_EXHAUSTED) refill; an immediate retry just fails again.
                    print(f"run_model: rate limited; waiting {RATE_LIMIT_WAIT_S}s", file=sys.stderr)
                    time.sleep(RATE_LIMIT_WAIT_S)
            continue
        add_usage(usage, result.get("usage"))
        cost_usd += result.get("cost_usd") or 0.0
        record_raw(args.out, str(attempt), result)
        if engine == "agy" and is_empty(result) and result.get("conversation_id"):
            # Seen in CI: status SUCCESS, thousands of output tokens, but no final message.
            # Ask the same conversation for the answer instead of paying for a fresh review.
            try:
                result = run_agy(FINALIZE, str(schema), args.model, args.workdir,
                                 str(Path(args.context).resolve().parent), result["conversation_id"])
                add_usage(usage, result.get("usage"))
                record_raw(args.out, f"{attempt}-finalize", result)
            except (RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
                print(f"run_model: attempt {attempt}: finalize failed: {exc}", file=sys.stderr)
        try:
            doc = extract(result)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            errors = [f"output is not a JSON document: {exc}. End your final turn with only the "
                      "complete findings JSON object, no prose and no tool calls"]
            print(f"run_model: attempt {attempt}: {exc}", file=sys.stderr)
            continue
        errors = lib.validate(doc)
        if not errors:
            Path(args.out).write_text(json.dumps(doc, indent=1), encoding="utf-8")
            Path(args.usage_out).write_text(json.dumps(usage_record(usage, engine, cost_usd, attempts=attempt)))
            print(f"run_model: {len(doc['findings'])} findings after {attempt} attempt(s); usage {usage}")
            return 0
        print(f"run_model: attempt {attempt}: {len(errors)} validation errors", file=sys.stderr)

    Path(args.usage_out).write_text(json.dumps(usage_record(usage, engine, cost_usd, errors=errors[:40])))
    print("run_model: no valid findings document after 2 attempts:\n- " + "\n- ".join(errors[:20]),
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
