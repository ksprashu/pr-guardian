#!/usr/bin/env python3
"""Run the Antigravity CLI review and leave a validated findings document.

Usage:
  run_model.py --context context.md --triage triage.json --findings-lib findings.py
               --out findings.json --usage-out agy.json [--model SLUG] [--workdir DIR]

The model gets the prompt in prompts/review.md plus the path to the context file.
Its structured output is validated with the forge's findings.py; one retry is
allowed with the validation errors fed back. If the second attempt still fails,
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
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_S = 40 * 60


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
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
    return json.loads(text)


def run_agy(prompt: str, schema: str, model: str, workdir: str, extra_dir: str) -> dict[str, Any]:
    cmd = ["agy", "-p", prompt, "--add-dir", extra_dir, "--model", model, "--effort", "max",
           "--output-format", "json", "--json-schema", schema, "--sandbox", "--disable-slash-commands",
           "--print-timeout", f"{TIMEOUT_S - 60}s"]
    proc = subprocess.run(cmd, capture_output=True, text=True, shell=False, cwd=workdir,
                          timeout=TIMEOUT_S)
    if proc.returncode != 0:
        raise RuntimeError(f"agy exited {proc.returncode}: {proc.stderr.strip()[-1500:]}")
    return json.loads(proc.stdout)


def add_usage(total: dict[str, int], usage: dict[str, Any] | None) -> None:
    for k, v in (usage or {}).items():
        if isinstance(v, (int, float)):
            total[k] = total.get(k, 0) + v


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--context", required=True)
    ap.add_argument("--triage", required=True)
    ap.add_argument("--findings-lib", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--usage-out", required=True)
    ap.add_argument("--model", default=os.environ.get("PRG_MODEL", "gemini-4-argon"))
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
    for attempt in (1, 2):
        if errors:
            prompt += ("\n\nYour previous output failed validation. Fix exactly these problems and "
                       "return the whole document again:\n- " + "\n- ".join(errors[:40]))
        try:
            result = run_agy(prompt, str(schema), args.model, args.workdir,
                             str(Path(args.context).resolve().parent))
        except (RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            errors = [f"run failed: {exc}"]
            print(f"run_model: attempt {attempt}: {exc}", file=sys.stderr)
            continue
        add_usage(usage, result.get("usage"))
        try:
            doc = extract(result)
        except (json.JSONDecodeError, TypeError) as exc:
            errors = [f"output is not JSON: {exc}"]
            continue
        errors = lib.validate(doc)
        if not errors:
            Path(args.out).write_text(json.dumps(doc, indent=1), encoding="utf-8")
            Path(args.usage_out).write_text(json.dumps({"usage": usage, "attempts": attempt}))
            print(f"run_model: {len(doc['findings'])} findings after {attempt} attempt(s); usage {usage}")
            return 0
        print(f"run_model: attempt {attempt}: {len(errors)} validation errors", file=sys.stderr)

    Path(args.usage_out).write_text(json.dumps({"usage": usage, "errors": errors[:40]}))
    print("run_model: no valid findings document after 2 attempts:\n- " + "\n- ".join(errors[:20]),
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
