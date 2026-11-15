#!/usr/bin/env python3
"""Offline eval linter, scorer, and live runner for pr-guardian."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import build_context  # noqa: E402
import check_pins  # noqa: E402
import run_model  # noqa: E402
import state as st  # noqa: E402

SEVERITIES = ("P0", "P1", "P2", "P3", "nit")
OPEN = (None, "new", "still_open", "reopened")
LINE_TOLERANCE = 3
GIT_TIMEOUT_S = 30
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def _git_env(tmp_home: str) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": tmp_home,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def _git(cmd: list[str], cwd: Path, env: dict[str, str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        shell=False,
        timeout=GIT_TIMEOUT_S,
    )


def _safe_relpath(rel: str) -> Path | None:
    if not isinstance(rel, str) or not rel or rel.startswith("/") or "\\" in rel:
        return None
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts:
        return None
    return p


def _patch_touched_files(diff_text: str) -> set[str]:
    touched: set[str] = set()
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].split("\t", 1)[0].strip()
            if target == "/dev/null":
                continue
            if target.startswith("b/"):
                target = target[2:]
            touched.add(target)
        elif line.startswith("rename to "):
            touched.add(line[len("rename to ") :].strip())
    return touched


def materialise_case(case: dict[str, Any], diff_text: str, dest: Path) -> None:
    """Write `case['files']` into `dest`, make a base git commit, and apply `diff_text`."""
    files = case.get("files")
    if not isinstance(files, dict):
        raise ValueError("case.json 'files' must be an object")
    for rel, content in files.items():
        safe = _safe_relpath(rel)
        if safe is None or not isinstance(content, str):
            raise ValueError(f"invalid fixture file entry: {rel!r}")
        full = dest / safe
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")

    env = _git_env(str(dest))
    steps = [
        ["git", "init", "-q"],
        ["git", "add", "-A"],
        ["git", "-c", "user.name=eval", "-c", "user.email=eval@localhost", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base"],
    ]
    for cmd in steps:
        proc = _git(cmd, dest, env)
        if proc.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd[:2])} failed: {proc.stderr.strip()}")

    for cmd in (["git", "apply", "--check", "-"], ["git", "apply", "-"]):
        proc = _git(cmd, dest, env, stdin=diff_text)
        if proc.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd[:3])} failed: {proc.stderr.strip()}")


def blocking(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Findings that would block a merge (P0..P3 and open/unspecified status)."""
    return [
        f
        for f in doc.get("findings", [])
        if isinstance(f, dict) and f.get("severity") in SEVERITIES[:4] and f.get("status") in OPEN
    ]


def matches(f: dict[str, Any], e: dict[str, Any]) -> bool:
    """Return True if finding `f` satisfies expectation `e`."""
    if f.get("file") != e["file"]:
        return False
    lo, hi = f.get("start_line"), f.get("end_line")
    if (
        not isinstance(lo, int)
        or isinstance(lo, bool)
        or not isinstance(hi, int)
        or isinstance(hi, bool)
    ):
        return False
    if hi + LINE_TOLERANCE < e["start_line"] or lo - LINE_TOLERANCE > e["end_line"]:
        return False
    rules, axes = e.get("rules") or [], e.get("axes") or []
    if not rules and not axes:
        return True
    rule_text = f.get("rule") or ""
    return any(re.search(re.escape(r), rule_text, re.I) for r in rules) or f.get("axis") in axes


def _case_names(root: Path, subset: str | None) -> list[str]:
    cases_dir = root / "evals" / "cases"
    if not cases_dir.is_dir():
        return []
    available = sorted(p.name for p in cases_dir.iterdir() if p.is_dir())
    if not subset:
        return available
    requested = [x.strip() for x in subset.split(",") if x.strip()]
    missing = [x for x in requested if x not in available]
    if missing:
        raise ValueError(f"unknown eval case(s): {', '.join(missing)}")
    return requested


def lint_cases(root: Path, subset: str | None = None) -> list[str]:
    errors: list[str] = []
    try:
        names = _case_names(root, subset)
    except ValueError as exc:
        return [str(exc)]
    if not names:
        return ["no cases found under evals/cases"]

    for name in names:
        case_err_start = len(errors)
        cdir = root / "evals" / "cases" / name
        for req in ("case.json", "diff.patch", "expected.json"):
            if not (cdir / req).is_file():
                errors.append(f"{name}: missing {req}")
        if any(not (cdir / req).is_file() for req in ("case.json", "diff.patch", "expected.json")):
            continue

        try:
            case = json.loads((cdir / "case.json").read_text(encoding="utf-8"))
            expected = json.loads((cdir / "expected.json").read_text(encoding="utf-8"))
            diff_text = (cdir / "diff.patch").read_text(encoding="utf-8")
        except (ValueError, OSError) as exc:
            errors.append(f"{name}: invalid file: {exc}")
            continue

        if not isinstance(case, dict) or not isinstance(case.get("title"), str) or not case["title"].strip():
            errors.append(f"{name}/case.json: title must be a non-empty string")
        if not isinstance(case.get("description"), str) or not case["description"].strip():
            errors.append(f"{name}/case.json: description must be a non-empty string")
        if not isinstance(case.get("files"), dict):
            errors.append(f"{name}/case.json: files must be an object")
        if not diff_text.strip():
            errors.append(f"{name}/diff.patch: patch is empty")

        clean = expected.get("clean")
        expect = expected.get("expect")
        if not isinstance(clean, bool):
            errors.append(f"{name}/expected.json: 'clean' must be a boolean")
            continue
        if not isinstance(expect, list):
            errors.append(f"{name}/expected.json: 'expect' must be a list")
            continue
        if clean and expect:
            errors.append(f"{name}/expected.json: clean=true requires expect=[]")
        if not clean and not expect:
            errors.append(f"{name}/expected.json: clean=false requires at least one expectation")

        touched = _patch_touched_files(diff_text)
        seen_labels: set[str] = set()
        for idx, e in enumerate(expect):
            if not isinstance(e, dict):
                errors.append(f"{name}/expected.json[{idx}]: item must be an object")
                continue
            lbl = e.get("label")
            if not isinstance(lbl, str) or not lbl.strip():
                errors.append(f"{name}/expected.json[{idx}]: invalid label {lbl!r}")
            elif lbl in seen_labels:
                errors.append(f"{name}/expected.json: duplicate label {lbl!r}")
            else:
                seen_labels.add(lbl)
            sev = e.get("min_severity")
            if sev not in SEVERITIES[:4]:
                errors.append(f"{name}/expected.json[{idx}]: invalid min_severity {sev!r}")
            f_path = e.get("file")
            if not isinstance(f_path, str) or f_path not in touched:
                errors.append(f"{name}/expected.json[{idx}]: file {f_path!r} is not touched by diff.patch")
            s_ln, e_ln = e.get("start_line"), e.get("end_line")
            if (
                not isinstance(s_ln, int)
                or isinstance(s_ln, bool)
                or not isinstance(e_ln, int)
                or isinstance(e_ln, bool)
                or s_ln < 1
                or e_ln < s_ln
            ):
                errors.append(f"{name}/expected.json[{idx}]: invalid line range {s_ln}..{e_ln}")

        if len(errors) > case_err_start:
            continue

        with tempfile.TemporaryDirectory(prefix=f"prg-eval-{name}-") as tmp:
            tree = Path(tmp)
            try:
                materialise_case(case, diff_text, tree)
            except Exception as exc:
                errors.append(f"{name}: {exc}")
                continue
            for idx, e in enumerate(expect):
                target = tree / e["file"]
                if not target.is_file():
                    errors.append(f"{name}/expected.json[{idx}]: post-patch file {e['file']!r} missing")
                    continue
                line_count = len(target.read_text(encoding="utf-8").splitlines())
                if e["end_line"] > line_count:
                    errors.append(
                        f"{name}/expected.json[{idx}]: end_line {e['end_line']} exceeds {e['file']} length ({line_count})"
                    )
    return errors


def _usage_metrics(usage: dict[str, Any] | None) -> tuple[float | None, float | None]:
    if not isinstance(usage, dict):
        return None, None
    raw_cost = usage.get("total_cost_usd")
    if raw_cost is None:
        raw_cost = usage.get("cost_usd")
    cost = float(raw_cost) if isinstance(raw_cost, (int, float)) and not isinstance(raw_cost, bool) else None
    details = usage.get("attempt_details")
    seconds: float | None = None
    if isinstance(details, list) and details:
        vals = [
            float(d["duration_seconds"])
            for d in details
            if isinstance(d, dict)
            and isinstance(d.get("duration_seconds"), (int, float))
            and not isinstance(d.get("duration_seconds"), bool)
        ]
        if vals:
            seconds = sum(vals)
    return cost, seconds


def score_case(
    name: str,
    expected_doc: dict[str, Any],
    findings_doc: dict[str, Any],
    usage_doc: dict[str, Any] | None = None,
) -> dict[str, Any]:
    block = blocking(findings_doc)
    expects = expected_doc.get("expect") or []
    matched_f: set[int] = set()
    hits = 0
    missed: list[str] = []
    underrated: list[dict[str, str]] = []

    for e in expects:
        hit_idx = None
        for idx, f in enumerate(block):
            if idx not in matched_f and matches(f, e):
                hit_idx = idx
                break
        if hit_idx is None:
            missed.append(e["label"])
        else:
            matched_f.add(hit_idx)
            hits += 1
            want_sev = e.get("min_severity")
            got_sev = block[hit_idx].get("severity")
            if want_sev in SEV_RANK and got_sev in SEV_RANK and SEV_RANK[got_sev] > SEV_RANK[want_sev]:
                underrated.append({"label": e["label"], "expected": want_sev, "got": got_sev})

    fp = len(block) - len(matched_f)
    cost, secs = _usage_metrics(usage_doc)
    return {
        "case": name,
        "clean": bool(expected_doc.get("clean")),
        "expected": len(expects),
        "hit": hits,
        "missed": missed,
        "false_positives": fp,
        "underrated": underrated,
        "cost_usd": cost,
        "seconds": secs,
    }


def score_directory(root: Path, label: str, findings_dir: Path, case_names: list[str]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for name in case_names:
        exp_path = root / "evals" / "cases" / name / "expected.json"
        f_path = findings_dir / f"{name}.findings.json"
        if not f_path.is_file():
            raise FileNotFoundError(f"missing {f_path}")
        u_path = findings_dir / f"{name}.usage.json"
        expected_doc = json.loads(exp_path.read_text(encoding="utf-8"))
        findings_doc = json.loads(f_path.read_text(encoding="utf-8"))
        usage_doc = json.loads(u_path.read_text(encoding="utf-8")) if u_path.is_file() else None
        rows.append(score_case(name, expected_doc, findings_doc, usage_doc))

    total_exp = sum(r["expected"] for r in rows)
    total_hit = sum(r["hit"] for r in rows)
    total_fp = sum(r["false_positives"] for r in rows)
    clean_fp = sum(r["false_positives"] for r in rows if r["clean"])
    recall = (total_hit / total_exp) if total_exp else 1.0
    precision = (total_hit / (total_hit + total_fp)) if (total_hit + total_fp) else 1.0
    costs = [r["cost_usd"] for r in rows if r["cost_usd"] is not None]
    secs = [r["seconds"] for r in rows if r["seconds"] is not None]
    return {
        "label": label,
        "cases": rows,
        "expected": total_exp,
        "hit": total_hit,
        "recall": recall,
        "precision": precision,
        "false_positives": total_fp,
        "clean_false_positives": clean_fp,
        "total_cost_usd": sum(costs) if costs else None,
        "mean_seconds": (sum(secs) / len(secs)) if secs else None,
        "stale": [],
    }


def current_prompt_sha256(root: Path) -> str:
    p = root / "prompts" / "review.md"
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ""


def current_forge_ref(root: Path) -> str:
    wf = root / ".github" / "workflows" / "review.yml"
    if not wf.is_file():
        return ""
    return check_pins._extract_env_map(wf.read_text(encoding="utf-8")).get("FORGE_REF", "")


def check_freshness(root: Path, rec_dir: Path) -> list[str]:
    meta_path = rec_dir / "meta.json"
    if not meta_path.is_file():
        return ["meta.json missing"]
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("engine") == "reference":
        return []
    changes: list[str] = []
    prompt_sha = current_prompt_sha256(root)
    forge_ref = current_forge_ref(root)
    if prompt_sha and meta.get("prompt_sha256") != prompt_sha:
        changes.append("prompts/review.md")
    if forge_ref and meta.get("forge_ref") != forge_ref:
        changes.append("FORGE_REF")
    return changes


def _format_scorecard(cards: list[dict[str, Any]]) -> str:
    out: list[str] = []
    for card in cards:
        out.append(f"## Eval scorecard: {card['label']}")
        out.append("")
        out.append("| case | expected | hit | missed labels | false positives | cost | seconds |")
        out.append("|---|---:|---:|---|---:|---:|---:|")
        for r in card["cases"]:
            missed = ", ".join(r["missed"]) if r["missed"] else "-"
            if r["underrated"]:
                notes = ", ".join(f"{u['label']}({u['got']}<{u['expected']})" for u in r["underrated"])
                missed = f"{missed}; underrated: {notes}" if missed != "-" else f"underrated: {notes}"
            cost_s = f"${r['cost_usd']:.4f}" if r["cost_usd"] is not None else "n/a"
            sec_s = f"{r['seconds']:.1f}" if r["seconds"] is not None else "n/a"
            out.append(
                f"| {r['case']} | {r['expected']} | {r['hit']} | {missed} | {r['false_positives']} | {cost_s} | {sec_s} |"
            )
        tcost = f"${card['total_cost_usd']:.4f}" if card["total_cost_usd"] is not None else "n/a"
        msec = f"{card['mean_seconds']:.1f}s" if card["mean_seconds"] is not None else "n/a"
        out.append("")
        out.append(
            f"**Totals (`{card['label']}`):** recall {card['recall']:.2f} ({card['hit']}/{card['expected']}), "
            f"precision {card['precision']:.2f}, clean false positives {card['clean_false_positives']}, "
            f"total cost {tcost}, mean seconds {msec}"
        )
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _cmd_lint(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    errors = lint_cases(root, args.cases)
    for err in errors:
        print(f"::error::{err}")
    if not errors:
        count = len(_case_names(root, args.cases))
        print(f"eval lint: {count} case(s) valid")
    return 1 if errors else 0


def _score_targets(
    root: Path,
    targets: list[tuple[str, Path, bool]],
    case_names: list[str],
    *,
    min_recall: float,
    max_clean_fp: int,
    check_fresh: bool,
    strict_fresh: bool,
    as_json: bool,
) -> int:
    cards: list[dict[str, Any]] = []
    failed = False
    warnings: list[str] = []

    for label, fdir, is_recorded in targets:
        card = score_directory(root, label, fdir, case_names)
        if is_recorded and (check_fresh or strict_fresh):
            stale = check_freshness(root, fdir)
            card["stale"] = stale
            if stale:
                msg = (
                    f'::warning::recorded evals "{label}" are stale: {", ".join(stale)}; '
                    f"re-record with eval.py run --record {label}"
                )
                warnings.append(msg)
                if strict_fresh:
                    failed = True
        if card["recall"] < min_recall or card["clean_false_positives"] > max_clean_fp:
            failed = True
        cards.append(card)

    for w in warnings:
        print(w)

    if as_json:
        print(json.dumps({"labels": cards}, indent=2))
    else:
        print(_format_scorecard(cards), end="")
    return 1 if failed else 0


def _cmd_score(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    try:
        case_names = _case_names(root, args.cases)
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    if not case_names:
        print("::notice::no eval cases to score")
        return 0

    targets: list[tuple[str, Path, bool]] = []
    if args.findings_dir:
        fdir = Path(args.findings_dir).resolve()
        if not fdir.is_dir():
            print(f"::error::findings directory not found: {fdir}", file=sys.stderr)
            return 1
        targets.append((fdir.name, fdir, False))
    else:
        rec_root = root / "evals" / "recorded"
        if args.recorded == "all":
            if rec_root.is_dir():
                for child in sorted(rec_root.iterdir()):
                    if child.is_dir():
                        targets.append((child.name, child, True))
        else:
            child = rec_root / args.recorded
            if not child.is_dir():
                print(f"::error::recorded label not found: {args.recorded}", file=sys.stderr)
                return 1
            targets.append((args.recorded, child, True))

    if not targets:
        print("::notice::no eval recordings to score")
        return 0

    try:
        return _score_targets(
            root,
            targets,
            case_names,
            min_recall=args.min_recall,
            max_clean_fp=args.max_clean_fp,
            check_fresh=args.check_fresh,
            strict_fresh=args.strict_fresh,
            as_json=args.as_json,
        )
    except FileNotFoundError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1


def _cmd_run(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    try:
        case_names = _case_names(root, args.cases)
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    if not case_names:
        print("::notice::no eval cases selected")
        return 0

    forge_dir = Path(args.forge).resolve()
    findings_lib = forge_dir / "skills" / "review" / "scripts" / "findings.py"
    if not findings_lib.is_file():
        print(f"::error::findings library not found: {findings_lib}", file=sys.stderr)
        return 1

    tmp_ctx = None if args.out else tempfile.TemporaryDirectory(prefix="prg-eval-run-")
    out_dir = Path(args.out).resolve() if args.out else Path(tmp_ctx.name)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        for name in case_names:
            cdir = root / "evals" / "cases" / name
            case = json.loads((cdir / "case.json").read_text(encoding="utf-8"))
            diff_text = (cdir / "diff.patch").read_text(encoding="utf-8")
            touched = sorted(_patch_touched_files(diff_text))

            with tempfile.TemporaryDirectory(prefix=f"prg-eval-tree-{name}-") as tdir:
                sandbox = Path(tdir)
                tree = sandbox / "tree"
                tree.mkdir()
                materialise_case(case, diff_text, tree)
                meta = {
                    "title": case["title"],
                    "body": case["description"],
                    "author": {"login": "eval"},
                    "baseRefName": "main",
                    "headRefName": "eval",
                    "changedFiles": len(touched),
                    "files": [
                        {
                            "filename": p,
                            "status": "modified" if p in case["files"] else "added",
                            "additions": 1,
                            "deletions": 0,
                        }
                        for p in touched
                    ],
                }
                ctx_md = build_context.build(
                    repo=f"evals/{name}",
                    pr=0,
                    scan=None,
                    collector=None,
                    meta=meta,
                    diff=diff_text,
                    prior=st.empty_state(),
                    threads=[],
                )
                ctx_path = sandbox / "context.md"
                triage_path = sandbox / "triage.json"
                ctx_path.write_text(ctx_md, encoding="utf-8")
                triage_path.write_text(json.dumps({"skip_model": False, "reason": "eval"}), encoding="utf-8")

                f_out = out_dir / f"{name}.findings.json"
                u_out = out_dir / f"{name}.usage.json"
                rm_argv = [
                    "run_model.py",
                    "--context",
                    str(ctx_path),
                    "--triage",
                    str(triage_path),
                    "--findings-lib",
                    str(findings_lib),
                    "--out",
                    str(f_out),
                    "--usage-out",
                    str(u_out),
                    "--workdir",
                    str(tree),
                ]
                if args.model:
                    rm_argv += ["--model", args.model]

                with mock.patch.dict(os.environ, {"PRG_ENGINES": args.engine}), mock.patch.object(sys, "argv", rm_argv):
                    rc = run_model.main()
                if rc not in (0, None):
                    print(f"::error::run_model failed on case {name} (exit {rc})", file=sys.stderr)
                    return 1

        if args.record:
            rec_dir = root / "evals" / "recorded" / args.record
            rec_dir.mkdir(parents=True, exist_ok=True)
            for name in case_names:
                shutil.copy2(out_dir / f"{name}.findings.json", rec_dir / f"{name}.findings.json")
                u_src = out_dir / f"{name}.usage.json"
                if u_src.is_file():
                    shutil.copy2(u_src, rec_dir / f"{name}.usage.json")
            meta_obj = {
                "engine": args.engine,
                "model": args.model or f"{args.engine}-default",
                "forge_ref": current_forge_ref(root),
                "prompt_sha256": current_prompt_sha256(root),
                "recorded_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            (rec_dir / "meta.json").write_text(json.dumps(meta_obj, indent=2) + "\n", encoding="utf-8")

        return _score_targets(
            root,
            [(args.record or out_dir.name, out_dir, False)],
            case_names,
            min_recall=args.min_recall,
            max_clean_fp=args.max_clean_fp,
            check_fresh=False,
            strict_fresh=False,
            as_json=args.as_json,
        )
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Golden eval harness for pr-guardian.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_lint = sub.add_parser("lint", help="Validate eval cases, patches, and line ranges.")
    p_lint.add_argument("--cases", default=None)
    p_lint.add_argument("--root", default=os.getcwd())

    p_score = sub.add_parser("score", help="Score findings against expected defects.")
    p_score.add_argument("--recorded", default="all")
    p_score.add_argument("--findings-dir", default=None)
    p_score.add_argument("--cases", default=None)
    p_score.add_argument("--min-recall", type=float, default=0.8)
    p_score.add_argument("--max-clean-fp", type=int, default=0)
    p_score.add_argument("--check-fresh", action="store_true")
    p_score.add_argument("--strict-fresh", action="store_true")
    p_score.add_argument("--json", action="store_true", dest="as_json")
    p_score.add_argument("--root", default=os.getcwd())

    p_run = sub.add_parser("run", help="Run the model across eval cases and score.")
    p_run.add_argument("--engine", required=True, choices=("agy", "claude"))
    p_run.add_argument("--forge", required=True)
    p_run.add_argument("--model", default=None)
    p_run.add_argument("--cases", default=None)
    p_run.add_argument("--record", default=None)
    p_run.add_argument("--out", default=None)
    p_run.add_argument("--min-recall", type=float, default=0.8)
    p_run.add_argument("--max-clean-fp", type=int, default=0)
    p_run.add_argument("--json", action="store_true", dest="as_json")
    p_run.add_argument("--root", default=os.getcwd())

    args = ap.parse_args(argv)
    if args.cmd == "lint":
        return _cmd_lint(args)
    if args.cmd == "score":
        return _cmd_score(args)
    return _cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
