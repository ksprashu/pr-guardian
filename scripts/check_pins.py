#!/usr/bin/env python3
"""Verify supply-chain and skill-forge pins across workflows and installers."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import gh  # noqa: E402

SHA40_RE = re.compile(r"\A[0-9a-f]{40}\Z")
SHA128_RE = re.compile(r"\A[0-9a-f]{128}\Z")
REPO_RE = re.compile(r"\A[\w.-]+/[\w.-]+\Z")
SEMVER_RE = re.compile(r"\A\d+\.\d+\.\d+\Z")
EXACT_NPM_RE = re.compile(r"\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")
AGY_STORAGE_PREFIX = "https://storage.googleapis.com/antigravity-public/antigravity-cli/"
HASH64_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}(?=\s|$)")


def _norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _strip_comment(val: str) -> str:
    # Strip inline YAML/shell comments when outside quotes, then surrounding quotes.
    s = val.strip()
    if s and s[0] in ('"', "'"):
        q = s[0]
        end = s.find(q, 1)
        if end != -1:
            return s[1:end].strip()
    return s.split("#", 1)[0].strip().strip("'\"")


def _extract_env_map(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$", line)
        if m:
            out.setdefault(m.group(1), _strip_comment(m.group(2)))
    return out


def _extract_shell_vars(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Handle single-line semicolon assignments too if present
        for stmt in stripped.split(";"):
            m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.+?)\s*$", stmt)
            if m:
                out[m.group(1)] = _strip_comment(m.group(2))
    return out


def _logical_req_lines(text: str) -> list[str]:
    entries: list[str] = []
    cur = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            if cur:
                entries.append(cur)
                cur = ""
            continue
        # Strip inline comment unless inside --hash=... (comments don't start with --)
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if line.endswith("\\"):
            cur = f"{cur} {line[:-1].rstrip()}".strip()
        else:
            cur = f"{cur} {line}".strip()
            entries.append(cur)
            cur = ""
    if cur:
        entries.append(cur)
    return entries


def _parse_req_spec(entry: str) -> tuple[str, str] | None:
    head = entry.split("--", 1)[0].split(";", 1)[0].strip()
    if "==" not in head:
        return None
    name, ver = head.split("==", 1)
    name = name.split("[", 1)[0].strip()
    ver = ver.strip()
    if not name or not ver:
        return None
    return _norm_pkg(name), ver


def _version_matches(in_ver: str, txt_ver: str) -> bool:
    if in_ver == txt_ver:
        return True
    if in_ver.endswith(".*"):
        prefix = in_ver[:-2]
        return txt_ver == prefix or txt_ver.startswith(prefix + ".")
    return False


def _check_review_pins(root: Path, errors: list[str]) -> tuple[str, str]:
    p = root / ".github" / "workflows" / "review.yml"
    if not p.is_file():
        errors.append("missing .github/workflows/review.yml")
        return "", ""
    env_map = _extract_env_map(p.read_text(encoding="utf-8"))
    forge_ref = env_map.get("FORGE_REF", "")
    forge_repo = env_map.get("FORGE_REPO", "")
    if not SHA40_RE.fullmatch(forge_ref):
        errors.append(f"review.yml FORGE_REF is not a 40-char lowercase SHA: {forge_ref!r}")
    if not REPO_RE.fullmatch(forge_repo):
        errors.append(f"review.yml FORGE_REPO is invalid: {forge_repo!r}")
    return forge_repo, forge_ref


def _check_workflow_uses(root: Path, errors: list[str]) -> None:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        errors.append("missing .github/workflows directory")
        return
    for wf in sorted(wf_dir.glob("*.yml")):
        for lineno, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = re.match(r"^(?:-\s*)?uses:\s*(.+)$", stripped)
            if not m:
                continue
            target = _strip_comment(m.group(1))
            if target.startswith("./"):
                continue
            if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", target):
                errors.append(f"{wf.relative_to(root)}:{lineno}: unpinned uses target {target!r}")


def _check_install_scanners(root: Path, errors: list[str]) -> None:
    p = root / "scripts" / "install_scanners.sh"
    if not p.is_file():
        errors.append("missing scripts/install_scanners.sh")
        return
    pip_lines: list[tuple[int, str]] = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.search(r"\bpip3?\s+install\b", stripped):
            pip_lines.append((lineno, stripped))
    if not pip_lines:
        errors.append("scripts/install_scanners.sh has no pip install command")
        return
    for lineno, cmd in pip_lines:
        if "--require-hashes" not in cmd:
            errors.append(f"scripts/install_scanners.sh:{lineno}: pip install missing --require-hashes")
        if "--only-binary=:all:" not in cmd:
            errors.append(f"scripts/install_scanners.sh:{lineno}: pip install missing --only-binary=:all:")


def _check_requirements(root: Path, errors: list[str]) -> None:
    scripts_dir = root / "scripts"
    txts = sorted(scripts_dir.glob("requirements-*.txt")) if scripts_dir.is_dir() else []
    if not txts:
        errors.append("no scripts/requirements-*.txt lockfiles found")
        return
    for txt_path in txts:
        rel = txt_path.relative_to(root)
        entries = _logical_req_lines(txt_path.read_text(encoding="utf-8"))
        if not entries:
            errors.append(f"{rel}: lockfile is empty")
            continue
        pinned: dict[str, str] = {}
        for entry in entries:
            parsed = _parse_req_spec(entry)
            if parsed is None:
                errors.append(f"{rel}: requirement without == pin: {entry.split()[0]!r}")
                continue
            pkg, ver = parsed
            pinned[pkg] = ver
            if not HASH64_RE.search(entry):
                errors.append(f"{rel}: {pkg}=={ver} lacks a valid --hash=sha256:<64 hex>")
        in_path = txt_path.with_suffix(".in")
        if in_path.is_file():
            in_rel = in_path.relative_to(root)
            for entry in _logical_req_lines(in_path.read_text(encoding="utf-8")):
                parsed = _parse_req_spec(entry)
                if parsed is None:
                    errors.append(f"{in_rel}: input requirement without == pin: {entry!r}")
                    continue
                pkg, in_ver = parsed
                if pkg not in pinned:
                    errors.append(f"{rel}: missing pin for {in_rel} entry {pkg}=={in_ver}")
                elif not _version_matches(in_ver, pinned[pkg]):
                    errors.append(
                        f"{rel}: version mismatch for {pkg}: .in asks {in_ver}, .txt has {pinned[pkg]}"
                    )


def _check_install_agy(root: Path, errors: list[str]) -> tuple[str, str, str]:
    p = root / "scripts" / "install_agy.sh"
    if not p.is_file():
        errors.append("missing scripts/install_agy.sh")
        return "", "", ""
    vars_map = _extract_shell_vars(p.read_text(encoding="utf-8"))
    ver = vars_map.get("AGY_VERSION", "")
    url = vars_map.get("AGY_URL", "")
    sha = vars_map.get("AGY_SHA512", "")
    manifest = vars_map.get("AGY_MANIFEST", "")
    if not SEMVER_RE.fullmatch(ver):
        errors.append(f"scripts/install_agy.sh AGY_VERSION is invalid: {ver!r}")
    if not url.startswith(AGY_STORAGE_PREFIX):
        errors.append(f"scripts/install_agy.sh AGY_URL must start with {AGY_STORAGE_PREFIX!r}")
    if ver and f"/{ver}-" not in url:
        errors.append(f"scripts/install_agy.sh AGY_URL does not contain '/{ver}-'")
    if not SHA128_RE.fullmatch(sha):
        errors.append("scripts/install_agy.sh AGY_SHA512 must be 128 lowercase hex chars")
    return ver, url, manifest


def _check_claude_package(root: Path, errors: list[str]) -> None:
    cc_dir = root / "config" / "claude-code"
    pkg_json = cc_dir / "package.json"
    lock_json = cc_dir / "package-lock.json"
    if not pkg_json.is_file():
        errors.append("missing config/claude-code/package.json")
        return
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except ValueError as exc:
        errors.append(f"config/claude-code/package.json is invalid JSON: {exc}")
        return
    deps: dict[str, object] = {}
    for section in ("dependencies", "devDependencies"):
        sec = data.get(section)
        if isinstance(sec, dict):
            deps.update(sec)
    if not deps:
        errors.append("config/claude-code/package.json has no pinned dependencies")
    for name, spec in deps.items():
        if not isinstance(spec, str) or not EXACT_NPM_RE.fullmatch(spec):
            errors.append(f"config/claude-code/package.json: {name} is not an exact version: {spec!r}")
    if not lock_json.is_file():
        errors.append("missing config/claude-code/package-lock.json")


def _https_request(url: str, method: str = "GET", timeout: int = 10) -> tuple[int, bytes]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"non-https URL refused: {url!r}")
    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        status = getattr(resp, "status", 200)
        body = b"" if method == "HEAD" else resp.read()
        return int(status), body


def _run_online_checks(forge_repo: str, forge_ref: str, agy_ver: str, agy_url: str, agy_manifest: str) -> list[str]:
    warnings: list[str] = []
    if forge_repo and forge_ref:
        default_branch = "main"
        try:
            repo_meta = gh.api(f"repos/{forge_repo}")
            if isinstance(repo_meta, dict) and isinstance(repo_meta.get("default_branch"), str):
                default_branch = repo_meta["default_branch"] or "main"
            cmp = gh.api(f"repos/{forge_repo}/compare/{forge_ref}...{default_branch}")
            if not isinstance(cmp, dict):
                warnings.append(f"::warning::FORGE_REF {forge_ref[:12]} compare returned unexpected payload")
            else:
                status = cmp.get("status")
                if status not in ("ahead", "identical"):
                    behind = cmp.get("behind_by", "?")
                    warnings.append(
                        f"::warning::FORGE_REF {forge_ref[:12]} is not reachable from {forge_repo}@{default_branch} "
                        f"(status={status}, behind_by={behind})"
                    )
                else:
                    ahead_by = cmp.get("ahead_by", 0)
                    if isinstance(ahead_by, int) and ahead_by > 0:
                        warnings.append(f"::notice::FORGE_REF is {ahead_by} commits behind {default_branch}")
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"::warning::online FORGE_REF check failed for {forge_repo}: {exc}")

    if agy_manifest and agy_ver:
        try:
            _status, raw = _https_request(agy_manifest, method="GET", timeout=10)
            manifest = json.loads(raw.decode("utf-8"))
            latest_ver = manifest.get("version") if isinstance(manifest, dict) else None
            if isinstance(latest_ver, str) and latest_ver and latest_ver != agy_ver:
                warnings.append(f"::warning::agy pin {agy_ver} is behind current {latest_ver}")
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"::warning::online agy manifest check failed: {exc}")

    if agy_url:
        try:
            status, _ = _https_request(agy_url, method="HEAD", timeout=10)
            if status != 200:
                warnings.append(f"::warning::pinned agy build is no longer downloadable (HTTP {status})")
        except urllib.error.HTTPError as exc:
            warnings.append(f"::warning::pinned agy build is no longer downloadable (HTTP {exc.code})")
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"::warning::online agy HEAD check failed: {exc}")

    return warnings


def check_all(root: Path, online: bool = False) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    forge_repo, forge_ref = _check_review_pins(root, errors)
    _check_workflow_uses(root, errors)
    _check_install_scanners(root, errors)
    _check_requirements(root, errors)
    agy_ver, agy_url, agy_manifest = _check_install_agy(root, errors)
    _check_claude_package(root, errors)
    notes = _run_online_checks(forge_repo, forge_ref, agy_ver, agy_url, agy_manifest) if online else []
    return errors, notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify supply-chain and skill-forge pins.")
    ap.add_argument("--online", action="store_true", help="Also check forge reachability and agy release drift.")
    ap.add_argument("--root", default=os.getcwd(), help="Repository root directory.")
    args = ap.parse_args(argv)

    errors, notes = check_all(Path(args.root), online=args.online)
    for err in errors:
        print(f"::error::{err}")
    for note in notes:
        print(note)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
