"""Load, parse, and validate `.github/pr-guardian.yml` from the PR base ref.

Stdlib only (CI runs unit tests without PyYAML). All config, guidelines, and
pattern matching follow strict provenance and fail-closed rules:

  - Config is read ONLY from the base commit/ref (`git cat-file` or GitHub API
    at `base_sha`/`base_ref`), never from the untrusted PR head worktree.
  - Only a deterministic YAML/JSON subset is accepted; tabs, anchors/aliases,
    tags, merge keys, multi-document streams, and duplicate keys fail closed.
  - Security-sensitive paths (`.github/workflows/`, `.github/actions/`,
    instruction files, and lockfiles) are non-bypassable regardless of config.
"""

from __future__ import annotations

import base64
import binascii
import functools
import json
import math
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Sequence

import gh
from textsafe import clean

CONFIG_PATH = ".github/pr-guardian.yml"
MAX_CONFIG_BYTES = 64 * 1024
VALID_BLOCKING = ("P0", "P1", "P2", "P3")
VALID_ENGINES = ("agy", "claude")
VALID_VERIFIER_MODES = ("off", "self", "cross", "auto")
MODEL_SLUG_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
SAFE_REF_RE = re.compile(r"\A(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,256}\Z")
_KEY_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_-]*\Z")
_INT_RE = re.compile(r"-?(?:0|[1-9][0-9_]*)")
_FLOAT_RE = re.compile(r"-?(?:0|[1-9][0-9_]*)\.[0-9_]+")

# Security non-bypassable lockfiles (GHSA-pp8w-8p9r-5f43): never treated as docs or ignored.
LOCKFILE_NAMES = frozenset({
    "uv.lock", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
    "yarn.lock", "poetry.lock", "pipfile.lock", "cargo.lock", "go.sum",
    "gemfile.lock", "composer.lock", "flake.lock", "pubspec.lock",
    "gradle.lockfile", "packages.lock.json",
})


class ConfigError(ValueError):
    """Raised when .github/pr-guardian.yml has invalid YAML syntax or schema values."""


def default_config() -> dict[str, Any]:
    return {
        "block_on": ["P0", "P1", "P2", "P3"],
        "ignore_paths": [],
        "docs_paths": [],
        "round_cap": 6,
        "reopen_escalation": 3,
        "diff_budget": 160_000,
        "per_file_budget": 16_000,
        "leads_budget": 150,
        "max_changed_lines": 25_000,
        "max_pr_cost_usd": 10.0,
        "engines": ["agy", "claude"],
        "verifier": "off",
        "chunk_threshold_chars": 160_000,
        "max_chunks": 4,
        "extra_instructions": "",
    }


def _segments(path: Any) -> list[str] | None:
    """A repo path as its segments, or None when it is not a plain relative file path."""
    if not isinstance(path, str) or not path or path.startswith(("/", "\\")) or path.endswith(("/", "\\")):
        return None
    if "\x00" in path or re.match(r"^[A-Za-z]:", path):
        return None
    segs = [s for s in path.replace("\\", "/").split("/") if s not in ("", ".")]
    if not segs or ".." in segs:
        return None
    return segs


def _is_safe_ref(ref: str) -> bool:
    return (isinstance(ref, str) and bool(SAFE_REF_RE.match(ref))
            and not ref.startswith("/") and not ref.endswith("/") and "//" not in ref)


def _reject_nonfinite(token: str) -> Any:
    raise ConfigError(f"non-finite JSON constant {token!r}")


def _no_dup_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ConfigError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _leading_indent(line: str, lineno: int) -> tuple[int, str]:
    """Count leading spaces, rejecting any tab character in leading whitespace."""
    i = 0
    n = len(line)
    while i < n and line[i] in (" ", "\t"):
        if line[i] == "\t":
            raise ConfigError(f"line {lineno}: tab indentation is not allowed")
        i += 1
    return i, line[i:]


def _strip_comment(text: str, lineno: int) -> str:
    """Strip an inline `# ...` comment outside quotes, rejecting unclosed quotes."""
    in_dq = False
    in_sq = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_dq:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_dq = False
        elif in_sq:
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                in_sq = False
        else:
            if ch == '"':
                in_dq = True
            elif ch == "'":
                in_sq = True
            elif ch == "#" and (i == 0 or text[i - 1].isspace()):
                return text[:i].rstrip()
        i += 1
    if in_dq or in_sq:
        raise ConfigError(f"line {lineno}: unclosed quote")
    return text.rstrip()


def _parse_quoted(raw: str, lineno: int) -> tuple[str, str]:
    """Parse a leading single- or double-quoted scalar and return (value, rest)."""
    quote = raw[0]
    if quote == '"':
        i = 1
        n = len(raw)
        while i < n:
            ch = raw[i]
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                token = raw[:i + 1]
                try:
                    val = json.loads(token)
                except json.JSONDecodeError as exc:
                    raise ConfigError(f"line {lineno}: invalid double-quoted string: {exc}") from exc
                return val, raw[i + 1:]
            i += 1
        raise ConfigError(f"line {lineno}: unclosed double quote")

    # Single-quoted YAML string: only '' escapes a single quote.
    i = 1
    n = len(raw)
    chars: list[str] = []
    while i < n:
        ch = raw[i]
        if ch == "'":
            if i + 1 < n and raw[i + 1] == "'":
                chars.append("'")
                i += 2
                continue
            return "".join(chars), raw[i + 1:]
        chars.append(ch)
        i += 1
    raise ConfigError(f"line {lineno}: unclosed single quote")


def _parse_scalar(raw: str, lineno: int) -> Any:
    s = raw.strip()
    if not s:
        return None
    if s[0] in ('"', "'"):
        val, rest = _parse_quoted(s, lineno)
        if rest.strip():
            raise ConfigError(f"line {lineno}: unexpected trailing text after quoted string: {rest.strip()!r}")
        return val
    if s[0] in ("&", "*", "!", "{", "["):
        raise ConfigError(f"line {lineno}: unsupported YAML syntax near {s[:24]!r}")
    if s in ("null", "~"):
        return None
    if s == "true":
        return True
    if s == "false":
        return False
    if _INT_RE.fullmatch(s):
        if s.endswith("_") or "__" in s or s.startswith("-_"):
            raise ConfigError(f"line {lineno}: malformed integer {s!r}")
        return int(s.replace("_", ""))
    if _FLOAT_RE.fullmatch(s):
        if s.endswith("_") or "__" in s or "._" in s or "_." in s or s.startswith("-_"):
            raise ConfigError(f"line {lineno}: malformed float {s!r}")
        val = float(s.replace("_", ""))
        if not math.isfinite(val):
            raise ConfigError(f"line {lineno}: non-finite float {s!r}")
        return val
    return s


def _parse_flow_list(raw: str, lineno: int) -> list[Any]:
    s = raw.strip()
    assert s.startswith("[")
    in_dq = False
    in_sq = False
    close_idx = -1
    i = 1
    n = len(s)
    while i < n:
        ch = s[i]
        if in_dq:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_dq = False
        elif in_sq:
            if ch == "'":
                if i + 1 < n and s[i + 1] == "'":
                    i += 2
                    continue
                in_sq = False
        else:
            if ch == '"':
                in_dq = True
            elif ch == "'":
                in_sq = True
            elif ch in ("[", "{"):
                raise ConfigError(f"line {lineno}: nested flow structures are not supported")
            elif ch == "]":
                close_idx = i
                break
        i += 1
    if close_idx == -1:
        raise ConfigError(f"line {lineno}: unclosed flow list '['")
    trailing = s[close_idx + 1:].strip()
    if trailing:
        raise ConfigError(f"line {lineno}: unexpected trailing text after flow list: {trailing!r}")

    inner = s[1:close_idx]
    if not inner.strip():
        return []

    items: list[str] = []
    start = 0
    in_dq = False
    in_sq = False
    i = 0
    m = len(inner)
    while i < m:
        ch = inner[i]
        if in_dq:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_dq = False
        elif in_sq:
            if ch == "'":
                if i + 1 < m and inner[i + 1] == "'":
                    i += 2
                    continue
                in_sq = False
        else:
            if ch == '"':
                in_dq = True
            elif ch == "'":
                in_sq = True
            elif ch == ",":
                part = inner[start:i].strip()
                if not part:
                    raise ConfigError(f"line {lineno}: empty item in flow list")
                items.append(part)
                start = i + 1
        i += 1
    last = inner[start:].strip()
    if not last:
        raise ConfigError(f"line {lineno}: trailing comma or empty item in flow list")
    items.append(last)
    return [_parse_scalar(item, lineno) for item in items]


def _split_mapping_entry(content: str, lineno: int) -> tuple[str, str]:
    """Split `key: value` on the first colon followed by whitespace or EOL."""
    if content.startswith(("'", '"')):
        key, rest = _parse_quoted(content, lineno)
        rest_l = rest.lstrip(" ")
        if not rest_l.startswith(":"):
            raise ConfigError(f"line {lineno}: expected ':' after key {key!r}")
        after = rest_l[1:]
        if after and not after[0].isspace():
            raise ConfigError(f"line {lineno}: expected space after ':' for key {key!r}")
        if not key:
            raise ConfigError(f"line {lineno}: empty key")
        return key, after.strip()

    in_dq = False
    in_sq = False
    colon_idx = -1
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if in_dq:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_dq = False
        elif in_sq:
            if ch == "'":
                if i + 1 < n and content[i + 1] == "'":
                    i += 2
                    continue
                in_sq = False
        else:
            if ch == '"':
                in_dq = True
            elif ch == "'":
                in_sq = True
            elif ch == ":" and (i + 1 == n or content[i + 1] == " "):
                colon_idx = i
                break
            elif ch == ":" and i + 1 < n and content[i + 1] == "\t":
                raise ConfigError(f"line {lineno}: tab after ':' is not allowed")
        i += 1
    if colon_idx <= 0:
        raise ConfigError(f"line {lineno}: expected 'key: value' mapping entry")
    key = content[:colon_idx].strip()
    if key == "<<":
        raise ConfigError(f"line {lineno}: YAML merge key '<<' is not supported")
    if not _KEY_RE.match(key):
        raise ConfigError(f"line {lineno}: invalid key {key!r}")
    return key, content[colon_idx + 1:].strip()


def _parse_block_scalar(lines: list[str], idx: int, key_indent: int, style: str) -> tuple[str, int]:
    """Consume a `|`, `|-`, `>`, `>-` (or `+`) block scalar starting after `idx`."""
    folded = style.startswith(">")
    chomp = style[1:]  # "", "-", or "+"
    collected: list[tuple[int, str]] = []
    n = len(lines)
    j = idx + 1
    while j < n:
        raw = lines[j]
        if not raw.strip():
            # Preserve blank lines inside block; disallow leading tabs before key_indent.
            if "\t" in raw[:key_indent + 1]:
                raise ConfigError(f"line {j + 1}: tab indentation is not allowed")
            collected.append((-1, raw))
            j += 1
            continue
        spaces = 0
        while spaces < len(raw) and raw[spaces] == " ":
            spaces += 1
        if spaces < len(raw) and raw[spaces] == "\t" and spaces <= key_indent:
            raise ConfigError(f"line {j + 1}: tab indentation is not allowed")
        if spaces <= key_indent:
            break
        collected.append((spaces, raw))
        j += 1

    non_empty = [ind for ind, _ in collected if ind >= 0]
    if not non_empty:
        return "", j

    block_indent = min(non_empty)
    # Trim trailing blank lines (only kept under '+' chomping).
    trailing_blanks = 0
    while collected and collected[-1][0] < 0:
        collected.pop()
        trailing_blanks += 1

    rel_lines: list[str] = []
    for ind, raw in collected:
        if ind < 0:
            rel_lines.append("")
        else:
            rel_lines.append(raw[block_indent:])

    if not folded:
        body = "\n".join(rel_lines)
    else:
        parts: list[str] = []
        k = 0
        m = len(rel_lines)
        prev_nonblank: str | None = None
        while k < m:
            line = rel_lines[k]
            if line == "":
                blanks = 0
                while k < m and rel_lines[k] == "":
                    blanks += 1
                    k += 1
                if prev_nonblank is None:
                    parts.append("\n" * blanks)
                elif k < m:
                    nxt = rel_lines[k]
                    extra = 1 if (prev_nonblank.startswith((" ", "\t")) or nxt.startswith((" ", "\t"))) else 0
                    parts.append("\n" * (blanks + extra))
                continue
            if prev_nonblank is not None and not parts[-1].endswith("\n"):
                if prev_nonblank.startswith((" ", "\t")) or line.startswith((" ", "\t")):
                    parts.append("\n")
                else:
                    parts.append(" ")
            parts.append(line)
            prev_nonblank = line
            k += 1
        body = "".join(parts)

    if chomp == "-":
        return body, j
    if chomp == "+":
        return body + "\n" * (1 + trailing_blanks), j
    return body + "\n", j


def _skip_ignored(lines: list[str], idx: int, *, seen_content: bool) -> int:
    n = len(lines)
    while idx < n:
        raw = lines[idx]
        if not raw.strip():
            idx += 1
            continue
        indent, content = _leading_indent(raw, idx + 1)
        if content.startswith("#"):
            idx += 1
            continue
        if indent == 0:
            cleaned = _strip_comment(content, idx + 1).strip()
            if cleaned == "...":
                raise ConfigError(f"line {idx + 1}: document end marker '...' is not allowed")
            if cleaned == "---":
                if seen_content:
                    raise ConfigError(f"line {idx + 1}: multi-document '---' is not allowed")
                seen_content = True
                idx += 1
                continue
        break
    return idx


def _parse_block_sequence(lines: list[str], idx: int, key_indent: int) -> tuple[list[Any], int]:
    """Parse consecutive `- <scalar>` lines starting at `idx`."""
    items: list[Any] = []
    seq_indent: int | None = None
    n = len(lines)
    while idx < n:
        raw = lines[idx]
        if not raw.strip():
            idx += 1
            continue
        indent, content = _leading_indent(raw, idx + 1)
        if content.startswith("#"):
            idx += 1
            continue
        if indent == 0:
            cleaned_top = _strip_comment(content, idx + 1).strip()
            if cleaned_top in ("---", "..."):
                raise ConfigError(f"line {idx + 1}: document marker {cleaned_top!r} is not allowed")
        if indent < key_indent:
            break
        if seq_indent is not None:
            if indent < seq_indent:
                if indent == key_indent and not content.startswith("-"):
                    break
                raise ConfigError(f"line {idx + 1}: inconsistent list indentation")
            if indent > seq_indent:
                raise ConfigError(f"line {idx + 1}: inconsistent list indentation")
        if content.startswith("-\t"):
            raise ConfigError(f"line {idx + 1}: tab after '-' is not allowed")
        if not (content == "-" or content.startswith("- ") or content.startswith("-#")):
            if indent == key_indent:
                break
            raise ConfigError(f"line {idx + 1}: expected list item '-'")
        if seq_indent is None:
            seq_indent = indent
        after_dash = _strip_comment(content[1:], idx + 1).strip()
        if after_dash.startswith("["):
            items.append(_parse_flow_list(after_dash, idx + 1))
        else:
            items.append(_parse_scalar(after_dash, idx + 1))
        idx += 1
    return items, idx


def _parse_mapping(lines: list[str], idx: int, expected_indent: int, *, allow_nested: bool) -> tuple[dict[str, Any], int]:
    out: dict[str, Any] = {}
    n = len(lines)
    seen_doc_start = False
    while idx < n:
        if expected_indent == 0 and not out and not seen_doc_start:
            # Handle optional leading `---` once before top-level keys.
            j = idx
            while j < n:
                raw = lines[j]
                if not raw.strip():
                    j += 1
                    continue
                indent, content = _leading_indent(raw, j + 1)
                if content.startswith("#"):
                    j += 1
                    continue
                cleaned = _strip_comment(content, j + 1).strip()
                if indent == 0 and cleaned == "---":
                    seen_doc_start = True
                    j += 1
                    continue
                break
            idx = j
        idx = _skip_ignored(lines, idx, seen_content=bool(out) or seen_doc_start or expected_indent > 0)
        if idx >= n:
            break
        indent, content = _leading_indent(lines[idx], idx + 1)
        if indent < expected_indent:
            break
        if indent > expected_indent:
            raise ConfigError(f"line {idx + 1}: unexpected indentation")

        cleaned = _strip_comment(content, idx + 1)
        if not cleaned:
            idx += 1
            continue
        key, val_raw = _split_mapping_entry(cleaned, idx + 1)
        if key in out:
            raise ConfigError(f"line {idx + 1}: duplicate key {key!r}")

        if val_raw in ("|", "|-", "|+", ">", ">-", ">+"):
            val, idx = _parse_block_scalar(lines, idx, indent, val_raw)
            out[key] = val
            continue

        if val_raw == "":
            nxt = _skip_ignored(lines, idx + 1, seen_content=True)
            if nxt >= n:
                out[key] = None
                idx = nxt
                continue
            nxt_indent, nxt_content = _leading_indent(lines[nxt], nxt + 1)
            if nxt_content.startswith("-\t"):
                raise ConfigError(f"line {nxt + 1}: tab after '-' is not allowed")
            is_dash = nxt_content == "-" or nxt_content.startswith("- ")
            if nxt_indent >= indent and is_dash:
                out[key], idx = _parse_block_sequence(lines, nxt, indent)
                continue
            if nxt_indent > indent:
                if not allow_nested:
                    raise ConfigError(f"line {nxt + 1}: deeply nested mapping is not supported")
                out[key], idx = _parse_mapping(lines, nxt, nxt_indent, allow_nested=False)
                continue
            out[key] = None
            idx = nxt
            continue

        if val_raw.startswith("["):
            out[key] = _parse_flow_list(val_raw, idx + 1)
        else:
            out[key] = _parse_scalar(val_raw, idx + 1)
        idx += 1
    return out, idx


def parse_yaml_subset(text: str) -> dict[str, Any]:
    """Parse `.github/pr-guardian.yml` using a strict stdlib-only YAML/JSON subset."""
    if not isinstance(text, str):
        raise ConfigError("config must be a string")
    if "\x00" in text:
        raise ConfigError("config contains null bytes")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ConfigError(f"config is not valid UTF-8: {exc}") from exc
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ConfigError("config exceeds 64 KiB")

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    stripped = normalized.lstrip()
    if not stripped:
        return {}
    if stripped.startswith("{"):
        try:
            obj = json.loads(
                normalized,
                object_pairs_hook=_no_dup_pairs,
                parse_constant=_reject_nonfinite,
            )
        except ConfigError:
            raise
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise ConfigError(f"invalid JSON config: {exc}") from exc
        if not isinstance(obj, dict):
            raise ConfigError("top-level config must be a mapping")
        return obj
    if stripped.startswith("["):
        raise ConfigError("top-level config must be a mapping")

    lines = normalized.split("\n")
    parsed, end_idx = _parse_mapping(lines, 0, 0, allow_nested=True)
    end_idx = _skip_ignored(lines, end_idx, seen_content=bool(parsed))
    if end_idx < len(lines):
        raise ConfigError(f"line {end_idx + 1}: unexpected trailing content")
    return parsed


def _validate_glob(pattern: Any, field: str) -> str:
    if not isinstance(pattern, str):
        raise ConfigError(f"{field} entries must be strings")
    if not 1 <= len(pattern) <= 256:
        raise ConfigError(f"{field} glob must be 1..256 chars: {pattern!r}")
    if pattern.startswith("/") or pattern.endswith("/") or "\\" in pattern or "//" in pattern:
        raise ConfigError(f"{field} glob must be repo-relative POSIX path without leading/trailing '/': {pattern!r}")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in pattern):
        raise ConfigError(f"{field} glob contains control characters")
    segs = pattern.split("/")
    if any(seg in ("", ".", "..") for seg in segs):
        raise ConfigError(f"{field} glob contains unsafe segment: {pattern!r}")
    return pattern


def _seg_to_regex(seg: str) -> str:
    out: list[str] = []
    for ch in seg:
        if ch == "*":
            out.append(r"[^/]*")
        elif ch == "?":
            out.append(r"[^/]")
        else:
            out.append(re.escape(ch))
    return "".join(out)


@functools.lru_cache(maxsize=512)
def compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile a segment-aware POSIX glob so `*` never crosses `/` and `**` spans 0+ dirs."""
    _validate_glob(pattern, "glob")
    raw_segs = pattern.split("/")
    segs: list[str] = []
    for seg in raw_segs:
        if seg == "**" and segs and segs[-1] == "**":
            continue
        segs.append(seg)

    if segs == ["**"]:
        return re.compile(r"\A.+\Z")

    parts = [r"\A"]
    n = len(segs)
    for i, seg in enumerate(segs):
        if seg == "**":
            if i == 0:
                parts.append(r"(?:[^/]+/)*")
            elif i == n - 1:
                parts.append(r"/.+")
            else:
                parts.append(r"/(?:[^/]+/)*")
        else:
            if i > 0 and segs[i - 1] != "**":
                parts.append("/")
            parts.append(_seg_to_regex(seg))
    parts.append(r"\Z")
    return re.compile("".join(parts))


def path_matches_any(path: Any, patterns: Sequence[str]) -> bool:
    """Return True if `path` is a valid repo-relative path matching any glob in `patterns`."""
    segs = _segments(path)
    if segs is None or not patterns:
        return False
    norm = "/".join(segs)
    for pat in patterns:
        if compile_glob(pat).match(norm):
            return True
    return False


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _validate_int_range(v: Any, name: str, lo: int, hi: int) -> int:
    if not _is_int(v) or not (lo <= v <= hi):
        raise ConfigError(f"{name} must be an integer between {lo} and {hi}")
    return v


def _validate_glob_list(v: Any, name: str) -> list[str]:
    if not isinstance(v, list):
        raise ConfigError(f"{name} must be a list of glob strings")
    if len(v) > 100:
        raise ConfigError(f"{name} exceeds 100 entries")
    return [_validate_glob(item, name) for item in v]


def validate_config(data: Any) -> dict[str, Any]:
    """Validate parsed config data against the pr-guardian schema and fill defaults."""
    if not isinstance(data, dict):
        raise ConfigError("config must be a mapping")
    cfg = default_config()
    for k in data:
        if k not in cfg:
            raise ConfigError(f"unknown config key: {k!r}")

    if "block_on" in data:
        v = data["block_on"]
        if not isinstance(v, list) or not (1 <= len(v) <= 4):
            raise ConfigError("block_on must be a list of 1..4 severities")
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str) or item not in VALID_BLOCKING:
                raise ConfigError(f"block_on entry {item!r} must be one of {VALID_BLOCKING}")
            seen.add(item)
        if "P0" not in seen:
            raise ConfigError("block_on must include 'P0'")
        cfg["block_on"] = [b for b in VALID_BLOCKING if b in seen]

    if "ignore_paths" in data:
        cfg["ignore_paths"] = _validate_glob_list(data["ignore_paths"], "ignore_paths")

    if "docs_paths" in data:
        cfg["docs_paths"] = _validate_glob_list(data["docs_paths"], "docs_paths")

    if "round_cap" in data:
        cfg["round_cap"] = _validate_int_range(data["round_cap"], "round_cap", 1, 20)

    if "reopen_escalation" in data:
        cfg["reopen_escalation"] = _validate_int_range(data["reopen_escalation"], "reopen_escalation", 1, 10)

    if "diff_budget" in data:
        cfg["diff_budget"] = _validate_int_range(data["diff_budget"], "diff_budget", 10_000, 1_000_000)

    if "per_file_budget" in data:
        cfg["per_file_budget"] = _validate_int_range(data["per_file_budget"], "per_file_budget", 1_000, 200_000)

    if cfg["per_file_budget"] > cfg["diff_budget"]:
        raise ConfigError("per_file_budget must not exceed diff_budget")

    if "leads_budget" in data:
        cfg["leads_budget"] = _validate_int_range(data["leads_budget"], "leads_budget", 10, 1_000)

    if "max_changed_lines" in data:
        v = data["max_changed_lines"]
        if v is None:
            cfg["max_changed_lines"] = None
        else:
            cfg["max_changed_lines"] = _validate_int_range(v, "max_changed_lines", 100, 500_000)

    if "max_pr_cost_usd" in data:
        v = data["max_pr_cost_usd"]
        if v is None:
            cfg["max_pr_cost_usd"] = None
        elif isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not (0.05 <= float(v) <= 500.0):
            raise ConfigError("max_pr_cost_usd must be null or a finite number between 0.05 and 500.0")
        else:
            cfg["max_pr_cost_usd"] = float(v)

    if "engines" in data:
        v = data["engines"]
        if not isinstance(v, list) or not (1 <= len(v) <= 4):
            raise ConfigError("engines must be a list of 1..4 entries")
        validated_engines: list[str] = []
        for item in v:
            if not isinstance(item, str):
                raise ConfigError("engines entries must be strings")
            if item in VALID_ENGINES:
                validated_engines.append(item)
            elif ":" in item:
                eng, slug = item.split(":", 1)
                if eng not in VALID_ENGINES or not MODEL_SLUG_RE.match(slug):
                    raise ConfigError(f"invalid engine entry {item!r}")
                validated_engines.append(item)
            else:
                raise ConfigError(f"invalid engine entry {item!r}")
        cfg["engines"] = validated_engines

    if "verifier" in data:
        v = data["verifier"]
        if isinstance(v, bool):
            cfg["verifier"] = "self" if v else "off"
        elif isinstance(v, str) and v in VALID_VERIFIER_MODES:
            cfg["verifier"] = v
        else:
            raise ConfigError(f"verifier must be bool or one of {VALID_VERIFIER_MODES}")

    if "chunk_threshold_chars" in data:
        cfg["chunk_threshold_chars"] = _validate_int_range(
            data["chunk_threshold_chars"], "chunk_threshold_chars", 20_000, 1_000_000
        )

    if "max_chunks" in data:
        cfg["max_chunks"] = _validate_int_range(data["max_chunks"], "max_chunks", 1, 10)

    if "extra_instructions" in data:
        v = data["extra_instructions"]
        if not isinstance(v, str):
            raise ConfigError("extra_instructions must be a string")
        if len(v) > 4_000:
            raise ConfigError("extra_instructions exceeds 4000 characters")
        cfg["extra_instructions"] = clean(v).strip()

    return cfg


def read_base_file(
    git_dir: Path | None,
    rel_path: str,
    *,
    base_sha: str = "",
    base_ref: str = "",
    repo: str = "",
    max_bytes: int | None = MAX_CONFIG_BYTES,
    strict_size: bool = True,
    strict_decode: bool = True,
) -> str | None:
    """Read `rel_path` strictly from the PR base commit/ref, NEVER from the head worktree.

    Returns the UTF-8 file text if the blob exists on base, None if the file or ref is absent.
    Raises ConfigError if the blob exceeds `max_bytes` (when `strict_size=True`) or cannot be
    decoded cleanly as UTF-8 (when `strict_decode=True`).
    """
    segs = _segments(rel_path)
    if segs is None:
        raise ConfigError(f"unsafe base file path: {rel_path!r}")
    norm_path = "/".join(segs)

    if git_dir is not None:
        candidates: list[str] = []
        if base_sha and SHA_RE.match(base_sha):
            candidates.append(base_sha)
        if _is_safe_ref(base_ref):
            candidates.append(f"refs/remotes/origin/{base_ref}")

        for ref in candidates:
            try:
                has_commit = subprocess.run(
                    ["git", "-C", str(git_dir), "cat-file", "-e", f"{ref}^{{commit}}"],
                    capture_output=True, shell=False, timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            if has_commit.returncode != 0:
                continue

            # Ref exists locally; inspect strictly at this ref and do NOT fall back to API.
            try:
                obj_type = subprocess.run(
                    ["git", "-C", str(git_dir), "cat-file", "-t", f"{ref}:{norm_path}"],
                    capture_output=True, text=True, errors="replace", shell=False, timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                return None
            if obj_type.returncode != 0 or obj_type.stdout.strip() != "blob":
                return None

            try:
                blob = subprocess.run(
                    ["git", "-C", str(git_dir), "cat-file", "blob", f"{ref}:{norm_path}"],
                    capture_output=True, shell=False, timeout=30,
                )
            except (OSError, subprocess.SubprocessError):
                return None
            if blob.returncode != 0:
                return None
            raw_bytes = blob.stdout
            if max_bytes is not None and len(raw_bytes) > max_bytes:
                if strict_size:
                    raise ConfigError(f"{norm_path} exceeds {max_bytes} bytes")
                raw_bytes = raw_bytes[:max_bytes]
            try:
                return raw_bytes.decode("utf-8", errors="strict" if strict_decode else "replace")
            except UnicodeDecodeError as exc:
                raise ConfigError(f"{norm_path} is not valid UTF-8: {exc}") from exc

    api_ref = base_sha if SHA_RE.match(base_sha) else (base_ref if _is_safe_ref(base_ref) else "")
    if repo and api_ref:
        encoded_path = "/".join(urllib.parse.quote(seg, safe="") for seg in segs)
        encoded_ref = urllib.parse.quote(api_ref, safe="")
        try:
            data = gh.api(f"repos/{repo}/contents/{encoded_path}?ref={encoded_ref}")
        except (gh.GhError, ValueError, TypeError):
            return None
        if not isinstance(data, dict) or data.get("type") != "file":
            return None
        size_hint = data.get("size")
        if (
            strict_size
            and max_bytes is not None
            and isinstance(size_hint, int)
            and not isinstance(size_hint, bool)
            and size_hint > max_bytes
        ):
            raise ConfigError(f"{norm_path} exceeds {max_bytes} bytes")
        if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
            return None
        try:
            raw_bytes = base64.b64decode(data["content"])
        except (binascii.Error, ValueError):
            return None
        if max_bytes is not None and len(raw_bytes) > max_bytes:
            if strict_size:
                raise ConfigError(f"{norm_path} exceeds {max_bytes} bytes")
            raw_bytes = raw_bytes[:max_bytes]
        try:
            return raw_bytes.decode("utf-8", errors="strict" if strict_decode else "replace")
        except UnicodeDecodeError as exc:
            raise ConfigError(f"{norm_path} is not valid UTF-8: {exc}") from exc

    return None


def load_from_base(
    git_dir: Path | None,
    *,
    base_sha: str = "",
    base_ref: str = "",
    repo: str = "",
    strict: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Load and validate `.github/pr-guardian.yml` from base, returning `(config, warnings)`."""
    try:
        raw = read_base_file(
            git_dir,
            CONFIG_PATH,
            base_sha=base_sha,
            base_ref=base_ref,
            repo=repo,
            max_bytes=MAX_CONFIG_BYTES,
            strict_size=True,
            strict_decode=True,
        )
        if raw is None:
            return default_config(), []
        return validate_config(parse_yaml_subset(raw)), []
    except ConfigError as exc:
        if strict:
            raise
        print(f"::warning::invalid {CONFIG_PATH} on base branch ({exc}); using safe defaults", file=sys.stderr)
        return default_config(), [str(exc)]
