"""Neutralise untrusted text before it is interpolated into a PR comment.

Everything the model writes, and everything read back from PR state, is
untrusted. Three helpers cover the ways such text reaches GitHub Markdown:

  clean(text)    multi-line prose: strips HTML comments to a fixpoint, so a
                 nested opener such as "<!<<!-- a -->!--" cannot reassemble a
                 marker, and defuses every @-mention with a zero-width space.
  inline(text)   a single-line field (file, id, rule, title, reason): clean()
                 plus control characters and line breaks collapsed to spaces.
  safe_url(url)  a link target: https only, real host, no characters that can
                 close a Markdown link or open an HTML comment. None otherwise.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

_COMMENT_RE = re.compile(r"<!--.*?(?:-->|$)", flags=re.S)
_MENTION_RE = re.compile(r"@(?=[A-Za-z0-9-])")
_LINEBREAK_RE = re.compile(r"[\s\x00-\x1f\x7f\u2028\u2029]+")
_URL_FORBIDDEN = set("()[]<>\"'`\\{}|^")
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
ZWSP = "\u200b"


def _text(value: Any) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def clean(text: Any) -> str:
    text = _text(text)
    while True:
        nxt = _COMMENT_RE.sub("", text).replace("<!--", "")
        if nxt == text:
            break
        text = nxt
    return _MENTION_RE.sub("@" + ZWSP, text)


def inline(text: Any) -> str:
    return _LINEBREAK_RE.sub(" ", clean(text)).strip()


def safe_url(url: Any) -> str | None:
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > 2048:
        return None
    if any(ord(c) <= 0x20 or ord(c) >= 0x7f or c in _URL_FORBIDDEN for c in url):
        return None
    if "<!--" in url or "-->" in url:
        return None
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.netloc or "@" in parts.netloc:
        return None
    host = parts.hostname or ""
    if not _HOST_RE.match(host) or (port is not None and not 0 < port < 65536):
        return None
    return url
