"""Static checks on the workflow files (stdlib only; CI has no PyYAML).

GHSA-7p2f-fx79-f4vw: the scan job checks out PR code, so review_collector.py must
run with --no-exec. Without it the collector executes linters, formatters and type
checkers from the checkout (node_modules/.bin/*, eslint/prettier configs, conftest.py)
and that code can overwrite scanner outputs in $RUNNER_TEMP before upload.

The checker is deliberately strict: every mention of review_collector in a workflow
(comments included) must be a direct, recognised invocation whose arguments use only
known options, so unusual forms fail loudly instead of slipping past.
"""
import re
import shlex
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_FILES = sorted((ROOT / ".github" / "workflows").glob("*.yml")) + \
    sorted((ROOT / "templates").glob("*.yml"))

NEEDLE = "review_collector"
SCRIPT_RE = re.compile(r"^[\w./${}-]*/?review_collector\.py$")
INTERPRETER_RE = re.compile(r"^python(3(\.\d+)?)?$")
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_]\w*=")
YAML_KEY_RE = re.compile(r"^\s*(?:-\s+)?[A-Za-z_][\w-]*:\s+")
PUNCT = set("();<>|&")
WORD_BREAK = set(" \t\n;&|()<>")

# review_collector.py options the workflows may use. Extend deliberately if needed.
FLAG = "--no-exec"
VALUE_OPTS = {"--path", "--base", "--out"}


def logical_lines(text):
    """Shell-style logical lines: comments dropped, backslash-newline joined.

    Quote state carries across lines, a '#' only starts a comment at the start of a
    word outside quotes, and only an unescaped trailing backslash continues a line.
    """
    text = text.replace("\r\n", "\n")
    lines, cur, quote, i, n = [], [], None, 0, len(text)
    while i < n:
        c = text[i]
        if quote == "'":
            cur.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\":
            if i + 1 < n and text[i + 1] == "\n":
                i += 2
                continue
            cur.append(text[i:i + 2])
            i += 2
            continue
        if quote == '"':
            cur.append(c)
            if c == '"':
                quote = None
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c == "#" and (not cur or cur[-1][-1] in WORD_BREAK):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif c == "\n":
            lines.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        lines.append("".join(cur))
    return lines


def _tokens(line):
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    return list(lex)


def _is_op(tok):
    return bool(tok) and set(tok) <= PUNCT


def _is_redirect(tok):
    return _is_op(tok) and ("<" in tok or ">" in tok) and not ("(" in tok or ")" in tok)


def _at_command_position(tokens, i):
    """True if tokens[i] is the command word (after optional VAR=x assignments)."""
    j = i - 1
    while j >= 0 and ASSIGNMENT_RE.match(tokens[j]):
        j -= 1
    return j < 0 or (_is_op(tokens[j]) and not _is_redirect(tokens[j]))


def _call_args(tokens, start):
    """Arguments bash would pass: stop at control operators, drop redirections."""
    args, k = [], start
    while k < len(tokens):
        t = tokens[k]
        if _is_redirect(t):
            if args and args[-1].isdigit():  # fd prefix such as 2> (conservative)
                args.pop()
            k += 2
            continue
        if _is_op(t):
            break
        args.append(t)
        k += 1
    return args


def collector_calls(text):
    """Return (calls, errors): argument lists of direct collector invocations, and
    descriptions of any review_collector mention that is not one."""
    calls, errors, matched = [], [], 0
    for line in logical_lines(text):
        if NEEDLE not in line:
            continue
        body = YAML_KEY_RE.sub("", line, count=1)
        try:
            tokens = _tokens(body)
        except ValueError as e:
            errors.append(f"unparseable line {line.strip()!r}: {e}")
            continue
        for i, tok in enumerate(tokens):
            if NEEDLE not in tok:
                continue
            direct = SCRIPT_RE.match(tok) and (
                _at_command_position(tokens, i)
                or (i > 0 and INTERPRETER_RE.match(tokens[i - 1]) and _at_command_position(tokens, i - 1)))
            if not direct:
                errors.append(f"indirect or unrecognised collector reference {tok!r} in {line.strip()!r}")
                continue
            matched += 1
            calls.append(_call_args(tokens, i + 1))
    if text.count(NEEDLE) != matched + len(errors):
        errors.append(f"{text.count(NEEDLE)} mentions of {NEEDLE} but only {matched} recognised "
                      "invocations (mentions in comments or hidden forms are not allowed)")
    return calls, errors


def no_exec_problem(args):
    """None if args (argparse semantics) set --no-exec as a standalone flag and use
    only known options; otherwise a reason string."""
    seen, k = False, 0
    while k < len(args):
        a = args[k]
        if a == FLAG:
            seen = True
            k += 1
        elif a in VALUE_OPTS:
            if k + 1 >= len(args) or args[k + 1].startswith("-"):
                return f"{a} has no value"
            k += 2
        elif "=" in a and a.split("=", 1)[0] in VALUE_OPTS:
            k += 1
        else:
            return f"unexpected argument {a!r}"
    return None if seen else f"{FLAG} missing"


def check(text):
    """List of problems for a workflow text (empty means compliant)."""
    calls, errors = collector_calls(text)
    return errors + [f"{p}: {args}" for args in calls if (p := no_exec_problem(args))]


GOOD = ('run: |\n  python3 .forge/skills/review/scripts/review_collector.py --no-exec \\\n'
        '    --path src --base "origin/$BASE" --out "$RUNNER_TEMP/evidence.json" || echo "collector exit $?"\n')


class CollectorNoExecChecker(unittest.TestCase):
    def assertOk(self, text):
        self.assertEqual(check(text), [], text)

    def assertBad(self, text):
        self.assertNotEqual(check(text), [], text)

    def test_accepts_current_form(self):
        self.assertOk(GOOD)
        self.assertOk("python3 review_collector.py --path src \\\n  --no-exec\n")
        self.assertOk("python3 review_collector.py --base \"a#b\" --no-exec --out=o.json\n")
        self.assertOk("- run: python3 x/review_collector.py --no-exec --path src > log 2>&1\n")
        self.assertOk("FOO=1 ./scripts/review_collector.py --no-exec\n")

    def test_missing_flag(self):
        self.assertBad("python3 review_collector.py --path src\n")

    def test_commented_flag(self):
        self.assertBad("python3 review_collector.py --path src # --no-exec\n")
        self.assertBad("python3 review_collector.py --path src \\\n  # --no-exec\n")
        self.assertBad("python3 review_collector.py --path src # note \\\n--no-exec\n")

    def test_comment_mentions_are_rejected(self):
        self.assertBad("# python3 review_collector.py --no-exec\n" + GOOD)
        self.assertBad(GOOD + "    # review_collector\n")

    def test_flag_after_control_operator(self):
        self.assertBad("python3 review_collector.py --path src || echo --no-exec\n")
        self.assertBad("python3 review_collector.py --path src; true --no-exec\n")

    def test_flag_as_redirection_target(self):
        for op in (">", ">>", "2>", "<", "<<<", "&>", ">|"):
            self.assertBad(f"python3 review_collector.py --path src {op} --no-exec\n")

    def test_escaped_backslash_is_not_continuation(self):
        self.assertBad("python3 review_collector.py --path src \\\\\n  --no-exec\n")

    def test_flag_in_value_slot_or_after_double_dash(self):
        self.assertBad("python3 review_collector.py --path src --out --no-exec\n")
        self.assertBad("python3 review_collector.py --base --no-exec\n")
        self.assertBad("python3 review_collector.py --path src -- --no-exec\n")
        self.assertBad("python3 review_collector.py --out 2>x --no-exec\n")

    def test_variant_flags_do_not_count(self):
        for flag in ("--no-exec=false", "--no-exe", "--NO-EXEC", "'--no-exec '"):
            self.assertBad(f"python3 review_collector.py --path src {flag}\n")

    def test_indirect_invocations_are_rejected(self):
        self.assertBad("python3 -m review_collector --path src\n")
        self.assertBad('bash -c "python3 x/review_collector.py --path src"\n')
        self.assertBad('bash -c "x/review_collector.py" --no-exec\n')
        self.assertBad("timeout 60 python3 x/review_collector.py --no-exec\n")
        self.assertBad("python3 -u x/review_collector.py --no-exec\n")

    def test_multiline_quote_does_not_hide_call(self):
        self.assertBad("echo 'a\n# ' ; python3 review_collector.py --path src\n")


class WorkflowCollectorNoExec(unittest.TestCase):
    def test_review_workflow_invokes_collector(self):
        calls, _ = collector_calls((ROOT / ".github/workflows/review.yml").read_text())
        self.assertTrue(calls, "review.yml no longer invokes review_collector.py; update this test")

    def test_every_collector_call_passes_no_exec(self):
        self.assertTrue(WORKFLOW_FILES)
        for path in WORKFLOW_FILES:
            with self.subTest(file=str(path.relative_to(ROOT))):
                self.assertEqual(check(path.read_text()), [],
                                 "review_collector.py must run with --no-exec on PR checkouts "
                                 "(GHSA-7p2f-fx79-f4vw)")


if __name__ == "__main__":
    unittest.main()
