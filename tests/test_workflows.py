"""Static checks on the workflow files (stdlib only; CI has no PyYAML).

GHSA-7p2f-fx79-f4vw: the scan job checks out PR code, so review_collector.py must
run with --no-exec. Without it the collector executes linters, formatters and type
checkers from the checkout (node_modules/.bin/*, eslint/prettier configs, conftest.py)
and that code can overwrite scanner outputs in $RUNNER_TEMP before upload.

The checker is deliberately strict: every mention of review_collector in a workflow
(comments included) must be a direct, recognised invocation whose arguments use only
known options, so unusual forms fail loudly instead of slipping past.

GHSA-6wg7-gfpx-8639: the caller template must start a run (and so join a concurrency
group that can cancel another run) only for events route.py acts on, and review.yml's
verdict job must not post an error for a run that was cancelled.
"""
import re
import shlex
import unittest
from pathlib import Path

import tests.helpers  # noqa: F401  (puts scripts/ on sys.path for route and governor)

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


# --- GHSA-6wg7-gfpx-8639: who can start (and so cancel) a pr-guardian run --------------
#
# The caller's job `if` decides which events join a concurrency group. If an outsider's
# comment passes it, that run cancels the review in flight before route.py skips it. The
# tests below evaluate the real expressions with a small stdlib model of the GitHub
# Actions expression language instead of matching their text.

_EXPR_TOKEN = re.compile(r"""\s*(?:
    (?P<str>'(?:[^']|'')*')
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<op>==|!=|&&|\|\||[!().,\[\]])
  | (?P<id>[A-Za-z_][\w-]*)
)""", re.X)
_STATUS_FUNCS = re.compile(r"\b(?:success|failure|cancelled|always)\s*\(")


def _expr_tokens(src):
    toks, pos, src = [], 0, src.rstrip()
    while pos < len(src):
        m = _EXPR_TOKEN.match(src, pos)
        if not m or m.end() == pos:
            raise ValueError(f"cannot tokenise expression at {src[pos:pos + 20]!r}")
        kind = m.lastgroup
        toks.append((kind, m.group(kind)))
        pos = m.end()
    return toks


def _to_num(v):
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip()) if v.strip() else 0.0
        except ValueError:
            return float("nan")
    return float("nan")


def _to_str(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _truthy(v):
    if isinstance(v, float) and v != v:
        return False
    return v not in (None, False, 0, "")


def _eq(a, b):
    if isinstance(a, str) and isinstance(b, str):
        return a.casefold() == b.casefold()  # GitHub compares strings case-insensitively
    if type(a) is type(b) and not isinstance(a, (dict, list)):
        return a == b
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return a is b
    return _to_num(a) == _to_num(b)


class _Expr:
    """Recursive-descent evaluator for the subset of expressions the workflows use."""

    def __init__(self, src):
        self.toks, self.i = _expr_tokens(src), 0
        self.tree = self._or()
        if self.i != len(self.toks):
            raise ValueError(f"trailing tokens: {self.toks[self.i:]}")

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def _take(self, value=None):
        kind, tok = self._peek()
        if kind is None or (value is not None and tok != value):
            raise ValueError(f"expected {value!r}, got {tok!r}")
        self.i += 1
        return kind, tok

    def _or(self):
        node = self._and()
        while self._peek()[1] == "||":
            self._take()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._cmp()
        while self._peek()[1] == "&&":
            self._take()
            node = ("and", node, self._cmp())
        return node

    def _cmp(self):
        node = self._unary()
        while self._peek()[1] in ("==", "!="):
            op = self._take()[1]
            node = (op, node, self._unary())
        return node

    def _unary(self):
        if self._peek()[1] == "!":
            self._take()
            return ("not", self._unary())
        return self._postfix()

    def _postfix(self):
        node = self._primary()
        while self._peek()[1] in (".", "["):
            if self._take()[1] == ".":
                kind, name = self._take()
                if kind != "id":
                    raise ValueError(f"bad property {name!r}")
                node = ("get", node, ("lit", name))
            else:
                node = ("get", node, self._or())
                self._take("]")
        return node

    def _primary(self):
        kind, tok = self._take()
        if kind == "str":
            return ("lit", tok[1:-1].replace("''", "'"))
        if kind == "num":
            return ("lit", float(tok))
        if tok == "(":
            node = self._or()
            self._take(")")
            return node
        if kind != "id":
            raise ValueError(f"unexpected token {tok!r}")
        if tok in ("true", "false", "null"):
            return ("lit", {"true": True, "false": False, "null": None}[tok])
        if self._peek()[1] == "(":
            self._take()
            args = []
            while self._peek()[1] != ")":
                args.append(self._or())
                if self._peek()[1] == ",":
                    self._take()
            self._take(")")
            return ("call", tok, args)
        return ("ctx", tok)

    def eval(self, ctx, node=None):
        node = self.tree if node is None else node
        op = node[0]
        if op == "lit":
            return node[1]
        if op == "ctx":
            return ctx.get(node[1])
        if op == "get":
            obj, key = self.eval(ctx, node[1]), self.eval(ctx, node[2])
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(key, str) and k.casefold() == key.casefold():
                        return v
            return None
        if op == "not":
            return not _truthy(self.eval(ctx, node[1]))
        if op == "and":
            left = self.eval(ctx, node[1])
            return self.eval(ctx, node[2]) if _truthy(left) else left
        if op == "or":
            left = self.eval(ctx, node[1])
            return left if _truthy(left) else self.eval(ctx, node[2])
        if op in ("==", "!="):
            same = _eq(self.eval(ctx, node[1]), self.eval(ctx, node[2]))
            return same if op == "==" else not same
        if op == "call":
            name, args = node[1].casefold(), [self.eval(ctx, a) for a in node[2]]
            status = ctx.get("__status__", {"success": True, "failure": False, "cancelled": False})
            if name in ("success", "failure", "cancelled"):
                return status[name]
            if name == "always":
                return True
            if name == "startswith":
                return _to_str(args[0]).casefold().startswith(_to_str(args[1]).casefold())
            if name == "contains":
                if isinstance(args[0], list):
                    return any(_eq(x, args[1]) for x in args[0])
                return _to_str(args[1]).casefold() in _to_str(args[0]).casefold()
            raise ValueError(f"unsupported function {node[1]}")
        raise ValueError(f"bad node {node!r}")


def _unwrap(raw):
    """Inner expression of a value that is exactly one ${{ ... }}, else None."""
    raw = raw.strip()
    if raw.startswith("${{") and raw.endswith("}}") and raw.count("${{") == 1:
        return raw[3:-2]
    return None


def eval_if(raw, ctx):
    """A job `if`: optional ${{ }} wrapper, implicit success() when no status function."""
    inner = _unwrap(raw)
    expr = inner if inner is not None else raw
    if "${{" in expr:
        raise ValueError(f"`if` mixes ${{{{ }}}} with bare text: {raw!r}")
    if not _STATUS_FUNCS.search(expr):
        expr = f"success() && ({expr})"
    return _truthy(_Expr(expr).eval(ctx))


def eval_value(raw, ctx):
    """A non-`if` value: one whole ${{ }} keeps its type; otherwise interpolate as text."""
    inner = _unwrap(raw)
    if inner is not None:
        return _Expr(inner).eval(ctx)
    return re.sub(r"\$\{\{(.*?)\}\}", lambda m: _to_str(_Expr(m.group(1)).eval(ctx)), raw, flags=re.S)


def yaml_get(text, *path):
    """Scalar at a mapping path, for the block-style YAML these workflows use. Supports
    plain scalars and > / >- / | / |- block scalars; comments outside scalars are skipped."""
    lines = text.replace("\r\n", "\n").split("\n")

    def indent(line):
        return len(line) - len(line.lstrip(" "))

    def skip(line):
        s = line.strip()
        return not s or s.startswith("#")

    lo, hi = 0, len(lines)
    for depth, key in enumerate(path):
        child, hit = None, None
        for i in range(lo, hi):
            if skip(lines[i]):
                continue
            child = indent(lines[i]) if child is None else child
            body = lines[i][indent(lines[i]):]
            if indent(lines[i]) == child and re.match(rf"{re.escape(key)}:(\s|$)", body):
                hit = i
                break
        if hit is None:
            raise KeyError(".".join(path))
        ind, end = indent(lines[hit]), hit + 1
        while end < hi and (skip(lines[end]) or indent(lines[end]) > ind):
            end += 1
        rest = lines[hit][ind + len(key) + 1:].strip()
        if depth < len(path) - 1:
            lo, hi = hit + 1, end
            continue
        if rest in (">", ">-", "|", "|-"):
            content = [ln.strip() for ln in lines[hit + 1:end] if ln.strip() and indent(ln) > ind]
            return (" " if rest.startswith(">") else "\n").join(content)
        return rest
    raise KeyError(".".join(path))


TEMPLATE = ROOT / "templates" / "pr-guardian.yml"
REVIEW = ROOT / ".github" / "workflows" / "review.yml"
WRITERS = ("OWNER", "MEMBER", "COLLABORATOR")
OUTSIDERS = ("NONE", "CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "MANNEQUIN")
OWNER_LOGIN = "owner"
SHA = "b" * 40


def _ctx(event_name, event, inputs=None):
    return {"github": {"event_name": event_name, "event": event, "repository_owner": OWNER_LOGIN},
            "inputs": inputs or {}}


def _pr_obj(number=7):
    repo = {"full_name": "owner/repo"}
    return {"number": number, "draft": False, "head": {"sha": SHA, "repo": repo}, "base": {"repo": repo}}


def pr_event(action, label=None):
    event = {"action": action, "number": 7, "pull_request": _pr_obj()}
    if label is not None:
        event["label"] = {"name": label}
    return _ctx("pull_request", event)


def retarget_event(prev="stage", changes=None):
    """pull_request.edited; a base retarget unless `changes` overrides the payload."""
    ctx = pr_event("edited")
    ctx["github"]["event"]["changes"] = (changes if changes is not None
                                         else {"base": {"ref": {"from": prev}, "sha": {"from": "f" * 40}}})
    return ctx


NON_RETARGET_EDITS = ({"title": {"from": "old"}}, {"body": {"from": "old"}}, {"base": None}, {},
                      {"base": {}}, {"base": {"ref": None}}, {"base": {"ref": {}}},
                      {"base": {"ref": {"from": ""}}}, {"base": {"ref": {"from": None}}})


def comment_event(body, assoc="OWNER", user_type="User", kind="issue_comment", on_pr=True,
                  login=OWNER_LOGIN):
    comment = {"body": body, "author_association": assoc, "user": {"login": login, "type": user_type}}
    if kind == "issue_comment":
        issue = {"number": 7}
        if on_pr is True:
            issue["pull_request"] = {"url": "https://api.github.com/repos/owner/repo/pulls/7"}
        elif on_pr is None:
            issue["pull_request"] = None
        return _ctx(kind, {"action": "created", "issue": issue, "comment": comment})
    return _ctx(kind, {"action": "created", "pull_request": _pr_obj(), "comment": comment})


def dispatch_event(pr="7"):
    return _ctx("workflow_dispatch", {"inputs": {"pr": pr}}, inputs={"pr": pr})


COMMANDS = ("/ai-review", "/ai-review escalate", "/ai-review wontfix: false positive", "/ai-review bogus",
            "/ai-review help", "/ai-review explain R-001", "/ai-review override " + "a" * 40 + ": reviewed")


class ExpressionModel(unittest.TestCase):
    """The evaluator itself, on GitHub's documented semantics."""

    def ev(self, src, ctx=None):
        return _Expr(src).eval(ctx or {})

    def test_operators_return_operands(self):
        self.assertEqual(self.ev("null || 'x'"), "x")
        self.assertEqual(self.ev("'a' && 'b'"), "b")
        self.assertIsNone(self.ev("null && 'b'"))
        self.assertEqual(self.ev("7 || 'x'"), 7.0)

    def test_case_insensitive_strings_and_null_comparisons(self):
        self.assertTrue(self.ev("'Bot' == 'bot'"))
        self.assertTrue(self.ev("startsWith('/AI-Review x', '/ai-review')"))
        self.assertFalse(self.ev("startsWith(null, '/ai-review')"))
        self.assertTrue(self.ev("a.b.c == null", {"a": {}}))
        self.assertFalse(self.ev("a.b != null", {"a": {"b": None}}))
        self.assertTrue(self.ev("a.b != null", {"a": {"b": {}}}))

    def test_implicit_success_unless_status_function(self):
        failed = {"__status__": {"success": False, "failure": True, "cancelled": False}}
        self.assertFalse(eval_if("true", failed))
        self.assertTrue(eval_if("${{ !cancelled() }}", failed))
        self.assertTrue(eval_if("always() && true", failed))

    def test_yaml_get_reads_folded_and_plain_scalars(self):
        text = "a:\n  # c\n  b: >-\n    x\n    y\n  c: ${{ z }}\nd: 1\n"
        self.assertEqual(yaml_get(text, "a", "b"), "x y")
        self.assertEqual(yaml_get(text, "a", "c"), "${{ z }}")
        with self.assertRaises(KeyError):
            yaml_get(text, "a", "d")


class CallerGate(unittest.TestCase):
    """templates/pr-guardian.yml: jobs.guardian.if and concurrency (GHSA-6wg7-gfpx-8639)."""

    @classmethod
    def setUpClass(cls):
        import governor  # noqa: E402  (tests.helpers puts scripts/ on sys.path)
        cls.texts = {"template": TEMPLATE.read_text(),
                     "rendered": governor.render_caller("0123456789abcdef0123456789abcdef01234567")}

    def each(self):
        for name, text in self.texts.items():
            with self.subTest(source=name):
                yield (yaml_get(text, "jobs", "guardian", "if"),
                       yaml_get(text, "jobs", "guardian", "concurrency", "group"),
                       yaml_get(text, "jobs", "guardian", "concurrency", "cancel-in-progress"))

    def fires(self, ctx):
        return [eval_if(cond, ctx) for cond, _, _ in self.each()]

    def assertFires(self, ctx, expected, msg=""):
        for cond, _, _ in self.each():
            self.assertIs(eval_if(cond, ctx), expected, msg or ctx)

    def assertGroup(self, ctx, suffix, cancel):
        for cond, group, cip in self.each():
            self.assertTrue(eval_if(cond, ctx), ctx)
            self.assertEqual(eval_value(group, ctx), f"pr-guardian-7-{suffix}", ctx)
            self.assertIs(eval_value(cip, ctx), cancel, ctx)

    def test_outsider_commands_never_start_a_run(self):
        for kind in ("issue_comment", "pull_request_review_comment"):
            for assoc in OUTSIDERS + ("", "owner-ish"):
                for body in COMMANDS:
                    self.assertFires(comment_event(body, assoc=assoc, kind=kind, login="mallory"), False)

    def test_bot_commands_never_start_a_run(self):
        for kind in ("issue_comment", "pull_request_review_comment"):
            for assoc in WRITERS:
                for body in COMMANDS:
                    self.assertFires(comment_event(body, assoc=assoc, user_type="Bot", kind=kind), False)

    def test_plain_issue_and_ordinary_comments_never_start_a_run(self):
        for on_pr in (False, None):
            for body in COMMANDS:
                self.assertFires(comment_event(body, on_pr=on_pr), False)
        for kind in ("issue_comment", "pull_request_review_comment"):
            for body in ("LGTM", "please /ai-review", "", "ai-review escalate"):
                self.assertFires(comment_event(body, kind=kind), False)

    def test_other_pull_request_actions_and_labels_never_start_a_run(self):
        for action in ("closed", "edited", "assigned", "unlabeled", "converted_to_draft",
                       "review_requested", "auto_merge_enabled"):
            self.assertFires(pr_event(action), False)
        for label in ("bug", "needs-human", "enhancement", "Human-Override-x", ""):
            self.assertFires(pr_event("labeled", label=label), False)
        # Removing human-override or needs-human recomputes the verdict (#27); other labels never
        # start a run. needs-human removal is safe to act on: verdict.py acknowledges only the
        # owner's removal, never a workflow-change escalation, and de-duplicates its comment.
        for label in ("bug", "Human-Override-x", "needs-human-x", ""):
            self.assertFires(pr_event("unlabeled", label=label), False)
        self.assertGroup(pr_event("unlabeled", label="needs-human"), "verdict", False)
        self.assertFires(_ctx("push", {"ref": "refs/heads/main"}), False)

    def test_writer_commands_start_a_run(self):
        for kind in ("issue_comment", "pull_request_review_comment"):
            for assoc in WRITERS:
                self.assertGroup(comment_event("/ai-review escalate", assoc=assoc, kind=kind), "verdict", False)
                # Only the owner's bare /ai-review is a review; anyone else's would only cancel one.
                self.assertGroup(comment_event("/ai-review", assoc=assoc, kind=kind), "review" if assoc == "OWNER"
                                 else "verdict", assoc == "OWNER")
                self.assertGroup(comment_event("/ai-review", assoc=assoc, kind=kind, login="someone"),
                                 "verdict", False)
                for body in ("/ai-review help", "/ai-review explain R-001",
                             "/ai-review override " + "a" * 40 + ": reviewed"):
                    self.assertGroup(comment_event(body, assoc=assoc, kind=kind), "verdict", False)
            # Pushback is a review only inside a finding thread; top level it gets a hint (#39).
            self.assertGroup(comment_event("/ai-review wontfix: fp", kind="issue_comment"), "verdict", False)
            self.assertGroup(comment_event("/ai-review wontfix: fp", kind="pull_request_review_comment"),
                             "review", True)

    def test_info_commands_never_cancel_reviews(self):
        """Only events route.decide() turns into a review may join the cancelling group (#39)."""
        import route  # noqa: E402
        bodies = COMMANDS + ("/ai-review frobnicate", "/ai-review wontfix", "/ai-review explain",
                             "/ai-review override", "/ai-review  ", "/ai-reviewer", "/AI-REVIEW help")
        for kind in ("issue_comment", "pull_request_review_comment"):
            # Logins are unique ignoring case on GitHub, so the expression's case-insensitive == on
            # login cannot match a different account than route.py's exact comparison does.
            for assoc, login in [(a, n) for a in WRITERS for n in (OWNER_LOGIN, "someone")]:
                for body in bodies:
                    ctx = comment_event(body, assoc=assoc, kind=kind, login=login)
                    decision = route.decide(kind, ctx["github"]["event"], OWNER_LOGIN)
                    for cond, group, cip in self.each():
                        if not eval_if(cond, ctx):
                            self.assertEqual(decision["action"], "skip", ctx)
                            continue
                        cancels = eval_value(cip, ctx)
                        self.assertIs(cancels, eval_value(group, ctx).endswith("-review"), ctx)
                        if cancels:
                            self.assertEqual(decision["action"], "review", (body, kind, decision))

    def test_review_actions_override_label_and_dispatch(self):
        for action in ("opened", "synchronize", "reopened", "ready_for_review"):
            self.assertGroup(pr_event(action), "review", True)
        self.assertGroup(pr_event("labeled", label="human-override"), "verdict", False)
        self.assertGroup(pr_event("unlabeled", label="human-override"), "verdict", False)
        self.assertGroup(dispatch_event("7"), "review", True)

    def test_caller_subscribes_to_unlabeled_and_edited(self):
        for name, text in self.texts.items():
            with self.subTest(source=name):
                types = yaml_get(text, "on", "pull_request", "types")
                self.assertIn("unlabeled", [t.strip() for t in types.strip("[]").split(",")])
                self.assertIn("edited", [t.strip() for t in types.strip("[]").split(",")])

    def test_base_retarget_starts_a_cancelling_review(self):
        """GHSA-6h55-p37r-jc34; '0' guards GitHub's '0' == null numeric coercion."""
        for prev in ("stage", "0", "main", "release/1.0", "false", "null"):
            with self.subTest(prev=prev):
                self.assertGroup(retarget_event(prev), "review", True)

    def test_title_body_and_malformed_edits_never_start_a_run(self):
        for changes in NON_RETARGET_EDITS:
            with self.subTest(changes=changes):
                self.assertFires(retarget_event(changes=changes), False)

    def test_caller_never_drops_an_event_route_acts_on(self):
        """Every event route.decide() would act on still reaches it through the caller."""
        import route  # noqa: E402
        events = [pr_event(a) for a in ("opened", "synchronize", "reopened", "ready_for_review",
                                        "closed", "edited", "labeled", "unlabeled")]
        events += [pr_event(a, label=n) for a in ("labeled", "unlabeled")
                   for n in ("human-override", "bug", "needs-human")]
        events.append(dispatch_event("7"))
        events += [retarget_event(p) for p in ("stage", "0", "main", "false")]
        events += [retarget_event(changes=c) for c in NON_RETARGET_EDITS]
        for kind in ("issue_comment", "pull_request_review_comment"):
            for assoc in WRITERS + OUTSIDERS:
                for user_type in ("User", "Bot"):
                    for body in COMMANDS + ("LGTM",):
                        for login in (OWNER_LOGIN, "someone"):
                            events.append(comment_event(body, assoc, user_type, kind, login=login))
        events += [comment_event(b, on_pr=False) for b in COMMANDS]
        acted = 0
        for ctx in events:
            gh = ctx["github"]
            decision = route.decide(gh["event_name"], gh["event"], OWNER_LOGIN)
            fired = self.fires(ctx)
            if decision["action"] != "skip":
                acted += 1
                self.assertEqual(fired, [True] * len(fired), (decision, ctx))
            if gh["event_name"].endswith("comment") and gh["event"]["comment"]["author_association"] in OUTSIDERS:
                self.assertEqual(decision["action"], "skip")
                self.assertEqual(fired, [False] * len(fired), ctx)
        self.assertGreater(acted, 20)


class VerdictGate(unittest.TestCase):
    """review.yml: a cancelled run must not post an error verdict; failures still must."""

    @classmethod
    def setUpClass(cls):
        cls.raw = yaml_get(REVIEW.read_text(), "jobs", "verdict", "if")

    def run_if(self, cancelled=False, upstream_ok=True, route_result="success", action="review"):
        status = {"cancelled": cancelled, "success": upstream_ok and not cancelled,
                  "failure": not upstream_ok and not cancelled}
        ctx = {"needs": {"route": {"result": route_result, "outputs": {"action": action}}},
               "__status__": status}
        return eval_if(self.raw, ctx)

    def test_shape(self):
        self.assertIsNotNone(_unwrap(self.raw), "wrap the whole verdict `if` in one ${{ }}")
        self.assertNotIn("always()", self.raw)
        self.assertIn("cancelled()", self.raw)

    def test_cancelled_run_skips_verdict(self):
        for action in ("review", "verdict"):
            for upstream_ok in (True, False):
                self.assertFalse(self.run_if(cancelled=True, upstream_ok=upstream_ok, action=action))

    def test_failed_or_timed_out_upstream_still_posts_verdict(self):
        for action in ("review", "verdict"):
            self.assertTrue(self.run_if(upstream_ok=True, action=action))
            self.assertTrue(self.run_if(upstream_ok=False, action=action))

    def test_route_failure_or_skip_never_posts(self):
        for route_result in ("failure", "cancelled", "skipped"):
            self.assertFalse(self.run_if(upstream_ok=False, route_result=route_result))
        self.assertFalse(self.run_if(action="skip"))


def _job_block(text, job):
    """Raw text of one top-level job in review.yml."""
    m = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z_][\w-]*:\n|\Z)", text, re.M | re.S)
    if not m:
        raise KeyError(job)
    return m.group(1)


def _step_env(block, key):
    m = re.search(rf"^\s+{re.escape(key)}:\s+(.*)$", block, re.M)
    if not m:
        raise KeyError(key)
    return m.group(1).strip()


class VerdictOverrideWiring(unittest.TestCase):
    """review.yml plumbing for GHSA-q4j9-99qr-cfhw: SHA fallback, bind flag, no synchronize-only clear."""

    @classmethod
    def setUpClass(cls):
        cls.text = REVIEW.read_text()
        cls.verdict = _job_block(cls.text, "verdict")

    def test_route_exports_head_sha_and_bind_override(self):
        for key in ("head_sha", "bind_override"):
            self.assertEqual(yaml_get(self.text, "jobs", "route", "outputs", key),
                             f"${{{{ steps.route.outputs.{key} }}}}")

    def test_sha_falls_back_to_event_head_not_live_head(self):
        raw = _step_env(self.verdict, "SHA")
        ctx = lambda scan, route_sha: {"needs": {"scan": {"outputs": {"head_sha": scan}},
                                                 "route": {"outputs": {"head_sha": route_sha}}}}
        self.assertEqual(eval_value(raw, ctx(SHA, "a" * 40)), SHA)
        self.assertEqual(eval_value(raw, ctx("", "a" * 40)), "a" * 40)  # scan skipped/failed early
        self.assertEqual(eval_value(raw, {"needs": {"route": {"outputs": {"head_sha": "a" * 40}}}}), "a" * 40)
        self.assertEqual(eval_value(raw, ctx("", "")), "")  # issue_comment: verdict.py uses the live head

    def test_bind_override_passed_and_clear_override_gone(self):
        self.assertEqual(_step_env(self.verdict, "BIND_OVERRIDE"), "${{ needs.route.outputs.bind_override }}")
        call = [ln for ln in logical_lines(self.verdict) if "verdict.py" in ln]
        self.assertEqual(len(call), 1, call)
        args = _tokens(call[0])
        self.assertEqual(args[args.index("--bind-override") + 1], "$BIND_OVERRIDE")
        self.assertEqual(args[args.index("--sha") + 1], "$SHA")
        self.assertNotIn("clear-override", self.verdict)
        self.assertNotRegex(self.verdict, r"^\s+CLEAR:", "override removal must not depend on the event reason")


class ReviewedBaseWiring(unittest.TestCase):
    """review.yml: publish records the base the scan diffed against (GHSA-6h55-p37r-jc34)."""

    @classmethod
    def setUpClass(cls):
        cls.text = REVIEW.read_text()
        cls.publish = _job_block(cls.text, "publish")

    def test_scan_exports_base_ref_from_its_own_pr_lookup(self):
        self.assertEqual(yaml_get(self.text, "jobs", "scan", "outputs", "base_ref"),
                         "${{ steps.pr.outputs.base_ref }}")
        self.assertIn('"base_ref=" + .baseRefName', _job_block(self.text, "scan"))

    def test_publish_passes_scan_base_not_a_live_lookup(self):
        self.assertEqual(_step_env(self.publish, "BASE"), "${{ needs.scan.outputs.base_ref }}")
        self.assertIn("scan", yaml_get(self.text, "jobs", "publish", "needs"))
        call = [ln for ln in logical_lines(self.publish) if "publish_review.py" in ln]
        self.assertEqual(len(call), 1, call)
        args = _tokens(call[0])
        # --base=VALUE so a ref starting with "-" is never parsed as an option.
        self.assertIn("--base=$BASE", args)
        self.assertNotIn("--base", args)
        self.assertEqual(args[args.index("--sha") + 1], "$SHA")


if __name__ == "__main__":
    unittest.main()


class VerdictForgeryWiring(unittest.TestCase):
    """GHSA-v7qp-pmhq-cf47: the publish tripwire and governor app id are wired through the workflows."""

    @classmethod
    def setUpClass(cls):
        cls.review = REVIEW.read_text()
        cls.publish = _job_block(cls.review, "publish")
        cls.governor = (ROOT / ".github" / "workflows" / "governor.yml").read_text()
        cls.reconcile = _job_block(cls.governor, "reconcile")

    def test_publish_passes_guardian_ref_as_one_value(self):
        self.assertEqual(_step_env(self.publish, "GUARDIAN_REF"), "${{ inputs.guardian_ref }}")
        call = [ln for ln in logical_lines(self.publish) if "publish_review.py" in ln]
        self.assertEqual(len(call), 1, call)
        args = _tokens(call[0])
        self.assertIn("--guardian-ref=$GUARDIAN_REF", args)
        self.assertNotIn("--guardian-ref", args)
        self.assertNotIn("inputs.guardian_ref", call[0], "inputs reach the script through env, not the shell")

    def test_publish_loads_the_template_from_the_same_ref(self):
        # The exemption compares against .prg/templates/pr-guardian.yml, so .prg must be guardian_ref.
        m = re.search(r"repository: ksprashu/pr-guardian\n\s+ref: (.*)\n\s+path: \.prg\n", self.publish)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1).strip(), "${{ inputs.guardian_ref }}")

    def test_template_pins_one_ref_in_both_places(self):
        text = TEMPLATE.read_text()
        self.assertIn("review.yml@{{REF}}\n", text)
        self.assertIn("guardian_ref: {{REF}}\n", text)
        self.assertEqual(text.count("{{REF}}"), 2)

    def test_governor_passes_verdict_app_id_variable(self):
        self.assertEqual(_step_env(self.reconcile, "PRG_VERDICT_APP_ID"), "${{ vars.PRG_VERDICT_APP_ID }}")
        self.assertEqual(_step_env(self.reconcile, "PRG_REF"), "${{ vars.PRG_REF || 'v1' }}")
