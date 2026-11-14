"""Guards GHSA-hf8m-fv4j-wxgh: governor secrets stay behind the `governor` environment.

Standard library only (no PyYAML). The reader below accepts a strict subset of YAML:
block mappings indented by two spaces, single-line quoted scalars and flow
collections, and `|` / `>` block scalars without indentation indicators. It raises on
anything outside that subset (quoted, flow-style or complex keys, multi-line quotes or
brackets, tags, anchors, aliases, explicit indentation indicators, odd indents,
duplicates), so an unusual layout fails the test instead of slipping past it.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
GOVERNOR = WORKFLOWS / "governor.yml"
GUARD = ("github.event_name == 'schedule' || "
         "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)")
SECRETS = re.compile(r"\bsecrets\b", re.I)
KEY = re.compile(r"^([A-Za-z0-9_-]+):(?:\s+(.*))?$")
BLOCK = re.compile(r"(?:^|\s)[|>]([-+0-9]*)$")
NODE_PROPERTY = re.compile(r"(?:^(?:-\s+)*|:\s+|[,\[{]\s*)[!&*?%@`]")


def _code(line):
    """Strip a trailing comment and check the line stays inside the supported subset."""
    out, bare, quote, depth, i = [], [], None, [], 0
    while i < len(line):
        ch = line[i]
        if quote is None:
            if ch == "#" and (i == 0 or line[i - 1] in " \t"):
                break
            if ch in "\"'":
                quote = ch
                bare.append("q")
            else:
                bare.append(ch)
                if ch in "{[":
                    depth.append("}" if ch == "{" else "]")
                elif ch in "}]":
                    if not depth or depth.pop() != ch:
                        raise ValueError(f"unbalanced bracket: {line!r}")
        elif quote == '"' and ch == "\\":
            out.append(ch)
            i += 1
        elif ch == quote:
            if quote == "'" and line[i + 1:i + 2] == "'":
                out.append(ch)
                i += 1
            else:
                quote = None
        out.append(ch)
        i += 1
    if quote:
        raise ValueError(f"multi-line quoted scalar not supported: {line!r}")
    if depth:
        raise ValueError(f"multi-line flow collection not supported: {line!r}")
    bare = "".join(bare).strip()
    if NODE_PROPERTY.search(bare) or bare.startswith(("---", "...")):
        raise ValueError(f"tags, anchors, aliases and directives not supported: {line!r}")
    return "".join(out).rstrip()


def structure(text):
    """Return (structural, raw): raw is every line; structural is (index, indent, code)
    for lines that are not blank, comments or block-scalar bodies."""
    raw = text.splitlines()
    out, block_indent = [], None
    for idx, line in enumerate(raw):
        if not line.strip():
            continue
        if "\t" in line[:len(line) - len(line.lstrip())]:
            raise ValueError(f"tab indentation at line {idx + 1}")
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None:
            if indent > block_indent:
                continue
            block_indent = None
        code = _code(line)
        if not code.strip():
            continue
        m = BLOCK.search(code)
        if m:
            if not re.fullmatch(r"[-+]?", m.group(1)):
                raise ValueError(f"block indentation indicator not supported: {line!r}")
            block_indent = indent
        out.append((idx, indent, code.strip()))
    return out, raw


def parse(text):
    """Return ({top_key: (start, end)}, {job: {"start", "end", "keys"}}) by raw line index."""
    lines, raw = structure(text)
    tops, jobs, order, parent, child_indent = {}, {}, [], None, None
    for idx, indent, code in lines:
        if indent == 0:
            m = KEY.match(code)
            if not m:
                raise ValueError(f"unrecognised top-level line {idx + 1}: {code!r}")
            if m.group(1) in tops:
                raise ValueError(f"duplicate top-level key {m.group(1)!r}")
            tops[m.group(1)] = [idx, len(raw)]
            order.append(m.group(1))
            parent, child_indent = m.group(1), None
        elif child_indent is None:
            if indent != 2:
                raise ValueError(f"children of {parent!r} must be indented 2 spaces (line {idx + 1})")
            child_indent = 2
        elif indent == 1:
            raise ValueError(f"odd indent at line {idx + 1}")
    for a, b in zip(order, order[1:]):
        tops[a][1] = tops[b][0]
    if "jobs" in tops:
        start, end = tops["jobs"]
        if KEY.match(_code(raw[start]).strip()).group(2):
            raise ValueError("flow-style jobs mapping not supported")
        current, fresh = None, False
        for idx, indent, code in lines:
            if not start < idx < end:
                continue
            if indent == 2:
                m = KEY.match(code)
                if not m or m.group(2):
                    raise ValueError(f"unrecognised job header line {idx + 1}: {code!r}")
                if m.group(1) in jobs:
                    raise ValueError(f"duplicate job {m.group(1)!r}")
                if current:
                    jobs[current]["end"] = idx
                current, fresh = m.group(1), True
                jobs[current] = {"start": idx, "end": end, "keys": {}}
                continue
            if fresh and indent != 4:
                raise ValueError(f"job keys must be indented 4 spaces (line {idx + 1})")
            fresh = False
            if indent == 3:
                raise ValueError(f"odd indent at line {idx + 1}")
            if indent == 4:
                m = KEY.match(code)
                if not m:
                    raise ValueError(f"unrecognised job key line {idx + 1}: {code!r}")
                if m.group(1) in jobs[current]["keys"]:
                    raise ValueError(f"duplicate key {m.group(1)!r} in job {current!r}")
                jobs[current]["keys"][m.group(1)] = (m.group(2) or "").strip()
    return {k: tuple(v) for k, v in tops.items()}, jobs


def triggers(text):
    tops, _ = parse(text)
    start, end = tops["on"]
    names = []
    for idx, indent, code in structure(text)[0]:
        if start < idx < end and indent == 2:
            m = KEY.match(code)
            if not m:
                raise ValueError(f"unrecognised trigger line {idx + 1}: {code!r}")
            names.append(m.group(1))
    return names


def secret_violations(text):
    """Lines reading secrets outside a job gated by both environment and branch guard."""
    _, jobs = parse(text)
    bad = []
    for idx, line in enumerate(text.splitlines()):
        if not SECRETS.search(line):
            continue
        owner = next((j for j in jobs.values() if j["start"] < idx < j["end"]), None)
        keys = owner["keys"] if owner else {}
        if keys.get("environment") != "governor" or keys.get("if") != GUARD:
            bad.append(idx + 1)
    return bad


class GovernorWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.text = GOVERNOR.read_text(encoding="utf-8")
        self.tops, self.jobs = parse(self.text)

    def test_only_reconcile_job(self):
        self.assertEqual(set(self.jobs), {"reconcile"})

    def test_reconcile_uses_governor_environment(self):
        self.assertEqual(self.jobs["reconcile"]["keys"].get("environment"), "governor")

    def test_reconcile_runs_only_on_schedule_or_default_branch(self):
        self.assertEqual(self.jobs["reconcile"]["keys"].get("if"), GUARD)

    def test_triggers_unchanged(self):
        self.assertEqual(sorted(triggers(self.text)), ["schedule", "workflow_dispatch"])

    def test_checkout_does_not_persist_credentials(self):
        lines = self.text.splitlines()
        job = self.jobs["reconcile"]
        idx = [i for i in range(job["start"], job["end"]) if "uses: actions/checkout@" in lines[i]]
        self.assertEqual(len(idx), 1)
        block = []
        for line in lines[idx[0] + 1:job["end"]]:
            if re.match(r"^\s*- ", line):
                break
            block.append(line)
        self.assertTrue(any(re.match(r"^\s+persist-credentials:\s*false\s*$", l) for l in block),
                        "actions/checkout must set persist-credentials: false")

    def test_secrets_only_in_gated_jobs(self):
        self.assertEqual(secret_violations(self.text), [])

    def test_no_other_workflow_touches_governor_token_or_environment(self):
        for path in sorted(WORKFLOWS.glob("*.y*ml")):
            if path == GOVERNOR:
                continue
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"governor_token", text, re.I), path.name)
            self.assertIsNone(re.search(r"environment:\s*['\"]?governor\b", text, re.I), path.name)


GATED = ("jobs:\n  ok:\n    if: " + GUARD + "\n    environment: governor\n"
         "    steps:\n      - run: echo ${{ secrets.GOVERNOR_TOKEN }}\n")


class ParserTest(unittest.TestCase):
    def test_gated_job_passes(self):
        self.assertEqual(secret_violations(GATED), [])

    def test_unscoped_job_flagged(self):
        text = GATED + "  b:\n    steps:\n      - run: echo ${{ secrets.GOVERNOR_TOKEN }}\n"
        self.assertEqual(secret_violations(text), [9])

    def test_job_without_guard_flagged(self):
        text = "jobs:\n  a:\n    environment: governor\n    env:\n      T: ${{ secrets.X }}\n"
        self.assertEqual(secret_violations(text), [5])

    def test_secret_spellings_flagged(self):
        for ref in ("secrets['GOVERNOR_TOKEN']", "secrets.governor_token", "toJSON(secrets)"):
            text = GATED + f"  b:\n    steps:\n      - run: echo ${{{{ {ref} }}}}\n"
            self.assertEqual(secret_violations(text), [9], ref)
        self.assertEqual(secret_violations(GATED + "  b:\n    uses: ./x.yml\n    secrets: inherit\n"),
                         [9])

    def test_commented_job_header_is_a_job(self):
        text = GATED + "  exfil: # harmless\n    steps:\n      - run: echo ${{ secrets.GOVERNOR_TOKEN }}\n"
        _, jobs = parse(text)
        self.assertIn("exfil", jobs)
        self.assertEqual(secret_violations(text), [9])

    def test_quoted_or_flow_keys_rejected(self):
        cases = ((parse, GATED + '  "exfil":\n    steps: []\n'),
                 (triggers, 'on:\n  "push":\njobs:\n  a:\n    steps: []\n'),
                 (parse, "jobs: {a: {steps: []}}\n"),
                 (parse, GATED + "  b: {steps: []}\n"))
        for fn, bad in cases:
            with self.assertRaises(ValueError, msg=bad):
                fn(bad)

    def test_multiline_quoted_scalar_rejected(self):
        text = ('jobs:\n  b:\n    name: "harmless\n    environment: governor\n    "\n'
                "    steps:\n      - run: echo ${{ secrets.GOVERNOR_TOKEN }}\n")
        with self.assertRaises(ValueError):
            parse(text)

    def test_nested_environment_is_not_job_level(self):
        _, jobs = parse("jobs:\n  a:\n    steps:\n      - with:\n          environment: governor\n")
        self.assertNotIn("environment", jobs["a"]["keys"])

    def test_block_scalar_body_is_opaque(self):
        text = ("jobs:\n  a:\n    steps:\n      - run: |\n          echo \"it's\"\n"
                "    environment: governor\n")
        _, jobs = parse(text)
        self.assertEqual(jobs["a"]["keys"].get("environment"), "governor")

    def test_duplicate_job_rejected(self):
        with self.assertRaises(ValueError):
            parse("jobs:\n  a:\n    steps: []\n  a:\n    steps: []\n")

    def test_spoofed_environment_lines_rejected(self):
        # Each hides "    environment: governor" inside a value YAML would not treat as a key.
        spoofs = ("    name: |2\n    environment: governor\n",
                  "    name: >1-\n    environment: governor\n",
                  "    env: {\n    environment: governor\n      }\n",
                  "    env: [\n    environment: governor ]\n",
                  '    name: !!str "spoof\n    environment: governor # "\n',
                  "    name: x'\n    environment: governor # '\n",
                  "    name: &a x\n    environment: governor\n",
                  "    name: *a\n")
        for spoof in spoofs:
            text = "jobs:\n  b:\n" + spoof + "    if: " + GUARD + "\n    steps: []\n"
            with self.assertRaises(ValueError, msg=spoof):
                parse(text)

    def test_job_keys_must_sit_at_four_spaces(self):
        # With job keys at 3 spaces, the 4-space lines are env vars, not job keys.
        text = ("jobs:\n  b:\n   env:\n    environment: governor\n    if: " + GUARD +
                "\n   steps:\n    - run: echo ${{ secrets.GOVERNOR_TOKEN }}\n")
        with self.assertRaises(ValueError):
            parse(text)
        with self.assertRaises(ValueError):
            parse("jobs:\n   b:\n     steps: []\n")


if __name__ == "__main__":
    unittest.main()
