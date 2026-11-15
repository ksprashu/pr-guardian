# pr-guardian golden eval suite

Offline evaluation fixtures and scoring for `pr-guardian` review quality and regression gating.

**Important:** Cases under `evals/cases/` contain **deliberately defective fixtures** stored inside JSON strings and unified diff patches (`case.json` and `diff.patch`) for evaluating the reviewer model. None of the code in `evals/cases/` is executed or shipped by `pr-guardian`.

## Layout

- `cases/<name>/case.json`: PR metadata (`title`, `description`) and pre-patch `files` mapping.
- `cases/<name>/diff.patch`: Unified diff applied on top of the base `files`.
- `cases/<name>/expected.json`: Expected blocking findings (`clean: true` requires `expect: []`; post-patch line numbers).
- `recorded/<label>/`: Recorded `meta.json`, `<case>.findings.json`, and optional `<case>.usage.json`.
  - `recorded/reference/` is hand-derived from `expected.json` and proves the fixtures and scorer agree offline.

## Commands

Validate all fixture schemas, patch applicability, and post-patch line bounds:

```sh
python3 scripts/eval.py lint
```

Score committed recordings against thresholds and check prompt/forge freshness:

```sh
python3 scripts/eval.py score --recorded all --check-fresh
```

Record a real model run locally (requires API credentials and a local forge checkout):

```sh
python3 scripts/eval.py run --engine agy --forge /path/to/agent-skill-forge --record agy-argon-high
```
