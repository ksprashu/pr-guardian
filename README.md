# pr-guardian

pr-guardian reviews every pull request automatically and gates the merge on the result. It runs as one reusable GitHub Actions workflow. The Antigravity CLI (`agy`) drives Gemini 4 Argon through the `review` and `security-review` skills from [agent-skill-forge](https://github.com/ksprashu/agent-skill-forge). A pinned set of scanners runs first and feeds the model leads.

A PR merges only when all of these hold:

- the `pr-guardian/verdict` commit status is green, meaning no open P0–P3 findings (nits never block)
- every review conversation is resolved
- the PR targets the default branch through the `main-via-pr` ruleset, whose bypass list is empty, so the owner is held to it too

## The loop

1. A PR is opened or pushed. The workflow runs `route`, then `scan` (semgrep, gitleaks, osv-scanner, trivy, actionlint, zizmor, native audits, linters). Then `review` runs agy with structured output, then `publish` writes the inline threads and summary, and `verdict` sets the status.
2. On every push, the PR gets a full re-review. Each earlier finding is marked `fixed`, `still_open`, `reopened` or `accepted_pushback`:
   - If a thread was resolved but the code still has the problem, the thread is unresolved and gets a reply.
   - If a finding was fixed, or the pushback was accepted, the bot resolves the thread.
3. The PR author works the threads. The [`pr-review-loop`](https://github.com/ksprashu/agent-skill-forge/tree/main/skills/pr-review-loop) skill does this for agents. For each thread they either:
   - fix it and push,
   - reply `/ai-review wontfix: <reason>`, or
   - comment `/ai-review escalate: <why>` on the PR.
4. The loop stops when one of these happens:
   - the verdict is green (no findings, or nits only)
   - a human is called in (`needs-human`): by an escalate command, round 6, a finding reopened 3 times, or a finding re-raised after its pushback was accepted
   - the owner applies `human-override`. This label counts only when the owner applies it, and only for the commit it was applied to.

## Commands

| Command | Where | Who | Effect |
|---|---|---|---|
| `/ai-review wontfix: <reason>` | reply in a finding's thread | writers | Re-review. The model judges the reason, then accepts and resolves the thread, or replies with a counter-argument. |
| `/ai-review escalate: <why>` | PR comment | writers | Adds `needs-human` and fails the verdict until the owner overrides. |
| `/ai-review` | PR comment | owner | Forces a re-review of the current head. |
| `human-override` label | PR | owner only | Turns the verdict green for this commit. |

## Security model

- The model job has a read-only token. `GEMINI_API_KEY` is set only on the agy step, and agy runs `--sandbox` with a read-only command allowlist (`config/agy-settings.json`).
- `publish` and `verdict` never run the model. They validate its output against the forge's findings schema, strip HTML comments so the model cannot forge markers, and defuse @-mentions.
- PRs from forks are never reviewed automatically, because secrets are not available to them. The owner reviews them and applies `human-override`. No workflow uses `pull_request_target`.
- Scanner and findings SARIF is kept as a run artifact, not uploaded to code scanning. Code-scanning alerts open their own PR threads, which the bot cannot resolve, and required conversation resolution would block on them.
- Every action is pinned by SHA, and every scanner binary is checked against its release SHA-256 (`scripts/install_scanners.sh`).
- Known gap: agy installs through its official bootstrapper and updates itself, so it is not pinned.

## Governor

`governor.yml` runs every day and on dispatch. It brings every owned, non-fork, non-archived repo up to the baseline:

1. Settings: squash only, delete merged branches, auto-merge on.
2. The `GEMINI_API_KEY` secret.
3. The caller workflow, delivered through a PR.
4. The `main-via-pr` ruleset, applied only after the caller is on the default branch.

It records drift in the "Governor drift report" issue.

To bootstrap it, add two secrets to this repo:

- `GOVERNOR_TOKEN`: a fine-grained PAT on all repos, with read/write access to Administration, Secrets, Contents, Pull requests and Workflows
- `GEMINI_API_KEY`

Optionally, set the `PRG_REF` variable to the tag or SHA that callers should pin.

## Development

```sh
python3 -m unittest discover -s tests -t .
actionlint && zizmor --offline .github/workflows templates
```

The scripts use the Python 3.12 standard library only, and they never call subprocess with `shell=True`.
