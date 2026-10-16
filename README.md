# 💥 agent-crashtest

[![npm](https://img.shields.io/npm/v/agent-crashtest?color=cb3837)](https://www.npmjs.com/package/agent-crashtest)
[![CI](https://github.com/glibey/agent-crashtest/actions/workflows/ci.yml/badge.svg)](https://github.com/glibey/agent-crashtest/actions/workflows/ci.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-agent--crashtest-2ea44f?logo=github)](https://github.com/marketplace/actions/agent-crashtest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![agent-crashtest: A · 100/100](https://img.shields.io/badge/agent--crashtest-A%20%C2%B7%20100%2F100-brightgreen)](https://github.com/glibey/agent-crashtest)

**Security for AI agents in your CI.**

Claude Code, Codex and other coding agents now run in GitHub Actions on issues, PR comments and fork PRs,
with your API keys and a write token in the environment. One wrong line in the workflow, and anyone on GitHub
can open an issue that tells your agent what to do.

`agent-crashtest` finds those workflows and blocks them in review, before they reach `main`.

```yaml
# .github/workflows/agent-crashtest.yml
name: agent-crashtest
on: [pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glibey/agent-crashtest@v1
```

Findings show up as annotations on the PR diff and as a table in the job summary, and the check fails on `high` or worse.

## What a risky agent workflow looks like

```yaml
on:
  issues:
    types: [opened]                         # anyone on GitHub can open an issue
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          allowed_non_write_users: "*"      # turns off the write-access check
          claude_args: --allowedTools "Bash,Read"   # any shell command
```

```
 CRITICAL  Anyone on GitHub can drive the agent in .github/workflows/triage.yml
 CRITICAL  Agent may run any shell command in .github/workflows/triage.yml
```

The issue text becomes the agent's instructions, and the agent can run any command next to your secrets.
Narrow the tools to what the job needs (`--allowedTools "Bash(gh issue edit:*),Read"`) and it drops to the
low-risk setup the action's own [security docs](https://github.com/anthropics/claude-code-action/blob/main/docs/security.md) recommend.

## What it checks in CI

| Risk | Example |
|---|---|
| **Strangers can drive the agent** | `allowed_non_write_users: "*"`, `allowed_bots: "*"`, or a raw `claude -p` / `codex exec` step on `issues`, `issue_comment`, `pull_request_target` with no actor check |
| **No permission checks** | `--dangerously-skip-permissions`, `--permission-mode bypassPermissions`, `codex exec --dangerously-bypass-approvals-and-sandbox` |
| **Unlimited tools** | `--allowedTools "Bash"` or `Bash(*)` where untrusted input reaches the agent |
| **Untrusted code in the workspace** | `pull_request_target` checking out the PR head into the workspace root |
| **Leaky logs and secrets** | `show_full_output: true` on public repos, `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0`, API keys pasted into the workflow |

It understands the guards people actually use, so it doesn't cry wolf: `author_association` and role allowlists,
gate jobs, maintainer-only labels, merged-PR-only triggers, and schedule-only workflows.

## Your local agent setup too

The same scanner checks the agent on your machine: Claude Code, Codex, Cursor, MCP servers and instruction files.

```bash
npx agent-crashtest          # scan this project and your global agent config
npx agent-crashtest --fix    # apply the safe fixes, each shown as a diff first
```

<p align="center"><img src="docs/demo.svg" alt="agent-crashtest --demo output: score 0/100 with critical findings" width="820"></p>

| Area | Examples |
|---|---|
| **Lethal trifecta** | untrusted input + private data + a way out, all without asking you |
| **Permissions** | `Bash(*)`, auto-approved `curl` / `python -c` / `gh api`, broad `WebFetch` |
| **Secrets in reach** | readable `.env` and key files; wallet `PRIVATE_KEY` / `MNEMONIC` flagged as critical (names only, values are never read out) |
| **MCP servers** | unpinned `npx` / `uvx` packages, plaintext tokens, project servers enabled automatically |
| **Instruction files** | invisible Unicode-tag instructions in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, rules and skills |
| **Codex** | `approval_policy = "never"` with `danger-full-access`, network access without approval |

`--fix` changes only what has one right answer: it denies agent reads of secret files, pins `npx` MCP servers to
the current version, and removes `enableAllProjectMcpServers` and `skipDangerousModePermissionPrompt`. Files in your
home directory are asked about separately and never changed with `--yes`.

### Inside your agent

Let the agent scan, explain each finding for your project, and fix it one change at a time with your OK.

- **Claude Code** (skill, plus a warning at session start when something is critical):
  `/plugin install agent-crashtest --marketplace glibey/agent-crashtest`
- **Codex, Cursor, Copilot, Gemini CLI** and other agents with [Agent Skills](https://github.com/vercel-labs/skills) support:
  `npx skills add glibey/agent-crashtest`
- **Any MCP client** (a read-only `scan` tool):

```json
{
  "mcpServers": {
    "agent-crashtest": { "command": "npx", "args": ["-y", "agent-crashtest@0.5.2", "mcp"] }
  }
}
```

For Codex, in `~/.codex/config.toml`:

```toml
[mcp_servers.agent-crashtest]
command = "npx"
args = ["-y", "agent-crashtest@0.5.2", "mcp"]
```

## For teams

Running AI agents in CI across an organization? We're building a Team version:

- a **GitHub App for private repos** that reviews every PR touching an agent workflow or agent config
- **one policy** for what agents may do in CI across all repos
- an **inventory** of every workflow that runs an AI agent, and who can trigger it

👉 **[Join the early access list](https://github.com/glibey/agent-crashtest/issues/1)**, free during the beta.

## Accuracy

A security check that cries wolf gets removed from CI. The rules were run against thousands of public repositories
that run AI agents in GitHub Actions or commit agent config, and every critical finding was reviewed by hand.
Patterns that turned out safe, such as allowlist-gated and schedule-only workflows, `Bash(npx eslint:*)`,
`curl localhost` and defensive rules in `CLAUDE.md`, are regression tests now.

Found a false positive or a missed risk? [Open an issue](https://github.com/glibey/agent-crashtest/issues/new).

## Privacy and trust

- The scan runs locally or on your runner. No network calls, no telemetry. Secret values are never printed; `.env` files are read for variable names only.
- The Action builds from the ref you pin and never downloads the package at run time.
- No runtime dependencies. npm releases are published from GitHub Actions with [provenance](https://docs.npmjs.com/generating-provenance-statements).

## Badge

```bash
npx agent-crashtest --badge
```

prints a snapshot badge with your grade. For one that stays current, use the workflow badge of the Action; the job summary prints the exact Markdown.

## Options

```
npx agent-crashtest [options]
npx agent-crashtest mcp           run as an MCP server over stdio

--dir <path>        project to scan (default: current directory)
--project-only      skip global config in your home directory
--fix               show safe fixes as diffs and apply them after you confirm
--yes               with --fix: apply project changes without asking (never touches files in ~)
--badge             print a README badge with your grade
--json              machine-readable output
--fail-on <level>   exit 1 on findings at or above: critical, high, medium, low
--ci                same as --fail-on high
--github            GitHub Actions mode: PR annotations, job summary, step outputs
--demo              scan a deliberately vulnerable sample project
```

Action inputs: `path` (default `.`), `fail-on` (default `high`). Outputs: `score`, `grade`, `critical`, `high`.

## Roadmap

- [ ] GitHub App for private repos ([early access](https://github.com/glibey/agent-crashtest/issues/1))
- [ ] Policy file (`.agent-crashtest.yml`): declare which workflows may run agents, with which tools, enforced in CI
- [ ] More CI agents: GitHub Copilot coding agent, Gemini CLI action, GitLab CI
- [ ] `--fix` for CI workflows: narrow tools and drop outsider access in agent workflows

Ideas and requests: [open an issue](https://github.com/glibey/agent-crashtest/issues/new).

MIT
