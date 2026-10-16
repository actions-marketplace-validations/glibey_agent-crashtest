# 💥 agent-crashtest

[![npm](https://img.shields.io/npm/v/agent-crashtest?color=cb3837)](https://www.npmjs.com/package/agent-crashtest)
[![CI](https://github.com/glibey/agent-crashtest/actions/workflows/ci.yml/badge.svg)](https://github.com/glibey/agent-crashtest/actions/workflows/ci.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-agent--crashtest-2ea44f?logo=github)](https://github.com/marketplace/actions/agent-crashtest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![agent-crashtest: A · 100/100](https://img.shields.io/badge/agent--crashtest-A%20%C2%B7%20100%2F100-brightgreen)](https://github.com/glibey/agent-crashtest)

**How hackable is your AI coding agent?** One command, zero config, 100% local.

```bash
npx agent-crashtest
```

<p align="center"><img src="docs/demo.svg" alt="agent-crashtest --demo output: score 0/100 with critical findings" width="820"></p>

Claude Code, Codex, Cursor and MCP servers read web pages, READMEs, issues and emails, and any of them can carry
a prompt injection. `agent-crashtest` checks whether your setup would let that injection **run commands or steal your secrets**,
and tells you exactly what to change.

Fix the safe things automatically. You see every change as a diff and confirm it first:

```bash
npx agent-crashtest --fix
```

Try it on a deliberately broken project first: `npx agent-crashtest --demo`.

**Use it where you work:** [terminal](#options) · [GitHub Actions](#github-action) · [Claude Code](#claude-code) · [Codex, Cursor and other agents](#codex-cursor-copilot-gemini-cli) · [any MCP client](#any-mcp-client)

## What it checks

| Area | Examples |
|---|---|
| **Lethal trifecta** | untrusted input + private data + a way out, all without asking you |
| **Permissions** | `Bash(*)`, auto-approved `curl` / `python -c` / `gh api`, broad `WebFetch` |
| **Secrets in reach** | readable `.env`; wallet `PRIVATE_KEY` / `MNEMONIC` flagged as critical (names only, values are never read out) |
| **MCP servers** | unpinned `npx` / `uvx` packages (rug pulls), plaintext tokens, project servers enabled automatically |
| **Instruction files** | invisible Unicode-tag instructions in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, rules and skills |
| **AI agents in CI** | anyone on GitHub can drive the agent (`allowed_non_write_users: "*"`, raw `claude -p` / `codex exec` on issues), `--dangerously-skip-permissions`, PR code checked out under `pull_request_target` |
| **Codex** | `approval_policy = "never"` with `danger-full-access`, network access without approval, MCP servers in `config.toml` |

Reads: Claude Code (`.claude/settings*.json`, `~/.claude.json`), Cursor (`.cursor/mcp.json`), Codex (`.codex/config.toml`),
Claude Desktop, VS Code (`.vscode/mcp.json`), instruction files and skills, and `.github/workflows`.

## GitHub Action

Check every pull request that touches agent config or AI-agent workflows:

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
        with:
          fail-on: high   # critical | high | medium | low | none
```

Findings show up as annotations on the PR diff and as a table in the job summary. Outputs: `score`, `grade`, `critical`, `high`.
The action builds from the ref you pin and never downloads the package at run time.

## Inside your agent: scan *and fix*

The agent runs the scanner, explains each finding for your project, and fixes them one change at a time with your OK.

### Claude Code

A plugin with the skill, plus a short warning at session start when something is critical (at most once a week per issue).

```
/plugin install agent-crashtest --marketplace glibey/agent-crashtest
```

Then ask *"is my agent setup safe?"* or run `/agent-crashtest:crashtest`.

### Codex, Cursor, Copilot, Gemini CLI

Any agent that supports the open [Agent Skills](https://github.com/vercel-labs/skills) format:

```bash
npx skills add glibey/agent-crashtest
```

### Any MCP client

Cursor, Codex, Claude Desktop, Windsurf, VS Code: add a read-only `scan` tool.

```json
{
  "mcpServers": {
    "agent-crashtest": { "command": "npx", "args": ["-y", "agent-crashtest@0.5.1", "mcp"] }
  }
}
```

For Codex, in `~/.codex/config.toml`:

```toml
[mcp_servers.agent-crashtest]
command = "npx"
args = ["-y", "agent-crashtest@0.5.1", "mcp"]
```

The version is pinned on purpose: an unpinned MCP server runs whatever gets published next.

## Badge

Scored well? Put it in your README:

```bash
npx agent-crashtest --badge
```

[![agent-crashtest: A · 100/100](https://img.shields.io/badge/agent--crashtest-A%20%C2%B7%20100%2F100-brightgreen)](https://github.com/glibey/agent-crashtest)

That badge is a snapshot. For one that stays current, run the [GitHub Action](#github-action) and use its workflow badge;
the job summary prints the exact Markdown.

## For teams

Rolling out Claude Code, Codex, Cursor or MCP across a team? We're building a Team version: a GitHub App for private repos,
one policy file for what agents may do, a dashboard of agent setups across developers, and audit-ready reports.

👉 **[Join the early access list](https://github.com/glibey/agent-crashtest/issues/1)**, free during the beta.

## Options

```
npx agent-crashtest [options]
npx agent-crashtest mcp           run as an MCP server over stdio

--dir <path>        project to scan (default: current directory)
--project-only      skip global config in your home directory
--fix               show safe fixes as diffs and apply them after you confirm
--badge             print a README badge with your grade
--yes               with --fix: apply project changes without asking (never touches files in ~)
--json              machine-readable output
--fail-on <level>   exit 1 on findings at or above: critical, high, medium, low
--ci                same as --fail-on high
--github            GitHub Actions mode: PR annotations, job summary, step outputs
--demo              scan a deliberately vulnerable sample project
```

## What `--fix` changes

Only changes with one right answer, shown as a diff first:

- denies agent reads of `.env` files (Claude Code `permissions.deny`, plus `.cursorignore` in Cursor projects)
- pins `npx` MCP servers to the current version on npm
- removes `enableAllProjectMcpServers` and `skipDangerousModePermissionPrompt`

Files in your home directory affect every project, so they're asked about separately and never changed with `--yes`.
Judgment calls, like narrowing `Bash(*)` to the commands your project uses or fixing a CI workflow, are listed with the
exact fix; the [agent skill](#inside-your-agent-scan-and-fix) can walk you through them.

## Accuracy

A security tool that cries wolf gets uninstalled. The rules were run against thousands of public repositories that commit
agent config or run AI agents in CI, and every critical finding was reviewed by hand. Patterns that turned out safe, such as
`Bash(npx eslint:*)`, `curl localhost`, allowlist-gated or schedule-only workflows, and defensive rules in `CLAUDE.md`,
are regression tests now.

Found a false positive or a missed risk? [Open an issue](https://github.com/glibey/agent-crashtest/issues/new).

## Privacy and trust

- The scan runs locally. No network calls, no telemetry. Secret values are never printed; `.env` files are read for variable names only.
- No runtime dependencies.
- npm releases are published from GitHub Actions with [provenance](https://docs.npmjs.com/generating-provenance-statements), so you can check each version was built from this repo.

## Roadmap

- [ ] Policy file (`.agent-crashtest.yml`): declare what agents may do in your repo, enforced in CI
- [ ] `--fix` for more cases: Codex `config.toml`, narrowing broad `Bash` rules to the commands your project uses
- [ ] More agents: Windsurf, GitHub Copilot and Gemini CLI settings
- [ ] Team version ([early access](https://github.com/glibey/agent-crashtest/issues/1))

Ideas and requests: [open an issue](https://github.com/glibey/agent-crashtest/issues/new).

MIT
