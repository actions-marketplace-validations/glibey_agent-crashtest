# 💥 agent-crashtest

**How hackable is your AI coding agent?** One command, zero config, 100% local.

```bash
npx agent-crashtest
```

<p align="center"><img src="docs/demo.svg" alt="agent-crashtest --demo output: score 0/100 with critical findings" width="820"></p>

Claude Code, Cursor and MCP servers read web pages, READMEs, issues and emails — any of which can carry
a prompt injection. `agent-crashtest` checks whether your setup would let that injection **steal your secrets**.

Try it on a deliberately broken project first:

```bash
npx agent-crashtest --demo
```

## What it checks

| Area | Examples |
|---|---|
| **Lethal trifecta** | untrusted input + private data + a way out, all auto-approved |
| **Permissions** | `bypassPermissions`, `Bash(*)`, auto-approved `curl` / `python -c`, readable `.env` |
| **MCP servers** | unpinned `npx`/`uvx` packages (rug pulls), plaintext tokens, auto-enabled project servers |
| **Instruction files** | invisible Unicode-tag instructions in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skills |

Supported: Claude Code, Cursor, Codex (`config.toml`), Claude Desktop, VS Code (`.vscode/mcp.json`), and AI agents in GitHub Actions.

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

The agent runs the scanner, explains each finding for your project, and fixes them one by one with your OK.

**Claude Code** (plugin: skill + a warning at session start when something is critical)

```
/plugin install agent-crashtest --marketplace glibey/agent-crashtest
```

Then ask *"is my agent setup safe?"* or run `/agent-crashtest:crashtest`.

**Codex, Cursor, Copilot, Gemini CLI and other agents with skills support**

```bash
npx skills add glibey/agent-crashtest
```

**Any MCP client** (Cursor, Codex, Claude Desktop, Windsurf, VS Code): add a read-only `scan` tool.

```json
{
  "mcpServers": {
    "agent-crashtest": { "command": "npx", "args": ["-y", "agent-crashtest@0.3.0", "mcp"] }
  }
}
```

For Codex, in `~/.codex/config.toml`:

```toml
[mcp_servers.agent-crashtest]
command = "npx"
args = ["-y", "agent-crashtest@0.3.0", "mcp"]
```

The version is pinned on purpose: an unpinned MCP server runs whatever gets published next.

## For teams

Rolling out Claude Code, Cursor or MCP across a team? We're building a Team version: a GitHub App for private repos,
one policy file for what agents may do, a dashboard of agent setups across developers, and audit-ready reports.

👉 **[Join the early access list](https://github.com/glibey/agent-crashtest/issues/1)**, free during the beta.

## Options

```
--dir <path>     project to scan (default: cwd)
--project-only   skip global config in ~
--json           machine-readable output
--fail-on <lvl>   exit 1 on findings at or above: critical, high, medium, low
--ci             same as --fail-on high
--github         GitHub Actions mode: PR annotations, job summary, step outputs
--demo           scan a sample vulnerable project
```

## Privacy

Nothing leaves your machine. No network calls, no telemetry. Secrets are masked in output.

## Roadmap

- [ ] `--attack`: live crash test — runs your real agent against poisoned files in a sandbox with canary secrets
- [ ] README badge with your grade

MIT
