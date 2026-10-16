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

Supported: Claude Code, Cursor, Claude Desktop, VS Code (`.vscode/mcp.json`).

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
