# 💥 agent-crashtest

**How hackable is your AI coding agent?** One command, zero config, 100% local.

```bash
npx agent-crashtest
```

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

## Options

```
--dir <path>     project to scan (default: cwd)
--project-only   skip global config in ~
--json           machine-readable output
--ci             exit 1 on critical/high findings
--demo           scan a sample vulnerable project
```

## Privacy

Nothing leaves your machine. No network calls, no telemetry. Secrets are masked in output.

## Roadmap

- [ ] `--attack`: live crash test — runs your real agent against poisoned files in a sandbox with canary secrets
- [ ] README badge with your grade
- [ ] GitHub Action for PRs that change agent config

MIT
