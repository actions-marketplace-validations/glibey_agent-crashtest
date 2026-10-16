import type { Context, Finding, McpServer } from '../types.js';

const UNTRUSTED = /fetch|browser|puppeteer|playwright|firecrawl|scrap|crawl|web|search|brave|tavily|exa\b|github|gitlab|gmail|mail|slack|discord|telegram|notion|linear|jira|confluence|reddit|twitter|youtube|rss/;
const PRIVATE = /filesystem|\bfs\b|github|gitlab|gmail|mail|drive|postgres|mysql|sqlite|supabase|mongo|redis|notion|slack|1password|vault|aws|gcp|azure|stripe|database|\bdb\b|obsidian|memory/;
const EXFIL = /fetch|http|browser|puppeteer|playwright|slack|discord|telegram|gmail|mail|github|gitlab|webhook|twitter|linear|jira|notion/;
const SECRET_VALUE = /^(sk-|sk_live|ghp_|gho_|github_pat_|xox[abp]-|AKIA|AIza|glpat-|npm_|eyJ)[A-Za-z0-9_\-.]{8,}|^[A-Fa-f0-9]{32,}$/;
const RUNNERS = new Set(['npx', 'bunx', 'pnpx', 'uvx', 'pipx']);

export type McpCategory = 'untrusted' | 'private' | 'exfil';

export function describe(server: McpServer): string {
  return [server.name, server.command, ...server.args, server.url].filter(Boolean).join(' ').toLowerCase();
}

export function categorize(server: McpServer): Set<McpCategory> {
  const text = describe(server);
  const cats = new Set<McpCategory>();
  if (UNTRUSTED.test(text)) cats.add('untrusted');
  if (PRIVATE.test(text)) cats.add('private');
  if (EXFIL.test(text)) cats.add('exfil');
  return cats;
}

export function checkMcp(ctx: Context): Finding[] {
  const findings: Finding[] = [];

  for (const s of ctx.mcpServers) {
    const runner = s.command?.split('/').pop();
    if (runner && RUNNERS.has(runner)) {
      const pkg = s.args.find((a) => !a.startsWith('-'));
      if (pkg && isUnpinned(pkg)) {
        findings.push({
          id: 'mcp-unpinned',
          severity: 'medium',
          title: `MCP server "${s.name}" is not version-pinned`,
          detail: `"${runner} ${pkg}" downloads whatever version is published today. A compromised update ("rug pull") runs on your machine automatically.`,
          fix: `Pin an exact version, e.g. "${stripVersion(pkg)}@1.2.3".`,
          file: s.file,
        });
      }
    }

    const leaked = Object.entries(s.env).filter(([, v]) => SECRET_VALUE.test(v));
    if (leaked.length) {
      findings.push({
        id: 'mcp-plaintext-secret',
        severity: 'high',
        title: `Plaintext secret in MCP config "${s.name}"`,
        detail: `${leaked.map(([k, v]) => `${k}=${mask(v)}`).join(', ')}. Any agent or tool that can read this file can steal the token.`,
        fix: 'Reference an environment variable (e.g. "${GITHUB_TOKEN}") or a secret manager instead of the literal value.',
        file: s.file,
      });
    }

    if (s.url && /^http:\/\//.test(s.url) && !/localhost|127\.0\.0\.1|\[::1\]/.test(s.url)) {
      findings.push({
        id: 'mcp-http',
        severity: 'medium',
        title: `MCP server "${s.name}" uses unencrypted HTTP`,
        detail: `${s.url} can be read or tampered with by anyone on the network path.`,
        fix: 'Use an https:// endpoint.',
        file: s.file,
      });
    }
  }

  if (ctx.mcpServers.length > 12) {
    findings.push({
      id: 'mcp-sprawl',
      severity: 'low',
      title: `${ctx.mcpServers.length} MCP servers configured`,
      detail: 'Every server is extra attack surface: its tool descriptions are read by the model and can carry hidden instructions.',
      fix: 'Remove servers you do not use every week.',
    });
  }
  return findings;
}

function isUnpinned(pkg: string): boolean {
  if (/^[./]/.test(pkg)) return false; // local path
  const at = pkg.lastIndexOf('@');
  if (at <= 0) return true; // no version (or scoped package without version)
  const version = pkg.slice(at + 1);
  return version === 'latest' || version === 'next' || /^[\^~]/.test(version);
}

function stripVersion(pkg: string): string {
  const at = pkg.lastIndexOf('@');
  return at > 0 ? pkg.slice(0, at) : pkg;
}

export function mask(value: string): string {
  return value.length <= 8 ? '****' : `${value.slice(0, 4)}…${value.slice(-2)}`;
}
