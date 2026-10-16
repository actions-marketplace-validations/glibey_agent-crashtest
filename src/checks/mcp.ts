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
    const spec = packageSpec(s);
    if (spec) {
      const { runner, spec: pkg } = spec;
      if (isUnpinned(pkg)) {
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

const VALUE_FLAGS = new Set(['--from', '--package', '-p', '--spec', '--with', '--python', '--index-url', '-i']);
const PACKAGE_FLAGS = new Set(['--from', '--package', '-p', '--spec']);

export interface PackageSpec {
  runner: string;
  /** Index in args of the value holding the package, and the text before it in that arg (e.g. "--from="). */
  index: number;
  prefix: string;
  spec: string;
}

/** The package an npx / uvx / pipx MCP server launches, e.g. "@scope/pkg@1.2.3" or "mcp-server-fetch==1.0". */
export function packageSpec(server: { command?: string; args: string[] }): PackageSpec | undefined {
  const runner = server.command?.split(/[\\/]/).pop()?.replace(/\.(cmd|exe)$/i, '');
  if (!runner || !RUNNERS.has(runner)) return undefined;
  const { args } = server;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const eq = a.match(/^(--[\w-]+=)(.*)$/);
    if (eq && PACKAGE_FLAGS.has(eq[1].slice(0, -1))) return { runner, index: i, prefix: eq[1], spec: eq[2] };
    if (PACKAGE_FLAGS.has(a) && i + 1 < args.length) return { runner, index: i + 1, prefix: '', spec: args[i + 1] };
    if (VALUE_FLAGS.has(a)) { i++; continue; }
    if (a.startsWith('-')) continue;
    if (runner === 'pipx' && a === 'run') continue;
    return { runner, index: i, prefix: '', spec: a };
  }
  return undefined;
}

/** npm style "pkg@1.2.3" and Python style "pkg==1.2.3" count as pinned; ranges, tags and bare names don't. */
export function isUnpinned(spec: string): boolean {
  if (/^[./~]|^[a-z+]+:\/\//i.test(spec)) return false; // local path or URL: not a registry package
  if (/==\s*[\w.]+$/.test(spec)) return false;
  if (/[<>~!]=|[<>]/.test(spec)) return true;
  const at = spec.lastIndexOf('@');
  if (at <= 0) return true; // no version (or a scoped package without one)
  const version = spec.slice(at + 1);
  return version === 'latest' || version === 'next' || /^[\^~]/.test(version);
}

export function stripVersion(spec: string): string {
  const py = spec.search(/[=<>~!]=|[<>]/);
  if (py > 0) return spec.slice(0, py);
  const at = spec.lastIndexOf('@');
  return at > 0 ? spec.slice(0, at) : spec;
}

export function mask(value: string): string {
  return value.length <= 8 ? '****' : `${value.slice(0, 4)}…${value.slice(-2)}`;
}
