import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { Context, Finding } from './types.js';

/** One file to write, with every change planned for it. */
export interface FilePlan {
  file: string;
  global: boolean;
  before: string | undefined;
  after: string;
  changes: string[];
}

export interface FixPlan {
  files: FilePlan[];
  /** Findings that need a human decision; the fix text is shown instead. */
  manual: Finding[];
  /** Fixes that were planned but could not be prepared (e.g. a version lookup failed). */
  skipped: string[];
}

const AUTO_IDS = new Set(['secrets-readable', 'wallet-keys-readable', 'auto-project-mcp', 'skip-danger-prompt', 'mcp-unpinned']);
const ENV_DENY = ['Read(./.env)', 'Read(./.env.*)'];
const RUNNERS = new Set(['npx', 'bunx', 'pnpx']);

export type VersionLookup = (pkg: string) => string | undefined;

/** Latest published version from the npm registry, or undefined if it can't be found. */
export const npmVersion: VersionLookup = (pkg) => {
  try {
    const out = execFileSync('npm', ['view', pkg, 'version'], { encoding: 'utf8', timeout: 20_000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    return /^\d+\.\d+\.\d+/.test(out) ? out : undefined;
  } catch {
    return undefined;
  }
};

export function planFixes(ctx: Context, findings: Finding[], lookup: VersionLookup = npmVersion): FixPlan {
  const files = new Map<string, FilePlan>();
  const skipped: string[] = [];
  const isGlobal = (file: string) => !file.startsWith(ctx.dir + '/');
  const edit = (file: string, change: string, apply: (current: string | undefined) => string | undefined) => {
    const plan = files.get(file) ?? { file, global: isGlobal(file), before: readText(file), after: '', changes: [] };
    const current = plan.changes.length ? plan.after : plan.before;
    const next = apply(current);
    if (next === undefined || next === current) return;
    plan.after = next;
    plan.changes.push(change);
    files.set(file, plan);
  };
  const ids = new Set(findings.map((f) => f.id));

  if (ids.has('secrets-readable') || ids.has('wallet-keys-readable')) {
    edit(join(ctx.dir, '.claude/settings.json'), 'Deny the agent reading .env files', (text) =>
      updateJson(text, (data) => {
        data.permissions ??= {};
        const deny: string[] = Array.isArray(data.permissions.deny) ? data.permissions.deny : [];
        for (const rule of ENV_DENY) if (!deny.includes(rule)) deny.push(rule);
        data.permissions.deny = deny;
      }));
    const usesCursor = existsSync(join(ctx.dir, '.cursor')) || existsSync(join(ctx.dir, '.cursorrules'));
    if (usesCursor) {
      edit(join(ctx.dir, '.cursorignore'), 'Keep .env files out of Cursor', (text = '') =>
        /^\.env\*?\s*$/m.test(text) ? text : `${text}${text && !text.endsWith('\n') ? '\n' : ''}# added by agent-crashtest\n.env*\n`);
    }
  }

  for (const key of ['enableAllProjectMcpServers', 'skipDangerousModePermissionPrompt'] as const) {
    if (!ids.has(key === 'enableAllProjectMcpServers' ? 'auto-project-mcp' : 'skip-danger-prompt')) continue;
    for (const { file, data } of ctx.claudeSettings) {
      if (data[key] !== true) continue;
      edit(file, `Remove "${key}"`, (text) => updateJson(text, (d) => { delete d[key]; }));
    }
  }

  if (ids.has('mcp-unpinned')) {
    for (const s of ctx.mcpServers) {
      const runner = s.command?.split('/').pop();
      // Codex TOML, VS Code JSONC and ~/.claude.json (rewritten by Claude Code while it runs) are left to the user.
      if (!runner || !RUNNERS.has(runner) || s.client === 'codex' || /\.vscode\/|\.claude\.json$/.test(s.file)) continue;
      const i = s.args.findIndex((a) => !a.startsWith('-'));
      const pkg = i >= 0 ? s.args[i] : undefined;
      if (!pkg || /^[./]/.test(pkg) || !isUnpinned(pkg)) continue;
      const name = stripVersion(pkg);
      const version = lookup(name);
      if (!version) {
        skipped.push(`Could not look up the latest version of ${name} for MCP server "${s.name}"`);
        continue;
      }
      edit(s.file, `Pin MCP server "${s.name}" to ${name}@${version}`, (text) =>
        updateJson(text, (data) => {
          const server = findServer(data, s.name, ctx.dir);
          if (server && Array.isArray(server.args) && server.args[i] === pkg) server.args[i] = `${name}@${version}`;
        }));
    }
  }

  const manual = findings.filter((f) => !AUTO_IDS.has(f.id) || (f.id === 'mcp-unpinned' && !coveredByPlan(f, files)));
  return { files: [...files.values()], manual, skipped };
}

export function applyPlan(plan: FixPlan, includeGlobal: boolean): FilePlan[] {
  const written: FilePlan[] = [];
  for (const f of plan.files) {
    if (f.global && !includeGlobal) continue;
    mkdirSync(dirname(f.file), { recursive: true });
    writeFileSync(f.file, f.after);
    written.push(f);
  }
  return written;
}

/** A compact line diff: removed lines with "-", added lines with "+", a little unchanged context. */
export function diff(before: string | undefined, after: string): string[] {
  const a = before === undefined ? [] : before.replace(/\n$/, '').split('\n');
  const b = after.replace(/\n$/, '').split('\n');
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
  }
  const ops: [' ' | '-' | '+', string][] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) { ops.push([' ', a[i]]); i++; j++; }
    else if (i < a.length && (j === b.length || lcs[i + 1][j] >= lcs[i][j + 1])) ops.push(['-', a[i++]]);
    else ops.push(['+', b[j++]]);
  }
  const keep = ops.map((op, k) => op[0] !== ' ' || ops.slice(Math.max(0, k - 2), k + 3).some((o) => o[0] !== ' '));
  const out: string[] = [];
  ops.forEach((op, k) => {
    if (keep[k]) out.push(`${op[0]} ${op[1]}`);
    else if (keep[k - 1]) out.push('  …');
  });
  return out;
}

function coveredByPlan(f: Finding, files: Map<string, FilePlan>): boolean {
  const server = f.title.match(/"(.+)"/)?.[1];
  return [...files.values()].some((p) => p.changes.some((c) => c.startsWith(`Pin MCP server "${server}"`)));
}

function updateJson(text: string | undefined, mutate: (data: Record<string, any>) => void): string | undefined {
  let data: Record<string, any> = {};
  if (text !== undefined && text.trim()) {
    try { data = JSON.parse(text); } catch { return undefined; } // leave hand-written JSONC alone
  }
  mutate(data);
  return JSON.stringify(data, null, 2) + '\n';
}

/** MCP server entry by name in .mcp.json, Cursor / Desktop configs, or ~/.claude.json (top level or this project). */
function findServer(data: Record<string, any>, name: string, dir: string): Record<string, any> | undefined {
  return data.mcpServers?.[name] ?? data.projects?.[dir]?.mcpServers?.[name] ?? data.servers?.[name];
}

function isUnpinned(pkg: string): boolean {
  const at = pkg.lastIndexOf('@');
  if (at <= 0) return true;
  const version = pkg.slice(at + 1);
  return version === 'latest' || version === 'next' || /^[\^~]/.test(version);
}

function stripVersion(pkg: string): string {
  const at = pkg.lastIndexOf('@');
  return at > 0 ? pkg.slice(0, at) : pkg;
}

function readText(file: string): string | undefined {
  try { return readFileSync(file, 'utf8'); } catch { return undefined; }
}

