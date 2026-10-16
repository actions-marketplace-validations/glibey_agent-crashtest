import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Client, Context, McpServer, SettingsFile, TextFile } from './types.js';

const MAX_TEXT_BYTES = 256 * 1024;
const MAX_TEXT_FILES = 800;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'cache', 'file-history', 'backups']);

export interface CollectOptions {
  dir: string;
  home: string;
  includeHome: boolean;
}

export function collect(opts: CollectOptions): Context {
  const dir = resolve(opts.dir);
  const { home, includeHome } = opts;

  const settingsPaths = [
    join(dir, '.claude/settings.json'),
    join(dir, '.claude/settings.local.json'),
  ];
  if (includeHome) {
    settingsPaths.push(
      join(home, '.claude/settings.json'),
      join(home, '.claude/settings.local.json'),
      '/Library/Application Support/ClaudeCode/managed-settings.json',
      '/etc/claude-code/managed-settings.json',
    );
  }
  const claudeSettings: SettingsFile[] = [];
  for (const file of settingsPaths) {
    const data = readJson(file);
    if (data && typeof data === 'object') claudeSettings.push({ file, data });
  }

  const secretFiles = collectSecrets(dir, home, includeHome);
  return {
    dir,
    home,
    includeHome,
    claudeSettings,
    mcpServers: collectMcp(dir, home, includeHome),
    instructionFiles: collectInstructions(dir, home, includeHome),
    secretFiles,
    envKeys: collectEnvKeys(dir, secretFiles),
    workflows: collectWorkflows(dir),
  };
}

function collectMcp(dir: string, home: string, includeHome: boolean): McpServer[] {
  const servers: McpServer[] = [];
  const add = (client: Client, file: string, map: unknown) => {
    if (!map || typeof map !== 'object') return;
    for (const [name, cfg] of Object.entries(map as Record<string, any>)) {
      if (!cfg || typeof cfg !== 'object') continue;
      servers.push({
        name,
        client,
        file,
        command: typeof cfg.command === 'string' ? cfg.command : undefined,
        args: Array.isArray(cfg.args) ? cfg.args.map(String) : [],
        url: typeof cfg.url === 'string' ? cfg.url : typeof cfg.serverUrl === 'string' ? cfg.serverUrl : undefined,
        env: cfg.env && typeof cfg.env === 'object' ? stringMap(cfg.env) : {},
      });
    }
  };

  const projectMcp = join(dir, '.mcp.json');
  add('claude-code', projectMcp, readJson(projectMcp)?.mcpServers);
  const projectCursor = join(dir, '.cursor/mcp.json');
  add('cursor', projectCursor, readJson(projectCursor)?.mcpServers);
  const projectVscode = join(dir, '.vscode/mcp.json');
  add('vscode', projectVscode, readJson(projectVscode)?.servers);

  if (includeHome) {
    const claudeJsonPath = join(home, '.claude.json');
    const claudeJson = readJson(claudeJsonPath);
    add('claude-code', claudeJsonPath, claudeJson?.mcpServers);
    add('claude-code', claudeJsonPath, claudeJson?.projects?.[dir]?.mcpServers);
    const cursorGlobal = join(home, '.cursor/mcp.json');
    add('cursor', cursorGlobal, readJson(cursorGlobal)?.mcpServers);
    const desktop = join(home, 'Library/Application Support/Claude/claude_desktop_config.json');
    add('claude-desktop', desktop, readJson(desktop)?.mcpServers);
  }
  return servers;
}

function collectInstructions(dir: string, home: string, includeHome: boolean): TextFile[] {
  const files: TextFile[] = [];
  const seen = new Set<string>();
  const addFile = (file: string) => {
    if (seen.has(file) || files.length >= MAX_TEXT_FILES) return;
    seen.add(file);
    const content = readText(file);
    if (content !== undefined) files.push({ file, content });
  };
  const addTree = (root: string, depth = 6) => {
    walk(root, depth, (file) => {
      if (/\.(md|mdc|txt)$/i.test(file) || /\.cursorrules$/.test(file)) addFile(file);
    });
  };

  for (const name of ['CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', 'GEMINI.md', '.cursorrules', '.windsurfrules', '.github/copilot-instructions.md']) {
    addFile(join(dir, name));
  }
  addTree(join(dir, '.cursor/rules'));
  addTree(join(dir, '.claude'));
  if (includeHome) {
    addFile(join(home, '.claude/CLAUDE.md'));
    for (const sub of ['skills', 'commands', 'agents', 'plugins']) addTree(join(home, '.claude', sub));
  }
  return files;
}

const PROJECT_SECRET = /^(\.env(\..+)?|.*\.pem|.*\.key|id_rsa|id_ed25519|credentials\.json|service-account.*\.json|\.npmrc|\.pypirc)$/;
const NOT_SECRET = /\.(example|sample|template|dist)$/;

function collectSecrets(dir: string, home: string, includeHome: boolean): string[] {
  const found: string[] = [];
  for (const name of safeReaddir(dir)) {
    if (PROJECT_SECRET.test(name) && !NOT_SECRET.test(name) && isFile(join(dir, name))) found.push(join(dir, name));
  }
  if (includeHome) {
    for (const rel of ['.aws/credentials', '.ssh/id_rsa', '.ssh/id_ed25519', '.npmrc', '.netrc', '.config/gh/hosts.yml', '.docker/config.json', '.kube/config']) {
      const file = join(home, rel);
      if (isFile(file)) found.push(file);
    }
  }
  return found;
}

function walk(root: string, depth: number, visit: (file: string) => void) {
  if (depth < 0) return;
  for (const name of safeReaddir(root)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(root, name);
    let st;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) walk(full, depth - 1, visit);
    else if (st.isFile()) visit(full);
  }
}

export function readJson(file: string): any {
  const text = readText(file);
  if (text === undefined) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    try {
      // tolerate JSONC (VS Code style comments and trailing commas)
      return JSON.parse(text.replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/,(\s*[}\]])/g, '$1'));
    } catch {
      return undefined;
    }
  }
}

function readText(file: string): string | undefined {
  try {
    if (!existsSync(file)) return undefined;
    const st = statSync(file);
    if (!st.isFile() || st.size > MAX_TEXT_BYTES) return undefined;
    return readFileSync(file, 'utf8');
  } catch {
    return undefined;
  }
}

function safeReaddir(dir: string): string[] {
  try { return readdirSync(dir); } catch { return []; }
}

function isFile(file: string): boolean {
  try { return statSync(file).isFile(); } catch { return false; }
}

function stringMap(obj: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) out[k] = String(v);
  return out;
}

function collectWorkflows(dir: string): TextFile[] {
  const wfDir = join(dir, '.github/workflows');
  return safeReaddir(wfDir)
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => ({ file: join(wfDir, name), content: readText(join(wfDir, name)) }))
    .filter((f): f is TextFile => f.content !== undefined);
}

/** Reads only the variable names from project .env files. Values are never kept. */
function collectEnvKeys(dir: string, secretFiles: string[]): Record<string, string[]> {
  const keys: Record<string, string[]> = {};
  for (const file of secretFiles) {
    if (!file.startsWith(dir + '/') || !/\/\.env[^/]*$/.test(file)) continue;
    const names = (readText(file) ?? '')
      .split('\n')
      .map((line) => line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/)?.[1])
      .filter((n): n is string => !!n);
    if (names.length) keys[file] = names;
  }
  return keys;
}
