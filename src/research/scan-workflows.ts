/**
 * Research script: find public GitHub Actions workflows that run AI coding agents and run the CI checks on them.
 * Only workflow files are fetched.
 *
 *   node dist/research/scan-workflows.js [--pages 3] [--out research-ci]
 */
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { checkWorkflows } from '../checks/workflows.js';
import type { Context, Finding } from '../types.js';

const QUERIES = [
  'allowed_non_write_users path:.github/workflows',
  'allowed_bots path:.github/workflows claude',
  'claude-code-base-action path:.github/workflows',
  'dangerously-skip-permissions path:.github/workflows',
  '"claude -p" path:.github/workflows',
  '"codex exec" path:.github/workflows',
  'anthropics/claude-code-action pull_request_target path:.github/workflows',
  'anthropics/claude-code-action issues path:.github/workflows',
];

const { values } = parseArgs({
  options: {
    pages: { type: 'string', default: '3' },
    out: { type: 'string', default: 'research-ci' },
  },
});
const OUT = values.out!;
const token = process.env.GITHUB_TOKEN ?? execSync('gh auth token').toString().trim();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const log = (...a: unknown[]) => console.error(new Date().toISOString().slice(11, 19), ...a);

async function gh(url: string, init: RequestInit = {}): Promise<any> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const res = await fetch(url, { ...init, headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', ...init.headers } });
    if (res.status === 403 || res.status === 429) {
      await sleep(30_000);
      continue;
    }
    if (!res.ok) throw new Error(`${res.status} ${url}`);
    return res.json();
  }
  throw new Error(`gave up on ${url}`);
}

interface Hit { repo: string; path: string; raw: string }

async function search(): Promise<Hit[]> {
  const hits = new Map<string, Hit>();
  for (const q of QUERIES) {
    for (let page = 1; page <= Number(values.pages); page++) {
      let data;
      try {
        data = await gh(`https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=100&page=${page}`);
      } catch (e) { log(String(e)); break; }
      for (const it of data.items ?? []) {
        if (it.repository.fork || !/^\.github\/workflows\/[^/]+\.ya?ml$/.test(it.path)) continue;
        const raw = it.html_url.replace('https://github.com/', 'https://raw.githubusercontent.com/').replace('/blob/', '/');
        hits.set(`${it.repository.full_name}/${it.path}`, { repo: it.repository.full_name, path: it.path, raw });
      }
      log(`"${q}" p${page}: ${data.items?.length ?? 0} (files: ${hits.size})`);
      await sleep(6500);
      if ((data.items?.length ?? 0) < 100) break;
    }
  }
  return [...hits.values()];
}

async function stars(repos: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  for (let i = 0; i < repos.length; i += 50) {
    const fields = repos.slice(i, i + 50).map((r, j) => {
      const [owner, name] = r.split('/');
      return `r${j}: repository(owner: ${JSON.stringify(owner)}, name: ${JSON.stringify(name)}) { nameWithOwner stargazerCount }`;
    });
    try {
      const data = await gh('https://api.github.com/graphql', { method: 'POST', body: JSON.stringify({ query: `{ ${fields.join('\n')} }` }) });
      for (const v of Object.values<any>(data.data ?? {})) if (v) out.set(v.nameWithOwner, v.stargazerCount);
    } catch (e) { log(String(e)); }
  }
  return out;
}

async function main() {
  mkdirSync(join(OUT, 'cache'), { recursive: true });
  const hits = await search();
  const byRepo = new Map<string, Hit[]>();
  for (const h of hits) byRepo.set(h.repo, [...(byRepo.get(h.repo) ?? []), h]);
  log(`${hits.length} workflow files in ${byRepo.size} repos; fetching`);
  const starMap = await stars([...byRepo.keys()]);

  const rows: { repo: string; stars: number; findings: Pick<Finding, 'id' | 'severity' | 'title'>[] }[] = [];
  const repos = [...byRepo.keys()];
  let next = 0;
  await Promise.all(Array.from({ length: 12 }, async () => {
    while (next < repos.length) {
      const repo = repos[next++];
      const dir = mkdtempSync(join(tmpdir(), 'act-ci-'));
      try {
        const workflows = [];
        for (const h of byRepo.get(repo)!) {
          const cache = join(OUT, 'cache', `${(repo + '/' + h.path).replace(/\//g, '__')}`);
          let content: string | undefined;
          if (existsSync(cache)) content = readFileSync(cache, 'utf8');
          else {
            const res = await fetch(h.raw).catch(() => undefined);
            if (res?.ok) { content = await res.text(); writeFileSync(cache, content); }
          }
          if (content) workflows.push({ file: join(dir, h.path), content });
        }
        const ctx: Context = { dir, home: '/nonexistent', includeHome: false, claudeSettings: [], mcpServers: [], instructionFiles: [], secretFiles: [], envKeys: {}, codexConfigs: [], workflows };
        const findings = checkWorkflows(ctx).map(({ id, severity, title }) => ({ id, severity, title: title.replace(dir + '/', '') }));
        rows.push({ repo, stars: starMap.get(repo) ?? 0, findings });
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  }));

  writeFileSync(join(OUT, 'results.jsonl'), rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  const count = (pred: (f: { id: string; severity: string }) => boolean) => rows.filter((r) => r.findings.some(pred)).length;
  const ids = new Map<string, number>();
  for (const r of rows) for (const id of new Set(r.findings.map((f) => f.id))) ids.set(id, (ids.get(id) ?? 0) + 1);
  const summary = [
    `# AI agents in public GitHub Actions (${new Date().toISOString().slice(0, 10)})`,
    '',
    `Repos with agent workflows matched by search: **${rows.length}**`,
    `- with a CRITICAL finding: **${count((f) => f.severity === 'critical')}**`,
    `- with CRITICAL or HIGH: **${count((f) => f.severity === 'critical' || f.severity === 'high')}**`,
    '',
    '| finding | repos |',
    '|---|---|',
    ...[...ids].sort((a, b) => b[1] - a[1]).map(([id, n]) => `| ${id} | ${n} |`),
    '',
  ].join('\n');
  writeFileSync(join(OUT, 'summary.md'), summary);
  log('done');
}

main().catch((e) => { console.error(e); process.exit(1); });
