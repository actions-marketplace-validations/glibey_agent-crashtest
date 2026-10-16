/**
 * Research script: find public repos that commit AI-agent config, fetch ONLY those config files
 * (never .env or other secrets), and run agent-crashtest checks on them.
 *
 *   node dist/research/scan-github.js [--pages 5] [--max-repos 2000] [--out research-out]
 *   node dist/research/scan-github.js --from research-out/results.jsonl   # re-check known repos, no search
 *
 * Output: <out>/results.jsonl (one line per repo, private) and <out>/summary.md (aggregate stats).
 */
import { execSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';
import { evaluate, type ScanResult } from '../scan.js';
import { collect } from '../collect.js';

const CONFIG_PATHS = [
  '.mcp.json',
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.cursor/mcp.json',
  '.vscode/mcp.json',
  'CLAUDE.md',
  'AGENTS.md',
  '.cursorrules',
];

const QUERIES = [
  'filename:.mcp.json mcpServers',
  'path:.claude filename:settings.json permissions',
  'path:.claude filename:settings.local.json',
  'path:.cursor filename:mcp.json',
];
const SIZE_SLICES = ['size:<200', 'size:200..500', 'size:500..1200', 'size:>1200'];

const { values } = parseArgs({
  options: {
    pages: { type: 'string', default: '5' },
    'max-repos': { type: 'string', default: '2000' },
    out: { type: 'string', default: 'research-out' },
    from: { type: 'string' },
  },
});
const PAGES = Number(values.pages);
const MAX_REPOS = Number(values['max-repos']);
const OUT = values.out!;
const token = process.env.GITHUB_TOKEN ?? execSync('gh auth token').toString().trim();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const log = (...a: unknown[]) => console.error(new Date().toISOString().slice(11, 19), ...a);

async function gh(url: string, init: RequestInit = {}): Promise<any> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const res = await fetch(url, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', ...init.headers },
    });
    if (res.status === 403 || res.status === 429) {
      const reset = Number(res.headers.get('x-ratelimit-reset')) * 1000;
      const wait = Math.max(10_000, Math.min(reset - Date.now() + 1000, 120_000));
      log(`rate limited, waiting ${Math.round(wait / 1000)}s`);
      await sleep(wait);
      continue;
    }
    if (!res.ok) throw new Error(`${res.status} ${url}`);
    return res.json();
  }
  throw new Error(`gave up on ${url}`);
}

async function searchRepos(): Promise<string[]> {
  const repos = new Set<string>();
  for (const q of QUERIES) {
    for (const slice of SIZE_SLICES) {
      for (let page = 1; page <= PAGES; page++) {
        const url = `https://api.github.com/search/code?q=${encodeURIComponent(`${q} ${slice}`)}&per_page=100&page=${page}`;
        let data;
        try { data = await gh(url); } catch (e) { log(String(e)); break; }
        const items = data.items ?? [];
        for (const it of items) {
          if (!it.repository.fork) repos.add(it.repository.full_name);
        }
        log(`"${q} ${slice}" p${page}: +${items.length} (repos: ${repos.size})`);
        await sleep(6500); // code search: 10 requests/minute
        if (items.length < 100) break;
      }
    }
  }
  return [...repos];
}

async function fetchStars(repos: string[]): Promise<Map<string, number>> {
  const stars = new Map<string, number>();
  for (let i = 0; i < repos.length; i += 50) {
    const batch = repos.slice(i, i + 50);
    const fields = batch.map((r, j) => {
      const [owner, name] = r.split('/');
      return `r${j}: repository(owner: ${JSON.stringify(owner)}, name: ${JSON.stringify(name)}) { nameWithOwner stargazerCount }`;
    });
    try {
      const data = await gh('https://api.github.com/graphql', {
        method: 'POST',
        body: JSON.stringify({ query: `{ ${fields.join('\n')} }` }),
      });
      for (const v of Object.values<any>(data.data ?? {})) if (v) stars.set(v.nameWithOwner, v.stargazerCount);
    } catch (e) {
      log(String(e));
    }
  }
  return stars;
}

async function fetchConfigs(repo: string): Promise<Record<string, string>> {
  const cacheFile = join(OUT, 'cache', `${repo.replace('/', '__')}.json`);
  if (existsSync(cacheFile)) return JSON.parse(readFileSync(cacheFile, 'utf8'));
  const files: Record<string, string> = {};
  await Promise.all(CONFIG_PATHS.map(async (p) => {
    try {
      const res = await fetch(`https://raw.githubusercontent.com/${repo}/HEAD/${p}`);
      if (res.ok) {
        const text = await res.text();
        if (text.length < 256 * 1024) files[p] = text;
      }
    } catch { /* missing file or network hiccup */ }
  }));
  writeFileSync(cacheFile, JSON.stringify(files));
  return files;
}

function scanFiles(files: Record<string, string>): ScanResult {
  const dir = mkdtempSync(join(tmpdir(), 'act-research-'));
  try {
    for (const [p, content] of Object.entries(files)) {
      mkdirSync(dirname(join(dir, p)), { recursive: true });
      writeFileSync(join(dir, p), content);
    }
    return evaluate(collect({ dir, home: '/nonexistent-home', includeHome: false }));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

interface Row {
  repo: string;
  stars: number;
  files: string[];
  score: number;
  findings: { id: string; severity: string; title: string }[];
}

async function main() {
  mkdirSync(join(OUT, 'cache'), { recursive: true });
  let repos: string[];
  let stars: Map<string, number>;
  if (values.from) {
    const previous: Row[] = readFileSync(values.from, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    repos = previous.map((r) => r.repo);
    stars = new Map(previous.map((r) => [r.repo, r.stars]));
    log(`re-checking ${repos.length} repos from ${values.from}`);
  } else {
    repos = (await searchRepos()).slice(0, MAX_REPOS);
    log(`found ${repos.length} repos, fetching stars`);
    stars = await fetchStars(repos);
  }
  const resultsFile = join(OUT, 'results.jsonl');
  writeFileSync(resultsFile, '');

  const rows: Row[] = [];
  let next = 0;
  const worker = async () => {
    while (next < repos.length) {
      const repo = repos[next++];
      const files = await fetchConfigs(repo);
      if (!Object.keys(files).length) continue;
      const r = scanFiles(files);
      const row: Row = {
        repo,
        stars: stars.get(repo) ?? 0,
        files: Object.keys(files),
        score: r.score,
        findings: r.findings.map(({ id, severity, title }) => ({ id, severity, title })),
      };
      rows.push(row);
      appendFileSync(resultsFile, JSON.stringify(row) + '\n');
      if (rows.length % 100 === 0) log(`scanned ${rows.length}/${repos.length}`);
    }
  };
  await Promise.all(Array.from({ length: 12 }, worker));

  writeFileSync(join(OUT, 'summary.md'), summarize(rows));
  log(`done: ${rows.length} repos → ${OUT}/summary.md`);
}

function summarize(rows: Row[]): string {
  const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(1)}%` : '–');
  const section = (title: string, set: Row[]) => {
    const counts = new Map<string, number>();
    for (const r of set) for (const id of new Set(r.findings.map((f) => f.id))) counts.set(id, (counts.get(id) ?? 0) + 1);
    const withCritical = set.filter((r) => r.findings.some((f) => f.severity === 'critical')).length;
    const withHigh = set.filter((r) => r.findings.some((f) => f.severity === 'critical' || f.severity === 'high')).length;
    const avg = set.reduce((s, r) => s + r.score, 0) / (set.length || 1);
    const lines = [
      `## ${title} (n=${set.length})`,
      '',
      `- average score: **${avg.toFixed(1)}/100**`,
      `- at least one CRITICAL: **${withCritical} (${pct(withCritical, set.length)})**`,
      `- at least one CRITICAL or HIGH: **${withHigh} (${pct(withHigh, set.length)})**`,
      '',
      '| finding | repos | share |',
      '|---|---|---|',
      ...[...counts.entries()].sort((a, b) => b[1] - a[1]).map(([id, n]) => `| ${id} | ${n} | ${pct(n, set.length)} |`),
      '',
    ];
    return lines.join('\n');
  };

  const grades = ['A', 'B', 'C', 'D', 'F'].map((g) => {
    const n = rows.filter((r) => grade(r.score) === g).length;
    return `| ${g} | ${n} | ${pct(n, rows.length)} |`;
  });

  return [
    `# agent-crashtest: public GitHub research (${new Date().toISOString().slice(0, 10)})`,
    '',
    'Only committed agent config files were fetched (.mcp.json, .claude/settings*.json, .cursor/mcp.json, .vscode/mcp.json, CLAUDE.md, AGENTS.md, .cursorrules). No .env or other secret files.',
    '',
    section('All repos', rows),
    section('Repos with 100+ stars', rows.filter((r) => r.stars >= 100)),
    '## Grade distribution',
    '',
    '| grade | repos | share |',
    '|---|---|---|',
    ...grades,
    '',
  ].join('\n');
}

function grade(score: number): string {
  return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
