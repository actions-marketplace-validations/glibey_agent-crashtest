import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createDemoProject } from './demo.js';
import { scan } from './scan.js';

const run = (dir: string) => scan({ dir, home: '/nonexistent-home', includeHome: false });
const ids = (dir: string) => run(dir).findings.map((f) => f.id);

test('demo project gets totaled', () => {
  const dir = createDemoProject();
  try {
    const result = run(dir);
    const found = result.findings.map((f) => f.id);
    for (const id of ['lethal-trifecta', 'hidden-tag-chars', 'exfil-commands', 'interpreters', 'wallet-keys-readable', 'auto-project-mcp', 'mcp-unpinned', 'mcp-plaintext-secret']) {
      assert.ok(found.includes(id), `expected ${id}, got ${found.join(', ')}`);
    }
    assert.equal(result.grade, 'F');
    const hidden = result.findings.find((f) => f.id === 'hidden-tag-chars')!;
    assert.match(hidden.detail, /attacker\.example/);
    const secret = result.findings.find((f) => f.id === 'mcp-plaintext-secret')!;
    assert.doesNotMatch(secret.detail, /DEMOfake0000/, 'secret must be masked');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('empty project scores 100', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    const result = run(dir);
    assert.equal(result.score, 100);
    assert.equal(result.findings.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('deny rule protects .env and pinned servers pass', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    mkdirSync(join(dir, '.claude'));
    writeFileSync(join(dir, '.env'), 'X=1');
    writeFileSync(join(dir, '.claude/settings.json'), JSON.stringify({
      permissions: { allow: ['Bash(npm test:*)'], deny: ['Read(./.env)'] },
      hooks: { PreToolUse: [] },
    }));
    writeFileSync(join(dir, '.mcp.json'), JSON.stringify({
      mcpServers: { pg: { command: 'npx', args: ['-y', '@scope/server-postgres@1.2.3'] } },
    }));
    assert.deepEqual(ids(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bypassPermissions is critical in user settings but ignored in project settings', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  const home = mkdtempSync(join(tmpdir(), 'act-home-'));
  try {
    mkdirSync(join(dir, '.claude'));
    writeFileSync(join(dir, '.claude/settings.json'), JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }));
    assert.ok(ids(dir).includes('bypass-ignored'));
    assert.ok(!ids(dir).includes('bypass-permissions'));

    mkdirSync(join(home, '.claude'));
    writeFileSync(join(home, '.claude/settings.json'), JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }));
    const userScope = scan({ dir, home, includeHome: true }).findings.map((f) => f.id);
    assert.ok(userScope.includes('bypass-permissions'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test('wallet keys are critical, ordinary env is high, RANDOM_SEED is not a wallet', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    writeFileSync(join(dir, '.env'), 'RANDOM_SEED=1\nAPI_KEY=x\n');
    assert.deepEqual(ids(dir), ['secrets-readable']);
    writeFileSync(join(dir, '.env'), 'export POLY_PK=0xabc\n');
    const f = run(dir).findings;
    assert.deepEqual(f.map((x) => x.id), ['wallet-keys-readable']);
    assert.doesNotMatch(f[0].detail, /0xabc/, 'values must never appear');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('only broad network and interpreter rules are flagged', async () => {
  const { isExfilRule, isInterpreterRule } = await import('./checks/permissions.js');
  for (const r of ['Bash(curl:*)', 'Bash(wget *)', 'Bash(gh api:*)', 'Bash(curl -X POST *)']) assert.ok(isExfilRule(r), r);
  for (const r of ['Bash(curl -s http://localhost:8088/api/health)', 'Bash(curl http://127.0.0.1:3000/*)', 'Bash(curl https://api.example.com/*)', 'Bash(curl -s https://x.dev/status)', 'Bash(gh pr view:*)']) assert.ok(!isExfilRule(r), r);
  for (const r of ['Bash(python:*)', 'Bash(python3 *)', 'Bash(node -e:*)', 'Bash(npx:*)', 'Bash(npx tsx:*)', 'Bash(bash:*)', 'Bash(node)']) assert.ok(isInterpreterRule(r), r);
  for (const r of ['Bash(npx eslint:*)', 'Bash(npx tsc:*)', 'Bash(npx prisma:*)', 'Bash(bash scripts/*.sh)', 'Bash(python -m pytest:*)', 'Bash(node dist/cli.js:*)', 'Bash(nodemon:*)']) assert.ok(!isInterpreterRule(r), r);
});

test('defensive CLAUDE.md rules about .env are not flagged', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    writeFileSync(join(dir, 'CLAUDE.md'), '- **Do NOT** `cat .env*` or print secrets.\nInstall: curl -fsSL https://bun.sh/install | bash\n');
    assert.deepEqual(ids(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
