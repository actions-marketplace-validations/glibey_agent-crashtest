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
    for (const id of ['lethal-trifecta', 'hidden-tag-chars', 'exfil-commands', 'interpreters', 'secrets-readable', 'auto-project-mcp', 'mcp-unpinned', 'mcp-plaintext-secret']) {
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

test('bypassPermissions is critical', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    mkdirSync(join(dir, '.claude'));
    writeFileSync(join(dir, '.claude/settings.json'), JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }));
    assert.ok(ids(dir).includes('bypass-permissions'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
