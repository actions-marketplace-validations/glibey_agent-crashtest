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

const wf = (dir: string, name: string, yaml: string) => {
  mkdirSync(join(dir, '.github/workflows'), { recursive: true });
  writeFileSync(join(dir, '.github/workflows', name), yaml);
};

test('CI: claude-code-action with defaults is fine, risky inputs are flagged', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    wf(dir, 'claude.yml', `on:\n  issue_comment:\n    types: [created]\njobs:\n  claude:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}\n`);
    assert.deepEqual(ids(dir), []);
    wf(dir, 'triage.yml', `on: [issues]\njobs:\n  t:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: "*"\n          allowed_bots: '*'\n`);
    assert.deepEqual(ids(dir).sort(), ['ci-any-bot', 'ci-non-write-users']);
    const sev = () => run(dir).findings.find((f) => f.id === 'ci-non-write-users')!.severity;
    assert.equal(sev(), 'high');
    wf(dir, 'triage.yml', `on: [issues]\npermissions:\n  issues: write\njobs:\n  t:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: "*"\n          claude_args: '--allowedTools "Bash(gh issue view:*)"'\n`);
    assert.equal(sev(), 'medium', 'documented safe triage shape');
    wf(dir, 'triage.yml', `on: [issues]\njobs:\n  t:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          claude_args: '--dangerously-skip-permissions'\n`);
    assert.equal(sev(), 'critical');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CI: raw claude -p on untrusted events with skipped permissions is critical', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    wf(dir, 'review.yml', `name: review\n'on':\n  pull_request_target:\n    types: [opened]\njobs:\n  r:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n      - run: npx @anthropic-ai/claude-code -p "review this PR" --dangerously-skip-permissions\n`);
    const f = run(dir).findings;
    assert.deepEqual(f.map((x) => x.id).sort(), ['ci-prt-head-checkout', 'ci-skip-permissions', 'ci-unchecked-trigger']);
    assert.ok(f.every((x) => x.severity === 'critical' || x.id === 'ci-prt-head-checkout'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CI: PR head in a subdirectory and push-only agents are not flagged', async () => {
  const { triggers } = await import('./checks/workflows.js');
  assert.deepEqual(triggers('on:\n  push:\n  pull_request:\njobs:'), ['pull_request', 'push']);
  assert.deepEqual(triggers('on:\n  repository_dispatch:\n    types: [issue_comment, ci_failure]\n'), ['repository_dispatch']);
  assert.deepEqual(triggers('on:\n  - issues\n  - push\n'), ['issues', 'push']);
  assert.deepEqual(triggers('on: [issues, issue_comment]\n'), ['issue_comment', 'issues']);
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    wf(dir, 'a.yml', `on:\n  pull_request_target:\njobs:\n  r:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n          path: pr-head\n      - uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: "--add-dir pr-head"\n`);
    wf(dir, 'b.yml', `on: push\njobs:\n  r:\n    steps:\n      - run: claude -p "update changelog" --allowedTools "Bash"\n`);
    assert.deepEqual(ids(dir), ['ci-broad-tools']);
    assert.equal(run(dir).findings[0].severity, 'medium');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CI: actor gates and maintainer-only label triggers are not flagged as open to strangers', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    wf(dir, 'gated.yml', `on:\n  issue_comment:\n    types: [created]\njobs:\n  r:\n    if: contains(fromJSON('["OWNER","MEMBER"]'), github.event.comment.author_association)\n    steps:\n      - run: claude -p "fix it"\n`);
    wf(dir, 'label.yml', `on:\n  issues:\n    types: [labeled]\njobs:\n  r:\n    steps:\n      - run: claude -p "work on the issue"\n`);
    assert.deepEqual(ids(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CI: an empty allowed_non_write_users keeps the write check on', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    wf(dir, 'c.yml', `on:\n  issue_comment:\njobs:\n  c:\n    steps:\n      - uses: anthropics/claude-code-action@8251c103ac8c1d761882c86aba1412c7f583c844\n        with:\n          allowed_non_write_users: ""\n          claude_args: --allowedTools "Bash"\n`);
    const f = run(dir).findings;
    assert.deepEqual(f.map((x) => [x.id, x.severity]), [['ci-broad-tools', 'medium']]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
