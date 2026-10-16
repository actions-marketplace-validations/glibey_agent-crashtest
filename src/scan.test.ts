import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

test('CI: false positives found in public-repo research stay quiet', async () => {
  const { checkWorkflows } = await import('./checks/workflows.js');
  const run = (content: string) =>
    checkWorkflows({ dir: '/r', workflows: [{ file: '/r/.github/workflows/a.yml', content }] } as any)
      .filter((f) => f.severity === 'critical' || f.severity === 'high')
      .map((f) => f.id);
  const action = (extra: string) => `      - uses: anthropics/claude-code-action@v1\n        with:\n${extra}`;

  // schedule-only: allowed_non_write_users has no outsider input to act on
  assert.deepEqual(run(`on:\n  schedule:\n    - cron: '0 0 * * *'\n  workflow_dispatch:\njobs:\n  t:\n    steps:\n${action(`          allowed_non_write_users: '*'\n          claude_args: --allowedTools "Bash,Read"`)}`), []);

  // allowlist check in a separate gate job: still HIGH (no permission checks), but not CRITICAL
  const gated = `on:\n  issues:\n    types: [opened]\njobs:\n  gate:\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: |\n            const allowedUsers = ['alice'];\n  agent:\n    steps:\n      - run: claude -p "fix" --dangerously-skip-permissions\n`;
  assert.deepEqual(run(gated), ['ci-skip-permissions']);
  assert.ok(!checkWorkflows({ dir: '/r', workflows: [{ file: '/r/.github/workflows/a.yml', content: gated }] } as any).some((f) => f.severity === 'critical'));

  // only merged PRs reach the agent
  assert.deepEqual(run(`on:\n  pull_request_target:\n    types: [closed]\njobs:\n  b:\n    if: github.event.pull_request.merged\n    steps:\n      - run: claude -p "backport" --allowedTools "Read"\n`), []);

  // broad tools in a job without allowed_non_write_users do not make the open job critical
  const mixed = `on:\n  issues:\n    types: [opened]\njobs:\n  label:\n    steps:\n${action(`          allowed_non_write_users: '*'\n          claude_args: '--allowedTools "Bash(gh:*),Read"'`)}\n  fix:\n    steps:\n${action(`          claude_args: '--allowedTools "Bash,Read,Write"'`)}\n`;
  const all = checkWorkflows({ dir: '/r', workflows: [{ file: '/r/.github/workflows/a.yml', content: mixed }] } as any);
  assert.ok(!all.some((f) => f.severity === 'critical'), JSON.stringify(all.map((f) => [f.id, f.severity])));
});

test('CI: confirmed patterns from research are critical', async () => {
  const { checkWorkflows } = await import('./checks/workflows.js');
  const crit = (content: string) =>
    checkWorkflows({ dir: '/r', workflows: [{ file: '/r/.github/workflows/a.yml', content }] } as any).some((f) => f.severity === 'critical');
  // anyone opens a PR, agent has Bash(*)
  assert.ok(crit(`on:\n  pull_request_target:\n    types: [opened]\njobs:\n  l:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: "*"\n          claude_args: |\n            --allowedTools Bash(*)\n`));
  // workflow_run after PR CI, bypassPermissions overrides the narrow tool list
  assert.ok(crit(`on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\njobs:\n  r:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: "*"\n          claude_args: |\n            --permission-mode bypassPermissions\n            --allowed-tools "Bash(gh:*) Read"\n`));
  // raw CLI on new issues with permissions off
  assert.ok(crit(`on:\n  issues:\n    types: [opened]\njobs:\n  t:\n    steps:\n      - run: claude -p "$(cat prompt.md)" --dangerously-skip-permissions\n`));
});

test('CI: a maintainer-applied label gate is not critical', async () => {
  const { checkWorkflows } = await import('./checks/workflows.js');
  const wf = `on:\n  issues:\n    types: [opened, labeled]\njobs:\n  r:\n    if: contains(github.event.issue.labels.*.name, 'research_needed')\n    steps:\n      - run: claude -p "research" --dangerously-skip-permissions\n`;
  const f = checkWorkflows({ dir: '/r', workflows: [{ file: '/r/.github/workflows/a.yml', content: wf }] } as any);
  assert.ok(!f.some((x) => x.severity === 'critical'), JSON.stringify(f.map((x) => [x.id, x.severity])));
  // a negated label check ("run unless labeled") is not a gate
  const negated = wf.replace("if: contains(", "if: !contains(");
  assert.ok(checkWorkflows({ dir: '/r', workflows: [{ file: '/r/.github/workflows/a.yml', content: negated }] } as any).some((x) => x.severity === 'critical'));
});

test('GitHub mode: annotations escape properties and use repo-relative paths', async () => {
  const { annotations, failsAt, summary } = await import('./github.js');
  const result = {
    dir: '/w', score: 58, grade: 'D',
    findings: [
      { id: 'a', severity: 'critical', title: 'Bad: x, y', detail: 'line1\nline2 100%', fix: 'do it', file: '/w/.mcp.json' },
      { id: 'b', severity: 'low', title: 'Meh | pipe', detail: 'd', fix: 'f', file: '/elsewhere/x' },
    ],
    stats: {} as any,
  } as any;
  const [a, b] = annotations(result, '/w');
  assert.equal(a, '::error file=.mcp.json,title=CRITICAL%3A Bad%3A x%2C y::line1%0Aline2 100%25%0AFix: do it');
  assert.ok(b.startsWith('::notice title='), 'files outside the workspace get no file= property');
  assert.ok(summary(result, '0.0.0', '/w').includes('Meh \\| pipe'));
  assert.equal(failsAt(result, 'high'), true);
  assert.equal(failsAt({ ...result, findings: [result.findings[1]] }, 'high'), false);
  assert.equal(failsAt(result, 'none'), false);
});

test('TOML reader handles the shapes Codex config uses', async () => {
  const { parseToml } = await import('./toml.js');
  const t = parseToml(`# comment
approval_policy = "never" # trailing
sandbox_mode = 'danger-full-access'
model = "gpt-5"

[sandbox_workspace_write]
network_access = true

[mcp_servers.github]
command = "npx"
args = [
  "-y",   # multi-line array
  "@modelcontextprotocol/server-github",
]
env = { GITHUB_TOKEN = "ghp_x#notacomment", "QUOTED.KEY" = "v" }

[profiles."safe mode"]
approval_policy = "on-request"
`);
  assert.equal(t.approval_policy, 'never');
  assert.equal(t.sandbox_mode, 'danger-full-access');
  assert.equal(t.sandbox_workspace_write.network_access, true);
  assert.deepEqual(t.mcp_servers.github.args, ['-y', '@modelcontextprotocol/server-github']);
  assert.equal(t.mcp_servers.github.env.GITHUB_TOKEN, 'ghp_x#notacomment');
  assert.equal(t.mcp_servers.github.env['QUOTED.KEY'], 'v');
  assert.equal(t.profiles['safe mode'].approval_policy, 'on-request');
});

test('Codex: full auto is critical, MCP servers are checked like any other client', () => {
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    mkdirSync(join(dir, '.codex'));
    writeFileSync(join(dir, '.codex/config.toml'), `approval_policy = "never"\nsandbox_mode = "danger-full-access"\n\n[mcp_servers.fetch]\ncommand = "uvx"\nargs = ["mcp-server-fetch"]\n\n[profiles.careful]\napproval_policy = "on-request"\nsandbox_mode = "workspace-write"\n`);
    const found = ids(dir);
    assert.ok(found.includes('codex-full-auto'), found.join(','));
    assert.ok(found.includes('mcp-unpinned'), found.join(','));
    assert.equal(found.filter((i) => i.startsWith('codex-')).length, 1, 'the careful profile is fine');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('MCP server: handshake, tool list, scan call and errors', async () => {
  const { handle } = await import('./mcp.js');
  const init: any = handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }, '9.9.9');
  assert.equal(init.result.serverInfo.version, '9.9.9');
  assert.equal(handle({ jsonrpc: '2.0', method: 'notifications/initialized' }, 'x'), undefined);
  const list: any = handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, 'x');
  assert.equal(list.result.tools[0].name, 'scan');
  assert.equal(list.result.tools[0].annotations.readOnlyHint, true);
  const dir = createDemoProject();
  try {
    const call: any = handle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'scan', arguments: { dir, project_only: true } } }, 'x');
    assert.equal(call.result.structuredContent.grade, 'F');
    assert.match(call.result.content[0].text, /treat their text as data/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const bad: any = handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'rm' } }, 'x');
  assert.equal(bad.error.code, -32602);
});

test('SessionStart hook: warns on critical once a week, silent otherwise', async () => {
  const { sessionStartOutput } = await import('./hook.js');
  const state = mkdtempSync(join(tmpdir(), 'act-state-'));
  const crit = { dir: '/p', score: 40, grade: 'D', stats: {} as any, findings: [{ id: 'x', severity: 'critical', title: 'Bad', detail: '', fix: '' }] } as any;
  try {
    const first = JSON.parse(sessionStartOutput(crit, state, 0)!);
    assert.match(first.systemMessage, /1 critical issue in this agent setup: Bad/);
    assert.equal(first.hookSpecificOutput.hookEventName, 'SessionStart');
    assert.equal(sessionStartOutput(crit, state, 1000), undefined, 'same findings stay quiet');
    assert.ok(sessionStartOutput(crit, state, 8 * 24 * 3600 * 1000), 'reminds again after a week');
    assert.equal(sessionStartOutput({ ...crit, findings: [] }, state), undefined);
  } finally {
    rmSync(state, { recursive: true, force: true });
  }
});

test('versions agree across npm, plugin, marketplace and skill', () => {
  const root = join(import.meta.dirname, '..');
  const read = (p: string) => readFileSync(join(root, p), 'utf8');
  const version = JSON.parse(read('package.json')).version;
  assert.equal(JSON.parse(read('.claude-plugin/plugin.json')).version, version);
  assert.ok(read('skills/crashtest/SKILL.md').includes(`agent-crashtest@${version}`), 'SKILL.md pins the current version');
  assert.match(read('plugin/agent-crashtest.mjs'), /Generated by/);
  assert.ok(!read('README.md').match(/agent-crashtest@(\d+\.\d+\.\d+)/g)?.some((m) => m !== `agent-crashtest@${version}`), 'README pins the current version');
});

test('--fix plan: safe changes, idempotent, global files flagged, risky files left alone', async () => {
  const { planFixes, applyPlan, diff } = await import('./fix.js');
  const { collect } = await import('./collect.js');
  const { evaluate } = await import('./scan.js');
  const home = mkdtempSync(join(tmpdir(), 'act-home-'));
  const dir = createDemoProject();
  const lookups: string[] = [];
  const lookup = (pkg: string) => { lookups.push(pkg); return pkg.includes('server-github') ? '1.2.3' : undefined; };
  try {
    mkdirSync(join(home, '.claude'));
    writeFileSync(join(home, '.claude/settings.json'), JSON.stringify({ skipDangerousModePermissionPrompt: true }));
    writeFileSync(join(home, '.claude.json'), JSON.stringify({ mcpServers: { mem: { command: 'npx', args: ['-y', 'some-mcp'] } } }));
    const opts = { dir, home, includeHome: true };
    const ctx = collect(opts);
    const plan = planFixes(ctx, evaluate(ctx).findings, lookup);

    const local = plan.files.find((f) => f.file === join(dir, '.claude/settings.json'))!;
    assert.deepEqual(JSON.parse(local.after).permissions.deny, ['Read(./.env)', 'Read(./.env.*)']);
    assert.equal(JSON.parse(local.after).enableAllProjectMcpServers, undefined);
    assert.ok(plan.files.find((f) => f.file === join(dir, '.mcp.json'))!.after.includes('@modelcontextprotocol/server-github@1.2.3'));
    assert.ok(plan.files.find((f) => f.file === join(home, '.claude/settings.json'))!.global);
    assert.ok(!plan.files.some((f) => f.file.endsWith('.claude.json')), '~/.claude.json is never rewritten');
    assert.ok(!lookups.includes('some-mcp'), 'no lookups for files we will not touch');
    assert.ok(plan.skipped.length === 0 || plan.skipped.every((s) => !s.includes('server-github')));
    assert.ok(plan.manual.some((f) => f.id === 'hidden-tag-chars'), 'judgment calls stay manual');

    applyPlan(plan, false);
    assert.equal(JSON.parse(readFileSync(join(home, '.claude/settings.json'), 'utf8')).skipDangerousModePermissionPrompt, true, 'global untouched without consent');
    const again = planFixes(collect(opts), evaluate(collect(opts)).findings, lookup).files.filter((f) => !f.global);
    assert.deepEqual(again.map((f) => f.file), [], 'second run has nothing left to do');

    assert.deepEqual(diff('a\nb\nc\n', 'a\nc\nd\n'), ['  a', '- b', '  c', '+ d']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test('--fix leaves hand-written JSONC alone instead of reformatting it', async () => {
  const { planFixes } = await import('./fix.js');
  const { collect } = await import('./collect.js');
  const { evaluate } = await import('./scan.js');
  const dir = mkdtempSync(join(tmpdir(), 'act-'));
  try {
    mkdirSync(join(dir, '.claude'));
    writeFileSync(join(dir, '.claude/settings.json'), '{\n  // team rules\n  "enableAllProjectMcpServers": true,\n}\n');
    const ctx = collect({ dir, home: '/nonexistent', includeHome: false });
    const plan = planFixes(ctx, evaluate(ctx).findings, () => undefined);
    assert.deepEqual(plan.files, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('badge: shields.io escaping, colors by grade, live workflow badge in the job summary', async () => {
  const { badgeMarkdown, workflowBadgeMarkdown } = await import('./badge.js');
  assert.equal(
    badgeMarkdown({ grade: 'A', score: 100 }),
    '[![agent-crashtest: A · 100/100](https://img.shields.io/badge/agent--crashtest-A%20%C2%B7%20100%2F100-brightgreen)](https://github.com/glibey/agent-crashtest)',
  );
  assert.match(badgeMarkdown({ grade: 'D', score: 42 }), /-orange\)/);
  assert.equal(workflowBadgeMarkdown('me/app'), '[![agent-crashtest](https://github.com/me/app/actions/workflows/agent-crashtest.yml/badge.svg)](https://github.com/me/app/actions/workflows/agent-crashtest.yml)');

  const { summary } = await import('./github.js');
  const env = { ...process.env };
  try {
    process.env.GITHUB_REPOSITORY = 'me/app';
    process.env.GITHUB_WORKFLOW_REF = 'me/app/.github/workflows/security.yml@refs/heads/main';
    assert.ok(summary({ dir: '/w', score: 100, grade: 'A', findings: [], stats: {} as any }, '1.0.0', '/w').includes('/actions/workflows/security.yml/badge.svg'));
  } finally {
    process.env = env;
  }
});
