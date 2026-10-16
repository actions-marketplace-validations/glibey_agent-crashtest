#!/usr/bin/env node
import { readFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { parseArgs } from 'node:util';
import { createDemoProject } from './demo.js';
import { failsAt, reportToGithub, SEVERITIES } from './github.js';
import { sessionStartOutput } from './hook.js';
import { serve } from './mcp.js';
import { runFix } from './fix-cli.js';
import { badgeMarkdown } from './badge.js';
import { renderText } from './report.js';
import { scan } from './scan.js';

const HELP = `
  agent-crashtest — crash-test your AI coding agent setup

  Usage
    npx agent-crashtest [options]
    npx agent-crashtest mcp          run as an MCP server (stdio) for Cursor, Codex, Claude Desktop…

  Options
    --dir <path>       project to scan (default: current directory)
    --project-only     skip global config in your home directory
    --fix              show safe fixes as diffs and apply them after you confirm
    --yes              with --fix: apply project changes without asking
    --badge            print a README badge with your grade
    --json             machine-readable output
    --fail-on <level>  exit with code 1 on findings at or above: critical, high, medium, low
    --ci               same as --fail-on high
    --github           GitHub Actions mode: PR annotations, job summary, step outputs
    --demo             scan a deliberately vulnerable sample project
    -v, --version
    -h, --help

  Scans Claude Code, Cursor, Claude Desktop and VS Code agent configs:
  permissions, MCP servers, CLAUDE.md / rules / skills, and secrets in reach.
  Runs 100% locally.
`;

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    dir: { type: 'string' },
    'project-only': { type: 'boolean' },
    json: { type: 'boolean' },
    ci: { type: 'boolean' },
    'fail-on': { type: 'string' },
    github: { type: 'boolean' },
    hook: { type: 'string' },
    fix: { type: 'boolean' },
    badge: { type: 'boolean' },
    yes: { type: 'boolean', short: 'y' },
    demo: { type: 'boolean' },
    version: { type: 'boolean', short: 'v' },
    help: { type: 'boolean', short: 'h' },
  },
});

if (values.help) {
  console.log(HELP);
  process.exit(0);
}
if (values.version) {
  console.log(version);
  process.exit(0);
}

if (positionals[0] === 'mcp') serve(version);
else if (values.hook === 'session-start') sessionStart();
else if (values.fix) fix();
else run();

async function fix() {
  const demoDir = values.demo ? createDemoProject() : undefined;
  try {
    await runFix({ dir: demoDir ?? values.dir ?? process.cwd(), home: homedir(), includeHome: !values['project-only'] && !demoDir }, !!values.yes);
  } finally {
    if (demoDir) rmSync(demoDir, { recursive: true, force: true });
  }
}

/** Claude Code SessionStart hook: must be quiet, fast, and never break the session. */
function sessionStart() {
  try {
    const out = sessionStartOutput(
      scan({ dir: process.env.CLAUDE_PROJECT_DIR ?? values.dir ?? process.cwd(), home: homedir(), includeHome: true }),
      process.env.CLAUDE_PLUGIN_DATA,
    );
    if (out) console.log(out);
  } catch { /* a scanner bug must never block a session */ }
}

function run() {
  const failOn = values['fail-on'] ?? (values.ci ? 'high' : 'none');
  if (failOn !== 'none' && !SEVERITIES.includes(failOn as never)) {
    console.error(`--fail-on must be one of: ${SEVERITIES.join(', ')}, none`);
    process.exit(2);
  }

  const home = homedir();
  const demoDir = values.demo ? createDemoProject() : undefined;
  try {
    const result = scan({
      dir: demoDir ?? values.dir ?? process.cwd(),
      home,
      includeHome: !values['project-only'] && !demoDir,
    });

    if (values.badge) {
      console.log(badgeMarkdown(result));
      return;
    }
    if (values.json) console.log(JSON.stringify(result, null, 2));
    else console.log(renderText(result, version, home));
    if (values.github) reportToGithub(result, version, result.dir);

    if (failsAt(result, failOn)) process.exitCode = 1;
  } finally {
    if (demoDir) rmSync(demoDir, { recursive: true, force: true });
  }
}
