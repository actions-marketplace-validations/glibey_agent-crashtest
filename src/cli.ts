#!/usr/bin/env node
import { readFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { parseArgs } from 'node:util';
import { createDemoProject } from './demo.js';
import { renderText } from './report.js';
import { scan } from './scan.js';

const HELP = `
  agent-crashtest — crash-test your AI coding agent setup

  Usage
    npx agent-crashtest [options]

  Options
    --dir <path>       project to scan (default: current directory)
    --project-only     skip global config in your home directory
    --json             machine-readable output
    --ci               exit with code 1 on critical or high findings
    --demo             scan a deliberately vulnerable sample project
    -v, --version
    -h, --help

  Scans Claude Code, Cursor, Claude Desktop and VS Code agent configs:
  permissions, MCP servers, CLAUDE.md / rules / skills, and secrets in reach.
  Runs 100% locally.
`;

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const { values } = parseArgs({
  options: {
    dir: { type: 'string' },
    'project-only': { type: 'boolean' },
    json: { type: 'boolean' },
    ci: { type: 'boolean' },
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

const home = homedir();
const demoDir = values.demo ? createDemoProject() : undefined;
try {
  const result = scan({
    dir: demoDir ?? values.dir ?? process.cwd(),
    home,
    includeHome: !values['project-only'] && !demoDir,
  });

  if (values.json) console.log(JSON.stringify(result, null, 2));
  else console.log(renderText(result, version, home));

  if (values.ci && result.findings.some((f) => f.severity === 'critical' || f.severity === 'high')) {
    process.exitCode = 1;
  }
} finally {
  if (demoDir) rmSync(demoDir, { recursive: true, force: true });
}
