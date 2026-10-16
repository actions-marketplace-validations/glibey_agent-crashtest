import type { ScanResult } from './scan.js';

const REPO = 'https://github.com/glibey/agent-crashtest';
const COLOR: Record<string, string> = { A: 'brightgreen', B: 'green', C: 'yellow', D: 'orange', F: 'red' };

/** Static shields.io badge with the grade and score, linking to agent-crashtest. */
export function badgeMarkdown(result: Pick<ScanResult, 'grade' | 'score'>): string {
  const message = `${result.grade} · ${result.score}/100`;
  const url = `https://img.shields.io/badge/${escape('agent-crashtest')}-${escape(message)}-${COLOR[result.grade] ?? 'lightgrey'}`;
  return `[![agent-crashtest: ${message}](${url})](${REPO})`;
}

/** Live badge for a repo that runs the GitHub Action in .github/workflows/<workflow>. */
export function workflowBadgeMarkdown(repo: string, workflow = 'agent-crashtest.yml'): string {
  return `[![agent-crashtest](https://github.com/${repo}/actions/workflows/${workflow}/badge.svg)](https://github.com/${repo}/actions/workflows/${workflow})`;
}

// shields.io path segments: "-" and "_" are doubled, everything else is URL-encoded.
function escape(s: string): string {
  return encodeURIComponent(s.replace(/-/g, '--').replace(/_/g, '__'));
}
