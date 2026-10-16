import { appendFileSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';
import type { ScanResult } from './scan.js';
import type { Finding, Severity } from './types.js';

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const LEVEL: Record<Severity, 'error' | 'warning' | 'notice'> = { critical: 'error', high: 'error', medium: 'warning', low: 'notice' };
const ICON: Record<Severity, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪' };
const REPO = 'https://github.com/glibey/agent-crashtest';

/** True when any finding is at or above `threshold` ("none" never fails). */
export function failsAt(result: ScanResult, threshold: string): boolean {
  const limit = SEVERITIES.indexOf(threshold as Severity);
  if (limit < 0) return false;
  return result.findings.some((f) => SEVERITIES.indexOf(f.severity) <= limit);
}

/** Workflow commands that show findings as annotations on the PR diff. */
export function annotations(result: ScanResult, workspace: string): string[] {
  return result.findings.map((f) => {
    const file = repoPath(f, workspace);
    const props = [file && `file=${escapeProperty(file)}`, `title=${escapeProperty(`${f.severity.toUpperCase()}: ${f.title}`)}`]
      .filter(Boolean)
      .join(',');
    return `::${LEVEL[f.severity]} ${props}::${escapeData(`${f.detail}\nFix: ${f.fix}`)}`;
  });
}

/** Markdown for the job summary page. */
export function summary(result: ScanResult, version: string, workspace: string): string {
  const { score, grade, findings } = result;
  const counts = SEVERITIES.map((s) => `${ICON[s]} ${findings.filter((f) => f.severity === s).length} ${s}`).join(' · ');
  const lines = [`## 💥 agent-crashtest: ${score}/100 (grade ${grade})`, '', counts, ''];
  if (findings.length) {
    lines.push('| | Finding | File |', '|---|---|---|');
    for (const f of findings) lines.push(`| ${ICON[f.severity]} | ${cell(f.title)} | ${cell(repoPath(f, workspace) ?? '')} |`);
    lines.push('', '<details><summary>How to fix</summary>', '');
    for (const f of findings) lines.push(`- **${cell(f.title)}**: ${cell(f.fix)}`);
    lines.push('', '</details>');
  } else {
    lines.push('No issues found. ✅');
  }
  lines.push('', `<sub>Ran on the runner, nothing was sent anywhere. [agent-crashtest](${REPO}) v${version} · Using agents across a team? [Early access](${REPO}/issues/1)</sub>`, '');
  return lines.join('\n');
}

/** Prints annotations and writes the job summary and step outputs when running in GitHub Actions. */
export function reportToGithub(result: ScanResult, version: string, workspace: string): void {
  for (const line of annotations(result, workspace)) console.log(line);
  const env = process.env;
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, summary(result, version, workspace));
  if (env.GITHUB_OUTPUT) {
    const count = (s: Severity) => result.findings.filter((f) => f.severity === s).length;
    appendFileSync(env.GITHUB_OUTPUT, [
      `score=${result.score}`,
      `grade=${result.grade}`,
      ...SEVERITIES.map((s) => `${s}=${count(s)}`),
      '',
    ].join('\n'));
  }
}

function repoPath(f: Finding, workspace: string): string | undefined {
  if (!f.file) return undefined;
  const rel = relative(workspace, f.file);
  return rel && !rel.startsWith('..') && !isAbsolute(rel) ? rel : undefined;
}

function escapeData(s: string): string {
  return s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProperty(s: string): string {
  return escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function cell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}
