import type { ScanResult } from './scan.js';
import type { Severity } from './types.js';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const c = {
  bold: paint('1'),
  dim: paint('2'),
  red: paint('31'),
  green: paint('32'),
  yellow: paint('33'),
  blue: paint('34'),
  magenta: paint('35'),
  cyan: paint('36'),
  inverse: paint('7;1'),
};

const BADGE: Record<Severity, (s: string) => string> = {
  critical: (s) => c.inverse(c.red(s)),
  high: c.red,
  medium: c.yellow,
  low: c.dim,
};

export function renderText(result: ScanResult, version: string, home: string): string {
  const { score, grade, findings, stats } = result;
  const out: string[] = [];
  const color = score >= 75 ? c.green : score >= 40 ? c.yellow : c.red;

  out.push('');
  out.push(`  ${c.bold('💥 agent-crashtest')} ${c.dim(`v${version}`)}  ${c.dim('how hackable is your AI coding agent?')}`);
  out.push(c.dim(`  scanned ${stats.settings} settings · ${stats.mcpServers} MCP servers · ${stats.instructionFiles} instruction/skill files · ${stats.secretFiles} secret files · ${stats.workflows} CI workflows`));
  out.push('');
  out.push(`  ${c.bold('SCORE')}  ${color(c.bold(`${score}/100`))}   ${c.bold('grade')} ${color(c.bold(grade))}   ${bar(score, color)}`);
  out.push('');

  if (!findings.length) {
    out.push(`  ${c.green('No issues found.')} Your agent setup looks tight.`);
  }
  for (const f of findings) {
    out.push(`  ${BADGE[f.severity](` ${f.severity.toUpperCase()} `)} ${c.bold(f.title)}`);
    out.push(wrap(f.detail, 4));
    out.push(`    ${c.cyan('fix →')} ${f.fix}`);
    if (f.file) out.push(c.dim(`    ${displayPath(f.file, result.dir, home)}`));
    out.push('');
  }

  const counts = (['critical', 'high', 'medium', 'low'] as Severity[])
    .map((s) => `${findings.filter((f) => f.severity === s).length} ${s}`)
    .join(' · ');
  out.push(c.dim(`  ${counts}`));
  out.push('');
  out.push(`  ${c.magenta('Share your score:')}`);
  out.push(`  ${shareText(result)}`);
  out.push('');
  out.push(c.dim('  Everything ran locally. Nothing was sent anywhere.'));
  out.push('');
  return out.join('\n');
}

export function shareText({ score, grade }: ScanResult): string {
  const verdict = score >= 90 ? 'survived the crash test 🛡️' : score >= 60 ? 'got dented 🚗💥' : 'got totaled 💀';
  return `My AI coding agent scored ${score}/100 (${grade}) on agent-crashtest and ${verdict} Test yours: npx agent-crashtest`;
}

function bar(score: number, color: (s: string) => string): string {
  const filled = Math.round(score / 5);
  return color('█'.repeat(filled)) + c.dim('░'.repeat(20 - filled));
}

function wrap(text: string, indent: number, width = 92): string {
  const pad = ' '.repeat(indent);
  const lines: string[] = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if ((line + ' ' + word).trim().length > width - indent) {
      lines.push(pad + line.trim());
      line = word;
    } else line += ' ' + word;
  }
  if (line.trim()) lines.push(pad + line.trim());
  return lines.join('\n');
}

function displayPath(file: string, dir: string, home: string): string {
  if (file.startsWith(dir + '/')) return file.slice(dir.length + 1);
  return file.startsWith(home) ? '~' + file.slice(home.length) : file;
}
