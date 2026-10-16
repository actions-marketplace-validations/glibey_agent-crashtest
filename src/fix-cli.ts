import { createInterface } from 'node:readline/promises';
import { collect, type CollectOptions } from './collect.js';
import { applyPlan, diff, planFixes, type FilePlan } from './fix.js';
import { SEVERITIES } from './github.js';
import { displayPath } from './paths.js';
import { c } from './report.js';
import { evaluate } from './scan.js';

/** `agent-crashtest --fix`: show the planned changes as diffs, apply them after confirmation, re-scan. */
export async function runFix(opts: CollectOptions, yes: boolean): Promise<void> {
  const before = evaluate(collect(opts));
  if (before.findings.some((f) => f.id === 'mcp-unpinned')) console.log(c.dim('  Looking up current MCP server versions on npm…'));
  const plan = planFixes(collect(opts), before.findings);
  const show = (file: string) => displayPath(file, before.dir, opts.home);

  console.log(`\n  ${c.bold('💥 agent-crashtest --fix')}   score ${c.bold(`${before.score}/100`)}\n`);
  for (const f of plan.files) {
    console.log(`  ${c.bold(show(f.file))}${f.before === undefined ? c.dim(' (new file)') : ''}${f.global ? c.yellow('  global: affects every project') : ''}`);
    for (const change of f.changes) console.log(`    ${c.cyan('•')} ${change}`);
    for (const line of diff(f.before, f.after)) {
      console.log(`      ${line.startsWith('+') ? c.green(line) : line.startsWith('-') ? c.red(line) : c.dim(line)}`);
    }
    console.log('');
  }
  for (const s of plan.skipped) console.log(`  ${c.yellow('!')} ${s}`);

  if (plan.manual.length) {
    console.log(`  ${c.bold('Needs your decision')} ${c.dim('(or ask your agent: the agent-crashtest skill walks through these)')}`);
    for (const f of plan.manual) console.log(`    ${c.dim('•')} ${f.title}\n      ${c.dim('fix →')} ${f.fix}`);
    console.log('');
  }

  const local = plan.files.filter((f) => !f.global);
  const global = plan.files.filter((f) => f.global);
  if (!plan.files.length) {
    console.log(`  Nothing to fix automatically.\n`);
    return;
  }

  let includeLocal = yes;
  let includeGlobal = false;
  if (!yes) {
    if (!process.stdin.isTTY) {
      console.log(c.dim('  Dry run. Re-run with --fix --yes to apply the project changes.\n'));
      return;
    }
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    try {
      if (local.length) includeLocal = /^y(es)?$/i.test((await rl.question(`  Apply ${count(local)} in this project? [y/N] `)).trim());
      if (global.length) includeGlobal = /^y(es)?$/i.test((await rl.question(`  Also change ${count(global)} in your home directory (every project)? [y/N] `)).trim());
    } finally {
      rl.close();
    }
  } else if (global.length) {
    console.log(c.dim(`  --yes changes project files only; run --fix without --yes to review the ${count(global)} in your home directory.`));
  }

  const written = applyPlan({ ...plan, files: plan.files.filter((f) => (f.global ? includeGlobal : includeLocal)) }, true);
  if (!written.length) {
    console.log(c.dim('\n  No changes made.\n'));
    return;
  }
  const after = evaluate(collect(opts));
  console.log(`\n  ${c.green('✓')} Updated ${written.map((f) => show(f.file)).join(', ')}`);
  console.log(`  Score ${c.bold(`${before.score}/100`)} → ${c.bold(c.green(`${after.score}/100`))} (grade ${after.grade})`);
  const changed = SEVERITIES.map((sev) => [sev, before.findings.filter((f) => f.severity === sev).length, after.findings.filter((f) => f.severity === sev).length] as const)
    .filter(([, b, a]) => b !== a)
    .map(([sev, b, a]) => `${sev} ${b} → ${a}`);
  if (changed.length) console.log(`  ${changed.join(' · ')}`);
  console.log('');
}

function count(files: FilePlan[]): string {
  return `${files.length} file${files.length > 1 ? 's' : ''}`;
}
