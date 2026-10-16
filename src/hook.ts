import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanResult } from './scan.js';

const REMIND_AFTER_MS = 7 * 24 * 3600 * 1000;

/**
 * Output for a Claude Code SessionStart hook: a short warning for the user when the setup has
 * critical findings, nothing otherwise. The same set of findings is shown once a week at most.
 */
export function sessionStartOutput(result: ScanResult, stateDir: string | undefined, now = Date.now()): string | undefined {
  const critical = result.findings.filter((f) => f.severity === 'critical');
  if (!critical.length) return undefined;

  const fingerprint = createHash('sha256').update(result.dir + critical.map((f) => f.id + f.title).sort().join('\n')).digest('hex').slice(0, 16);
  if (stateDir && !shouldShow(stateDir, fingerprint, now)) return undefined;

  const titles = critical.slice(0, 3).map((f) => f.title);
  const more = critical.length > titles.length ? ` and ${critical.length - titles.length} more` : '';
  return JSON.stringify({
    systemMessage: `⚠️ agent-crashtest: ${critical.length} critical issue${critical.length > 1 ? 's' : ''} in this agent setup: ${titles.join('; ')}${more}. Run /agent-crashtest:crashtest to review and fix.`,
    hookSpecificOutput: {
      hookEventName: 'SessionStart',
      additionalContext: `agent-crashtest found ${critical.length} critical issue(s) in this project's AI agent setup (score ${result.score}/100): ${critical.map((f) => f.title).join('; ')}. If the user asks about them, the agent-crashtest:crashtest skill explains and fixes them.`,
    },
  });
}

function shouldShow(stateDir: string, fingerprint: string, now: number): boolean {
  const file = join(stateDir, 'session-warnings.json');
  let state: Record<string, number> = {};
  try { state = JSON.parse(readFileSync(file, 'utf8')); } catch { /* first run */ }
  const last = state[fingerprint];
  if (last !== undefined && now - last < REMIND_AFTER_MS) return false;
  state[fingerprint] = now;
  try {
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(file, JSON.stringify(state));
  } catch { /* still show the warning if state can't be saved */ }
  return true;
}
