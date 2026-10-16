import { collect, type CollectOptions } from './collect.js';
import { checkInstructions } from './checks/instructions.js';
import { checkMcp } from './checks/mcp.js';
import { checkPermissions, readPermissions } from './checks/permissions.js';
import { checkTrifecta } from './checks/trifecta.js';
import type { Context, Finding, Severity } from './types.js';

export const PENALTY: Record<Severity, number> = { critical: 30, high: 12, medium: 5, low: 1 };
const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

export interface ScanResult {
  dir: string;
  score: number;
  grade: string;
  findings: Finding[];
  stats: { settings: number; mcpServers: number; instructionFiles: number; secretFiles: number };
}

export function scan(opts: CollectOptions): ScanResult {
  return evaluate(collect(opts));
}

export function evaluate(ctx: Context): ScanResult {
  const perms = readPermissions(ctx);
  const findings = [
    ...checkTrifecta(ctx, perms),
    ...checkPermissions(ctx, perms),
    ...checkMcp(ctx),
    ...checkInstructions(ctx),
  ].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));

  const score = Math.max(0, 100 - findings.reduce((sum, f) => sum + PENALTY[f.severity], 0));
  return {
    dir: ctx.dir,
    score,
    grade: grade(score),
    findings,
    stats: {
      settings: ctx.claudeSettings.length,
      mcpServers: ctx.mcpServers.length,
      instructionFiles: ctx.instructionFiles.length,
      secretFiles: ctx.secretFiles.length,
    },
  };
}

function grade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}
