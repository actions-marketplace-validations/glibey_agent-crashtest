import type { Context, Finding } from '../types.js';
import { categorize, type McpCategory } from './mcp.js';
import type { Permissions } from './permissions.js';

interface Leg {
  auto: string[]; // capabilities that work without asking
  gated: string[]; // capabilities that exist but need your approval click
}

/**
 * The "lethal trifecta" (Simon Willison): an agent that can
 *  1. read untrusted content, 2. access private data, 3. send data out
 * can be made to steal your data by a single injected instruction.
 */
export function checkTrifecta(ctx: Context, perms: Permissions): Finding[] {
  const legs: Record<McpCategory, Leg> = {
    untrusted: { auto: [], gated: [] },
    private: { auto: [], gated: [] },
    exfil: { auto: [], gated: [] },
  };

  if (perms.webFetchUnrestricted) legs.untrusted.auto.push('WebFetch');
  if (perms.webSearch) legs.untrusted.auto.push('WebSearch');
  if (perms.bashUnrestricted) {
    legs.untrusted.auto.push('shell (curl)');
    legs.exfil.auto.push('shell (curl)');
  }
  if (perms.exfilCommands.length || perms.interpreters.length) legs.exfil.auto.push('network/interpreter commands');
  if (perms.webFetchUnrestricted) legs.exfil.auto.push('WebFetch (URL query params)');

  const projectSecrets = ctx.secretFiles.filter((f) => f.startsWith(ctx.dir));
  if (projectSecrets.length && !perms.envDenied) legs.private.auto.push('project secret files');
  const homeSecrets = ctx.secretFiles.filter((f) => !f.startsWith(ctx.dir));
  if (homeSecrets.length && perms.bashUnrestricted) legs.private.auto.push('~/.ssh, ~/.aws and other home credentials');

  for (const server of ctx.mcpServers) {
    const auto = server.client === 'claude-code' && isMcpAutoApproved(server.name, perms);
    for (const cat of categorize(server)) {
      (auto ? legs[cat].auto : legs[cat].gated).push(`MCP "${server.name}"`);
    }
  }

  const has = (l: Leg) => l.auto.length + l.gated.length > 0;
  const fullyAuto = legs.untrusted.auto.length && legs.private.auto.length && legs.exfil.auto.length;
  const summary =
    `untrusted input: ${list(legs.untrusted)} · private data: ${list(legs.private)} · way out: ${list(legs.exfil)}`;

  if (fullyAuto) {
    return [{
      id: 'lethal-trifecta',
      severity: 'critical',
      title: 'Lethal trifecta, fully automatic',
      detail: `Your agent can read attacker-controlled content, access secrets and send them out — all without asking you. ${summary}.`,
      fix: 'Break at least one leg: deny secret reads, remove auto-approval for network tools, or run in a sandbox without credentials.',
    }];
  }
  if (has(legs.untrusted) && has(legs.private) && has(legs.exfil)) {
    return [{
      id: 'lethal-trifecta-gated',
      severity: 'medium',
      title: 'Lethal trifecta, protected only by approval clicks',
      detail: `All three legs exist; only your "Yes" button stands between an injection and a data leak (approval fatigue is real). ${summary}.`,
      fix: 'Split risky MCP servers into separate projects or profiles so one session never holds all three.',
    }];
  }
  return [];
}

function isMcpAutoApproved(name: string, perms: Permissions): boolean {
  if (perms.bypass) return true;
  return perms.allow.some((r) => r === `mcp__${name}` || r.startsWith(`mcp__${name}__`));
}

function list(leg: Leg): string {
  const items = [...leg.auto.map((a) => `${a} (auto)`), ...leg.gated];
  return items.length ? [...new Set(items)].join(', ') : 'none';
}
