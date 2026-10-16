import { inDir } from '../paths.js';
import type { Context, Finding } from '../types.js';
import { categorize, type McpCategory } from './mcp.js';
import type { Permissions } from './permissions.js';

interface Leg {
  auto: string[]; // capabilities that work without asking, even in auto mode
  headless: string[]; // auto-approved only where auto mode is off (Manual mode, claude -p, Agent SDK, CI)
  gated: string[]; // capabilities that exist but need your approval click
}

/**
 * The "lethal trifecta" (Simon Willison): an agent that can
 *  1. read untrusted content, 2. access private data, 3. send data out
 * can be made to steal your data by a single injected instruction.
 */
export function checkTrifecta(ctx: Context, perms: Permissions): Finding[] {
  const legs: Record<McpCategory, Leg> = {
    untrusted: { auto: [], headless: [], gated: [] },
    private: { auto: [], headless: [], gated: [] },
    exfil: { auto: [], headless: [], gated: [] },
  };

  if (perms.webFetchUnrestricted) legs.untrusted.auto.push('WebFetch');
  if (perms.webSearch) legs.untrusted.auto.push('WebSearch');
  // bypassPermissions in user settings really is fully automatic; Bash(*) is dropped by auto mode.
  const shellLeg = perms.bypass ? 'auto' : 'headless';
  if (perms.bashUnrestricted) {
    legs.untrusted[shellLeg].push('shell (curl)');
    legs.exfil[shellLeg].push('shell (curl)');
  }
  if (perms.exfilCommands.length) legs.exfil.auto.push('network commands');
  if (perms.interpreters.length) legs.exfil.headless.push('script interpreters');
  if (perms.webFetchUnrestricted) legs.exfil.auto.push('WebFetch (URL query params)');

  if (perms.readableSecrets.length) legs.private.auto.push('project secret files');
  const homeSecrets = ctx.secretFiles.filter((f) => !inDir(f, ctx.dir));
  if (homeSecrets.length && perms.bashUnrestricted) legs.private[shellLeg].push('~/.ssh, ~/.aws and other home credentials');

  for (const server of ctx.mcpServers) {
    const auto = server.client === 'claude-code' && isMcpAutoApproved(server.name, perms);
    for (const cat of categorize(server)) {
      (auto ? legs[cat].auto : legs[cat].gated).push(`MCP "${server.name}"`);
    }
  }

  const has = (l: Leg) => l.auto.length + l.headless.length + l.gated.length > 0;
  const auto = (l: Leg) => l.auto.length > 0;
  const autoOrHeadless = (l: Leg) => l.auto.length + l.headless.length > 0;
  const fullyAuto = auto(legs.untrusted) && auto(legs.private) && auto(legs.exfil);
  const headlessAuto = autoOrHeadless(legs.untrusted) && autoOrHeadless(legs.private) && autoOrHeadless(legs.exfil);
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
  if (headlessAuto) {
    return [{
      id: 'lethal-trifecta-headless',
      severity: 'high',
      title: 'Lethal trifecta in headless runs',
      detail: `Interactive auto mode breaks the chain by dropping broad shell rules, but Manual mode and headless runs (claude -p, Agent SDK, CI) let an injection read secrets and send them out with no one watching. ${summary}.`,
      fix: 'Replace "Bash(*)" and interpreter rules with narrow ones, and never run headless agents on untrusted input (PRs, issues, web pages) with this config.',
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
  const items = [...leg.auto.map((a) => `${a} (auto)`), ...leg.headless.map((a) => `${a} (headless)`), ...leg.gated];
  return items.length ? [...new Set(items)].join(', ') : 'none';
}
