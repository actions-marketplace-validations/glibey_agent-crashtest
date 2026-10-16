import type { Context, Finding } from '../types.js';

/** Codex CLI / IDE settings: approval_policy and sandbox_mode, at the top level and in each profile. */
export function checkCodex(ctx: Context): Finding[] {
  const findings: Finding[] = [];
  for (const { file, data } of ctx.codexConfigs) {
    const scopes: [string, Record<string, any>][] = [['', data]];
    for (const [name, profile] of Object.entries<any>(data.profiles ?? {})) {
      if (profile && typeof profile === 'object') scopes.push([` (profile "${name}")`, { ...data, ...profile }]);
    }
    for (const [where, cfg] of scopes) {
      if (where && cfg.approval_policy === data.approval_policy && cfg.sandbox_mode === data.sandbox_mode) continue;
      const never = cfg.approval_policy === 'never';
      const fullAccess = cfg.sandbox_mode === 'danger-full-access';
      const network = cfg.sandbox_workspace_write?.network_access === true;
      if (never && fullAccess) {
        findings.push({
          id: 'codex-full-auto',
          severity: 'critical',
          title: `Codex runs every command with no approval and no sandbox${where}`,
          detail: 'approval_policy = "never" with sandbox_mode = "danger-full-access" is the same as --dangerously-bypass-approvals-and-sandbox: one injected instruction can read any file and send it anywhere.',
          fix: 'Use sandbox_mode = "workspace-write" and approval_policy = "on-request", or keep full access only inside a container without secrets.',
          file,
        });
      } else if (fullAccess) {
        findings.push({
          id: 'codex-no-sandbox',
          severity: 'high',
          title: `Codex runs without a sandbox${where}`,
          detail: 'sandbox_mode = "danger-full-access" gives every approved command full disk and network access. Approval prompts are the only guard left.',
          fix: 'Use sandbox_mode = "workspace-write".',
          file,
        });
      } else if (never && network) {
        findings.push({
          id: 'codex-never-network',
          severity: 'high',
          title: `Codex runs commands without approval and with network access${where}`,
          detail: 'approval_policy = "never" plus network_access = true in the workspace sandbox lets injected commands read project files, including .env, and send them out.',
          fix: 'Set approval_policy = "on-request", or turn network_access off.',
          file,
        });
      }
    }
  }
  return findings;
}
