import type { Context, Finding } from '../types.js';

export interface Permissions {
  allow: string[];
  deny: string[];
  bypass: boolean;
  bashUnrestricted: boolean;
  exfilCommands: string[];
  interpreters: string[];
  webFetchUnrestricted: boolean;
  webSearch: boolean;
  envDenied: boolean;
}

const EXFIL = /^Bash\((curl|wget|nc|ncat|netcat|scp|sftp|ssh|rsync|ftp|telnet|gh api|http|xh)\b/;
const INTERPRETER = /^Bash\((python3?|node|deno|bun|ruby|perl|php|bash|sh|zsh|eval|npx|uvx)\b/;
const WALLET_KEY = /(^|_)(PRIVATE_?KEY|PRIV_?KEY|PK|MNEMONIC|SEED_?PHRASE|SECRET_?PHRASE|KEYPAIR|WALLET_?(KEY|SECRET))(_|$)/;

export function readPermissions(ctx: Context): Permissions {
  const allow: string[] = [];
  const deny: string[] = [];
  let bypass = false;
  for (const { data } of ctx.claudeSettings) {
    const p = data.permissions ?? {};
    if (Array.isArray(p.allow)) allow.push(...p.allow.map(String));
    if (Array.isArray(p.deny)) deny.push(...p.deny.map(String));
    if (p.defaultMode === 'bypassPermissions') bypass = true;
  }
  return {
    allow,
    deny,
    bypass,
    bashUnrestricted: bypass || allow.some((r) => /^Bash(\(\*(:\*)?\))?$/.test(r.trim())),
    exfilCommands: allow.filter((r) => EXFIL.test(r)),
    interpreters: allow.filter((r) => INTERPRETER.test(r)),
    webFetchUnrestricted: bypass || allow.includes('WebFetch'),
    webSearch: bypass || allow.includes('WebSearch'),
    envDenied: deny.some((r) => /^Read\([^)]*\.env/.test(r) || /^Read\(\*\*\)$/.test(r)),
  };
}

export function checkPermissions(ctx: Context, perms: Permissions): Finding[] {
  const findings: Finding[] = [];
  const settingsFile = ctx.claudeSettings[0]?.file;

  if (perms.bypass) {
    findings.push({
      id: 'bypass-permissions',
      severity: 'critical',
      title: 'Claude Code runs in bypassPermissions mode',
      detail: 'Every tool call runs without asking. One poisoned README or web page is enough to take over the agent.',
      fix: 'Remove "defaultMode": "bypassPermissions". Use it only inside a container or VM with no secrets.',
      file: ctx.claudeSettings.find((s) => s.data.permissions?.defaultMode === 'bypassPermissions')?.file,
    });
  } else if (perms.bashUnrestricted) {
    findings.push({
      id: 'bash-unrestricted',
      severity: 'critical',
      title: 'Any shell command is auto-approved',
      detail: 'An allow rule like "Bash" or "Bash(*)" lets injected instructions run curl, rm, or anything else silently.',
      fix: 'Replace it with narrow rules such as "Bash(npm test:*)" or "Bash(git status)".',
      file: settingsFile,
    });
  }

  if (!perms.bashUnrestricted && perms.exfilCommands.length) {
    findings.push({
      id: 'exfil-commands',
      severity: 'high',
      title: 'Network commands are auto-approved',
      detail: `Allowed without asking: ${perms.exfilCommands.join(', ')}. These are a direct channel to send your data out.`,
      fix: 'Remove these allow rules, or limit them to exact URLs you trust.',
      file: settingsFile,
    });
  }

  if (!perms.bashUnrestricted && perms.interpreters.length) {
    findings.push({
      id: 'interpreters',
      severity: 'high',
      title: 'Script interpreters are auto-approved',
      detail: `Allowed without asking: ${perms.interpreters.join(', ')}. "python -c" or "node -e" can run any code, so this equals unrestricted shell.`,
      fix: 'Allow specific scripts ("Bash(node scripts/build.js)") instead of the whole interpreter.',
      file: settingsFile,
    });
  }

  if (!perms.bypass && perms.allow.includes('WebFetch')) {
    findings.push({
      id: 'webfetch-any',
      severity: 'medium',
      title: 'WebFetch is auto-approved for every domain',
      detail: 'The agent reads any web page without asking. Web pages are the #1 source of indirect prompt injection.',
      fix: 'Use per-domain rules like "WebFetch(domain:docs.python.org)".',
      file: settingsFile,
    });
  }

  const projectSecrets = ctx.secretFiles.filter((f) => f.startsWith(ctx.dir + '/'));
  const walletKeys = Object.entries(ctx.envKeys).flatMap(([file, names]) =>
    names.filter((n) => WALLET_KEY.test(n.toUpperCase())).map((n) => `${n} (${file.slice(ctx.dir.length + 1)})`));
  if (walletKeys.length && !perms.envDenied) {
    findings.push({
      id: 'wallet-keys-readable',
      severity: 'critical',
      title: 'Wallet private keys are readable by the agent',
      detail: `${walletKeys.join(', ')}. One injected instruction can read the key, and a leaked private key means drained funds, not a rotated token.`,
      fix: 'Add "Read(./.env)" and "Read(./.env.*)" to permissions.deny, and keep signing keys in a hardware wallet or a key manager, not in the repo.',
    });
  } else if (projectSecrets.length && !perms.envDenied) {
    findings.push({
      id: 'secrets-readable',
      severity: 'high',
      title: 'Secret files are readable by the agent',
      detail: `Found ${projectSecrets.map((f) => f.slice(ctx.dir.length + 1)).join(', ')} and no deny rule. Claude Code reads project files without asking.`,
      fix: 'Add "Read(./.env)" and "Read(./.env.*)" (and other secret paths) to permissions.deny.',
    });
  }

  for (const { file, data } of ctx.claudeSettings) {
    if (data.enableAllProjectMcpServers === true) {
      findings.push({
        id: 'auto-project-mcp',
        severity: 'high',
        title: 'Project MCP servers are enabled automatically',
        detail: 'Any repo you clone can ship a .mcp.json that starts a server on your machine without asking.',
        fix: 'Remove "enableAllProjectMcpServers": true and approve servers one by one.',
        file,
      });
    }
    if (data.skipDangerousModePermissionPrompt === true) {
      findings.push({
        id: 'skip-danger-prompt',
        severity: 'medium',
        title: 'Dangerous-mode warning is turned off',
        detail: 'You will not be warned when a session starts with all permissions bypassed.',
        fix: 'Remove "skipDangerousModePermissionPrompt".',
        file,
      });
    }
  }

  const sandboxOn = ctx.claudeSettings.some((s) => s.data.sandbox?.enabled === true);
  if (perms.bashUnrestricted && !sandboxOn) {
    findings.push({
      id: 'no-sandbox',
      severity: 'medium',
      title: 'Shell runs without a sandbox',
      detail: 'Auto-approved commands have full access to your filesystem and network.',
      fix: 'Enable "sandbox": { "enabled": true } in Claude Code settings, or run the agent in a dev container.',
      file: settingsFile,
    });
  }

  const hasHooks = ctx.claudeSettings.some((s) => s.data.hooks && Object.keys(s.data.hooks).length > 0);
  if (ctx.claudeSettings.length && !hasHooks) {
    findings.push({
      id: 'no-hooks',
      severity: 'low',
      title: 'No guard hooks configured',
      detail: 'Nothing inspects tool inputs or outputs before the agent acts on them.',
      fix: 'Add a PreToolUse/PostToolUse hook that scans for injection patterns and blocks risky commands.',
    });
  }

  return findings;
}
