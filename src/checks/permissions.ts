import type { Context, Finding } from '../types.js';

export interface Permissions {
  allow: string[];
  deny: string[];
  bypass: boolean;
  /** Project file that asks for bypassPermissions, which Claude Code ignores since v2.1.257. */
  bypassIgnoredFile?: string;
  bashUnrestricted: boolean;
  exfilCommands: string[];
  interpreters: string[];
  webFetchUnrestricted: boolean;
  webSearch: boolean;
  envDenied: boolean;
}

const NET_CMD = /^(curl|wget|nc|ncat|netcat|scp|sftp|ssh|rsync|ftp|telnet|http|xh)(?=$|[\s:])/;
const LOCAL_HOST = /localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0/;
const INTERPRETER = /^(python3?|node|deno|bun|ruby|perl|php|bash|sh|zsh|eval|npx|bunx|pnpx|uvx|tsx|ts-node)(?=$|[\s:])(.*)$/;
const WALLET_KEY = /(^|_)(PRIVATE_?KEY|PRIV_?KEY|PK|MNEMONIC|SEED_?PHRASE|SECRET_?PHRASE|KEYPAIR|WALLET_?(KEY|SECRET))(_|$)/;

export function readPermissions(ctx: Context): Permissions {
  const allow: string[] = [];
  const deny: string[] = [];
  let bypass = false;
  let bypassIgnoredFile: string | undefined;
  for (const { file, data } of ctx.claudeSettings) {
    const p = data.permissions ?? {};
    if (Array.isArray(p.allow)) allow.push(...p.allow.map(String));
    if (Array.isArray(p.deny)) deny.push(...p.deny.map(String));
    if (p.defaultMode === 'bypassPermissions') {
      if (isProjectFile(ctx, file)) bypassIgnoredFile = file;
      else bypass = true;
    }
  }
  return {
    allow,
    deny,
    bypass,
    bypassIgnoredFile,
    bashUnrestricted: bypass || allow.some((r) => /^Bash(\(\*(:\*)?\))?$/.test(r.trim())),
    exfilCommands: allow.filter(isExfilRule),
    interpreters: allow.filter(isInterpreterRule),
    webFetchUnrestricted: bypass || allow.includes('WebFetch'),
    webSearch: bypass || allow.includes('WebSearch'),
    envDenied: deny.some((r) => /^Read\([^)]*\.env/.test(r) || /^Read\(\*\*\)$/.test(r)),
  };
}

function isProjectFile(ctx: Context, file: string): boolean {
  return file.startsWith(ctx.dir + '/');
}

// Claude Code facts these checks rely on (docs, v2.1.300):
// - auto mode (the interactive default) drops Bash(*) and wildcard interpreter rules, but keeps the rest;
// - claude -p, the Agent SDK and CI start in Manual mode, skip the workspace-trust prompt and load .mcp.json servers;
// - bypassPermissions in a project or local settings file is ignored.
const HEADLESS_NOTE = 'Auto mode drops this rule in interactive sessions, but Manual mode and every headless run (claude -p, Agent SDK, CI) apply it with no one watching.';

function bashCommand(rule: string): string | undefined {
  return rule.match(/^Bash\(([\s\S]*)\)$/)?.[1].trim();
}

/** A network command that can reach an attacker-chosen host without asking. */
export function isExfilRule(rule: string): boolean {
  const cmd = bashCommand(rule);
  if (!cmd || !cmd.includes('*')) return false; // exact commands are reviewed once by the user
  if (/^gh api(?=$|[\s:])/.test(cmd)) return true; // can POST anywhere on GitHub (gists, issues)
  if (!NET_CMD.test(cmd) || LOCAL_HOST.test(cmd)) return false;
  return !/https?:\/\/[^\s/*]+/.test(cmd); // a fixed host limits where data can go
}

/** An interpreter that will run arbitrary inline code, e.g. "python:*" or "node -e *". */
export function isInterpreterRule(rule: string): boolean {
  const m = bashCommand(rule)?.match(INTERPRETER);
  if (!m) return false;
  const [, bin, rawRest] = m;
  const rest = rawRest.trim();
  if (rest === '' || rest === ':*' || rest === '*') return true;
  if (/^(-c|-e|--eval|-p|--print)\b/.test(rest) && rest.includes('*')) return true;
  return /^(npx|bunx|pnpx)$/.test(bin) && /^(tsx|ts-node)(?=$|[\s:]).*\*/.test(rest);
}

export function checkPermissions(ctx: Context, perms: Permissions): Finding[] {
  const findings: Finding[] = [];
  const settingsFile = ctx.claudeSettings[0]?.file;

  if (perms.bypass) {
    findings.push({
      id: 'bypass-permissions',
      severity: 'critical',
      title: 'Claude Code runs in bypassPermissions mode',
      detail: 'Your user or managed settings start every session with all checks off, in every project. One poisoned README or web page is enough to take over the agent.',
      fix: 'Remove "defaultMode": "bypassPermissions". Use it only inside a container or VM with no secrets.',
      file: ctx.claudeSettings.find((s) => s.data.permissions?.defaultMode === 'bypassPermissions' && !isProjectFile(ctx, s.file))?.file,
    });
  } else if (perms.bashUnrestricted) {
    findings.push({
      id: 'bash-unrestricted',
      severity: 'high',
      title: 'Any shell command is auto-approved',
      detail: `An allow rule like "Bash" or "Bash(*)" lets injected instructions run curl, rm, or anything else silently. ${HEADLESS_NOTE}`,
      fix: 'Replace it with narrow rules such as "Bash(npm test:*)" or "Bash(git status)".',
      file: settingsFile,
    });
  }

  if (perms.bypassIgnoredFile) {
    findings.push({
      id: 'bypass-ignored',
      severity: 'low',
      title: 'Project settings ask for bypassPermissions',
      detail: 'Claude Code ignores this in project and local settings since v2.1.257, but older versions run with every check off.',
      fix: 'Remove "defaultMode": "bypassPermissions" from the project settings.',
      file: perms.bypassIgnoredFile,
    });
  }

  if (!perms.bashUnrestricted && perms.exfilCommands.length) {
    findings.push({
      id: 'exfil-commands',
      severity: 'high',
      title: 'Network commands are auto-approved',
      detail: `Allowed without asking: ${perms.exfilCommands.join(', ')}. These are a direct channel to send your data out, and unlike "Bash(*)" they stay in effect in auto mode, so they skip the safety classifier.`,
      fix: 'Remove these allow rules, or limit them to exact URLs you trust.',
      file: settingsFile,
    });
  }

  if (!perms.bashUnrestricted && perms.interpreters.length) {
    findings.push({
      id: 'interpreters',
      severity: 'high',
      title: 'Script interpreters are auto-approved',
      detail: `Allowed without asking: ${perms.interpreters.join(', ')}. "python -c" or "node -e" can run any code, so this equals unrestricted shell. ${HEADLESS_NOTE}`,
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
    const inProject = isProjectFile(ctx, file);
    if (data.enableAllProjectMcpServers === true) {
      findings.push({
        id: 'auto-project-mcp',
        severity: inProject ? 'medium' : 'high',
        title: inProject ? 'This repo approves its own MCP servers' : 'Every repo you open can start MCP servers',
        detail: inProject
          ? 'Once a contributor trusts the folder, every server in .mcp.json starts without asking. Headless runs (claude -p, Agent SDK, CI) load them with no prompt at all.'
          : 'Your user settings approve the .mcp.json of any repo you trust, so a cloned repo can start a server on your machine without asking.',
        fix: 'Remove "enableAllProjectMcpServers": true and list trusted servers in "enabledMcpjsonServers" instead.',
        file,
      });
    }
    // Claude Code only reads this key from user, local or managed settings.
    if (data.skipDangerousModePermissionPrompt === true && !(inProject && file.endsWith('/settings.json'))) {
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
