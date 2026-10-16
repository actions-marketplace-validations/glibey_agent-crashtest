import { relPath } from '../paths.js';
import type { Context, Finding } from '../types.js';

/**
 * AI agents in GitHub Actions. Headless runs have no human watching and no workspace-trust prompt,
 * and workflows often hold secrets, so untrusted issues/PRs become a direct injection path.
 * Rules follow anthropics/claude-code-action docs/security.md.
 */

const AGENT_STEP = /anthropics\/claude-code(-base)?-action|\bclaude\s+(-p|--print)\b|@anthropic-ai\/claude-code|openai\/codex-action|\bcodex\s+exec\b|google-github-actions\/run-gemini-cli|\bgemini\s+(-p|--prompt)\b/;
// Actions that verify the triggering actor has write access before running the agent
// (codex-action is counted here to stay conservative).
const CHECKED_ACTION = /anthropics\/claude-code-action@|openai\/codex-action@/;
// A workflow-level check on who triggered it.
// Exclusions such as `github.actor != 'dependabot[bot]'` don't stop strangers, so only allowlist-style checks count.
const ACTOR_GATE = /author_association\s*==|,\s*github\.event\.[\w.]*author_association\s*\)|includes\([^)]*author_association|github\.(actor|triggering_actor)\s*==|(sender|user)\.login\s*==|check-user-permission|getCollaboratorPermissionLevel|\/collaborators\/|permission\s*[!=]=\s*['"]?(admin|write|maintain)|allowed_?users|authorized_?users|\.includes\(\s*(context\.)?(actor|sender|github\.actor)|github\.event\.pull_request\.merged|(?<!!\s*)contains\(\s*github\.event\.(issue|pull_request)\.labels/i;
// author_association compared against the write-access roles, e.g. `case "$ASSOC" in OWNER | MEMBER | COLLABORATOR)`.
const ALLOWLISTED_ROLES = /author_association[\s\S]*\b(OWNER|MEMBER|COLLABORATOR)\b[\s\S]*\b(OWNER|MEMBER|COLLABORATOR)\b/;
// Event types only a maintainer can cause, so a human has looked at the issue first.
const MAINTAINER_TYPES = ['labeled', 'unlabeled', 'assigned', 'milestoned'];
const UNTRUSTED_EVENTS = ['pull_request_target', 'workflow_run', 'issue_comment', 'issues', 'discussion_comment', 'discussion', 'pull_request_review_comment', 'pull_request_review'];
const SKIP_PERMISSIONS = /--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--permission-mode[\s=]+["']?bypassPermissions|permission_mode:\s*["']?bypassPermissions/;
// Case-sensitive on purpose: the tool is "Bash", while "bash scripts/x.sh" inside a rule is a command.
const BROAD_TOOLS = /--allowed-?[Tt]ools[\s=]+["']?[^"'\n]*\bBash(?![(\w])|--allowed-?[Tt]ools[\s=]+["']?[^"'\n]*Bash\(\*\)/;
const HEAD_CHECKOUT = /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}/;
const API_KEY = /sk-ant-[A-Za-z0-9_-]{20,}/;

export function checkWorkflows(ctx: Context): Finding[] {
  const findings: Finding[] = [];
  for (const wf of ctx.workflows) {
    const text = stripComments(wf.content);
    const rel = relPath(ctx.dir, wf.file);
    const key = text.match(API_KEY);
    if (key) {
      findings.push({
        id: 'ci-hardcoded-key',
        severity: 'critical',
        title: `Anthropic API key hardcoded in ${rel}`,
        detail: `Found ${key[0].slice(0, 10)}… in the workflow file. Anyone who can read the repo can use it.`,
        fix: 'Revoke the key now, then use ${{ secrets.ANTHROPIC_API_KEY }}.',
        file: wf.file,
      });
    }
    if (!AGENT_STEP.test(text)) continue;

    const on = parseOn(text);
    const found: Finding[] = [];
    const maintainerOnly = (e: string) => (on.get(e) ?? []).length > 0 && on.get(e)!.every((t) => MAINTAINER_TYPES.includes(t));
    const untrusted = [...on.keys()].filter((e) => UNTRUSTED_EVENTS.includes(e) && !maintainerOnly(e));
    // Gates often live in a separate job whose output the agent job depends on, so check the whole file.
    const gated = ACTOR_GATE.test(text) || ALLOWLISTED_ROLES.test(text);
    const workflowWrites = /contents:\s*write|permissions:\s*write-all/.test(text.split(/^jobs:/m)[0]);
    for (const job of splitJobs(text).filter((j) => AGENT_STEP.test(j))) {
      // An empty value ("" or '') keeps the write-access check on.
      const nonWrite = job.match(/allowed_non_write_users:[ \t]*(.*)$/m)?.[1].replace(/^["']|["']$/g, '').trim() || undefined;
      const anyBot = /allowed_bots:\s*["']?\*/.test(job);
      const unchecked = !CHECKED_ACTION.test(job); // base action, raw CLI, or another vendor's agent
      const skip = SKIP_PERMISSIONS.test(job);
      const broad = BROAD_TOOLS.test(job);
      // The documented safe shape for open triage bots: explicit narrow tools and no write access to code.
      const narrowTools = /--allowed-?tools/i.test(job) && !broad && !skip;
      const writesCode = workflowWrites || /contents:\s*write|permissions:\s*write-all/.test(job);
      const strangers = untrusted.length > 0 && !gated && (unchecked || nonWrite !== undefined || anyBot);

      // With only schedule/dispatch/push triggers there is no outsider input, so the flag does nothing.
      if (nonWrite && untrusted.length) {
        const everyone = nonWrite === '*' || nonWrite.includes("'*'") || nonWrite.includes('"*"');
        found.push({
          id: 'ci-non-write-users',
          severity: !everyone || gated ? 'medium' : skip || broad ? 'critical' : narrowTools && !writesCode ? 'medium' : 'high',
          title: everyone ? `Anyone on GitHub can drive the agent in ${rel}` : `Listed non-collaborators can drive the agent in ${rel}`,
          detail: `allowed_non_write_users: ${nonWrite} turns off the write-access check, which the action's own docs call "a significant security risk". An issue or comment becomes the agent's instructions${
            gated ? '. A job-level actor check still limits who can trigger it, so the input check is the real guard' : skip || broad ? ', and this agent can run any shell command' : narrowTools && !writesCode ? '. The tool list is narrow and the job cannot push code, which is the setup the docs recommend' : ', and its tools are not narrowed with --allowedTools'}.`,
          fix: 'Remove allowed_non_write_users, or keep it with minimal workflow permissions, a narrow --allowedTools list and github_token (never a PAT).',
          file: wf.file,
        });
      }
      if (anyBot) {
        found.push({
          id: 'ci-any-bot',
          severity: narrowTools && !writesCode ? 'medium' : 'high',
          title: `Any GitHub App can trigger the agent in ${rel}`,
          detail: 'allowed_bots: "*" skips the repository-permission check for bots, so an App created by anyone can invoke the agent with a prompt it controls.',
          fix: 'List the specific bots you trust instead of "*".',
          file: wf.file,
        });
      }
      if (untrusted.length && unchecked && !nonWrite && !gated) {
        found.push({
          id: 'ci-unchecked-trigger',
          severity: skip || broad ? 'critical' : 'high',
          title: `Agent runs on ${untrusted.join('/')} with no actor check in ${rel}`,
          detail: `This workflow starts an agent directly (CLI, base action or another vendor), which does not verify who opened the issue or PR. Any GitHub user can feed it instructions${skip || broad ? ', and it runs with broad tool access' : ''}.`,
          fix: 'Use anthropics/claude-code-action (it checks write access), or gate the job with an author_association / permission check.',
          file: wf.file,
        });
      }
      if (skip) {
        found.push({
          id: 'ci-skip-permissions',
          severity: strangers ? 'critical' : 'high',
          title: `Agent runs with all permission checks off in ${rel}`,
          detail: 'bypassPermissions / --dangerously-skip-permissions lets any injected instruction run shell commands with the workflow\'s secrets in reach.',
          fix: 'Pass a narrow --allowedTools list instead.',
          file: wf.file,
        });
      } else if (broad) {
        found.push({
          id: 'ci-broad-tools',
          severity: strangers ? 'critical' : 'medium',
          title: `Agent may run any shell command in ${rel}`,
          detail: 'The --allowedTools list includes Bash without a command pattern.',
          fix: 'Allow exact commands, e.g. --allowedTools "Bash(gh issue view:*)".',
          file: wf.file,
        });
      }
    }
    findings.push(...dedupe(found));

    if (on.has('pull_request_target') && headCheckoutInRoot(text)) {
      findings.push({
        id: 'ci-prt-head-checkout',
        severity: 'high',
        title: `PR code checked out into the workspace root in ${rel}`,
        detail: 'pull_request_target runs with the base repo\'s secrets. With the PR head in the workspace root, the PR controls package.json, scripts and configs the agent and its hooks execute.',
        fix: 'Check out the base ref, put the PR head in a subdirectory (path: pr-head) and pass --add-dir pr-head.',
        file: wf.file,
      });
    }
    if (/show_full_output:\s*["']?true/.test(text)) {
      findings.push({
        id: 'ci-full-output',
        severity: 'medium',
        title: `Full agent output is logged in ${rel}`,
        detail: 'show_full_output prints everything the agent saw and did. On a public repo those Actions logs are public.',
        fix: 'Remove show_full_output, or enable it only while debugging a private repo.',
        file: wf.file,
      });
    }
    if (/CLAUDE_CODE_SUBPROCESS_ENV_SCRUB:\s*["']?0/.test(text)) {
      findings.push({
        id: 'ci-env-scrub-off',
        severity: 'medium',
        title: `Secret scrubbing is turned off in ${rel}`,
        detail: 'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0 leaves API keys and cloud credentials visible to every command the agent runs.',
        fix: 'Remove CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: 0.',
        file: wf.file,
      });
    }
  }
  return findings;
}

/** Splits a workflow into job bodies so tool and permission settings are judged per job. */
export function splitJobs(yaml: string): string[] {
  const lines = yaml.split('\n');
  const start = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  if (start < 0) return [yaml];
  const jobs: string[][] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    if (/^  [A-Za-z0-9_-]+:\s*$/.test(line)) jobs.push([]);
    jobs[jobs.length - 1]?.push(line);
  }
  return jobs.length ? jobs.map((j) => j.join('\n')) : [yaml];
}

const RANK = { critical: 0, high: 1, medium: 2, low: 3 } as const;

/** One finding per id and file, keeping the most severe job. */
function dedupe(found: Finding[]): Finding[] {
  const best = new Map<string, Finding>();
  for (const f of found) {
    const prev = best.get(f.id);
    if (!prev || RANK[f.severity] < RANK[prev.severity]) best.set(f.id, f);
  }
  return [...best.values()];
}

/** A checkout of the PR head whose own step has no `path:`, i.e. it lands in the workspace root. */
function headCheckoutInRoot(yaml: string): boolean {
  const m = HEAD_CHECKOUT.exec(yaml);
  if (!m) return false;
  const stepStart = yaml.lastIndexOf('- ', m.index);
  const next = yaml.slice(m.index).search(/\n\s*- /);
  const step = yaml.slice(stepStart, next < 0 ? undefined : m.index + next);
  return !/\bpath:\s*\S/.test(step);
}

/** Event names under the top-level `on:` key, from any of the YAML shapes GitHub accepts. */
export function triggers(yaml: string): string[] {
  return [...parseOn(yaml).keys()].sort();
}

/** Maps each workflow event to its inline `types: [...]` list (empty when not given). */
export function parseOn(yaml: string): Map<string, string[]> {
  const on = new Map<string, string[]>();
  const lines = yaml.split('\n');
  const start = lines.findIndex((l) => /^["']?(on|true)["']?\s*:/.test(l));
  if (start < 0) return on;
  const inline = lines[start].replace(/^["']?(on|true)["']?\s*:/, '').trim();
  if (inline) {
    for (const e of inline.replace(/[[\]"']/g, '').split(',')) if (e.trim()) on.set(e.trim(), []);
    return on;
  }
  let indent = -1;
  let current: string | undefined;
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    if (!line.trim()) continue;
    const ind = line.search(/\S/);
    if (indent < 0) indent = ind;
    if (ind === indent) {
      current = line.trim().match(/^-?\s*["']?([a-z_]+)["']?/)?.[1];
      if (current) on.set(current, []);
    } else if (current) {
      const types = line.match(/^\s*types:\s*\[([^\]]*)\]/)?.[1];
      if (types) on.set(current, types.split(',').map((t) => t.trim().replace(/["']/g, '')).filter(Boolean));
    }
  }
  return on;
}

function stripComments(yaml: string): string {
  return yaml.split('\n').map((l) => l.replace(/(^|\s)#.*$/, '')).join('\n');
}
