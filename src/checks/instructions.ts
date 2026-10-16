import type { Context, Finding } from '../types.js';

// Unicode "tag" characters are invisible but models read them as ASCII.
const TAG_CHARS = /[\u{E0000}-\u{E007F}]+/gu;
const BIDI = /[‪-‮⁦-⁩]/g;
const ZERO_WIDTH = /[​⁠᠎]|(?<!^)﻿/g;

const SUSPICIOUS: [RegExp, string][] = [
  [/ignore (all |any )?(the )?(previous|prior|above) (instructions|rules)/i, 'tries to override earlier instructions'],
  [/(do not|don't|never) (tell|inform|mention (this|it) to) the user/i, 'asks the agent to hide actions from you'],
  [/(curl|wget)[^\n|]*\|\s*(ba|z)?sh\b/i, 'pipes a remote script straight into a shell'],
  [/base64 (-d|--decode)/i, 'decodes hidden base64 payloads'],
  [/(cat|read|upload|send|post)[^\n]{0,40}(~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b)/i, 'touches credentials together with a read/send action'],
];

export function checkInstructions(ctx: Context): Finding[] {
  const findings: Finding[] = [];
  for (const { file, content } of ctx.instructionFiles) {
    const rel = file.startsWith(ctx.dir) ? file.slice(ctx.dir.length + 1) : file.replace(ctx.home, '~');

    const tags = content.match(TAG_CHARS);
    if (tags) {
      const hidden = tags.map(decodeTags).join(' ').trim();
      findings.push({
        id: 'hidden-tag-chars',
        severity: 'critical',
        title: `Invisible instructions hidden in ${rel}`,
        detail: `Unicode tag characters decode to: "${truncate(hidden, 120)}". You cannot see this text in an editor, but the model reads it.`,
        fix: 'Delete the hidden characters (or the file) and find out where it came from.',
        file,
      });
    }

    const bidi = content.match(BIDI)?.length ?? 0;
    const zw = content.match(ZERO_WIDTH)?.length ?? 0;
    if (bidi > 0 || zw >= 3) {
      findings.push({
        id: 'hidden-unicode',
        severity: 'high',
        title: `Invisible Unicode in ${rel}`,
        detail: `${bidi} bidi-control and ${zw} zero-width characters. These are used to hide or disguise instructions.`,
        fix: 'Inspect the file with a hex viewer and strip the hidden characters.',
        file,
      });
    }

    // Third-party skills often quote attack phrases defensively; only pattern-match files the user owns.
    const inProject = file.startsWith(ctx.dir + '/');
    const userOwned = inProject || file === `${ctx.home}/.claude/CLAUDE.md`;
    const reasons = userOwned ? SUSPICIOUS.filter(([re]) => re.test(content)).map(([, why]) => why) : [];
    if (reasons.length) {
      findings.push({
        id: 'suspicious-instructions',
        severity: inProject ? 'high' : 'medium',
        title: `Suspicious agent instructions in ${rel}`,
        detail: `This file ${reasons.join('; ')}. Agent instruction files are loaded into every session.`,
        fix: 'Read the file yourself. If you did not write those lines, remove them.',
        file,
      });
    }
  }
  return findings;
}

function decodeTags(s: string): string {
  return [...s].map((c) => String.fromCharCode(c.codePointAt(0)! - 0xe0000)).join('');
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
