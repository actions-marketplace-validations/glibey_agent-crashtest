import { displayPath } from '../paths.js';
import type { Context, Finding } from '../types.js';

// Unicode "tag" characters are invisible but models read them as ASCII.
const TAG_CHARS = /[\u{E0000}-\u{E007F}]+/gu;
// Subdivision flags (England, Scotland, Wales…) are a black flag followed by tag characters and a cancel tag.
const FLAG_EMOJI = /\u{1F3F4}[\u{E0020}-\u{E007E}]+\u{E007F}/gu;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/g;

export function checkInstructions(ctx: Context): Finding[] {
  const findings: Finding[] = [];
  for (const { file, content } of ctx.instructionFiles) {
    const rel = displayPath(file, ctx.dir, ctx.home);

    const tags = content.replace(FLAG_EMOJI, '').match(TAG_CHARS);
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

    // Zero-width spaces are common in copied docs, so only bidi controls count here.
    const bidi = content.match(BIDI)?.length ?? 0;
    if (bidi > 0) {
      findings.push({
        id: 'hidden-unicode',
        severity: 'high',
        title: `Invisible Unicode in ${rel}`,
        detail: `${bidi} bidi-control characters. They reorder text so what you read differs from what the model reads.`,
        fix: 'Inspect the file with a hex viewer and strip the hidden characters.',
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
