/**
 * Small TOML reader for agent config files (e.g. ~/.codex/config.toml). Supports tables, dotted and quoted
 * keys, strings, numbers, booleans, arrays (also multi-line) and inline tables. Not a full TOML parser:
 * dates and multi-line strings are read as plain strings or skipped.
 */
export function parseToml(text: string): Record<string, any> {
  const root: Record<string, any> = {};
  let table = root;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = stripComment(lines[i]).trim();
    if (!line) continue;

    const header = line.match(/^\[\[?(.+?)\]\]?$/);
    if (header) {
      table = root;
      for (const key of splitKey(header[1])) table = table[key] ??= {};
      continue;
    }

    const eq = indexOutsideQuotes(line, '=');
    if (eq < 0) continue;
    // Arrays and inline tables may continue on the next lines.
    while (!balanced(line) && i + 1 < lines.length) line += ' ' + stripComment(lines[++i]).trim();
    const keys = splitKey(line.slice(0, eq));
    let target = table;
    for (const key of keys.slice(0, -1)) target = target[key] ??= {};
    target[keys[keys.length - 1]] = parseValue(line.slice(eq + 1).trim());
  }
  return root;
}

function parseValue(v: string): any {
  if (v.startsWith('"')) return JSON.parse(v.slice(0, closingQuote(v, 0) + 1));
  if (v.startsWith("'")) return v.slice(1, v.indexOf("'", 1));
  if (v === 'true' || v === 'false') return v === 'true';
  if (v.startsWith('[')) return splitTop(v.slice(1, v.lastIndexOf(']'))).map(parseValue);
  if (v.startsWith('{')) {
    const obj: Record<string, any> = {};
    for (const part of splitTop(v.slice(1, v.lastIndexOf('}')))) {
      const eq = indexOutsideQuotes(part, '=');
      if (eq > 0) obj[splitKey(part.slice(0, eq)).join('.')] = parseValue(part.slice(eq + 1).trim());
    }
    return obj;
  }
  const n = Number(v.replace(/_/g, ''));
  return Number.isNaN(n) ? v : n;
}

/** Splits `a."b.c".d` into ["a", "b.c", "d"]. */
function splitKey(k: string): string[] {
  const parts: string[] = [];
  for (const m of k.trim().matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'|([^.\s]+)/g)) parts.push(m[1] ?? m[2] ?? m[3]);
  return parts;
}

/** Splits a comma list at the top level, ignoring commas inside strings, arrays and tables. */
function splitTop(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"') i = closingQuote(s, i);
    else if (ch === "'") i = s.indexOf("'", i + 1);
    else if (ch === '[' || ch === '{') depth++;
    else if (ch === ']' || ch === '}') depth--;
    else if (ch === ',' && depth === 0) {
      out.push(s.slice(start, i).trim());
      start = i + 1;
    }
    if (i < 0) break;
  }
  const last = s.slice(start).trim();
  if (last) out.push(last);
  return out.filter(Boolean);
}

function balanced(s: string): boolean {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"') i = closingQuote(s, i);
    else if (ch === "'") i = s.indexOf("'", i + 1);
    else if (ch === '[' || ch === '{') depth++;
    else if (ch === ']' || ch === '}') depth--;
    if (i < 0) return true;
  }
  return depth <= 0;
}

function closingQuote(s: string, open: number): number {
  for (let i = open + 1; i < s.length; i++) {
    if (s[i] === '\\') i++;
    else if (s[i] === '"') return i;
  }
  return s.length - 1;
}

function indexOutsideQuotes(s: string, ch: string): number {
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '"') i = closingQuote(s, i);
    else if (s[i] === "'") i = s.indexOf("'", i + 1);
    else if (s[i] === ch) return i;
    if (i < 0) return -1;
  }
  return -1;
}

function stripComment(line: string): string {
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') i = closingQuote(line, i);
    else if (line[i] === "'") {
      const end = line.indexOf("'", i + 1);
      if (end < 0) return line;
      i = end;
    } else if (line[i] === '#') return line.slice(0, i);
  }
  return line;
}
