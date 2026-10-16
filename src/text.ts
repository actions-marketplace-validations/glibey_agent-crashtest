/**
 * Makes text from scanned files safe to print: control characters (terminal escapes, newlines that
 * could start a GitHub workflow command) and bidi overrides become visible \u escapes.
 */
const UNSAFE = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]', 'g');

export function sanitize(s: string): string {
  return s.replace(UNSAFE, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
