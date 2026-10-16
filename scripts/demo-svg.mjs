#!/usr/bin/env node
// Renders `agent-crashtest --demo` into an animated terminal SVG for the README.
//   npm run build && node scripts/demo-svg.mjs > docs/demo.svg
import { execFileSync } from 'node:child_process';

const MAX_FINDINGS = 3;
const CHAR_W = 8.4;
const LINE_H = 19;
const PAD = 20;
const TOP = 44;
const LINE_DELAY = 0.09; // seconds between lines
const HOLD = 6; // seconds to keep the full output before looping

const COLORS = { 31: '#ff5f57', 32: '#28c840', 33: '#febc2e', 34: '#5aa9ff', 35: '#d68cff', 36: '#4fd1e8' };
const FG = '#e6e6e6';
const BG = '#16161a';

const raw = execFileSync(process.execPath, ['dist/cli.js', '--demo'], {
  env: { ...process.env, FORCE_COLOR: '1' },
  encoding: 'utf8',
});

// Keep the header, the first few findings and the footer so the frame stays readable.
const lines = raw.replace(/\n+$/, '').split('\n');
const blocks = [];
let current = [];
for (const line of lines) {
  current.push(line);
  if (strip(line).trim() === '') {
    blocks.push(current);
    current = [];
  }
}
if (current.length) blocks.push(current);
const findingIdx = blocks.map((b, i) => (/(CRITICAL|HIGH|MEDIUM|LOW) /.test(strip(b[0] ?? '')) && /^\s{2}/.test(b[0] ?? '') ? i : -1)).filter((i) => i >= 0);
const lastFinding = findingIdx[findingIdx.length - 1];
const kept = [
  ...blocks.slice(0, findingIdx[0]),
  ...blocks.slice(findingIdx[0], findingIdx[0] + MAX_FINDINGS),
  ...(findingIdx.length > MAX_FINDINGS ? [[`  \x1b[2m… ${findingIdx.length - MAX_FINDINGS} more findings\x1b[0m`, '']] : []),
  ...blocks.slice(lastFinding + 1),
].flat();

const shown = ['\x1b[32m❯\x1b[0m npx agent-crashtest --demo', ...kept];
const cols = Math.max(...shown.map((l) => width(strip(l))));
const W = Math.ceil(PAD * 2 + cols * CHAR_W);
const H = TOP + shown.length * LINE_H + PAD;
const total = shown.length * LINE_DELAY + HOLD;

let css = `text{font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}.b{font-weight:700}.d{opacity:.55}`;
let body = '';
shown.forEach((line, i) => {
  const start = (i === 0 ? 0.2 : 0.8 + i * LINE_DELAY) / total;
  const pct = (x) => `${(x * 100).toFixed(2)}%`;
  css += `@keyframes k${i}{0%,${pct(start)}{opacity:0}${pct(Math.min(start + 0.001, 0.999))},99%{opacity:1}100%{opacity:0}}.l${i}{opacity:0;animation:k${i} ${total.toFixed(1)}s infinite}`;
  body += `<g class="l${i}">${renderLine(line, TOP + i * LINE_H)}</g>`;
});

process.stdout.write(`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
<style>${css}</style>
<rect width="${W}" height="${H}" rx="10" fill="${BG}"/>
<circle cx="20" cy="18" r="6" fill="#ff5f57"/><circle cx="40" cy="18" r="6" fill="#febc2e"/><circle cx="60" cy="18" r="6" fill="#28c840"/>
${body}
</svg>
`);

function renderLine(line, y) {
  let out = '';
  let col = 0;
  let state = { bold: false, dim: false, inverse: false, color: null };
  for (const part of line.split(/(\x1b\[[0-9;]*m)/)) {
    const m = part.match(/^\x1b\[([0-9;]*)m$/);
    if (m) {
      for (const code of m[1].split(';').map(Number)) {
        if (code === 0) state = { bold: false, dim: false, inverse: false, color: null };
        else if (code === 1) state.bold = true;
        else if (code === 2) state.dim = true;
        else if (code === 7) state.inverse = true;
        else if (COLORS[code]) state.color = COLORS[code];
      }
      continue;
    }
    if (!part) continue;
    const x = PAD + col * CHAR_W;
    const w = width(part) * CHAR_W;
    const color = state.color ?? FG;
    if (state.inverse) out += `<rect x="${x}" y="${y - 14}" width="${w}" height="${LINE_H - 1}" rx="3" fill="${color}"/>`;
    const cls = [state.bold && 'b', state.dim && 'd'].filter(Boolean).join(' ');
    out += `<text x="${x}" y="${y}" textLength="${w.toFixed(1)}" lengthAdjust="spacingAndGlyphs" fill="${state.inverse ? BG : color}"${cls ? ` class="${cls}"` : ''}>${escape(part)}</text>`;
    col += width(part);
  }
  return out;
}

function strip(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function width(s) {
  let n = 0;
  for (const ch of s) n += /\p{Extended_Pictographic}/u.test(ch) ? 2 : 1;
  return n;
}

function escape(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
