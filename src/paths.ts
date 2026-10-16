import { isAbsolute, relative, sep } from 'node:path';

/** True when `file` is inside `dir` (not equal to it). Works with either path separator. */
export function inDir(file: string, dir: string): boolean {
  const rel = relative(dir, file);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

/** `file` relative to `dir` with forward slashes, for display and rule matching. */
export function relPath(dir: string, file: string): string {
  return relative(dir, file).split(sep).join('/');
}

/** Short form for output: relative inside the project, `~/…` inside home, absolute otherwise. */
export function displayPath(file: string, dir: string, home: string): string {
  if (inDir(file, dir)) return relPath(dir, file);
  if (inDir(file, home)) return `~/${relPath(home, file)}`;
  return file;
}
