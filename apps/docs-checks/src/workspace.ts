import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

/** The repository root, which every path the checks read is relative to. */
export const REPO_ROOT = resolve(__dirname, '..', '..', '..');

/** Oxfmt's command line, which formats with the repository's `.oxfmtrc.json`. */
const OXFMT = join(
  dirname(createRequire(__filename).resolve('oxfmt/package.json')),
  'bin',
  'oxfmt'
);

/**
 * `text` as Oxfmt formats the file at `path`. A generated page goes through it
 * before it is compared with the committed file, so the committed file is
 * already formatted and the formatter never rewrites it.
 */
export function formatAs(path: string, text: string): string {
  return execFileSync(process.execPath, [OXFMT, `--stdin-filepath=${path}`], {
    cwd: REPO_ROOT,
    input: text,
    encoding: 'utf8',
  });
}
