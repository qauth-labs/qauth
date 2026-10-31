/**
 * Write `test-vectors/interaction/steps.json` from the contract's step
 * examples and the transport mappers, then format it with Oxfmt as the other
 * vector generators do. Run through
 * `pnpm exec nx run server-step-grammar:vectors-export`; a test fails when the
 * committed file differs. Nothing imports this script.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { STEP_VECTORS_PATH, stepVectorFile } from '../lib/vectors';

const root = resolve(__dirname, '..', '..', '..', '..', '..');
const path = join(root, STEP_VECTORS_PATH);
const file = stepVectorFile();
mkdirSync(dirname(path), { recursive: true });
writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`);
execFileSync('pnpm', ['exec', 'oxfmt', path], { cwd: root, stdio: 'inherit' });
console.log(`server-step-grammar: wrote ${STEP_VECTORS_PATH} (${file.cases.length} cases)`);
