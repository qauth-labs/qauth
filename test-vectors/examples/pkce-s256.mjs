// Runs the PKCE S256 vectors with Node's standard library alone: no
// TypeScript, no loader, no QAuth code. It is what a reader in any language
// does with a vector file: check the format version, compute an actual
// result from each case's input, and compare it with expected.
//
//   node test-vectors/examples/pkce-s256.mjs [path/to/pkce/s256.json]
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const path = process.argv[2] ?? new URL('../pkce/s256.json', import.meta.url);
const file = JSON.parse(readFileSync(path, 'utf8'));
if (file.schema !== 'qauth-vectors/1-rc.0') {
  throw new Error(`unsupported vector format ${JSON.stringify(file.schema)}`);
}

// RFC 7636 §4.1: 43 to 128 unreserved characters.
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

function check({ code_verifier: verifier, code_challenge: challenge }) {
  const computed = VERIFIER.test(verifier)
    ? createHash('sha256').update(verifier, 'ascii').digest('base64url')
    : null;
  return { computed_challenge: computed, accepted: computed !== null && computed === challenge };
}

let failed = 0;
for (const { id, input, expected } of file.cases) {
  const actual = check(input);
  const ok = isDeepStrictEqual(actual, expected);
  if (!ok) failed += 1;
  console.log(`${ok ? 'pass' : 'FAIL'} ${id}${ok ? '' : `: got ${JSON.stringify(actual)}`}`);
}
console.log(`${file.cases.length - failed}/${file.cases.length} cases passed`);
process.exitCode = failed === 0 ? 0 : 1;
