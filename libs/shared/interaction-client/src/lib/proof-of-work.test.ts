import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import { solveProofOfWork } from './proof-of-work';

/**
 * The page's solver of the built-in bot challenge (#643), run on the shared
 * vectors of the proof of work (#1082): the rule the Interaction API contract
 * states for the `captcha` step's `pow` params. `@qauth-labs/server-sign-in-engine`
 * runs the server's check on the same file, so the solver and the check agree
 * through the contract.
 *
 * The file is read as any other language reads it: as JSON, refused unless it
 * names the format this reader knows. A shared library imports no workspace
 * library, `@qauth-labs/shared-test-vectors` included; `test-vectors:validate`
 * checks the file's format.
 */
const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');
const VECTORS_PATH = 'test-vectors/interaction/proof-of-work.json';

interface ProofOfWorkVector {
  readonly id: string;
  readonly input: { challenge: string; difficulty: number; captcha_token: string };
  readonly expected: { accepted: boolean; smallest_solution: boolean };
}

const vectorFile = JSON.parse(readFileSync(join(REPO_ROOT, VECTORS_PATH), 'utf8')) as {
  schema: string;
  id: string;
  cases: ProofOfWorkVector[];
};

/** The cases whose token a solver that tries 0, 1, 2 and so on returns. */
const smallestSolutions = vectorFile.cases.filter((vector) => vector.expected.smallest_solution);

function vectorCase(id: string): ProofOfWorkVector {
  const found = vectorFile.cases.find((vector) => vector.id === id);
  if (found === undefined) throw new Error(`no case ${id} in ${VECTORS_PATH}`);
  return found;
}

/** A case at a difficulty the solver meets in a few thousand hashes. */
const EASY = vectorCase('smallest-at-difficulty-12');

const zeroBits = (input: string) => {
  const digest = createHash('sha256').update(input).digest();
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
};

const paramsOf = ({ input }: ProofOfWorkVector) =>
  ({ provider: 'pow', challenge: input.challenge, difficulty: input.difficulty }) as const;

describe('the proof-of-work solver', () => {
  it('reads the shared vectors of the proof of work', () => {
    expect(vectorFile.schema).toBe('qauth-vectors/1-rc.0');
    expect(vectorFile.id).toBe('interaction/proof-of-work');
    expect(smallestSolutions.length).toBeGreaterThan(0);
  });

  // The contract's example, at 18 bits, takes about 46,000 hashes: two seconds
  // on an idle machine, so the default 5 s would fail it on a loaded runner.
  it.each(smallestSolutions.map((vector) => [vector.id, vector] as const))(
    '%s: finds the smallest nonce whose SHA-256 over challenge:nonce has enough zero bits',
    async (_id, vector) => {
      const solved = await solveProofOfWork(paramsOf(vector));
      expect(solved).toBe(vector.input.captcha_token);
      expect(zeroBits(`${vector.input.challenge}:${solved}`)).toBeGreaterThanOrEqual(
        vector.input.difficulty
      );
    },
    30_000
  );

  it('refuses params that are not a proof of work', async () => {
    const { challenge } = EASY.input;
    for (const params of [
      { provider: 'hosted', challenge, difficulty: 4 },
      { provider: 'pow', challenge: 'short', difficulty: 4 },
      { provider: 'pow', challenge, difficulty: 0 },
      { provider: 'pow', challenge, difficulty: 33 },
      { provider: 'pow', challenge, difficulty: 1.5 },
    ]) {
      await expect(solveProofOfWork(params as never)).rejects.toThrow(RangeError);
    }
  });

  it('gives up past its attempts, and stops when told to', async () => {
    const params = { ...paramsOf(EASY), difficulty: 32 };
    await expect(solveProofOfWork(params, { maxAttempts: 300 })).rejects.toThrow(RangeError);
    const controller = new AbortController();
    controller.abort(new Error('left the page'));
    await expect(solveProofOfWork(params, { signal: controller.signal })).rejects.toThrow(
      'left the page'
    );
  });

  it('hashes with the Web Crypto it is given, and nothing else', async () => {
    const digest = vi.fn((algorithm: AlgorithmIdentifier, data: BufferSource) =>
      globalThis.crypto.subtle.digest(algorithm, data)
    );
    const solved = await solveProofOfWork(paramsOf(EASY), { subtle: { digest } });
    expect(solved).toBe(EASY.input.captcha_token);
    expect(digest.mock.calls.every(([algorithm]) => algorithm === 'SHA-256')).toBe(true);
  });
});
