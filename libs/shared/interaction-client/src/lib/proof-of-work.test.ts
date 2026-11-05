import { createHash } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { solveProofOfWork } from './proof-of-work';

/**
 * The page's solver of the built-in bot challenge (#643). The vector below is
 * the one `@qauth-labs/server-sign-in-engine`'s own test checks, so the
 * solver and the server's check agree on what a solution is.
 */
const VECTOR = {
  challenge: 'cWF1dGgtcG93LXRlc3QtdmVjdG9yLW9mLTMyLWJ5dGVz',
  solutions: { 12: '2596', 16: '4124' },
} as const;

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

describe('the proof-of-work solver', () => {
  it('finds the smallest nonce whose SHA-256 over challenge:nonce has enough zero bits', async () => {
    for (const [difficulty, nonce] of Object.entries(VECTOR.solutions)) {
      const solved = await solveProofOfWork({
        provider: 'pow',
        challenge: VECTOR.challenge,
        difficulty: Number(difficulty),
      });
      expect(solved).toBe(nonce);
      expect(zeroBits(`${VECTOR.challenge}:${solved}`)).toBeGreaterThanOrEqual(Number(difficulty));
    }
  });

  it('refuses params that are not a proof of work', async () => {
    for (const params of [
      { provider: 'hosted', challenge: VECTOR.challenge, difficulty: 4 },
      { provider: 'pow', challenge: 'short', difficulty: 4 },
      { provider: 'pow', challenge: VECTOR.challenge, difficulty: 0 },
      { provider: 'pow', challenge: VECTOR.challenge, difficulty: 33 },
      { provider: 'pow', challenge: VECTOR.challenge, difficulty: 1.5 },
    ]) {
      await expect(solveProofOfWork(params as never)).rejects.toThrow(RangeError);
    }
  });

  it('gives up past its attempts, and stops when told to', async () => {
    const params = { provider: 'pow', challenge: VECTOR.challenge, difficulty: 32 } as const;
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
    const solved = await solveProofOfWork(
      { provider: 'pow', challenge: VECTOR.challenge, difficulty: 12 },
      { subtle: { digest } }
    );
    expect(solved).toBe(VECTOR.solutions[12]);
    expect(digest.mock.calls.every(([algorithm]) => algorithm === 'SHA-256')).toBe(true);
  });
});
