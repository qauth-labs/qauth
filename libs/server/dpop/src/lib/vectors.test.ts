import { loadVectors } from '@qauth-labs/shared-test-vectors';
import { describe, expect, it } from 'vitest';

import { fakeReplayStore } from '../testing/proofs';
import { DpopProofError } from './dpop-error';
import type { DpopNonceSource } from './nonce';
import { createDpopVerifier } from './verifier';

/**
 * The shared DPoP vectors (`test-vectors/dpop/proof.json`, issue #479): the
 * example proofs of RFC 9449 and one failing case per check, which every
 * QAuth verifier, in any language, must pass the same way.
 */

interface VectorRequest {
  dpop: string[];
  method: string;
  url: string;
  access_token?: string;
}

interface VectorInput {
  now: number;
  nonce?: { accepted: string[] };
  requests: VectorRequest[];
}

type VectorResult = { valid: true; jkt: string } | { valid: false; error: string };

const vectors = loadVectors<VectorInput, { results: VectorResult[] }>('dpop/proof');

/** A nonce source that hands out the first accepted value and accepts exactly the listed ones. */
function listedNonces(accepted: readonly string[]): DpopNonceSource {
  return {
    current: () => accepted[0],
    accepts: (nonce) => accepted.includes(nonce),
  };
}

describe('dpop/proof', () => {
  it.each(vectors.cases)('$id', async ({ input, expected }) => {
    const now = () => input.now * 1000;
    const verifier = createDpopVerifier({
      replayStore: fakeReplayStore(now),
      algorithms: ['ES256', 'EdDSA'],
      nonces: input.nonce === undefined ? undefined : listedNonces(input.nonce.accepted),
      now,
    });

    const results: VectorResult[] = [];
    for (const request of input.requests) {
      try {
        const verified = await verifier.verify({
          proof: request.dpop,
          method: request.method,
          url: request.url,
          accessToken: request.access_token,
          requireNonce: input.nonce !== undefined,
        });
        results.push({ valid: true, jkt: verified.thumbprint });
      } catch (error) {
        if (!(error instanceof DpopProofError)) throw error;
        results.push({ valid: false, error: error.error });
      }
    }

    expect(results).toEqual(expected.results);
  });

  it('includes the three example proofs of RFC 9449, each accepted', () => {
    const accepted = vectors.cases.filter(
      ({ id, expected }) =>
        /^rfc9449-figure-(2|7|13)-(token|refresh|resource)-request$/.test(id) &&
        expected.results.every((result) => result.valid)
    );
    expect(accepted.map(({ id }) => id).sort()).toEqual([
      'rfc9449-figure-13-resource-request',
      'rfc9449-figure-2-token-request',
      'rfc9449-figure-7-refresh-request',
    ]);
  });
});
