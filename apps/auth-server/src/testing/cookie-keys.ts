import { createHash } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { type Mock, vi } from 'vitest';

/**
 * A stand-in for the signer's `getCookieSecrets` (#493) for unit tests whose
 * Fastify stub has no signer: put it on `fastify.signer`. Every realm has a
 * cookie key from the first call, so any realm id works, UUID or not.
 *
 * A realm's keys are derived from its id and its rotation count, so two fakes
 * hold the same keys: a cookie one signs verifies with the other. To make the
 * signer fail, reject one call (`getCookieSecrets.mockRejectedValueOnce`).
 */

type GetCookieSecrets = FastifyInstance['signer']['getCookieSecrets'];

/** What {@link createFakeCookieSigner} returns. */
export interface FakeCookieSigner {
  readonly getCookieSecrets: Mock<GetCookieSecrets>;
  /** A new current key for the realm; the one before becomes its previous key. */
  rotate(realmId: string): void;
  /** Forget the realm's previous key, as the end of its retention does. */
  endRetention(realmId: string): void;
}

function fakeKey(realmId: string, generation: number) {
  const digest = createHash('sha256').update(`fake-cookie-key\u0000${realmId}\u0000${generation}`);
  const secret = digest.digest();
  return {
    kid: `test-${generation}-${secret.subarray(0, 6).toString('hex')}`,
    secret,
  };
}

/** Create a {@link FakeCookieSigner}. */
export function createFakeCookieSigner(): FakeCookieSigner {
  const generations = new Map<string, number>();
  const retained = new Map<string, boolean>();

  const getCookieSecrets = vi.fn<GetCookieSecrets>(async (_caller, realmId) => {
    const generation = generations.get(realmId) ?? 0;
    // Fresh buffers each call: the caller zeroes the ones it is handed.
    const current = fakeKey(realmId, generation);
    const previous =
      generation > 0 && retained.get(realmId) !== false ? fakeKey(realmId, generation - 1) : null;
    return Object.freeze({ current, previous });
  });

  return {
    getCookieSecrets,
    rotate(realmId) {
      generations.set(realmId, (generations.get(realmId) ?? 0) + 1);
      retained.set(realmId, true);
    },
    endRetention(realmId) {
      retained.set(realmId, false);
    },
  };
}
