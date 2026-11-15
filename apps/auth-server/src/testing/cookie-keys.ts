import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { cookieMacInput, deriveCookieKey } from '@qauth-labs/fastify-plugin-signer';
import type { FastifyInstance } from 'fastify';
import { type Mock, vi } from 'vitest';

/**
 * A stand-in for the signer's cookie key operations (#493, #497) for unit
 * tests whose Fastify stub has no signer: put it on `fastify.signer`. Every
 * realm has a cookie key from the first call, so any realm id works, UUID or
 * not. `getCookieDerivedKey` derives from the current key and
 * `verifyCookieMac` checks with the current or previous one, as the signer
 * does.
 *
 * A realm's keys are derived from its id and its rotation count, so two fakes
 * hold the same keys: a cookie one signs verifies with the other. To make the
 * signer fail, reject one call (`getCookieSecrets.mockRejectedValueOnce`).
 */

type GetCookieSecrets = FastifyInstance['signer']['getCookieSecrets'];
type GetCookieDerivedKey = FastifyInstance['signer']['getCookieDerivedKey'];
type VerifyCookieMac = FastifyInstance['signer']['verifyCookieMac'];

/** What {@link createFakeCookieSigner} returns. */
export interface FakeCookieSigner {
  readonly getCookieSecrets: Mock<GetCookieSecrets>;
  readonly getCookieDerivedKey: Mock<GetCookieDerivedKey>;
  readonly verifyCookieMac: Mock<VerifyCookieMac>;
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

  function keysOf(realmId: string) {
    const generation = generations.get(realmId) ?? 0;
    // Fresh buffers each call: the caller zeroes the ones it is handed.
    const current = fakeKey(realmId, generation);
    const previous =
      generation > 0 && retained.get(realmId) !== false ? fakeKey(realmId, generation - 1) : null;
    return Object.freeze({ current, previous });
  }

  const getCookieSecrets = vi.fn<GetCookieSecrets>(async (_caller, realmId) => keysOf(realmId));

  const getCookieDerivedKey = vi.fn<GetCookieDerivedKey>(async (_caller, { realmId, label }) => {
    const { current } = keysOf(realmId);
    return { kid: current.kid, key: deriveCookieKey(current.secret, label) };
  });

  const verifyCookieMac = vi.fn<VerifyCookieMac>(async (_caller, request) => {
    const { current, previous } = keysOf(request.realmId);
    const key = [current, previous].find((candidate) => candidate?.kid === request.kid);
    if (key === undefined || key === null) return false;
    const expected = createHmac('sha256', key.secret).update(cookieMacInput(request)).digest();
    const presented = Buffer.from(request.mac, 'base64url');
    return (
      presented.toString('base64url') === request.mac &&
      presented.length === expected.length &&
      timingSafeEqual(presented, expected)
    );
  });

  return {
    getCookieSecrets,
    getCookieDerivedKey,
    verifyCookieMac,
    rotate(realmId) {
      generations.set(realmId, (generations.get(realmId) ?? 0) + 1);
      retained.set(realmId, true);
    },
    endRetention(realmId) {
      retained.set(realmId, false);
    },
  };
}
