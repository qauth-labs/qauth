import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { resolveWalletPresentation } from './wallet-presentation';

/**
 * The seam refuses. That is the whole test, and it is not a placeholder.
 *
 * A wallet presentation becomes a session only once #234 validates it, #236
 * accepts its issuer and #300 resolves it to the asserted account (ADR-009 §1).
 * None of those exists, so anything reaching this function is still
 * attacker-supplied bytes that redeemed an unauthenticated `state`. If this test
 * ever fails, either the three dependencies landed — in which case it should be
 * rewritten alongside them — or something taught the login UI to authenticate on
 * transport alone, which is the exact failure `WalletProvider.verify()` throws to
 * prevent.
 */
describe('resolveWalletPresentation', () => {
  function fakeFastify() {
    return { log: { warn: vi.fn(), error: vi.fn() } } as unknown as FastifyInstance;
  }

  it('refuses every presentation until #234/#236/#300 land', async () => {
    const result = await resolveWalletPresentation(fakeFastify(), {
      realmId: 'realm-1',
      stateHash: 'a'.repeat(64),
      assertedIdentifier: 'user@example.com',
    });

    expect(result).toEqual({ status: 'rejected' });
  });

  it('refuses identically whatever identifier is asserted (no enumeration)', async () => {
    const fastify = fakeFastify();
    const known = await resolveWalletPresentation(fastify, {
      realmId: 'realm-1',
      stateHash: 'b'.repeat(64),
      assertedIdentifier: 'user@example.com',
    });
    const unknown = await resolveWalletPresentation(fastify, {
      realmId: 'realm-1',
      stateHash: 'c'.repeat(64),
      assertedIdentifier: 'nobody-at-all@example.com',
    });

    expect(known).toEqual(unknown);
  });

  it('records the refusal for the operator', async () => {
    const fastify = fakeFastify();
    await resolveWalletPresentation(fastify, {
      realmId: 'realm-1',
      stateHash: 'd'.repeat(64),
      assertedIdentifier: 'user@example.com',
    });

    expect(fastify.log.warn).toHaveBeenCalledTimes(1);
  });
});
