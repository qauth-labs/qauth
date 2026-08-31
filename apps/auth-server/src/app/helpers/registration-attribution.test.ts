import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { resolveRegistrationDeveloperId } from './registration-attribution';

/**
 * Ownership of a dynamically registered client (#374, ADR-012).
 *
 * Both self-registration paths pinned `developerId: null`, and every
 * developer-scoped query is an equality match on that column, so a dynamically
 * registered client was invisible and unmanageable from the portal. The decision
 * is NOT to invent an owner — it is to attribute when, and only when, the caller
 * proved who they are.
 */

const DEVELOPER_ID = '11111111-1111-4111-8111-111111111111';

function makeFastify(onVerify?: (request: FastifyRequest) => void) {
  const requireJwt = vi.fn(async (request: FastifyRequest) => {
    onVerify?.(request);
  });
  return { requireJwt } as unknown as FastifyInstance;
}

function makeRequest(authorization?: string): FastifyRequest {
  return { headers: authorization ? { authorization } : {} } as unknown as FastifyRequest;
}

describe('resolveRegistrationDeveloperId', () => {
  it('returns null with no Authorization header — open-mode DCR is unchanged', async () => {
    const fastify = makeFastify();
    const request = makeRequest();

    await expect(resolveRegistrationDeveloperId(fastify, request)).resolves.toBeNull();
    // The verifier is never invoked, so an anonymous registration costs nothing
    // and cannot fail on a JWT path it never enters.
    expect(fastify.requireJwt).not.toHaveBeenCalled();
  });

  it('attributes to the token subject when a developer token is presented', async () => {
    const fastify = makeFastify((request) => {
      (request as { jwtPayload?: unknown }).jwtPayload = { sub: DEVELOPER_ID };
    });

    await expect(
      resolveRegistrationDeveloperId(fastify, makeRequest('Bearer dev.token'))
    ).resolves.toBe(DEVELOPER_ID);
  });

  it('verifies through the SHARED preHandler, not a second implementation', async () => {
    // Issuer pinning (RFC 9700 mix-up defence) and revocation live in
    // `requireJwt`. Re-implementing verification here would let the two drift,
    // and this path would be the one nobody remembers to update.
    const fastify = makeFastify((request) => {
      (request as { jwtPayload?: unknown }).jwtPayload = { sub: DEVELOPER_ID };
    });
    const request = makeRequest('Bearer dev.token');

    await resolveRegistrationDeveloperId(fastify, request);

    expect(fastify.requireJwt).toHaveBeenCalledTimes(1);
    expect(vi.mocked(fastify.requireJwt).mock.calls[0][0]).toBe(request);
  });

  it('REJECTS a token that does not verify — never falls back to anonymous', async () => {
    // The important case. Silently registering an unowned client for a caller
    // who presented a token would reproduce the exact failure #374 is about: a
    // client the developer believes they own and cannot find.
    const fastify = makeFastify(() => {
      throw new JWTInvalidError('bad signature');
    });

    await expect(
      resolveRegistrationDeveloperId(fastify, makeRequest('Bearer forged.token'))
    ).rejects.toThrow(JWTInvalidError);
  });

  it('REJECTS a verified token whose sub is not a user UUID', async () => {
    // A `client_credentials` token's `sub` is a client_id. `developer_id` is a
    // UUID column with a foreign key, so attributing to it would produce a row
    // with a dangling owner.
    const fastify = makeFastify((request) => {
      (request as { jwtPayload?: unknown }).jwtPayload = { sub: 'some-client-id' };
    });

    await expect(
      resolveRegistrationDeveloperId(fastify, makeRequest('Bearer machine.token'))
    ).rejects.toThrow(JWTInvalidError);
  });

  it('REJECTS a verified token carrying no sub at all', async () => {
    const fastify = makeFastify((request) => {
      (request as { jwtPayload?: unknown }).jwtPayload = {};
    });

    await expect(
      resolveRegistrationDeveloperId(fastify, makeRequest('Bearer subless.token'))
    ).rejects.toThrow(JWTInvalidError);
  });
});
