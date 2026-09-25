import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// management-token → client-auth → client-resolution → cimd pulls in the env
// module; stub it so the real env-schema parse does not run in tests.
vi.mock('../../config/env', () => ({ env: {} }));

const systemClient = {
  id: '00000000-0000-4000-8000-00000000000a',
  clientId: 'system',
  audience: null as unknown,
};

vi.mock('./realm', () => ({
  getOrCreateDefaultRealm: vi.fn(async () => ({ id: 'realm-1' })),
}));
vi.mock('./oauth-client', () => ({
  getOrCreateSystemClient: vi.fn(async () => systemClient),
}));

import { assertManagementToken, createRequireManagementJwt } from './management-token';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const fastify = {} as FastifyInstance;

/** The claims `/auth/login` puts on the developer-portal token. */
function portalClaims(overrides: Record<string, unknown> = {}) {
  return { sub: USER_ID, clientId: 'system', aud: 'system', ...overrides };
}

beforeEach(() => {
  systemClient.audience = null;
});

describe('assertManagementToken', () => {
  it('accepts the developer-portal token minted for the system client', async () => {
    await expect(assertManagementToken(fastify, portalClaims())).resolves.toBeUndefined();
  });

  it('rejects a token issued to any other client', async () => {
    await expect(
      assertManagementToken(fastify, portalClaims({ clientId: 'third-party-app', aud: 'system' }))
    ).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a token bound to an RFC 8707 resource instead of the system audience', async () => {
    await expect(
      assertManagementToken(fastify, portalClaims({ aud: 'https://mcp.example.com' }))
    ).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a token with no audience', async () => {
    await expect(assertManagementToken(fastify, portalClaims({ aud: undefined }))).rejects.toThrow(
      JWTInvalidError
    );
  });

  it('rejects a delegated token carrying an act claim', async () => {
    await expect(
      assertManagementToken(fastify, portalClaims({ act: { sub: 'agent-client' } }))
    ).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a missing payload', async () => {
    await expect(assertManagementToken(fastify, undefined)).rejects.toThrow(JWTInvalidError);
  });

  it('follows a configured system-client audience, requiring every value', async () => {
    systemClient.audience = ['https://portal.example.com', 'https://auth.example.com'];

    await expect(
      assertManagementToken(
        fastify,
        portalClaims({ aud: ['https://portal.example.com', 'https://auth.example.com'] })
      )
    ).resolves.toBeUndefined();
    await expect(
      assertManagementToken(fastify, portalClaims({ aud: 'https://portal.example.com' }))
    ).rejects.toThrow(JWTInvalidError);
    // The bare client id no longer matches once an audience is configured.
    await expect(assertManagementToken(fastify, portalClaims())).rejects.toThrow(JWTInvalidError);
  });
});

describe('createRequireManagementJwt', () => {
  it('runs the shared requireJwt first, then the management-token check', async () => {
    const requireJwt = vi.fn(async (request: FastifyRequest) => {
      request.jwtPayload = portalClaims({ clientId: 'third-party-app' }) as never;
    });
    const guard = createRequireManagementJwt({ requireJwt } as unknown as FastifyInstance);
    const request = { headers: {} } as FastifyRequest;
    const reply = {} as FastifyReply;

    await expect(guard(request, reply)).rejects.toThrow(JWTInvalidError);
    expect(requireJwt).toHaveBeenCalledWith(request, reply);
  });

  it('does not run the management-token check when requireJwt rejects', async () => {
    const requireJwt = vi.fn(async () => {
      throw new JWTInvalidError('bad signature');
    });
    const guard = createRequireManagementJwt({ requireJwt } as unknown as FastifyInstance);

    await expect(guard({ headers: {} } as FastifyRequest, {} as FastifyReply)).rejects.toThrow(
      'bad signature'
    );
  });

  it('passes the developer-portal token through', async () => {
    const requireJwt = vi.fn(async (request: FastifyRequest) => {
      request.jwtPayload = portalClaims() as never;
    });
    const guard = createRequireManagementJwt({ requireJwt } as unknown as FastifyInstance);

    await expect(
      guard({ headers: {} } as FastifyRequest, {} as FastifyReply)
    ).resolves.toBeUndefined();
  });
});
