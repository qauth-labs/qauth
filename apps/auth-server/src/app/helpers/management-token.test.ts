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

vi.mock('./oauth-client', () => ({
  getOrCreateSystemClient: vi.fn(async () => systemClient),
}));

import { assertManagementToken, createRequireManagementJwt } from './management-token';
import { getOrCreateSystemClient } from './oauth-client';

const USER_ID = '11111111-1111-4111-8111-111111111111';
/** The realm of the request (`request.realm`), and the user's. */
const REALM = { id: '0190e3c4-0000-7000-8000-00000000000a' };
const OTHER_REALM_ID = '0190e3c4-0000-7000-8000-00000000000b';
const users = { findById: vi.fn() };
const fastify = { repositories: { users } } as unknown as FastifyInstance;

/** The claims `/auth/login` puts on the developer-portal token. */
function portalClaims(overrides: Record<string, unknown> = {}) {
  return { sub: USER_ID, clientId: 'system', aud: 'system', ...overrides };
}

beforeEach(() => {
  systemClient.audience = null;
  users.findById.mockReset();
  users.findById.mockResolvedValue({ id: USER_ID, enabled: true, realmId: REALM.id });
  vi.mocked(getOrCreateSystemClient).mockClear();
});

describe('assertManagementToken', () => {
  it('accepts the developer-portal token minted for the system client', async () => {
    await expect(assertManagementToken(fastify, REALM, portalClaims())).resolves.toBeUndefined();
  });

  it('rejects a token issued to any other client', async () => {
    await expect(
      assertManagementToken(
        fastify,
        REALM,
        portalClaims({ clientId: 'third-party-app', aud: 'system' })
      )
    ).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a token bound to an RFC 8707 resource instead of the system audience', async () => {
    await expect(
      assertManagementToken(fastify, REALM, portalClaims({ aud: 'https://mcp.example.com' }))
    ).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a token with no audience', async () => {
    await expect(
      assertManagementToken(fastify, REALM, portalClaims({ aud: undefined }))
    ).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a delegated token carrying an act claim', async () => {
    await expect(
      assertManagementToken(fastify, REALM, portalClaims({ act: { sub: 'agent-client' } }))
    ).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a missing payload', async () => {
    await expect(assertManagementToken(fastify, REALM, undefined)).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a token whose user has been disabled since it was minted', async () => {
    users.findById.mockResolvedValue({ id: USER_ID, enabled: false, realmId: REALM.id });

    await expect(assertManagementToken(fastify, REALM, portalClaims())).rejects.toThrow(
      JWTInvalidError
    );
    expect(users.findById).toHaveBeenCalledWith(USER_ID);
  });

  it('rejects a token whose user no longer exists', async () => {
    users.findById.mockResolvedValue(undefined);

    await expect(assertManagementToken(fastify, REALM, portalClaims())).rejects.toThrow(
      JWTInvalidError
    );
  });

  it('rejects a subject that is not a user id without touching the database', async () => {
    await expect(
      assertManagementToken(fastify, REALM, portalClaims({ sub: 'system' }))
    ).rejects.toThrow(JWTInvalidError);
    await expect(
      assertManagementToken(fastify, REALM, portalClaims({ sub: undefined }))
    ).rejects.toThrow(JWTInvalidError);
    expect(users.findById).not.toHaveBeenCalled();
  });

  it('skips the enabled check for a caller that only ends access (logout)', async () => {
    users.findById.mockResolvedValue({ id: USER_ID, enabled: false, realmId: REALM.id });

    await expect(
      assertManagementToken(fastify, REALM, portalClaims(), { requireActiveUser: false })
    ).resolves.toBeUndefined();
  });

  it('leaves a subject that names no user to a caller that only ends access', async () => {
    users.findById.mockResolvedValue(undefined);

    await expect(
      assertManagementToken(fastify, REALM, portalClaims(), { requireActiveUser: false })
    ).resolves.toBeUndefined();
  });

  describe('the realm of the request (#487)', () => {
    it('reads the system client of the request realm', async () => {
      await assertManagementToken(fastify, REALM, portalClaims());

      expect(getOrCreateSystemClient).toHaveBeenCalledWith(REALM.id, fastify);
    });

    it('rejects a token whose user belongs to another realm', async () => {
      users.findById.mockResolvedValue({ id: USER_ID, enabled: true, realmId: OTHER_REALM_ID });

      await expect(assertManagementToken(fastify, REALM, portalClaims())).rejects.toBeInstanceOf(
        JWTInvalidError
      );
    });

    it('rejects it for a caller that only ends access, too', async () => {
      users.findById.mockResolvedValue({ id: USER_ID, enabled: false, realmId: OTHER_REALM_ID });

      await expect(
        assertManagementToken(fastify, REALM, portalClaims(), { requireActiveUser: false })
      ).rejects.toBeInstanceOf(JWTInvalidError);
    });
  });

  it('follows a configured system-client audience, requiring every value', async () => {
    systemClient.audience = ['https://portal.example.com', 'https://auth.example.com'];

    await expect(
      assertManagementToken(
        fastify,
        REALM,
        portalClaims({ aud: ['https://portal.example.com', 'https://auth.example.com'] })
      )
    ).resolves.toBeUndefined();
    await expect(
      assertManagementToken(fastify, REALM, portalClaims({ aud: 'https://portal.example.com' }))
    ).rejects.toThrow(JWTInvalidError);
    // The bare client id no longer matches once an audience is configured.
    await expect(assertManagementToken(fastify, REALM, portalClaims())).rejects.toThrow(
      JWTInvalidError
    );
  });
});

describe('createRequireManagementJwt', () => {
  it('runs the shared requireJwt first, then the management-token check', async () => {
    const requireJwt = vi.fn(async (request: FastifyRequest) => {
      request.jwtPayload = portalClaims({ clientId: 'third-party-app' }) as never;
    });
    const guard = createRequireManagementJwt({
      requireJwt,
      repositories: { users },
    } as unknown as FastifyInstance);
    const request = { headers: {}, realm: REALM } as unknown as FastifyRequest;
    const reply = {} as FastifyReply;

    await expect(guard(request, reply)).rejects.toThrow(JWTInvalidError);
    expect(requireJwt).toHaveBeenCalledWith(request, reply);
  });

  it('does not run the management-token check when requireJwt rejects', async () => {
    const requireJwt = vi.fn(async () => {
      throw new JWTInvalidError('bad signature');
    });
    const guard = createRequireManagementJwt({ requireJwt } as unknown as FastifyInstance);

    await expect(
      guard({ headers: {}, realm: REALM } as unknown as FastifyRequest, {} as FastifyReply)
    ).rejects.toThrow('bad signature');
  });

  it('passes the developer-portal token through', async () => {
    const requireJwt = vi.fn(async (request: FastifyRequest) => {
      request.jwtPayload = portalClaims() as never;
    });
    const guard = createRequireManagementJwt({
      requireJwt,
      repositories: { users },
    } as unknown as FastifyInstance);

    await expect(
      guard({ headers: {}, realm: REALM } as unknown as FastifyRequest, {} as FastifyReply)
    ).resolves.toBeUndefined();
  });

  it('refuses a token of another realm’s user at the request realm', async () => {
    users.findById.mockResolvedValue({ id: USER_ID, enabled: true, realmId: OTHER_REALM_ID });
    const requireJwt = vi.fn(async (request: FastifyRequest) => {
      request.jwtPayload = portalClaims() as never;
    });
    const guard = createRequireManagementJwt({
      requireJwt,
      repositories: { users },
    } as unknown as FastifyInstance);

    await expect(
      guard({ headers: {}, realm: REALM } as unknown as FastifyRequest, {} as FastifyReply)
    ).rejects.toThrow(JWTInvalidError);
  });
});
