import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// management-token → client-auth → client-resolution → cimd pulls in the env
// module; stub it so the real env-schema parse does not run in tests.
vi.mock('../../config/env', () => ({ env: {} }));

const DEVELOPER_AUDIENCE = 'urn:qauth:aud:developer:v1-rc.0';

const systemClient = {
  id: '00000000-0000-4000-8000-00000000000a',
  clientId: 'system',
  audience: [DEVELOPER_AUDIENCE] as unknown,
};

vi.mock('./oauth-client', () => ({
  getOrCreateSystemClient: vi.fn(async () => systemClient),
}));

import { assertManagementToken, createRequireManagementJwt } from './management-token';
import { getOrCreateSystemClient } from './oauth-client';
import { inactiveSubjectError } from './token-subject';

const USER_ID = '11111111-1111-4111-8111-111111111111';
/** The realm of the request (`request.realm`), and the user's. */
const REALM = { id: '0190e3c4-0000-7000-8000-00000000000a' };
const OTHER_REALM_ID = '0190e3c4-0000-7000-8000-00000000000b';
const users = { findById: vi.fn() };
const fastify = { repositories: { users } } as unknown as FastifyInstance;

/** The claims `/auth/login` puts on the developer-portal token since #524. */
function portalClaims(overrides: Record<string, unknown> = {}) {
  return { sub: USER_ID, clientId: 'system', aud: DEVELOPER_AUDIENCE, ...overrides };
}

/**
 * Make {@link USER_ID} a user of the other realm: the realm-scoped lookup
 * (#489) finds it there only, and no user at the request realm.
 */
function userOfOtherRealmOnly(enabled = true) {
  users.findById.mockImplementation(async (realmId: string, id: string) =>
    realmId === OTHER_REALM_ID && id === USER_ID
      ? { id: USER_ID, enabled, realmId: OTHER_REALM_ID }
      : undefined
  );
}

/** The refusal as the client sees it, to compare two refusals by. */
async function refusal(promise: Promise<unknown>) {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e
  );
  expect(error).toBeInstanceOf(JWTInvalidError);
  const { name, message, statusCode, code } = error as JWTInvalidError;
  return { name, message, statusCode, code };
}

beforeEach(() => {
  systemClient.audience = [DEVELOPER_AUDIENCE];
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
      assertManagementToken(fastify, REALM, portalClaims({ clientId: 'third-party-app' }))
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
    // Looked up in the request's realm (#489).
    expect(users.findById).toHaveBeenCalledWith(REALM.id, USER_ID);
  });

  it('rejects a token minted before its user was last disabled, as a disabled user’s token (#748)', async () => {
    // Disabled a minute ago and enabled again since; the token is older.
    const disabledAt = Date.now() - 60_000;
    users.findById.mockResolvedValue({
      id: USER_ID,
      enabled: true,
      notValidBefore: disabledAt,
      realmId: REALM.id,
    });
    const issuedBefore = await refusal(
      assertManagementToken(
        fastify,
        REALM,
        portalClaims({ iat: Math.floor((disabledAt - 60_000) / 1000) })
      )
    );
    expect(users.findById).toHaveBeenCalledWith(REALM.id, USER_ID);

    users.findById.mockResolvedValue({ id: USER_ID, enabled: false, realmId: REALM.id });
    const disabled = await refusal(assertManagementToken(fastify, REALM, portalClaims()));

    // One answer: the caller cannot tell the two apart.
    expect(issuedBefore).toEqual(disabled);
    expect(issuedBefore).toEqual(await refusal(Promise.reject(inactiveSubjectError())));
    expect(issuedBefore.statusCode).toBe(401);
  });

  it('accepts a token minted after its user was enabled again (#748)', async () => {
    const disabledAt = Date.now() - 600_000;
    users.findById.mockResolvedValue({
      id: USER_ID,
      enabled: true,
      notValidBefore: disabledAt,
      realmId: REALM.id,
    });

    await expect(
      assertManagementToken(
        fastify,
        REALM,
        portalClaims({ iat: Math.floor((disabledAt + 60_000) / 1000) })
      )
    ).resolves.toBeUndefined();
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
    // No user lookup at all: the caller looks the subject up in its realm (#489).
    expect(users.findById).not.toHaveBeenCalled();
  });

  it('leaves a subject that names no user to a caller that only ends access', async () => {
    users.findById.mockResolvedValue(undefined);

    await expect(
      assertManagementToken(fastify, REALM, portalClaims(), { requireActiveUser: false })
    ).resolves.toBeUndefined();
    expect(users.findById).not.toHaveBeenCalled();
  });

  describe('the realm of the request (#487)', () => {
    it('reads the system client of the request realm', async () => {
      await assertManagementToken(fastify, REALM, portalClaims());

      expect(getOrCreateSystemClient).toHaveBeenCalledWith(REALM.id, fastify);
    });

    // #489: the subject is looked up in the request's realm only. Another
    // realm's user is no user here, refused as an unknown subject is, so the
    // answer does not tell that the subject exists in another realm.
    it('rejects a token whose user belongs to another realm, as a token of an unknown user (#489)', async () => {
      userOfOtherRealmOnly();
      const otherRealmUser = await refusal(assertManagementToken(fastify, REALM, portalClaims()));
      expect(users.findById).toHaveBeenCalledWith(REALM.id, USER_ID);

      users.findById.mockReset();
      users.findById.mockResolvedValue(undefined);
      const unknownUser = await refusal(assertManagementToken(fastify, REALM, portalClaims()));

      expect(otherRealmUser).toEqual(unknownUser);
      expect(otherRealmUser.message).toBe(inactiveSubjectError().message);
    });

    it("leaves another realm's user to a caller that only ends access, which looks it up in its realm (#489)", async () => {
      // Logout refuses a subject that names no user of its realm itself
      // (logout.test.ts); this check reads no user for it.
      userOfOtherRealmOnly(false);

      await expect(
        assertManagementToken(fastify, REALM, portalClaims(), { requireActiveUser: false })
      ).resolves.toBeUndefined();
      expect(users.findById).not.toHaveBeenCalled();
    });
  });

  // #524, the contract step after #509's expand (ADR-018 §5): the portal
  // token carries the developer API's audience, and nothing else is accepted.
  describe('the developer audience, and only it (#524)', () => {
    it("refuses the system client's id as audience, the portal token of before #524", async () => {
      await expect(
        assertManagementToken(fastify, REALM, portalClaims({ aud: 'system' }))
      ).rejects.toThrow(JWTInvalidError);
      // Expired tokens reach the check at sign-out: refused there too.
      await expect(
        assertManagementToken(fastify, REALM, portalClaims({ aud: 'system' }), {
          requireActiveUser: false,
        })
      ).rejects.toThrow(JWTInvalidError);
    });

    it('accepts it for a sign-out too', async () => {
      await expect(
        assertManagementToken(fastify, REALM, portalClaims(), { requireActiveUser: false })
      ).resolves.toBeUndefined();
    });

    it('refuses it beside another audience, as the developer family does', async () => {
      await expect(
        assertManagementToken(
          fastify,
          REALM,
          portalClaims({ aud: [DEVELOPER_AUDIENCE, 'https://mcp.example.com'] })
        )
      ).rejects.toThrow(JWTInvalidError);
    });

    it('keeps the client id and delegation pins', async () => {
      await expect(
        assertManagementToken(fastify, REALM, portalClaims({ clientId: 'third-party-app' }))
      ).rejects.toThrow(JWTInvalidError);
      await expect(
        assertManagementToken(fastify, REALM, portalClaims({ act: { sub: 'agent' } }))
      ).rejects.toThrow(JWTInvalidError);
    });

    it('refuses another family audience', async () => {
      await expect(
        assertManagementToken(
          fastify,
          REALM,
          portalClaims({ aud: 'urn:qauth:aud:account:v1-rc.0' })
        )
      ).rejects.toThrow(JWTInvalidError);
    });
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

  it('refuses a token of another realm’s user at the request realm, as an unknown user (#489)', async () => {
    userOfOtherRealmOnly();
    const requireJwt = vi.fn(async (request: FastifyRequest) => {
      request.jwtPayload = portalClaims() as never;
    });
    const guard = createRequireManagementJwt({
      requireJwt,
      repositories: { users },
    } as unknown as FastifyInstance);

    expect(
      await refusal(
        guard({ headers: {}, realm: REALM } as unknown as FastifyRequest, {} as FastifyReply)
      )
    ).toEqual(await refusal(Promise.reject(inactiveSubjectError())));
    expect(users.findById).toHaveBeenCalledWith(REALM.id, USER_ID);
  });
});
