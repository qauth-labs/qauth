import { VERIFIED_OWNER_REFUSAL_REASONS } from '@qauth-labs/fastify-plugin-federation';
import { ForbiddenError } from '@qauth-labs/shared-errors';
import { getEventType } from '@qauth-labs/shared-events';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { find, emit } = vi.hoisted(() => ({
  find: vi.fn(async (): Promise<{ marksVerified: boolean } | undefined> => undefined),
  emit: vi.fn(async () => 'event-1'),
}));
vi.mock('./upstream-providers', () => ({ upstreamProviderCatalog: () => ({ find }) }));
vi.mock('./user-events', () => ({ emitUserEvent: emit }));

import { assertVerifiedOwner, checkVerifiedOwner, isVerifiedOwner } from './verified-owner';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const ACCOUNT = { realmId: REALM, userId: USER };
const REFUSED = 'urn:qauth:event:user.agent_ownership_refused:v1-rc.0';

/**
 * A server whose account `USER` has `primary` as its primary credential, and
 * an operator's verification at `operatorVerifiedAt` (#1052).
 */
function serverWith(primary: unknown, operatorVerifiedAt: number | null = null) {
  const findPrimaryByUserId = vi.fn(async () => primary);
  const findById = vi.fn(async () => ({ id: USER, enabled: true, operatorVerifiedAt }));
  const fastify = {
    repositories: { userCredentials: { findPrimaryByUserId }, users: { findById } },
  } as unknown as FastifyInstance;
  return { fastify, findPrimaryByUserId, findById };
}

const UNCONFIRMED_PASSWORD = {
  providerType: 'password',
  credentialData: { password_hash: '$argon2id$h', email_verified: false },
};
const UPSTREAM = {
  providerType: 'oidc_corp',
  credentialData: { kind: 'upstream', iss: 'https://idp.example.com', verified: true },
};

beforeEach(() => {
  find.mockReset().mockResolvedValue(undefined);
  emit.mockClear();
});

describe('checkVerifiedOwner (ADR-015 Decision 8, #846)', () => {
  it("reads the account's primary credential in the account's realm", async () => {
    const { fastify, findPrimaryByUserId } = serverWith(undefined);
    expect(await checkVerifiedOwner(fastify, ACCOUNT)).toEqual({
      verified: false,
      identity: 'none',
      reason: 'no_primary_identity',
    });
    expect(findPrimaryByUserId).toHaveBeenCalledWith(REALM, USER);
    expect(find).not.toHaveBeenCalled();
  });

  it("reads the realm's provider of an upstream identity, and its verified switch", async () => {
    const { fastify } = serverWith(UPSTREAM);
    find.mockResolvedValueOnce({ marksVerified: true });
    expect(await isVerifiedOwner(fastify, ACCOUNT)).toBe(true);
    expect(find).toHaveBeenCalledWith(REALM, 'oidc_corp');

    find.mockResolvedValueOnce({ marksVerified: false });
    expect(await checkVerifiedOwner(fastify, ACCOUNT)).toMatchObject({
      verified: false,
      reason: 'account_not_verified',
    });
    // Off, or gone: the catalog has no provider of that type.
    expect(await checkVerifiedOwner(fastify, ACCOUNT)).toMatchObject({
      verified: false,
      reason: 'account_not_verified',
    });
  });

  it('reads no provider for an identity that is not upstream', async () => {
    const { fastify } = serverWith(UNCONFIRMED_PASSWORD);
    expect(await isVerifiedOwner(fastify, ACCOUNT)).toBe(false);
    expect(find).not.toHaveBeenCalled();
  });

  it("counts an operator's verification of the account, read in the account's realm (#1052)", async () => {
    const { fastify, findById } = serverWith(UNCONFIRMED_PASSWORD, 1_700_000_000_000);
    expect(await checkVerifiedOwner(fastify, ACCOUNT)).toEqual({
      verified: true,
      identity: 'password',
      operatorVerified: true,
    });
    expect(findById).toHaveBeenCalledWith(REALM, USER);

    // An upstream identity whose provider vouches for nothing, verified by an operator.
    expect(await isVerifiedOwner(serverWith(UPSTREAM, 1_700_000_000_000).fastify, ACCOUNT)).toBe(
      true
    );
  });
});

describe('assertVerifiedOwner', () => {
  function requestOf(fastify: FastifyInstance): FastifyRequest {
    return { server: fastify } as unknown as FastifyRequest;
  }

  it('lets a verified owner through and records nothing', async () => {
    const { fastify } = serverWith({
      providerType: 'password',
      credentialData: { password_hash: '$argon2id$h', email_verified: true },
    });
    await expect(
      assertVerifiedOwner(requestOf(fastify), ACCOUNT, 'client_registration')
    ).resolves.toBeUndefined();
    expect(emit).not.toHaveBeenCalled();
  });

  it('records the refusal on the account, then answers 403 with no scope to ask for', async () => {
    const { fastify } = serverWith(UNCONFIRMED_PASSWORD);
    const request = requestOf(fastify);
    const refused = assertVerifiedOwner(request, ACCOUNT, 'client_registration');
    await expect(refused).rejects.toBeInstanceOf(ForbiddenError);
    await expect(refused).rejects.toMatchObject({ statusCode: 403, requiredScope: undefined });
    expect(emit).toHaveBeenCalledExactlyOnceWith(
      request,
      REFUSED,
      {
        action: 'client_registration',
        reason: 'account_not_verified',
        primaryIdentity: 'password',
      },
      { realmId: REALM, userId: USER, actor: 'user' }
    );
  });
});

describe('the user.agent_ownership_refused event', () => {
  it('takes every reason and identity kind the rule gives', () => {
    const type = getEventType(REFUSED);
    expect(type).toBeDefined();
    for (const reason of VERIFIED_OWNER_REFUSAL_REASONS) {
      for (const primaryIdentity of [
        'password',
        'passkey',
        'wallet',
        'upstream',
        'other',
        'none',
      ]) {
        expect(
          type?.data.safeParse({ action: 'client_registration', reason, primaryIdentity }).success
        ).toBe(true);
      }
    }
  });
});
