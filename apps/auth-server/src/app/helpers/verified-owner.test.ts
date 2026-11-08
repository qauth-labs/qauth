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
const OTHER_REALM = '0199fa20-0000-7000-8000-00000000bbbb';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const ACCOUNT = { realmId: REALM, userId: USER };
const REFUSED = 'urn:qauth:event:user.agent_ownership_refused:v1-rc.0';

interface StoredCredential {
  readonly realmId: string;
  readonly providerType: string;
  readonly credentialData: unknown;
  readonly isPrimary: boolean;
}

/** A server whose account `USER` holds `credentials`. */
function serverWith(...credentials: StoredCredential[]) {
  const findAllByUserId = vi.fn(async () => credentials);
  const fastify = {
    repositories: { userCredentials: { findAllByUserId } },
  } as unknown as FastifyInstance;
  return { fastify, findAllByUserId };
}

const UNCONFIRMED_PASSWORD: StoredCredential = {
  realmId: REALM,
  providerType: 'password',
  credentialData: { password_hash: '$argon2id$h', email_verified: false },
  isPrimary: true,
};
const UPSTREAM: StoredCredential = {
  realmId: REALM,
  providerType: 'oidc_corp',
  credentialData: { kind: 'upstream', iss: 'https://idp.example.com', verified: true },
  isPrimary: true,
};
/** A passkey whose registration checked user verification, added after the account. */
const LATER_PASSKEY: StoredCredential = {
  realmId: REALM,
  providerType: 'webauthn',
  credentialData: {
    public_key: 'pQECAyYgASFYIK_voW-Xypst',
    algorithm: -7,
    sign_count: 0,
    transports: ['internal'],
    backup_eligible: false,
    backed_up: false,
    aaguid: '00000000-0000-0000-0000-000000000000',
    user_verified: true,
    rp_id: 'auth.example.com',
    user_handle: 'dXNlci1oYW5kbGU',
    nickname: null,
    created_at: 1,
    last_used_at: null,
    sign_counter_regressed_at: null,
  },
  isPrimary: false,
};

beforeEach(() => {
  find.mockReset().mockResolvedValue(undefined);
  emit.mockClear();
});

describe('checkVerifiedOwner (ADR-015 Decision 8, amended 2026-11-08; #846)', () => {
  it('reads every credential of the account', async () => {
    const { fastify, findAllByUserId } = serverWith();
    expect(await checkVerifiedOwner(fastify, ACCOUNT)).toEqual({
      verified: false,
      reason: 'no_credentials',
      primaryIdentity: 'none',
    });
    expect(findAllByUserId).toHaveBeenCalledWith(USER);
    expect(find).not.toHaveBeenCalled();
  });

  it("counts a passkey added after the account was created, and names the primary's kind", async () => {
    const { fastify } = serverWith(UNCONFIRMED_PASSWORD, LATER_PASSKEY);
    expect(await checkVerifiedOwner(fastify, ACCOUNT)).toEqual({
      verified: true,
      proof: 'passkey',
      primaryIdentity: 'password',
    });
  });

  it('ignores a credential of another realm (#489), even a proved one', async () => {
    const { fastify } = serverWith(UNCONFIRMED_PASSWORD, {
      ...LATER_PASSKEY,
      realmId: OTHER_REALM,
    });
    expect(await checkVerifiedOwner(fastify, ACCOUNT)).toEqual({
      verified: false,
      reason: 'account_not_verified',
      primaryIdentity: 'password',
    });
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

  it('reads no provider for a credential that is not upstream', async () => {
    const { fastify } = serverWith(UNCONFIRMED_PASSWORD, LATER_PASSKEY);
    expect(await isVerifiedOwner(fastify, ACCOUNT)).toBe(true);
    expect(find).not.toHaveBeenCalled();
  });

  it('reads one provider per upstream type', async () => {
    const { fastify } = serverWith(UPSTREAM, { ...UPSTREAM, isPrimary: false });
    expect(await isVerifiedOwner(fastify, ACCOUNT)).toBe(false);
    expect(find).toHaveBeenCalledOnce();
  });
});

describe('assertVerifiedOwner', () => {
  function requestOf(fastify: FastifyInstance): FastifyRequest {
    return { server: fastify } as unknown as FastifyRequest;
  }

  it('lets a verified owner through and records nothing', async () => {
    const { fastify } = serverWith({
      ...UNCONFIRMED_PASSWORD,
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
