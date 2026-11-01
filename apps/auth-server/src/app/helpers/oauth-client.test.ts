import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { SYSTEM_CLIENT_ID: 'system' } }));

import { getOrCreateSystemClient, SYSTEM_CLIENT_AUDIENCE } from './oauth-client';
import { giveSystemClientsTheDeveloperAudience } from './system-client-boot';

const DEVELOPER_AUDIENCE = 'urn:qauth:aud:developer:v1-rc.0';

function makeFastify(existing: unknown) {
  return {
    repositories: {
      oauthClients: {
        findByClientId: vi.fn(async () => existing),
        create: vi.fn(async (data: Record<string, unknown>) => ({ id: 'row-1', ...data })),
        update: vi.fn(async (_realmId: string, id: string, data: Record<string, unknown>) => ({
          ...(existing as Record<string, unknown>),
          id,
          ...data,
        })),
      },
    },
    passwordHasher: { hashPassword: vi.fn(async () => 'argon2id$hash') },
    log: { warn: vi.fn() },
  } as unknown as FastifyInstance;
}

describe('getOrCreateSystemClient', () => {
  // #631 (ADR-017 phase F0): the operator provisions the system client. The
  // placeholder the server creates holds no secret and no key, so it can
  // authenticate nowhere, and no first-party profile, which only an operator
  // path sets.
  it('creates a placeholder that holds no secret: private_key_jwt with no key and no profile', async () => {
    const fastify = makeFastify(undefined);

    await getOrCreateSystemClient('realm-1', fastify);

    const row = (fastify.repositories.oauthClients.create as unknown as Mock).mock.calls[0][0];
    expect(row.tokenEndpointAuthMethod).toBe('private_key_jwt');
    expect(row.jwks).toBeNull();
    expect(row.jwksUri).toBeNull();
    expect(row.clientSecretHash).toMatch(
      /^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/
    );
    expect(row).not.toHaveProperty('firstPartyProfile');
    expect(row).not.toHaveProperty('firstPartyPolicy');
    expect(row).not.toHaveProperty('firstPartyReason');
    // No KDF ran: there is no secret to hash.
    expect(fastify.passwordHasher.hashPassword).not.toHaveBeenCalled();
  });

  it('creates a different unusable hash for each realm', async () => {
    const first = makeFastify(undefined);
    const second = makeFastify(undefined);

    await getOrCreateSystemClient('realm-1', first);
    await getOrCreateSystemClient('realm-2', second);

    const hashOf = (fastify: FastifyInstance) =>
      (fastify.repositories.oauthClients.create as unknown as Mock).mock.calls[0][0]
        .clientSecretHash;
    expect(hashOf(first)).not.toBe(hashOf(second));
  });

  it('provisions the system client as an operator-provisioned client (ANT-2026-O8U3P920)', async () => {
    const fastify = makeFastify(undefined);

    await getOrCreateSystemClient('realm-1', fastify);

    const create = fastify.repositories.oauthClients.create as unknown as Mock;
    expect(create).toHaveBeenCalledOnce();
    const row = create.mock.calls[0][0];
    expect(row.clientId).toBe('system');
    expect(row.provisionedByOperator).toBe(true);
    expect(row.developerId).toBeNull();
    expect(row.redirectUris).toEqual([]);
  });

  // #524, the contract step after #509 (ADR-018 §5): the portal token
  // `/auth/login` mints from this client carries the developer audience.
  it('creates the system client with the developer audience', async () => {
    const fastify = makeFastify(undefined);

    const client = await getOrCreateSystemClient('realm-1', fastify);

    expect(SYSTEM_CLIENT_AUDIENCE).toEqual([DEVELOPER_AUDIENCE]);
    expect(client.audience).toEqual([DEVELOPER_AUDIENCE]);
  });

  it('returns an existing system client that has the developer audience without writing', async () => {
    const existing = { id: 'row-0', clientId: 'system', audience: [DEVELOPER_AUDIENCE] };
    const fastify = makeFastify(existing);

    await expect(getOrCreateSystemClient('realm-1', fastify)).resolves.toBe(existing);
    expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
  });

  it.each([
    ['no audience, as created before #524', null],
    ['an audience an operator set by hand', ['https://portal.example.com']],
    ['the developer audience beside another', [DEVELOPER_AUDIENCE, 'system']],
  ])('gives an existing system client with %s the developer audience', async (_label, audience) => {
    const fastify = makeFastify({ id: 'row-0', clientId: 'system', audience });

    const client = await getOrCreateSystemClient('realm-1', fastify);

    expect(fastify.repositories.oauthClients.update).toHaveBeenCalledExactlyOnceWith(
      'realm-1',
      'row-0',
      { audience: [DEVELOPER_AUDIENCE] }
    );
    expect(client).toMatchObject({ id: 'row-0', audience: [DEVELOPER_AUDIENCE] });
  });

  // #631 and #524 together: an existing row is the operator's, read as it
  // is; the developer audience is the one column this writes.
  it.each([
    [
      'the secret-based shape an earlier release created',
      { tokenEndpointAuthMethod: 'client_secret_post', firstPartyProfile: null },
    ],
    [
      'the shape the operator provisioned (#631)',
      {
        tokenEndpointAuthMethod: 'private_key_jwt',
        firstPartyProfile: 'web_redirect',
        redirectUris: ['https://portal.example.com/auth/callback'],
      },
    ],
  ])(
    'keeps an existing system client with %s, writing only the developer audience',
    async (_l, columns) => {
      const existing = { id: 'row-0', clientId: 'system', audience: null, ...columns };
      const fastify = makeFastify(existing);

      const client = await getOrCreateSystemClient('realm-1', fastify);

      expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
      expect(fastify.repositories.oauthClients.update).toHaveBeenCalledExactlyOnceWith(
        'realm-1',
        'row-0',
        { audience: [DEVELOPER_AUDIENCE] }
      );
      expect(client).toMatchObject({ ...columns, audience: [DEVELOPER_AUDIENCE] });
      expect(fastify.log.warn).not.toHaveBeenCalled();
    }
  );
});

describe('giveSystemClientsTheDeveloperAudience (the boot step of #524)', () => {
  it('sets the developer audience on the system client of every realm, in one statement', async () => {
    const setAudienceInEveryRealm = vi.fn(async () => 2);
    const fastify = {
      repositories: { oauthClients: { setAudienceInEveryRealm } },
    } as unknown as FastifyInstance;

    await expect(giveSystemClientsTheDeveloperAudience(fastify)).resolves.toBe(2);

    expect(setAudienceInEveryRealm).toHaveBeenCalledExactlyOnceWith('system', [DEVELOPER_AUDIENCE]);
  });
});
