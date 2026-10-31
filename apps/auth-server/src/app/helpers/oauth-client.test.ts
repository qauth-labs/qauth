import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { SYSTEM_CLIENT_ID: 'system' } }));

import { getOrCreateSystemClient, SYSTEM_CLIENT_AUDIENCE } from './oauth-client';
import { giveSystemClientsTheDeveloperAudience } from './system-client-boot';

const DEVELOPER_AUDIENCE = 'urn:qauth:aud:developer:v1-rc.0';

function makeFastify(existing: unknown, realmIds: string[] = ['realm-1']) {
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
      realms: {
        listPolicyRecords: vi.fn(async () => realmIds.map((realmId) => ({ realmId }))),
      },
    },
    passwordHasher: { hashPassword: vi.fn(async () => 'argon2id$hash') },
    log: { warn: vi.fn() },
  } as unknown as FastifyInstance;
}

describe('getOrCreateSystemClient', () => {
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
});

describe('giveSystemClientsTheDeveloperAudience (the boot step of #524)', () => {
  it("updates every realm's system client that lacks the audience, and creates none", async () => {
    const fastify = makeFastify({ id: 'row-0', clientId: 'system', audience: null }, [
      'realm-1',
      'realm-2',
    ]);

    await expect(giveSystemClientsTheDeveloperAudience(fastify)).resolves.toBe(2);

    const { oauthClients } = fastify.repositories;
    expect(oauthClients.findByClientId).toHaveBeenCalledWith('realm-1', 'system');
    expect(oauthClients.findByClientId).toHaveBeenCalledWith('realm-2', 'system');
    expect(oauthClients.update).toHaveBeenCalledWith('realm-2', 'row-0', {
      audience: [DEVELOPER_AUDIENCE],
    });
    expect(oauthClients.create).not.toHaveBeenCalled();
  });

  it('changes nothing in a realm without a system client, or one that has the audience', async () => {
    for (const existing of [undefined, { id: 'row-0', audience: [DEVELOPER_AUDIENCE] }]) {
      const fastify = makeFastify(existing);
      await expect(giveSystemClientsTheDeveloperAudience(fastify)).resolves.toBe(0);
      expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
      expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
    }
  });
});
