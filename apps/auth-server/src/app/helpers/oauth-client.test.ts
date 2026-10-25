import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { SYSTEM_CLIENT_ID: 'system' } }));

import { getOrCreateSystemClient, SYSTEM_CLIENT_AUDIENCE } from './oauth-client';

function makeFastify(existing: unknown) {
  return {
    repositories: {
      oauthClients: {
        findByClientId: vi.fn(async () => existing),
        create: vi.fn(async (data: Record<string, unknown>) => ({ id: 'row-1', ...data })),
        update: vi.fn(async (id: string, data: Record<string, unknown>) => ({
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

  it('creates the system client with the developer audience (#509)', async () => {
    const fastify = makeFastify(undefined);

    const client = await getOrCreateSystemClient('realm-1', fastify);

    expect(client.audience).toEqual(['urn:qauth:aud:developer:v1-rc.0']);
    expect(SYSTEM_CLIENT_AUDIENCE).toEqual(['urn:qauth:aud:developer:v1-rc.0']);
  });

  it('returns an existing system client that has the developer audience without writing', async () => {
    const existing = {
      id: 'row-0',
      clientId: 'system',
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
    };
    const fastify = makeFastify(existing);

    await expect(getOrCreateSystemClient('realm-1', fastify)).resolves.toBe(existing);
    expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
  });

  it.each([
    ['no audience, as created before #509', null],
    ['an audience an operator set by hand', ['https://portal.example.com']],
    ['the developer audience beside another', ['urn:qauth:aud:developer:v1-rc.0', 'system']],
  ])('gives an existing system client with %s the developer audience', async (_label, audience) => {
    const fastify = makeFastify({ id: 'row-0', clientId: 'system', audience });

    const client = await getOrCreateSystemClient('realm-1', fastify);

    expect(fastify.repositories.oauthClients.update).toHaveBeenCalledExactlyOnceWith('row-0', {
      audience: ['urn:qauth:aud:developer:v1-rc.0'],
    });
    expect(client).toMatchObject({ id: 'row-0', audience: ['urn:qauth:aud:developer:v1-rc.0'] });
    // Only an audience someone set by hand is worth a warning.
    expect(fastify.log.warn).toHaveBeenCalledTimes(audience === null ? 0 : 1);
  });
});
