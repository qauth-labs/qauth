import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { SYSTEM_CLIENT_ID: 'system' } }));

import { getOrCreateSystemClient } from './oauth-client';

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

  // #509, expand then contract (ADR-018 §5): this release accepts the
  // developer API's audience on a portal token but does not mint it, so a
  // node of the previous release accepts every portal token this one mints.
  it('creates the system client with no audience, so its token keeps its client id as aud', async () => {
    const fastify = makeFastify(undefined);

    const client = await getOrCreateSystemClient('realm-1', fastify);

    const row = (fastify.repositories.oauthClients.create as unknown as Mock).mock.calls[0][0];
    expect(row).not.toHaveProperty('audience');
    expect(client.audience).toBeUndefined();
  });

  it.each([
    ['no audience', null],
    ['an audience an operator set by hand', ['https://portal.example.com']],
  ])(
    'returns an existing system client with %s as it is, without writing',
    async (_l, audience) => {
      const existing = { id: 'row-0', clientId: 'system', audience };
      const fastify = makeFastify(existing);

      await expect(getOrCreateSystemClient('realm-1', fastify)).resolves.toBe(existing);
      expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
      expect(fastify.repositories.oauthClients.update).not.toHaveBeenCalled();
      expect(fastify.log.warn).not.toHaveBeenCalled();
    }
  );
});
