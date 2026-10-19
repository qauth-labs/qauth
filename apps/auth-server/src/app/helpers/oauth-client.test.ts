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
      },
    },
    passwordHasher: { hashPassword: vi.fn(async () => 'argon2id$hash') },
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

  it('returns an existing system client without writing', async () => {
    const existing = { id: 'row-0', clientId: 'system' };
    const fastify = makeFastify(existing);

    await expect(getOrCreateSystemClient('realm-1', fastify)).resolves.toBe(existing);
    expect(fastify.repositories.oauthClients.create).not.toHaveBeenCalled();
  });
});
