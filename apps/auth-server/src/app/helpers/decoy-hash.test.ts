import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { verifyAgainstDecoyHash } from './decoy-hash';

function makeFastify() {
  return {
    passwordHasher: {
      hashPassword: vi.fn().mockResolvedValue('decoy-hash'),
      verifyPassword: vi.fn().mockResolvedValue(false),
    },
    log: { error: vi.fn() },
  } as unknown as FastifyInstance;
}

describe('verifyAgainstDecoyHash', () => {
  it('verifies the presented secret against a hash made by the configured hasher', async () => {
    const fastify = makeFastify();

    await verifyAgainstDecoyHash(fastify, 'presented');

    expect(fastify.passwordHasher.hashPassword).toHaveBeenCalledOnce();
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledExactlyOnceWith(
      'decoy-hash',
      'presented'
    );
  });

  it('hashes the decoy once per hasher, so every later miss costs one verification like a hit', async () => {
    const fastify = makeFastify();

    await Promise.all([verifyAgainstDecoyHash(fastify, 'a'), verifyAgainstDecoyHash(fastify, 'b')]);
    await verifyAgainstDecoyHash(fastify, 'c');

    expect(fastify.passwordHasher.hashPassword).toHaveBeenCalledOnce();
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledTimes(3);

    // Another hasher (other cost parameters) gets a decoy of its own.
    const other = makeFastify();
    await verifyAgainstDecoyHash(other, 'd');
    expect(other.passwordHasher.hashPassword).toHaveBeenCalledOnce();
  });

  it('never throws, and does not cache a failed decoy', async () => {
    const fastify = makeFastify();
    vi.mocked(fastify.passwordHasher.hashPassword).mockRejectedValueOnce(new Error('no memory'));

    await expect(verifyAgainstDecoyHash(fastify, 'a')).resolves.toBeUndefined();
    expect(fastify.log.error).toHaveBeenCalledOnce();
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();

    await verifyAgainstDecoyHash(fastify, 'b');
    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledExactlyOnceWith(
      'decoy-hash',
      'b'
    );
  });
});
