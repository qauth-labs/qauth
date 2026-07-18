import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { resolveEmailClaims } from './email-claims';

function fastifyStub(rows: unknown[]) {
  return {
    repositories: {
      userAttributes: {
        findVerifiedByUserIdAndKey: vi.fn().mockResolvedValue(rows),
      },
    },
  } as unknown as FastifyInstance;
}

function attrRow(source: string, attrValue: string, expiresAt: number | null = null) {
  return {
    id: `attr-${source}`,
    userId: 'user-1',
    source,
    attrKey: 'email',
    attrValue,
    verified: true,
    expiresAt,
    createdAt: 1,
    updatedAt: 1,
  };
}

describe('resolveEmailClaims', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns the literal-true pair for the trust-order winner', async () => {
    const fastify = fastifyStub([
      attrRow('self_reported', 'self@example.com'),
      attrRow('wallet', 'wallet@example.com'),
    ]);

    const claims = await resolveEmailClaims(fastify, 'user-1');

    expect(claims).toEqual({ email: 'wallet@example.com', email_verified: true });
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).toHaveBeenCalledWith(
      'user-1',
      'email'
    );
  });

  it('returns an empty object — no keys at all — when no verified row exists', async () => {
    const claims = await resolveEmailClaims(fastifyStub([]), 'user-1');

    // Omitted means the keys are ABSENT, not undefined-valued.
    expect(claims).toEqual({});
    expect('email' in claims).toBe(false);
    expect('email_verified' in claims).toBe(false);
  });

  it('passes the current wall clock to the selector (expired rows drop out)', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_700_000_000_000);
    const fastify = fastifyStub([
      attrRow('wallet', 'expired@example.com', 1_700_000_000_000 - 1),
      attrRow('self_reported', 'live@example.com'),
    ]);

    const claims = await resolveEmailClaims(fastify, 'user-1');

    expect(claims).toEqual({ email: 'live@example.com', email_verified: true });
  });
});
