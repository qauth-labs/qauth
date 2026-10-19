import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

// Whether a wallet row's issuer is still trusted is `wallet-verification.test.ts`'s
// subject; here it is a lever.
vi.mock('./wallet-verification', () => ({ isWalletAttributeIssuerStillTrusted: vi.fn() }));

import { resolveEmailClaims, resolveEmailClaimsForScopes } from './email-claims';
import { isWalletAttributeIssuerStillTrusted } from './wallet-verification';

const PROVENANCE = { issuer: 'https://issuer.example.com', issuer_key_resolution: 'x5c' };

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
    provenance: source === 'wallet' ? PROVENANCE : null,
    createdAt: 1,
    updatedAt: 1,
  };
}

describe('resolveEmailClaims', () => {
  beforeEach(() => {
    (isWalletAttributeIssuerStillTrusted as unknown as Mock).mockReset().mockResolvedValue(true);
  });

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
    // Already out on expiry, so nothing is asked about it.
    expect(isWalletAttributeIssuerStillTrusted).not.toHaveBeenCalled();
  });

  describe('a wallet row is asserted only while its issuer is still trusted (ANT-2026-ULJIA4P4)', () => {
    it('asks about the provenance the winning wallet row recorded', async () => {
      const fastify = fastifyStub([attrRow('wallet', 'wallet@example.com')]);

      await resolveEmailClaims(fastify, 'user-1');

      expect(isWalletAttributeIssuerStillTrusted).toHaveBeenCalledWith(
        fastify,
        'user-1',
        PROVENANCE
      );
    });

    it('falls to the next source when the issuer is no longer trusted', async () => {
      (isWalletAttributeIssuerStillTrusted as unknown as Mock).mockResolvedValue(false);
      const fastify = fastifyStub([
        attrRow('self_reported', 'self@example.com'),
        attrRow('wallet', 'withdrawn@example.com'),
      ]);

      const claims = await resolveEmailClaims(fastify, 'user-1');

      expect(claims).toEqual({ email: 'self@example.com', email_verified: true });
    });

    it('omits both claims when that wallet row was the only verified one', async () => {
      (isWalletAttributeIssuerStillTrusted as unknown as Mock).mockResolvedValue(false);

      const claims = await resolveEmailClaims(
        fastifyStub([attrRow('wallet', 'withdrawn@example.com')]),
        'user-1'
      );

      expect(claims).toEqual({});
    });

    it('asks nothing when no wallet row wins', async () => {
      await resolveEmailClaims(
        fastifyStub([attrRow('self_reported', 'self@example.com')]),
        'user-1'
      );

      expect(isWalletAttributeIssuerStillTrusted).not.toHaveBeenCalled();
    });
  });
});

describe('resolveEmailClaimsForScopes — release only under the email scope (ANT-2026-2O0T72HY)', () => {
  beforeEach(() => {
    (isWalletAttributeIssuerStillTrusted as unknown as Mock).mockReset().mockResolvedValue(true);
  });

  it('releases nothing, and looks nothing up, without the email scope', async () => {
    const fastify = fastifyStub([attrRow('self_reported', 'self@example.com')]);

    for (const scopes of [[], ['openid'], ['openid', 'profile', 'offline_access'], ['emails']]) {
      expect(await resolveEmailClaimsForScopes(fastify, 'user-1', scopes)).toEqual({});
    }
    expect(fastify.repositories.userAttributes.findVerifiedByUserIdAndKey).not.toHaveBeenCalled();
  });

  it('resolves the trust-ordered pair under the email scope, from an array or a set', async () => {
    const fastify = fastifyStub([attrRow('self_reported', 'self@example.com')]);

    expect(await resolveEmailClaimsForScopes(fastify, 'user-1', ['openid', 'email'])).toEqual({
      email: 'self@example.com',
      email_verified: true,
    });
    expect(await resolveEmailClaimsForScopes(fastify, 'user-1', new Set(['email']))).toEqual({
      email: 'self@example.com',
      email_verified: true,
    });
  });
});
