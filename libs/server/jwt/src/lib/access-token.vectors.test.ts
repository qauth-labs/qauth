import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import { loadVectors } from '@qauth-labs/shared-test-vectors';
import { decodeProtectedHeader, importJWK } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { type PublishedJwk, selectJwksKey } from './jwks-resolution';
import { verifyAccessToken } from './jwt-service';

/**
 * The shared RFC 9068 §4 access token vectors (`test-vectors/jwt/access-token.json`),
 * run through {@link verifyAccessToken} the way a resource server would: the
 * key is selected from the case's JWKS by `kid`, the clock is the case's
 * `now`, and `typ` is required. Each case's whole `expected` object is
 * rebuilt from the outcome, so a wrong value anywhere in a case fails it.
 */
interface AccessTokenInput {
  token: string;
  jwks: { keys: PublishedJwk[] };
  now: number;
  issuer: string;
  audience: string;
}

type AccessTokenExpected =
  | { valid: true; claims: Record<string, unknown> }
  | { valid: false; reason: 'typ' | 'iss' | 'aud' | 'exp' | 'signature' };

const vectors = loadVectors<AccessTokenInput, AccessTokenExpected>('jwt/access-token');

/** Which RFC 9068 §4 check a verification error stands for. */
function reasonOf(error: unknown): string {
  if (error instanceof JWTExpiredError) return 'exp';
  if (!(error instanceof JWTInvalidError)) throw error;
  if (/\btyp\b/.test(error.message)) return 'typ';
  if (/"iss"/.test(error.message)) return 'iss';
  if (/"aud"/.test(error.message)) return 'aud';
  if (/signature verification failed/.test(error.message)) return 'signature';
  return `unclassified: ${error.message}`;
}

async function outcome(
  input: AccessTokenInput
): Promise<AccessTokenExpected | { valid: false; reason: string }> {
  const { kid } = decodeProtectedHeader(input.token);
  const jwk = selectJwksKey(input.jwks.keys, { kid, alg: 'EdDSA' });
  if (jwk === undefined) return { valid: false, reason: 'no key for the token kid' };
  const key = await importJWK(jwk, 'EdDSA');
  if (key instanceof Uint8Array) return { valid: false, reason: 'not an asymmetric key' };

  vi.setSystemTime(input.now * 1000);
  try {
    const payload = await verifyAccessToken(input.token, key, {
      issuer: input.issuer,
      audience: input.audience,
      requireTyp: true,
    });
    // Back to the claim names on the wire, dropping what the token lacks.
    const claims = Object.fromEntries(
      Object.entries({
        iss: payload.iss,
        sub: payload.sub,
        aud: payload.aud,
        client_id: payload.clientId,
        scope: payload.scope,
        iat: payload.iat,
        exp: payload.exp,
        jti: payload.jti,
        token_use: payload.token_use,
        email: payload.email,
        email_verified: payload.email_verified,
        act: payload.act,
      }).filter(([, value]) => value !== undefined)
    );
    return { valid: true, claims };
  } catch (error) {
    return { valid: false, reason: reasonOf(error) };
  }
}

describe('jwt/access-token shared vectors (RFC 9068 §4)', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it.each(vectors.cases)('$id', async ({ input, expected }) => {
    expect(await outcome(input)).toEqual(expected);
  });
});
