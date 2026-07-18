import { getSignatureBackend, type HybridSigningKey } from '@qauth-labs/core-crypto';
import { describe, expect, it } from 'vitest';

import { signHybridAccessToken, signHybridIdToken } from './hybrid-jwt-service';
import { generateEdDSAKeyPair } from './key-management';

/**
 * Token-size measurement for ADR-005 / #247.
 *
 * Produces ACTUAL byte counts (AC#1: "measured data, not estimates") for the
 * #245 detached-parallel hybrid tokens and asserts the load-bearing invariant:
 * the BEARER token (`.token`, what travels in `Authorization: Bearer` / a
 * cookie) stays an ordinary Ed25519 JWS regardless of PQC, because the ~3.3 KB
 * ML-DSA-65 signature is carried out-of-band in `.pqcSignature`, never inline.
 *
 * The printed table is the source for the size figures in
 * `docs/adr/005-pqc-hybrid-signing.md`. Re-run with:
 *   pnpm nx test server-jwt -- token-size.bench
 */

// Operationally relevant budgets. Conservative real-world values, not spec maxima:
// - 8 KB: common reverse-proxy request-header ceiling (nginx default
//   `large_client_header_buffers` 8k; many CDNs/ALBs cap total headers at 8-16 KB).
// - 4 KB: per-cookie byte ceiling enforced by mainstream browsers (RFC 6265 §6.1).
// - 2048: safe cross-browser/proxy URL length (query-delivered tokens).
const HEADER_BUDGET = 8 * 1024;
const COOKIE_BUDGET = 4 * 1024;
const URL_BUDGET = 2048;

const utf8 = (s: string): number => Buffer.byteLength(s, 'utf8');

describe('token size (ADR-005 / #247)', () => {
  it('measures classical vs hybrid access/ID token sizes and prints the budget table', async () => {
    const { privateKey } = await generateEdDSAKeyPair(true);
    const mlDsaBackend = getSignatureBackend('ML-DSA-65', ['ML-DSA-65']);
    const { privateKey: mlDsa } = mlDsaBackend.generateKeyPair({ extractable: true });

    const keys: HybridSigningKey = {
      ed: privateKey,
      mlDsa,
      edKid: 'ed-2026',
      mlDsaKid: 'mldsa-2026',
    };
    const issuer = 'https://auth.example.com';

    // A representative user-context access token: realistic sub/email/scope.
    const access = await signHybridAccessToken(
      {
        sub: '018f4e6a-7b2c-7d3e-9f10-2a3b4c5d6e7f',
        email: 'alexandra.henderson@enterprise.example.com',
        email_verified: true,
        clientId: 'portal-web-018f4e6a7b2c',
        scope: 'openid profile email offline_access mcp:tools mcp:resources',
        aud: 'https://api.example.com',
      },
      keys,
      issuer,
      900
    );
    const id = await signHybridIdToken(
      {
        sub: '018f4e6a-7b2c-7d3e-9f10-2a3b4c5d6e7f',
        audience: 'portal-web-018f4e6a7b2c',
        email: 'alexandra.henderson@enterprise.example.com',
        email_verified: true,
        name: 'Alexandra Henderson',
        nonce: 'n-0S6_WzA2Mj',
      },
      keys,
      issuer,
      900
    );

    const bearer = utf8(access.token);
    const pqcSig = utf8(access.pqcSignature);
    const compound = bearer + pqcSig; // if pqcSignature were ever concatenated inline
    const idBearer = utf8(id.token);

    // Reference figures from the representative payload above (2026-07):
    //   access bearer JWS   ≈ 716 B    id-token bearer JWS ≈ 576 B
    //   detached ML-DSA sig  = 4412 B   compound (inlined)  ≈ 5128 B
    // ML-DSA-65 signatures are a fixed 3309 raw bytes → 4412 base64url chars.

    console.log(
      [
        '',
        '=== ADR-005 / #247 token-size measurement (bytes) ===',
        `access bearer JWS (.token)          : ${bearer}`,
        `id-token bearer JWS (.token)        : ${idBearer}`,
        `detached ML-DSA sig (.pqcSignature) : ${pqcSig}`,
        `compound if inlined (bearer+pqc)    : ${compound}`,
        '--- budgets ---',
        `header 8 KB : bearer ${bearer <= HEADER_BUDGET ? 'OK' : 'OVER'} | compound ${
          compound <= HEADER_BUDGET ? 'OK' : 'OVER'
        }`,
        `cookie 4 KB : bearer ${bearer <= COOKIE_BUDGET ? 'OK' : 'OVER'} | compound ${
          compound <= COOKIE_BUDGET ? 'OK' : 'OVER'
        }`,
        `url 2048 B  : bearer ${bearer <= URL_BUDGET ? 'OK' : 'OVER'} | compound ${
          compound <= URL_BUDGET ? 'OK' : 'OVER'
        }`,
        '=====================================================',
        '',
      ].join('\n')
    );

    // Invariant 1: the bearer token is a plain Ed25519 JWS — comfortably inside
    // every budget. This is the whole point of the detached design.
    expect(bearer).toBeLessThanOrEqual(URL_BUDGET);
    expect(idBearer).toBeLessThanOrEqual(URL_BUDGET);

    // Invariant 2: the detached PQC signature ALONE exceeds a cookie and eats
    // most of a header budget — proof it must NOT be delivered inline. ML-DSA-65
    // is 3309 raw bytes ≈ 4412 base64url chars.
    expect(pqcSig).toBeGreaterThan(COOKIE_BUDGET);

    // Invariant 3: a naive inline/compound token would blow the cookie budget,
    // which is exactly the failure #247's reference-token default prevents.
    expect(compound).toBeGreaterThan(COOKIE_BUDGET);

    // EXACT figures — these ARE the numbers documented in
    // docs/adr/005-pqc-hybrid-signing.md. They are deterministic for the fixed
    // representative payload above: the ML-DSA-65 signature is a constant 3309
    // bytes (FIPS 204) → 4412 base64url chars, and the Ed25519 JWS length is
    // fixed because every claim is fixed-length (36-char jti, 10-digit iat/exp).
    // Pinning them keeps AC#1 ("measured, not estimated") SELF-ENFORCING: if a
    // change here moves a number, CI fails until the ADR-005 table is updated to
    // match. Update BOTH together.
    expect(pqcSig).toBe(4412);
    expect(bearer).toBe(716);
    expect(idBearer).toBe(576);
    expect(compound).toBe(5128);
  });
});
