import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import { jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { signAccessToken, signIdToken, verifyAccessToken } from './jwt-service';
import { generateEdDSAKeyPair, importPrivateKey, importPublicKey } from './key-management';

describe('signAccessToken', () => {
  it('should sign a token with valid payload', async () => {
    const { privateKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
      clientId: 'client-123',
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);

    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
    // JWT tokens have three parts separated by dots
    expect(token.split('.').length).toBe(3);
  });

  it('should include all claims in the token', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-456',
      email: 'test@example.com',
      email_verified: false,
      clientId: 'client-456',
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);

    const decoded = await verifyAccessToken(token, publicKey);
    expect(decoded.sub).toBe(payload.sub);
    expect(decoded.email).toBe(payload.email);
    expect(decoded.email_verified).toBe(payload.email_verified);
    expect(decoded.clientId).toBe(payload.clientId);
    expect(decoded.iss).toBe('https://auth.example.com');
    expect(decoded.iat).toBeDefined();
    expect(decoded.exp).toBeDefined();
    // Token-use marker is always stamped (token-confusion defence).
    expect(decoded.token_use).toBe('access');
  });

  it('should set expiration time correctly', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const expiresIn = 3600; // 1 hour
    const payload = {
      sub: 'user-789',
      email: 'expire@example.com',
      email_verified: true,
      clientId: 'client-789',
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', expiresIn);

    const decoded = await verifyAccessToken(token, publicKey);
    expect(decoded.exp).toBeDefined();
    expect(decoded.iat).toBeDefined();

    if (decoded.iat && decoded.exp) {
      const actualExpiration = decoded.exp - decoded.iat;
      // Allow 1 second tolerance
      expect(actualExpiration).toBeGreaterThanOrEqual(expiresIn - 1);
      expect(actualExpiration).toBeLessThanOrEqual(expiresIn + 1);
    }
  });

  it('emits and round-trips a nested RFC 8693 act claim when provided', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-deleg',
      clientId: 'agent-client',
      act: { sub: 'agent-client', act: { sub: 'prior-agent' } },
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);
    const decoded = await verifyAccessToken(token, publicKey);

    expect(decoded.sub).toBe('user-deleg');
    expect(decoded.act).toEqual({ sub: 'agent-client', act: { sub: 'prior-agent' } });
  });

  it('omits the act claim when not provided (non-delegated token)', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = { sub: 'user-plain', clientId: 'app-client' };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);
    const decoded = await verifyAccessToken(token, publicKey);

    expect(decoded.act).toBeUndefined();
  });
});

describe('signIdToken', () => {
  it('signs an EdDSA ID token with the required OIDC claims', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const token = await signIdToken(
      {
        sub: 'user-oidc-1',
        audience: 'client-oidc-1',
        email: 'oidc@example.com',
        email_verified: true,
        name: 'Ada Lovelace',
        nonce: 'n-0S6_WzA2Mj',
      },
      privateKey,
      'https://auth.example.com',
      900
    );

    expect(token.split('.').length).toBe(3);

    const { payload, protectedHeader } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
    });
    expect(protectedHeader.alg).toBe('EdDSA');
    expect(payload.sub).toBe('user-oidc-1');
    expect(payload.aud).toBe('client-oidc-1');
    expect(payload.iss).toBe('https://auth.example.com');
    expect(payload['email']).toBe('oidc@example.com');
    expect(payload['email_verified']).toBe(true);
    expect(payload['name']).toBe('Ada Lovelace');
    expect(payload['nonce']).toBe('n-0S6_WzA2Mj');
    expect(payload.iat).toBeDefined();
    expect(payload.exp).toBeDefined();
    // Token-use marker distinguishes the ID token from an access token.
    expect(payload['token_use']).toBe('id');
  });

  it('omits nonce and name when not supplied', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const token = await signIdToken(
      { sub: 'user-oidc-2', audience: 'client-oidc-2' },
      privateKey,
      'https://auth.example.com',
      900
    );

    const { payload } = await jwtVerify(token, publicKey, { algorithms: ['EdDSA'] });
    expect(payload['nonce']).toBeUndefined();
    expect(payload['name']).toBeUndefined();
    expect(payload['email']).toBeUndefined();
    expect(payload.sub).toBe('user-oidc-2');
    expect(payload.aud).toBe('client-oidc-2');
  });

  it('is rejected as an access token by the token-confusion guard (typ + token_use=id)', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const idToken = await signIdToken(
      { sub: 'user-oidc-3', audience: 'client-oidc-3' },
      privateKey,
      'https://auth.example.com',
      900
    );

    // The ID token verifies cryptographically — same key, same JWKS entry — but
    // since #283 the SIGNED protected header says `typ: JWT`, so the access-token
    // verifier refuses it outright rather than handing back claims a consumer
    // has to remember to inspect. The payload-level `token_use: 'id'` marker is
    // still there underneath as defence in depth.
    await expect(verifyAccessToken(idToken, publicKey)).rejects.toThrow(JWTInvalidError);

    const { payload, protectedHeader } = await jwtVerify(idToken, publicKey, {
      algorithms: ['EdDSA'],
    });
    expect(protectedHeader['typ']).toBe('JWT');
    expect(payload['token_use']).toBe('id');
  });
});

describe('verifyAccessToken', () => {
  it('should verify a valid token', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
      clientId: 'client-123',
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);

    const decoded = await verifyAccessToken(token, publicKey);
    expect(decoded.sub).toBe(payload.sub);
    expect(decoded.email).toBe(payload.email);
    expect(decoded.email_verified).toBe(payload.email_verified);
  });

  it('should throw JWTExpiredError for expired tokens', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
      clientId: 'client-123',
    };

    // Sign with very short expiration (1 second)
    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 1);

    // Wait for token to expire
    await new Promise((resolve) => setTimeout(resolve, 1100));

    await expect(verifyAccessToken(token, publicKey)).rejects.toThrow(JWTExpiredError);
  }, 10000);

  it('should throw JWTInvalidError for invalid token format', async () => {
    const { publicKey } = await generateEdDSAKeyPair();
    const invalidToken = 'invalid.token.format';

    await expect(verifyAccessToken(invalidToken, publicKey)).rejects.toThrow(JWTInvalidError);
  });

  it('should throw JWTInvalidError for token signed with different key', async () => {
    const { privateKey: privateKey1 } = await generateEdDSAKeyPair();
    const { publicKey: publicKey2 } = await generateEdDSAKeyPair();

    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
      clientId: 'client-123',
    };

    const token = await signAccessToken(payload, privateKey1, 'https://auth.example.com', 900);

    // Try to verify with different public key
    await expect(verifyAccessToken(token, publicKey2)).rejects.toThrow(JWTInvalidError);
  });

  it('should work with imported keys', async () => {
    const { privateKey: originalPrivateKey, publicKey: originalPublicKey } =
      await generateEdDSAKeyPair(true);
    const { exportPKCS8, exportSPKI } = await import('jose');

    const privateKeyPEM = await exportPKCS8(originalPrivateKey);
    const publicKeyPEM = await exportSPKI(originalPublicKey);

    const importedPrivateKey = await importPrivateKey(privateKeyPEM);
    const importedPublicKey = await importPublicKey(publicKeyPEM);

    const payload = {
      sub: 'user-imported',
      email: 'imported@example.com',
      email_verified: true,
      clientId: 'client-imported',
    };

    const token = await signAccessToken(
      payload,
      importedPrivateKey,
      'https://auth.example.com',
      900
    );

    const decoded = await verifyAccessToken(token, importedPublicKey);
    expect(decoded.sub).toBe(payload.sub);
    expect(decoded.email).toBe(payload.email);
  });

  it('rejects a token whose issuer does not match the expected issuer', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const token = await signAccessToken(
      { sub: 'user-iss', email: 'iss@example.com', email_verified: true, clientId: 'client-iss' },
      privateKey,
      'https://attacker.example.com',
      900
    );

    // RFC 9700 mix-up defence: a valid signature is NOT sufficient — the issuer
    // must also match. A token from a different AS (even under the same key) is
    // rejected when the expected issuer is supplied.
    await expect(
      verifyAccessToken(token, publicKey, { issuer: 'https://auth.example.com' })
    ).rejects.toThrow(JWTInvalidError);
  });

  it('accepts a token whose issuer matches the expected issuer', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const token = await signAccessToken(
      { sub: 'user-iss-ok', email: 'ok@example.com', email_verified: true, clientId: 'client-ok' },
      privateKey,
      'https://auth.example.com',
      900
    );

    const decoded = await verifyAccessToken(token, publicKey, {
      issuer: 'https://auth.example.com',
    });
    expect(decoded.sub).toBe('user-iss-ok');
    expect(decoded.iss).toBe('https://auth.example.com');
  });
});

describe('verifyAccessToken runtime claim-shape validation (F-10)', () => {
  /**
   * Mint a JWT directly via jose (bypassing signAccessToken) so we can forge an
   * arbitrary — including malformed — claim set that is still correctly SIGNED.
   * This models a token whose signature verifies but whose claim shape is wrong.
   */
  async function signRawClaims(
    claims: Record<string, unknown>,
    privateKey: Parameters<typeof signAccessToken>[1]
  ): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuedAt()
      .setExpirationTime('900s')
      .setIssuer('https://auth.example.com')
      .setAudience('client-mal')
      .sign(privateKey);
  }

  it('rejects a correctly-signed token whose sub is not a string', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    // `sub` is numeric — jose verifies the signature, but the claim shape is
    // invalid, so the previous `as string` cast would have silently mis-typed it.
    const token = await signRawClaims({ sub: 12345, client_id: 'client-mal' }, privateKey);

    await expect(verifyAccessToken(token, publicKey)).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a correctly-signed token whose email is not a valid email', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const token = await signRawClaims(
      { sub: 'user-mal', client_id: 'client-mal', email: 'not-an-email' },
      privateKey
    );

    await expect(verifyAccessToken(token, publicKey)).rejects.toThrow(JWTInvalidError);
  });

  it('rejects a correctly-signed token whose email_verified is not a boolean', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const token = await signRawClaims(
      { sub: 'user-mal', client_id: 'client-mal', email_verified: 'yes' },
      privateKey
    );

    await expect(verifyAccessToken(token, publicKey)).rejects.toThrow(JWTInvalidError);
  });

  it('accepts a well-formed client_credentials token without email claims', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const token = await signAccessToken(
      { sub: 'service-client', clientId: 'service-client' },
      privateKey,
      'https://auth.example.com',
      900
    );

    const decoded = await verifyAccessToken(token, publicKey);
    expect(decoded.sub).toBe('service-client');
    expect(decoded.email).toBeUndefined();
    expect(decoded.email_verified).toBeUndefined();
  });
});

describe('access token jti claim (RFC 7009 revocation support)', () => {
  it('stamps a unique jti on every access token and surfaces it on verify', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-jti',
      email: 'jti@example.com',
      email_verified: true,
      clientId: 'client-jti',
    };

    const tokenA = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);
    const tokenB = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);

    const decodedA = await verifyAccessToken(tokenA, publicKey);
    const decodedB = await verifyAccessToken(tokenB, publicKey);

    expect(decodedA.jti).toBeDefined();
    expect(decodedB.jti).toBeDefined();
    // Each token gets its own id so a single token can be revoked individually.
    expect(decodedA.jti).not.toBe(decodedB.jti);
  });
});

describe('RFC 9068 typ enforcement (#283)', () => {
  const ISSUER = 'https://auth.example.com';
  /**
   * The resource an access token is bound to (RFC 8707). Used as the `aud` of
   * BOTH tokens below so the audience check can never be the thing that rejects.
   */
  const RESOURCE = 'https://mcp.example.com';

  /** Decode a compact JWS protected header without verifying (test-only). */
  function decodeHeader(token: string): Record<string, unknown> {
    const [encodedHeader] = token.split('.');
    return JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf-8')) as Record<
      string,
      unknown
    >;
  }

  it('stamps typ: at+jwt on access tokens (RFC 9068 §2.1)', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const token = await signAccessToken(
      { sub: 'user-1', clientId: 'client-1' },
      privateKey,
      ISSUER,
      900
    );

    // Assert on the SIGNATURE-PROTECTED header, not the raw decode, so this
    // pins what a verifier actually authenticates.
    const { protectedHeader } = await jwtVerify(token, publicKey, { algorithms: ['EdDSA'] });
    expect(protectedHeader['typ']).toBe('at+jwt');
  });

  it('stamps typ: JWT on ID tokens, distinct from at+jwt', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const idToken = await signIdToken(
      { sub: 'user-1', audience: 'client-1' },
      privateKey,
      ISSUER,
      900
    );

    const { protectedHeader } = await jwtVerify(idToken, publicKey, { algorithms: ['EdDSA'] });
    expect(protectedHeader['typ']).toBe('JWT');
    expect(protectedHeader['typ']).not.toBe('at+jwt');
  });

  it('rejects an ID token presented as an access token on typ grounds ALONE', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    // The whole point of issue #283's acceptance criterion. The ID token is
    // minted with `aud` = the RESOURCE, not a client_id, so the RFC 8707
    // audience binding — QAuth's existing, unrelated defence — PASSES. The only
    // control left standing is the protected-header `typ`.
    const idToken = await signIdToken(
      { sub: 'user-1', audience: RESOURCE },
      privateKey,
      ISSUER,
      900
    );

    // Prove the audience check is genuinely satisfied before asserting the
    // rejection, otherwise this test could pass for the wrong reason forever.
    const { payload } = await jwtVerify(idToken, publicKey, {
      algorithms: ['EdDSA'],
      issuer: ISSUER,
      audience: RESOURCE,
    });
    expect(payload.aud).toBe(RESOURCE);

    await expect(
      verifyAccessToken(idToken, publicKey, { issuer: ISSUER, audience: RESOURCE })
    ).rejects.toThrow(/typ is not at\+jwt/);
  });

  it('accepts a legitimate access token for the same issuer/audience (control)', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    // Identical constraints to the case above; only the token type differs. This
    // is what proves the rejection is attributable to `typ` and not to the
    // issuer/audience pins.
    const accessToken = await signAccessToken(
      { sub: 'user-1', clientId: 'client-1', aud: RESOURCE },
      privateKey,
      ISSUER,
      900
    );

    await expect(
      verifyAccessToken(accessToken, publicKey, { issuer: ISSUER, audience: RESOURCE })
    ).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('accepts a legacy typ-less token by default (rollout phase 1)', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    // A token minted by the build BEFORE #283: valid in every way, no `typ`.
    // Rejecting it by default would invalidate every live token at deploy time.
    const legacy = await new SignJWT({
      sub: 'user-1',
      client_id: 'client-1',
      token_use: 'access',
    })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuedAt()
      .setExpirationTime('900s')
      .setIssuer(ISSUER)
      .setAudience(RESOURCE)
      .sign(privateKey);

    await expect(
      verifyAccessToken(legacy, publicKey, { issuer: ISSUER, audience: RESOURCE })
    ).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('rejects a legacy typ-less token under requireTyp (rollout phase 2)', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const legacy = await new SignJWT({
      sub: 'user-1',
      client_id: 'client-1',
      token_use: 'access',
    })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuedAt()
      .setExpirationTime('900s')
      .setIssuer(ISSUER)
      .setAudience(RESOURCE)
      .sign(privateKey);

    await expect(
      verifyAccessToken(legacy, publicKey, { issuer: ISSUER, audience: RESOURCE, requireTyp: true })
    ).rejects.toThrow(/missing typ header/);
  });

  it('rejects a WRONG typ even with requireTyp off — the flag never weakens this', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const idToken = await signIdToken(
      { sub: 'user-1', audience: RESOURCE },
      privateKey,
      ISSUER,
      900
    );

    await expect(
      verifyAccessToken(idToken, publicKey, {
        issuer: ISSUER,
        audience: RESOURCE,
        requireTyp: false,
      })
    ).rejects.toThrow(/typ is not at\+jwt/);
  });

  it('reads typ from the signed header, so rewriting it cannot smuggle a token through', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const idToken = await signIdToken(
      { sub: 'user-1', audience: RESOURCE },
      privateKey,
      ISSUER,
      900
    );
    const [, payload, signature] = idToken.split('.');

    // Splice a forged `typ: at+jwt` header onto the genuine payload+signature.
    // Because the header is part of the JWS signing input, this must fail at the
    // SIGNATURE, never reach the typ check, and certainly never be accepted.
    const forgedHeader = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'at+jwt' })).toString(
      'base64url'
    );
    const forged = `${forgedHeader}.${payload}.${signature}`;
    expect(decodeHeader(forged)['typ']).toBe('at+jwt');

    await expect(
      verifyAccessToken(forged, publicKey, { issuer: ISSUER, audience: RESOURCE })
    ).rejects.toThrow(JWTInvalidError);
  });
});
