import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { InvalidTokenError } from './errors';
import { JwtValidator } from './jwt-validator';

const ISSUER = 'https://auth.example.com';
const RESOURCE = 'https://mcp.example.com';
const JWKS_URI = `${ISSUER}/.well-known/jwks.json`;

let privateKey: CryptoKey;
let publicJwk: JWK;
// A second, unrelated key — tokens signed with this must fail (bad signature).
let otherPrivateKey: CryptoKey;

/**
 * A jose-compatible fetch that serves our test JWKS, regardless of URL. jose
 * calls it with (url, options) and expects a Response-like with `.json()`.
 */
function jwksFetch(jwks: { keys: JWK[] }) {
  return async () =>
    ({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/jwk-set+json' }),
      json: async () => jwks,
      text: async () => JSON.stringify(jwks),
    }) as unknown as Response;
}

async function signToken(
  key: CryptoKey,
  claims: Record<string, unknown>,
  opts: { issuer?: string; audience?: string | string[]; expSeconds?: number } = {}
): Promise<string> {
  let jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(opts.issuer ?? ISSUER)
    .setExpirationTime(`${opts.expSeconds ?? 300}s`);
  if (opts.audience !== undefined) {
    jwt = jwt.setAudience(opts.audience);
  }
  return jwt.sign(key);
}

function validator(fetchImpl: ReturnType<typeof jwksFetch>) {
  return new JwtValidator({
    jwksUri: JWKS_URI,
    issuer: ISSUER,
    audience: RESOURCE,
    fetch: fetchImpl as never,
  });
}

beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { extractable: true });
  privateKey = kp.privateKey;
  publicJwk = await exportJWK(kp.publicKey);
  publicJwk.alg = 'EdDSA';
  publicJwk.kid = 'test-key-1';
  const other = await generateKeyPair('EdDSA', { extractable: true });
  otherPrivateKey = other.privateKey;
});

describe('JwtValidator', () => {
  it('accepts a well-formed, audience-bound token and normalises claims', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 'user-123', client_id: 'client-abc', scope: 'mcp:read mcp:write' },
      { audience: RESOURCE }
    );
    const result = await validator(fetchImpl).validate(token);
    expect(result.sub).toBe('user-123');
    expect(result.clientId).toBe('client-abc');
    expect(result.scopes).toEqual(['mcp:read', 'mcp:write']);
    expect(result.audience).toContain(RESOURCE);
    expect(result.issuer).toBe(ISSUER);
  });

  it('accepts a token whose aud is an array containing the resource', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { audience: ['https://other.example.com', RESOURCE] }
    );
    const result = await validator(fetchImpl).validate(token);
    expect(result.audience).toEqual(['https://other.example.com', RESOURCE]);
  });

  it('rejects a token whose aud is a DIFFERENT resource (no passthrough, RFC 8707)', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { audience: 'https://other-resource.example.com' }
    );
    await expect(validator(fetchImpl).validate(token)).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(validator(fetchImpl).validate(token)).rejects.toThrow(/audience/i);
  });

  it('rejects a token with no aud claim at all', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(privateKey, { sub: 's', client_id: 'c' });
    await expect(validator(fetchImpl).validate(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects a token from an untrusted issuer', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { issuer: 'https://evil.example.com', audience: RESOURCE }
    );
    await expect(validator(fetchImpl).validate(token)).rejects.toThrow(/issuer/i);
  });

  it('rejects an expired token', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { audience: RESOURCE, expSeconds: -10 }
    );
    await expect(validator(fetchImpl).validate(token)).rejects.toThrow(/expired/i);
  });

  it('rejects a token signed by an unknown key (no matching JWK)', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      otherPrivateKey,
      { sub: 's', client_id: 'c' },
      { audience: RESOURCE }
    );
    await expect(validator(fetchImpl).validate(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects a structurally invalid token', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    await expect(validator(fetchImpl).validate('not-a-jwt')).rejects.toBeInstanceOf(
      InvalidTokenError
    );
  });

  it('never includes the token in the thrown reason', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { audience: 'https://other.example.com' }
    );
    try {
      await validator(fetchImpl).validate(token);
      expect.unreachable('should have thrown');
    } catch (error) {
      expect((error as Error).message).not.toContain(token);
    }
  });
});

describe('JwtValidator — RFC 9068 typ enforcement (#283)', () => {
  /**
   * Like {@link signToken}, but lets a test control the protected header so it
   * can mint an at+jwt access token, a `typ: JWT` ID token, or a hybrid header.
   */
  async function signWithHeader(
    header: Record<string, unknown>,
    claims: Record<string, unknown>,
    opts: { audience?: string | string[] } = {}
  ): Promise<string> {
    let jwt = new SignJWT(claims)
      .setProtectedHeader({ alg: 'EdDSA', ...header })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setExpirationTime('300s');
    if (opts.audience !== undefined) {
      jwt = jwt.setAudience(opts.audience);
    }
    return jwt.sign(privateKey);
  }

  function strictValidator(fetchImpl: ReturnType<typeof jwksFetch>) {
    return new JwtValidator({
      jwksUri: JWKS_URI,
      issuer: ISSUER,
      audience: RESOURCE,
      requireAccessTokenTyp: true,
      fetch: fetchImpl as never,
    });
  }

  it('accepts an access token carrying typ: at+jwt', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signWithHeader(
      { typ: 'at+jwt' },
      { sub: 'user-1', client_id: 'client-1', token_use: 'access' },
      { audience: RESOURCE }
    );
    await expect(validator(fetchImpl).validate(token)).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('rejects an ID token presented as an access token on typ grounds ALONE', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    // #283 acceptance criterion. `aud` is set to the RESOURCE — not a client_id
    // — so the RFC 8707 audience binding this guard normally leans on is
    // SATISFIED. The `iss` matches and the signature verifies against the same
    // JWKS entry, because the AS signs ID and access tokens with one key. `typ`
    // is the only thing left that can reject this token.
    const idToken = await signWithHeader(
      { typ: 'JWT' },
      { sub: 'user-1', token_use: 'id' },
      { audience: RESOURCE }
    );

    // Same claims, same audience, only the header type changed → accepted. This
    // pins the attribution: the failure below is `typ`, nothing else.
    const asAccessToken = await signWithHeader(
      { typ: 'at+jwt' },
      { sub: 'user-1', token_use: 'id' },
      { audience: RESOURCE }
    );
    await expect(validator(fetchImpl).validate(asAccessToken)).resolves.toMatchObject({
      sub: 'user-1',
    });

    await expect(validator(fetchImpl).validate(idToken)).rejects.toThrow(InvalidTokenError);
    await expect(validator(fetchImpl).validate(idToken)).rejects.toThrow(/typ is not at\+jwt/);
  });

  it('coexists with the ADR-005 hybrid header members (pqc_alg / pqc_kid)', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    // A hybrid-signed access token is an ordinary Ed25519 JWS whose protected
    // header additionally carries the non-critical PQC members (#245). A
    // classical resource server must still verify it AND read its `typ`.
    const token = await signWithHeader(
      { typ: 'at+jwt', kid: 'test-key-1', pqc_alg: 'ML-DSA-65', pqc_kid: 'mldsa-1' },
      { sub: 'user-hybrid', client_id: 'client-1', token_use: 'access' },
      { audience: RESOURCE }
    );
    await expect(validator(fetchImpl).validate(token)).resolves.toMatchObject({
      sub: 'user-hybrid',
    });
  });

  it('rejects a hybrid-header ID token — pqc members do not launder a wrong typ', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signWithHeader(
      { typ: 'JWT', kid: 'test-key-1', pqc_alg: 'ML-DSA-65', pqc_kid: 'mldsa-1' },
      { sub: 'user-1', token_use: 'id' },
      { audience: RESOURCE }
    );
    await expect(validator(fetchImpl).validate(token)).rejects.toThrow(/typ is not at\+jwt/);
  });

  it('accepts a typ-less token by default (AS not yet on #283, or still draining)', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 'user-legacy', client_id: 'client-1' },
      { audience: RESOURCE }
    );
    await expect(validator(fetchImpl).validate(token)).resolves.toMatchObject({
      sub: 'user-legacy',
    });
  });

  it('rejects a typ-less token under requireAccessTokenTyp (rollout phase 2)', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 'user-legacy', client_id: 'client-1' },
      { audience: RESOURCE }
    );
    await expect(strictValidator(fetchImpl).validate(token)).rejects.toThrow(
      /missing the required at\+jwt type/
    );
  });

  it('still rejects a wrong typ when requireAccessTokenTyp is off', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    // The flag governs only the ABSENT case; it can never be used to tolerate a
    // token that positively declares itself to be something else.
    const token = await signWithHeader({ typ: 'JWT' }, { sub: 'user-1' }, { audience: RESOURCE });
    await expect(validator(fetchImpl).validate(token)).rejects.toThrow(/typ is not at\+jwt/);
  });

  it('reads typ from the signed header — a spliced header fails at the signature', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const idToken = await signWithHeader({ typ: 'JWT' }, { sub: 'user-1' }, { audience: RESOURCE });
    const [, payload, signature] = idToken.split('.');
    const forgedHeader = Buffer.from(
      JSON.stringify({ alg: 'EdDSA', typ: 'at+jwt', kid: 'test-key-1' })
    ).toString('base64url');

    // Rewriting the header to claim `at+jwt` changes the JWS signing input, so
    // this dies on the signature check — never on (or past) the typ check.
    await expect(
      validator(fetchImpl).validate(`${forgedHeader}.${payload}.${signature}`)
    ).rejects.toThrow(/signature verification failed/);
  });
});
