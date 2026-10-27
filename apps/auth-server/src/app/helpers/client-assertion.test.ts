import { InvalidClientError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { ENV, egressGet } = vi.hoisted(() => ({
  ENV: {
    CIMD_ENABLED: true,
    CIMD_TRUST_POLICY: 'accept-any-https' as 'accept-any-https' | 'allowlist',
    CIMD_TRUSTED_DOMAINS: [] as string[],
    CIMD_CACHE_DEFAULT_TTL: 300,
    CIMD_CACHE_MAX_TTL: 3600,
    CIMD_MAX_DOCUMENT_BYTES: 65536,
    CIMD_FETCH_TIMEOUT_MS: 5000,
  },
  egressGet: vi.fn(),
}));

vi.mock('../../config/env', () => ({ env: ENV }));

vi.mock('./egress-get', () => ({ egressGet }));

import { blockedEgress } from '../../testing/egress';
import {
  authenticateClientAssertion,
  CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS,
  CLIENT_ASSERTION_MAX_LIFETIME_SECONDS,
  type ClientAssertionCredentials,
} from './client-assertion';

const ISSUER = 'https://auth.example.com';
/** The realm the request was resolved to, whose issuer is the only audience (#490). */
const REALM = { id: 'realm-1', issuer: ISSUER };
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;
const CLIENT_ID = 'pkjwt-client';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/* -------------------------------------------------------------------------- */
/*                                  Fixtures                                  */
/* -------------------------------------------------------------------------- */

interface ClientRow {
  id: string;
  clientId: string;
  clientSecretHash: string;
  enabled: boolean;
  suspended?: boolean;
  grantTypes: string[];
  scopes: string[];
  audience: string[] | null;
  tokenEndpointAuthMethod: string;
  jwks?: { keys: Record<string, unknown>[] } | null;
  jwksUri?: string | null;
}

function clientRow(overrides: Partial<ClientRow> = {}): ClientRow {
  return {
    id: 'row-1',
    clientId: CLIENT_ID,
    clientSecretHash: '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGlnZXN0',
    enabled: true,
    grantTypes: ['client_credentials'],
    scopes: [],
    audience: null,
    tokenEndpointAuthMethod: 'private_key_jwt',
    jwks: null,
    jwksUri: null,
    ...overrides,
  };
}

/**
 * Fastify stub with an in-memory Redis that honours `SET ... NX` semantics —
 * the replay tests are only meaningful if the second write actually fails.
 */
function fastifyStub(client: ClientRow | null) {
  const store = new Map<string, string>();
  const redis = {
    get: vi.fn(async (k: string) => store.get(k) ?? null),
    set: vi.fn(async (k: string, v: string, ..._rest: unknown[]) => {
      const nx = _rest.includes('NX');
      if (nx && store.has(k)) return null;
      store.set(k, v);
      return 'OK';
    }),
  };
  return {
    redis,
    store,
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    repositories: {
      oauthClients: {
        findByClientId: vi.fn(async () => client),
        upsertCimdClient: vi.fn(),
      },
    },
  };
}

function asFastify(stub: ReturnType<typeof fastifyStub>): FastifyInstance {
  return stub as unknown as FastifyInstance;
}

function creds(assertion: string, overrides: Partial<ClientAssertionCredentials> = {}) {
  return {
    assertionType: ASSERTION_TYPE,
    assertion,
    method: 'private_key_jwt' as const,
    ...overrides,
  };
}

let es256: { privateKey: CryptoKey; publicKey: CryptoKey };
let es256Jwk: JWK;
let otherKeys: { privateKey: CryptoKey; publicKey: CryptoKey };

beforeEach(async () => {
  vi.clearAllMocks();
  ENV.CIMD_ENABLED = true;
  ENV.CIMD_TRUST_POLICY = 'accept-any-https';
  ENV.CIMD_TRUSTED_DOMAINS = [];
  es256 = await generateKeyPair('ES256', { extractable: true });
  es256Jwk = await exportJWK(es256.publicKey);
  otherKeys = await generateKeyPair('ES256', { extractable: true });
});

interface AssertionOptions {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string | null;
  expOffset?: number;
  iat?: number | null;
  nbf?: number;
  alg?: string;
  key?: CryptoKey | Uint8Array;
  extraHeader?: Record<string, unknown>;
}

async function makeAssertion(options: AssertionOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT({})
    .setProtectedHeader({ alg: options.alg ?? 'ES256', ...(options.extraHeader ?? {}) })
    .setIssuer(options.iss ?? CLIENT_ID)
    .setSubject(options.sub ?? CLIENT_ID)
    .setAudience(options.aud ?? ISSUER)
    .setExpirationTime(now + (options.expOffset ?? 60));

  if (options.jti !== null) jwt.setJti(options.jti ?? `jti-${Math.random()}`);
  if (options.iat !== null) jwt.setIssuedAt(options.iat ?? now);
  if (options.nbf !== undefined) jwt.setNotBefore(options.nbf);

  return jwt.sign(options.key ?? es256.privateKey);
}

function jwkSet(...keys: JWK[]) {
  return { keys: keys as unknown as Record<string, unknown>[] };
}

/* -------------------------------------------------------------------------- */
/*                                Happy paths                                 */
/* -------------------------------------------------------------------------- */

describe('authenticateClientAssertion — accepted', () => {
  it('authenticates a private_key_jwt client whose assertion names the issuer', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion();

    const client = await authenticateClientAssertion(asFastify(stub), REALM, creds(assertion));

    expect(client.clientId).toBe(CLIENT_ID);
  });

  it("takes the audience from the request realm's issuer, not from JWT_ISSUER (ADR-019 Decision 1, #490)", async () => {
    const realmB = { id: 'realm-b', issuer: 'https://b.example.com' };
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));

    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        realmB,
        creds(await makeAssertion({ aud: 'https://b.example.com' }))
      )
    ).resolves.toMatchObject({ clientId: CLIENT_ID });
    // An assertion for another realm's issuer is refused at realm B.
    await expect(
      authenticateClientAssertion(asFastify(stub), realmB, creds(await makeAssertion()))
    ).rejects.toBeInstanceOf(InvalidClientError);
    expect(stub.repositories.oauthClients.findByClientId).toHaveBeenCalledWith(
      'realm-b',
      CLIENT_ID
    );
  });

  it('accepts a one-element `aud` array that holds the issuer', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ aud: [ISSUER] });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).resolves.toMatchObject({ clientId: CLIENT_ID });
  });

  it('accepts a matching body client_id alongside the assertion (RFC 7521 §4.2)', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion, { clientId: CLIENT_ID }))
    ).resolves.toMatchObject({ clientId: CLIENT_ID });
  });

  it('accepts an EdDSA assertion and selects the right key by kid', async () => {
    const ed = await generateKeyPair('EdDSA', { extractable: true });
    const edJwk = { ...(await exportJWK(ed.publicKey)), kid: 'ed-1' };
    const decoyJwk = { ...es256Jwk, kid: 'ec-1' };
    const stub = fastifyStub(clientRow({ jwks: jwkSet(decoyJwk, edJwk) }));

    const assertion = await makeAssertion({
      alg: 'EdDSA',
      key: ed.privateKey,
      extraHeader: { kid: 'ed-1' },
    });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).resolves.toMatchObject({ clientId: CLIENT_ID });
  });

  it('resolves keys from a registered jwks_uri through the SSRF-guarded fetcher', async () => {
    const stub = fastifyStub(
      clientRow({ jwks: null, jwksUri: 'https://client.example.com/jwks.json' })
    );
    egressGet.mockResolvedValue({
      status: 200,
      body: JSON.stringify({ keys: [es256Jwk] }),
      headers: {},
    });
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).resolves.toMatchObject({ clientId: CLIENT_ID });

    // A client-supplied URL: never a deployment allowlist destination.
    expect(egressGet).toHaveBeenCalledWith(
      expect.anything(),
      'https://client.example.com/jwks.json',
      expect.objectContaining({ source: 'client' })
    );
  });
});

/* -------------------------------------------------------------------------- */
/*                                 Deny paths                                 */
/* -------------------------------------------------------------------------- */

describe('authenticateClientAssertion — rejected', () => {
  it('rejects the token endpoint URL as `aud` (RFC 7523 §3 allows it, rfc7523bis does not)', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ aud: TOKEN_ENDPOINT });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects an `aud` array that holds the issuer next to another value', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ aud: [ISSUER, 'https://other.example.com'] });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects the token endpoint URL next to the issuer, as the sole-value rule demands', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ aud: [ISSUER, TOKEN_ENDPOINT] });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects a wrong audience', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ aud: 'https://evil.example.com/oauth/token' });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects an assertion whose aud is another authorization server path on the same host', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ aud: `${ISSUER}/oauth/introspect` });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects an expired assertion', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    // Beyond `exp` plus the clock-skew leeway.
    const assertion = await makeAssertion({ expOffset: -600, iat: null });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects an assertion that is not yet valid (nbf in the future)', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const now = Math.floor(Date.now() / 1000);
    const assertion = await makeAssertion({ nbf: now + 600, expOffset: 900 });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects an assertion whose iat is in the future', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const now = Math.floor(Date.now() / 1000);
    const assertion = await makeAssertion({ iat: now + 600, expOffset: 660 });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects an assertion whose lifetime exceeds the permitted maximum', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({
      expOffset: CLIENT_ASSERTION_MAX_LIFETIME_SECONDS + 3600,
    });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/lifetime exceeds/) });
  });

  it('rejects an assertion whose iss and sub disagree', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ iss: CLIENT_ID, sub: 'someone-else' });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/iss and sub/) });
  });

  it('rejects an assertion with no sub at all', async () => {
    const now = Math.floor(Date.now() / 1000);
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(CLIENT_ID)
      .setAudience(ISSUER)
      .setJti('no-sub')
      .setExpirationTime(now + 60)
      .sign(es256.privateKey);

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/iss and sub/) });
  });

  it('rejects a body client_id that disagrees with the assertion subject', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        REALM,
        creds(assertion, { clientId: 'a-different-client' })
      )
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/does not match/) });
  });

  it('rejects an unknown client', async () => {
    const stub = fastifyStub(null);
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects an operator-suspended client (ANT-2026-DR5XI3LV)', async () => {
    const stub = fastifyStub(clientRow({ suspended: true, jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects a disabled client', async () => {
    const stub = fastifyStub(clientRow({ enabled: false, jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('rejects a signature made with a key that is not in the client JWKS', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ key: otherKeys.privateKey });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/signature or claims/) });
  });

  it('rejects `alg: none`', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const now = Math.floor(Date.now() / 1000);
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const unsigned = `${b64({ alg: 'none' })}.${b64({
      iss: CLIENT_ID,
      sub: CLIENT_ID,
      aud: ISSUER,
      jti: 'none-alg',
      exp: now + 60,
      iat: now,
    })}.`;

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(unsigned))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/alg is not permitted/) });
  });

  it('rejects an HS256 assertion (MAC algorithms are never accepted)', async () => {
    // The classic confusion attack: the "signature" is an HMAC keyed with data
    // the attacker can read out of the client's own public JWK.
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({
      alg: 'HS256',
      key: new Uint8Array(32).fill(7),
    });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/alg is not permitted/) });
  });

  it('rejects an assertion that carries its own key material (jwk header)', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const attackerJwk = await exportJWK(otherKeys.publicKey);
    const assertion = await makeAssertion({
      key: otherKeys.privateKey,
      extraHeader: { jwk: attackerJwk },
    });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/must not carry its own key material/),
    });
  });

  it('rejects an assertion that points at a remote key set (jku header)', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({
      extraHeader: { jku: 'https://evil.example.com/jwks.json' },
    });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/must not carry its own key material/),
    });
  });

  it('rejects a replayed jti', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ jti: 'replay-me' });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).resolves.toBeDefined();
    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/already been used/) });
  });

  // Regression (ANT-2026-D8J0C6IS): the verifier grants the clock-skew leeway
  // twice — an `iat` up to one leeway ahead, and `exp` accepted one leeway
  // past — but the replay entry's ceiling counted it once, so it expired while
  // the assertion of a client whose clock runs ahead was still acceptable.
  it('keeps the jti entry until the assertion itself stops being acceptable', async () => {
    // A client whose clock runs ahead, within the leeway, signing for the
    // maximum lifetime: the longest-lived assertion the verifier accepts.
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const now = Math.floor(Date.now() / 1000);
    const skew = CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS - 5;
    const assertion = await makeAssertion({
      iat: now + skew,
      expOffset: skew + CLIENT_ASSERTION_MAX_LIFETIME_SECONDS,
    });

    await authenticateClientAssertion(asFastify(stub), REALM, creds(assertion));

    const [, , , ttlSeconds] = stub.redis.set.mock.calls[0];
    const acceptableFor =
      skew + CLIENT_ASSERTION_MAX_LIFETIME_SECONDS + CLIENT_ASSERTION_CLOCK_SKEW_LEEWAY_SECONDS;
    // 1 s of slack for a second boundary between `now` here and in the verifier.
    expect(ttlSeconds).toBeGreaterThanOrEqual(acceptableFor - 1);
  });

  it('rejects an assertion with no jti (replay protection needs one)', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion({ jti: null });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toThrow(InvalidClientError);
  });

  it('fails closed when the replay store is unavailable', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    stub.redis.set.mockRejectedValue(new Error('redis down'));
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/replay protection is unavailable/),
    });
  });

  it('rejects a client_secret_post client presenting an assertion', async () => {
    const stub = fastifyStub(
      clientRow({ tokenEndpointAuthMethod: 'client_secret_post', jwks: jwkSet(es256Jwk) })
    );
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/not registered for private_key_jwt/),
    });
  });

  it('rejects a public client presenting an assertion', async () => {
    const stub = fastifyStub(
      clientRow({ tokenEndpointAuthMethod: 'none', jwks: jwkSet(es256Jwk) })
    );
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/not registered for private_key_jwt/),
    });
  });

  it('rejects a client that registered both jwks and jwks_uri', async () => {
    const stub = fastifyStub(
      clientRow({ jwks: jwkSet(es256Jwk), jwksUri: 'https://client.example.com/jwks.json' })
    );
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/mutually exclusive/) });
  });

  it('rejects a client that registered neither jwks nor jwks_uri', async () => {
    const stub = fastifyStub(clientRow({ jwks: null, jwksUri: null }));
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/no registered jwks/) });
  });

  it('rejects a jwks_uri that resolves to a private address', async () => {
    const stub = fastifyStub(
      clientRow({ jwks: null, jwksUri: 'https://internal.example.com/jwks.json' })
    );
    egressGet.mockRejectedValue(
      blockedEgress('host resolves to a non-public address (169.254.169.254)')
    );
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/jwks_uri fetch blocked/) });
  });

  it('rejects a jwks_uri document that is not a 200', async () => {
    const stub = fastifyStub(
      clientRow({ jwks: null, jwksUri: 'https://client.example.com/jwks.json' })
    );
    egressGet.mockResolvedValue({ status: 404, body: '', headers: {} });
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({ errorDescription: expect.stringMatching(/returned 404/) });
  });

  it('rejects a registered key set that leaks a private component', async () => {
    const privateJwk = await exportJWK(es256.privateKey);
    const stub = fastifyStub(clientRow({ jwks: jwkSet(privateJwk) }));
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/not a valid public JWK Set/),
    });
  });

  it('rejects a registered key set containing a symmetric key', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet({ kty: 'oct' } as JWK) }));
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/not a valid public JWK Set/),
    });
  });

  // Regression (ANT-2026-IY5YYLQR): the key went to WebCrypto's importKey with
  // every member as the key set had it, and importKey converts a `key_ops`
  // entry that is not a string with `String()` — which, for a deeply nested
  // array, copies its text once per level. All of it before the signature of
  // an assertion anybody can send was checked.
  it('refuses a key whose key_ops is deeply nested before converting any of it', async () => {
    let keyOps: unknown = Array.from({ length: 4000 }, () => ({}));
    for (let level = 0; level < 2500; level++) keyOps = [keyOps, 0];
    const jwk = { ...es256Jwk, key_ops: ['verify', keyOps] } as unknown as JWK;
    const stub = fastifyStub(clientRow({ jwks: jwkSet(jwk) }));
    const assertion = await makeAssertion();

    const started = performance.now();
    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(assertion))
    ).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/not a valid public JWK Set/),
    });
    expect(performance.now() - started).toBeLessThan(250);
  }, 60_000);

  it('rejects the grant-type URN presented as a client_assertion_type', async () => {
    // `...:grant-type:jwt-bearer` and `...:client-assertion-type:jwt-bearer`
    // differ by one path segment and must never be interchangeable.
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const assertion = await makeAssertion();

    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        REALM,
        creds(assertion, { assertionType: 'urn:ietf:params:oauth:grant-type:jwt-bearer' })
      )
    ).rejects.toMatchObject({
      errorDescription: expect.stringMatching(/unsupported client_assertion_type/),
    });
  });

  it('rejects an assertion that is not a decodable JWT', async () => {
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds('not-a-jwt'))
    ).rejects.toThrow(InvalidClientError);
  });

  it('does not consume the jti when the signature is invalid', async () => {
    // Burning a jti before verification would let an unauthenticated caller
    // invalidate assertions the real client is about to send.
    const stub = fastifyStub(clientRow({ jwks: jwkSet(es256Jwk) }));
    const forged = await makeAssertion({ jti: 'shared-jti', key: otherKeys.privateKey });

    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(forged))
    ).rejects.toThrow(InvalidClientError);

    const genuine = await makeAssertion({ jti: 'shared-jti' });
    await expect(
      authenticateClientAssertion(asFastify(stub), REALM, creds(genuine))
    ).resolves.toBeDefined();
  });
});

/* -------------------------------------------------------------------------- */
/*                                CIMD clients                                */
/* -------------------------------------------------------------------------- */

// Regression (ANT-2026-4V7HWAND): a materialised CIMD row is only a cache of
// the metadata document (ADR-012 §3). The assertion path read the stored row
// and went through `resolveClient` only when there was none, so once the row
// existed, `CIMD_ENABLED=false`, the trust allowlist, a vanished document and
// key rotation never reached a `private_key_jwt` CIMD client.
describe('authenticateClientAssertion — re-resolves a materialised CIMD client', () => {
  const CIMD_ID = 'https://app.example.com/client.json';

  function cimdDocument(...keys: JWK[]) {
    return {
      status: 200,
      body: JSON.stringify({
        client_id: CIMD_ID,
        client_name: 'Example',
        redirect_uris: ['https://app.example.com/cb'],
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: { keys },
      }),
      headers: {},
    };
  }

  function cimdAssertion(key: CryptoKey) {
    return makeAssertion({ iss: CIMD_ID, sub: CIMD_ID, key });
  }

  async function materialise() {
    const stub = fastifyStub(null);
    let stored: ClientRow | null = null;
    stub.repositories.oauthClients.findByClientId.mockImplementation(async () => stored);
    stub.repositories.oauthClients.upsertCimdClient.mockImplementation(async (row: ClientRow) => {
      stored = { ...row, id: 'row-cimd', audience: null };
      return stored;
    });
    egressGet.mockResolvedValue(cimdDocument(es256Jwk));

    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        REALM,
        creds(await cimdAssertion(es256.privateKey))
      )
    ).resolves.toMatchObject({ clientId: CIMD_ID });
    // From here on the row exists, exactly as after a first token request.
    expect(stored).not.toBeNull();
    stub.store.clear(); // expire the document cache
    return stub;
  }

  it('keeps authenticating while the document is unchanged', async () => {
    const stub = await materialise();

    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        REALM,
        creds(await cimdAssertion(es256.privateKey))
      )
    ).resolves.toMatchObject({ clientId: CIMD_ID });
  });

  it('follows a key rotation in the document', async () => {
    const stub = await materialise();
    egressGet.mockResolvedValue(cimdDocument(await exportJWK(otherKeys.publicKey)));

    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        REALM,
        creds(await cimdAssertion(es256.privateKey))
      )
    ).rejects.toThrow(InvalidClientError);
    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        REALM,
        creds(await cimdAssertion(otherKeys.privateKey))
      )
    ).resolves.toMatchObject({ clientId: CIMD_ID });
  });

  it('fails closed once CIMD is switched off, even for a stored client', async () => {
    const stub = await materialise();
    ENV.CIMD_ENABLED = false;

    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        REALM,
        creds(await cimdAssertion(es256.privateKey))
      )
    ).rejects.toThrow(InvalidClientError);
  });

  it('fails closed once the host leaves the trust allowlist', async () => {
    const stub = await materialise();
    ENV.CIMD_TRUST_POLICY = 'allowlist';
    ENV.CIMD_TRUSTED_DOMAINS = ['other.example.com'];

    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        REALM,
        creds(await cimdAssertion(es256.privateKey))
      )
    ).rejects.toThrow(InvalidClientError);
  });

  it('fails closed when the document can no longer be fetched', async () => {
    const stub = await materialise();
    egressGet.mockResolvedValue({ status: 404, body: '', headers: {} });

    await expect(
      authenticateClientAssertion(
        asFastify(stub),
        REALM,
        creds(await cimdAssertion(es256.privateKey))
      )
    ).rejects.toThrow(InvalidClientError);
  });
});
