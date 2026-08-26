import { generateKeyPairSync } from 'node:crypto';

import { importPublicSigningKey } from '@qauth-labs/core-crypto';
import { type CryptoKey, decodeJwt, decodeProtectedHeader, importPKCS8, SignJWT } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

/** A fresh Ed25519 pair in the PKCS#8 / SPKI PEM form the config carries. */
function generateEd25519Pem(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

const SERVER_KEYS = generateEd25519Pem();

const { ENV } = vi.hoisted(() => ({
  ENV: {
    ID_JAG_ENABLED: true,
    ID_JAG_TRUSTED_ISSUERS: [] as string[],
    ID_JAG_CLOCK_SKEW_LEEWAY: 60,
    ID_JAG_MAX_ASSERTION_LIFETIME: 300,
    ID_JAG_ISSUED_LIFETIME: 300,
    JWT_PRIVATE_KEY: '',
  },
}));
ENV.JWT_PRIVATE_KEY = SERVER_KEYS.privateKeyPem;

vi.mock('../../config/env', () => ({ env: ENV }));

import {
  ID_JAG_TYP,
  idJagCredentialProviderType,
  IdJagValidationError,
  mintIdJag,
  validateIdJagAssertion,
} from './id-jag';
import type { IdJagIssuerKeyResolver } from './id-jag-issuer-keys';

const AS_ISSUER = 'https://auth.example.com';
const IDP_ISSUER = 'https://idp.example.com';
const CLIENT_ID = 'mcp-client-1';
const MCP_SERVER = 'https://mcp.example.com/';

/** The enterprise IdP's signing key pair, used to mint fixture assertions. */
const IDP_KEYS = generateEd25519Pem();
let idpPrivateKey: CryptoKey;
let idpPublicKey: Awaited<ReturnType<typeof importPublicSigningKey>>;

/** A resolver that answers with the IdP's key for the allowlisted issuer only. */
function trustedResolver(overrides?: {
  identifier?: string;
  key?: Awaited<ReturnType<typeof importPublicSigningKey>>;
}): IdJagIssuerKeyResolver {
  return vi.fn(async (request) => {
    if (request.issuer !== IDP_ISSUER && request.issuer !== `${IDP_ISSUER}/`) return undefined;
    return { key: overrides?.key ?? idpPublicKey, identifier: overrides?.identifier ?? IDP_ISSUER };
  });
}

/** A resolver that trusts nothing — the empty-allowlist / unknown-issuer shape. */
const untrustedResolver: IdJagIssuerKeyResolver = vi.fn(async () => undefined);

interface AssertionOverrides {
  readonly typ?: string;
  readonly alg?: string;
  readonly iss?: string;
  readonly sub?: string;
  readonly aud?: string | string[];
  readonly resource?: unknown;
  readonly clientId?: unknown;
  readonly jti?: string;
  readonly scope?: string;
  readonly iat?: number;
  readonly exp?: number;
  readonly key?: CryptoKey;
  /** Extra top-level claims, for asserting on members the schema would strip. */
  readonly extraClaims?: Record<string, unknown>;
}

let jtiCounter = 0;

async function makeAssertion(overrides: AssertionOverrides = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const iat = overrides.iat ?? now;
  const exp = overrides.exp ?? iat + 120;
  const payload: Record<string, unknown> = {
    jti: overrides.jti ?? `jti-${++jtiCounter}`,
    iss: overrides.iss ?? IDP_ISSUER,
    sub: overrides.sub ?? 'U019488227',
    aud: overrides.aud ?? AS_ISSUER,
    client_id: overrides.clientId ?? CLIENT_ID,
    iat,
    exp,
  };
  if (overrides.resource !== null) {
    payload['resource'] = overrides.resource ?? MCP_SERVER;
  }
  if (overrides.scope !== undefined) payload['scope'] = overrides.scope;
  if (overrides.extraClaims) Object.assign(payload, overrides.extraClaims);

  return new SignJWT(payload)
    .setProtectedHeader({ alg: overrides.alg ?? 'EdDSA', typ: overrides.typ ?? ID_JAG_TYP })
    .sign(overrides.key ?? idpPrivateKey);
}

/** Minimal `fastify` stand-in: jwtUtils.getIssuer + a SET-NX-capable redis. */
function fastifyStub() {
  const store = new Map<string, string>();
  const redis = {
    set: vi.fn(async (key: string, value: string, _ex?: string, _ttl?: number, nx?: string) => {
      if (nx === 'NX' && store.has(key)) return null;
      store.set(key, value);
      return 'OK';
    }),
    get: vi.fn(async (key: string) => store.get(key) ?? null),
  };
  return {
    store,
    redis,
    fastify: {
      redis,
      jwtUtils: { getIssuer: () => AS_ISSUER },
      log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  };
}

beforeEach(async () => {
  idpPrivateKey = (await importPKCS8(IDP_KEYS.privateKeyPem, 'EdDSA')) as CryptoKey;
  idpPublicKey = await importPublicSigningKey(IDP_KEYS.publicKeyPem, 'EdDSA');
  ENV.ID_JAG_ENABLED = true;
  ENV.ID_JAG_TRUSTED_ISSUERS = [IDP_ISSUER];
  ENV.ID_JAG_CLOCK_SKEW_LEEWAY = 60;
  ENV.ID_JAG_MAX_ASSERTION_LIFETIME = 300;
  ENV.ID_JAG_ISSUED_LIFETIME = 300;
});

async function expectRejection(
  promise: Promise<unknown>,
  reason: string
): Promise<IdJagValidationError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e
  );
  expect(err).toBeInstanceOf(IdJagValidationError);
  expect((err as IdJagValidationError).reason).toBe(reason);
  return err as IdJagValidationError;
}

describe('validateIdJagAssertion — happy path', () => {
  it('accepts a well-formed assertion from an allowlisted issuer', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({ scope: 'chat.read chat.history chat.read' });

    const validated = await validateIdJagAssertion(fastify, {
      assertion,
      expectedClientId: CLIENT_ID,
      resolver: trustedResolver(),
    });

    expect(validated.issuer).toBe(IDP_ISSUER);
    expect(validated.subject).toBe('U019488227');
    expect(validated.audience).toBe(AS_ISSUER);
    expect(validated.resource).toBe(MCP_SERVER);
    expect(validated.clientId).toBe(CLIENT_ID);
    // Deduped, so a repeated scope cannot bloat the granted set.
    expect(validated.scopes).toEqual(['chat.read', 'chat.history']);
  });

  it('reports the CONFIRMED issuer identifier, not the assertion text', async () => {
    const { fastify } = fastifyStub();
    // The assertion spells the issuer with a trailing slash; the resolver
    // confirms the canonical allowlist entry.
    const assertion = await makeAssertion({ iss: `${IDP_ISSUER}/` });

    const validated = await validateIdJagAssertion(fastify, {
      assertion,
      expectedClientId: CLIENT_ID,
      resolver: trustedResolver(),
    });

    expect(validated.issuer).toBe(IDP_ISSUER);
  });
});

describe('validateIdJagAssertion — deny paths', () => {
  it('rejects everything when ID_JAG_ENABLED is false', async () => {
    ENV.ID_JAG_ENABLED = false;
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion();

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'disabled'
    );
  });

  it('rejects when the trusted-issuer allowlist resolves nothing (empty allowlist)', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion();

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: untrustedResolver,
      }),
      'unresolvable_key'
    );
  });

  it('rejects an issuer that is not on the allowlist', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({ iss: 'https://evil.example.com' });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'unresolvable_key'
    );
  });

  it('rejects `alg: none` before any key is resolved', async () => {
    const { fastify } = fastifyStub();
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: ID_JAG_TYP })).toString(
      'base64url'
    );
    const payload = Buffer.from(
      JSON.stringify({
        jti: 'x',
        iss: IDP_ISSUER,
        sub: 'u',
        aud: AS_ISSUER,
        resource: MCP_SERVER,
        client_id: CLIENT_ID,
        iat: 1,
        exp: 2,
      })
    ).toString('base64url');
    const resolver = trustedResolver();

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion: `${header}.${payload}.`,
        expectedClientId: CLIENT_ID,
        resolver,
      }),
      'unsupported_algorithm'
    );
    expect(resolver).not.toHaveBeenCalled();
  });

  it('rejects a MAC-algorithm assertion before any key is resolved', async () => {
    const { fastify } = fastifyStub();
    const secret = new Uint8Array(32).fill(7);
    const assertion = await new SignJWT({
      jti: 'x',
      iss: IDP_ISSUER,
      sub: 'u',
      aud: AS_ISSUER,
      resource: MCP_SERVER,
      client_id: CLIENT_ID,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 120,
    })
      .setProtectedHeader({ alg: 'HS256', typ: ID_JAG_TYP })
      .sign(secret);
    const resolver = trustedResolver();

    await expectRejection(
      validateIdJagAssertion(fastify, { assertion, expectedClientId: CLIENT_ID, resolver }),
      'unsupported_algorithm'
    );
    expect(resolver).not.toHaveBeenCalled();
  });

  it('rejects an assertion whose `typ` is not oauth-id-jag+jwt', async () => {
    const { fastify } = fastifyStub();
    // An access token minted by the same issuer must not be usable here.
    const assertion = await makeAssertion({ typ: 'at+jwt' });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'unsupported_typ'
    );
  });

  it('rejects an assertion signed with a key the issuer does not publish', async () => {
    const { fastify } = fastifyStub();
    const otherKeys = generateEd25519Pem();
    const otherPrivate = (await importPKCS8(otherKeys.privateKeyPem, 'EdDSA')) as CryptoKey;
    const assertion = await makeAssertion({ key: otherPrivate });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'signature_invalid'
    );
  });

  it('rejects an `aud` that is not this authorization server', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({ aud: 'https://someone-else.example.com' });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'signature_invalid'
    );
  });

  it('rejects a MULTI-VALUED `aud` even when it contains this server', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({ aud: [AS_ISSUER, 'https://other-as.example.com'] });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'audience_invalid'
    );
  });

  // ADR-011 gate 15. The regression this guards is specific: `idJagClaimsSchema`
  // is non-strict, so before the explicit check existed Zod stripped
  // `authorization_details` and the assertion was ACCEPTED with the IdP's
  // narrowing silently discarded — a privilege upgrade relative to what the
  // enterprise authorized. A passing "rejects" assertion here is only
  // meaningful alongside the sibling test below proving other unknown members
  // still pass, otherwise `.strict()` would satisfy this one and break callers.
  it('rejects an assertion carrying authorization_details (RFC 9396), never ignores it', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({
      extraClaims: {
        authorization_details: [{ type: 'payment_initiation', actions: ['initiate'] }],
      },
    });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'unsupported_constraint'
    );
  });

  it('still accepts an assertion carrying an unrecognised member that is NOT a constraint', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({
      extraClaims: { some_future_spec_member: 'tolerated' },
    });

    const result = await validateIdJagAssertion(fastify, {
      assertion,
      expectedClientId: CLIENT_ID,
      resolver: trustedResolver(),
    });

    expect(result.clientId).toBe(CLIENT_ID);
  });

  it('rejects an expired assertion', async () => {
    const { fastify } = fastifyStub();
    const now = Math.floor(Date.now() / 1000);
    const assertion = await makeAssertion({ iat: now - 600, exp: now - 500 });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'signature_invalid'
    );
  });

  it('rejects an assertion whose declared lifetime exceeds the configured bound', async () => {
    const { fastify } = fastifyStub();
    const now = Math.floor(Date.now() / 1000);
    // Still unexpired, but the window is far longer than the replay cache retains.
    const assertion = await makeAssertion({ iat: now, exp: now + 86400 });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'lifetime_invalid'
    );
  });

  it('rejects an assertion issued in the future beyond the skew leeway', async () => {
    const { fastify } = fastifyStub();
    const now = Math.floor(Date.now() / 1000);
    const assertion = await makeAssertion({ iat: now + 3600, exp: now + 3660 });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'lifetime_invalid'
    );
  });

  it('rejects an assertion with NO `resource` claim', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({ resource: null });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'claims_invalid'
    );
  });

  it('rejects an assertion with a non-string `resource`', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({ resource: [MCP_SERVER] });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'claims_invalid'
    );
  });

  it('rejects an assertion with no `client_id` claim', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({ clientId: 42 });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'claims_invalid'
    );
  });

  it('rejects anything that is not a compact JWS', async () => {
    const { fastify } = fastifyStub();

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion: 'not-a-jwt',
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'malformed'
    );
  });

  it('rejects an assertion whose `iss` disagrees with the issuer whose key verified it', async () => {
    const { fastify } = fastifyStub();
    // A resolver that hands back the IdP's key but CONFIRMS a different
    // identity — the shape a buggy or subverted backend would have. The
    // post-verification `iss` binding must catch it.
    const assertion = await makeAssertion({ iss: IDP_ISSUER });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver({ identifier: 'https://someone-else.example.com' }),
      }),
      'issuer_invalid'
    );
  });
});

describe('validateIdJagAssertion — replay protection', () => {
  it('accepts an assertion once and rejects the replay', async () => {
    const { fastify } = fastifyStub();
    const assertion = await makeAssertion({ jti: 'single-use-1' });
    const resolver = trustedResolver();

    await expect(
      validateIdJagAssertion(fastify, { assertion, expectedClientId: CLIENT_ID, resolver })
    ).resolves.toBeDefined();
    await expectRejection(
      validateIdJagAssertion(fastify, { assertion, expectedClientId: CLIENT_ID, resolver }),
      'replayed'
    );
  });

  it('does NOT burn the jti when the assertion names a different client', async () => {
    const { fastify, store } = fastifyStub();
    const assertion = await makeAssertion({ jti: 'not-yours' });
    const resolver = trustedResolver();

    // A second client presenting an assertion it does not own must not be able
    // to destroy it: the binding is checked BEFORE the single-use marker.
    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: 'some-other-client',
        resolver,
      }),
      'client_mismatch'
    );
    expect(store.size).toBe(0);

    // The rightful client can still redeem it.
    await expect(
      validateIdJagAssertion(fastify, { assertion, expectedClientId: CLIENT_ID, resolver })
    ).resolves.toBeDefined();
  });

  it('scopes the replay marker by issuer, so two IdPs cannot collide on one jti', async () => {
    const { fastify, store } = fastifyStub();
    const secondIssuer = 'https://idp2.example.com';
    const secondKeys = generateEd25519Pem();
    const secondPrivate = (await importPKCS8(secondKeys.privateKeyPem, 'EdDSA')) as CryptoKey;
    const secondPublic = await importPublicSigningKey(secondKeys.publicKeyPem, 'EdDSA');

    const resolver: IdJagIssuerKeyResolver = vi.fn(async (request) => {
      if (request.issuer === IDP_ISSUER) return { key: idpPublicKey, identifier: IDP_ISSUER };
      if (request.issuer === secondIssuer) return { key: secondPublic, identifier: secondIssuer };
      return undefined;
    });

    // The SAME jti from two different issuers must both be accepted.
    await expect(
      validateIdJagAssertion(fastify, {
        assertion: await makeAssertion({ jti: 'shared-jti' }),
        expectedClientId: CLIENT_ID,
        resolver,
      })
    ).resolves.toBeDefined();
    await expect(
      validateIdJagAssertion(fastify, {
        assertion: await makeAssertion({
          jti: 'shared-jti',
          iss: secondIssuer,
          key: secondPrivate,
        }),
        expectedClientId: CLIENT_ID,
        resolver,
      })
    ).resolves.toBeDefined();

    expect(store.size).toBe(2);
    // ...and each is still single-use within its own issuer.
    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion: await makeAssertion({ jti: 'shared-jti' }),
        expectedClientId: CLIENT_ID,
        resolver,
      }),
      'replayed'
    );
  });

  it('FAILS CLOSED when the replay store is unavailable', async () => {
    const { fastify } = fastifyStub();
    fastify.redis.set.mockRejectedValue(new Error('redis down'));
    const assertion = await makeAssertion();

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'replay_store_unavailable'
    );
  });

  it('does not burn a jti for an assertion that fails verification', async () => {
    const { fastify, store } = fastifyStub();
    const assertion = await makeAssertion({ aud: 'https://elsewhere.example.com' });

    await expectRejection(
      validateIdJagAssertion(fastify, {
        assertion,
        expectedClientId: CLIENT_ID,
        resolver: trustedResolver(),
      }),
      'signature_invalid'
    );
    expect(store.size).toBe(0);
  });
});

describe('mintIdJag', () => {
  it('mints an assertion with exactly the ID-JAG claim set', async () => {
    const { fastify } = fastifyStub();

    const minted = await mintIdJag(fastify, {
      subject: 'user-uuid-1',
      audience: 'https://auth.chat.example',
      resource: 'https://mcp.chat.example/',
      clientId: CLIENT_ID,
      scope: 'chat.read chat.history',
    });

    expect(decodeProtectedHeader(minted.assertion)).toEqual({ alg: 'EdDSA', typ: ID_JAG_TYP });

    const claims = decodeJwt(minted.assertion) as Record<string, unknown>;
    expect(Object.keys(claims).sort()).toEqual(
      ['aud', 'client_id', 'exp', 'iat', 'iss', 'jti', 'resource', 'scope', 'sub'].sort()
    );
    expect(claims['iss']).toBe(AS_ISSUER);
    expect(claims['sub']).toBe('user-uuid-1');
    expect(claims['aud']).toBe('https://auth.chat.example');
    expect(claims['resource']).toBe('https://mcp.chat.example/');
    expect(claims['client_id']).toBe(CLIENT_ID);
    expect(claims['scope']).toBe('chat.read chat.history');
    expect(minted.expiresIn).toBe(300);
    expect(minted.jti).toBe(claims['jti']);
  });

  it('omits `scope` entirely when nothing was granted', async () => {
    const { fastify } = fastifyStub();

    const minted = await mintIdJag(fastify, {
      subject: 'user-uuid-1',
      audience: 'https://auth.chat.example',
      resource: 'https://mcp.chat.example/',
      clientId: CLIENT_ID,
    });

    expect(decodeJwt(minted.assertion)).not.toHaveProperty('scope');
  });

  it('releases NO identity claims into the foreign trust domain', async () => {
    const { fastify } = fastifyStub();

    const minted = await mintIdJag(fastify, {
      subject: 'user-uuid-1',
      audience: 'https://auth.chat.example',
      resource: 'https://mcp.chat.example/',
      clientId: CLIENT_ID,
    });

    const claims = decodeJwt(minted.assertion);
    expect(claims).not.toHaveProperty('email');
    expect(claims).not.toHaveProperty('email_verified');
    expect(claims).not.toHaveProperty('name');
    expect(claims).not.toHaveProperty('act');
  });

  it('honours ID_JAG_ISSUED_LIFETIME', async () => {
    ENV.ID_JAG_ISSUED_LIFETIME = 60;
    const { fastify } = fastifyStub();

    const minted = await mintIdJag(fastify, {
      subject: 'user-uuid-1',
      audience: 'https://auth.chat.example',
      resource: 'https://mcp.chat.example/',
      clientId: CLIENT_ID,
    });

    const claims = decodeJwt(minted.assertion);
    expect(minted.expiresIn).toBe(60);
    expect((claims.exp as number) - (claims.iat as number)).toBe(60);
  });

  it('canonicalises the `iss` it stamps (trailing slash stripped)', async () => {
    const { fastify } = fastifyStub();
    fastify.jwtUtils.getIssuer = () => `${AS_ISSUER}/`;

    const minted = await mintIdJag(fastify, {
      subject: 'user-uuid-1',
      audience: 'https://auth.chat.example',
      resource: 'https://mcp.chat.example/',
      clientId: CLIENT_ID,
    });

    expect(decodeJwt(minted.assertion).iss).toBe(AS_ISSUER);
  });
});

describe('idJagCredentialProviderType', () => {
  it('namespaces the subject by issuer so two IdPs cannot collide', () => {
    expect(idJagCredentialProviderType(IDP_ISSUER)).toBe(`oidc_${IDP_ISSUER}`);
    expect(idJagCredentialProviderType('https://other.example.com')).not.toBe(
      idJagCredentialProviderType(IDP_ISSUER)
    );
  });
});
