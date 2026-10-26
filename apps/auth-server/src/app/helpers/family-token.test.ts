import { generateKeyPairSync } from 'node:crypto';

import { type ActClaim, jwtPlugin, type JwtPluginOptions } from '@qauth-labs/fastify-plugin-jwt';
import {
  createTestSigner,
  type TestSigner,
} from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { decodeJwt, decodeProtectedHeader, importPKCS8, SignJWT } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The error handler reads the validated env; stub it so no env parse runs.
vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

// The real helper, watched: the default issuer rule must go through it.
vi.mock('./realm-url', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./realm-url')>();
  return { ...actual, realmIssuer: vi.fn(actual.realmIssuer) };
});

import { API_FAMILIES, API_FAMILY_AUDIENCES, type ApiFamily } from '../api-conventions/families';
import errorHandler from '../plugins/error-handler';
import { type IssuerResolver, requireFamilyToken } from './family-token';
import { realmIssuer, tokenRealm } from './realm-url';
import { requestRealm } from './request-realm';

/**
 * The API family guards (#509, ADR-019 Decision 7), against the real JWT
 * plugin over the real in-memory signer, and the real error handler. Each
 * family has a route under its prefix. Each realm has keys of its own (#491):
 * a token is minted by the plugin for its realm unless a test needs claims the
 * server never mints, which are signed by hand with that realm's key.
 */

const ISSUER = 'https://auth.test.example.com';
const OTHER_ISSUER = 'https://other.test.example.com';
const USER_ID = '11111111-1111-4111-8111-111111111111';
const DISABLED_USER_ID = '22222222-2222-4222-8222-222222222222';
const USER_OF_B_ID = '33333333-3333-4333-8333-333333333333';
const UNKNOWN_USER_ID = '44444444-4444-4444-8444-444444444444';
const REVOKED_JTI = 'revoked-jti';

/**
 * Two realms, told apart by the host, as the realm resolver tells them
 * (ADR-019 Decision 1). A family audience reads the same in both. Each has its
 * own issuer and its own keys (#491): the signer signs a realm's tokens with
 * its key and gives them its issuer, and a request verifies a token only with
 * the keys of its realm.
 */
const HOST_B = 'b.test.example.com';
const ISSUER_B = `https://${HOST_B}`;
const REALM_A = { id: 'aaaaaaaa-0000-4000-8000-00000000000a', name: 'a', issuer: ISSUER };
const REALM_B = { id: 'bbbbbbbb-0000-4000-8000-00000000000b', name: 'b', issuer: ISSUER_B };
type TestRealm = typeof REALM_A;

const USERS = new Map([
  [USER_ID, { id: USER_ID, enabled: true, realmId: REALM_A.id }],
  [DISABLED_USER_ID, { id: DISABLED_USER_ID, enabled: false, realmId: REALM_A.id }],
  [USER_OF_B_ID, { id: USER_OF_B_ID, enabled: true, realmId: REALM_B.id }],
]);

/**
 * Clients per realm. `twin` is the same `client_id` in both realms: enabled
 * in A, disabled in B. `solo` exists in A only, `held` is suspended.
 */
const CLIENTS = new Map([
  [`${REALM_A.id}/twin`, { clientId: 'twin', enabled: true, suspended: false }],
  [`${REALM_B.id}/twin`, { clientId: 'twin', enabled: false, suspended: false }],
  [`${REALM_A.id}/solo`, { clientId: 'solo', enabled: true, suspended: false }],
  [`${REALM_A.id}/held`, { clientId: 'held', enabled: true, suspended: true }],
]);

const findUserById = vi.fn(async (id: string) => USERS.get(id));
const findClientByClientId = vi.fn(async (realmId: string, clientId: string) =>
  CLIENTS.get(`${realmId}/${clientId}`)
);

/** The refusals of a token another realm's key signed, and of one whose `iss` is not accepted. */
const NO_REALM_KEY = 'Invalid JWT token: no key of this realm verifies it';
const ISSUER_NOT_ACCEPTED = 'Access token issuer is not accepted here';

let app: FastifyInstance;
let signer: TestSigner;
/** Each realm's EdDSA `token_signing` key, PKCS#8 PEM, by realm id: to sign tokens by hand. */
let realmKeys: Map<string, string>;

/** The path of the probe route each family serves. */
function probePath(family: ApiFamily, suffix = 'probe'): string {
  return `/${family}/v1-rc.0/${suffix}`;
}

/** The realm of each request, by host, and the repositories the guard reads. */
function withRealms(instance: FastifyInstance): void {
  instance.decorate('repositories', {
    users: { findById: findUserById },
    oauthClients: { findByClientId: findClientByClientId },
  } as never);
  instance.decorateRequest('realm', null);
  instance.addHook('onRequest', async (request) => {
    request.realm = (request.headers.host === HOST_B ? REALM_B : REALM_A) as never;
  });
}

/** The JWT plugin over the test signer, wired to the request realm as app.ts wires it. */
async function registerJwt(
  instance: FastifyInstance,
  options: Pick<JwtPluginOptions, 'isTokenRevoked'> = {}
): Promise<void> {
  await instance.register(jwtPlugin, {
    signer: signer.signer,
    requestRealm: (request) => tokenRealm(requestRealm(request)),
    accessTokenLifespan: 900,
    refreshTokenLifespan: 86400,
    ...options,
  });
}

/** An app with realms, the JWT plugin, the error handler and one route. */
async function localApp(
  path: string,
  preHandler: (request: FastifyRequest, reply: FastifyReply) => Promise<void>
): Promise<FastifyInstance> {
  const local = Fastify({ logger: false });
  withRealms(local);
  await registerJwt(local);
  await local.register(errorHandler);
  local.get(path, { preHandler }, async () => ({ ok: true }));
  return local;
}

beforeEach(async () => {
  findUserById.mockClear();
  findClientByClientId.mockClear();
  vi.mocked(realmIssuer).mockClear();
  signer = createTestSigner();
  realmKeys = new Map();
  for (const realm of [REALM_A, REALM_B]) {
    const pem = generateKeyPairSync('ed25519')
      .privateKey.export({ type: 'pkcs8', format: 'pem' })
      .toString();
    realmKeys.set(realm.id, pem);
    await signer.addRealm({ id: realm.id, issuer: realm.issuer, ed25519PrivateKey: pem });
  }
  app = Fastify({ logger: false });
  withRealms(app);
  await registerJwt(app, { isTokenRevoked: (jti) => jti === REVOKED_JTI });
  await app.register(errorHandler);

  const reply = async (request: FastifyRequest) => ({
    sub: request.jwtPayload?.sub,
    aud: request.jwtPayload?.aud,
  });
  for (const family of API_FAMILIES) {
    app.get(
      probePath(family),
      { preHandler: requireFamilyToken(family, { subjects: ['user', 'client'] }) },
      reply
    );
    app.get(
      probePath(family, 'scoped'),
      {
        preHandler: requireFamilyToken(family, {
          subjects: ['user', 'client'],
          requiredScopes: ['probe:read', 'probe:write'],
        }),
      },
      reply
    );
    app.get(
      probePath(family, 'users'),
      { preHandler: requireFamilyToken(family, { subjects: ['user'] }) },
      reply
    );
    app.get(
      probePath(family, 'clients'),
      { preHandler: requireFamilyToken(family, { subjects: ['client'] }) },
      reply
    );
  }
  await app.ready();
});

afterEach(async () => {
  await app.close();
});

/**
 * A token the server mints for `realm` (realm A by default): `typ: at+jwt`,
 * the realm's issuer, its key's `kid`, an expiry and a `jti`.
 */
function mint(
  claims: {
    aud?: string | string[];
    act?: ActClaim;
    scope?: string;
    sub?: string;
    clientId?: string;
  },
  realm: TestRealm = REALM_A
) {
  return app.jwtUtils.signAccessToken(realm, {
    sub: claims.sub ?? USER_ID,
    clientId: 'client-1',
    ...claims,
  });
}

/** The `kid` of the realm's EdDSA `token_signing` key, as the signer lists it. */
async function realmKid(realm: TestRealm): Promise<string> {
  const keys = await signer.signer.getVerificationKeys('local', realm.id, 'token_signing');
  const key = keys.find((candidate) => candidate.algorithm === 'EdDSA');
  if (key === undefined) throw new Error(`realm ${realm.name} has no EdDSA key`);
  return key.kid;
}

/**
 * A token with exactly the claims given, signed by hand with the key of
 * `realm` (realm A by default). The header names that key's `kid`, as the
 * signer's does, unless `header` says otherwise; `kid: undefined` leaves it
 * out, as a token issued before #491 did.
 */
async function signRaw(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  realm: TestRealm = REALM_A
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const pem = realmKeys.get(realm.id);
  if (pem === undefined) throw new Error(`no key for realm ${realm.name}`);
  const protectedHeader: { alg: string; [name: string]: unknown } = {
    alg: 'EdDSA',
    kid: await realmKid(realm),
    ...header,
  };
  if (protectedHeader['kid'] === undefined) delete protectedHeader['kid'];
  return new SignJWT({ sub: USER_ID, client_id: 'client-1', iat: now, ...claims })
    .setProtectedHeader(protectedHeader)
    .sign(await importPKCS8(pem, 'EdDSA'));
}

/** The claims of a well-formed family token, to vary one at a time. */
function familyClaims(family: ApiFamily): Record<string, unknown> {
  return {
    iss: ISSUER,
    aud: API_FAMILY_AUDIENCES[family],
    exp: Math.floor(Date.now() / 1000) + 600,
    jti: `jti-${family}`,
  };
}

function call(path: string, token: string, scheme = 'Bearer', host?: string) {
  return app.inject({
    method: 'GET',
    url: path,
    headers: { authorization: `${scheme} ${token}`, ...(host === undefined ? {} : { host }) },
  });
}

describe('requireFamilyToken (#509)', () => {
  it.each(API_FAMILIES)(
    'admits a token for the %s family and puts its claims on the request',
    async (family) => {
      for (const aud of [API_FAMILY_AUDIENCES[family], [API_FAMILY_AUDIENCES[family]]]) {
        const response = await call(probePath(family), await mint({ aud }));
        expect(response.statusCode).toBe(200);
        expect(response.json()).toEqual({ sub: USER_ID, aud });
      }
    }
  );

  it.each(API_FAMILIES)('refuses another family’s token on the %s family', async (family) => {
    for (const other of API_FAMILIES.filter((f) => f !== family)) {
      const response = await call(
        probePath(family),
        await mint({ aud: API_FAMILY_AUDIENCES[other] })
      );
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ code: 'invalid_access_token' });
    }
  });

  describe('a token with two audiences', () => {
    it.each(API_FAMILIES)(
      'is refused by the %s guard, even when one is its own',
      async (family) => {
        const own = API_FAMILY_AUDIENCES[family];
        for (const aud of [
          [own, 'https://mcp.example.com'],
          [own, API_FAMILY_AUDIENCES[API_FAMILIES.find((f) => f !== family) ?? 'admin']],
          [own, own],
        ]) {
          const response = await call(probePath(family), await mint({ aud }));
          expect(response.statusCode).toBe(401);
          expect(response.headers['www-authenticate']).toContain('error="invalid_token"');
        }
      }
    );
  });

  describe('a token without typ: at+jwt', () => {
    it.each(API_FAMILIES)(
      'is refused by the %s guard though the rollout switch is off',
      async (family) => {
        const claims = familyClaims(family);
        // The same claims with the header the server stamps are admitted, so
        // only the header can be what refuses the others.
        expect(
          (await call(probePath(family), await signRaw({ typ: 'at+jwt' }, claims))).statusCode
        ).toBe(200);

        for (const header of [{}, { typ: 'JWT' }]) {
          const response = await call(probePath(family), await signRaw(header, claims));
          expect(response.statusCode).toBe(401);
          expect(response.headers['www-authenticate']).toContain('error="invalid_token"');
        }
      }
    );
  });

  describe('a delegated token (RFC 8693 act claim)', () => {
    const act: ActClaim = { sub: 'agent-client' };

    it('is refused on the developer family', async () => {
      const response = await call(
        probePath('developer'),
        await mint({ aud: API_FAMILY_AUDIENCES.developer, act })
      );
      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toContain('error="invalid_token"');
    });

    it.each(['admin', 'account'] as const)(
      'is left to the %s routes, which decide per operation',
      async (family) => {
        const response = await call(
          probePath(family),
          await mint({ aud: API_FAMILY_AUDIENCES[family], act })
        );
        expect(response.statusCode).toBe(200);
      }
    );
  });

  it.each(API_FAMILIES)(
    'refuses a %s token with no subject, expiry or token id',
    async (family) => {
      const claims = familyClaims(family);
      for (const changed of [
        { ...claims, sub: '' },
        { ...claims, exp: undefined },
        { ...claims, jti: undefined },
        // A `jti` must be a string with something in it (#509).
        { ...claims, jti: '' },
        { ...claims, jti: 42 },
      ]) {
        const response = await call(probePath(family), await signRaw({ typ: 'at+jwt' }, changed));
        expect(response.statusCode).toBe(401);
      }
    }
  );

  it('refuses a token with no audience, an expired one and a revoked one', async () => {
    const claims = familyClaims('account');
    for (const token of [
      await mint({}),
      await signRaw({ typ: 'at+jwt' }, { ...claims, aud: undefined }),
      await signRaw({ typ: 'at+jwt' }, { ...claims, exp: Math.floor(Date.now() / 1000) - 60 }),
      await signRaw({ typ: 'at+jwt' }, { ...claims, jti: REVOKED_JTI }),
    ]) {
      const response = await call(probePath('account'), token);
      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toContain('error="invalid_token"');
    }
  });

  it('answers a missing or malformed credential with the RFC 6750 challenge', async () => {
    // No credentials: `unauthorized`, and a challenge that names no error
    // (RFC 6750 §3.1), as on every bearer-protected route.
    for (const headers of [{}, { authorization: 'Basic dXNlcjpwYXNz' }, { authorization: '' }]) {
      const missing = await app.inject({ method: 'GET', url: probePath('developer'), headers });
      expect(missing.statusCode).toBe(401);
      expect(missing.headers['content-type']).toMatch(/^application\/problem\+json/);
      expect(missing.json()).toMatchObject({ code: 'unauthorized' });
      expect(missing.headers['www-authenticate']).toBe('Bearer realm="OAuth"');
    }

    const malformed = await call(probePath('developer'), 'not-a-jwt');
    expect(malformed.statusCode).toBe(401);
    expect(malformed.headers['content-type']).toMatch(/^application\/problem\+json/);
    expect(malformed.json()).toMatchObject({ code: 'invalid_access_token' });
    expect(malformed.headers['www-authenticate']).toContain('error="invalid_token"');
  });

  describe('the issuer rule', () => {
    it('accepts only the token issuer of the request realm by default', async () => {
      // Signed with the request realm's own key, so only its issuer refuses it.
      const response = await call(
        probePath('admin'),
        await signRaw({ typ: 'at+jwt' }, { ...familyClaims('admin'), iss: OTHER_ISSUER })
      );
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        code: 'invalid_access_token',
        detail: ISSUER_NOT_ACCEPTED,
      });
    });

    it("admits at each realm only its own tokens, which name that realm's issuer (ADR-019 Decision 1, #490, #491)", async () => {
      const account = API_FAMILY_AUDIENCES.account;
      // Each realm's own token: signed with its key, naming its issuer.
      const minted = await mint({ aud: account });
      const ofB = await mint({ aud: account, sub: USER_OF_B_ID }, REALM_B);
      expect(decodeJwt(minted).iss).toBe(ISSUER);
      expect(decodeJwt(ofB).iss).toBe(ISSUER_B);

      expect((await call(probePath('account'), minted)).statusCode).toBe(200);
      expect((await call(probePath('account'), ofB, 'Bearer', HOST_B)).statusCode).toBe(200);

      // At the other realm, each is refused on its key, before its subject is
      // looked up: no key of that realm verifies it.
      findUserById.mockClear();
      for (const [token, host] of [
        [minted, HOST_B],
        [ofB, undefined],
      ] as const) {
        const response = await call(probePath('account'), token, 'Bearer', host);
        expect(response.statusCode).toBe(401);
        expect(response.json()).toMatchObject({
          code: 'invalid_access_token',
          detail: NO_REALM_KEY,
        });
      }

      // Signed with the request realm's own key but naming the other realm's
      // issuer: the issuer rule refuses it, again before the subject.
      const namesA = await signRaw(
        { typ: 'at+jwt' },
        { ...familyClaims('account'), sub: USER_OF_B_ID },
        REALM_B
      );
      const namesB = await signRaw(
        { typ: 'at+jwt' },
        { ...familyClaims('account'), iss: ISSUER_B }
      );
      for (const [token, host] of [
        [namesA, HOST_B],
        [namesB, undefined],
      ] as const) {
        const response = await call(probePath('account'), token, 'Bearer', host);
        expect(response.statusCode).toBe(401);
        expect(response.json()).toMatchObject({
          code: 'invalid_access_token',
          detail: ISSUER_NOT_ACCEPTED,
        });
      }
      expect(findUserById).not.toHaveBeenCalled();
    });

    it("pins the request realm's issuer through realmIssuer", async () => {
      const account = API_FAMILY_AUDIENCES.account;
      const token = await mint({ aud: account });
      expect((await call(probePath('account'), token)).statusCode).toBe(200);
      expect(realmIssuer).toHaveBeenCalledWith(REALM_A);

      vi.mocked(realmIssuer).mockClear();
      const ofB = await mint({ aud: account, sub: USER_OF_B_ID }, REALM_B);
      expect((await call(probePath('account'), ofB, 'Bearer', HOST_B)).statusCode).toBe(200);
      expect(realmIssuer).toHaveBeenCalledWith(REALM_B);

      // The rule compares with what the helper answers: when it names another
      // issuer, the same genuine token is refused on its issuer.
      vi.mocked(realmIssuer).mockReturnValueOnce(OTHER_ISSUER);
      const refused = await call(probePath('account'), token);
      expect(refused.statusCode).toBe(401);
      expect(refused.json()).toMatchObject({ detail: ISSUER_NOT_ACCEPTED });
    });

    it("admits the realm's tokens, which name the realm row's issuer, not a JWT_ISSUER's trailing slash (#491)", async () => {
      // The signer gives a realm's tokens the issuer of its row, the issuer
      // discovery publishes, never `JWT_ISSUER` as written: the row drops the
      // trailing slash `JWT_ISSUER` may carry, and so do the tokens.
      const token = await mint({ aud: API_FAMILY_AUDIENCES.account });
      expect(decodeJwt(token).iss).toBe(REALM_A.issuer);
      expect((await call(probePath('account'), token)).statusCode).toBe(200);

      // A token issued before the upgrade: no `kid`, signed with the key
      // `JWT_PRIVATE_KEY` held, which the realm imported. It still verifies,
      // and is admitted when it names the realm's issuer. One that names
      // `JWT_ISSUER` with its trailing slash is refused until it expires, as
      // the changelog of #491 says.
      const legacy = (iss: string) =>
        signRaw({ typ: 'at+jwt', kid: undefined }, { ...familyClaims('account'), iss });
      const legacyToken = await legacy(ISSUER);
      expect(decodeProtectedHeader(legacyToken)).not.toHaveProperty('kid');
      expect((await call(probePath('account'), legacyToken)).statusCode).toBe(200);
      const withSlash = await call(probePath('account'), await legacy(`${ISSUER}/`));
      expect(withSlash.statusCode).toBe(401);
      expect(withSlash.json()).toMatchObject({ detail: ISSUER_NOT_ACCEPTED });
    });

    it('is a hook: a family may accept another issuer, and refuse its own', async () => {
      const seen: string[] = [];
      const otherOnly: IssuerResolver = async (issuer, request) => {
        seen.push(`${issuer} ${request.url}`);
        return issuer === OTHER_ISSUER;
      };
      const local = await localApp(
        '/admin/v1-rc.0/probe',
        requireFamilyToken('admin', { issuerResolver: otherOnly, subjects: ['user'] })
      );
      try {
        const claims = familyClaims('admin');
        const fromOther = await signRaw({ typ: 'at+jwt' }, { ...claims, iss: OTHER_ISSUER });
        const fromOwn = await signRaw({ typ: 'at+jwt' }, claims);
        const send = (token: string) =>
          local.inject({
            method: 'GET',
            url: '/admin/v1-rc.0/probe',
            headers: { authorization: `Bearer ${token}` },
          });
        expect((await send(fromOther)).statusCode).toBe(200);
        expect((await send(fromOwn)).statusCode).toBe(401);
        expect(seen).toEqual([
          `${OTHER_ISSUER} /admin/v1-rc.0/probe`,
          `${ISSUER} /admin/v1-rc.0/probe`,
        ]);
      } finally {
        await local.close();
      }
    });

    it("decides only the issuer: a token another realm's key signed is refused before it (#491)", async () => {
      const seen: string[] = [];
      const anyIssuer: IssuerResolver = (issuer) => {
        seen.push(issuer);
        return true;
      };
      const local = await localApp(
        '/account/v1-rc.0/probe',
        requireFamilyToken('account', { issuerResolver: anyIssuer, subjects: ['user'] })
      );
      try {
        const send = (token: string) =>
          local.inject({
            method: 'GET',
            url: '/account/v1-rc.0/probe',
            headers: { authorization: `Bearer ${token}` },
          });
        // Realm B's genuine token, for realm A's user, at realm A: the hook
        // would accept its issuer, but no key of realm A verifies it.
        const ofB = await local.jwtUtils.signAccessToken(REALM_B, {
          sub: USER_ID,
          clientId: 'client-1',
          aud: API_FAMILY_AUDIENCES.account,
        });
        const refused = await send(ofB);
        expect(refused.statusCode).toBe(401);
        expect(refused.json()).toMatchObject({ detail: NO_REALM_KEY });
        expect(seen).toEqual([]);

        // The same claims signed with realm A's key: the hook admits B's issuer.
        const namingB = await signRaw(
          { typ: 'at+jwt' },
          { ...familyClaims('account'), iss: ISSUER_B }
        );
        expect((await send(namingB)).statusCode).toBe(200);
        expect(seen).toEqual([ISSUER_B]);
      } finally {
        await local.close();
      }
    });
  });

  describe('required scopes', () => {
    it('admits a token that carries every one', async () => {
      const token = await mint({
        aud: API_FAMILY_AUDIENCES.account,
        scope: 'probe:write openid probe:read',
      });
      expect((await call(probePath('account', 'scoped'), token)).statusCode).toBe(200);
    });

    it('answers 403 forbidden with an insufficient_scope challenge naming the scopes', async () => {
      for (const scope of [undefined, 'probe:read', 'probe:readwrite']) {
        const token = await mint({ aud: API_FAMILY_AUDIENCES.admin, ...(scope ? { scope } : {}) });
        const response = await call(probePath('admin', 'scoped'), token);
        expect(response.statusCode).toBe(403);
        // One answer for a missing scope, the one every route gives (#509).
        expect(response.json()).toMatchObject({ code: 'forbidden' });
        expect(response.headers['www-authenticate']).toBe(
          'Bearer realm="OAuth", error="insufficient_scope", scope="probe:read probe:write"'
        );
      }
    });

    it('checks the audience before the scopes', async () => {
      const token = await mint({ aud: API_FAMILY_AUDIENCES.developer });
      expect((await call(probePath('admin', 'scoped'), token)).statusCode).toBe(401);
    });

    it("checks the subject's realm before the scopes", async () => {
      const token = await mint({ aud: API_FAMILY_AUDIENCES.admin, scope: 'probe:read' });
      expect((await call(probePath('admin', 'scoped'), token)).statusCode).toBe(403);
      // Realm A's user, in a token realm B minted: its key and issuer pass at
      // realm B, so the subject is what refuses it, with 401 and not 403.
      const atB = await mint({ aud: API_FAMILY_AUDIENCES.admin, scope: 'probe:read' }, REALM_B);
      const response = await call(probePath('admin', 'scoped'), atB, 'Bearer', HOST_B);
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        detail: 'Access token subject is not an active user',
      });
    });
  });

  // ADR-019 Decision 1: a token from another realm is refused. A family
  // audience reads the same in every realm, so the guard also resolves the
  // subject in the request's realm. The tokens sent to realm B are realm B's
  // own, signed with its key and naming its issuer, so they reach the subject
  // check.
  describe("the subject, in the request's realm", () => {
    const account = API_FAMILY_AUDIENCES.account;

    it("admits a realm-A user's token at realm A and refuses it at realm B", async () => {
      const token = await mint({ aud: account });

      expect((await call(probePath('account'), token)).statusCode).toBe(200);

      const atB = await call(
        probePath('account'),
        await mint({ aud: account }, REALM_B),
        'Bearer',
        HOST_B
      );
      expect(atB.statusCode).toBe(401);
      expect(atB.json()).toMatchObject({
        code: 'invalid_access_token',
        detail: 'Access token subject is not an active user',
      });
      expect(atB.headers['www-authenticate']).toContain('error="invalid_token"');
    });

    it("admits a realm-B user's token at realm B only", async () => {
      const token = await mint({ aud: account, sub: USER_OF_B_ID }, REALM_B);
      expect((await call(probePath('account'), token, 'Bearer', HOST_B)).statusCode).toBe(200);
      // At realm A, neither its key, its issuer nor its subject is realm A's.
      expect((await call(probePath('account'), token)).statusCode).toBe(401);
      const minted = await mint({ aud: account, sub: USER_OF_B_ID });
      expect((await call(probePath('account'), minted)).statusCode).toBe(401);
    });

    it('refuses a disabled user, an unknown one and a subject that is no user id', async () => {
      for (const sub of [DISABLED_USER_ID, UNKNOWN_USER_ID, 'not-a-uuid']) {
        const response = await call(probePath('account'), await mint({ aud: account, sub }));
        expect(response.statusCode, sub).toBe(401);
        expect(response.json()).toMatchObject({ code: 'invalid_access_token' });
      }
      // A subject that is no UUID never reaches the users table.
      expect(findUserById).not.toHaveBeenCalledWith('not-a-uuid');
    });

    it('resolves a client_credentials token as the client of the request realm', async () => {
      // `twin` is enabled in realm A and disabled in realm B: each realm's
      // token for it is admitted at A and refused at B.
      const twin = await mint({ aud: account, sub: 'twin', clientId: 'twin' });
      expect((await call(probePath('account'), twin)).statusCode).toBe(200);
      const twinOfB = await mint({ aud: account, sub: 'twin', clientId: 'twin' }, REALM_B);
      const atB = await call(probePath('account'), twinOfB, 'Bearer', HOST_B);
      expect(atB.statusCode).toBe(401);
      expect(atB.json()).toMatchObject({ code: 'invalid_access_token' });
      expect(findClientByClientId).toHaveBeenCalledWith(REALM_B.id, 'twin');

      // `solo` names no client of realm B; `held` is suspended.
      const solo = await mint({ aud: account, sub: 'solo', clientId: 'solo' }, REALM_B);
      expect((await call(probePath('account'), solo, 'Bearer', HOST_B)).statusCode).toBe(401);
      expect(findClientByClientId).toHaveBeenCalledWith(REALM_B.id, 'solo');
      const held = await mint({ aud: account, sub: 'held', clientId: 'held' });
      expect((await call(probePath('account'), held)).statusCode).toBe(401);
    });

    it('refuses a subject of a kind the route does not admit', async () => {
      const user = await mint({ aud: account });
      const client = await mint({ aud: account, sub: 'twin', clientId: 'twin' });

      expect((await call(probePath('account', 'users'), user)).statusCode).toBe(200);
      expect((await call(probePath('account', 'users'), client)).statusCode).toBe(401);
      expect((await call(probePath('account', 'clients'), client)).statusCode).toBe(200);
      expect((await call(probePath('account', 'clients'), user)).statusCode).toBe(401);
    });

    it('is required: a family route admits at least one kind of subject', () => {
      expect(() => requireFamilyToken('account', { subjects: [] })).toThrow(
        /at least one kind of subject/
      );
    });
  });
});
