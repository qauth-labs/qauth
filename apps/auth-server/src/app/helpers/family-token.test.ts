import { generateKeyPairSync } from 'node:crypto';

import { type ActClaim, jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { importPKCS8, SignJWT } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The error handler reads the validated env; stub it so no env parse runs.
vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

// The real helper, watched: the default issuer rule must go through it.
vi.mock('./realm-url', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./realm-url')>();
  return { ...actual, realmTokenIssuer: vi.fn(actual.realmTokenIssuer) };
});

import { API_FAMILIES, API_FAMILY_AUDIENCES, type ApiFamily } from '../api-conventions/families';
import errorHandler from '../plugins/error-handler';
import { type IssuerResolver, requireFamilyToken } from './family-token';
import { realmTokenIssuer } from './realm-url';

/**
 * The API family guards (#509, ADR-019 Decision 7), against the real JWT
 * plugin and the real error handler. Each family has a route under its prefix;
 * a token is minted by the plugin itself unless a test needs claims the server
 * never mints, which are signed with the same key by hand.
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
 * (ADR-019 Decision 1). A family audience reads the same in both. Realm A's
 * issuer is the JWT plugin's, `JWT_ISSUER`; realm B has its own, so it admits
 * only a token naming B's issuer, which the server does not mint before #491.
 */
const HOST_B = 'b.test.example.com';
const ISSUER_B = `https://${HOST_B}`;
const REALM_A = { id: 'aaaaaaaa-0000-4000-8000-00000000000a', name: 'a', issuer: ISSUER };
const REALM_B = { id: 'bbbbbbbb-0000-4000-8000-00000000000b', name: 'b', issuer: ISSUER_B };

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

/** Realm-scoped as the repository is (#489): a user of another realm is no row. */
const findUserById = vi.fn(async (realmId: string, id: string) => {
  const user = USERS.get(id);
  return user?.realmId === realmId ? user : undefined;
});
const findClientByClientId = vi.fn(async (realmId: string, clientId: string) =>
  CLIENTS.get(`${realmId}/${clientId}`)
);

let app: FastifyInstance;
let privateKeyPem: string;
let publicKeyPem: string;

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

beforeEach(async () => {
  findUserById.mockClear();
  findClientByClientId.mockClear();
  vi.mocked(realmTokenIssuer).mockClear();
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  app = Fastify({ logger: false });
  withRealms(app);
  await app.register(jwtPlugin, {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
    issuer: ISSUER,
    accessTokenLifespan: 900,
    refreshTokenLifespan: 86400,
    isTokenRevoked: (jti) => jti === REVOKED_JTI,
  });
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

/** A token the server mints: `typ: at+jwt`, its issuer, an expiry and a `jti`. */
function mint(claims: {
  aud?: string | string[];
  act?: ActClaim;
  scope?: string;
  sub?: string;
  clientId?: string;
}) {
  return app.jwtUtils.signAccessToken({
    sub: claims.sub ?? USER_ID,
    clientId: 'client-1',
    ...claims,
  });
}

/** A token with exactly the header and claims given, signed with the server's key. */
async function signRaw(
  header: Record<string, unknown>,
  claims: Record<string, unknown>
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: USER_ID, client_id: 'client-1', iat: now, ...claims })
    .setProtectedHeader({ alg: 'EdDSA', ...header })
    .sign(await importPKCS8(privateKeyPem, 'EdDSA'));
}

/**
 * A well-formed `account` token naming realm B's issuer, as realm B's own
 * tokens will once each realm signs with its issuer (#491).
 */
function signForB(claims: Record<string, unknown> = {}): Promise<string> {
  return signRaw({ typ: 'at+jwt' }, { ...familyClaims('account'), iss: ISSUER_B, ...claims });
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

    // #510: an agent's exchanged token never stands for an admin's passkey
    // sign-in, nor manages a developer's clients.
    it.each(['developer', 'admin'] as const)('is refused on the %s family', async (family) => {
      const response = await call(
        probePath(family),
        await mint({ aud: API_FAMILY_AUDIENCES[family], act })
      );
      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toContain('error="invalid_token"');
    });

    it('is left to the account routes, which decide per operation', async () => {
      const response = await call(
        probePath('account'),
        await mint({ aud: API_FAMILY_AUDIENCES.account, act })
      );
      expect(response.statusCode).toBe(200);
    });
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
      const response = await call(
        probePath('admin'),
        await signRaw({ typ: 'at+jwt' }, { ...familyClaims('admin'), iss: OTHER_ISSUER })
      );
      expect(response.statusCode).toBe(401);
    });

    it("admits at each realm only a token naming that realm's issuer (ADR-019 Decision 1, #490)", async () => {
      const account = API_FAMILY_AUDIENCES.account;
      // What the server mints today: `iss` is JWT_ISSUER, realm A's issuer.
      const minted = await mint({ aud: account });
      // A token of realm B's user that names realm B's issuer.
      const ofB = await signForB({ sub: USER_OF_B_ID });

      expect((await call(probePath('account'), minted)).statusCode).toBe(200);
      expect((await call(probePath('account'), ofB, 'Bearer', HOST_B)).statusCode).toBe(200);

      // Each refused on its issuer, before its subject is looked up.
      findUserById.mockClear();
      const mintedAtB = await call(probePath('account'), minted, 'Bearer', HOST_B);
      expect(mintedAtB.statusCode).toBe(401);
      expect(mintedAtB.json()).toMatchObject({ code: 'invalid_access_token' });
      expect((await call(probePath('account'), ofB)).statusCode).toBe(401);
      expect(findUserById).not.toHaveBeenCalled();
    });

    it("pins the request realm's token issuer through realmTokenIssuer", async () => {
      const token = await mint({ aud: API_FAMILY_AUDIENCES.account });
      expect((await call(probePath('account'), token)).statusCode).toBe(200);
      expect(realmTokenIssuer).toHaveBeenCalledWith(app, REALM_A);
    });

    it('admits the tokens of a JWT_ISSUER with a trailing slash at its realm', async () => {
      // Tokens keep the slash; the realm row and discovery drop it.
      const local = Fastify({ logger: false });
      withRealms(local);
      await local.register(jwtPlugin, {
        privateKey: privateKeyPem,
        publicKey: publicKeyPem,
        issuer: `${ISSUER}/`,
        accessTokenLifespan: 900,
        refreshTokenLifespan: 86400,
      });
      await local.register(errorHandler);
      local.get(
        '/account/v1-rc.0/probe',
        { preHandler: requireFamilyToken('account', { subjects: ['user'] }) },
        async () => ({ ok: true })
      );
      try {
        const token = await local.jwtUtils.signAccessToken({
          sub: USER_ID,
          clientId: 'client-1',
          aud: API_FAMILY_AUDIENCES.account,
        });
        const response = await local.inject({
          method: 'GET',
          url: '/account/v1-rc.0/probe',
          headers: { authorization: `Bearer ${token}` },
        });
        expect(response.statusCode).toBe(200);
      } finally {
        await local.close();
      }
    });

    it('is a hook: a family may accept another issuer, and refuse its own', async () => {
      const seen: string[] = [];
      const otherOnly: IssuerResolver = async (issuer, request) => {
        seen.push(`${issuer} ${request.url}`);
        return issuer === OTHER_ISSUER;
      };
      const local = Fastify({ logger: false });
      withRealms(local);
      await local.register(jwtPlugin, {
        privateKey: privateKeyPem,
        publicKey: publicKeyPem,
        issuer: ISSUER,
        accessTokenLifespan: 900,
        refreshTokenLifespan: 86400,
      });
      await local.register(errorHandler);
      local.get(
        '/admin/v1-rc.0/probe',
        {
          preHandler: requireFamilyToken('admin', {
            issuerResolver: otherOnly,
            subjects: ['user'],
          }),
        },
        async () => ({ ok: true })
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
      // Realm A's user, in a token that names realm B's issuer.
      const atB = await signRaw(
        { typ: 'at+jwt' },
        { ...familyClaims('admin'), iss: ISSUER_B, scope: 'probe:read' }
      );
      expect((await call(probePath('admin', 'scoped'), atB, 'Bearer', HOST_B)).statusCode).toBe(
        401
      );
    });
  });

  // ADR-019 Decision 1: a token from another realm is refused. A family
  // audience reads the same in every realm, so the guard also resolves the
  // subject in the request's realm. The tokens sent to realm B name realm B's
  // issuer, so its issuer rule lets them through to the subject check.
  describe("the subject, in the request's realm", () => {
    const account = API_FAMILY_AUDIENCES.account;

    it("admits a realm-A user's token at realm A and refuses it at realm B", async () => {
      const token = await mint({ aud: account });

      expect((await call(probePath('account'), token)).statusCode).toBe(200);

      const atB = await call(probePath('account'), await signForB(), 'Bearer', HOST_B);
      expect(atB.statusCode).toBe(401);
      expect(atB.json()).toMatchObject({
        code: 'invalid_access_token',
        detail: 'Access token subject is not an active user',
      });
      expect(atB.headers['www-authenticate']).toContain('error="invalid_token"');
    });

    it("admits a realm-B user's token at realm B only", async () => {
      const token = await signForB({ sub: USER_OF_B_ID });
      expect((await call(probePath('account'), token, 'Bearer', HOST_B)).statusCode).toBe(200);
      // At realm A, neither its issuer nor its subject is realm A's.
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
      expect(findUserById).not.toHaveBeenCalledWith(expect.anything(), 'not-a-uuid');
    });

    it('resolves a client_credentials token as the client of the request realm', async () => {
      // `twin` is enabled in realm A and disabled in realm B: the same token is
      // admitted at A and refused at B.
      const twin = await mint({ aud: account, sub: 'twin', clientId: 'twin' });
      expect((await call(probePath('account'), twin)).statusCode).toBe(200);
      const twinOfB = await signForB({ sub: 'twin', client_id: 'twin' });
      const atB = await call(probePath('account'), twinOfB, 'Bearer', HOST_B);
      expect(atB.statusCode).toBe(401);
      expect(atB.json()).toMatchObject({ code: 'invalid_access_token' });
      expect(findClientByClientId).toHaveBeenCalledWith(REALM_B.id, 'twin');

      // `solo` names no client of realm B; `held` is suspended.
      const solo = await signForB({ sub: 'solo', client_id: 'solo' });
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
