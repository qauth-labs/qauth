import { generateKeyPairSync } from 'node:crypto';

import { type ActClaim, jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { importPKCS8, SignJWT } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The error handler reads the validated env; stub it so no env parse runs.
vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import { API_FAMILIES, API_FAMILY_AUDIENCES, type ApiFamily } from '../api-conventions/families';
import errorHandler from '../plugins/error-handler';
import { type IssuerResolver, requireFamilyToken } from './family-token';

/**
 * The API family guards (#509, ADR-019 Decision 7), against the real JWT
 * plugin and the real error handler. Each family has a route under its prefix;
 * a token is minted by the plugin itself unless a test needs claims the server
 * never mints, which are signed with the same key by hand.
 */

const ISSUER = 'https://auth.test.example.com';
const OTHER_ISSUER = 'https://other.test.example.com';
const USER_ID = '11111111-1111-4111-8111-111111111111';
const REVOKED_JTI = 'revoked-jti';

let app: FastifyInstance;
let privateKeyPem: string;
let publicKeyPem: string;

/** The path of the probe route each family serves. */
function probePath(family: ApiFamily, suffix = 'probe'): string {
  return `/${family}/v1-rc.0/${suffix}`;
}

beforeEach(async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  app = Fastify({ logger: false });
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
    app.get(probePath(family), { preHandler: requireFamilyToken(family) }, reply);
    app.get(
      probePath(family, 'scoped'),
      { preHandler: requireFamilyToken(family, { requiredScopes: ['probe:read', 'probe:write'] }) },
      reply
    );
  }
  await app.ready();
});

afterEach(async () => {
  await app.close();
});

/** A token the server mints: `typ: at+jwt`, its issuer, an expiry and a `jti`. */
function mint(claims: { aud?: string | string[]; act?: ActClaim; scope?: string; sub?: string }) {
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

/** The claims of a well-formed family token, to vary one at a time. */
function familyClaims(family: ApiFamily): Record<string, unknown> {
  return {
    iss: ISSUER,
    aud: API_FAMILY_AUDIENCES[family],
    exp: Math.floor(Date.now() / 1000) + 600,
    jti: `jti-${family}`,
  };
}

function call(path: string, token: string, scheme = 'Bearer') {
  return app.inject({ method: 'GET', url: path, headers: { authorization: `${scheme} ${token}` } });
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
      expect(response.json()).toMatchObject({ code: 'jwt_invalid' });
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
    const missing = await app.inject({ method: 'GET', url: probePath('developer') });
    expect(missing.statusCode).toBe(401);
    expect(missing.headers['www-authenticate']).toMatch(/^Bearer realm="OAuth"/);

    const malformed = await call(probePath('developer'), 'not-a-jwt');
    expect(malformed.statusCode).toBe(401);
    expect(malformed.headers['content-type']).toMatch(/^application\/problem\+json/);
    expect(malformed.headers['www-authenticate']).toContain('error="invalid_token"');
  });

  describe('the issuer rule', () => {
    it('accepts only the deployment issuer by default', async () => {
      const response = await call(
        probePath('admin'),
        await signRaw({ typ: 'at+jwt' }, { ...familyClaims('admin'), iss: OTHER_ISSUER })
      );
      expect(response.statusCode).toBe(401);
    });

    it('is a hook: a family may accept another issuer, and refuse its own', async () => {
      const seen: string[] = [];
      const otherOnly: IssuerResolver = async (issuer, request) => {
        seen.push(`${issuer} ${request.url}`);
        return issuer === OTHER_ISSUER;
      };
      const local = Fastify({ logger: false });
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
        { preHandler: requireFamilyToken('admin', { issuerResolver: otherOnly }) },
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

    it('answers 403 insufficient_scope, naming the scopes, when one is missing', async () => {
      for (const scope of [undefined, 'probe:read', 'probe:readwrite']) {
        const token = await mint({ aud: API_FAMILY_AUDIENCES.admin, ...(scope ? { scope } : {}) });
        const response = await call(probePath('admin', 'scoped'), token);
        expect(response.statusCode).toBe(403);
        expect(response.json()).toMatchObject({ code: 'insufficient_scope' });
        expect(response.headers['www-authenticate']).toBe(
          'Bearer realm="OAuth", error="insufficient_scope", scope="probe:read probe:write"'
        );
      }
    });

    it('checks the audience before the scopes', async () => {
      const token = await mint({ aud: API_FAMILY_AUDIENCES.developer });
      expect((await call(probePath('admin', 'scoped'), token)).statusCode).toBe(401);
    });
  });
});
