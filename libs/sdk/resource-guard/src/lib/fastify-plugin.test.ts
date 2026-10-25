import Fastify, { type FastifyInstance } from 'fastify';
import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { ResourceGuardConfigError } from './errors';
import { resourceGuardPlugin } from './fastify-plugin';

const ISSUER = 'https://auth.example.com';
const RESOURCE = 'https://mcp.example.com';
const METADATA_URL = `${RESOURCE}/.well-known/oauth-protected-resource`;

let privateKey: CryptoKey;
let publicJwk: JWK;

function jwksFetch(jwks: { keys: JWK[] }) {
  return (async () =>
    ({
      ok: true,
      status: 200,
      json: async () => jwks,
      text: async () => JSON.stringify(jwks),
    }) as unknown) as never;
}

async function signToken(claims: Record<string, unknown>, audience: string | string[] = RESOURCE) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setExpirationTime('300s')
    .sign(privateKey);
}

async function buildApp(requiredScopes: string[] = []): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(resourceGuardPlugin, {
    resource: RESOURCE,
    authorizationServer: ISSUER,
    requiredScopes,
    fetch: jwksFetch({ keys: [publicJwk] }),
  });

  app.get('/data', { preHandler: app.requireBearer }, async (request) => ({
    ok: true,
    sub: request.tokenClaims?.sub,
  }));

  app.post('/admin', { preHandler: app.requireScopes('mcp:admin') }, async () => ({ ok: true }));

  await app.ready();
  return app;
}

beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { extractable: true });
  privateKey = kp.privateKey;
  publicJwk = await exportJWK(kp.publicKey);
  publicJwk.alg = 'EdDSA';
  publicJwk.kid = 'k1';
});

let app: FastifyInstance | undefined;
afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('resource-guard Fastify plugin — RFC 9728 metadata', () => {
  it('serves the Protected Resource Metadata document', async () => {
    app = await buildApp(['mcp:read']);
    const res = await app.inject({
      method: 'GET',
      url: '/.well-known/oauth-protected-resource',
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
    expect(res.headers['cache-control']).toContain('max-age');
    const body = res.json();
    expect(body.resource).toBe(RESOURCE);
    expect(body.authorization_servers).toEqual([ISSUER]);
    expect(body.scopes_supported).toEqual(['mcp:read']);
  });
});

describe('resource-guard Fastify plugin — 401 challenge', () => {
  it('returns 401 with a WWW-Authenticate pointing at resource_metadata when no token', async () => {
    app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/data' });
    expect(res.statusCode).toBe(401);
    const challenge = res.headers['www-authenticate'] as string;
    expect(challenge).toContain('Bearer');
    expect(challenge).toContain(
      'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"'
    );
    // Bare challenge: no error code when credentials are simply absent.
    expect(challenge).not.toContain('error=');
    // No required scopes configured for this route, so no `scope` at all —
    // never an empty `scope=""` (#284).
    expect(challenge).toBe(`Bearer resource_metadata="${METADATA_URL}"`);
  });

  // #284 — MCP Authorization ("Scope Selection Strategy").
  it('advertises the route required scopes on the 401, still with no error code', async () => {
    app = await buildApp(['mcp:read']);
    const res = await app.inject({ method: 'GET', url: '/data' });
    expect(res.statusCode).toBe(401);
    expect(res.headers['www-authenticate']).toBe(
      `Bearer scope="mcp:read", resource_metadata="${METADATA_URL}"`
    );
  });

  it('advertises defaults plus step-up scopes on the 401 of a privileged route', async () => {
    app = await buildApp(['mcp:read']);
    const res = await app.inject({ method: 'POST', url: '/admin' });
    expect(res.statusCode).toBe(401);
    // The full set the operation needs, so the client authorizes in one round
    // instead of coming back for a 403 step-up.
    expect(res.headers['www-authenticate']).toBe(
      `Bearer scope="mcp:read mcp:admin", resource_metadata="${METADATA_URL}"`
    );
  });

  it('keeps offline_access out of both the 401 challenge and PRM scopes_supported', async () => {
    app = await buildApp(['mcp:read', 'offline_access']);

    const challenge = await app.inject({ method: 'GET', url: '/data' });
    expect(challenge.headers['www-authenticate']).toBe(
      `Bearer scope="mcp:read", resource_metadata="${METADATA_URL}"`
    );

    const prm = await app.inject({
      method: 'GET',
      url: '/.well-known/oauth-protected-resource',
    });
    expect(prm.json().scopes_supported).toEqual(['mcp:read']);
  });

  it('returns 401 invalid_token for a wrong-audience token (no passthrough)', async () => {
    app = await buildApp();
    const token = await signToken({ sub: 'u', client_id: 'c' }, 'https://other.example.com');
    const res = await app.inject({
      method: 'GET',
      url: '/data',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(401);
    expect(res.headers['www-authenticate']).toContain('error="invalid_token"');
    expect(res.json().error).toBe('invalid_token');
  });

  it('returns 401 invalid_token for a malformed token', async () => {
    app = await buildApp();
    const res = await app.inject({
      method: 'GET',
      url: '/data',
      headers: { authorization: 'Bearer not-a-jwt' },
    });
    expect(res.statusCode).toBe(401);
    expect(res.headers['www-authenticate']).toContain('error="invalid_token"');
  });
});

describe('resource-guard Fastify plugin — happy path & step-up', () => {
  it('allows access with a valid, audience-bound token', async () => {
    app = await buildApp(['mcp:read']);
    const token = await signToken({ sub: 'user-9', client_id: 'c', scope: 'mcp:read' });
    const res = await app.inject({
      method: 'GET',
      url: '/data',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true, sub: 'user-9' });
  });

  it('returns 403 insufficient_scope with a step-up challenge for a missing scope', async () => {
    app = await buildApp();
    const token = await signToken({ sub: 'u', client_id: 'c', scope: 'mcp:read' });
    const res = await app.inject({
      method: 'POST',
      url: '/admin',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(403);
    const challenge = res.headers['www-authenticate'] as string;
    expect(challenge).toContain('error="insufficient_scope"');
    expect(challenge).toContain('scope="mcp:admin"');
    const body = res.json();
    expect(body.error).toBe('insufficient_scope');
    expect(body.scope).toBe('mcp:admin');
  });

  it('grants the step-up route when the token carries the scope', async () => {
    app = await buildApp();
    const token = await signToken({ sub: 'u', client_id: 'c', scope: 'mcp:read mcp:admin' });
    const res = await app.inject({
      method: 'POST',
      url: '/admin',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('resource-guard Fastify plugin — path-bearing resource', () => {
  it('serves PRM at the nested well-known path AND the bare prefix', async () => {
    const nested = Fastify();
    await nested.register(resourceGuardPlugin, {
      resource: 'https://host.example.com/mcp/memory',
      authorizationServer: ISSUER,
      fetch: jwksFetch({ keys: [publicJwk] }),
    });
    await nested.ready();
    try {
      const nestedRes = await nested.inject({
        method: 'GET',
        url: '/.well-known/oauth-protected-resource/mcp/memory',
      });
      expect(nestedRes.statusCode).toBe(200);
      expect(nestedRes.json().resource).toBe('https://host.example.com/mcp/memory');

      const bareRes = await nested.inject({
        method: 'GET',
        url: '/.well-known/oauth-protected-resource',
      });
      expect(bareRes.statusCode).toBe(200);
    } finally {
      await nested.close();
    }
  });
});

describe('resource-guard Fastify plugin — multiple resources on one instance', () => {
  const NOTES = 'https://host.example.com/mcp/notes';
  const ADMIN = 'https://host.example.com/mcp/admin';

  function registerNotes(scope: FastifyInstance) {
    return scope.register(resourceGuardPlugin, {
      resource: NOTES,
      authorizationServer: ISSUER,
      fetch: jwksFetch({ keys: [publicJwk] }),
    });
  }

  /** The admin resource: its own guard and route, in an encapsulated child scope. */
  function registerAdminScope(parent: FastifyInstance) {
    return parent.register(async (admin) => {
      await admin.register(resourceGuardPlugin, {
        resource: ADMIN,
        authorizationServer: ISSUER,
        requiredScopes: ['mcp:admin'],
        fetch: jwksFetch({ keys: [publicJwk] }),
      });
      admin.get('/mcp/admin', { preHandler: admin.requireBearer }, async () => ({ ok: true }));
    });
  }

  async function expectEachResourceBehindItsOwnGuard(multi: FastifyInstance) {
    const get = async (url: string, token?: string) =>
      multi.inject({
        method: 'GET',
        url,
        headers: token ? { authorization: `Bearer ${token}` } : {},
      });
    const notesToken = await signToken({ sub: 'u', scope: 'mcp:admin' }, NOTES);
    const adminToken = await signToken({ sub: 'u', scope: 'mcp:admin' }, ADMIN);

    expect((await get('/mcp/notes', notesToken)).statusCode).toBe(200);
    expect((await get('/mcp/notes', adminToken)).statusCode).toBe(401);
    expect((await get('/mcp/admin', adminToken)).statusCode).toBe(200);
    expect((await get('/mcp/admin', notesToken)).statusCode).toBe(401);
    // The admin guard's own `requiredScopes` and metadata pointer apply.
    expect(
      (await get('/mcp/admin', await signToken({ sub: 'u', scope: 'openid' }, ADMIN))).statusCode
    ).toBe(403);
    expect((await get('/mcp/admin')).headers['www-authenticate']).toBe(
      'Bearer scope="mcp:admin", resource_metadata=' +
        '"https://host.example.com/.well-known/oauth-protected-resource/mcp/admin"'
    );

    for (const [path, resource] of [
      ['/mcp/notes', NOTES],
      ['/mcp/admin', ADMIN],
    ]) {
      const res = await get(`/.well-known/oauth-protected-resource${path}`);
      expect(res.statusCode).toBe(200);
      expect(res.json().resource).toBe(resource);
    }
    // The bare prefix is claimed once (by the first guard) and still serves.
    expect((await get('/.well-known/oauth-protected-resource')).json().resource).toBe(NOTES);
  }

  it('wires a guard registered in a child scope, shadowing the one inherited from the parent', async () => {
    app = Fastify();
    await registerNotes(app);
    app.get('/mcp/notes', { preHandler: app.requireBearer }, async () => ({ ok: true }));
    await registerAdminScope(app);
    await app.ready();

    expect(app.resourceGuard.resource).toBe(NOTES);
    await expectEachResourceBehindItsOwnGuard(app);
  });

  it('boots with each guard in a sibling scope, without colliding on the bare PRM prefix', async () => {
    app = Fastify();
    await app.register(async (notes) => {
      await registerNotes(notes);
      notes.get('/mcp/notes', { preHandler: notes.requireBearer }, async () => ({ ok: true }));
    });
    await registerAdminScope(app);
    await app.ready();

    await expectEachResourceBehindItsOwnGuard(app);
  });

  it('does not let requireScopes reuse claims another guard validated', async () => {
    app = Fastify();
    await registerNotes(app);
    // The parent scope authenticates every request against the notes resource.
    app.addHook('preHandler', app.requireBearer);
    await app.register(async (admin) => {
      await admin.register(resourceGuardPlugin, {
        resource: ADMIN,
        authorizationServer: ISSUER,
        fetch: jwksFetch({ keys: [publicJwk] }),
      });
      admin.get('/mcp/admin', { preHandler: admin.requireScopes('mcp:admin') }, async () => ({
        ok: true,
      }));
    });
    await app.ready();

    const withToken = async (token: string) =>
      app!.inject({
        method: 'GET',
        url: '/mcp/admin',
        headers: { authorization: `Bearer ${token}` },
      });
    // A notes-audience token that happens to carry `mcp:admin` passes the
    // parent's hook but must not satisfy the admin guard.
    const notesToken = await signToken({ sub: 'u', scope: 'mcp:admin' }, NOTES);
    expect((await withToken(notesToken)).statusCode).toBe(401);
    // A token for both resources gets through both guards.
    const bothToken = await signToken({ sub: 'u', scope: 'mcp:admin' }, [NOTES, ADMIN]);
    expect((await withToken(bothToken)).statusCode).toBe(200);
  });

  it('refuses a second guard on the same scope, which the decorators could not reach', async () => {
    app = Fastify();
    await registerNotes(app);
    await expect(
      app.register(resourceGuardPlugin, {
        resource: ADMIN,
        authorizationServer: ISSUER,
        fetch: jwksFetch({ keys: [publicJwk] }),
      })
    ).rejects.toThrow(ResourceGuardConfigError);
  });
});

describe('resource-guard Fastify plugin — operational introspection failure', () => {
  it('surfaces a misconfigured-introspection (non-2xx) failure as 5xx, not 401 invalid_token', async () => {
    const opApp = Fastify();
    // The AS rejects OUR introspection client credentials with 401 — an
    // RS-side misconfiguration, not a bad bearer. The guard must not relabel
    // this as the client's token being invalid. The JWKS is served normally:
    // only a bearer that verifies locally reaches the introspection endpoint.
    const introspectFetch = (async (input: string | URL) =>
      String(input) === `${ISSUER}/oauth/introspect`
        ? {
            ok: false,
            status: 401,
            json: async () => ({}),
            text: async () => '{}',
          }
        : {
            ok: true,
            status: 200,
            json: async () => ({ keys: [publicJwk] }),
            text: async () => '',
          }) as unknown as never;
    await opApp.register(resourceGuardPlugin, {
      resource: RESOURCE,
      authorizationServer: ISSUER,
      validationMode: 'introspection',
      introspectionClient: { clientId: 'rs', clientSecret: 'bad' },
      fetch: introspectFetch,
    });
    opApp.get('/data', { preHandler: opApp.requireBearer }, async () => ({ ok: true }));
    await opApp.ready();
    try {
      const res = await opApp.inject({
        method: 'GET',
        url: '/data',
        headers: { authorization: `Bearer ${await signToken({ sub: 'u', client_id: 'c' })}` },
      });
      expect(res.statusCode).toBe(500);
      // Not a Bearer challenge — the client's token was never declared invalid.
      expect(res.headers['www-authenticate']).toBeUndefined();
      expect(res.json().error).not.toBe('invalid_token');
    } finally {
      await opApp.close();
    }
  });
});
