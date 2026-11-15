import {
  createFixtureNetwork,
  type EgressTransport,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/fastify-plugin-egress/src/testing/egress-fixtures';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { createLocalJWKSet, type JSONWebKeySet, type JWTPayload, jwtVerify } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  decodeHtmlEntities,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  extractCsrfToken,
  generateJwtPem,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE MCP QUICKSTART, END TO END (docs `integrate/mcp-quickstart.md`, #1087):
 * an MCP server whose scopes any CIMD client can be granted, and the step-up
 * loop of MCP 2026-07-28 (Scope Challenge Handling) against it.
 *
 * The operator registers the MCP server's protected resource in the realm,
 * `http://localhost:8088` with `mcp:read` and `mcp:write`, open to any
 * client. An MCP client that no operator ever listed, identified by its
 * Client ID Metadata Document (CIMD):
 *
 * 1. calls the server without a token and gets `401` with the challenge's
 *    `scope` and the server's RFC 9728 metadata, which names QAuth;
 * 2. authorizes with that scope and the server as `resource`, the user
 *    consents, and the token carries the scope with the server as `aud`;
 * 3. calls a tool that needs `mcp:write`, gets `403 insufficient_scope` with
 *    the scopes the call needs;
 * 4. authorizes again with the challenged scopes, the user consents to the
 *    new one, and the token carries it: the call succeeds, and the loop ends.
 *
 * Before #1087 the client's scope list (empty for a CIMD client) was the
 * ceiling, so step 4 returned a token without `mcp:write` and the loop never
 * ended.
 *
 * The MCP server here stands in for the quickstart's `memory-mcp` example,
 * which runs `@qauth-labs/resource-guard`: the SDK is published on its own
 * and the auth server's tests import no SDK (the module boundaries of
 * `.oxlintrc.json`). It answers the challenges `resource-guard` answers
 * (RFC 6750 §3, RFC 9728 §5.1) and checks a token as it does in `jwt` mode:
 * the signature against QAuth's JWKS, `iss`, `aud` and the scopes.
 *
 * The CIMD document is served by a fixture server on a public address of the
 * fixture network, which replaces only the production egress client's two
 * network edges (DNS and dialler), as the egress suites do.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const network = vi.hoisted(() => ({ current: undefined as EgressTransport | undefined }));

// The production client's network edges: the fixture network while a test
// sets one, the real ones otherwise.
vi.mock('../../../../libs/server/egress/src/lib/transport', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const real = actual['NODE_TRANSPORT'] as EgressTransport;
  const current = (): EgressTransport => network.current ?? real;
  return {
    ...actual,
    NODE_TRANSPORT: {
      resolveHost: (...args: Parameters<EgressTransport['resolveHost']>) =>
        current().resolveHost(...args),
      exchange: (...args: Parameters<EgressTransport['exchange']>) => current().exchange(...args),
    },
  };
});

/** Keys this suite sets that the harness does not clear between boots. */
const SUITE_KEYS = [
  'CIMD_ENABLED',
  'AUTHORIZE_RATE_LIMIT',
  'AUTHORIZE_RATE_LIMIT_LENIENT',
] as const;

const EMAIL = 'mcp-quickstart@example.test';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

/** The quickstart's MCP server: its canonical URL is its resource indicator (RFC 8707). */
const MCP_RESOURCE = 'http://localhost:8088';
const METADATA_URL = `${MCP_RESOURCE}/.well-known/oauth-protected-resource`;

/** The MCP client, by CIMD: an HTTPS URL that serves its metadata document. */
const CLIENT_HOST = 'mcp-client.egress.test';
const CLIENT_ID = `https://${CLIENT_HOST}/oauth/client.json`;
/** A public address, as the CIMD fetch (`source: client`) requires. */
const CLIENT_ADDRESS = '93.184.215.44';
const REDIRECT_URI = 'https://mcp-client.example.com/oauth/callback';

/** An RFC 6750 §3 challenge's parameters. */
function challengeOf(header: unknown): Record<string, string> {
  const value = String(header);
  expect(value.startsWith('Bearer ')).toBe(true);
  return Object.fromEntries(
    [...value.matchAll(/([a-z_]+)="([^"]*)"/g)].map(([, name, param]) => [name, param])
  );
}

/**
 * The quickstart's MCP server, as `memory-mcp` with `resource-guard` in `jwt`
 * mode: `GET /mcp/memory` needs `mcp:read`, `PUT /mcp/memory/:key` needs
 * `mcp:read` and `mcp:write`.
 */
async function mcpServer(issuer: string, jwks: JSONWebKeySet): Promise<FastifyInstance> {
  const keys = createLocalJWKSet(jwks);
  const store = new Map<string, string>();
  const app = Fastify();

  app.get('/.well-known/oauth-protected-resource', async () => ({
    resource: MCP_RESOURCE,
    authorization_servers: [issuer],
    scopes_supported: ['mcp:read', 'mcp:write'],
    bearer_methods_supported: ['header'],
  }));

  /** The token's scopes, or the reply's challenge when it has none or not the ones needed. */
  async function guard(
    request: FastifyRequest,
    reply: FastifyReply,
    needed: readonly string[]
  ): Promise<string | undefined> {
    const scope = needed.join(' ');
    const header = request.headers.authorization;
    if (header === undefined || !header.startsWith('Bearer ')) {
      await reply
        .code(401)
        .header('WWW-Authenticate', `Bearer scope="${scope}", resource_metadata="${METADATA_URL}"`)
        .send();
      return undefined;
    }
    let claims: JWTPayload;
    try {
      ({ payload: claims } = await jwtVerify(header.slice('Bearer '.length), keys, {
        issuer,
        audience: MCP_RESOURCE,
        algorithms: ['EdDSA'],
      }));
    } catch {
      await reply
        .code(401)
        .header(
          'WWW-Authenticate',
          `Bearer error="invalid_token", scope="${scope}", resource_metadata="${METADATA_URL}"`
        )
        .send();
      return undefined;
    }
    const held = new Set((typeof claims['scope'] === 'string' ? claims['scope'] : '').split(' '));
    if (!needed.every((one) => held.has(one))) {
      await reply
        .code(403)
        .header(
          'WWW-Authenticate',
          `Bearer error="insufficient_scope", scope="${scope}", resource_metadata="${METADATA_URL}"`
        )
        .send();
      return undefined;
    }
    return claims.sub;
  }

  app.get('/mcp/memory', async (request, reply) => {
    const subject = await guard(request, reply, ['mcp:read']);
    if (subject === undefined) return reply;
    return { subject, items: Object.fromEntries(store) };
  });

  app.put<{ Params: { key: string }; Body: { value: string } }>(
    '/mcp/memory/:key',
    async (request, reply) => {
      const subject = await guard(request, reply, ['mcp:read', 'mcp:write']);
      if (subject === undefined) return reply;
      store.set(request.params.key, request.body.value);
      return { ok: true, key: request.params.key };
    }
  );

  await app.ready();
  return app;
}

describe('the MCP quickstart: an MCP server whose scopes any CIMD client can be granted (#1087, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let net: FixtureNetwork | undefined;
  let documentHost: FixtureServer;
  let booted: BootedAuthServer | undefined;
  let mcp: FastifyInstance | undefined;
  let dockerUp = false;
  let cookie = '';

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    net = await createFixtureNetwork();
    documentHost = await net.serve(CLIENT_ADDRESS, () => undefined);
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      CIMD_ENABLED: 'true',
      // The loop runs several authorization requests from one address.
      AUTHORIZE_RATE_LIMIT: '10000',
      AUTHORIZE_RATE_LIMIT_LENIENT: '10000',
    });
  }, 240_000);

  afterAll(async () => {
    await mcp?.close();
    await booted?.close();
    await net?.close();
    await infra?.teardown();
    for (const key of SUITE_KEYS) delete process.env[key];
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined || net === undefined) {
      ctx.skip();
      return;
    }
    net.dns.clear();
    net.dns.set(CLIENT_HOST, [CLIENT_ADDRESS]);
    documentHost.handler = (_req, _body, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=600' });
      res.end(
        JSON.stringify({
          client_id: CLIENT_ID,
          client_name: 'An MCP client',
          redirect_uris: [REDIRECT_URI],
          grant_types: ['authorization_code', 'refresh_token'],
          token_endpoint_auth_method: 'none',
        })
      );
    };
    network.current = net.transport;
    const app = booted.app;
    await resetE2eState(app);

    // The operator's one step: register the MCP server's resource and its
    // scopes, open to any client, as the seed manifest's `resources` section
    // or the admin API does.
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    await app.repositories.protectedResources.create(realm.id, MCP_RESOURCE, {
      scopes: [
        { scope: 'mcp:read', text: { en: 'Read your memory store' }, sensitive: false },
        { scope: 'mcp:write', text: { en: 'Change your memory store' }, sensitive: false },
      ],
      anyClient: true,
      clientIds: [],
    });

    await registerPasswordAccount(app, EMAIL);
    cookie = (await signInWithPassword(app, EMAIL)).header() as string;

    // The MCP server trusts QAuth's issuer and verifies against its JWKS.
    const discovery = await app.inject({
      method: 'GET',
      url: '/.well-known/oauth-authorization-server',
    });
    expect(discovery.statusCode, discovery.body).toBe(200);
    const issuer = discovery.json<{ issuer: string }>().issuer;
    const jwks = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(jwks.statusCode, jwks.body).toBe(200);
    await mcp?.close();
    mcp = await mcpServer(issuer, jwks.json<JSONWebKeySet>());
  }, 120_000);

  afterEach(() => {
    network.current = undefined;
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  function resourceServer(): FastifyInstance {
    if (mcp === undefined) throw new Error('MCP server not started');
    return mcp;
  }

  /**
   * The MCP client's authorization request for `scope` at the MCP server, as
   * the user's browser runs it: the consent page, allowed, and the code
   * redeemed. Returns the scopes the page showed and the access token.
   */
  async function authorize(scope: string): Promise<{ shown: string[]; accessToken: string }> {
    const app = server();
    const pkce = pkcePair();
    const response = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope,
        resource: MCP_RESOURCE,
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'mcp-quickstart-state',
      }).toString()}`,
      headers: { cookie },
    });
    expect(response.statusCode, response.body).toBe(302);
    const location = String(response.headers['location']);
    expect(location.startsWith('/ui/consent?'), location).toBe(true);

    const screen = await app.inject({ method: 'GET', url: location, headers: { cookie } });
    expect(screen.statusCode, screen.body).toBe(200);
    const shown = [...screen.body.matchAll(/<li><code>([^<]+)<\/code>/g)].map(([, value]) =>
      decodeHtmlEntities(value)
    );
    const form = new URLSearchParams();
    for (const [, name, value] of screen.body.matchAll(
      /<input type="hidden" name="([^"]+)" value="([^"]*)"/g
    )) {
      form.append(name, decodeHtmlEntities(value));
    }
    form.set('csrf_token', extractCsrfToken(screen.body));
    form.set('decision', 'allow');
    form.set('allow_forever', '1');
    const decision = await app.inject({
      method: 'POST',
      url: '/ui/consent',
      headers: { ...FORM, cookie },
      payload: form.toString(),
    });
    expect(decision.statusCode, decision.body).toBe(302);
    const code = new URL(String(decision.headers['location'])).searchParams.get('code');
    if (code === null) throw new Error('no code');

    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: pkce.verifier,
        resource: MCP_RESOURCE,
      }).toString(),
    });
    expect(token.statusCode, token.body).toBe(200);
    return { shown, accessToken: token.json<{ access_token: string }>().access_token };
  }

  it('ends the step-up loop with a token that carries the challenged scope', async () => {
    const mcpApp = resourceServer();

    // 1. No token: 401, the scope the call needs and where to read the server's metadata.
    const first = await mcpApp.inject({ method: 'GET', url: '/mcp/memory' });
    expect(first.statusCode).toBe(401);
    const unauthorized = challengeOf(first.headers['www-authenticate']);
    expect(unauthorized).toEqual({ scope: 'mcp:read', resource_metadata: METADATA_URL });
    const metadata = await mcpApp.inject({
      method: 'GET',
      url: '/.well-known/oauth-protected-resource',
    });
    expect(metadata.json()).toMatchObject({ resource: MCP_RESOURCE });

    // 2. The challenged scope at the server's resource: consent, and the token holds it.
    const reading = await authorize(unauthorized['scope']);
    expect(reading.shown).toEqual(['mcp:read']);
    const read = await mcpApp.inject({
      method: 'GET',
      url: '/mcp/memory',
      headers: { authorization: `Bearer ${reading.accessToken}` },
    });
    expect(read.statusCode, read.body).toBe(200);

    // 3. A tool that needs more: 403 insufficient_scope, with the scopes it needs.
    const write = {
      method: 'PUT' as const,
      url: '/mcp/memory/greeting',
      payload: { value: 'hi' },
    };
    const refused = await mcpApp.inject({
      ...write,
      headers: { authorization: `Bearer ${reading.accessToken}` },
    });
    expect(refused.statusCode).toBe(403);
    const insufficient = challengeOf(refused.headers['www-authenticate']);
    expect(insufficient).toEqual({
      error: 'insufficient_scope',
      scope: 'mcp:read mcp:write',
      resource_metadata: METADATA_URL,
    });

    // 4. The challenged scopes: the user consents to the new one, and the
    //    token carries it. The loop ends.
    const writing = await authorize(insufficient['scope']);
    expect(writing.shown).toEqual(['mcp:read', 'mcp:write']);
    const written = await mcpApp.inject({
      ...write,
      headers: { authorization: `Bearer ${writing.accessToken}` },
    });
    expect(written.statusCode, written.body).toBe(200);
    expect(written.json()).toEqual({ ok: true, key: 'greeting' });

    // The operator never granted the client a scope of its own.
    const realm = await server().repositories.realms.findByName(E2E_REALM_NAME);
    const client = await server().repositories.oauthClients.findByClientId(
      realm?.id ?? '',
      CLIENT_ID
    );
    expect(client?.scopes).toEqual([]);
  });
});
