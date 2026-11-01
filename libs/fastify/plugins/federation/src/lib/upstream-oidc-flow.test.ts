import type { IncomingMessage } from 'node:http';

import formbody from '@fastify/formbody';
import {
  createTestSigner,
  type TestSigner,
} from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import {
  createEgressClient,
  type EgressClient,
  parseEgressAllowlist,
} from '@qauth-labs/server-egress';
import type { EgressTransport } from '@qauth-labs/server-egress/src/lib/transport';
import {
  createFixtureNetwork,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/server-egress/src/testing/fixture-network';
import {
  type AuthMethod,
  completeUpstreamStep,
  createAuthMethodContext,
  startUpstreamStep,
} from '@qauth-labs/server-federation';
import {
  checkUpstreamOidcProvider,
  createUpstreamOidcMethod,
  describeUpstreamOidcConfig,
  openUpstreamOidcConfig,
  sealUpstreamOidcConfig,
  type StoredUpstreamOidcConfig,
  upstreamClientSecretDestination,
  UpstreamClientSecretDestinationChangedError,
} from '@qauth-labs/server-upstream-oidc';
import {
  createFakeProvider,
  type FakeClientAuthentication,
  type FakeProvider,
} from '@qauth-labs/server-upstream-oidc/src/testing/fake-provider';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { decodeProtectedHeader } from 'jose';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { type AuthMethodRouteHost, authMethodRoutesPlugin } from './auth-method-routes';
import { createConfiguredProviders } from './configured-providers';
import { federationPlugin } from './federation-plugin';

/**
 * THE GENERIC UPSTREAM OIDC CLIENT, END TO END (#601), against a mock
 * provider, with no database:
 *
 * - the real egress client, with a deployment allowlist, whose two network
 *   edges (DNS and dialling) are replaced by a fixture network of local
 *   HTTPS servers, as the egress library's own tests do. Every check
 *   between, the address checks and the allowlist included, is the
 *   production code, and every call crosses TLS to a server;
 * - the real in-process signer over keys in memory (`createTestSigner`):
 *   it signs the `private_key_jwt` assertions with the realm's
 *   `upstream_client_assertion` key and seals the client secret with the
 *   realm's `data_at_rest` key;
 * - the real route mount (`authMethodRoutesPlugin`) and engine checks, with
 *   a small host that keeps each pending transaction under a
 *   `SameSite=Lax` flow cookie, and a browser that sends that cookie as a
 *   browser would: on a same-site request and on a cross-site top-level
 *   `GET`, never on a cross-site `POST`.
 *
 * The upstream sign-in flow itself (#639) and provider storage (#714) are
 * not built yet: the host here stands in for them.
 */

const network = vi.hoisted(() => ({ current: undefined as EgressTransport | undefined }));

// The production client's network edges: the fixture network while it is up.
vi.mock('../../../../../server/egress/src/lib/transport', async (importOriginal) => {
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

const REALM = 'acme';
const ORIGIN = 'https://auth.acme.example';
const CLIENT_ID = 'qauth-acme';
const CLIENT_SECRET = 'a-client-secret-nobody-may-see-0042';
const TYPE = 'oidc_corp';

/** The public provider, and an address in the documentation-free public range. */
const PUBLIC_ISSUER = 'https://idp.egress.test';
const PUBLIC_ADDRESS = '93.184.215.14';
/** A provider on a private address, which the allowlist opens for `acme` only. */
const PRIVATE_ISSUER = 'https://private-idp.egress.test';
const PRIVATE_ADDRESS = '10.0.0.7';

/** Where a token endpoint's redirect points: a public host of its own. */
const ELSEWHERE_ADDRESS = '151.101.1.140';

const ALLOWLIST = parseEgressAllowlist({ entries: [{ cidr: '10.0.0.0/24', realms: [REALM] }] });

const FLOW_COOKIE = '__Host-qauth-flow';

/** How many calls of `purpose` the egress client blocked for a non-public address. */
const addressRefusals = (purpose: string): number => egress.counts()[purpose]?.reasons.address ?? 0;

/** How many calls of `purpose` the egress client blocked for a redirect. */
const redirectRefusals = (purpose: string): number =>
  egress.counts()[purpose]?.reasons.redirect ?? 0;

const PERSON = { sub: 'user-1', claims: { email: 'ada@example.com', email_verified: true } };

let net: FixtureNetwork;
let publicProvider: FakeProvider;
let privateProvider: FakeProvider;
let publicServer: FixtureServer;
let privateServer: FixtureServer;
let elsewhereServer: FixtureServer;
let egress: EgressClient;
let signer: TestSigner;
let realmId: string;

/** Answer a fixture server's requests from a fake provider. */
function providerHandler(provider: FakeProvider, host: string): FixtureServer['handler'] {
  return (req: IncomingMessage, body, res) => {
    const headers = Object.fromEntries(
      Object.entries(req.headers).flatMap(([name, value]) =>
        typeof value === 'string' ? [[name, value]] : []
      )
    );
    void provider
      .answer({
        method: req.method ?? 'GET',
        url: `https://${host}${req.url ?? '/'}`,
        headers,
        body: body.toString('utf8'),
      })
      .then((answer) => {
        res.writeHead(answer.status, answer.headers);
        res.end(Buffer.from(answer.body));
      });
  };
}

beforeAll(async () => {
  net = await createFixtureNetwork();
  network.current = net.transport;
  publicProvider = await createFakeProvider({ issuer: PUBLIC_ISSUER, algorithm: 'RS256' });
  privateProvider = await createFakeProvider({ issuer: PRIVATE_ISSUER });
  net.dns.set('idp.egress.test', [PUBLIC_ADDRESS]);
  net.dns.set('private-idp.egress.test', [PRIVATE_ADDRESS]);
  publicServer = await net.serve(
    PUBLIC_ADDRESS,
    providerHandler(publicProvider, 'idp.egress.test')
  );
  privateServer = await net.serve(
    PRIVATE_ADDRESS,
    providerHandler(privateProvider, 'private-idp.egress.test')
  );
  net.dns.set('elsewhere.egress.test', [ELSEWHERE_ADDRESS]);
  elsewhereServer = await net.serve(ELSEWHERE_ADDRESS, (_req, _body, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  egress = createEgressClient({ allowlist: ALLOWLIST });
  signer = createTestSigner({ refreshIntervalMs: 0 });
  realmId = await signer.addRealm({ issuer: ORIGIN });
  // The private_key_jwt case's assertion key: an RSA key, made here rather
  // than under that test's own timeout.
  await signer.addUpstreamClient(realmId, 'oidc_private_key_jwt', { clientId: CLIENT_ID });
  // Certificates and RSA keys: slow when every project's suite runs at once.
}, 30_000);

afterAll(async () => {
  network.current = undefined;
  await net.close();
});

/** A provider's config in the realm, sealed as it is stored. */
function seal(type: string, config: unknown): Promise<StoredUpstreamOidcConfig> {
  return sealUpstreamOidcConfig(
    signer.signer,
    { realmId, providerId: type, caller: 'api' },
    config
  );
}

function configFor(
  authentication: FakeClientAuthentication,
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    issuer: PUBLIC_ISSUER,
    clientId: CLIENT_ID,
    clientAuthentication:
      authentication === 'private_key_jwt'
        ? { method: authentication }
        : { method: authentication, clientSecret: CLIENT_SECRET },
    ...overrides,
  };
}

/** The test host: the sign-in flow's part, a flow cookie and a transaction store. */
interface Booted {
  readonly app: FastifyInstance;
  readonly method: AuthMethod;
  /** Pending transactions by flow id. */
  readonly pending: Map<string, { binding: string; transaction: unknown }>;
  readonly logLines: string[];
}

async function boot(
  type: string,
  stored: StoredUpstreamOidcConfig,
  options: { realmName?: string } = {}
): Promise<Booted> {
  const method = createUpstreamOidcMethod({ type, display: { name: 'Example Corp' } });
  const pending = new Map<string, { binding: string; transaction: unknown }>();
  const logLines: string[] = [];
  const log = (fields: Record<string, unknown>, message: string) => {
    logLines.push(`${message} ${JSON.stringify(fields)}`);
  };
  const contextFor = async (forMethod: AuthMethod) =>
    createAuthMethodContext(forMethod, {
      // Opened from the stored form at each use, as a host would.
      config: await openUpstreamOidcConfig(
        signer.signer,
        { realmId, providerId: forMethod.type, caller: 'api' },
        stored
      ),
      origin: ORIGIN,
      realmName: options.realmName ?? REALM,
      realmId,
      providerId: forMethod.type,
      signerCaller: 'api',
      egress,
      signer: signer.signer,
      log: { debug: log, info: log, warn: log, error: log },
    });
  const flowId = (request: FastifyRequest): string | undefined =>
    /(?:^|;\s*)__Host-qauth-flow=([^;]+)/.exec(request.headers.cookie ?? '')?.[1];

  const host: AuthMethodRouteHost = {
    contextFor: (forMethod) => contextFor(forMethod),
    async peekTransaction(_method, request) {
      const id = flowId(request);
      return id === undefined ? undefined : pending.get(id);
    },
    async takeTransaction(_method, request) {
      const id = flowId(request);
      if (id === undefined) return undefined;
      const taken = pending.get(id);
      pending.delete(id);
      return taken;
    },
    async complete(forMethod, outcome, _request, reply) {
      try {
        const completion = await completeUpstreamStep(forMethod, outcome);
        return reply.send(
          completion.kind === 'identity'
            ? {
                kind: 'identity',
                externalSub: completion.identity.externalSub,
                iss: completion.identity.rawClaims['iss'],
                attributes: completion.attributes,
              }
            : completion
        );
      } catch (error) {
        return reply.code(500).send({ fault: (error as Error).message });
      }
    },
  };

  const app = Fastify({ logger: false });
  // The auth server's own form parser: a repeated key arrives as a list.
  await app.register(formbody);
  await app.register(federationPlugin, {
    providers: createConfiguredProviders({
      walletFederationEnabled: false,
      verifierProfileId: undefined,
      cryptoCapabilities: { signingAlgs: ['EdDSA'], responseEncryption: false },
      authMethods: [method],
    }),
  });
  await app.register(authMethodRoutesPlugin, { host });
  // The sign-in flow's start, standing in for #639: a flow cookie, the
  // pending transaction stored under it, and the redirect.
  app.get('/test/start', async (request, reply) => {
    const id = flowId(request) ?? crypto.randomUUID();
    const registered = app.providerRegistry.resolveAuthMethod(type);
    const start = await startUpstreamStep(
      registered,
      { uiLocales: ['en'] },
      await contextFor(registered)
    );
    pending.set(id, { binding: start.binding, transaction: start.transaction });
    reply.header('set-cookie', `${FLOW_COOKIE}=${id}; Path=/; Secure; HttpOnly; SameSite=Lax`);
    return reply.redirect(start.redirectTo, 303);
  });
  await app.ready();
  booted.push(app);
  return { app, method, pending, logLines };
}

const booted: FastifyInstance[] = [];
afterEach(async () => {
  for (const app of booted.splice(0)) await app.close();
  publicProvider.tamper = {};
});

/**
 * A browser with one cookie jar on the realm origin. `SameSite=Lax`: the
 * flow cookie goes with a same-site request and with a cross-site top-level
 * GET, never with a cross-site POST (a provider's `form_post`).
 */
function browser(app: FastifyInstance) {
  const jar = new Map<string, string>();
  return {
    jar,
    async request(options: {
      method: 'GET' | 'POST';
      url: string;
      form?: Record<string, string> | [string, string][];
      crossSite?: boolean;
    }) {
      const sendsLaxCookie = options.crossSite !== true || options.method === 'GET';
      const cookie = [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
      const response = await app.inject({
        method: options.method,
        url: options.url,
        headers: {
          ...(sendsLaxCookie && cookie !== '' ? { cookie } : {}),
          ...(options.form === undefined
            ? {}
            : { 'content-type': 'application/x-www-form-urlencoded' }),
        },
        ...(options.form === undefined
          ? {}
          : { payload: new URLSearchParams(options.form).toString() }),
      });
      const setCookie = response.headers['set-cookie'];
      for (const line of Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : []) {
        const [pair] = line.split(';');
        const [name, value] = pair.split('=');
        jar.set(name, value);
      }
      return response;
    },
  };
}

/** Start, sign in at the provider, and come back to the GET callback. */
async function signInThroughQuery(app: FastifyInstance, provider: FakeProvider, type = TYPE) {
  const tab = browser(app);
  const started = await tab.request({ method: 'GET', url: '/test/start' });
  expect(started.statusCode).toBe(303);
  const authorizationRequest = new URL(started.headers.location as string);
  const response = provider.authorize(authorizationRequest, PERSON);
  const back = await tab.request({
    method: 'GET',
    url: `/upstream/${type}/callback?${new URLSearchParams(response)}`,
    crossSite: true,
  });
  return { tab, started, authorizationRequest, response, back };
}

function registerClient(
  provider: FakeProvider,
  type: string,
  authentication: FakeClientAuthentication
): void {
  provider.register({
    clientId: CLIENT_ID,
    method: authentication,
    clientSecret: CLIENT_SECRET,
    redirectUris: [`${ORIGIN}/upstream/${type}/callback`],
    assertionKeys: () => signer.signer.getUpstreamJwks('api', realmId, type),
  });
}

describe('the code flow with PKCE, against a mock provider', () => {
  it.each(['client_secret_basic', 'client_secret_post', 'private_key_jwt'] as const)(
    'signs a person in with %s',
    async (authentication) => {
      // The signer holds the oidc_private_key_jwt assertion key from beforeAll.
      const type = `oidc_${authentication}`;
      registerClient(publicProvider, type, authentication);
      const { app } = await boot(type, await seal(type, configFor(authentication)));
      const tokenRequestsBefore = publicProvider.tokenRequests.length;
      const assertionsBefore = publicProvider.assertions.length;

      const { authorizationRequest, back } = await signInThroughQuery(app, publicProvider, type);
      expect(authorizationRequest.searchParams.get('code_challenge_method')).toBe('S256');
      expect(authorizationRequest.searchParams.get('redirect_uri')).toBe(
        `${ORIGIN}/upstream/${type}/callback`
      );
      expect(back.statusCode).toBe(200);
      expect(back.json()).toEqual({
        kind: 'identity',
        externalSub: 'user-1',
        iss: PUBLIC_ISSUER,
        attributes: [
          { source: type, attrKey: 'email', attrValue: 'ada@example.com', verified: true },
        ],
      });

      // The provider redeemed the code with the verifier and these credentials.
      const form = publicProvider.tokenRequests[tokenRequestsBefore];
      expect(form.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const tokenCall = publicServer.requests.filter((r) => r.url === '/token').at(-1);
      if (authentication === 'client_secret_basic') {
        expect(tokenCall?.headers.authorization).toMatch(/^Basic /);
      } else {
        expect(tokenCall?.headers.authorization).toBeUndefined();
      }
      if (authentication === 'private_key_jwt') {
        // The signer role signed it with the provider's assertion key, which
        // the provider verified from the signer's published key set.
        const assertion = form.get('client_assertion') as string;
        const jwks = await signer.signer.getUpstreamJwks('api', realmId, type);
        expect(decodeProtectedHeader(assertion)).toMatchObject({
          alg: 'RS256',
          kid: jwks.keys[0].kid,
          typ: 'client-authentication+jwt',
        });
        expect(publicProvider.assertions[assertionsBefore]).toMatchObject({
          iss: CLIENT_ID,
          sub: CLIENT_ID,
          aud: PUBLIC_ISSUER,
        });
      }
    }
  );

  it('refuses the same callback a second time: the transaction is taken once', async () => {
    registerClient(publicProvider, TYPE, 'client_secret_basic');
    const { app } = await boot(TYPE, await seal(TYPE, configFor('client_secret_basic')));
    const { tab, response, back } = await signInThroughQuery(app, publicProvider);
    expect(back.json()).toMatchObject({ kind: 'identity' });
    const again = await tab.request({
      method: 'GET',
      url: `/upstream/${TYPE}/callback?${new URLSearchParams(response)}`,
    });
    expect(again.json()).toEqual({ kind: 'failed', reason: 'transaction_mismatch' });
  });

  it('refuses a callback replayed in another browser, which holds no flow cookie', async () => {
    registerClient(publicProvider, TYPE, 'client_secret_basic');
    const { app, pending } = await boot(TYPE, await seal(TYPE, configFor('client_secret_basic')));
    const tab = browser(app);
    const started = await tab.request({ method: 'GET', url: '/test/start' });
    const response = publicProvider.authorize(new URL(started.headers.location as string), PERSON);
    const other = browser(app);
    const replayed = await other.request({
      method: 'GET',
      url: `/upstream/${TYPE}/callback?${new URLSearchParams(response)}`,
    });
    expect(replayed.json()).toEqual({ kind: 'failed', reason: 'transaction_mismatch' });
    // The sign-in the first browser started is still pending.
    expect(pending.size).toBe(1);
  });
});

describe('form_post', () => {
  it('bounces the cross-site POST to the GET callback, which brings the SameSite=Lax flow cookie', async () => {
    registerClient(publicProvider, TYPE, 'client_secret_post');
    const { app, pending } = await boot(
      TYPE,
      await seal(TYPE, configFor('client_secret_post', { responseMode: 'form_post' }))
    );
    const tab = browser(app);
    const started = await tab.request({ method: 'GET', url: '/test/start' });
    expect(started.headers['set-cookie']).toMatch(/SameSite=Lax/);
    const authorizationRequest = new URL(started.headers.location as string);
    expect(authorizationRequest.searchParams.get('response_mode')).toBe('form_post');
    const response = publicProvider.authorize(authorizationRequest, PERSON);

    // The provider's page posts the response cross-site: no flow cookie.
    const posted = await tab.request({
      method: 'POST',
      url: `/upstream/${TYPE}/callback`,
      form: response,
      crossSite: true,
    });
    expect(posted.statusCode).toBe(303);
    expect(posted.headers['cache-control']).toBe('no-store');
    const location = new URL(posted.headers.location as string, ORIGIN);
    expect(location.pathname).toBe(`/upstream/${TYPE}/callback`);
    expect(Object.fromEntries(location.searchParams)).toEqual(response);
    // Nothing was spent: the bounce holds no transaction and calls nobody.
    expect(pending.size).toBe(1);

    // The browser follows the 303 with a top-level GET: Lax sends the cookie.
    const back = await tab.request({
      method: 'GET',
      url: `${location.pathname}${location.search}`,
      crossSite: true,
    });
    expect(back.json()).toMatchObject({ kind: 'identity', externalSub: 'user-1' });
  });

  it('refuses a posted response that repeats error beside a valid code, and redeems nothing', async () => {
    registerClient(publicProvider, TYPE, 'client_secret_post');
    const { app } = await boot(
      TYPE,
      await seal(TYPE, configFor('client_secret_post', { responseMode: 'form_post' }))
    );
    const tab = browser(app);
    const started = await tab.request({ method: 'GET', url: '/test/start' });
    const response = publicProvider.authorize(new URL(started.headers.location as string), PERSON);
    const tokenRequestsBefore = publicProvider.tokenRequests.length;

    const posted = await tab.request({
      method: 'POST',
      url: `/upstream/${TYPE}/callback`,
      form: [...Object.entries(response), ['error', 'access_denied'], ['error', 'server_error']],
      crossSite: true,
    });
    expect(posted.statusCode).toBe(303);
    const location = new URL(posted.headers.location as string, ORIGIN);
    expect(location.searchParams.get('error')).toBe('');
    const back = await tab.request({
      method: 'GET',
      url: `${location.pathname}${location.search}`,
      crossSite: true,
    });
    expect(back.json()).toEqual({ kind: 'failed', reason: 'provider_error' });
    expect(publicProvider.tokenRequests.length).toBe(tokenRequestsBefore);
  });

  it('without the bounce, the cross-site POST would carry no flow cookie and be refused', async () => {
    registerClient(publicProvider, TYPE, 'client_secret_post');
    const { app } = await boot(
      TYPE,
      await seal(TYPE, configFor('client_secret_post', { responseMode: 'form_post' }))
    );
    const tab = browser(app);
    const started = await tab.request({ method: 'GET', url: '/test/start' });
    const response = publicProvider.authorize(new URL(started.headers.location as string), PERSON);
    // As if the provider had posted straight to a GET-only callback with the
    // cookie left behind: the request the bounce turns into, minus the cookie.
    const noCookie = await app.inject({
      method: 'GET',
      url: `/upstream/${TYPE}/callback?${new URLSearchParams(response)}`,
    });
    expect(noCookie.json()).toEqual({ kind: 'failed', reason: 'transaction_mismatch' });
  });
});

describe('private addresses and the egress allowlist', () => {
  it('refuses a discovered token endpoint on a private address, though the allowlist names it for the realm', async () => {
    registerClient(publicProvider, TYPE, 'client_secret_post');
    publicProvider.tamper.discovery = { token_endpoint: `${PRIVATE_ISSUER}/token` };
    const { app, logLines } = await boot(TYPE, await seal(TYPE, configFor('client_secret_post')));
    const connectionsBefore = privateServer.connections;
    const refusalsBefore = addressRefusals('upstream-token');
    const { back } = await signInThroughQuery(app, publicProvider);
    expect(back.json()).toEqual({ kind: 'failed', reason: 'upstream_unavailable' });
    // The address check refused it before anything was sent.
    expect(addressRefusals('upstream-token')).toBe(refusalsBefore + 1);
    expect(privateServer.connections).toBe(connectionsBefore);
    expect(logLines.join('\n')).toContain('upstream-token');
  });

  it('refuses a discovered jwks_uri on a private address', async () => {
    registerClient(publicProvider, TYPE, 'client_secret_post');
    publicProvider.tamper.discovery = { jwks_uri: `${PRIVATE_ISSUER}/jwks` };
    const { app } = await boot(TYPE, await seal(TYPE, configFor('client_secret_post')));
    const connectionsBefore = privateServer.connections;
    const refusalsBefore = addressRefusals('upstream-jwks');
    const { back } = await signInThroughQuery(app, publicProvider);
    expect(back.json()).toEqual({ kind: 'failed', reason: 'upstream_unavailable' });
    expect(addressRefusals('upstream-jwks')).toBe(refusalsBefore + 1);
    expect(privateServer.connections).toBe(connectionsBefore);
  });

  it('reads the discovery document of an allowlisted private issuer, and still refuses the token endpoint it names on the same host', async () => {
    // ADR-019 Decision 8: the allowlist opens the issuer's document, which
    // the operator's config names, and never a URL the document names, even
    // on the same origin.
    registerClient(privateProvider, TYPE, 'client_secret_basic');
    const { app } = await boot(
      TYPE,
      await seal(TYPE, configFor('client_secret_basic', { issuer: PRIVATE_ISSUER }))
    );
    const requestsBefore = privateServer.requests.length;
    const refusalsBefore = addressRefusals('upstream-token');
    const { back } = await signInThroughQuery(app, privateProvider);
    expect(back.json()).toEqual({ kind: 'failed', reason: 'upstream_unavailable' });
    expect(addressRefusals('upstream-token')).toBe(refusalsBefore + 1);
    expect(privateServer.requests.slice(requestsBefore).map((r) => `${r.method} ${r.url}`)).toEqual(
      ['GET /.well-known/openid-configuration']
    );
  });

  it('follows no redirect: a 307 from the token endpoint sends the code and the secret nowhere', async () => {
    registerClient(publicProvider, TYPE, 'client_secret_post');
    publicProvider.tamper.tokenAnswer = () => ({
      status: 307,
      headers: { location: 'https://elsewhere.egress.test/token' },
      body: new Uint8Array(),
      url: publicProvider.tokenEndpoint,
    });
    const { app } = await boot(TYPE, await seal(TYPE, configFor('client_secret_post')));
    const refusalsBefore = redirectRefusals('upstream-token');
    const { back } = await signInThroughQuery(app, publicProvider);
    expect(back.json()).toEqual({ kind: 'failed', reason: 'upstream_unavailable' });
    expect(redirectRefusals('upstream-token')).toBe(refusalsBefore + 1);
    expect(elsewhereServer.connections).toBe(0);
  });

  it('reports the discovered private endpoint at registration, with the real egress client', async () => {
    publicProvider.tamper.discovery = { token_endpoint: `${PRIVATE_ISSUER}/token` };
    expect(await checkUpstreamOidcProvider(egress, REALM, configFor('client_secret_post'))).toEqual(
      {
        ok: false,
        finding: 'destination_refused',
        detail: expect.stringContaining('token endpoint'),
      }
    );
    publicProvider.tamper = {};
    expect(
      await checkUpstreamOidcProvider(egress, REALM, configFor('client_secret_post'))
    ).toMatchObject({
      ok: true,
    });
  });

  it('reaches a provider on a private address through endpoints set by hand, for the realm the allowlist names', async () => {
    registerClient(privateProvider, TYPE, 'client_secret_basic');
    const config = configFor('client_secret_basic', {
      issuer: PRIVATE_ISSUER,
      endpoints: {
        authorization: privateProvider.authorizationEndpoint,
        token: privateProvider.tokenEndpoint,
        jwks: privateProvider.jwksUri,
        issParameterSupported: true,
      },
    });
    const { app } = await boot(TYPE, await seal(TYPE, config));
    const { back } = await signInThroughQuery(app, privateProvider);
    expect(back.json()).toMatchObject({ kind: 'identity', iss: PRIVATE_ISSUER });

    // Another realm's destinations: the entry does not name it.
    const other = await boot('oidc_other', await seal('oidc_other', config), {
      realmName: 'other',
    });
    registerClient(privateProvider, 'oidc_other', 'client_secret_basic');
    const refusalsBefore = addressRefusals('upstream-token');
    const refused = await signInThroughQuery(other.app, privateProvider, 'oidc_other');
    expect(refused.back.json()).toEqual({ kind: 'failed', reason: 'upstream_unavailable' });
    expect(addressRefusals('upstream-token')).toBe(refusalsBefore + 1);
  });

  it('refuses discovery of an issuer on a private address the allowlist does not open for the realm', async () => {
    const config = configFor('client_secret_basic', { issuer: PRIVATE_ISSUER });
    const { app } = await boot(TYPE, await seal(TYPE, config), { realmName: 'other' });
    const refusalsBefore = addressRefusals('upstream-discovery');
    const started = await app.inject({ method: 'GET', url: '/test/start' });
    expect(started.statusCode).toBe(500);
    expect(addressRefusals('upstream-discovery')).toBe(refusalsBefore + 1);
    expect(await checkUpstreamOidcProvider(egress, 'other', config)).toMatchObject({
      ok: false,
      finding: 'discovery_unavailable',
    });
  });
});

describe('the stored client secret', () => {
  it('is sealed with the realm’s data-at-rest key, and never returned', async () => {
    registerClient(publicProvider, TYPE, 'client_secret_post');
    const stored = await seal(TYPE, configFor('client_secret_post'));
    const forms = [
      CLIENT_SECRET,
      Buffer.from(CLIENT_SECRET).toString('base64'),
      Buffer.from(CLIENT_SECRET).toString('base64url'),
      encodeURIComponent(CLIENT_SECRET),
    ];
    const sealed = (stored.clientAuthentication as { clientSecretSealed: string })
      .clientSecretSealed;
    expect(sealed).toMatch(/^v1\./);
    for (const form of forms) expect(JSON.stringify(stored)).not.toContain(form);

    // The view an API or event carries: neither the secret nor its ciphertext.
    const view = JSON.stringify(describeUpstreamOidcConfig(stored));
    for (const form of [...forms, sealed]) expect(view).not.toContain(form);

    // The sign-in works from the stored form, and no answer or log line
    // carries the secret.
    const { app, logLines } = await boot(TYPE, stored);
    const { started, back } = await signInThroughQuery(app, publicProvider);
    expect(back.json()).toMatchObject({ kind: 'identity' });
    const seen = [started.headers.location, started.body, back.body, ...logLines].join('\n');
    for (const form of forms) expect(seen).not.toContain(form);
  });

  it('opens as api, and not for another provider, the web role or the delivery role', async () => {
    const stored = await seal(TYPE, configFor('client_secret_post'));
    await expect(
      openUpstreamOidcConfig(
        signer.signer,
        { realmId, providerId: 'oidc_other', caller: 'api' },
        stored
      )
    ).rejects.toThrow();
    for (const caller of ['web', 'delivery']) {
      await expect(
        openUpstreamOidcConfig(signer.signer, { realmId, providerId: TYPE, caller }, stored),
        caller
      ).rejects.toMatchObject({ code: 'SIGNER_ACCESS_DENIED', caller, operation: 'decrypt' });
    }
    await expect(
      openUpstreamOidcConfig(signer.signer, { realmId, providerId: TYPE, caller: 'api' }, stored)
    ).resolves.toMatchObject({ clientAuthentication: { clientSecret: CLIENT_SECRET } });
  });

  it('does not open once the issuer points elsewhere, even with the recorded destination edited', async () => {
    const stored = await seal(TYPE, configFor('client_secret_post'));
    const owner = { realmId, providerId: TYPE, caller: 'api' };
    const repointed = { ...stored, issuer: PRIVATE_ISSUER };
    await expect(openUpstreamOidcConfig(signer.signer, owner, repointed)).rejects.toBeInstanceOf(
      UpstreamClientSecretDestinationChangedError
    );
    // The row edited by hand to claim the new destination: the signer's
    // context names it, so the ciphertext sealed for the old one fails.
    const forged = {
      ...repointed,
      clientAuthentication: {
        ...(stored.clientAuthentication as { method: 'client_secret_post' }),
        clientSecretDestination: upstreamClientSecretDestination({ issuer: PRIVATE_ISSUER }),
      },
    };
    await expect(openUpstreamOidcConfig(signer.signer, owner, forged)).rejects.toMatchObject({
      code: 'DATA_DECRYPTION_FAILED',
    });
  });
});
