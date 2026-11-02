import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';

import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE INTERACTION API ON A REAL REDIS AND POSTGRES (#616, ADR-019 Decision 6).
 *
 * Each test boots the real auth server, with the real sign-in engine, the
 * failure ladder and the event store, and starts an interaction through a
 * test route, as the authorization endpoint does (#628), for a client the
 * user has consented to: a finished sign-in ends in the client's code. It
 * proves the
 * issue's integration criteria: a missing or wrong CSRF value is refused with
 * 403 before the engine runs (spied on the repository and the hasher the
 * engine uses); a used value and the value of another step are refused; a
 * cross-site request is refused; a plain HTML form signs in over HTTP and ends
 * in 303; and no request field moves the redirect.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const EMAIL = 'interaction-api@example.com';
const ORIGIN = 'https://auth.example.com';
const HOST = 'auth.example.com';
const SESSION_COOKIE = '__Host-qauth_session';
const FLOW_COOKIE = '__Host-qauth_flow';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');

const AUTHORIZE_REQUEST = {
  response_type: 'code' as const,
  client_id: 'interaction-api-client',
  redirect_uri: 'https://client.example.com/callback',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256' as const,
  state: 'af0ifjsldkj',
  scope: 'openid email',
  resource: undefined,
};

/**
 * The client of the interactions, with the user's stored consent to their
 * scopes: the finish decides the request as the endpoint does (#628) and
 * mints the code.
 */
async function provisionClient(app: FastifyInstance, userId: string): Promise<void> {
  const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
  if (!realm) throw new Error('default realm missing');
  const client = await app.repositories.oauthClients.create({
    realmId: realm.id,
    clientId: AUTHORIZE_REQUEST.client_id,
    clientSecretHash: 'unused-public-client',
    tokenEndpointAuthMethod: 'none',
    name: 'Interaction API client',
    redirectUris: [AUTHORIZE_REQUEST.redirect_uri],
    scopes: ['openid', 'email'],
    grantTypes: ['authorization_code'],
    enabled: true,
    requirePkce: true,
    provisionedByOperator: true,
  });
  await app.repositories.oauthConsents.upsertGrant(realm.id, userId, client.id, [
    'openid',
    'email',
  ]);
}

/** Start an interaction at the identifier step, as the authorization endpoint does (#628). */
async function startRoute(app: FastifyInstance): Promise<void> {
  app.post('/test/interactions', { config: { surface: 'browser' } }, async (request, reply) => {
    // Imported here, after the boot reset the module registry, so this is the
    // instance the app loaded.
    const { startInteraction } = await import('./helpers/interaction');
    const { IDENTIFIER_STEP } = await import('./helpers/interaction-record');
    return startInteraction(request, reply, {
      request: AUTHORIZE_REQUEST,
      step: { name: IDENTIFIER_STEP, params: {}, alternatives: [] },
    });
  });
}

/** An HTTP response, as the browser sees it. */
interface Answer {
  readonly status: number;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: string;
}

/**
 * A browser without JavaScript: a cookie jar and plain HTTP requests on a real
 * socket, the realm's host in `Host`, as a form post sends them.
 */
class Browser {
  readonly cookies = new Map<string, string>();

  constructor(private readonly port: number) {}

  absorb(header: string | string[] | undefined): void {
    for (const line of header === undefined ? [] : Array.isArray(header) ? header : [header]) {
      const [pair] = line.split(';');
      const eq = pair.indexOf('=');
      if (/Max-Age=0/i.test(line)) this.cookies.delete(pair.slice(0, eq));
      else this.cookies.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
  }

  send(
    method: 'GET' | 'POST',
    path: string,
    options: { body?: string; type?: string; headers?: Record<string, string> } = {}
  ): Promise<Answer> {
    const cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    return new Promise((resolve, reject) => {
      const req = httpRequest(
        {
          host: '127.0.0.1',
          port: this.port,
          method,
          path,
          headers: {
            host: HOST,
            ...(cookie.length === 0 ? {} : { cookie }),
            ...(options.body === undefined
              ? {}
              : {
                  'content-type': options.type ?? 'application/x-www-form-urlencoded',
                  'content-length': String(Buffer.byteLength(options.body)),
                }),
            ...options.headers,
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            this.absorb(res.headers['set-cookie']);
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          });
        }
      );
      req.on('error', reject);
      if (options.body !== undefined) req.write(options.body);
      req.end();
    });
  }

  async start(): Promise<string> {
    const started = await this.send('POST', '/test/interactions');
    expect(started.status, started.body).toBe(200);
    return (JSON.parse(started.body) as { id: string }).id;
  }

  /** The step read, as the ceremony app's server makes it: the id alone, no cookie. */
  async read(id: string): Promise<{ step: string; csrf: string; error?: string }> {
    const read = await new Browser(this.port).send('GET', `${INTERACTION_API_PREFIX}/${id}`);
    expect(read.status, read.body).toBe(200);
    return JSON.parse(read.body) as { step: string; csrf: string; error?: string };
  }

  /** A form post to the answer endpoint, from a page of the realm origin. */
  post(
    id: string,
    fields: Record<string, string>,
    headers: Record<string, string> = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' },
    operation: 'answer' | 'cancel' = 'answer',
    query = ''
  ): Promise<Answer> {
    return this.send('POST', `${INTERACTION_API_PREFIX}/${id}/${operation}${query}`, {
      body: new URLSearchParams(fields).toString(),
      headers,
    });
  }
}

describe('the Interaction API (#616, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let server: BootedAuthServer | undefined;
  let port = 0;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp) ctx.skip();
    if (!infra || !jwt) throw new Error('infrastructure not started');
    server = await bootAuthServer(baseEnvironment(infra, jwt), { routes: startRoute });
    await resetE2eState(server.app);
    await provisionClient(server.app, await registerPasswordAccount(server.app, EMAIL));
    await server.app.listen({ port: 0, host: '127.0.0.1' });
    port = (server.app.server.address() as AddressInfo).port;
  }, 120_000);

  afterEach(async () => {
    vi.restoreAllMocks();
    await server?.close();
    server = undefined;
  });

  function app(): FastifyInstance {
    if (server === undefined) throw new Error('no server');
    return server.app;
  }

  /** Spies on what the engine reads to check a password: neither may run before the checks pass. */
  function engineSpies() {
    return {
      account: vi.spyOn(app().repositories.userCredentials, 'findByRealmProviderSub'),
      hash: vi.spyOn(app().passwordHasher, 'verifyPassword'),
    };
  }

  /** A browser at the password step: the identifier answered by a form post. */
  async function atPasswordStep(): Promise<{
    browser: Browser;
    id: string;
    identifierCsrf: string;
  }> {
    const browser = new Browser(port);
    const id = await browser.start();
    const identifierCsrf = (await browser.read(id)).csrf;
    const answered = await browser.post(id, {
      type: IDENTIFIER,
      csrf: identifierCsrf,
      login_hint: EMAIL,
    });
    expect(answered.status, answered.body).toBe(303);
    expect((await browser.read(id)).step).toBe(PASSWORD);
    return { browser, id, identifierCsrf };
  }

  async function csrfRejections(): Promise<number> {
    const { rows } = await app().dbPool.query<{ count: string }>(
      `SELECT count(*) AS count FROM events WHERE type = 'urn:qauth:event:request.csrf_rejected:v1-rc.0'`
    );
    return Number(rows[0]?.count ?? 0);
  }

  it('signs in with a plain HTML form over HTTP and ends in 303, with no JavaScript', async () => {
    const browser = new Browser(port);
    const id = await browser.start();

    const identifier = await browser.post(id, {
      type: IDENTIFIER,
      csrf: (await browser.read(id)).csrf,
      login_hint: EMAIL,
    });
    expect(identifier.status).toBe(303);
    expect(identifier.headers.location).toBe(`${ORIGIN}${CEREMONY_PAGE_PREFIX}${id}`);
    expect(identifier.headers['cache-control']).toBe('no-store');

    const password = await browser.post(id, {
      type: PASSWORD,
      csrf: (await browser.read(id)).csrf,
      password: E2E_PASSWORD,
    });
    expect(password.status, password.body).toBe(303);
    const location = new URL(String(password.headers.location));
    expect(`${location.origin}${location.pathname}`).toBe(AUTHORIZE_REQUEST.redirect_uri);
    expect(location.searchParams.get('state')).toBe(AUTHORIZE_REQUEST.state);
    expect(location.searchParams.get('iss')).toBe(ORIGIN);
    expect(location.searchParams.get('code')).toMatch(/.+/);
    expect(browser.cookies.get(SESSION_COOKIE)).toBeTruthy();
    expect(browser.cookies.has(FLOW_COOKIE)).toBe(false);
    // The interaction is over.
    const after = await new Browser(port).send('GET', `${INTERACTION_API_PREFIX}/${id}`);
    expect(after.status).toBe(410);
  });

  it('signs in a form post from a no-referrer page: Sec-Fetch-Site same-origin with Origin: null', async () => {
    const { browser, id } = await atPasswordStep();
    const response = await browser.post(
      id,
      { type: PASSWORD, csrf: (await browser.read(id)).csrf, password: E2E_PASSWORD },
      { origin: 'null', 'sec-fetch-site': 'same-origin' }
    );
    expect(response.status, response.body).toBe(303);
    expect(browser.cookies.get(SESSION_COOKIE)).toBeTruthy();
  });

  it('gives a wrong password the same step back with its error and a new CSRF value', async () => {
    const { browser, id } = await atPasswordStep();
    const before = await browser.read(id);
    const refused = await browser.post(id, {
      type: PASSWORD,
      csrf: before.csrf,
      password: 'not the password',
    });
    expect(refused.status).toBe(303);
    const again = await browser.read(id);
    expect(again.step).toBe(PASSWORD);
    expect(again.error).toBe('invalid_credentials');
    expect(again.csrf).not.toBe(before.csrf);
  });

  it.each([
    ['missing', undefined],
    ['wrong', 'A'.repeat(43)],
  ])(
    'refuses a %s CSRF value with 403, audited, and the engine is not called',
    async (_l, csrf) => {
      const { browser, id } = await atPasswordStep();
      const spies = engineSpies();
      const rejectedBefore = await csrfRejections();

      const response = await browser.post(id, {
        type: PASSWORD,
        ...(csrf === undefined ? {} : { csrf }),
        password: E2E_PASSWORD,
      });

      expect(response.status).toBe(403);
      expect(JSON.parse(response.body)).toMatchObject({ code: 'forbidden' });
      expect(spies.account).not.toHaveBeenCalled();
      expect(spies.hash).not.toHaveBeenCalled();
      expect(await csrfRejections()).toBe(rejectedBefore + 1);
      expect(browser.cookies.has(SESSION_COOKIE)).toBe(false);
    }
  );

  it('refuses a CSRF value the second time it is used', async () => {
    const { browser, id } = await atPasswordStep();
    const { csrf } = await browser.read(id);
    const first = await browser.post(id, { type: PASSWORD, csrf, password: 'wrong once' });
    expect(first.status).toBe(303);

    const spies = engineSpies();
    const second = await browser.post(id, { type: PASSWORD, csrf, password: E2E_PASSWORD });
    expect(second.status).toBe(403);
    expect(spies.hash).not.toHaveBeenCalled();
  });

  it('refuses the CSRF value of step A on step B', async () => {
    const { browser, id, identifierCsrf } = await atPasswordStep();
    const spies = engineSpies();
    const response = await browser.post(id, {
      type: PASSWORD,
      csrf: identifierCsrf,
      password: E2E_PASSWORD,
    });
    expect(response.status).toBe(403);
    expect(spies.hash).not.toHaveBeenCalled();
  });

  it.each([
    [
      'Sec-Fetch-Site: cross-site',
      { 'sec-fetch-site': 'cross-site', origin: 'https://evil.example' },
    ],
    ['Sec-Fetch-Site: cross-site alone', { 'sec-fetch-site': 'cross-site' }],
    ['an Origin of another site', { origin: 'https://evil.example' }],
  ])('refuses a request with %s, before the engine runs', async (_label, headers) => {
    const { browser, id } = await atPasswordStep();
    const spies = engineSpies();
    const response = await browser.post(
      id,
      { type: PASSWORD, csrf: (await browser.read(id)).csrf, password: E2E_PASSWORD },
      headers
    );
    expect(response.status).toBe(403);
    expect(spies.account).not.toHaveBeenCalled();
    expect(spies.hash).not.toHaveBeenCalled();
    expect(browser.cookies.has(SESSION_COOKIE)).toBe(false);
  });

  it('takes the redirect from the record: no request field moves it', async () => {
    const { browser, id } = await atPasswordStep();
    const { csrf } = await browser.read(id);
    const hostile = {
      redirect_uri: 'https://evil.example/callback',
      state: 'attacker-state',
      iss: 'https://evil.example',
      location: 'https://evil.example/',
    };

    // A body member the step does not declare is refused, not used.
    for (const [name, value] of Object.entries(hostile)) {
      const refused = await browser.post(id, {
        type: PASSWORD,
        csrf,
        password: E2E_PASSWORD,
        [name]: value,
      });
      expect(refused.status, name).toBe(400);
    }

    // The query and the Referer: ignored.
    const query = `?${new URLSearchParams(hostile).toString()}`;
    const signedIn = await browser.post(
      id,
      { type: PASSWORD, csrf, password: E2E_PASSWORD },
      {
        origin: ORIGIN,
        'sec-fetch-site': 'same-origin',
        referer: 'https://evil.example/page',
      },
      'answer',
      query
    );
    expect(signedIn.status, signedIn.body).toBe(303);
    const location = new URL(String(signedIn.headers.location));
    expect(`${location.origin}${location.pathname}`).toBe(AUTHORIZE_REQUEST.redirect_uri);
    expect(location.searchParams.get('state')).toBe(AUTHORIZE_REQUEST.state);
    expect(location.searchParams.get('iss')).toBe(ORIGIN);
  });

  it('cancels with the CSRF value to the client, with access_denied', async () => {
    const { browser, id } = await atPasswordStep();
    const cancelled = await browser.post(
      id,
      { csrf: (await browser.read(id)).csrf },
      { origin: ORIGIN, 'sec-fetch-site': 'same-origin' },
      'cancel'
    );
    expect(cancelled.status).toBe(303);
    const location = new URL(String(cancelled.headers.location));
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('state')).toBe(AUTHORIZE_REQUEST.state);
    expect(location.searchParams.get('iss')).toBe(ORIGIN);
  });
});
