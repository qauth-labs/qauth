import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';

import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import { type ProofOfWorkParams, solveProofOfWork } from '@qauth-labs/shared-interaction-client';
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
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE INLINE VERIFICATION OF AN ACCOUNT ON A REAL REDIS AND POSTGRES (#638,
 * ADR-017 Decisions 5, 7 and 8; `graphs/flows/core/account-verification`).
 *
 * Each test boots the real auth server, with the real sign-in engine, the
 * failure ladder, the send caps and the event store, registers an account
 * through `POST /auth/register` and leaves it unverified, and signs it in
 * through the Interaction API with plain form posts. The mailed code is read
 * off the realm's mail service. It proves the issue's integration criteria:
 * an unverified account gets the email_code step after its correct password,
 * under the realm's gate (with it off, since 2026-11-08, the account signs in
 * with no code); after 5 wrong codes across two
 * transactions the next attempt inside the email-code ladder's wait is
 * refused and the account stays unverified; and a correct code outside a wait
 * is accepted, verifies the address and completes the sign-in. Past the
 * ladder's free failures the next round first asks for the bot challenge
 * (#643; ADR-017 Decision 7), which the page's own solver answers.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const EMAIL = 'unverified-owner@example.com';
const ORIGIN = 'https://auth.example.com';
const HOST = 'auth.example.com';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const EMAIL_CODE = stepUrn('email_code');
const CAPTCHA = stepUrn('captcha');

const AUTHORIZE_REQUEST = {
  response_type: 'code' as const,
  client_id: 'email-code-client',
  redirect_uri: 'https://client.example.com/callback',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256' as const,
  state: 'af0ifjsldkj',
  scope: 'openid email',
  resource: undefined,
};

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

/** A step read: the step, its CSRF value, its params by URN and the error of a refused answer. */
interface StepRead {
  readonly step: string;
  readonly csrf: string;
  readonly params?: Record<string, Record<string, unknown>>;
  readonly error?: string;
}

/** A browser without JavaScript: a cookie jar and plain HTTP form posts on a real socket. */
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
    options: { body?: string; headers?: Record<string, string> } = {}
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
                  'content-type': 'application/x-www-form-urlencoded',
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
  async read(id: string): Promise<StepRead> {
    const read = await new Browser(this.port).send('GET', `${INTERACTION_API_PREFIX}/${id}`);
    expect(read.status, read.body).toBe(200);
    return JSON.parse(read.body) as StepRead;
  }

  /** Answer the current step with a form post from a page of the realm origin. */
  async answer(id: string, type: string, fields: Record<string, string>): Promise<Answer> {
    const { csrf } = await this.read(id);
    return this.send('POST', `${INTERACTION_API_PREFIX}/${id}/answer`, {
      body: new URLSearchParams({ type, csrf, ...fields }).toString(),
      headers: { origin: ORIGIN, 'sec-fetch-site': 'same-origin' },
    });
  }
}

describe('the inline verification of an account (#638, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let server: BootedAuthServer | undefined;
  let port = 0;
  /** The codes mailed to each address, in order. */
  const codes = new Map<string, string[]>();

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  function app(): FastifyInstance {
    if (server === undefined) throw new Error('no server');
    return server.app;
  }

  async function realmId(): Promise<string> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    return realm.id;
  }

  /**
   * `POST /auth/register` of {@link EMAIL}, the account left unverified, and
   * the client with the user's stored consent. The registration's link mail
   * goes out off the request path: it is waited for, so none is still being
   * sent when the next test empties the database.
   */
  async function registerUnverified(): Promise<string> {
    const emailService = app().emailService;
    const original = emailService.sendVerificationEmail;
    let mailed = false;
    emailService.sendVerificationEmail = async (realm, to, token, link, options) => {
      if (to === EMAIL) mailed = true;
      return original.call(emailService, realm, to, token, link, options);
    };
    try {
      const response = await app().inject({
        method: 'POST',
        url: '/auth/register',
        payload: { email: EMAIL, password: E2E_PASSWORD },
      });
      expect(response.statusCode, response.body).toBe(202);
      const deadline = Date.now() + 5_000;
      while (!mailed && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    } finally {
      emailService.sendVerificationEmail = original;
    }
    const id = await realmId();
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      id,
      'password',
      EMAIL
    );
    if (!credential) throw new Error('the registration left no password credential');
    const client = await app().repositories.oauthClients.create({
      realmId: id,
      clientId: AUTHORIZE_REQUEST.client_id,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Email code client',
      redirectUris: [AUTHORIZE_REQUEST.redirect_uri],
      scopes: ['openid', 'email'],
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
      provisionedByOperator: true,
    });
    await app().repositories.oauthConsents.upsertGrant(id, credential.userId, client.id, [
      'openid',
      'email',
    ]);
    return credential.userId;
  }

  /** Whether {@link EMAIL}'s password credential says its address is verified. */
  async function addressVerified(): Promise<boolean> {
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      await realmId(),
      'password',
      EMAIL
    );
    return (credential?.credentialData as { email_verified?: boolean })?.email_verified === true;
  }

  /** Set the realm's `accounts.requireVerifiedAccount`, as an operator's policy patch does. */
  async function requireVerifiedAccount(required: boolean): Promise<void> {
    const id = await realmId();
    const current = await app().policyStore.get(id);
    if (current === undefined) throw new Error('no policies for the default realm');
    await app().policyStore.update(
      id,
      { accounts: { requireVerifiedAccount: required } },
      { expectedVersion: current.version }
    );
    app().realmHostCache.clear();
  }

  /**
   * Wait until `count` codes went to `to`, and return the last. The deadline
   * is on the monotonic clock: a test may hold `Date.now` still.
   */
  async function mailedCode(to: string, count: number): Promise<string> {
    const deadline = performance.now() + 5_000;
    while ((codes.get(to)?.length ?? 0) < count && performance.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const mailed = codes.get(to) ?? [];
    expect(mailed).toHaveLength(count);
    return mailed[count - 1] as string;
  }

  beforeEach(async (ctx) => {
    if (!dockerUp || !infra || !jwt) {
      ctx.skip();
      return;
    }
    codes.clear();
    server = await bootAuthServer(baseEnvironment(infra, jwt), { routes: startRoute });
    await resetE2eState(server.app);
    const { emailService } = server.app;
    const original = emailService.sendEngineMail.bind(emailService);
    emailService.sendEngineMail = async (realm, to, mail: EngineMail, context) => {
      if (mail.template === 'code') codes.set(to, [...(codes.get(to) ?? []), mail.code]);
      return original(realm, to, mail, context);
    };
    await server.app.listen({ port: 0, host: '127.0.0.1' });
    port = (server.app.server.address() as AddressInfo).port;
  }, 120_000);

  afterEach(async () => {
    vi.restoreAllMocks();
    await server?.close();
    server = undefined;
  });

  /** A new interaction of {@link EMAIL}, answered up to the code its correct password mailed. */
  async function atCodeStep(
    browser: Browser,
    mailed: number
  ): Promise<{ id: string; code: string }> {
    const id = await browser.start();
    const identified = await browser.answer(id, IDENTIFIER, { login_hint: EMAIL });
    expect(identified.status, identified.body).toBe(303);
    const password = await browser.answer(id, PASSWORD, { password: E2E_PASSWORD });
    expect(password.status, password.body).toBe(303);
    expect(password.headers.location).toBe(`${ORIGIN}${CEREMONY_PAGE_PREFIX}${id}`);
    return { id, code: await mailedCode(EMAIL, mailed) };
  }

  /** A six-digit code that is not `code`. */
  const wrong = (code: string) => (code === '000000' ? '111111' : '000000');

  it('signs an unverified account in with no code while the realm’s gate is off (ADR-017 Decision 8, amended 2026-11-08)', async () => {
    await registerUnverified();
    await requireVerifiedAccount(false);
    const browser = new Browser(port);
    const id = await browser.start();
    const identified = await browser.answer(id, IDENTIFIER, { login_hint: EMAIL });
    expect(identified.status, identified.body).toBe(303);
    const done = await browser.answer(id, PASSWORD, { password: E2E_PASSWORD });
    expect(done.status, done.body).toBe(303);
    const location = new URL(String(done.headers.location));
    expect(`${location.origin}${location.pathname}`).toBe(AUTHORIZE_REQUEST.redirect_uri);
    expect(location.searchParams.get('code')).toMatch(/.+/);
    expect(codes.get(EMAIL) ?? []).toEqual([]);
    expect(await addressVerified()).toBe(false);
  });

  it.each([true])(
    'offers the email_code step after the correct password of an unverified account under the realm’s gate (REQUIRE_VERIFIED_ACCOUNT %s)',
    async (required) => {
      await registerUnverified();
      await requireVerifiedAccount(required);
      const browser = new Browser(port);
      const { id, code } = await atCodeStep(browser, 1);
      const read = await browser.read(id);
      expect(read.step).toBe(EMAIL_CODE);
      expect(read.params?.[EMAIL_CODE]).toEqual({
        purpose: 'verify_account',
        length: 6,
        expires_in: 600,
        resend_after: 60,
      });
      expect(code).toMatch(/^[0-9]{6}$/);
      expect(await addressVerified()).toBe(false);

      // The right code verifies the address and completes the sign-in.
      const done = await browser.answer(id, EMAIL_CODE, { otp: code });
      expect(done.status, done.body).toBe(303);
      const location = new URL(String(done.headers.location));
      expect(`${location.origin}${location.pathname}`).toBe(AUTHORIZE_REQUEST.redirect_uri);
      expect(location.searchParams.get('code')).toMatch(/.+/);
      expect(await addressVerified()).toBe(true);
    }
  );

  it('refuses the next attempt inside the wait after 5 wrong codes across transactions, and accepts a correct code outside it', async () => {
    await registerUnverified();
    // One instant for the whole run, moved by hand: the wait the 5th wrong
    // code sets (one second) neither passes nor is missed by chance.
    let now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);

    // Transaction A: four wrong codes, each refused with invalid_credentials.
    const first = new Browser(port);
    const a = await atCodeStep(first, 1);
    for (let attempt = 1; attempt <= 4; attempt++) {
      const refused = await first.answer(a.id, EMAIL_CODE, { otp: wrong(a.code) });
      expect(refused.status, refused.body).toBe(303);
      const read = await first.read(a.id);
      expect(read).toMatchObject({ step: EMAIL_CODE, error: 'invalid_credentials' });
    }

    // Transaction B: a new sign-in, a new code; its first wrong code is the
    // account's 5th.
    const second = new Browser(port);
    const b = await atCodeStep(second, 2);
    const fifth = await second.answer(b.id, EMAIL_CODE, { otp: wrong(b.code) });
    expect(fifth.status, fifth.body).toBe(303);
    expect(await second.read(b.id)).toMatchObject({ error: 'invalid_credentials' });

    // The 5th wrong code passed the email-code ladder's free failures (a soft
    // threshold, PRO-12): the next round asks for the bot challenge before
    // its answer is read (#643, rule 5), and the code step resumes after it.
    const challenged = await second.answer(b.id, EMAIL_CODE, { otp: b.code });
    expect(challenged.status, challenged.body).toBe(303);
    const offered = await second.read(b.id);
    expect(offered.step).toBe(CAPTCHA);
    const params = offered.params?.[CAPTCHA] as unknown as ProofOfWorkParams;
    expect(params).toMatchObject({ provider: 'pow', difficulty: 18 });
    const failed = await second.answer(b.id, CAPTCHA, { captcha_token: 'not-a-solution' });
    expect(failed.status, failed.body).toBe(303);
    const again = await second.read(b.id);
    expect(again).toMatchObject({ step: CAPTCHA, error: 'captcha_failed' });
    const solution = await solveProofOfWork(
      again.params?.[CAPTCHA] as unknown as ProofOfWorkParams
    );
    const passed = await second.answer(b.id, CAPTCHA, { captcha_token: solution });
    expect(passed.status, passed.body).toBe(303);
    expect((await second.read(b.id)).step).toBe(EMAIL_CODE);
    expect(await addressVerified()).toBe(false);

    // Inside the wait the right code is refused, neither compared nor counted.
    const waited = await second.answer(b.id, EMAIL_CODE, { otp: b.code });
    expect(waited.status, waited.body).toBe(429);
    expect(waited.headers['retry-after']).toBe('1');
    expect(await addressVerified()).toBe(false);
    expect((await second.read(b.id)).step).toBe(EMAIL_CODE);

    // Outside the wait the right code is accepted.
    now += 2_000;
    const done = await second.answer(b.id, EMAIL_CODE, { otp: b.code });
    expect(done.status, done.body).toBe(303);
    const location = new URL(String(done.headers.location));
    expect(`${location.origin}${location.pathname}`).toBe(AUTHORIZE_REQUEST.redirect_uri);
    expect(await addressVerified()).toBe(true);
  });
});
