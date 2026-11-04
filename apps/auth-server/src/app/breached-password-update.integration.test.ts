import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

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
 * THE BREACH LIST AND THE FORCED PASSWORD UPDATE ON A REAL REDIS AND POSTGRES
 * (#635, ADR-018 §3, ADR-020 §3, ADR-017 Decision 8;
 * `libs/server/sign-in-engine` README, "The forced password update").
 *
 * Each test drives the real auth server, with the real sign-in engine, the
 * mail service, the event store and a breach list file the deployment names in
 * `BREACHED_PASSWORD_LIST_PATH`, through the Interaction API with plain form
 * posts. The file is written before the server boots, because the server reads
 * it at boot. It proves, end to end:
 *
 * - with the realm's `password.breachListSource` at its default, `off`, a
 *   listed password signs in directly and nothing is mailed;
 * - with `local`, a listed password that proved the account does not complete
 *   the sign-in: the account's mailbox is proved first (an 8-digit
 *   `recovery` code), an answer to `new_password` before it is ignored, a
 *   listed new password is refused as `blocklisted`, a good one is written
 *   and completes the sign-in, and the next sign-in asks for nothing;
 * - an `update_password` required action does the same for a password that is
 *   not listed, and the update removes the action;
 * - `POST /auth/register` refuses a listed password with a 422 before it
 *   creates anything;
 * - a check that cannot be made (`k_anonymity` with no range URL) never blocks
 *   a sign-in and is recorded as `user.password_breach_check_failed`.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
const HOST = 'auth.example.com';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const EMAIL_CODE = stepUrn('email_code');
const NEW_PASSWORD = stepUrn('new_password');

/** A password the deployment's breach list holds; long enough for the realm's policy. */
const LISTED_PASSWORD = 'Tangerine-Quartz-Lantern-Orbit-58!';
/** Another listed password, the one a user tries to change to. */
const LISTED_NEW_PASSWORD = 'Marble-Copper-Harbour-Violin-73?';
/** A password the list does not hold, that the realm's policy accepts. */
const GOOD_NEW_PASSWORD = 'Willow-Anvil-Meadow-Sextant-26#';

/** The variables this suite sets beyond the harness's, removed when it ends. */
const SUITE_KEYS = [
  'REGISTRATION_RATE_LIMIT',
  'VERIFICATION_RATE_LIMIT',
  'BREACHED_PASSWORD_LIST_PATH',
  'BREACHED_PASSWORD_RANGE_URL',
];

const AUTHORIZE_REQUEST = {
  response_type: 'code' as const,
  client_id: 'breach-list-client',
  redirect_uri: 'https://client.example.com/callback',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256' as const,
  state: 'af0ifjsldkj',
  scope: 'openid email',
  resource: undefined,
};

/** The SHA-1 of a password as the list file holds it: 40 uppercase hex characters. */
function sha1Of(password: string): string {
  return createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
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

/** Where an answer sent the browser, as a URL. */
function locationOf(answer: Answer): URL {
  expect(answer.status, answer.body).toBe(303);
  return new URL(String(answer.headers.location));
}

/** Assert that an answer completed the sign-in: a redirect to the client with an authorization code. */
function expectCompleted(answer: Answer): void {
  const location = locationOf(answer);
  expect(`${location.origin}${location.pathname}`).toBe(AUTHORIZE_REQUEST.redirect_uri);
  expect(location.searchParams.get('code')).toMatch(/.+/);
}

/** Assert that an answer did not complete the sign-in: the browser goes on at the ceremony page. */
function expectNotCompleted(answer: Answer, id: string): void {
  expect(locationOf(answer).href).toBe(`${ORIGIN}${CEREMONY_PAGE_PREFIX}${id}`);
}

describe('the breach list and the forced password update (#635, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let server: BootedAuthServer | undefined;
  let listDirectory: string | undefined;
  let port = 0;
  /** The codes mailed to each address, in order. */
  const codes = new Map<string, string[]>();

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();

    // The server reads the operator's list at boot, so the file is written
    // first: two passwords of the suite among others, one with the optional
    // `:count` the public lists carry.
    listDirectory = await mkdtemp(join(tmpdir(), 'qauth-breach-list-'));
    const listPath = join(listDirectory, 'breached-passwords.txt');
    await writeFile(
      listPath,
      [
        sha1Of('password'),
        `${sha1Of(LISTED_PASSWORD)}:42`,
        sha1Of('correct horse battery staple'),
        sha1Of(LISTED_NEW_PASSWORD),
        '',
      ].join('\n'),
      'utf8'
    );

    // The harness leaves these two alone between boots: a value an earlier
    // file in this worker set must not make the range lookup configured.
    delete process.env['BREACHED_PASSWORD_RANGE_URL'];
    server = await bootAuthServer(
      {
        ...baseEnvironment(infra, jwt),
        // Sized for humans; a test registers several accounts from one address.
        REGISTRATION_RATE_LIMIT: '1000',
        VERIFICATION_RATE_LIMIT: '1000',
        BREACHED_PASSWORD_LIST_PATH: listPath,
      },
      { routes: startRoute }
    );
    const { emailService } = server.app;
    const original = emailService.sendEngineMail.bind(emailService);
    emailService.sendEngineMail = async (realm, to, mail: EngineMail, context) => {
      if (mail.template === 'code') codes.set(to, [...(codes.get(to) ?? []), mail.code]);
      return original(realm, to, mail, context);
    };
    await server.app.listen({ port: 0, host: '127.0.0.1' });
    port = (server.app.server.address() as AddressInfo).port;
  }, 240_000);

  afterAll(async () => {
    await server?.close();
    await infra?.teardown();
    if (listDirectory !== undefined) await rm(listDirectory, { recursive: true, force: true });
    for (const key of SUITE_KEYS) delete process.env[key];
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || server === undefined) {
      ctx.skip();
      return;
    }
    codes.clear();
    // The boot step puts the default realm back, with the policies' defaults.
    await resetE2eState(server.app);
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

  /** Set the realm's `password.breachListSource`, as an operator's policy patch does. */
  async function setBreachListSource(source: 'off' | 'local' | 'k_anonymity'): Promise<void> {
    const id = await realmId();
    const current = await app().policyStore.get(id);
    if (current === undefined) throw new Error('no policies for the default realm');
    await app().policyStore.update(
      id,
      { password: { breachListSource: source } },
      { expectedVersion: current.version }
    );
    app().realmHostCache.clear();
  }

  /**
   * A verified password account, and the client with the user's stored
   * consent, so a completed sign-in redirects to the client at once.
   *
   * @returns the account's `users.id`
   */
  async function accountWithConsent(email: string, password: string): Promise<string> {
    const userId = await registerPasswordAccount(app(), email, password);
    const id = await realmId();
    const client = await app().repositories.oauthClients.create({
      realmId: id,
      clientId: AUTHORIZE_REQUEST.client_id,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Breach list client',
      redirectUris: [AUTHORIZE_REQUEST.redirect_uri],
      scopes: ['openid', 'email'],
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
      provisionedByOperator: true,
    });
    await app().repositories.oauthConsents.upsertGrant(id, userId, client.id, ['openid', 'email']);
    return userId;
  }

  /**
   * Wait until `count` codes went to `to`, and return the last. The deadline
   * is on the monotonic clock.
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

  /** A new interaction of `email`, answered up to and including its password. */
  async function signInWithPassword(
    browser: Browser,
    email: string,
    password: string
  ): Promise<{ id: string; answer: Answer }> {
    const id = await browser.start();
    const identified = await browser.answer(id, IDENTIFIER, { login_hint: email });
    expect(identified.status, identified.body).toBe(303);
    return { id, answer: await browser.answer(id, PASSWORD, { password }) };
  }

  /**
   * The sign-in of an account whose password update is due, up to the step
   * that asks for the new password: the password, the 8-digit `recovery`
   * code it mails, an eager answer to `new_password` that is ignored, and
   * the right code.
   */
  async function toNewPasswordStep(
    browser: Browser,
    email: string,
    password: string
  ): Promise<string> {
    const { id, answer } = await signInWithPassword(browser, email, password);
    expectNotCompleted(answer, id);
    const read = await browser.read(id);
    expect(read.step).toBe(EMAIL_CODE);
    expect(read.params?.[EMAIL_CODE]).toMatchObject({ purpose: 'recovery', length: 8 });
    const code = await mailedCode(email, 1);
    expect(code).toMatch(/^[0-9]{8}$/);

    // A new password before the mailbox is proved is not read: the code step
    // is offered again, and nothing is written.
    const eager = await browser.answer(id, NEW_PASSWORD, { new_password: GOOD_NEW_PASSWORD });
    expect(eager.headers.location ?? '').not.toContain(AUTHORIZE_REQUEST.redirect_uri);
    expect((await browser.read(id)).step).toBe(EMAIL_CODE);

    const proved = await browser.answer(id, EMAIL_CODE, { otp: code });
    expectNotCompleted(proved, id);
    const next = await browser.read(id);
    expect(next.step).toBe(NEW_PASSWORD);
    expect(next.params?.[NEW_PASSWORD]).toMatchObject({
      purpose: 'update_required',
      min_length: 15,
      max_length: 256,
    });
    return id;
  }

  /** The stored `user.password_breach_check_failed` events of `userId`, waited for until one exists. */
  async function breachCheckFailures(
    userId: string
  ): Promise<{ subject_id: string | null; data: Record<string, unknown> }[]> {
    const deadline = performance.now() + 5_000;
    for (;;) {
      const { rows } = await app().dbPool.query<{
        subject_id: string | null;
        data: Record<string, unknown>;
      }>(`SELECT subject_id, data FROM events WHERE type = $1 AND subject_id = $2`, [
        'urn:qauth:event:user.password_breach_check_failed:v1-rc.0',
        userId,
      ]);
      if (rows.length > 0 || performance.now() >= deadline) return rows;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  it('signs in directly with a listed password while the realm setting is off, mailing nothing', async () => {
    const email = 'listed-off@example.com';
    await accountWithConsent(email, LISTED_PASSWORD);

    const { answer } = await signInWithPassword(new Browser(port), email, LISTED_PASSWORD);

    expectCompleted(answer);
    expect(codes.size).toBe(0);
  });

  it('asks a listed password for a mailbox code and a new password before it completes, then signs in directly with the new one', async () => {
    const email = 'listed-local@example.com';
    await accountWithConsent(email, LISTED_PASSWORD);
    await setBreachListSource('local');

    const browser = new Browser(port);
    const id = await toNewPasswordStep(browser, email, LISTED_PASSWORD);

    // A new password on the list is asked for again, with its reason.
    const refused = await browser.answer(id, NEW_PASSWORD, { new_password: LISTED_NEW_PASSWORD });
    expectNotCompleted(refused, id);
    const again = await browser.read(id);
    expect(again.step).toBe(NEW_PASSWORD);
    expect(again.error).toBe('password_rejected');
    expect(again.params?.[NEW_PASSWORD]).toMatchObject({ reasons: ['blocklisted'] });

    // A good one is written, and the sign-in completes.
    const done = await browser.answer(id, NEW_PASSWORD, { new_password: GOOD_NEW_PASSWORD });
    expectCompleted(done);

    // The next sign-in, with the new password, asks for nothing more.
    const next = await signInWithPassword(new Browser(port), email, GOOD_NEW_PASSWORD);
    expectCompleted(next.answer);
    expect(codes.get(email)).toHaveLength(1);
  });

  it('asks for the update an update_password required action requires of an unlisted password, and removes the action once it is done', async () => {
    const email = 'required-action@example.com';
    const userId = await accountWithConsent(email, E2E_PASSWORD);
    const id = await realmId();
    await setBreachListSource('local');
    await app().repositories.userRequiredActions.add({
      realmId: id,
      userId,
      action: 'update_password',
      source: 'admin',
    });

    const browser = new Browser(port);
    const interaction = await toNewPasswordStep(browser, email, E2E_PASSWORD);
    const done = await browser.answer(interaction, NEW_PASSWORD, {
      new_password: GOOD_NEW_PASSWORD,
    });
    expectCompleted(done);
    expect(await app().repositories.userRequiredActions.listForUser(id, userId)).toEqual([]);

    const next = await signInWithPassword(new Browser(port), email, GOOD_NEW_PASSWORD);
    expectCompleted(next.answer);
    expect(codes.get(email)).toHaveLength(1);
  });

  it('refuses the registration of a listed password with a 422, creating no account', async () => {
    const email = 'register-listed@example.com';
    await setBreachListSource('local');

    const response = await app().inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: LISTED_PASSWORD },
    });

    expect(response.statusCode, response.body).toBe(422);
    expect(response.json<{ code: string; reasons: string[] }>()).toMatchObject({
      code: 'weak_password',
    });
    expect(response.json<{ reasons: string[] }>().reasons).toContain('blocklisted');
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      await realmId(),
      'password',
      email
    );
    expect(credential).toBeUndefined();
  });

  it('lets a sign-in through when the k-anonymity lookup is not configured, and records the failed check', async () => {
    const email = 'k-anonymity-unconfigured@example.com';
    const userId = await accountWithConsent(email, E2E_PASSWORD);
    await setBreachListSource('k_anonymity');

    const { answer } = await signInWithPassword(new Browser(port), email, E2E_PASSWORD);

    expectCompleted(answer);
    expect(codes.size).toBe(0);
    const failures = await breachCheckFailures(userId);
    expect(failures).toHaveLength(1);
    expect(failures[0]?.data).toMatchObject({ reason: 'not_configured' });
  });
});
