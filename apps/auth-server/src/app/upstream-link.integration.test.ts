import { createHmac, randomBytes } from 'node:crypto';

import { createTestEgressClient } from '@qauth-labs/fastify-plugin-egress';
import {
  type LocalHttpsFixture,
  startLocalHttpsFixture,
} from '@qauth-labs/fastify-plugin-egress/src/testing/egress-fixtures';
import type { EngineMail } from '@qauth-labs/fastify-plugin-email';
import {
  createFakeProvider,
  type FakeProvider,
  type FakeSignIn,
  sealUpstreamOidcConfig,
  type UpstreamOidcConfigInput,
} from '@qauth-labs/fastify-plugin-federation/src/testing/upstream-oidc-fixtures';
import type { MfaPolicyReader } from '@qauth-labs/fastify-plugin-sign-in-engine';
import * as accountContract from '@qauth-labs/shared-account-contract';
import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  decodeHtmlEntities,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { SESSION_COOKIE } from '../testing/session-cookie-value';
import type { BackgroundTasks } from './helpers/background-tasks';
import type { InteractionEngines } from './helpers/interaction-engines';

/**
 * LINKING AN UPSTREAM ACCOUNT TO AN EXISTING ONE (#670; ADR-020 §3, NIST SP
 * 800-63C-4 §5.4), end to end against real Postgres and Redis, with the
 * Interaction API on and sign-up on.
 *
 * The provider is the fake OpenID Provider of the upstream OIDC library on a
 * local HTTPS fixture, as in `upstream-sign-in.integration.test.ts`; the
 * browser is a cookie jar, and the ceremony page's answers are plain form
 * posts. The account to link to is a verified password account.
 *
 * Covers the acceptance criteria of #670:
 *
 * - the first upstream sign-in of an unknown identity asks at the
 *   `upstream_link` step; "I already have an account" goes on to a sign-in
 *   to that account, and the identity joins it once that sign-in succeeds
 *   (the E2E criterion: the choice, the sign-in, the link);
 * - a signed-in account links one through `qauth_link`: its session is not
 *   enough, the account signs in again;
 * - the provider's answer in another browser, and a sign-in in another
 *   interaction, link nothing;
 * - an identity another account holds is refused, at the callback and when
 *   another account takes it while the person signs in;
 * - with MFA required the link asks for the second factor before it links;
 * - an unlink needs a fresh sign-in, and the last way to sign in stays;
 * - a link and an unlink each mail the owner and write the event the
 *   security log reads.
 *
 * No page and no step view shows the account's email address, and nothing
 * finds the account by it: the unit tests of `helpers/upstream-links.ts`
 * and `helpers/upstream-sign-in.ts` prove the reads.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
/** An operator-flagged first-party client (`web_redirect`), as the account console is. */
const CLIENT_ID = 'portal';
const REDIRECT_URI = 'https://portal.example.com/auth/callback';
/** A public key the client authenticates with; no test here reaches the token endpoint. */
const CLIENT_JWKS = {
  keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
};
const STATE = 'link-state';

const TYPE = 'oidc_corp';
const PROVIDER_NAME = 'Corp';
/** QAuth's registration at the fake provider. */
const UPSTREAM_CLIENT_ID = 'qauth-corp';
const UPSTREAM_CLIENT_SECRET = 'an-upstream-client-secret-of-some-length-0042';

/** The account to link to: a password account. */
const EMAIL = 'grace@example.com';
/**
 * The person at the provider: the same address as the account, which must
 * not matter, since nothing matches by it.
 */
const PERSON: FakeSignIn = {
  sub: 'corp-user-1',
  claims: { email: EMAIL, email_verified: true, name: 'Grace Hopper' },
};

/** The page titles and texts of `helpers/upstream-pages.ts`, written out: app modules read the environment at import. */
const WAITING_TITLE = 'Continuing to your sign-in provider';
const ERROR_TITLE = 'We could not sign you in';
const LINK_REFUSED_TITLE = 'The account was not linked';

const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const TOTP = stepUrn('totp');
const UPSTREAM = stepUrn('upstream');
const UPSTREAM_LINK = stepUrn('upstream_link');
const LINKED = 'urn:qauth:event:user.upstream_linked:v1-rc.0';
const UNLINKED = 'urn:qauth:event:user.upstream_unlinked:v1-rc.0';
const LINK_FAILED = 'urn:qauth:event:user.upstream_link_failed:v1-rc.0';
const SIGN_IN_FAILED = 'urn:qauth:event:user.sign_in_failed:v1-rc.0';
const SIGNED_IN = 'urn:qauth:event:user.signed_in:v1-rc.0';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
/** An interaction id: 43 base64url characters. */
const INTERACTION_ID = /^[A-Za-z0-9_-]{43}$/;
const TOTP_STEP_MS = 30_000;
const POLICY_OFF = Object.freeze({ realm: 'off', client: 'off' }) as Awaited<
  ReturnType<MfaPolicyReader['read']>
>;
const POLICY_REQUIRED = Object.freeze({ realm: 'required', client: 'off' }) as Awaited<
  ReturnType<MfaPolicyReader['read']>
>;
/** The background tasks of the recovery-code port this suite builds: run now, failures dropped. */
const TASKS: BackgroundTasks = {
  run: (task) => {
    void Promise.resolve()
      .then(task)
      .catch(() => undefined);
  },
};

/** The step view the ceremony page reads. */
interface StepView {
  readonly step: string;
  readonly csrf: string;
  readonly alternatives?: readonly string[];
  readonly params?: Record<string, unknown>;
  readonly upstreamLink?: { readonly provider: string; readonly name: string };
}

/** The callback URL the provider sends the browser back to. */
const CALLBACK_URL = `${ORIGIN}/upstream/${TYPE}/callback`;

/** The path and query of a location, relative or on the realm origin. */
function pathOf(location: unknown): string {
  const url = new URL(String(location), ORIGIN);
  expect(url.origin).toBe(ORIGIN);
  return `${url.pathname}${url.search}`;
}

/** The interaction id of a ceremony page location. */
function ceremonyIdOf(location: unknown): string {
  const path = pathOf(location);
  expect(path.startsWith(CEREMONY_PAGE_PREFIX), path).toBe(true);
  const id = path.slice(CEREMONY_PAGE_PREFIX.length);
  expect(id).toMatch(INTERACTION_ID);
  return id;
}

/** The code a redirect to the client carries, with the request's `state` and `iss`. */
function codeAt(location: unknown): string {
  const url = new URL(String(location));
  expect(`${url.origin}${url.pathname}`).toBe(REDIRECT_URI);
  expect(url.searchParams.get('state')).toBe(STATE);
  expect(url.searchParams.get('iss')).toBe(ORIGIN);
  const code = url.searchParams.get('code');
  expect(code).toMatch(/.+/);
  return code as string;
}

/** The authenticator app: the RFC 6238 code (SHA-1, six digits, 30 s) of `secret` at `at`. */
function totpCodeAt(secret: Buffer, at: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / TOTP_STEP_MS)));
  const mac = createHmac('sha1', secret).update(counter).digest();
  const offset = mac.readUInt8(19) & 0x0f;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

/** A sign-in `secondsAgo` old, as an account API token's `auth_time` keeps it: whole seconds, in ms. */
function signedInAgo(secondsAgo: number): number {
  return (Math.floor(Date.now() / 1000) - secondsAgo) * 1000;
}

describe('linking an upstream account to an existing one (#670, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let fixture: LocalHttpsFixture | undefined;
  let provider: FakeProvider;
  let engines: InteractionEngines | undefined;
  let dockerUp = false;
  let realmId = '';
  /** The MFA policy every round reads. */
  let policy = POLICY_OFF;
  /** The engine mails, in order: their address and their template. */
  const mails: { readonly to: string; readonly template: string }[] = [];
  /** The server's warnings and errors in the current test, to say why an answer was refused. */
  const serverLog: string[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    fixture = await startLocalHttpsFixture();
    const served = await createFakeProvider({ issuer: fixture.origin });
    served.register({
      clientId: UPSTREAM_CLIENT_ID,
      method: 'client_secret_basic',
      clientSecret: UPSTREAM_CLIENT_SECRET,
      redirectUris: [CALLBACK_URL],
    });
    const origin = fixture.origin;
    fixture.handler = (req, body, res) => {
      const headers = Object.fromEntries(
        Object.entries(req.headers).flatMap(([name, value]) =>
          typeof value === 'string' ? [[name, value]] : []
        )
      );
      served
        .answer({
          method: req.method ?? 'GET',
          url: `${origin}${req.url ?? '/'}`,
          headers,
          body: body.toString('utf8'),
        })
        .then(
          (answer) => {
            res.writeHead(answer.status, answer.headers);
            res.end(Buffer.from(answer.body));
          },
          () => {
            res.writeHead(500);
            res.end();
          }
        );
    };
    provider = served;

    booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, await generateJwtPem()),
        INTERACTION_UI_ENABLED: 'true',
        ALLOW_SIGN_UP: 'true',
        // Each test registers its accounts and runs several authorization
        // requests from one address.
        REGISTRATION_RATE_LIMIT: '10000',
        AUTHORIZE_RATE_LIMIT: '10000',
        AUTHORIZE_RATE_LIMIT_LENIENT: '10000',
      },
      {
        egressClientFactory: createTestEgressClient,
        logStream: { write: (line: string) => void serverLog.push(line) },
        mfaPolicy: { read: async () => policy },
      }
    );
    const { emailService } = booted.app;
    const original = emailService.sendEngineMail.bind(emailService);
    emailService.sendEngineMail = async (realm, to, mail: EngineMail, context) => {
      mails.push({ to, template: mail.template });
      return original(realm, to, mail, context);
    };
    // Imported after the boot, as the harness imports the app: the modules
    // read the environment the boot sets, and share the app's instances.
    const { createInteractionEngines } = await import('./helpers/interaction-engines');
    engines = createInteractionEngines(booted.app, { tasks: TASKS });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await fixture?.close();
    await infra?.teardown();
  });

  afterEach(() => {
    policy = POLICY_OFF;
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    const app = booted.app;
    await resetE2eState(app);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
    await app.repositories.oauthClients.create({
      realmId,
      clientId: CLIENT_ID,
      clientSecretHash: 'unused',
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwks: CLIENT_JWKS,
      name: 'Developer Portal',
      redirectUris: [REDIRECT_URI],
      scopes: ['openid', 'email'],
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
    });
    // The operator flags it first-party (ADR-017 Decision 2): only such a
    // client may ask for a link, and its codes need no consent screen.
    await app.dbPool.query(
      `UPDATE oauth_clients
          SET first_party_profile = 'web_redirect', first_party_reason = 'The developer portal.'
        WHERE client_id = $1`,
      [CLIENT_ID]
    );
    const config: UpstreamOidcConfigInput = {
      issuer: provider.issuer,
      clientId: UPSTREAM_CLIENT_ID,
      clientAuthentication: { method: 'client_secret_basic', clientSecret: UPSTREAM_CLIENT_SECRET },
    };
    await app.repositories.realmUpstreamProviders.create({
      realmId,
      type: TYPE,
      displayName: PROVIDER_NAME,
      displayOrder: 0,
      hidden: false,
      enabled: true,
      marksVerified: true,
      config: await sealUpstreamOidcConfig(
        app.signer,
        { realmId, providerId: TYPE, caller: 'api' },
        config
      ),
    });
    mails.length = 0;
    serverLog.length = 0;
  }, 120_000);

  function app(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /** `body`, with the server's warnings and errors of this test after it. */
  function withServerLog(body: string): string {
    return serverLog.length === 0 ? body : `${body}\nserver log:\n${serverLog.join('')}`;
  }

  /** A GET from the browser holding `jar`, which keeps what the answer sets. */
  async function get(jar: CookieJar, url: string): Promise<LightMyRequestResponse> {
    const cookie = jar.header();
    const response = await app().inject({
      method: 'GET',
      url,
      headers: cookie === undefined ? {} : { cookie },
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** The client's authorization request, with `extra` parameters. */
  function authorizeUrl(extra: Record<string, string> = {}): string {
    return `/oauth/authorize?${new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid email',
      code_challenge: pkcePair().challenge,
      code_challenge_method: 'S256',
      state: STATE,
      ...extra,
    }).toString()}`;
  }

  /** The step read, as the ceremony app's server makes it: the id alone, no cookie. */
  async function read(id: string): Promise<StepView> {
    const response = await app().inject({ method: 'GET', url: `${INTERACTION_API_PREFIX}/${id}` });
    expect(response.statusCode, withServerLog(response.body)).toBe(200);
    return response.json();
  }

  /** Answer the current step of `id` with a form post from the ceremony page in the browser holding `jar`. */
  async function answer(
    jar: CookieJar,
    id: string,
    type: string,
    fields: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    const { csrf } = await read(id);
    const response = await app().inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${id}/answer`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: jar.header() ?? '' },
      payload: new URLSearchParams({ type, csrf, ...fields }).toString(),
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** Answer a step that leads to another: `303` back to the ceremony page of `id`. */
  async function answerToNext(
    jar: CookieJar,
    id: string,
    type: string,
    fields: Record<string, string> = {}
  ): Promise<StepView> {
    const response = await answer(jar, id, type, fields);
    expect(response.statusCode, withServerLog(response.body)).toBe(303);
    expect(ceremonyIdOf(response.headers['location'])).toBe(id);
    return read(id);
  }

  /** The identifier and the password of `email` at the interaction `id`: the answer to the password. */
  async function signInWithPassword(
    jar: CookieJar,
    id: string,
    email = EMAIL
  ): Promise<LightMyRequestResponse> {
    expect((await read(id)).step).toBe(IDENTIFIER);
    const next = await answerToNext(jar, id, IDENTIFIER, { login_hint: email });
    expect(next.step).toBe(PASSWORD);
    return answer(jar, id, PASSWORD, { password: E2E_PASSWORD });
  }

  /** A sign-in to the account in the browser holding `jar`, which then holds its session. */
  async function signIn(jar: CookieJar): Promise<void> {
    const ceremony = await get(jar, authorizeUrl());
    expect(ceremony.statusCode, withServerLog(ceremony.body)).toBe(302);
    const done = await signInWithPassword(jar, ceremonyIdOf(ceremony.headers['location']));
    expect(done.statusCode, withServerLog(done.body)).toBe(303);
    codeAt(done.headers['location']);
    expect(jar.get(SESSION_COOKIE)).toBeDefined();
  }

  /** A provider started for a request: its interaction and the provider's authorization request. */
  interface Started {
    readonly interactionId: string;
    readonly providerRequest: URL;
  }

  /**
   * The authorization request with `extra` (`qauth_upstream` or
   * `qauth_link`), its redirect to the provider's start and the waiting
   * page, whose link is the provider's authorization request.
   */
  async function startProvider(jar: CookieJar, extra: Record<string, string>): Promise<Started> {
    const routed = await get(jar, authorizeUrl(extra));
    expect(routed.statusCode, withServerLog(routed.body)).toBe(302);
    const start = new URL(String(routed.headers['location']), ORIGIN);
    expect(start.pathname).toBe(`/ui/upstream/${TYPE}/start`);
    const interactionId = start.searchParams.get('interaction') ?? '';
    expect(interactionId).toMatch(INTERACTION_ID);
    const page = await get(jar, `${start.pathname}${start.search}`);
    expect(page.statusCode, withServerLog(page.body)).toBe(200);
    expect(page.body).toContain(WAITING_TITLE);
    const link = /<a class="alt-action" href="([^"]+)"/.exec(page.body)?.[1];
    if (link === undefined) throw new Error('no provider link on the waiting page');
    const providerRequest = new URL(decodeHtmlEntities(link));
    expect(`${providerRequest.origin}${providerRequest.pathname}`).toBe(
      provider.authorizationEndpoint
    );
    return { interactionId, providerRequest };
  }

  /** The provider's callback with the response `params`, from the browser holding `jar`. */
  function callbackAt(jar: CookieJar, params: Record<string, string>) {
    return get(jar, `/upstream/${TYPE}/callback?${new URLSearchParams(params).toString()}`);
  }

  /** Start the provider with `extra`, sign `person` in at it, and come back to the callback. */
  async function throughProvider(
    jar: CookieJar,
    extra: Record<string, string>,
    person: FakeSignIn = PERSON
  ): Promise<LightMyRequestResponse> {
    const started = await startProvider(jar, extra);
    const answered = provider.authorize(started.providerRequest, person);
    expect(answered['error']).toBeUndefined();
    return callbackAt(jar, answered);
  }

  /**
   * A first upstream sign-in of an unknown identity, up to the choice: the
   * callback's `303` to the ceremony page, at the `upstream_link` step.
   */
  async function atChoice(jar: CookieJar, person: FakeSignIn = PERSON): Promise<string> {
    const callback = await throughProvider(jar, { qauth_upstream: TYPE }, person);
    expect(callback.statusCode, withServerLog(callback.body)).toBe(303);
    const id = ceremonyIdOf(callback.headers['location']);
    const choice = await read(id);
    expect(choice.step).toBe(UPSTREAM_LINK);
    return id;
  }

  /** "I already have an account" at the choice: the sign-in to the account's first step. */
  async function chooseLink(jar: CookieJar, id: string): Promise<StepView> {
    const next = await answerToNext(jar, id, UPSTREAM_LINK, { decision: 'link' });
    expect(next.step).toBe(IDENTIFIER);
    expect(next.upstreamLink).toEqual({ provider: TYPE, name: PROVIDER_NAME });
    return next;
  }

  async function count(sql: string, params: unknown[] = []): Promise<number> {
    const { rows } = await app().dbPool.query<{ count: string }>(sql, params);
    return Number(rows[0]?.count ?? 0);
  }

  const users = () => count('SELECT count(*) AS count FROM users');
  const upstreamCredentials = () =>
    count('SELECT count(*) AS count FROM user_credentials WHERE provider_type = $1', [TYPE]);
  const codes = () => count('SELECT count(*) AS count FROM authorization_codes');

  /** The events of `type`, oldest first: their subject and their data. */
  async function events(type: string) {
    const { rows } = await app().dbPool.query<{
      subject_id: string | null;
      data: Record<string, unknown>;
    }>('SELECT subject_id, data FROM events WHERE type = $1 ORDER BY seq', [type]);
    return rows;
  }

  /** The credential the provider's subject `sub` signs in with, if any. */
  function upstreamCredentialOf(sub = PERSON.sub) {
    return app().repositories.userCredentials.findByRealmProviderSub(realmId, TYPE, sub);
  }

  /** Give `userId` an identity of the provider, as a first sign-in or a link stores it. */
  async function holdIdentity(userId: string, sub = PERSON.sub): Promise<string> {
    const credential = await app().repositories.userCredentials.create({
      userId,
      realmId,
      providerType: TYPE,
      externalSub: sub,
      credentialData: { kind: 'upstream', iss: provider.issuer, verified: true },
    });
    return credential.id;
  }

  /** Wait for the engine mail of `template` to `to`: the notices go out after the answer. */
  async function expectMail(to: string, template: string): Promise<void> {
    const deadline = Date.now() + 5_000;
    while (
      !mails.some((mail) => mail.to === to && mail.template === template) &&
      Date.now() < deadline
    ) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(mails).toContainEqual({ to, template });
  }

  /**
   * Bind a TOTP to the account as a set-up stores it: a secret sealed by the
   * signer under the account's context, its last step two behind now, and,
   * with `recovery`, a confirmed recovery set beside it.
   */
  async function bindTotp(userId: string, recovery: boolean): Promise<Buffer> {
    const secret = randomBytes(20);
    const { totpSecretContext } = await import('./helpers/totp-sign-in');
    const sealed = await app().signer.encrypt('api', {
      realmId,
      plaintext: new Uint8Array(secret),
      context: totpSecretContext(realmId, userId),
    });
    const bound = await app().repositories.userCredentials.upsertTotp({
      realmId,
      userId,
      credentialData: { secret: sealed, last_step: Math.floor(Date.now() / TOTP_STEP_MS) - 2 },
      at: Date.now(),
    });
    expect(bound).toBeDefined();
    if (recovery) {
      if (engines === undefined) throw new Error('engines not built');
      const issued = await engines.recoveryCodes.issue({ realmId, userId });
      if (issued === null) throw new Error('no set issued');
      expect(await engines.recoveryCodes.confirm({ realmId, userId, setId: issued.setId })).toBe(
        true
      );
    }
    return secret;
  }

  /** An account API token, as the code exchange mints it for the account console. */
  function accountToken(
    userId: string,
    claims: { readonly authTime: number; readonly amr: readonly string[] }
  ): Promise<string> {
    return app().jwtUtils.signAccessToken(
      { id: realmId },
      {
        sub: userId,
        clientId: 'account-console',
        aud: accountContract.ACCOUNT_API_AUDIENCE,
        scope: 'qauth:account:read qauth:account:write',
        ...claims,
      }
    );
  }

  /** A call to the account API's linked accounts, `path` under them. */
  function linkedAccounts(
    method: 'GET' | 'DELETE',
    bearer: string,
    path = ''
  ): Promise<LightMyRequestResponse> {
    return app().inject({
      method,
      url: `${accountContract.ACCOUNT_API_PREFIX}/linked-accounts${path}`,
      headers: { authorization: `Bearer ${bearer}` },
    });
  }

  describe('from the first upstream sign-in (the E2E criterion)', () => {
    it('asks at the choice, signs in to the account and links the identity to it, with a notice and an event', async () => {
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const usersBefore = await users();
      const jar = new CookieJar();

      const id = await atChoice(jar);

      // The choice: the provider's name, and a new account the realm allows.
      const choice = await read(id);
      expect(choice.params?.[UPSTREAM_LINK]).toEqual({
        provider: { provider: TYPE, name: PROVIDER_NAME },
        create: true,
      });
      const page = await get(jar, `/ui/upstream-link/${id}`);
      expect(page.statusCode, withServerLog(page.body)).toBe(200);
      expect(page.headers['cache-control']).toBe('no-store');
      expect(page.body).toContain('I already have an account');
      expect(page.body).toContain('Create a new account');
      expect(page.body).toContain(PROVIDER_NAME);
      // The address the provider gave, which an account holds, is shown nowhere.
      expect(page.body).not.toContain(EMAIL);
      expect(JSON.stringify(choice)).not.toContain(EMAIL);
      expect(await upstreamCredentials()).toBe(0);

      // "I already have an account": the account's own sign-in, with no provider and no hint.
      const identifier = await chooseLink(jar, id);
      expect(identifier.alternatives ?? []).not.toContain(UPSTREAM);
      expect(JSON.stringify(identifier)).not.toContain(EMAIL);
      const password = await answerToNext(jar, id, IDENTIFIER, { login_hint: EMAIL });
      expect(password.step).toBe(PASSWORD);
      expect(await upstreamCredentials()).toBe(0);

      const done = await answer(jar, id, PASSWORD, { password: E2E_PASSWORD });

      expect(done.statusCode, withServerLog(done.body)).toBe(303);
      codeAt(done.headers['location']);
      const credential = await upstreamCredentialOf();
      expect(credential?.userId).toBe(ownerId);
      expect(credential?.credentialData).toEqual({
        kind: 'upstream',
        iss: provider.issuer,
        verified: true,
      });
      expect(await users()).toBe(usersBefore);
      // The link stores no claim of the provider as an attribute.
      expect(await app().repositories.userAttributes.findByUserIdAndSource(ownerId, TYPE)).toEqual(
        []
      );
      const linked = await events(LINKED);
      expect(linked).toHaveLength(1);
      expect(linked[0]?.subject_id).toBe(ownerId);
      expect(linked[0]?.data).toMatchObject({ provider: TYPE, credentialId: credential?.id });
      // The event is a source of the security log's `account_linked` entries.
      expect(
        accountContract.SECURITY_LOG_KINDS.account_linked.sources.map((source) => source.event)
      ).toContain('user.upstream_linked');
      await expectMail(EMAIL, 'upstream_linked');
      // The account API lists it.
      const listed = await linkedAccounts(
        'GET',
        await accountToken(ownerId, { authTime: signedInAgo(10), amr: ['pwd'] })
      );
      expect(listed.statusCode, listed.body).toBe(200);
      expect(listed.json().items).toEqual([
        {
          id: credential?.id,
          provider: TYPE,
          providerName: PROVIDER_NAME,
          createdAt: expect.any(String),
        },
      ]);

      // The provider now signs the owner in.
      const again = new CookieJar();
      const returning = await throughProvider(again, { qauth_upstream: TYPE });
      expect(returning.statusCode, withServerLog(returning.body)).toBe(303);
      codeAt(returning.headers['location']);
      expect((await events(SIGNED_IN)).map((event) => event.subject_id).at(-1)).toBe(ownerId);
    });

    it('creates a separate account on "Create a new account", the same address notwithstanding', async () => {
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const usersBefore = await users();
      const jar = new CookieJar();
      const id = await atChoice(jar);

      const created = await answer(jar, id, UPSTREAM_LINK, { decision: 'create' });

      expect(created.statusCode, withServerLog(created.body)).toBe(303);
      codeAt(created.headers['location']);
      expect(await users()).toBe(usersBefore + 1);
      expect((await upstreamCredentialOf())?.userId).not.toBe(ownerId);
      expect(await events(LINKED)).toEqual([]);
    });
  });

  describe('from a signed-in account (qauth_link)', () => {
    it('asks for a sign-in to the account, its session notwithstanding, and links only once it succeeds', async () => {
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const jar = new CookieJar();
      await signIn(jar);

      const callback = await throughProvider(jar, { qauth_link: TYPE });

      // The session is not a sign-in for the link: the account's first step.
      expect(callback.statusCode, withServerLog(callback.body)).toBe(303);
      const id = ceremonyIdOf(callback.headers['location']);
      const step = await read(id);
      expect(step.step).toBe(IDENTIFIER);
      expect(step.upstreamLink).toEqual({ provider: TYPE, name: PROVIDER_NAME });
      expect(step.alternatives ?? []).not.toContain(UPSTREAM);
      expect(await upstreamCredentials()).toBe(0);

      const done = await signInWithPassword(jar, id);

      expect(done.statusCode, withServerLog(done.body)).toBe(303);
      codeAt(done.headers['location']);
      expect((await upstreamCredentialOf())?.userId).toBe(ownerId);
      expect((await events(LINKED)).map((event) => event.subject_id)).toEqual([ownerId]);
      await expectMail(EMAIL, 'upstream_linked');
    });

    it('signs in without a link when the person comes back from the provider and signs in another way', async () => {
      await registerPasswordAccount(app(), EMAIL);
      const jar = new CookieJar();
      const started = await startProvider(jar, { qauth_link: TYPE });
      const cancelled = await callbackAt(jar, {
        error: 'access_denied',
        state: started.providerRequest.searchParams.get('state') ?? '',
        iss: provider.issuer,
      });
      expect(cancelled.statusCode, withServerLog(cancelled.body)).toBe(200);

      // The way back is the interaction's first step: an ordinary sign-in,
      // which the provider never proved an identity for.
      const done = await signInWithPassword(jar, started.interactionId);

      expect(done.statusCode, withServerLog(done.body)).toBe(303);
      codeAt(done.headers['location']);
      expect(await upstreamCredentials()).toBe(0);
      expect(await events(LINKED)).toEqual([]);
      expect(await events(LINK_FAILED)).toEqual([]);
    });

    it('links nothing when the sign-in fails: a wrong password leaves the identity free', async () => {
      await registerPasswordAccount(app(), EMAIL);
      const jar = new CookieJar();
      const callback = await throughProvider(jar, { qauth_link: TYPE });
      const id = ceremonyIdOf(callback.headers['location']);
      await answerToNext(jar, id, IDENTIFIER, { login_hint: EMAIL });

      const wrong = await answer(jar, id, PASSWORD, { password: `${E2E_PASSWORD}-not` });

      expect(wrong.statusCode, withServerLog(wrong.body)).toBe(303);
      expect(ceremonyIdOf(wrong.headers['location'])).toBe(id);
      const again = await read(id);
      expect(again.step).toBe(PASSWORD);
      expect(again.upstreamLink).toEqual({ provider: TYPE, name: PROVIDER_NAME });
      expect(await upstreamCredentials()).toBe(0);
      expect(await events(LINKED)).toEqual([]);
      expect(await codes()).toBe(0);
    });
  });

  describe('another browser or another interaction', () => {
    it("refuses the provider's answer in another browser, and the answers of the link's sign-in there, linking nothing", async () => {
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const jar = new CookieJar();
      const started = await startProvider(jar, { qauth_link: TYPE });
      const answered = provider.authorize(started.providerRequest, PERSON);

      // Another browser: no flow cookie of the start.
      const elsewhere = new CookieJar();
      const replayed = await callbackAt(elsewhere, answered);

      expect(replayed.statusCode, replayed.body).toBe(400);
      expect(replayed.body).toContain(ERROR_TITLE);
      expect((await events(SIGN_IN_FAILED)).map((event) => event.data['reason'])).toContain(
        'transaction_mismatch'
      );
      expect(await upstreamCredentials()).toBe(0);

      // The original browser goes on to the sign-in; another one cannot answer it.
      const callback = await callbackAt(jar, answered);
      expect(callback.statusCode, withServerLog(callback.body)).toBe(303);
      const id = ceremonyIdOf(callback.headers['location']);
      const { csrf } = await read(id);
      const foreign = await app().inject({
        method: 'POST',
        url: `${INTERACTION_API_PREFIX}/${id}/answer`,
        headers: { ...FORM, ...SAME_ORIGIN, cookie: elsewhere.header() ?? '' },
        payload: new URLSearchParams({ type: IDENTIFIER, csrf, login_hint: EMAIL }).toString(),
      });
      expect(foreign.statusCode, foreign.body).toBe(410);
      expect(await upstreamCredentials()).toBe(0);

      const done = await signInWithPassword(jar, id);
      expect(done.statusCode, withServerLog(done.body)).toBe(303);
      expect((await upstreamCredentialOf())?.userId).toBe(ownerId);
    });

    it('links nothing on a sign-in in another interaction of the same browser', async () => {
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const jar = new CookieJar();
      const choosing = await atChoice(jar);

      // Another authorization request of the same browser, signed in to the account.
      await signIn(jar);

      expect(await upstreamCredentials()).toBe(0);
      expect(await events(LINKED)).toEqual([]);
      // The interaction that holds the identity still asks for its own sign-in.
      await chooseLink(jar, choosing);
      expect(await upstreamCredentials()).toBe(0);
      const done = await signInWithPassword(jar, choosing);
      expect(done.statusCode, withServerLog(done.body)).toBe(303);
      expect((await upstreamCredentialOf())?.userId).toBe(ownerId);
    });
  });

  describe('an identity already linked to another account', () => {
    it('is refused at the callback of a qauth_link, with its page and an event, and stays with its holder', async () => {
      const holder = await app().repositories.users.create({ realmId });
      await holdIdentity(holder.id);
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const jar = new CookieJar();
      await signIn(jar);
      const codesBefore = await codes();

      const refused = await throughProvider(jar, { qauth_link: TYPE });

      expect(refused.statusCode, withServerLog(refused.body)).toBe(409);
      expect(refused.body).toContain(LINK_REFUSED_TITLE);
      expect(refused.body).toContain(PROVIDER_NAME);
      expect(refused.headers['location']).toBeUndefined();
      expect((await upstreamCredentialOf())?.userId).toBe(holder.id);
      expect(await codes()).toBe(codesBefore);
      expect(await events(LINKED)).toEqual([]);
      const failed = await events(LINK_FAILED);
      expect(failed.map((event) => event.data)).toEqual([
        { provider: TYPE, reason: 'already_linked' },
      ]);
      // Nobody has signed in for the link yet: the event is the holder's.
      expect(failed[0]?.subject_id).toBe(holder.id);
      expect(failed[0]?.subject_id).not.toBe(ownerId);
    });

    it('is refused at the finish when another account took it during the sign-in, and nothing goes to the client', async () => {
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const jar = new CookieJar();
      const id = await atChoice(jar);
      await chooseLink(jar, id);
      await answerToNext(jar, id, IDENTIFIER, { login_hint: EMAIL });
      // Meanwhile another account takes the identity.
      const other = await app().repositories.users.create({ realmId });
      await holdIdentity(other.id);

      const done = await answer(jar, id, PASSWORD, { password: E2E_PASSWORD });

      expect(done.statusCode, withServerLog(done.body)).toBe(303);
      expect(pathOf(done.headers['location'])).toBe(
        `/ui/upstream-link-refused?provider=${TYPE}&reason=already_linked`
      );
      expect(await codes()).toBe(0);
      expect((await upstreamCredentialOf())?.userId).toBe(other.id);
      expect(await events(LINKED)).toEqual([]);
      expect(await events(LINK_FAILED)).toEqual([
        { subject_id: ownerId, data: { provider: TYPE, reason: 'already_linked' } },
      ]);
      const page = await get(jar, pathOf(done.headers['location']));
      expect(page.statusCode).toBe(409);
      expect(page.body).toContain(LINK_REFUSED_TITLE);
    });

    it('refuses a second identity of the same provider for the account (provider_linked)', async () => {
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      await holdIdentity(ownerId, 'corp-user-earlier');
      const jar = new CookieJar();
      const id = await atChoice(jar);
      await chooseLink(jar, id);

      const done = await signInWithPassword(jar, id);

      expect(done.statusCode, withServerLog(done.body)).toBe(303);
      expect(pathOf(done.headers['location'])).toBe(
        `/ui/upstream-link-refused?provider=${TYPE}&reason=provider_linked`
      );
      expect(await upstreamCredentialOf()).toBeUndefined();
      expect(await upstreamCredentials()).toBe(1);
      expect((await events(LINK_FAILED)).map((event) => event.data['reason'])).toEqual([
        'provider_linked',
      ]);
    });
  });

  describe('with MFA required', () => {
    it("asks for the account's second factor after its password, and links only after it", async () => {
      policy = POLICY_REQUIRED;
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const secret = await bindTotp(ownerId, true);
      const jar = new CookieJar();
      const id = await atChoice(jar);
      await chooseLink(jar, id);
      await answerToNext(jar, id, IDENTIFIER, { login_hint: EMAIL });

      const second = await answerToNext(jar, id, PASSWORD, { password: E2E_PASSWORD });

      expect(second.step).toBe(TOTP);
      expect(await upstreamCredentials()).toBe(0);
      const done = await answer(jar, id, TOTP, { otp: totpCodeAt(secret, Date.now()) });
      expect(done.statusCode, withServerLog(done.body)).toBe(303);
      codeAt(done.headers['location']);
      expect((await upstreamCredentialOf())?.userId).toBe(ownerId);
    });
  });

  describe('the account API (list and unlink)', () => {
    it('lists the linked account, refuses a stale sign-in to unlink it, and unlinks it on a fresh one, with a notice and an event', async () => {
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const credentialId = await holdIdentity(ownerId);

      const listed = await linkedAccounts(
        'GET',
        await accountToken(ownerId, { authTime: signedInAgo(3600), amr: ['pwd'] })
      );
      expect(listed.statusCode, listed.body).toBe(200);
      expect(listed.json()).toEqual({
        items: [
          {
            id: credentialId,
            provider: TYPE,
            providerName: PROVIDER_NAME,
            createdAt: expect.any(String),
          },
        ],
        nextCursor: null,
      });
      expect(listed.body).not.toContain(PERSON.sub);

      // A sign-in six minutes old: the RFC 9470 challenge, and the identity stays.
      const stale = await linkedAccounts(
        'DELETE',
        await accountToken(ownerId, { authTime: signedInAgo(301), amr: ['pwd'] }),
        `/${credentialId}`
      );
      expect(stale.statusCode, stale.body).toBe(401);
      expect(stale.headers['www-authenticate']).toBe(
        'Bearer error="insufficient_user_authentication", max_age="300"'
      );
      expect((await upstreamCredentialOf())?.id).toBe(credentialId);
      expect(await events(UNLINKED)).toEqual([]);

      const fresh = await linkedAccounts(
        'DELETE',
        await accountToken(ownerId, { authTime: signedInAgo(5), amr: ['pwd'] }),
        `/${credentialId}`
      );

      expect(fresh.statusCode, fresh.body).toBe(204);
      expect(await upstreamCredentialOf()).toBeUndefined();
      expect(await events(UNLINKED)).toEqual([
        { subject_id: ownerId, data: { provider: TYPE, credentialId } },
      ]);
      expect(
        accountContract.SECURITY_LOG_KINDS.account_unlinked.sources.map((source) => source.event)
      ).toContain('user.upstream_unlinked');
      await expectMail(EMAIL, 'upstream_unlinked');
    });

    it("refuses to unlink the account's last way to sign in, its authenticator app notwithstanding", async () => {
      const user = await app().repositories.users.create({ realmId });
      const credentialId = await holdIdentity(user.id);
      await bindTotp(user.id, false);

      const refused = await linkedAccounts(
        'DELETE',
        await accountToken(user.id, { authTime: signedInAgo(5), amr: ['otp', 'mfa'] }),
        `/${credentialId}`
      );

      expect(refused.statusCode, refused.body).toBe(409);
      expect(refused.json()).toMatchObject({ code: 'last_credential', status: 409 });
      expect((await upstreamCredentialOf())?.id).toBe(credentialId);
      expect(await events(UNLINKED)).toEqual([]);
    });

    it("answers 404 for another account's linked account, as for one that does not exist", async () => {
      const ownerId = await registerPasswordAccount(app(), EMAIL);
      const other = await app().repositories.users.create({ realmId });
      const credentialId = await holdIdentity(other.id);

      const refused = await linkedAccounts(
        'DELETE',
        await accountToken(ownerId, { authTime: signedInAgo(5), amr: ['pwd'] }),
        `/${credentialId}`
      );

      expect(refused.statusCode, refused.body).toBe(404);
      expect((await upstreamCredentialOf())?.userId).toBe(other.id);
    });
  });
});
