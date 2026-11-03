import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { SESSION_COOKIE, sessionCookieParts } from '../testing/session-cookie-value';
import { REDIS_KEYS, STEP_UP_FRESH_AUTH_WINDOW_MS } from './constants';

/**
 * THE CONSENT STEP OF THE INTERACTION API (#629, ADR-019 Decision 6), end to
 * end against real Postgres and Redis, with INTERACTION_UI_ENABLED on.
 *
 * The step shows the scopes the request asked for that the client may have,
 * the resources or the client's audience, the client's display data and, for
 * an AI agent, the `agent` member; the person allows or denies it, and may
 * ask for the decision to be remembered. The grant is the scope set the step
 * showed, which the interaction holds: no answer field can add to it. An
 * `allow` checks the agent scope cap and the step-up gate again, and mints the
 * code, the remembered grant and the events in one transaction.
 *
 * The scenarios of `routes/ui/consent.test.ts` (the server-rendered page) are
 * ported here where they apply to the step. Left out, as page mechanics the
 * step has no counterpart for:
 *
 * - the HTML itself, its hidden form fields and the page's form schema
 *   ("renders consent HTML with CSRF token hidden input", the long
 *   state/nonce form-schema bounds, "redirect_uri reaches the handler as
 *   sent", "max_age is never converted from a non-scalar"): the step reads no
 *   request parameter from its answer, only `decision` and `remember`;
 * - the session side record's CSRF value and its scope/resource/agent
 *   bindings ("keeps the consent CSRF values out of the session service",
 *   "rendering does not extend the session", "binds whether the page was the
 *   agent’s", "reads a binding without the flag"): the interaction record
 *   holds the step, and the Interaction API's own CSRF value is per step;
 * - the bidirectional-control sentence of the agent line: the step carries no
 *   sentence, only the typed `agent` member and the sanitised declared name;
 * - "redirects to /ui/login when no session cookie present": a consent step
 *   is only ever started for a session; without one `/oauth/authorize` starts
 *   the identifier step (authorize-interaction.integration.test.ts);
 * - the page's REJECTED loopback variants and the self-registered client's
 *   `invalid_scope` shown on the issuer: both are decided by
 *   `/oauth/authorize` before any step, unchanged by #629;
 * - REDIRECT_URI_CUSTOM_SCHEMES, a malformed `dpop_jkt` with DPoP on, a CIMD
 *   client and a wallet session's assurance level: each needs a deployment
 *   setting or a fixture (an egress server, a wallet) this suite does not
 *   boot; the code paths are the endpoint's, shared with the step;
 * - a session that ends inside the code's transaction (#549): no request can
 *   be timed to land there; a session ended before the answer is covered.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const MINUTE = 60_000;
/** Past the fresh-sign-in window a dangerous scope, `prompt=login` and a native profile need. */
const STALE_MS = STEP_UP_FRESH_AUTH_WINDOW_MS + MINUTE;
const EMAIL = 'consent-interaction@example.test';
const ORIGIN = 'https://auth.example.com';
const CLIENT_ID = 'consent-notes-app';
const CLIENT_NAME = 'Consent notes app';
const REDIRECT_URI = 'https://client.example.com/callback';
const STATE = 'consent-state';
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const CONSENT = stepUrn('consent');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const JSON_BODY = { 'content-type': 'application/json' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
const CREATED = 'urn:qauth:event:interaction.created:v1-rc.0';
const GRANTED = 'urn:qauth:event:consent.granted:v1-rc.0';
const DENIED = 'urn:qauth:event:consent.denied:v1-rc.0';
const STEP_UP_REQUIRED = 'urn:qauth:event:step_up.required:v1-rc.0';
const STEP_UP_ELEVATED = 'urn:qauth:event:step_up.elevated:v1-rc.0';
const SIGNED_IN = 'urn:qauth:event:user.signed_in:v1-rc.0';
const DENY_DESCRIPTION = 'User denied the authorization request.';
/** A public key a first-party client authenticates with; no test here reaches the token endpoint with it. */
const CLIENT_JWKS = {
  keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
};
/** An interaction id: 43 base64url characters. */
const INTERACTION_ID = /^[A-Za-z0-9_-]{43}$/;

type NewClient = Parameters<FastifyInstance['repositories']['oauthClients']['create']>[0];

/** A step read, as the ceremony app's server gets it. */
interface StepRead {
  readonly step: string;
  readonly csrf: string;
  readonly params: Record<string, Record<string, unknown>>;
  readonly client?: Record<string, unknown>;
}

/** The columns of a code row the tests read. */
interface CodeRow {
  readonly scopes: string[];
  readonly resource: string[];
  readonly redirect_uri: string;
  readonly state: string | null;
  readonly session_id: string | null;
  readonly assurance_level: string | null;
  readonly auth_time: string | null;
}

/** The columns of an event the tests read. */
interface EventRow {
  readonly data: Record<string, unknown>;
  readonly subject_id: string | null;
  readonly client_id: string | null;
  readonly realm_id: string;
}

/**
 * The interaction id of a ceremony page location, relative or on the realm
 * origin; `undefined` for any other location.
 */
function ceremonyIdOf(location: string): string | undefined {
  const path = location.startsWith(`${ORIGIN}/`) ? location.slice(ORIGIN.length) : location;
  if (!path.startsWith(CEREMONY_PAGE_PREFIX)) return undefined;
  const id = path.slice(CEREMONY_PAGE_PREFIX.length);
  return INTERACTION_ID.test(id) ? id : undefined;
}

/** The query of a redirect to `redirectUri`, which it must be. */
function callbackOf(location: string, redirectUri = REDIRECT_URI): URLSearchParams {
  expect(location.startsWith(`${redirectUri}?`), location).toBe(true);
  return new URL(location).searchParams;
}

describe('the consent step of the Interaction API (#629, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let userId = '';
  let realmId = '';
  let clientRowId = '';

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      INTERACTION_UI_ENABLED: 'true',
      // Some tests run several authorization requests and steps from one address.
      AUTHORIZE_RATE_LIMIT: '10000',
    });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
    delete process.env['AUTHORIZE_RATE_LIMIT'];
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    const app = booted.app;
    await resetE2eState(app);
    userId = await registerPasswordAccount(app, EMAIL);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
    clientRowId = await createClient(CLIENT_ID, {});
  }, 120_000);

  afterEach(() => {
    vi.useRealTimers();
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /**
   * An operator-provisioned public client of the realm, with `overrides` on
   * top of the defaults, and its row id.
   */
  async function createClient(clientId: string, overrides: Partial<NewClient>): Promise<string> {
    const client = await server().repositories.oauthClients.create({
      realmId,
      clientId,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: CLIENT_NAME,
      redirectUris: [REDIRECT_URI],
      scopes: ['openid', 'email', 'profile', 'write:notes'],
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
      // A seeded client: its redirect URI receives authorization errors.
      provisionedByOperator: true,
      ...overrides,
    });
    return client.id;
  }

  /** Change a client row as an operator does in the database. */
  async function operatorUpdate(sql: string, params: unknown[]): Promise<void> {
    await server().dbPool.query(sql, params);
  }

  /**
   * Set the realm's `sso_max_lifespan`, as an operator does in the database,
   * and drop the host cache so the next request reads the new row.
   */
  async function setRealmLimit(seconds: number | null): Promise<void> {
    await server().dbPool.query('UPDATE realms SET sso_max_lifespan = $1 WHERE name = $2', [
      seconds,
      E2E_REALM_NAME,
    ]);
    server().realmHostCache.clear();
  }

  /** The user's stored consent to `scopes` for the client row `oauthClientId`. */
  async function consentTo(scopes: string[], oauthClientId = clientRowId): Promise<void> {
    await server().repositories.oauthConsents.upsertGrant(realmId, userId, oauthClientId, scopes);
  }

  /** `/oauth/authorize` from the browser holding `jar`; `extra` replaces the defaults. */
  async function authorize(
    jar: CookieJar,
    extra: Record<string, string | string[]> = {},
    challenge = pkcePair().challenge
  ): Promise<LightMyRequestResponse> {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid email',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: STATE,
    });
    for (const [name, value] of Object.entries(extra)) {
      params.delete(name);
      for (const one of [value].flat()) params.append(name, one);
    }
    const response = await server().inject({
      method: 'GET',
      url: `/oauth/authorize?${params.toString()}`,
      headers: jar.header() === undefined ? {} : { cookie: jar.header() as string },
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** The interaction id of a redirect to a ceremony page. */
  function interactionIdOf(response: LightMyRequestResponse): string {
    expect([302, 303], response.body).toContain(response.statusCode);
    return interactionIdOfLocation(String(response.headers['location']));
  }

  function interactionIdOfLocation(location: string): string {
    const id = ceremonyIdOf(location);
    if (id === undefined) throw new Error(`not a ceremony page: ${location}`);
    return id;
  }

  /** The step read, as the ceremony app's server makes it: the id alone, no cookie. */
  async function read(id: string): Promise<StepRead> {
    const response = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}`,
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json() as StepRead;
  }

  /** The step's statusCode alone: 410 once it has ended. */
  async function readStatus(id: string): Promise<number> {
    return (await server().inject({ method: 'GET', url: `${INTERACTION_API_PREFIX}/${id}` }))
      .statusCode;
  }

  /** The consent step's params of a step read. */
  function consentParams(step: StepRead): Record<string, unknown> {
    expect(step.step).toBe(CONSENT);
    return step.params[CONSENT];
  }

  /** Authorize from `jar` and return the consent step it starts. */
  async function consentStep(
    jar: CookieJar,
    extra: Record<string, string | string[]> = {},
    challenge?: string
  ): Promise<{ id: string; step: StepRead }> {
    const id = interactionIdOf(await authorize(jar, extra, challenge));
    const step = await read(id);
    expect(step.step).toBe(CONSENT);
    return { id, step };
  }

  /** A form post to the answer endpoint from the ceremony page. */
  async function post(
    jar: CookieJar,
    id: string,
    fields: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${id}/answer`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: jar.header() ?? '' },
      payload: new URLSearchParams(fields).toString(),
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** A JSON answer, as the ceremony app sends it with JavaScript. */
  async function answerJson(
    jar: CookieJar,
    id: string,
    body: Record<string, unknown>
  ): Promise<LightMyRequestResponse> {
    const response = await server().inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${id}/answer`,
      headers: { ...JSON_BODY, ...SAME_ORIGIN, cookie: jar.header() ?? '' },
      payload: JSON.stringify(body),
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /**
   * Answer the consent step `id` with `decision`, with the CSRF value of a
   * fresh step read, and return where the browser goes: a JSON answer gets
   * `{ result: 'redirect', location }`, a form post 303.
   */
  async function decide(
    jar: CookieJar,
    id: string,
    decision: 'allow' | 'deny',
    options: { readonly remember?: boolean; readonly form?: boolean } = {}
  ): Promise<string> {
    const { csrf } = await read(id);
    if (options.form === true) {
      const response = await post(jar, id, {
        type: CONSENT,
        csrf,
        decision,
        ...(options.remember === true ? { remember: 'true' } : {}),
      });
      expect(response.statusCode, response.body).toBe(303);
      return String(response.headers['location']);
    }
    const response = await answerJson(jar, id, {
      type: CONSENT,
      csrf,
      decision,
      ...(options.remember === undefined ? {} : { remember: options.remember }),
    });
    expect(response.statusCode, response.body).toBe(200);
    const body = response.json() as { result: string; location: string };
    expect(body.result).toBe('redirect');
    return body.location;
  }

  /** Answer the identifier step; the next answer is the password's, with its CSRF value. */
  async function toPasswordStep(jar: CookieJar, id: string): Promise<string> {
    const identifier = await post(jar, id, {
      type: IDENTIFIER,
      csrf: (await read(id)).csrf,
      login_hint: EMAIL,
    });
    expect(identifier.statusCode, identifier.body).toBe(303);
    const step = await read(id);
    expect(step.step).toBe(PASSWORD);
    return step.csrf;
  }

  /** Sign in at the interaction `id`: the response to the password answer. */
  async function signIn(jar: CookieJar, id: string): Promise<LightMyRequestResponse> {
    const csrf = await toPasswordStep(jar, id);
    return post(jar, id, { type: PASSWORD, csrf, password: E2E_PASSWORD });
  }

  /** The `sid` of the browser session `jar` holds. */
  function sidOf(jar: CookieJar): string {
    const cookie = jar.get(SESSION_COOKIE);
    if (cookie === undefined) throw new Error('the browser holds no session cookie');
    return sessionCookieParts(cookie).sid;
  }

  async function count(sql: string, params: unknown[] = []): Promise<number> {
    const { rows } = await server().dbPool.query<{ count: string }>(sql, params);
    return Number(rows[0]?.count ?? 0);
  }

  async function codeRows(oauthClientId = clientRowId): Promise<CodeRow[]> {
    const { rows } = await server().dbPool.query<CodeRow>(
      `SELECT scopes, resource, redirect_uri, state, session_id, assurance_level, auth_time
         FROM authorization_codes WHERE oauth_client_id = $1 ORDER BY created_at`,
      [oauthClientId]
    );
    return rows;
  }

  /** Every consent row of the user, active or not. */
  async function consentRows(): Promise<
    {
      scopes: string[];
      resource_scopes: Record<string, string[]>;
      realm_id: string;
      revoked_at: string | null;
    }[]
  > {
    const { rows } = await server().dbPool.query<{
      scopes: string[];
      resource_scopes: Record<string, string[]>;
      realm_id: string;
      revoked_at: string | null;
    }>(
      'SELECT scopes, resource_scopes, realm_id, revoked_at FROM oauth_consents WHERE user_id = $1',
      [userId]
    );
    return rows;
  }

  async function eventsOf(type: string): Promise<EventRow[]> {
    const { rows } = await server().dbPool.query<EventRow>(
      'SELECT data, subject_id, client_id, realm_id FROM events WHERE type = $1 ORDER BY seq',
      [type]
    );
    return rows;
  }

  function events(type: string): Promise<number> {
    return count('SELECT count(*) AS count FROM events WHERE type = $1', [type]);
  }

  /** Redeem a code at the token endpoint with its PKCE verifier. */
  function redeem(code: string, verifier: string): Promise<LightMyRequestResponse> {
    return server().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
      }).toString(),
    });
  }

  // ---------------------------------------------------------------------
  // The acceptance criteria of #629
  // ---------------------------------------------------------------------

  it('An answer that adds a scope the user did not see grants nothing extra: an answer carrying another member is refused, and the step stays', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const pkce = pkcePair();
    const { id, step } = await consentStep(jar, {}, pkce.challenge);
    expect(
      (consentParams(step)['scopes'] as { scope: string }[]).map((entry) => entry.scope)
    ).toEqual(['openid', 'email']);

    for (const extra of [
      { scope: 'openid email write:notes' },
      { scopes: ['openid', 'email', 'write:notes'] },
      { resource: 'https://payroll.example.com/v1' },
    ]) {
      const refused = await answerJson(jar, id, {
        type: CONSENT,
        csrf: step.csrf,
        decision: 'allow',
        ...extra,
      });
      expect(refused.statusCode, refused.body).toBe(400);
      expect(refused.json()).toMatchObject({ code: 'invalid_answer' });
      // The step and its CSRF value stay.
      const again = await read(id);
      expect(again.step).toBe(CONSENT);
      expect(again.csrf).toBe(step.csrf);
    }
    // The same through a form post.
    const form = await post(jar, id, {
      type: CONSENT,
      csrf: step.csrf,
      decision: 'allow',
      scope: 'openid email write:notes',
    });
    expect(form.statusCode, form.body).toBe(400);
    expect(await codeRows()).toEqual([]);
    expect(await events(GRANTED)).toBe(0);

    // The allow grants what the step showed, and nothing else.
    const code = callbackOf(await decide(jar, id, 'allow')).get('code');
    expect(code).toMatch(/.+/);
    expect((await codeRows()).map((row) => row.scopes)).toEqual([['openid', 'email']]);
    const token = await redeem(code as string, pkce.verifier);
    expect(token.statusCode, token.body).toBe(200);
    expect(String((token.json() as { scope?: string }).scope).split(' ')).toEqual([
      'openid',
      'email',
    ]);
  });

  it('An answer that adds a scope the user did not see grants nothing extra: a scope the allowlist gains after the step is shown is not granted', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const pkce = pkcePair();
    // The request asks for `read:notes`, which the client may not have yet:
    // the step shows the two it may.
    const { id, step } = await consentStep(
      jar,
      { scope: 'openid email read:notes' },
      pkce.challenge
    );
    expect(
      (consentParams(step)['scopes'] as { scope: string }[]).map((entry) => entry.scope)
    ).toEqual(['openid', 'email']);

    // The client's owner adds it while the step is shown.
    await operatorUpdate(
      `UPDATE oauth_clients SET scopes = scopes || '["read:notes"]'::jsonb WHERE id = $1`,
      [clientRowId]
    );

    const callback = callbackOf(await decide(jar, id, 'allow'));
    expect(callback.get('state')).toBe(STATE);
    expect(callback.get('iss')).toBe(ORIGIN);
    expect((await codeRows()).map((row) => row.scopes)).toEqual([['openid', 'email']]);
    expect((await eventsOf(GRANTED)).map((event) => event.data)).toEqual([
      { scopes: ['openid', 'email'], remembered: false },
    ]);

    const token = await redeem(callback.get('code') as string, pkce.verifier);
    expect(token.statusCode, token.body).toBe(200);
    const scope = String((token.json() as { scope?: string }).scope).split(' ');
    expect(scope).toEqual(['openid', 'email']);
    expect(scope).not.toContain('read:notes');
  });

  it('A dangerous scope on a stale session sends the user to a fresh login step before any code', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    // Shown on a fresh session: the dangerous scope needs no new sign-in yet.
    const { id, step } = await consentStep(jar, { scope: 'openid write:notes' });
    expect(consentParams(step)['scopes']).toEqual([
      { scope: 'openid', text: 'Verify your identity', sensitive: false, dangerous: false },
      { scope: 'write:notes', sensitive: false, dangerous: true },
    ]);

    // The person leaves the step open past the fresh-sign-in window.
    vi.setSystemTime(Date.now() + STALE_MS);
    const location = await decide(jar, id, 'allow', { remember: true });

    // A NEW interaction, at the identifier step; nothing issued, nothing remembered.
    const next = interactionIdOfLocation(location);
    expect(next).not.toBe(id);
    expect(location).toBe(`${ORIGIN}${CEREMONY_PAGE_PREFIX}${next}`);
    expect(await readStatus(id)).toBe(410);
    expect((await read(next)).step).toBe(IDENTIFIER);
    expect(await codeRows()).toEqual([]);
    expect(await consentRows()).toEqual([]);
    expect(await events(GRANTED)).toBe(0);
    const required = await eventsOf(STEP_UP_REQUIRED);
    expect(required.at(-1)).toEqual({
      data: { reason: 'fresh_authentication_required', dangerousScopes: ['write:notes'] },
      subject_id: userId,
      client_id: CLIENT_ID,
      realm_id: realmId,
    });

    // The fresh sign-in shows the consent step again, and its allow mints the code.
    const signedIn = await signIn(jar, next);
    expect(signedIn.statusCode, signedIn.body).toBe(303);
    const again = interactionIdOf(signedIn);
    expect(consentParams(await read(again))['scopes']).toEqual([
      { scope: 'openid', text: 'Verify your identity', sensitive: false, dangerous: false },
      { scope: 'write:notes', sensitive: false, dangerous: true },
    ]);
    const callback = callbackOf(await decide(jar, again, 'allow'));
    expect(callback.get('code')).toMatch(/.+/);
    expect((await codeRows()).map((row) => row.scopes)).toEqual([['openid', 'write:notes']]);
  });

  it.each([
    {
      why: 'its agent scope cap is lowered',
      sql: 'UPDATE oauth_clients SET max_agent_mode = NULL WHERE id = $1',
    },
    {
      why: 'it stops being an agent',
      sql: 'UPDATE oauth_clients SET is_agent = false WHERE id = $1',
    },
  ])(
    'A client over its agent scope cap gets invalid_scope and no code: $why after the step is shown',
    async ({ sql }) => {
      await setRealmLimit(null);
      const agentRowId = await createClient('capped-agent', {
        scopes: ['openid', 'agent:readonly'],
        isAgent: true,
        maxAgentMode: 'readonly',
      });
      const jar = await signInWithPassword(server(), EMAIL);
      const { id, step } = await consentStep(jar, {
        client_id: 'capped-agent',
        scope: 'openid agent:readonly',
      });
      expect(consentParams(step)['agent']).toEqual({});

      await operatorUpdate(sql, [agentRowId]);

      const callback = callbackOf(await decide(jar, id, 'allow', { remember: true }));
      expect(callback.get('error')).toBe('invalid_scope');
      expect(callback.get('code')).toBeNull();
      expect(callback.get('state')).toBe(STATE);
      expect(callback.get('iss')).toBe(ORIGIN);
      expect(await codeRows(agentRowId)).toEqual([]);
      expect(await consentRows()).toEqual([]);
      expect(await eventsOf(DENIED)).toEqual([
        {
          data: { error: 'invalid_scope', reason: 'agent_scope_mode_exceeded' },
          subject_id: userId,
          client_id: 'capped-agent',
          realm_id: realmId,
        },
      ]);
    }
  );

  it('`deny` redirects with access_denied, state and iss, as JSON and as a form post', async () => {
    const jar = await signInWithPassword(server(), EMAIL);

    const fromJson = await consentStep(jar);
    const json = callbackOf(await decide(jar, fromJson.id, 'deny'));
    const fromForm = await consentStep(jar);
    // "Remember" with a deny stores nothing.
    const form = callbackOf(await decide(jar, fromForm.id, 'deny', { form: true, remember: true }));

    for (const callback of [json, form]) {
      expect(callback.get('error')).toBe('access_denied');
      expect(callback.get('error_description')).toBe(DENY_DESCRIPTION);
      expect(callback.get('state')).toBe(STATE);
      expect(callback.get('iss')).toBe(ORIGIN);
      expect(callback.get('code')).toBeNull();
    }
    expect(await readStatus(fromJson.id)).toBe(410);
    expect(await readStatus(fromForm.id)).toBe(410);
    expect(await codeRows()).toEqual([]);
    expect(await consentRows()).toEqual([]);
    const denied = {
      data: { error: 'access_denied' },
      subject_id: userId,
      client_id: CLIENT_ID,
      realm_id: realmId,
    };
    expect(await eventsOf(DENIED)).toEqual([denied, denied]);
    expect(await events(GRANTED)).toBe(0);
  });

  it('"Remember" writes one active oauth_consents row; a later request that fits skips the step', async () => {
    const resource = 'https://notes-api.example.com/v1';
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar, { resource });

    callbackOf(await decide(jar, id, 'allow', { remember: true, form: true }));

    expect(await consentRows()).toEqual([
      {
        scopes: ['email', 'openid'],
        resource_scopes: { [resource]: ['email', 'openid'] },
        realm_id: realmId,
        revoked_at: null,
      },
    ]);
    expect((await eventsOf(GRANTED)).map((event) => event.data)).toEqual([
      { scopes: ['openid', 'email'], remembered: true },
    ]);

    // A request for a subset at the same resource: the code, with no step.
    const createdBefore = await events(CREATED);
    const skipped = await authorize(jar, { scope: 'openid', resource });
    expect(skipped.statusCode).toBe(302);
    const callback = callbackOf(String(skipped.headers['location']));
    expect(callback.get('code')).toMatch(/.+/);
    expect(callback.get('iss')).toBe(ORIGIN);
    expect(await events(CREATED)).toBe(createdBefore);
    const scopes = (await codeRows()).map((row) => row.scopes);
    expect(scopes).toHaveLength(2);
    expect(scopes).toEqual(expect.arrayContaining([['openid', 'email'], ['openid']]));
  });

  it('"Remember" left off writes no row, and the next request shows the step again', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar);

    expect(callbackOf(await decide(jar, id, 'allow', { remember: false })).get('code')).toMatch(
      /.+/
    );
    expect(await consentRows()).toEqual([]);
    expect((await eventsOf(GRANTED)).map((event) => event.data)).toEqual([
      { scopes: ['openid', 'email'], remembered: false },
    ]);

    await consentStep(jar);
  });

  it('"Remember" twice keeps one active row, merged', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const first = await consentStep(jar);
    callbackOf(await decide(jar, first.id, 'allow', { remember: true }));
    // A scope the stored grant does not cover shows the step again.
    const second = await consentStep(jar, { scope: 'openid profile' });
    callbackOf(await decide(jar, second.id, 'allow', { remember: true }));

    expect(await consentRows()).toEqual([
      {
        scopes: ['email', 'openid', 'profile'],
        resource_scopes: {},
        realm_id: realmId,
        revoked_at: null,
      },
    ]);
  });

  // ---------------------------------------------------------------------
  // The scenarios of routes/ui/consent.test.ts, against the step
  // ---------------------------------------------------------------------

  it('shows the scopes with QAuth’s texts, the client, "remember" on by default, and the identifier only in the personal-data read (#230)', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id, step } = await consentStep(jar, { scope: 'openid email write:notes' });

    expect(consentParams(step)).toEqual({
      scopes: [
        { scope: 'openid', text: 'Verify your identity', sensitive: false, dangerous: false },
        { scope: 'email', text: 'View your email address', sensitive: false, dangerous: false },
        { scope: 'write:notes', sensitive: false, dangerous: true },
      ],
      resources: [],
      remember_default: true,
    });
    expect(step.client).toEqual({
      kind: 'unverified',
      redirect: { target: 'host', host: 'client.example.com' },
      declaredName: CLIENT_NAME,
      newClient: false,
    });
    expect(JSON.stringify(step)).not.toContain(EMAIL);

    const personal = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}/personal`,
      headers: { cookie: jar.header() as string },
    });
    expect(personal.statusCode, personal.body).toBe(200);
    expect(personal.json()).toEqual({ step: CONSENT, data: { [CONSENT]: { identifier: EMAIL } } });
  });

  it('shows no identifier when the session’s side record holds none', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    await server().redis.del(REDIS_KEYS.BROWSER_SESSION_SIDE_RECORD(realmId, sidOf(jar)));
    const { id } = await consentStep(jar);

    const personal = await server().inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}/personal`,
      headers: { cookie: jar.header() as string },
    });
    expect(personal.statusCode, personal.body).toBe(200);
    expect(personal.json()).toEqual({ step: CONSENT, data: { [CONSENT]: {} } });
  });

  it('shows the RFC 8707 resources of the validated request, never a key the parser did not validate', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    // `??resource=…` is the unknown key `?resource` to the query parser. Its
    // value is a marker no member of a step read holds (the brand's font is
    // `system`, so that word would prove nothing).
    const response = await server().inject({
      method: 'GET',
      url: `/oauth/authorize??resource=unvalidated-marker&${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: 'openid email',
        code_challenge: pkcePair().challenge,
        code_challenge_method: 'S256',
        state: STATE,
        resource: 'https://notes-api.example.com/v1',
      }).toString()}`,
      headers: { cookie: jar.header() as string },
    });
    jar.absorb(response.headers['set-cookie']);
    const step = await read(interactionIdOf(response));
    expect(consentParams(step)['resources']).toEqual(['https://notes-api.example.com/v1']);
    expect(JSON.stringify(step)).not.toContain('unvalidated-marker');
  });

  it('names the requested resource as the audience over the client default, the client’s audience when there is none, and binds the resources to the code', async () => {
    const audienceRowId = await createClient('audience-app', {
      audience: ['https://notes-api.example.com'],
    });
    const jar = await signInWithPassword(server(), EMAIL);

    const plain = await consentStep(jar, { client_id: 'audience-app' });
    expect(consentParams(plain.step)['resources']).toEqual([]);
    expect(consentParams(plain.step)['audience']).toEqual(['https://notes-api.example.com']);

    const resource = 'https://other-api.example.com/v1';
    const named = await consentStep(jar, { client_id: 'audience-app', resource });
    expect(consentParams(named.step)['resources']).toEqual([resource]);
    expect(consentParams(named.step)).not.toHaveProperty('audience');

    // RFC 8707: the resources the step showed are bound to the code.
    callbackOf(await decide(jar, named.id, 'allow'));
    expect((await codeRows(audienceRowId)).map((row) => row.resource)).toEqual([[resource]]);
  });

  it('refuses a QAuth API audience the client does not list before any step, and shows one it lists (#509)', async () => {
    const audience = 'urn:qauth:aud:account:v1-rc.0';
    await createClient('listing-app', { audience: [audience] });
    const jar = await signInWithPassword(server(), EMAIL);
    const createdBefore = await events(CREATED);

    const refused = await authorize(jar, { resource: audience });
    expect(refused.statusCode).toBe(302);
    const callback = callbackOf(String(refused.headers['location']));
    expect(callback.get('error')).toBe('invalid_target');
    expect(callback.get('state')).toBe(STATE);
    expect(callback.get('iss')).toBe(ORIGIN);
    expect(await events(CREATED)).toBe(createdBefore);

    const { step } = await consentStep(jar, { client_id: 'listing-app', resource: audience });
    expect(consentParams(step)['resources']).toEqual([audience]);
  });

  it('names an agent client in the agent member, with the realm’s sso_max_lifespan when it sets one, and nothing the client declared in it (#845)', async () => {
    await setRealmLimit(null);
    await createClient('release-bot', {
      name: '<script>alert(1)</script> & "Bot"',
      isAgent: true,
    });
    const jar = await signInWithPassword(server(), EMAIL);

    const unlimited = await consentStep(jar, { client_id: 'release-bot' });
    expect(consentParams(unlimited.step)['agent']).toEqual({});
    expect(JSON.stringify(unlimited.step.params)).not.toContain('Bot');
    expect(JSON.stringify(unlimited.step)).not.toContain('<script>');

    await setRealmLimit(3600);
    const limited = await consentStep(jar, { client_id: 'release-bot' });
    expect(consentParams(limited.step)['agent']).toEqual({ max_lifespan: 3600 });

    // A client that is not an agent has no agent member.
    const notAgent = await consentStep(jar);
    expect(consentParams(notAgent.step)).not.toHaveProperty('agent');
  });

  it('keeps the new-client badge and the agent scope cap for an agent client', async () => {
    await setRealmLimit(null);
    await createClient('fresh-agent', {
      isAgent: true,
      provisionedByOperator: false,
      dynamicRegisteredAt: Date.now() - 24 * 60 * MINUTE,
      metadata: { registrationType: 'dynamic' },
    });
    await createClient('readonly-agent', {
      scopes: ['openid', 'agent:readonly', 'agent:exec'],
      isAgent: true,
      maxAgentMode: 'readonly',
    });
    const jar = await signInWithPassword(server(), EMAIL);

    const { step } = await consentStep(jar, { client_id: 'fresh-agent' });
    expect(consentParams(step)['agent']).toEqual({});
    expect(step.client).toMatchObject({ kind: 'unverified', newClient: true });

    // An agent scope above the cap is refused before any step.
    const createdBefore = await events(CREATED);
    const overCap = await authorize(jar, {
      client_id: 'readonly-agent',
      scope: 'openid agent:exec',
    });
    expect(overCap.statusCode).toBe(302);
    const callback = callbackOf(String(overCap.headers['location']));
    expect(callback.get('error')).toBe('invalid_scope');
    expect(callback.get('iss')).toBe(ORIGIN);
    expect(await events(CREATED)).toBe(createdBefore);
  });

  it('allows an agent an in-cap agent scope', async () => {
    await setRealmLimit(null);
    const agentRowId = await createClient('readonly-agent', {
      scopes: ['openid', 'agent:readonly'],
      isAgent: true,
      maxAgentMode: 'readonly',
    });
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar, {
      client_id: 'readonly-agent',
      scope: 'openid agent:readonly',
    });

    const callback = callbackOf(await decide(jar, id, 'allow'));
    expect(callback.get('code')).toMatch(/.+/);
    expect(callback.get('error')).toBeNull();
    expect((await codeRows(agentRowId)).map((row) => row.scopes)).toEqual([
      ['openid', 'agent:readonly'],
    ]);
  });

  it.each([
    { shown: false, now: true, why: 'became an agent after a step that named none' },
    { shown: true, now: false, why: 'stopped being an agent after the agent’s step' },
  ])(
    'grants nothing to a client that $why, and shows the step it needs now (ADR-014 §11)',
    async ({ shown, now }) => {
      await setRealmLimit(null);
      const flipRowId = await createClient('flip-app', { isAgent: shown });
      const jar = await signInWithPassword(server(), EMAIL);
      const { id, step } = await consentStep(jar, { client_id: 'flip-app' });
      expect(Object.hasOwn(consentParams(step), 'agent')).toBe(shown);

      await operatorUpdate('UPDATE oauth_clients SET is_agent = $2 WHERE id = $1', [
        flipRowId,
        now,
      ]);

      const location = await decide(jar, id, 'allow', { remember: true });
      const next = interactionIdOfLocation(location);
      expect(next).not.toBe(id);
      expect(await codeRows(flipRowId)).toEqual([]);
      expect(await consentRows()).toEqual([]);
      expect(await events(GRANTED)).toBe(0);
      const again = await read(next);
      expect(Object.hasOwn(consentParams(again), 'agent')).toBe(now);
      if (now) expect(consentParams(again)['agent']).toEqual({});

      // The step the client needs now mints the code.
      expect(callbackOf(await decide(jar, next, 'allow')).get('code')).toMatch(/.+/);
      expect(await codeRows(flipRowId)).toHaveLength(1);
    }
  );

  it.each<{
    readonly label: string;
    readonly client: Partial<NewClient>;
    readonly redirectUri: string;
    readonly display: Record<string, unknown>;
  }>([
    {
      label:
        'leads with the verified domain of a client an admin registered, then the declared name',
      client: { verifiedDomain: 'app.example.com' },
      redirectUri: REDIRECT_URI,
      display: {
        kind: 'admin_registered',
        verifiedDomain: {
          host: 'app.example.com',
          registrableDomain: 'example.com',
          sharedHosting: false,
        },
        redirect: { target: 'host', host: 'client.example.com' },
        declaredName: CLIENT_NAME,
        newClient: false,
      },
    },
    {
      label: 'flags a verified domain under a shared-hosting suffix',
      client: { verifiedDomain: 'alice.eu.org' },
      redirectUri: REDIRECT_URI,
      display: {
        kind: 'admin_registered',
        verifiedDomain: {
          host: 'alice.eu.org',
          registrableDomain: 'alice.eu.org',
          sharedHosting: true,
        },
        redirect: { target: 'host', host: 'client.example.com' },
        declaredName: CLIENT_NAME,
        newClient: false,
      },
    },
    {
      label:
        'says a self-registered client is unverified, names where the code goes, and shows no logo, client link or domain of its own',
      client: {
        provisionedByOperator: false,
        dynamicRegisteredAt: Date.now() - MINUTE,
        metadata: {
          registrationType: 'dynamic',
          logo_uri: 'https://cdn.example.net/logo.png',
          client_uri: 'https://cdn.example.net/about',
        },
        // A self-registered client never shows a domain, whatever its row holds.
        verifiedDomain: 'bank.example',
      },
      redirectUri: 'https://notes-helper.example.net/cb',
      display: {
        kind: 'unverified',
        redirect: { target: 'host', host: 'notes-helper.example.net' },
        declaredName: CLIENT_NAME,
        newClient: true,
      },
    },
    {
      label: 'shows a loopback redirect as this device, for a client an admin registered too',
      client: { verifiedDomain: 'app.example.com' },
      redirectUri: 'http://127.0.0.1:8080/cb',
      display: {
        kind: 'admin_registered',
        verifiedDomain: {
          host: 'app.example.com',
          registrableDomain: 'example.com',
          sharedHosting: false,
        },
        redirect: { target: 'this_device' },
        declaredName: CLIENT_NAME,
        newClient: false,
      },
    },
    {
      label: 'shows a native app by its scheme',
      client: {},
      redirectUri: 'com.example.notes:/callback',
      display: {
        kind: 'unverified',
        redirect: { target: 'app', scheme: 'com.example.notes' },
        declaredName: CLIENT_NAME,
        newClient: false,
      },
    },
    {
      label: 'strips control and bidirectional characters from the declared name',
      client: { name: 'Bank‮ppa.live‬​' },
      redirectUri: REDIRECT_URI,
      display: {
        kind: 'unverified',
        redirect: { target: 'host', host: 'client.example.com' },
        declaredName: 'Bankppa.live',
        newClient: false,
      },
    },
  ])('$label (#593)', async ({ client, redirectUri, display }) => {
    await createClient('display-app', { redirectUris: [redirectUri], ...client });
    const jar = await signInWithPassword(server(), EMAIL);

    const { step } = await consentStep(jar, {
      client_id: 'display-app',
      redirect_uri: redirectUri,
    });

    expect(step.client).toEqual(display);
    const text = JSON.stringify(step);
    expect(text).not.toContain('cdn.example.net');
    expect(text).not.toContain('bank.example');
    expect(text).not.toMatch(/[‪-‮⁦-⁩​]/u);
  });

  it('refuses before any step a redirect URI it may not send to, or cannot show', async () => {
    const javascriptUri = 'javascript:alert(document.domain)//';
    const ipv6Uri = 'https://[2001:db8::1]/cb';
    await createClient('js-app', { redirectUris: [javascriptUri] });
    await createClient('ipv6-app', { redirectUris: [ipv6Uri] });
    const jar = await signInWithPassword(server(), EMAIL);
    const createdBefore = await events(CREATED);

    for (const [clientId, redirectUri] of [
      ['js-app', javascriptUri],
      ['ipv6-app', ipv6Uri],
    ]) {
      const refused = await authorize(jar, { client_id: clientId, redirect_uri: redirectUri });
      expect(refused.statusCode, refused.body).toBe(400);
      expect(refused.json()).toMatchObject({ error: 'invalid_request' });
      expect(refused.headers['location']).toBeUndefined();
    }
    expect(await events(CREATED)).toBe(createdBefore);
  });

  it('refuses a wrong CSRF value with 403, and keeps the step', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id, step } = await consentStep(jar);

    const refused = await answerJson(jar, id, {
      type: CONSENT,
      // The first character: every bit of it counts, unlike the last one's.
      csrf: `${step.csrf.startsWith('A') ? 'B' : 'A'}${step.csrf.slice(1)}`,
      decision: 'allow',
    });
    expect(refused.statusCode, refused.body).toBe(403);
    expect(await codeRows()).toEqual([]);
    expect((await read(id)).step).toBe(CONSENT);
  });

  it('stores the session’s sid and a password session’s empty assurance level on the code, and records the client on the session (#549, #237)', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const sid = sidOf(jar);
    const { id } = await consentStep(jar);

    callbackOf(await decide(jar, id, 'allow'));

    const [code] = await codeRows();
    expect(code).toMatchObject({
      session_id: sid,
      assurance_level: null,
      redirect_uri: REDIRECT_URI,
      state: STATE,
    });
    expect(
      await count(
        'SELECT count(*) AS count FROM session_clients WHERE session_id = $1 AND oauth_client_id = $2',
        [sid, clientRowId]
      )
    ).toBe(1);
  });

  it('issues no code, and remembers nothing, for a session signed out before the answer: 410, and the step stays', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar);
    await server().sessionService.revoke({
      realmId,
      sid: sidOf(jar),
      userId,
      reason: 'sign_out',
      actor: { type: 'user', id: userId },
    });

    const { csrf } = await read(id);
    const answered = await answerJson(jar, id, {
      type: CONSENT,
      csrf,
      decision: 'allow',
      remember: true,
    });

    expect(answered.statusCode, answered.body).toBe(410);
    expect(answered.json()).toMatchObject({ code: 'interaction_expired' });
    expect(await codeRows()).toEqual([]);
    expect(await consentRows()).toEqual([]);
    expect(await events(GRANTED)).toBe(0);
    expect((await read(id)).step).toBe(CONSENT);
  });

  it('records the grant and its events in the realm of the request (#487)', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar);

    callbackOf(await decide(jar, id, 'allow', { remember: true }));

    expect((await consentRows()).map((row) => row.realm_id)).toEqual([realmId]);
    expect(await eventsOf(GRANTED)).toEqual([
      {
        data: { scopes: ['openid', 'email'], remembered: true },
        subject_id: userId,
        client_id: CLIENT_ID,
        realm_id: realmId,
      },
    ]);
  });

  it('refuses the allow of a client an operator suspended, with unauthorized_client and no code (ANT-2026-DR5XI3LV)', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar);
    await operatorUpdate(
      'UPDATE oauth_clients SET suspended = true, suspended_at = $2 WHERE id = $1',
      [clientRowId, Date.now()]
    );

    const { csrf } = await read(id);
    const answered = await answerJson(jar, id, { type: CONSENT, csrf, decision: 'allow' });

    expect(answered.statusCode, answered.body).toBe(400);
    expect(answered.json()).toMatchObject({ code: 'unauthorized_client' });
    expect(answered.headers['location']).toBeUndefined();
    expect(await codeRows()).toEqual([]);
    expect(await events(GRANTED)).toBe(0);

    // A suspended client gets no step at all.
    const refused = await authorize(jar);
    expect(refused.statusCode, refused.body).toBe(400);
    expect(refused.json()).toMatchObject({ error: 'unauthorized_client' });
  });

  it('sends nothing to a redirect URI the client no longer holds: 400 invalid_request, no code (#513)', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar);
    await operatorUpdate(
      `UPDATE oauth_clients SET redirect_uris = '["https://client.example.com/other"]'::jsonb WHERE id = $1`,
      [clientRowId]
    );

    const { csrf } = await read(id);
    const answered = await answerJson(jar, id, { type: CONSENT, csrf, decision: 'allow' });

    expect(answered.statusCode, answered.body).toBe(400);
    expect(answered.json()).toMatchObject({ code: 'invalid_request' });
    expect(await codeRows()).toEqual([]);
  });

  it('sends the allow and the deny of a loopback redirect to the requested port (RFC 8252 §7.3, #414)', async () => {
    const requested = 'http://127.0.0.1:53817/callback';
    const loopbackRowId = await createClient('loopback-app', {
      redirectUris: ['http://127.0.0.1/callback'],
    });
    const jar = await signInWithPassword(server(), EMAIL);

    const denied = await consentStep(jar, { client_id: 'loopback-app', redirect_uri: requested });
    expect(denied.step.client).toMatchObject({ redirect: { target: 'this_device' } });
    expect(callbackOf(await decide(jar, denied.id, 'deny'), requested).get('error')).toBe(
      'access_denied'
    );

    const allowed = await consentStep(jar, { client_id: 'loopback-app', redirect_uri: requested });
    expect(callbackOf(await decide(jar, allowed.id, 'allow'), requested).get('code')).toMatch(/.+/);
    expect((await codeRows(loopbackRowId)).map((row) => row.redirect_uri)).toEqual([requested]);
  });

  it('round-trips a 2048-character state on the allow and on the deny (#316)', async () => {
    const state = 's'.repeat(2048);
    const jar = await signInWithPassword(server(), EMAIL);

    const allowed = await consentStep(jar, { state });
    const code = callbackOf(await decide(jar, allowed.id, 'allow', { form: true }));
    expect(code.get('state')).toBe(state);
    expect(code.get('code')).toMatch(/.+/);
    expect((await codeRows()).map((row) => row.state)).toEqual([state]);

    const denied = await consentStep(jar, { state });
    const error = callbackOf(await decide(jar, denied.id, 'deny', { form: true }));
    expect(error.get('state')).toBe(state);
    expect(error.get('error')).toBe('access_denied');
  });

  it('forces a fresh sign-in for prompt=login on a stale session, even with no dangerous scope', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar, { prompt: 'login' });
    vi.setSystemTime(Date.now() + STALE_MS);

    const location = await decide(jar, id, 'allow');

    expect((await read(interactionIdOfLocation(location))).step).toBe(IDENTIFIER);
    expect(await codeRows()).toEqual([]);
    expect((await eventsOf(STEP_UP_REQUIRED)).at(-1)?.data).toEqual({
      reason: 'fresh_authentication_required',
      prompt: 'login',
    });
  });

  it('mints a scope that is not dangerous on a stale session, with no step-up', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar);
    vi.setSystemTime(Date.now() + STALE_MS);
    const stepUpsBefore = await events(STEP_UP_REQUIRED);

    expect(callbackOf(await decide(jar, id, 'allow')).get('code')).toMatch(/.+/);
    expect(await codeRows()).toHaveLength(1);
    expect(await events(STEP_UP_REQUIRED)).toBe(stepUpsBefore);
  });

  describe('a first-party client (ADR-017 Decision 9, #633)', () => {
    const NATIVE_ID = 'notes-backend';
    const NATIVE_CALLBACK = 'https://notes.example.com/app/callback';
    const PORTAL_ID = 'portal';
    const PORTAL_CALLBACK = 'https://portal.example.com/auth/callback';

    /** The two first-party clients, flagged as an operator flags them. */
    async function firstPartyClients(): Promise<{ native: string; portal: string }> {
      const native = await createClient(NATIVE_ID, {
        tokenEndpointAuthMethod: 'private_key_jwt',
        jwks: CLIENT_JWKS,
        redirectUris: [NATIVE_CALLBACK],
      });
      const portal = await createClient(PORTAL_ID, {
        tokenEndpointAuthMethod: 'private_key_jwt',
        jwks: CLIENT_JWKS,
        redirectUris: [PORTAL_CALLBACK],
      });
      await operatorUpdate(
        `UPDATE oauth_clients
            SET first_party_profile = 'native_backend', first_party_reason = 'The notes app.',
                first_party_policy = '{"flows":["login"],"email_code_after_password":false,"pkce_required":true}'
          WHERE id = $1`,
        [native]
      );
      await operatorUpdate(
        `UPDATE oauth_clients
            SET first_party_profile = 'web_redirect', first_party_reason = 'The developer portal.'
          WHERE id = $1`,
        [portal]
      );
      return { native, portal };
    }

    it('sends a native_backend client to a fresh sign-in on a stale session, and mints on a fresh one', async () => {
      const { native } = await firstPartyClients();
      const jar = await signInWithPassword(server(), EMAIL);
      // prompt=consent shows the step that the administrative consent would skip.
      const extra = { client_id: NATIVE_ID, redirect_uri: NATIVE_CALLBACK, prompt: 'consent' };
      const { id } = await consentStep(jar, extra);
      vi.setSystemTime(Date.now() + STALE_MS);

      const location = await decide(jar, id, 'allow');

      const next = interactionIdOfLocation(location);
      expect((await read(next)).step).toBe(IDENTIFIER);
      expect(await codeRows(native)).toEqual([]);
      expect((await eventsOf(STEP_UP_REQUIRED)).at(-1)?.data).toEqual({
        reason: 'native_profile_login_required',
        prompt: 'consent',
      });

      // Right after the sign-in, the step again, and its allow mints.
      const signedIn = await signIn(jar, next);
      expect(signedIn.statusCode, signedIn.body).toBe(303);
      const again = interactionIdOf(signedIn);
      expect((await read(again)).step).toBe(CONSENT);
      const callback = callbackOf(await decide(jar, again, 'allow'), NATIVE_CALLBACK);
      expect(callback.get('code')).toMatch(/.+/);
      expect(await codeRows(native)).toHaveLength(1);
    });

    it('leaves a web_redirect client to the ordinary rule: no forced sign-in on a stale session', async () => {
      const { portal } = await firstPartyClients();
      const jar = await signInWithPassword(server(), EMAIL);
      vi.setSystemTime(Date.now() + STALE_MS);
      const { id } = await consentStep(jar, {
        client_id: PORTAL_ID,
        redirect_uri: PORTAL_CALLBACK,
        prompt: 'consent',
      });

      expect(callbackOf(await decide(jar, id, 'allow'), PORTAL_CALLBACK).get('code')).toMatch(/.+/);
      expect(await codeRows(portal)).toHaveLength(1);
    });
  });

  it('mints a dangerous scope on a fresh session, and audits the elevation and the grant (#185, #186)', async () => {
    const jar = await signInWithPassword(server(), EMAIL);
    const { id } = await consentStep(jar, { scope: 'openid write:notes' });
    const signedInBefore = await events(SIGNED_IN);

    callbackOf(await decide(jar, id, 'allow'));

    const [code] = await codeRows();
    expect(code?.scopes).toEqual(['openid', 'write:notes']);
    // The code and the elevation carry the session's sign-in time.
    const authenticatedAt = new Date(Number(code?.auth_time)).toISOString();
    expect(await eventsOf(STEP_UP_ELEVATED)).toEqual([
      {
        // A client that is not an agent: no scope mode.
        data: {
          scopes: ['openid', 'write:notes'],
          dangerousScopes: ['write:notes'],
          authenticatedAt,
        },
        subject_id: userId,
        client_id: CLIENT_ID,
        realm_id: realmId,
      },
    ]);
    expect((await eventsOf(GRANTED)).map((event) => event.data)).toEqual([
      { scopes: ['openid', 'write:notes'], remembered: false, dangerousScopes: ['write:notes'] },
    ]);
    // Nobody signed in at the consent step.
    expect(await events(SIGNED_IN)).toBe(signedInBefore);
  });

  it('records the scope mode of an agent’s elevation (#186)', async () => {
    await setRealmLimit(null);
    await createClient('exec-bot', {
      scopes: ['openid', 'agent:exec'],
      isAgent: true,
      maxAgentMode: 'exec',
    });
    const jar = await signInWithPassword(server(), EMAIL);
    const { id, step } = await consentStep(jar, {
      client_id: 'exec-bot',
      scope: 'openid agent:exec',
    });
    expect(consentParams(step)['scopes']).toContainEqual({
      scope: 'agent:exec',
      sensitive: false,
      dangerous: true,
    });

    callbackOf(await decide(jar, id, 'allow'));

    expect(await eventsOf(STEP_UP_ELEVATED)).toEqual([
      {
        data: {
          scopes: ['openid', 'agent:exec'],
          dangerousScopes: ['agent:exec'],
          scopeMode: 'exec',
          authenticatedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/),
        },
        subject_id: userId,
        client_id: 'exec-bot',
        realm_id: realmId,
      },
    ]);
    expect((await eventsOf(GRANTED)).map((event) => event.data)).toEqual([
      { scopes: ['openid', 'agent:exec'], remembered: false, dangerousScopes: ['agent:exec'] },
    ]);
  });

  it('shows the step under prompt=consent although a stored consent covers the request', async () => {
    await consentTo(['openid', 'email']);
    const jar = await signInWithPassword(server(), EMAIL);

    await consentStep(jar, { prompt: 'consent' });

    // Without it, the stored consent gives the code at once.
    const skipped = await authorize(jar);
    expect(callbackOf(String(skipped.headers['location'])).get('code')).toMatch(/.+/);
  });

  it('shows an agent the step although a stored consent covers the request (ADR-015 Decision 11)', async () => {
    await setRealmLimit(null);
    const agentRowId = await createClient('remembered-agent', { isAgent: true });
    await consentTo(['openid', 'email'], agentRowId);
    const jar = await signInWithPassword(server(), EMAIL);

    const { step } = await consentStep(jar, { client_id: 'remembered-agent' });

    expect(consentParams(step)['agent']).toEqual({});
    expect(await codeRows(agentRowId)).toEqual([]);
  });
});
