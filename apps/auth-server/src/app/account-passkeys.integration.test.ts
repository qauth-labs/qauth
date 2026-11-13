import { randomUUID } from 'node:crypto';

import * as contract from '@qauth-labs/shared-account-contract';
import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

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
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { type SoftPasskey, softPasskey, type SoftPasskeyCreation } from '../testing/soft-passkey';

/**
 * THE ACCOUNT API'S PASSKEYS, AND A PASSKEY SET-UP THROUGH AN AUTHORIZATION
 * REQUEST (#1108; ADR-020 §1 and §3, ADR-017 Decision 8, ADR-019 Decision 7),
 * against a real Postgres and Redis, booted with INTERACTION_UI_ENABLED and
 * WEBAUTHN_ENABLED on. One case per acceptance criterion:
 *
 * - the list shows each passkey's nickname, creation time, last use and
 *   whether it syncs; one passkey reads with its ETag, and its rename takes
 *   `If-Match`;
 * - removing the only passkey of a passkey-only account answers
 *   `last_credential`;
 * - a stale sign-in gets the `insufficient_user_authentication` challenge on
 *   a removal;
 * - an act-chain token gets `delegated_token_refused` on the rename and the
 *   removal;
 * - an authorization request with `qauth_action=setup_passkey`, from a client
 *   whose audience lists the account API, signs the person in fresh although
 *   the browser has a session, binds a passkey through `webauthn_create` (a
 *   software authenticator), and returns a code;
 * - a client whose audience does not list the account API is refused.
 *
 * Tokens are minted as the code exchange mints the account API's (`auth_time`,
 * `amr`), for the account console's backend.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ACCOUNT_AUDIENCE = contract.ACCOUNT_API_AUDIENCE;
const PASSKEYS = `${contract.ACCOUNT_API_PREFIX}/passkeys`;
const MERGE_PATCH = 'application/merge-patch+json';
const ORIGIN = 'https://auth.example.com';
const RP_ID = 'auth.example.com';
const CONSOLE_ID = 'account-console';
const OTHER_ID = 'ordinary-app';
const REDIRECT_URI = 'https://console.example.com/callback';
const SCOPES = ['openid', 'email'];
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony page sends it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');
const WEBAUTHN_GET = stepUrn('webauthn_get');
const WEBAUTHN_CREATE = stepUrn('webauthn_create');
const RECOVERY_CODES = stepUrn('recovery_codes');
const CONSENT = stepUrn('consent');
const DAY_MS = 86_400_000;

/** The step view the ceremony page reads. */
interface StepView {
  readonly step: string;
  readonly csrf: string;
  readonly params?: Record<string, Record<string, unknown>>;
}

/** An interaction in progress: its browser, its id and its PKCE verifier. */
interface Flow {
  readonly jar: CookieJar;
  id: string;
  readonly verifier: string;
}

/** A passkey's `credential_data`, as an enrolment stores it. */
function passkeyData(
  n: number,
  fields: {
    readonly nickname?: string | null;
    readonly createdAt?: number;
    readonly lastUsedAt?: number | null;
    readonly backedUp?: boolean;
  } = {}
): Record<string, unknown> {
  return {
    public_key: 'pQECAyYgASFYIK_voW-Xypst',
    algorithm: -7,
    sign_count: 0,
    transports: ['internal'],
    backup_eligible: fields.backedUp ?? true,
    backed_up: fields.backedUp ?? true,
    aaguid: '00000000-0000-0000-0000-000000000000',
    rp_id: RP_ID,
    user_handle: `dXNlci1oYW5kbGU${n}`,
    nickname: fields.nickname ?? null,
    created_at: fields.createdAt ?? Date.now(),
    last_used_at: fields.lastUsedAt ?? null,
    sign_counter_regressed_at: null,
  };
}

/** The creation options the "add a passkey" page hands the browser's ceremony. */
function creationOptionsOf(body: string): SoftPasskeyCreation & {
  readonly user: { readonly id: string };
} {
  const match = /data-options="([^"]*)"/.exec(body);
  if (match === null) throw new Error('no options on the page');
  return JSON.parse(
    (match[1] as string)
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
  );
}

describe('the account API’s passkeys and the passkey set-up (#1108, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let accounts = 0;
  let signCookie: ((session: { sid: string; realmId: string }) => Promise<string>) | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer({
      ...baseEnvironment(infra, await generateJwtPem()),
      INTERACTION_UI_ENABLED: 'true',
      WEBAUTHN_ENABLED: 'true',
      // Each case registers its accounts and drives its pages from one address.
      REGISTRATION_RATE_LIMIT: '10000',
      VERIFICATION_RATE_LIMIT: '10000',
      AUTHORIZE_RATE_LIMIT: '10000',
      AUTHORIZE_RATE_LIMIT_LENIENT: '10000',
    });
    // Imported after the boot, as the harness imports the app: the module
    // reads the environment the boot sets.
    const { signSessionCookie, SESSION_COOKIE_NAME } = await import('./helpers/session-cookie');
    const app = booted.app;
    signCookie = async (session) =>
      `${SESSION_COOKIE_NAME}=${await signSessionCookie(app, session)}`;
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    await resetE2eState(booted.app);
    const realm = await booted.app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
  }, 120_000);

  function app(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  async function query<Row extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = []
  ): Promise<Row[]> {
    return (await app().dbPool.query<Row>(sql, params)).rows;
  }

  async function eventsOf(type: string, userId: string): Promise<Record<string, unknown>[]> {
    const rows = await query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      [`urn:qauth:event:${type}:v1-rc.0`, userId]
    );
    return rows.map((row) => row.data);
  }

  // ── Accounts ───────────────────────────────────────────────────────────

  /** A verified password account: its id and address. */
  async function passwordAccount(): Promise<{ userId: string; email: string }> {
    const email = `passkeys-${++accounts}-${randomUUID()}@example.test`;
    return { userId: await registerPasswordAccount(app(), email), email };
  }

  /** An account whose only credential is a passkey; its id and the passkey's. */
  async function passkeyOnlyAccount(): Promise<{ userId: string; passkeyId: string }> {
    const created = await app().repositories.users.create(
      { realmId },
      {
        providerType: 'webauthn',
        externalSub: `cGFzc2tleS1vbmx5${++accounts}`,
        credentialData: passkeyData(accounts),
      }
    );
    const [row] = await query<{ id: string }>(
      "SELECT id::text AS id FROM user_credentials WHERE user_id = $1 AND provider_type = 'webauthn'",
      [created.id]
    );
    return { userId: created.id, passkeyId: row?.id as string };
  }

  /** Bind a passkey to the account; its credential id. */
  async function bindPasskey(
    userId: string,
    fields: Parameters<typeof passkeyData>[1] = {}
  ): Promise<string> {
    const row = await app().repositories.userCredentials.create({
      userId,
      realmId,
      providerType: 'webauthn',
      externalSub: `cGFzc2tleS0${++accounts}`,
      credentialData: passkeyData(accounts, fields),
    });
    return row.id;
  }

  async function passkeyRows(userId: string): Promise<{ id: string; external_sub: string }[]> {
    return query(
      "SELECT id::text AS id, external_sub FROM user_credentials WHERE user_id = $1 AND provider_type = 'webauthn' ORDER BY id",
      [userId]
    );
  }

  // ── Tokens and calls ───────────────────────────────────────────────────

  /** A sign-in `secondsAgo` old, as the token's `auth_time` keeps it: whole seconds, in ms. */
  function signedInAgo(secondsAgo: number): number {
    return (Math.floor(Date.now() / 1000) - secondsAgo) * 1000;
  }

  /** An account API token, as the code exchange mints it for the account console. */
  async function token(
    userId: string,
    claims: { authTime?: number; amr?: readonly string[]; act?: { sub: string } } = {}
  ): Promise<string> {
    return app().jwtUtils.signAccessToken(
      { id: realmId },
      {
        sub: userId,
        clientId: CONSOLE_ID,
        aud: ACCOUNT_AUDIENCE,
        scope: 'qauth:account:read qauth:account:write',
        ...claims,
      }
    );
  }

  /** A token of a sign-in with a passkey five seconds ago. */
  function freshPasskeyToken(userId: string, act?: { sub: string }): Promise<string> {
    return token(userId, {
      authTime: signedInAgo(5),
      amr: ['pop', 'mfa'],
      ...(act === undefined ? {} : { act }),
    });
  }

  function call(
    method: 'GET' | 'PATCH' | 'DELETE',
    path: string,
    bearer: string,
    options: { readonly headers?: Record<string, string>; readonly body?: unknown } = {}
  ): Promise<LightMyRequestResponse> {
    return app().inject({
      method,
      url: path,
      headers: {
        authorization: `Bearer ${bearer}`,
        ...(options.body === undefined ? {} : { 'content-type': MERGE_PATCH }),
        ...options.headers,
      },
      ...(options.body === undefined ? {} : { payload: JSON.stringify(options.body) }),
    });
  }

  // ── The operations ─────────────────────────────────────────────────────

  describe('GET /passkeys and GET /passkeys/{passkeyId}', () => {
    it('lists each passkey’s nickname, creation time, last use and whether it syncs, newest first', async () => {
      const { userId } = await passwordAccount();
      const older = Date.now() - 3 * DAY_MS;
      const used = Date.now() - DAY_MS;
      const laptop = await bindPasskey(userId, {
        nickname: 'Work laptop',
        createdAt: older,
        lastUsedAt: used,
        backedUp: false,
      });
      const phone = await bindPasskey(userId, { nickname: null, createdAt: older + 60_000 });

      const listed = await call('GET', PASSKEYS, await token(userId));
      expect(listed.statusCode, listed.body).toBe(200);
      expect(listed.headers['cache-control']).toBe('no-store');
      expect(listed.json()).toEqual({
        items: [
          {
            id: phone,
            // A passkey the person never named shows the default name.
            nickname: 'Passkey',
            backedUp: true,
            createdAt: new Date(older + 60_000).toISOString(),
            lastUsedAt: null,
          },
          {
            id: laptop,
            nickname: 'Work laptop',
            backedUp: false,
            createdAt: new Date(older).toISOString(),
            lastUsedAt: new Date(used).toISOString(),
          },
        ],
        nextCursor: null,
      });

      // A page of one, then the rest from its cursor.
      const first = await call('GET', `${PASSKEYS}?limit=1`, await token(userId));
      expect(first.statusCode, first.body).toBe(200);
      const page = first.json<{ items: { id: string }[]; nextCursor: string | null }>();
      expect(page.items.map((item) => item.id)).toEqual([phone]);
      expect(page.nextCursor).toEqual(expect.any(String));
      const rest = await call(
        'GET',
        `${PASSKEYS}?limit=1&cursor=${encodeURIComponent(page.nextCursor as string)}`,
        await token(userId)
      );
      expect(rest.json<{ items: { id: string }[] }>().items.map((item) => item.id)).toEqual([
        laptop,
      ]);

      // A read takes a delegated token (ADR-019 Decision 7).
      const delegated = await call(
        'GET',
        PASSKEYS,
        await token(userId, { act: { sub: 'support-agent' } })
      );
      expect(delegated.statusCode, delegated.body).toBe(200);
      expect(delegated.json()).toEqual(listed.json());

      // One passkey, with its entity tag; another account's is not found.
      const one = await call('GET', `${PASSKEYS}/${laptop}`, await token(userId));
      expect(one.statusCode, one.body).toBe(200);
      expect(one.headers['etag']).toMatch(/^"[^"]+"$/);
      expect(one.json()).toMatchObject({ id: laptop, nickname: 'Work laptop' });
      const other = await passwordAccount();
      const foreign = await call('GET', `${PASSKEYS}/${laptop}`, await token(other.userId));
      expect(foreign.statusCode, foreign.body).toBe(404);
      expect(foreign.json()).toMatchObject({ code: 'not_found' });
    });
  });

  describe('PATCH /passkeys/{passkeyId}', () => {
    it('renames a passkey under If-Match, with no fresh sign-in, and records it', async () => {
      const { userId } = await passwordAccount();
      const passkeyId = await bindPasskey(userId, { nickname: 'Phone' });
      // A sign-in an hour old: a name is no credential.
      const bearer = await token(userId, { authTime: signedInAgo(3_600), amr: ['pwd'] });
      const read = await call('GET', `${PASSKEYS}/${passkeyId}`, bearer);
      const etag = String(read.headers['etag']);

      const unconditional = await call('PATCH', `${PASSKEYS}/${passkeyId}`, bearer, {
        body: { nickname: 'Pixel' },
      });
      expect(unconditional.statusCode, unconditional.body).toBe(428);

      const renamed = await call('PATCH', `${PASSKEYS}/${passkeyId}`, bearer, {
        headers: { 'if-match': etag },
        body: { nickname: 'Pixel' },
      });
      expect(renamed.statusCode, renamed.body).toBe(200);
      expect(renamed.json()).toMatchObject({ id: passkeyId, nickname: 'Pixel' });
      expect(renamed.headers['etag']).not.toBe(etag);

      // The old tag no longer matches.
      const stale = await call('PATCH', `${PASSKEYS}/${passkeyId}`, bearer, {
        headers: { 'if-match': etag },
        body: { nickname: 'Again' },
      });
      expect(stale.statusCode, stale.body).toBe(412);
      expect(
        (await call('GET', `${PASSKEYS}/${passkeyId}`, bearer)).json<{ nickname: string }>()
          .nickname
      ).toBe('Pixel');

      expect(await eventsOf('user.passkey_renamed', userId)).toHaveLength(1);
    });

    it('refuses an act-chain token with delegated_token_refused, and renames nothing', async () => {
      const { userId } = await passwordAccount();
      const passkeyId = await bindPasskey(userId, { nickname: 'Phone' });
      const etag = String(
        (await call('GET', `${PASSKEYS}/${passkeyId}`, await token(userId))).headers['etag']
      );

      const delegated = await call(
        'PATCH',
        `${PASSKEYS}/${passkeyId}`,
        await freshPasskeyToken(userId, { sub: 'support-agent' }),
        { headers: { 'if-match': etag }, body: { nickname: 'Taken over' } }
      );
      expect(delegated.statusCode, delegated.body).toBe(403);
      expect(delegated.json()).toMatchObject({ code: 'delegated_token_refused' });
      expect(
        (await call('GET', `${PASSKEYS}/${passkeyId}`, await token(userId))).json<{
          nickname: string;
        }>().nickname
      ).toBe('Phone');
    });
  });

  describe('DELETE /passkeys/{passkeyId}', () => {
    it('removes a passkey after a fresh sign-in with it, and sends the person no data back', async () => {
      const { userId } = await passwordAccount();
      const passkeyId = await bindPasskey(userId);

      const removed = await call(
        'DELETE',
        `${PASSKEYS}/${passkeyId}`,
        await freshPasskeyToken(userId)
      );
      expect(removed.statusCode, removed.body).toBe(204);
      expect(await passkeyRows(userId)).toEqual([]);
      expect(await eventsOf('user.credential_removed', userId)).toEqual([
        expect.objectContaining({ type: 'passkey', credentialId: passkeyId }),
      ]);

      const again = await call(
        'DELETE',
        `${PASSKEYS}/${passkeyId}`,
        await freshPasskeyToken(userId)
      );
      expect(again.statusCode, again.body).toBe(404);
    });

    it('refuses to remove the only passkey of a passkey-only account with last_credential', async () => {
      const { userId, passkeyId } = await passkeyOnlyAccount();

      const refused = await call(
        'DELETE',
        `${PASSKEYS}/${passkeyId}`,
        await freshPasskeyToken(userId)
      );
      expect(refused.statusCode, refused.body).toBe(409);
      expect(refused.json()).toMatchObject({ code: 'last_credential' });
      expect((await passkeyRows(userId)).map((row) => row.id)).toEqual([passkeyId]);
    });

    it('answers a stale sign-in with the insufficient_user_authentication challenge', async () => {
      const { userId } = await passwordAccount();
      const passkeyId = await bindPasskey(userId);

      const stale = await call(
        'DELETE',
        `${PASSKEYS}/${passkeyId}`,
        await token(userId, { authTime: signedInAgo(3_600), amr: ['pop', 'mfa'] })
      );
      expect(stale.statusCode, stale.body).toBe(401);
      expect(stale.headers['www-authenticate']).toBe(
        'Bearer error="insufficient_user_authentication", max_age="300"'
      );
      expect(stale.json()).toMatchObject({ code: 'insufficient_user_authentication' });

      // A fresh sign-in with the password alone is not the strongest factor.
      const weaker = await call(
        'DELETE',
        `${PASSKEYS}/${passkeyId}`,
        await token(userId, { authTime: signedInAgo(5), amr: ['pwd'] })
      );
      expect(weaker.statusCode, weaker.body).toBe(401);
      expect(weaker.headers['www-authenticate']).toBe(
        'Bearer error="insufficient_user_authentication", max_age="0"'
      );
      expect(await passkeyRows(userId)).toHaveLength(1);
    });

    it('refuses an act-chain token with delegated_token_refused, and removes nothing', async () => {
      const { userId } = await passwordAccount();
      const passkeyId = await bindPasskey(userId);

      const delegated = await call(
        'DELETE',
        `${PASSKEYS}/${passkeyId}`,
        await freshPasskeyToken(userId, { sub: 'support-agent' })
      );
      expect(delegated.statusCode, delegated.body).toBe(403);
      expect(delegated.json()).toMatchObject({ code: 'delegated_token_refused' });
      expect(await passkeyRows(userId)).toHaveLength(1);
    });

    it('removes a passkey still new with a fresh sign-in by password alone (#1064)', async () => {
      const { userId } = await passwordAccount();
      const passkeyId = await bindPasskey(userId);
      await query('UPDATE user_credentials SET new_until = $2 WHERE id = $1::uuid', [
        passkeyId,
        Date.now() + DAY_MS,
      ]);

      const removed = await call(
        'DELETE',
        `${PASSKEYS}/${passkeyId}`,
        await token(userId, { authTime: signedInAgo(5), amr: ['pwd'] })
      );
      expect(removed.statusCode, removed.body).toBe(204);
      expect(await passkeyRows(userId)).toEqual([]);
    });
  });

  // ── The set-up through an authorization request ───────────────────────

  describe('an authorization request with qauth_action=setup_passkey', () => {
    /** A client of the realm, with the account API's audience when `account`. */
    async function client(clientId: string, account: boolean): Promise<void> {
      const created = await app().repositories.oauthClients.create({
        realmId,
        clientId,
        clientSecretHash: 'unused-public-client',
        tokenEndpointAuthMethod: 'none',
        name: account ? 'Account console' : 'Ordinary app',
        redirectUris: [REDIRECT_URI],
        scopes: SCOPES,
        grantTypes: ['authorization_code'],
        enabled: true,
        requirePkce: true,
        // A seeded client: its redirect URI receives authorization errors.
        provisionedByOperator: true,
      });
      if (account) {
        await query('UPDATE oauth_clients SET audience = $2::jsonb WHERE id = $1', [
          created.id,
          JSON.stringify([ACCOUNT_AUDIENCE]),
        ]);
      }
    }

    /** A browser with a live session of the account, signed in a minute ago with its password. */
    async function signedInBrowser(userId: string): Promise<CookieJar> {
      if (signCookie === undefined) throw new Error('server not booted');
      const session = await app().sessionService.create({
        realmId,
        userId,
        authTime: Date.now() - 60_000,
        amr: ['pwd'],
        ipAddress: '192.0.2.10',
        userAgent: 'Browser/1',
      });
      const jar = new CookieJar();
      jar.absorb(await signCookie({ sid: session.sid, realmId }));
      return jar;
    }

    /** `/oauth/authorize` from `jar`'s browser, asking for the set-up. */
    async function authorize(
      jar: CookieJar,
      clientId: string
    ): Promise<{ response: LightMyRequestResponse; verifier: string }> {
      const { verifier, challenge } = pkcePair();
      const response = await app().inject({
        method: 'GET',
        url: `/oauth/authorize?${new URLSearchParams({
          response_type: 'code',
          client_id: clientId,
          redirect_uri: REDIRECT_URI,
          scope: SCOPES.join(' '),
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'set-up-state',
          qauth_action: 'setup_passkey',
        }).toString()}`,
        headers: { cookie: jar.header() ?? '' },
      });
      jar.absorb(response.headers['set-cookie']);
      return { response, verifier };
    }

    /** The path of a redirect, without the realm origin. */
    function locationOf(response: LightMyRequestResponse): string {
      expect([302, 303], response.body).toContain(response.statusCode);
      const location = String(response.headers['location']);
      return location.startsWith(`${ORIGIN}/`) ? location.slice(ORIGIN.length) : location;
    }

    async function read(id: string): Promise<StepView> {
      const response = await app().inject({
        method: 'GET',
        url: `${INTERACTION_API_PREFIX}/${id}`,
      });
      expect(response.statusCode, response.body).toBe(200);
      return response.json();
    }

    async function answer(
      flow: Flow,
      type: string,
      fields: Record<string, string> = {}
    ): Promise<LightMyRequestResponse> {
      const { csrf } = await read(flow.id);
      const response = await app().inject({
        method: 'POST',
        url: `${INTERACTION_API_PREFIX}/${flow.id}/answer`,
        headers: { ...FORM, ...SAME_ORIGIN, cookie: flow.jar.header() ?? '' },
        payload: new URLSearchParams({ type, csrf, ...fields }).toString(),
      });
      flow.jar.absorb(response.headers['set-cookie']);
      return response;
    }

    /** The "add a passkey" page of the interaction, opened by its browser. */
    async function enrolmentPage(flow: Flow): Promise<string> {
      const response = await app().inject({
        method: 'GET',
        url: `/ui/passkey-enrolment/${flow.id}`,
        headers: { cookie: flow.jar.header() ?? '', 'sec-fetch-site': 'same-origin' },
      });
      expect(response.statusCode, response.body).toBe(200);
      return response.body;
    }

    /**
     * Follow the interaction from the authorization endpoint's redirect to
     * the client's redirect URI: the address and the password, the passkey
     * (created by a software authenticator unless `decline`), the recovery
     * codes, the consent. Returns the steps it was asked, the passkey and the
     * redirect.
     */
    async function setUp(
      email: string,
      started: LightMyRequestResponse,
      jar: CookieJar,
      verifier: string,
      decline = false
    ): Promise<{ steps: string[]; created?: SoftPasskey; callback: URL; flow: Flow }> {
      const path = locationOf(started);
      expect(path.startsWith(CEREMONY_PAGE_PREFIX), path).toBe(true);
      const flow: Flow = { jar, id: path.slice(CEREMONY_PAGE_PREFIX.length), verifier };
      const steps: string[] = [];
      let created: SoftPasskey | undefined;
      for (let round = 0; round < 12; round += 1) {
        const view = await read(flow.id);
        steps.push(view.step);
        let response: LightMyRequestResponse;
        if (view.step === WEBAUTHN_GET || view.step === IDENTIFIER) {
          response = await answer(flow, IDENTIFIER, { login_hint: email });
        } else if (view.step === PASSWORD) {
          response = await answer(flow, PASSWORD, { password: E2E_PASSWORD });
        } else if (view.step === WEBAUTHN_CREATE && decline) {
          response = await answer(flow, WEBAUTHN_CREATE);
        } else if (view.step === WEBAUTHN_CREATE) {
          const options = creationOptionsOf(await enrolmentPage(flow));
          const passkey = softPasskey(RP_ID, options.user.id);
          response = await answer(flow, WEBAUTHN_CREATE, {
            webauthn_response: passkey.create(options),
          });
          created = passkey;
        } else if (view.step === RECOVERY_CODES) {
          response = await answer(flow, RECOVERY_CODES, { acknowledged: 'true' });
        } else if (view.step === CONSENT) {
          response = await answer(flow, CONSENT, { decision: 'allow' });
        } else {
          throw new Error(`no answer for the step ${view.step}`);
        }
        expect(response.statusCode, response.body).toBe(303);
        const location = String(response.headers['location']);
        if (location.startsWith(REDIRECT_URI)) {
          return {
            steps,
            ...(created === undefined ? {} : { created }),
            callback: new URL(location),
            flow,
          };
        }
        const next = locationOf(response);
        expect(next.startsWith(CEREMONY_PAGE_PREFIX), next).toBe(true);
        flow.id = next.slice(CEREMONY_PAGE_PREFIX.length);
      }
      throw new Error('the interaction never reached the redirect URI');
    }

    async function exchange(code: string, verifier: string): Promise<LightMyRequestResponse> {
      return app().inject({
        method: 'POST',
        url: '/oauth/token',
        headers: FORM,
        payload: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: CONSOLE_ID,
          redirect_uri: REDIRECT_URI,
          code_verifier: verifier,
        }).toString(),
      });
    }

    it('signs the person in fresh, binds a passkey through webauthn_create, and returns a code', async () => {
      await client(CONSOLE_ID, true);
      const { userId, email } = await passwordAccount();
      const jar = await signedInBrowser(userId);

      const { response, verifier } = await authorize(jar, CONSOLE_ID);
      // The session the browser has does not stand in for the sign-in.
      const { steps, created, callback } = await setUp(email, response, jar, verifier);
      expect(steps).toContain(PASSWORD);
      expect(steps).toContain(WEBAUTHN_CREATE);
      expect(steps.indexOf(PASSWORD)).toBeLessThan(steps.indexOf(WEBAUTHN_CREATE));
      expect(await eventsOf('user.signed_in', userId)).toEqual([
        expect.objectContaining({ method: 'password' }),
      ]);

      // The passkey is bound to the account.
      if (created === undefined) throw new Error('no passkey was created');
      const rows = await passkeyRows(userId);
      expect(rows.map((row) => row.external_sub)).toEqual([created.credentialId]);
      expect(await eventsOf('user.credential_added', userId)).toEqual([
        expect.objectContaining({ type: 'passkey', credentialId: rows[0]?.id }),
      ]);

      // The code at the client's redirect URI, with its state; it exchanges.
      expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
      expect(callback.searchParams.get('state')).toBe('set-up-state');
      const code = callback.searchParams.get('code');
      expect(code).toEqual(expect.any(String));
      const exchanged = await exchange(code as string, verifier);
      expect(exchanged.statusCode, exchanged.body).toBe(200);

      // The console's backend sees it in the account API's list.
      const listed = await call('GET', PASSKEYS, await token(userId));
      expect(listed.json<{ items: { id: string }[] }>().items.map((item) => item.id)).toEqual([
        rows[0]?.id,
      ]);
    });

    it('returns a code with no passkey when the person declines it', async () => {
      await client(CONSOLE_ID, true);
      const { userId, email } = await passwordAccount();
      const jar = new CookieJar();

      const { response, verifier } = await authorize(jar, CONSOLE_ID);
      const { steps, callback } = await setUp(email, response, jar, verifier, true);
      expect(steps).toContain(WEBAUTHN_CREATE);
      expect(callback.searchParams.get('code')).toEqual(expect.any(String));
      expect(await passkeyRows(userId)).toEqual([]);
    });

    it('refuses a client whose audience does not list the account API, before any sign-in', async () => {
      await client(OTHER_ID, false);
      const { userId } = await passwordAccount();
      const jar = await signedInBrowser(userId);

      const { response } = await authorize(jar, OTHER_ID);
      expect(response.statusCode, response.body).toBe(302);
      const callback = new URL(String(response.headers['location']));
      expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
      expect(callback.searchParams.get('error')).toBe('unauthorized_client');
      expect(callback.searchParams.get('state')).toBe('set-up-state');
      expect(callback.searchParams.has('code')).toBe(false);
      expect(await passkeyRows(userId)).toEqual([]);
    });
  });
});
