import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
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
 * THE CONSENT SCREEN NAMES AN AGENT CLIENT AS AN AI AGENT, AND AN AGENT NEVER
 * SKIPS IT (ADR-014 §11, ADR-015 Decision 11, issue #845), end to end against
 * real Postgres and Redis.
 *
 * For a client with `is_agent`, `/ui/consent` says, in QAuth's words, that the
 * client is an AI agent and how long it may keep working: until the person
 * revokes it, or, when the realm sets `sso_max_lifespan`, until that long
 * after the sign-in at the latest, which is where #552 ends the agent's
 * refresh-token family. A stored consent never skips the screen for an agent,
 * and `prompt=none`, which may show no screen, answers `consent_required`.
 * A client that is not an agent sees neither line and keeps the skip.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const MINUTE = 60_000;
const EMAIL = 'agent-owner@example.test';
const AGENT_ID = 'release-bot';
const APP_ID = 'notes-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

const AGENT_LINE = 'is an AI agent.';
const PERSISTENCE_LINE = 'It may keep working until you revoke it';

describe('the consent screen for an AI agent client (#845, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer(baseEnvironment(infra, await generateJwtPem()));
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
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  /**
   * Set the realm's `sso_max_lifespan`, as an operator does in the database,
   * and drop the host cache so the next request reads the new row.
   */
  async function setRealmLimit(app: FastifyInstance, seconds: number | null): Promise<void> {
    await app.dbPool.query('UPDATE realms SET sso_max_lifespan = $1 WHERE name = $2', [
      seconds,
      E2E_REALM_NAME,
    ]);
    app.realmHostCache.clear();
  }

  /**
   * A signed-in user, an operator-provisioned agent client and a client that
   * is not an agent, both public, with the same scopes. With `remembered` the
   * user has a stored consent that covers the request for both.
   *
   * @returns the browser session's cookie
   */
  async function signedInUser(
    app: FastifyInstance,
    opts: { agentName?: string; remembered?: boolean } = {}
  ): Promise<string> {
    const userId = await registerPasswordAccount(app, EMAIL);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    for (const [clientId, name, isAgent] of [
      [AGENT_ID, opts.agentName ?? 'Release Bot', true],
      [APP_ID, 'Notes App', false],
    ] as const) {
      const client = await app.repositories.oauthClients.create({
        realmId: realm.id,
        clientId,
        clientSecretHash: 'unused-public-client',
        tokenEndpointAuthMethod: 'none',
        name,
        redirectUris: [REDIRECT_URI],
        scopes: SCOPES,
        grantTypes: ['authorization_code', 'refresh_token'],
        enabled: true,
        requirePkce: true,
        isAgent,
        // A seeded client: its redirect URI receives authorization errors.
        provisionedByOperator: true,
      });
      if (opts.remembered === true) {
        await app.repositories.oauthConsents.upsertGrant(realm.id, userId, client.id, SCOPES);
      }
    }
    const jar = await signInWithPassword(app, EMAIL);
    return jar.header() as string;
  }

  /** `/oauth/authorize` for `clientId` with the browser session's cookie. */
  async function authorize(
    app: FastifyInstance,
    cookie: string,
    clientId: string,
    extra: Record<string, string> = {}
  ): Promise<{ response: LightMyRequestResponse; verifier: string }> {
    const pkce = pkcePair();
    const response = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'agent-state',
        ...extra,
      }).toString()}`,
      headers: { cookie },
    });
    return { response, verifier: pkce.verifier };
  }

  /** Authorize `clientId`, follow the redirect to the consent screen and return its page. */
  async function consentScreen(
    app: FastifyInstance,
    cookie: string,
    clientId: string
  ): Promise<{ body: string; verifier: string }> {
    const { response, verifier } = await authorize(app, cookie, clientId);
    expect(response.statusCode).toBe(302);
    const location = response.headers['location'] as string;
    expect(location.startsWith('/ui/consent?')).toBe(true);
    const screen = await app.inject({ method: 'GET', url: location, headers: { cookie } });
    expect(screen.statusCode).toBe(200);
    return { body: screen.body, verifier };
  }

  /** Allow the page, with "Remember this decision" ticked, and return the code. */
  async function allow(app: FastifyInstance, cookie: string, page: string): Promise<string> {
    const hidden = Object.fromEntries(
      [...page.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)].map(
        ([, name, value]) => [name, decodeHtmlEntities(value)]
      )
    );
    const decision = await app.inject({
      method: 'POST',
      url: '/ui/consent',
      headers: { ...FORM, cookie },
      payload: new URLSearchParams({
        ...hidden,
        csrf_token: extractCsrfToken(page),
        decision: 'allow',
        allow_forever: '1',
      }).toString(),
    });
    expect(decision.statusCode).toBe(302);
    const code = new URL(decision.headers['location'] as string).searchParams.get('code');
    if (code === null) throw new Error(`no code in ${decision.headers['location']}`);
    return code;
  }

  function tokenRequest(
    app: FastifyInstance,
    form: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams(form).toString(),
    });
  }

  async function codesOf(app: FastifyInstance, clientId: string): Promise<number> {
    const { rows } = await app.dbPool.query<{ count: string }>(
      `SELECT count(*) AS count FROM authorization_codes c
       JOIN oauth_clients o ON o.id = c.oauth_client_id WHERE o.client_id = $1`,
      [clientId]
    );
    return Number(rows[0].count);
  }

  it('names an agent client as an AI agent with the persistence line, and a client that is not one with neither', async () => {
    const app = server();
    await setRealmLimit(app, null);
    const cookie = await signedInUser(app);

    const agent = await consentScreen(app, cookie, AGENT_ID);
    expect(agent.body).toContain('Release Bot wants to access your account');
    expect(agent.body).toContain('<p>Release Bot is an AI agent.</p>');
    expect(agent.body).toContain(`<p>${PERSISTENCE_LINE}.</p>`);

    const app2 = await consentScreen(app, cookie, APP_ID);
    expect(app2.body).toContain('Notes App wants to access your account');
    expect(app2.body).not.toContain(AGENT_LINE);
    expect(app2.body).not.toContain(PERSISTENCE_LINE);
  });

  it('says only "until you revoke it" in a realm without sso_max_lifespan', async () => {
    const app = server();
    await setRealmLimit(app, null);
    const cookie = await signedInUser(app);

    const { body } = await consentScreen(app, cookie, AGENT_ID);
    expect(body).toContain('<p>It may keep working until you revoke it.</p>');
    expect(body).not.toContain('whichever comes first');
    expect(body).not.toContain('after you signed in');
  });

  it('names the realm’s sso_max_lifespan, and the agent’s family ends that long after the sign-in (#552)', async () => {
    const app = server();
    // A one-hour limit, set before the user signs in: the browser session
    // ends an hour after the sign-in, and so does every family it backs.
    await setRealmLimit(app, 3600);
    const cookie = await signedInUser(app);

    const limited = await consentScreen(app, cookie, AGENT_ID);
    expect(limited.body).toContain(
      '<p>It may keep working until you revoke it, or until 1 hour after you signed in, ' +
        'whichever comes first.</p>'
    );

    // The user allows it and remembers the decision: the exchange starts the
    // agent's refresh-token family.
    const code = await allow(app, cookie, limited.body);
    const exchange = await tokenRequest(app, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: AGENT_ID,
      code_verifier: limited.verifier,
    });
    expect(exchange.statusCode).toBe(200);
    const refreshToken = (exchange.json() as { refresh_token?: string }).refresh_token;
    if (refreshToken === undefined) throw new Error('the exchange issued no refresh token');

    // The family ends an hour after the sign-in, as the page said: the
    // earlier of its start plus the limit and its session's end, which is the
    // sign-in plus the limit.
    const {
      rows: [family],
    } = await app.dbPool.query<{
      family_created_at: string;
      family_session_expires_at: string | null;
      signed_in_at: string;
    }>(
      `SELECT r.family_created_at, r.family_session_expires_at, s.created_at AS signed_in_at
       FROM refresh_tokens r
       JOIN oauth_clients o ON o.id = r.oauth_client_id
       JOIN authorization_codes c ON c.id = r.authorization_code_id
       JOIN sessions s ON s.id = c.session_id
       WHERE o.client_id = $1`,
      [AGENT_ID]
    );
    const familyCreatedAt = Number(family.family_created_at);
    const familyEnd = Math.min(
      familyCreatedAt + 60 * MINUTE,
      Number(family.family_session_expires_at)
    );
    expect(Number(family.family_session_expires_at)).toBe(
      Number(family.signed_in_at) + 60 * MINUTE
    );
    expect(familyEnd).toBe(Number(family.signed_in_at) + 60 * MINUTE);

    // Before the end the agent refreshes; past it, invalid_grant.
    vi.setSystemTime(familyEnd - MINUTE);
    const before = await tokenRequest(app, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: AGENT_ID,
    });
    expect(before.statusCode).toBe(200);
    const current = (before.json() as { refresh_token: string }).refresh_token;

    vi.setSystemTime(familyEnd + MINUTE);
    const after = await tokenRequest(app, {
      grant_type: 'refresh_token',
      refresh_token: current,
      client_id: AGENT_ID,
    });
    expect(after.statusCode).toBe(400);
    expect(after.json()).toMatchObject({ error: 'invalid_grant' });
    expect(after.json()).not.toHaveProperty('refresh_token');
  });

  it('shows the screen to an agent under a covering stored consent, and skips it for a client that is not one', async () => {
    const app = server();
    await setRealmLimit(app, null);
    const cookie = await signedInUser(app, { remembered: true });

    const agent = await authorize(app, cookie, AGENT_ID);
    expect(agent.response.statusCode).toBe(302);
    expect((agent.response.headers['location'] as string).startsWith('/ui/consent?')).toBe(true);
    expect(await codesOf(app, AGENT_ID)).toBe(0);

    const notAgent = await authorize(app, cookie, APP_ID);
    expect(notAgent.response.statusCode).toBe(302);
    const location = new URL(notAgent.response.headers['location'] as string);
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
    expect(location.searchParams.get('code')).not.toBeNull();
    expect(await codesOf(app, APP_ID)).toBe(1);
  });

  it('answers prompt=none from an agent with consent_required and issues no code', async () => {
    const app = server();
    await setRealmLimit(app, null);
    const cookie = await signedInUser(app, { remembered: true });

    const { response } = await authorize(app, cookie, AGENT_ID, { prompt: 'none' });
    expect(response.statusCode).toBe(302);
    const location = new URL(response.headers['location'] as string);
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe('consent_required');
    expect(location.searchParams.get('state')).toBe('agent-state');
    expect(location.searchParams.get('code')).toBeNull();
    expect(await codesOf(app, AGENT_ID)).toBe(0);

    // The same silent request from a client that is not an agent is served
    // from its stored consent.
    const control = await authorize(app, cookie, APP_ID, { prompt: 'none' });
    expect(
      new URL(control.response.headers['location'] as string).searchParams.get('code')
    ).not.toBeNull();
  });

  it('escapes markup in the client name on the agent line', async () => {
    const app = server();
    await setRealmLimit(app, null);
    const cookie = await signedInUser(app, { agentName: '<script>alert(1)</script> & "Bot"' });

    const { body } = await consentScreen(app, cookie, AGENT_ID);
    expect(body).toContain(
      '<p>&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;Bot&quot; is an AI agent.</p>'
    );
    expect(body).not.toContain('<script>alert(1)');
  });
});
