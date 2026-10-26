import { randomBytes, randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type CookieJar,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import type { RealmRow } from './helpers/request-realm';

/**
 * AN ID FROM ANOTHER REALM IS AN UNKNOWN ID (ADR-019 Decision 1, issue #489).
 *
 * One deployment, two realms: the default realm A on `auth.example.com` and
 * realm B on `beta.example.com`. Each has a confidential client with the SAME
 * `client_id`, so a value of realm A presented at realm B passes client
 * authentication there and reaches the lookup this issue scopes; a refusal is
 * then the realm's doing, not the client's.
 *
 * Every row of the matrix presents a value of realm A at realm B, and the same
 * request with a random value of that kind, and expects the two answers to be
 * the same: status, body (less its `trace_id`) and, within a tolerance, time.
 * Where it matters, the value is then shown still good in realm A, so the
 * refusal at B changed nothing there.
 *
 * Failed logins for one address are counted per realm in
 * `realm-routing.integration.test.ts` ("keeps the login lockout of an address
 * apart in two realms"); this suite adds the verification-mail counters.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const HOST_A = 'auth.example.com';
const HOST_B = 'beta.example.com';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const CLIENT_ID = 'shared-client';
const SECRET_A = 'secret-of-the-realm-a-client-0123456789';
const SECRET_B = 'secret-of-the-realm-b-client-0123456789';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const ALICE = 'alice@example.com';
const BOB = 'bob@example.com';
/** How many times each side of a comparison is sent; the medians are compared. */
const TIMING_SAMPLES = 3;

interface World {
  readonly app: FastifyInstance;
  readonly realmA: RealmRow;
  readonly realmB: RealmRow;
  /** Realm A's `shared-client` row id. */
  readonly clientA: string;
  /** Alice's `users.id`, a user of realm A. */
  readonly aliceId: string;
  /** Realm A's active consent of alice for `shared-client`. */
  readonly consentA: string;
  /** Alice's browser at realm A. */
  readonly jarA: CookieJar;
  /** Bob's management token at realm B (`/auth/login`). */
  readonly bobTokenB: string;
}

/**
 * A response as the comparison sees it: status and body, `trace_id` dropped,
 * and the presented value masked where the body echoes it back (a problem
 * document's `instance` and `detail` name the id the caller sent).
 */
function answerOf(
  response: LightMyRequestResponse,
  presented: string
): { status: number; body: unknown } {
  const text = response.body.split(presented).join('<presented>');
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // Not JSON (an empty 200): compared as text.
  }
  if (body !== null && typeof body === 'object' && 'trace_id' in body) {
    body = Object.fromEntries(Object.entries(body).filter(([key]) => key !== 'trace_id'));
  }
  return { status: response.statusCode, body };
}

/** One stored event, as the comparison sees it: no id, time or request data. */
interface EventSeen {
  readonly realm_id: string;
  readonly type: string;
  readonly subject_id: string | null;
  readonly data: unknown;
}

/**
 * Send one request and read the events it stored. Requests are sent one at a
 * time, so the events after the highest `seq` seen before are this request's.
 */
async function sendAndReadEvents(
  app: FastifyInstance,
  send: () => Promise<LightMyRequestResponse>
): Promise<{ response: LightMyRequestResponse; events: EventSeen[] }> {
  const before = await app.dbPool.query<{ seq: string }>(
    'SELECT coalesce(max(seq), 0)::text AS seq FROM events'
  );
  const response = await send();
  const { rows } = await app.dbPool.query<EventSeen>(
    `SELECT realm_id, type, subject_id, data FROM events
     WHERE seq > $1::bigint ORDER BY seq`,
    [before.rows[0]?.seq ?? '0']
  );
  return { response, events: rows };
}

function median(values: readonly number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] as number;
}

/**
 * Send `realmAValue` and `randomValue` alternately and expect the same answer,
 * and the same events stored: an event that recorded realm A's user as the
 * subject at realm B, or a reason only a found row can have, tells the value
 * apart as surely as the response would.
 *
 * The time check compares medians with a tolerance (50 ms or half the slower
 * median): both sides run the same single statement, and the token, introspection
 * and userinfo answers are also padded to a floor, so a lookup that told the
 * two apart by doing more work for one of them shows up here, while scheduler
 * noise on a loaded runner does not.
 *
 * @returns the realm-A value's answer, for assertions of its own.
 */
async function expectSameAnswerAsRandom(
  app: FastifyInstance,
  send: (value: string) => Promise<LightMyRequestResponse>,
  realmAValue: string,
  randomValue: string
): Promise<{ status: number; body: unknown }> {
  const times = { realmA: [] as number[], random: [] as number[] };
  let realmAAnswer: { status: number; body: unknown } | undefined;
  let randomAnswer: { status: number; body: unknown } | undefined;
  for (let sample = 0; sample < TIMING_SAMPLES; sample += 1) {
    let start = performance.now();
    const realmA = await sendAndReadEvents(app, async () => send(realmAValue));
    times.realmA.push(performance.now() - start);
    start = performance.now();
    const random = await sendAndReadEvents(app, async () => send(randomValue));
    times.random.push(performance.now() - start);
    realmAAnswer = answerOf(realmA.response, realmAValue);
    randomAnswer = answerOf(random.response, randomValue);
    expect(realmA.events).toEqual(random.events);
  }
  expect(realmAAnswer, JSON.stringify({ realmAAnswer, randomAnswer })).toEqual(randomAnswer);
  const [a, r] = [median(times.realmA), median(times.random)];
  expect(Math.abs(a - r), `medians ${a.toFixed(1)} ms vs ${r.toFixed(1)} ms`).toBeLessThanOrEqual(
    Math.max(50, Math.max(a, r) / 2)
  );
  return realmAAnswer as { status: number; body: unknown };
}

describe('an id from another realm is an unknown id (#489)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let server: BootedAuthServer | undefined;
  let world: World | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await server?.close();
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  /** Seed `shared-client` in a realm, for the code and refresh-token grants. */
  async function seedClient(app: FastifyInstance, realm: RealmRow, secret: string) {
    return app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(secret),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: `E2E ${CLIENT_ID}`,
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
  }

  /**
   * One boot for the suite: every row below leaves realm A's values as it
   * found them, which is what the rows assert.
   */
  async function setUp(): Promise<World> {
    if (world) return world;
    if (!infra || !jwt) throw new Error('infrastructure not started');
    server = await bootAuthServer(baseEnvironment(infra, jwt));
    const { app } = server;
    await resetE2eState(app);

    const realmA = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realmA) throw new Error('the default realm boot step left no realm');
    const { realm: realmB } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: `https://${HOST_B}`, enabled: true },
      HOST_B
    );

    const clientA = await seedClient(app, realmA, SECRET_A);
    await seedClient(app, realmB, SECRET_B);

    const alice = await registerPasswordAccount(app, ALICE);
    const consent = await app.repositories.oauthConsents.upsertGrant(
      realmA.id,
      alice,
      clientA.id,
      SCOPES
    );
    const jarA = await signInWithPassword(app, ALICE);

    await registerPasswordAccount(app, BOB, E2E_PASSWORD, { host: HOST_B });
    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: { host: HOST_B },
      payload: { email: BOB, password: E2E_PASSWORD },
    });
    expect(login.statusCode, login.body).toBe(200);

    world = {
      app,
      realmA,
      realmB,
      clientA: clientA.id,
      aliceId: alice,
      consentA: consent.id,
      jarA,
      bobTokenB: login.json<{ access_token: string }>().access_token,
    };
    return world;
  }

  /** An authorization code of realm A, minted by alice's browser at realm A. */
  async function codeOfRealmA({ app, jarA }: World): Promise<{ code: string; verifier: string }> {
    const pkce = pkcePair();
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'cross-realm',
      }).toString()}`,
      headers: { host: HOST_A, cookie: jarA.header() as string },
    });
    expect(authorize.statusCode, authorize.body).toBe(302);
    const code = new URL(String(authorize.headers['location'])).searchParams.get('code');
    if (code === null) throw new Error('authorize returned no code');
    return { code, verifier: pkce.verifier };
  }

  async function redeemCode(
    app: FastifyInstance,
    host: string,
    secret: string,
    code: string,
    verifier: string
  ) {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { ...FORM, host },
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: secret,
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
      }).toString(),
    });
  }

  async function refresh(app: FastifyInstance, host: string, secret: string, token: string) {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { ...FORM, host },
      payload: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        client_secret: secret,
        refresh_token: token,
      }).toString(),
    });
  }

  /** Tokens of realm A: alice's code redeemed at realm A. */
  async function tokensOfRealmA(w: World) {
    const { code, verifier } = await codeOfRealmA(w);
    const response = await redeemCode(w.app, HOST_A, SECRET_A, code, verifier);
    expect(response.statusCode, response.body).toBe(200);
    return response.json<{ access_token: string; refresh_token: string }>();
  }

  it('an authorization code of realm A redeemed at realm B is invalid_grant, as a random code is', async () => {
    const w = await setUp();
    const { code, verifier } = await codeOfRealmA(w);

    const answer = await expectSameAnswerAsRandom(
      w.app,
      async (value) => redeemCode(w.app, HOST_B, SECRET_B, value, verifier),
      code,
      randomBytes(32).toString('base64url')
    );
    expect(answer).toMatchObject({ status: 400, body: { error: 'invalid_grant' } });

    // Not spent by the attempts at B: it still redeems where it was issued.
    const atA = await redeemCode(w.app, HOST_A, SECRET_A, code, verifier);
    expect(atA.statusCode, atA.body).toBe(200);
  });

  it('a refresh token of realm A is invalid_grant at realm B, as a random one is, and its family lives on', async () => {
    const w = await setUp();
    const { refresh_token: refreshToken } = await tokensOfRealmA(w);

    const answer = await expectSameAnswerAsRandom(
      w.app,
      async (value) => refresh(w.app, HOST_B, SECRET_B, value),
      refreshToken,
      randomBytes(32).toString('hex')
    );
    expect(answer).toMatchObject({ status: 400, body: { error: 'invalid_grant' } });

    // No replay detection fired on realm A's family: the token still rotates at A.
    const atA = await refresh(w.app, HOST_A, SECRET_A, refreshToken);
    expect(atA.statusCode, atA.body).toBe(200);
  });

  it('revoking a refresh token of realm A at realm B revokes nothing, as for a random one', async () => {
    const w = await setUp();
    const { refresh_token: refreshToken } = await tokensOfRealmA(w);

    const answer = await expectSameAnswerAsRandom(
      w.app,
      async (value) =>
        w.app.inject({
          method: 'POST',
          url: '/oauth/revoke',
          headers: { ...FORM, host: HOST_B },
          payload: new URLSearchParams({
            token: value,
            client_id: CLIENT_ID,
            client_secret: SECRET_B,
          }).toString(),
        }),
      refreshToken,
      randomBytes(32).toString('hex')
    );
    expect(answer.status).toBe(200);

    const atA = await refresh(w.app, HOST_A, SECRET_A, refreshToken);
    expect(atA.statusCode, atA.body).toBe(200);
  });

  it('an access token of realm A is inactive at realm B introspection, as a random token is', async () => {
    const w = await setUp();
    const { access_token: accessToken } = await tokensOfRealmA(w);
    const introspect = (host: string, secret: string, token: string) =>
      w.app.inject({
        method: 'POST',
        url: '/oauth/introspect',
        headers: { ...FORM, host },
        payload: new URLSearchParams({
          token,
          client_id: CLIENT_ID,
          client_secret: secret,
        }).toString(),
      });

    const answer = await expectSameAnswerAsRandom(
      w.app,
      async (value) => introspect(HOST_B, SECRET_B, value),
      accessToken,
      randomBytes(32).toString('base64url')
    );
    expect(answer).toEqual({ status: 200, body: { active: false } });

    // The same token is active where it was issued.
    const atA = await introspect(HOST_A, SECRET_A, accessToken);
    expect(atA.json()).toMatchObject({ active: true, client_id: CLIENT_ID });
  });

  it('an access token of realm A is refused 401 at realm B userinfo', async () => {
    const w = await setUp();
    const { access_token: accessToken } = await tokensOfRealmA(w);
    const userinfo = (host: string, token: string) =>
      w.app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: { host, authorization: `Bearer ${token}` },
      });

    const atB = await userinfo(HOST_B, accessToken);
    expect(atB.statusCode).toBe(401);
    expect(atB.json()).toMatchObject({ error: 'invalid_token' });
    expect(atB.json()).not.toHaveProperty('sub');

    // The same token is good where it was issued.
    const atA = await userinfo(HOST_A, accessToken);
    expect(atA.statusCode, atA.body).toBe(200);
  });

  it('a consent id of realm A is 404 at realm B, as a random id is, and the consent stays', async () => {
    const w = await setUp();

    const answer = await expectSameAnswerAsRandom(
      w.app,
      async (value) =>
        w.app.inject({
          method: 'DELETE',
          url: `/api/consents/${value}`,
          headers: { host: HOST_B, authorization: `Bearer ${w.bobTokenB}` },
        }),
      w.consentA,
      randomUUID()
    );
    expect(answer.status).toBe(404);

    const consent = await w.app.repositories.oauthConsents.findActive(
      w.realmA.id,
      w.aliceId,
      w.clientA
    );
    expect(consent?.id).toBe(w.consentA);
  });

  it('a client id of realm A is 404 at realm B, as a random id is', async () => {
    const w = await setUp();

    const answer = await expectSameAnswerAsRandom(
      w.app,
      async (value) =>
        w.app.inject({
          method: 'GET',
          url: `/api/clients/${value}`,
          headers: { host: HOST_B, authorization: `Bearer ${w.bobTokenB}` },
        }),
      w.clientA,
      randomUUID()
    );
    expect(answer.status).toBe(404);
  });

  it('a user id of realm A names no user at realm B', async () => {
    const w = await setUp();

    expect(await w.app.repositories.users.findById(w.realmB.id, w.aliceId)).toBeUndefined();
    expect(await w.app.repositories.users.findById(w.realmA.id, w.aliceId)).toMatchObject({
      id: w.aliceId,
    });
  });

  it('a verification token of realm A is refused at realm B, as a random token is, and still verifies at A', async () => {
    const w = await setUp();
    const email = 'carol@example.com';
    const tokens: string[] = [];
    const emailService = w.app.emailService;
    const original = emailService.sendVerificationEmail;
    emailService.sendVerificationEmail = async (to, token, options) => {
      if (to === email) tokens.push(token);
      return original.call(emailService, to, token, options);
    };
    try {
      const registered = await w.app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host: HOST_A },
        payload: { email, password: E2E_PASSWORD },
      });
      expect(registered.statusCode, registered.body).toBe(202);
      const deadline = Date.now() + 5_000;
      while (tokens.length === 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    } finally {
      emailService.sendVerificationEmail = original;
    }
    const token = tokens.at(-1);
    if (token === undefined) throw new Error('registration sent no verification mail');
    const verify = (host: string, value: string) =>
      w.app.inject({
        method: 'POST',
        url: '/auth/verify',
        headers: { host },
        payload: { token: value, password: E2E_PASSWORD },
      });

    const answer = await expectSameAnswerAsRandom(
      w.app,
      async (value) => verify(HOST_B, value),
      token,
      randomBytes(32).toString('hex')
    );
    expect(answer.status).toBeGreaterThanOrEqual(400);

    const atA = await verify(HOST_A, token);
    expect(atA.statusCode, atA.body).toBe(200);
  });

  it('counts verification mail for one address per realm', async () => {
    const w = await setUp();
    const resend = (host: string) =>
      w.app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host },
        payload: { email: 'dave@example.com' },
      });

    // The minimum interval holds the second request at realm A back ...
    expect((await resend(HOST_A)).statusCode).toBe(200);
    expect((await resend(HOST_A)).statusCode).toBe(429);
    // ... and does not reach realm B, where the address has its own allowance.
    expect((await resend(HOST_B)).statusCode).toBe(200);

    const keys = await w.app.redis.keys('*:resend:*');
    const lastSent = await w.app.redis.keys('last-email-sent:*');
    for (const realm of [w.realmA, w.realmB]) {
      expect(keys.some((key) => key.startsWith(`rate-limit:resend:${realm.id}:`))).toBe(true);
      expect(lastSent.some((key) => key.startsWith(`last-email-sent:${realm.id}:`))).toBe(true);
    }
  });
});
