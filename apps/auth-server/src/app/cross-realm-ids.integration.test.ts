import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { type CompactJWSHeaderParameters, CompactSign, decodeProtectedHeader } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type CookieJar,
  decodeJwtClaims,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  provisionRealmKeys,
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
 * request with a random value of that kind, and expects the two to get the
 * same answer (status, body less its `trace_id`), to leave the same events and,
 * within a tolerance, to take the same time. Where it matters, the value is
 * then shown still good in realm A, so the refusal at B changed nothing there.
 *
 * The last rows go the other way, a realm-B token to the default realm.
 * Tokens are signed per realm (#491), so such a token verifies with none of
 * the default realm's keys: it is compared with the same token signed by a key
 * no realm holds, the answer a forged token gets.
 *
 * Where an earlier check (client ownership, the user a consent belongs to)
 * would refuse a realm-A value at B by itself, the row seeds a realm-A row that
 * names realm B's user, which the schema allows, so that only the realm filter
 * stands between the request and the row.
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
/** How many times each side of a comparison is timed, after one warm-up pair; medians are compared. */
const TIMING_SAMPLES = 5;

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
  /** Bob's `users.id`, a user of realm B. */
  readonly bobId: string;
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
 * Send one request, time it, and read the events it stored. Requests are sent
 * one at a time, so the events after the highest `seq` seen before are this
 * request's. Only the request itself is timed, not the event reads.
 */
async function sendAndReadEvents(
  app: FastifyInstance,
  send: () => Promise<LightMyRequestResponse>
): Promise<{ response: LightMyRequestResponse; events: EventSeen[]; ms: number }> {
  const before = await app.dbPool.query<{ seq: string }>(
    'SELECT coalesce(max(seq), 0)::text AS seq FROM events'
  );
  const start = performance.now();
  const response = await send();
  const ms = performance.now() - start;
  const { rows } = await app.dbPool.query<EventSeen>(
    `SELECT realm_id, type, subject_id, data FROM events
     WHERE seq > $1::bigint ORDER BY seq`,
    [before.rows[0]?.seq ?? '0']
  );
  return { response, events: rows, ms };
}

let addresses = 0;

/**
 * A client address of its own for one request, so the per-address rate limits
 * of the routes compared here never answer one side of a pair with a 429.
 */
function nextAddress(): string {
  addresses += 1;
  return `10.89.${Math.floor(addresses / 250)}.${(addresses % 250) + 1}`;
}

function median(values: readonly number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] as number;
}

/**
 * Send `foreignValue` (another realm's) and `unknownValue` alternately and
 * expect, for every pair, the same answer and the same events stored: an event
 * that recorded another realm's user as its subject, or a reason only a found
 * row can have, tells the value apart as surely as the response would.
 *
 * The time check compares medians with a tolerance (50 ms or half the slower
 * median), after one untimed warm-up pair: both sides run the same single
 * statement, and the token, introspection and userinfo answers are also padded
 * to a floor, so a lookup that told the two apart by doing more work for one of
 * them shows up here, while scheduler noise on a loaded runner does not.
 *
 * @returns the foreign value's answer, for assertions of its own.
 */
async function expectSameAnswerAsUnknown(
  app: FastifyInstance,
  send: (value: string) => Promise<LightMyRequestResponse>,
  foreignValue: string,
  unknownValue: string
): Promise<{ status: number; body: unknown }> {
  const times = { foreign: [] as number[], unknown: [] as number[] };
  let foreignAnswer: { status: number; body: unknown } | undefined;
  for (let sample = 0; sample <= TIMING_SAMPLES; sample += 1) {
    const foreign = await sendAndReadEvents(app, async () => send(foreignValue));
    const unknown = await sendAndReadEvents(app, async () => send(unknownValue));
    foreignAnswer = answerOf(foreign.response, foreignValue);
    const unknownAnswer = answerOf(unknown.response, unknownValue);
    expect(foreignAnswer, JSON.stringify({ foreignAnswer, unknownAnswer })).toEqual(unknownAnswer);
    expect(foreign.events).toEqual(unknown.events);
    if (sample === 0) continue; // the warm-up pair is not timed
    times.foreign.push(foreign.ms);
    times.unknown.push(unknown.ms);
  }
  const [f, u] = [median(times.foreign), median(times.unknown)];
  expect(Math.abs(f - u), `medians ${f.toFixed(1)} ms vs ${u.toFixed(1)} ms`).toBeLessThanOrEqual(
    Math.max(50, Math.max(f, u) / 2)
  );
  return foreignAnswer as { status: number; body: unknown };
}

/**
 * `token` with its header and claims as they are, signed by a fresh Ed25519
 * key that no realm holds: a forgery that names the same key.
 */
async function forgedLike(token: string): Promise<string> {
  const [, payload] = token.split('.');
  return new CompactSign(Buffer.from(payload, 'base64url'))
    .setProtectedHeader(decodeProtectedHeader(token) as CompactJWSHeaderParameters)
    .sign(generateKeyPairSync('ed25519').privateKey);
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
    // A realm signs its tokens only with its own keys (#491).
    await provisionRealmKeys(app, 'beta');

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

    const bob = await registerPasswordAccount(app, BOB, E2E_PASSWORD, { host: HOST_B });
    const bobTokenB = await managementToken(app, HOST_B, BOB);

    world = {
      app,
      realmA,
      realmB,
      clientA: clientA.id,
      aliceId: alice,
      consentA: consent.id,
      jarA,
      bobId: bob,
      bobTokenB,
    };
    return world;
  }

  /** The developer-portal token `/auth/login` gives `email` at `host`. */
  async function managementToken(app: FastifyInstance, host: string, email: string) {
    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: { host },
      payload: { email, password: E2E_PASSWORD },
    });
    expect(login.statusCode, login.body).toBe(200);
    return login.json<{ access_token: string }>().access_token;
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
      remoteAddress: nextAddress(),
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
      remoteAddress: nextAddress(),
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

    const answer = await expectSameAnswerAsUnknown(
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

    const answer = await expectSameAnswerAsUnknown(
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

    const answer = await expectSameAnswerAsUnknown(
      w.app,
      async (value) =>
        w.app.inject({
          remoteAddress: nextAddress(),
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
        remoteAddress: nextAddress(),
        method: 'POST',
        url: '/oauth/introspect',
        headers: { ...FORM, host },
        payload: new URLSearchParams({
          token,
          client_id: CLIENT_ID,
          client_secret: secret,
        }).toString(),
      });

    const answer = await expectSameAnswerAsUnknown(
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
        remoteAddress: nextAddress(),
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
    // A realm-A consent that names bob, realm B's user: the user filter alone
    // would let bob revoke it at B, so only the realm filter refuses it.
    const crossed = await w.app.repositories.oauthConsents.upsertGrant(
      w.realmA.id,
      w.bobId,
      w.clientA,
      SCOPES
    );

    for (const consentId of [w.consentA, crossed.id]) {
      const answer = await expectSameAnswerAsUnknown(
        w.app,
        async (value) =>
          w.app.inject({
            remoteAddress: nextAddress(),
            method: 'DELETE',
            url: `/api/consents/${value}`,
            headers: { host: HOST_B, authorization: `Bearer ${w.bobTokenB}` },
          }),
        consentId,
        randomUUID()
      );
      expect(answer.status).toBe(404);
    }

    expect(
      (await w.app.repositories.oauthConsents.findActive(w.realmA.id, w.aliceId, w.clientA))?.id
    ).toBe(w.consentA);
    expect(
      (await w.app.repositories.oauthConsents.findActive(w.realmA.id, w.bobId, w.clientA))?.id
    ).toBe(crossed.id);
  });

  it('a client id of realm A is 404 at realm B, as a random id is', async () => {
    const w = await setUp();
    // A realm-A client whose developer is bob, realm B's user: ownership alone
    // would hand it to him at B, so only the realm filter refuses it.
    const crossed = await w.app.repositories.oauthClients.create({
      realmId: w.realmA.id,
      clientId: 'owned-across-realms',
      clientSecretHash: 'unused',
      tokenEndpointAuthMethod: 'none',
      name: 'E2E owned across realms',
      developerId: w.bobId,
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code'],
      enabled: true,
      requirePkce: true,
    });

    for (const clientRowId of [w.clientA, crossed.id]) {
      const answer = await expectSameAnswerAsUnknown(
        w.app,
        async (value) =>
          w.app.inject({
            remoteAddress: nextAddress(),
            method: 'GET',
            url: `/api/clients/${value}`,
            headers: { host: HOST_B, authorization: `Bearer ${w.bobTokenB}` },
          }),
        clientRowId,
        randomUUID()
      );
      expect(answer.status).toBe(404);
    }

    // Bob's own listing at B does not show it either.
    const listed = await w.app.inject({
      method: 'GET',
      url: '/api/clients',
      headers: { host: HOST_B, authorization: `Bearer ${w.bobTokenB}` },
    });
    expect(listed.statusCode, listed.body).toBe(200);
    expect(listed.body).not.toContain(crossed.id);
  });

  it("a realm-B user's token at the default realm's userinfo is answered as a forged one (#491)", async () => {
    const w = await setUp();

    const answer = await expectSameAnswerAsUnknown(
      w.app,
      async (token) =>
        w.app.inject({
          remoteAddress: nextAddress(),
          method: 'GET',
          url: '/oauth/userinfo',
          headers: { host: HOST_A, authorization: `Bearer ${token}` },
        }),
      w.bobTokenB,
      await forgedLike(w.bobTokenB)
    );
    expect(answer).toMatchObject({ status: 401, body: { error: 'invalid_token' } });
  });

  it("a realm-B user's token at the default realm's introspection is inactive, as a forged one is (#491)", async () => {
    const w = await setUp();
    // A resource server of the default realm that is authoritative for the
    // portal token's audience: were the token verified, the audience would
    // admit it there.
    const audience = decodeJwtClaims(w.bobTokenB)['aud'];
    const secret = 'secret-of-the-introspecting-client-0123';
    await w.app.repositories.oauthClients.create({
      realmId: w.realmA.id,
      clientId: 'introspector',
      clientSecretHash: await w.app.passwordHasher.hashPassword(secret),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'E2E introspector',
      redirectUris: [],
      scopes: [],
      grantTypes: ['client_credentials'],
      audience: [audience].flat() as string[],
      enabled: true,
      requirePkce: false,
    });

    const answer = await expectSameAnswerAsUnknown(
      w.app,
      async (token) =>
        w.app.inject({
          remoteAddress: nextAddress(),
          method: 'POST',
          url: '/oauth/introspect',
          headers: { ...FORM, host: HOST_A },
          payload: new URLSearchParams({
            token,
            client_id: 'introspector',
            client_secret: secret,
          }).toString(),
        }),
      w.bobTokenB,
      await forgedLike(w.bobTokenB)
    );
    expect(answer).toEqual({ status: 200, body: { active: false } });
  });

  it("a realm-B client_credentials token, for an audience a resource server of the default realm is authoritative for, is inactive at the default realm's introspection and not denylisted by its revocation (#491)", async () => {
    const w = await setUp();
    // A client_credentials token names no user, so no realm-scoped user
    // lookup stands between it and the default realm: only its realm's keys
    // and issuer do. The same client_id in both realms, so client ownership
    // does not refuse it either.
    const audience = 'https://rs.cross-realm.example.com';
    const machine = 'cross-realm-machine';
    const secrets = {
      a: 'secret-of-the-machine-in-a-0123456',
      b: 'secret-of-the-machine-in-b-0123456',
    };
    for (const [realm, secret] of [
      [w.realmA, secrets.a],
      [w.realmB, secrets.b],
    ] as const) {
      await w.app.repositories.oauthClients.create({
        realmId: realm.id,
        clientId: machine,
        clientSecretHash: await w.app.passwordHasher.hashPassword(secret),
        tokenEndpointAuthMethod: 'client_secret_post',
        name: 'E2E cross-realm machine',
        redirectUris: [],
        scopes: ['read'],
        grantTypes: ['client_credentials'],
        audience: [audience],
        enabled: true,
        requirePkce: false,
      });
    }
    const introspectorSecret = 'secret-of-the-authoritative-rs-0123';
    await w.app.repositories.oauthClients.create({
      realmId: w.realmA.id,
      clientId: 'cross-realm-rs',
      clientSecretHash: await w.app.passwordHasher.hashPassword(introspectorSecret),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'E2E authoritative resource server',
      redirectUris: [],
      scopes: [],
      grantTypes: ['client_credentials'],
      audience: [audience],
      enabled: true,
      requirePkce: false,
    });

    const issued = await w.app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { ...FORM, host: HOST_B },
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'read',
        client_id: machine,
        client_secret: secrets.b,
      }).toString(),
    });
    expect(issued.statusCode, issued.body).toBe(200);
    const token = issued.json<{ access_token: string }>().access_token;
    expect(decodeJwtClaims(token)).toMatchObject({ iss: `https://${HOST_B}`, aud: audience });

    const introspect = (host: string, clientId: string, secret: string) =>
      w.app.inject({
        method: 'POST',
        url: '/oauth/introspect',
        headers: { ...FORM, host },
        payload: new URLSearchParams({
          token,
          client_id: clientId,
          client_secret: secret,
        }).toString(),
      });
    // At the default realm: inactive for the authoritative resource server
    // and for the same-named client alike.
    for (const [clientId, secret] of [
      ['cross-realm-rs', introspectorSecret],
      [machine, secrets.a],
    ] as const) {
      const atA = await introspect(HOST_A, clientId, secret);
      expect(atA.statusCode).toBe(200);
      expect(atA.json(), clientId).toEqual({ active: false });
    }

    // Revoked at the default realm by the same-named client: 200, as RFC 7009
    // §2.2 answers any token, and nothing is denylisted.
    const revoked = await w.app.inject({
      method: 'POST',
      url: '/oauth/revoke',
      headers: { ...FORM, host: HOST_A },
      payload: new URLSearchParams({
        token,
        client_id: machine,
        client_secret: secrets.a,
      }).toString(),
    });
    expect(revoked.statusCode).toBe(200);

    // Still active where it was issued.
    const atB = await introspect(HOST_B, machine, secrets.b);
    expect(atB.json()).toMatchObject({
      active: true,
      client_id: machine,
      iss: `https://${HOST_B}`,
    });
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
        remoteAddress: nextAddress(),
        method: 'POST',
        url: '/auth/verify',
        headers: { host },
        payload: { token: value, password: E2E_PASSWORD },
      });

    const answer = await expectSameAnswerAsUnknown(
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
        remoteAddress: nextAddress(),
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
