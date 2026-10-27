import { performance } from 'node:perf_hooks';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
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
 * CLIENT-SECRET CHECKS ARE SHED, NOT QUEUED, WHEN THE ARGON2 QUEUE IS FULL
 * (#751, GHSA-7fxx-3c59-jx98).
 *
 * Every presented `client_secret` costs one Argon2id verification, and at
 * most half the libuv thread pool runs them at once (d822f30). The queue in
 * front of that cap used to have no length limit, so a burst waited there
 * until its callers timed out. With `PASSWORD_HASH_QUEUE_LIMIT` jobs waiting,
 * a further check is now refused at once with 503 and `Retry-After`.
 *
 * The burst below mixes the three endpoints that check a secret. While it
 * runs, a JWT-authenticated request (`GET /oauth/userinfo`, whose signature
 * check runs on the same thread pool through WebCrypto) must answer within
 * twice its idle latency.
 *
 * The burst is small on purpose. It runs in this process, on the event loop
 * the JWT request needs too, and every request costs some main-thread work
 * whether it reaches Argon2 or not: 120 requests naming an unknown client,
 * which never hash, delayed the JWT request by 0.4 to 2 s. Thirty requests
 * cost it nothing measurable, yet hold far more checks than two slots and a
 * queue of two, and slow jobs keep both Argon2 threads busy while the JWT
 * request runs. A first burst of unknown clients opens the database pool, so
 * the measured one does not pay for new connections.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const MACHINE_CLIENT_ID = 'shedding-machine-client';
const MACHINE_SECRET = 'machine-client-secret-of-sufficient-length-42';
const MACHINE_SCOPE = 'reports:read';
const USER_EMAIL = 'shedding-user@example.test';

/** Waiting Argon2 jobs before a client-secret check is shed. */
const QUEUE_LIMIT = 2;
/** Requests per endpoint in the burst; far more than the slots and the queue hold. */
const BURST_PER_ENDPOINT = 10;
/** Idle userinfo requests the baseline latency is the median of. */
const IDLE_SAMPLES = 5;

/** pino's numeric level for `warn`. */
const PINO_WARN_LEVEL = 40;

/** One parsed line of the server's own log. */
interface LogLine {
  readonly level: number;
  readonly msg?: string;
  readonly statusCode?: number;
  readonly err?: { readonly type?: string; readonly details?: Record<string, unknown> };
}

type Endpoint = 'token' | 'introspect' | 'revoke';

const FORM = { 'content-type': 'application/x-www-form-urlencoded' } as const;

const ENDPOINTS: readonly Endpoint[] = ['token', 'introspect', 'revoke'];

/** One client-secret request to `endpoint`, with the right secret. */
function secretRequest(
  app: FastifyInstance,
  endpoint: Endpoint,
  clientId = MACHINE_CLIENT_ID
): Promise<LightMyRequestResponse> {
  const credentials = { client_id: clientId, client_secret: MACHINE_SECRET };
  const body =
    endpoint === 'token'
      ? { grant_type: 'client_credentials', scope: MACHINE_SCOPE, ...credentials }
      : { token: 'not-a-token-this-server-issued', ...credentials };
  return app.inject({
    method: 'POST',
    url: `/oauth/${endpoint}`,
    headers: FORM,
    payload: new URLSearchParams(body).toString(),
  });
}

/** Every request of a burst sent at once, the endpoints taking turns. */
function burst(
  app: FastifyInstance,
  clientId = MACHINE_CLIENT_ID
): Promise<{ endpoint: Endpoint; response: LightMyRequestResponse }>[] {
  return Array.from({ length: BURST_PER_ENDPOINT * ENDPOINTS.length }, (_, i) => {
    const endpoint = ENDPOINTS[i % ENDPOINTS.length] as Endpoint;
    return secretRequest(app, endpoint, clientId).then((response) => ({ endpoint, response }));
  });
}

/** Time one request, in milliseconds. */
async function timed<T>(request: () => Promise<T>): Promise<{ result: T; ms: number }> {
  const start = performance.now();
  const result = await request();
  return { result, ms: performance.now() - start };
}

function median(values: readonly number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] as number;
}

describe('client-secret checks under a burst (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  /** Boot a deployment with a small queue limit that records its own log. */
  async function withDeployment<T>(
    body: (app: FastifyInstance, log: () => LogLine[]) => Promise<T>
  ): Promise<T> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    // Parsed after the run, so the parsing does not compete with the burst.
    const raw: string[] = [];
    const log = (): LogLine[] => raw.map((line) => JSON.parse(line) as LogLine);
    let booted: BootedAuthServer | undefined;
    try {
      booted = await bootAuthServer(
        {
          ...baseEnvironment(infra, jwt),
          PASSWORD_HASH_QUEUE_LIMIT: String(QUEUE_LIMIT),
          // Each verification holds an Argon2 thread long enough that the
          // burst keeps both busy while the JWT request runs.
          PASSWORD_TIME_COST: '10',
          // A 429 would end the burst before the queue fills.
          TOKEN_RATE_LIMIT: '10000',
          TOKEN_RATE_LIMIT_LENIENT: '10000',
          INTROSPECT_RATE_LIMIT: '10000',
          USERINFO_RATE_LIMIT: '10000',
        },
        { logStream: { write: (line) => raw.push(line) } }
      );
      await resetE2eState(booted.app);
      return await body(booted.app, log);
    } finally {
      await booted?.close();
    }
  }

  async function seedMachineClient(app: FastifyInstance): Promise<void> {
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('the default realm was not booted');
    await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: MACHINE_CLIENT_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(MACHINE_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Shedding machine client',
      redirectUris: [],
      scopes: [MACHINE_SCOPE],
      grantTypes: ['client_credentials'],
      enabled: true,
    });
  }

  /** A user's access token from the first-party login, addressed to userinfo. */
  async function userAccessToken(app: FastifyInstance): Promise<string> {
    await registerPasswordAccount(app, USER_EMAIL);
    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: USER_EMAIL, password: E2E_PASSWORD },
    });
    expect(login.statusCode).toBe(200);
    return (login.json() as { access_token: string }).access_token;
  }

  function userinfo(app: FastifyInstance, accessToken: string): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'GET',
      url: '/oauth/userinfo',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  it('answers part of a burst with 503 and Retry-After, and keeps a JWT request fast', async () => {
    await withDeployment(async (app, log) => {
      await seedMachineClient(app);
      const accessToken = await userAccessToken(app);
      // Opens the database pool; an unknown client is refused before any hash.
      for (const { response } of await Promise.all(burst(app, 'no-such-client'))) {
        expect(response.statusCode).toBe(401);
      }

      // Idle: no Argon2 job runs or waits.
      const idle: number[] = [];
      for (let i = 0; i < IDLE_SAMPLES; i++) {
        const { result, ms } = await timed(() => userinfo(app, accessToken));
        expect(result.statusCode).toBe(200);
        idle.push(ms);
      }
      const idleLatency = median(idle);

      // The burst, every request in flight at once, then the JWT request
      // behind it.
      const inFlight = burst(app);
      const during = await timed(() => userinfo(app, accessToken));
      const answers = await Promise.all(inFlight);

      expect(during.result.statusCode).toBe(200);
      expect(during.ms).toBeLessThan(2 * idleLatency);

      // Every check either ran (the secret is right) or was shed; none timed
      // out, failed or was refused as a wrong secret.
      const shed = answers.filter(({ response }) => response.statusCode === 503);
      expect(answers.filter(({ response }) => ![200, 503].includes(response.statusCode))).toEqual(
        []
      );
      expect(shed.length).toBeGreaterThan(0);
      expect(shed.length).toBeLessThan(answers.length);
      for (const endpoint of ENDPOINTS) {
        expect(shed.some((answer) => answer.endpoint === endpoint)).toBe(true);
      }
      for (const { response } of shed) {
        expect(response.headers['retry-after']).toBe('1');
        // The OAuth error body and nothing else (#513): a 5xx carries no
        // description.
        expect(response.json()).toEqual({ error: 'temporarily_unavailable' });
      }

      // Counted, logged at warn with its reason, and recorded once as a
      // failure event per shed request.
      const counter = await app.metrics.clientSecretChecksShed.get();
      expect(counter.values[0]?.value).toBe(shed.length);

      const shedLines = log().filter((line) => line.statusCode === 503);
      expect(shedLines).toHaveLength(shed.length);
      for (const line of shedLines) {
        expect(line.level).toBe(PINO_WARN_LEVEL);
        expect(line.err?.type).toBe('TemporarilyUnavailableError');
        expect(line.err?.details).toMatchObject({
          reason: 'argon2_queue_full',
          clientId: MACHINE_CLIENT_ID,
          queueLimit: QUEUE_LIMIT,
        });
      }

      const events = await app.dbPool.query<{ type: string; data: { error?: string } }>(
        `SELECT type, data FROM events
         WHERE type IN (
           'urn:qauth:event:token.request_failed:v1-rc.0',
           'urn:qauth:event:token.introspection_failed:v1-rc.0',
           'urn:qauth:event:token.revocation_failed:v1-rc.0'
         )`
      );
      const shedEvents = events.rows.filter((row) => row.data.error === 'temporarily_unavailable');
      expect(shedEvents).toHaveLength(shed.length);
    });
  }, 180_000);

  it('serves every check of the same requests sent one at a time', async () => {
    // The limit sheds only what would queue: the same deployment, without a
    // burst, refuses nothing.
    await withDeployment(async (app) => {
      await seedMachineClient(app);
      for (const endpoint of ENDPOINTS) {
        for (let i = 0; i < 3; i++) {
          const response = await secretRequest(app, endpoint);
          expect(response.statusCode).toBe(200);
        }
      }
      const counter = await app.metrics.clientSecretChecksShed.get();
      expect(counter.values[0]?.value).toBe(0);
    });
  }, 120_000);
});
