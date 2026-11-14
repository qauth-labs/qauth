import { createHmac } from 'node:crypto';

import type { MfaPolicyReader } from '@qauth-labs/fastify-plugin-sign-in-engine';
import * as contract from '@qauth-labs/shared-account-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { REDIS_KEYS } from './constants/redis-keys';
import type { BackgroundTasks } from './helpers/background-tasks';
import type { InteractionEngines } from './helpers/interaction-engines';

/**
 * THE ACCOUNT API'S AUTHENTICATOR APP AND RECOVERY CODES (#1109; ADR-017
 * Decision 8, ADR-020 §3, ADR-019 Decision 7), against a real Postgres and
 * Redis, with INTERACTION_UI_ENABLED on and an MFA policy each case sets (the
 * boot's test option). One case per acceptance criterion:
 *
 * - an enrolment binds only after a valid first code, and a wrong code
 *   answers `invalid_code`;
 * - a stale sign-in gets the `insufficient_user_authentication` challenge on
 *   every change, and an act-chain token gets `delegated_token_refused`;
 * - regenerating invalidates the old set and answers the new one once;
 * - removing the last second factor the policy requires answers
 *   `second_factor_required`;
 * - the secret and the codes never appear in a log line or a cached answer.
 *
 * The authenticator app is this file's own RFC 6238 code generator (SHA-1,
 * six digits, 30 seconds) over the secret the enrolment answers. Tokens are
 * minted as the code exchange mints the account API's (`auth_time`, `amr`),
 * for the account console's backend.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ACCOUNT_AUDIENCE = contract.ACCOUNT_API_AUDIENCE;
const PREFIX = contract.ACCOUNT_API_PREFIX;
const CONSOLE_ID = 'account-console';
const STEP_MS = 30_000;
/** A recovery code as the contract shows it. */
const RECOVERY_CODE = /^[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}$/;
const POLICY_OFF = Object.freeze({ realm: 'off', client: 'off' }) as Awaited<
  ReturnType<MfaPolicyReader['read']>
>;
const POLICY_REQUIRED = Object.freeze({ realm: 'required', client: 'off' }) as Awaited<
  ReturnType<MfaPolicyReader['read']>
>;
/** The background tasks of the ports this suite builds: run now, failures dropped. */
const TASKS: BackgroundTasks = {
  run: (task) => {
    void Promise.resolve()
      .then(task)
      .catch(() => undefined);
  },
};

/** RFC 4648 §6 base32, unpadded, as the enrolment answers the secret. */
function base32Decode(text: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const character of text) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error(`not base32: ${character}`);
    value = ((value << 5) | index) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** The authenticator app: the RFC 6238 code of `secret` at `at`, `offset` steps away. */
function codeAt(secret: Buffer, at: number, offset = 0): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / STEP_MS) + offset));
  const mac = createHmac('sha1', secret).update(counter).digest();
  const at4 = mac.readUInt8(19) & 0x0f;
  return String((mac.readUInt32BE(at4) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

/** A six-digit code no step of the window at `at` accepts. */
function wrongCodeAt(secret: Buffer, at: number): string {
  const valid = new Set([-1, 0, 1].map((offset) => codeAt(secret, at, offset)));
  for (const candidate of ['000000', '111111', '222222', '333333']) {
    if (!valid.has(candidate)) return candidate;
  }
  throw new Error('no wrong code');
}

/** A started enrolment, as the API answers it. */
interface Enrolment {
  readonly secret: string;
  readonly otpauthUri: string;
  readonly expiresAt: string;
  readonly emailCode: string;
}

/** A set of recovery codes, as the API answers it. */
interface CodeSet {
  readonly codes: readonly string[];
  readonly issuedAt: string;
}

describe('the account API’s authenticator app and recovery codes (#1109, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let accounts = 0;
  let engines: InteractionEngines | undefined;
  /** The MFA policy every read sees. */
  let policy = POLICY_OFF;
  /** Every line the server logged, from `debug` up. */
  const logLines: string[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, await generateJwtPem()),
        INTERACTION_UI_ENABLED: 'true',
        // Each case registers its own account from one address.
        REGISTRATION_RATE_LIMIT: '10000',
      },
      {
        mfaPolicy: { read: async () => policy },
        logStream: { write: (line) => logLines.push(line) },
        logLevel: 'debug',
      }
    );
    // Imported after the boot, as the harness imports the app: the modules
    // read the environment the boot sets, and share the app's instances.
    const { createInteractionEngines } = await import('./helpers/interaction-engines');
    engines = createInteractionEngines(booted.app, { tasks: TASKS });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
  });

  afterEach(() => {
    policy = POLICY_OFF;
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || !booted) {
      ctx.skip();
      return;
    }
    await resetE2eState(booted.app);
    const realm = await booted.app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    realmId = realm.id;
  });

  function app(): FastifyInstance {
    if (!booted) throw new Error('server not booted');
    return booted.app;
  }

  async function query<Row extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = []
  ): Promise<Row[]> {
    const { rows } = await app().dbPool.query<Row>(sql, params);
    return rows;
  }

  /** A verified password account. */
  function account(): Promise<string> {
    return registerPasswordAccount(app(), `factors-${++accounts}-${Date.now()}@example.com`);
  }

  /** A sign-in `secondsAgo` old, as the token's `auth_time` keeps it: whole seconds, in ms. */
  function signedInAgo(secondsAgo: number): number {
    return (Math.floor(Date.now() / 1000) - secondsAgo) * 1000;
  }

  /** An account API token, as the code exchange mints it for the account console. */
  function token(
    userId: string,
    claims: { authTime?: number; amr?: readonly string[]; sid?: string; act?: { sub: string } }
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

  /**
   * The browser session a sign-in `authTime` started, as the hosted pages
   * record it, and the account API token its code exchange mints, naming it
   * in `sid`: a factor bound new under it is named on it (#1064).
   */
  async function signedIn(
    userId: string,
    amr: readonly string[],
    options: { recoveryCodeUsed?: boolean } = {}
  ): Promise<{ bearer: string; sessionId: string }> {
    const authTime = signedInAgo(5);
    const session = await app().repositories.sessions.create({
      realmId,
      userId,
      authTime: authTime + 250,
      amr: [...amr],
      ...(options.recoveryCodeUsed === true ? { recoveryCodeUsed: true } : {}),
      expiresAt: Date.now() + 3_600_000,
    });
    return {
      bearer: await token(userId, { authTime, amr, sid: session.id }),
      sessionId: session.id,
    };
  }

  /** A fresh sign-in with the password alone, from the code exchange (`sid`). */
  async function passwordToken(userId: string): Promise<string> {
    return (await signedIn(userId, ['pwd'])).bearer;
  }

  /** A fresh sign-in with the password and the authenticator app. */
  function otpToken(userId: string): Promise<string> {
    return token(userId, { authTime: signedInAgo(5), amr: ['pwd', 'otp', 'mfa'] });
  }

  function call(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    bearer: string,
    payload?: Record<string, unknown>
  ): Promise<LightMyRequestResponse> {
    return app().inject({
      method,
      url: `${PREFIX}${path}`,
      headers: { authorization: `Bearer ${bearer}` },
      ...(payload === undefined ? {} : { payload }),
    });
  }

  async function startEnrolment(bearer: string): Promise<Enrolment> {
    const response = await call('POST', '/totp/enrollment', bearer);
    expect(response.statusCode, response.body).toBe(201);
    return response.json<Enrolment>();
  }

  /** Enrol an authenticator app through the API: its secret and the first set. */
  async function enrol(userId: string): Promise<{ secret: Buffer; first: CodeSet }> {
    const bearer = await passwordToken(userId);
    const enrolment = await startEnrolment(bearer);
    const secret = base32Decode(enrolment.secret);
    const bound = await call('POST', '/totp/enrollment/confirm', bearer, {
      code: codeAt(secret, Date.now()),
    });
    expect(bound.statusCode, bound.body).toBe(200);
    const first = bound.json<{ recoveryCodes: CodeSet }>().recoveryCodes;
    return { secret, first };
  }

  async function totpRows(userId: string): Promise<{ id: string }[]> {
    return query<{ id: string }>(
      "SELECT id FROM user_credentials WHERE user_id = $1 AND provider_type = 'totp'",
      [userId]
    );
  }

  async function eventsOf(
    type: string,
    userId: string
  ): Promise<{ data: Record<string, unknown>; client_id: string | null }[]> {
    return query<{ data: Record<string, unknown>; client_id: string | null }>(
      'SELECT data, client_id FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      [`urn:qauth:event:${type}:v1-rc.0`, userId]
    );
  }

  function redeem(userId: string, code: string) {
    if (engines === undefined) throw new Error('engines not built');
    return engines.recoveryCodes.redeem({ realmId, userId, clientId: CONSOLE_ID, code });
  }

  function expectChallenge(response: LightMyRequestResponse): void {
    expect(response.statusCode, response.body).toBe(401);
    expect(response.headers['www-authenticate']).toBe(
      'Bearer error="insufficient_user_authentication", max_age="300"'
    );
    expect(response.json()).toMatchObject({ code: 'insufficient_user_authentication' });
  }

  it('binds an enrolment only after a valid first code; a wrong code is invalid_code', async () => {
    const userId = await account();
    const bearer = await passwordToken(userId);

    const enrolment = await startEnrolment(bearer);
    expect(enrolment).toMatchObject({
      secret: expect.stringMatching(/^[A-Z2-7]{32}$/),
      otpauthUri: expect.stringMatching(/^otpauth:\/\/totp\//),
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      // The account decides, never a mailbox (ADR-017 Decision 8).
      emailCode: 'not_required',
    });
    expect(enrolment.otpauthUri).toContain(`secret=${enrolment.secret}`);
    // Started, nothing bound.
    expect(await totpRows(userId)).toEqual([]);

    const secret = base32Decode(enrolment.secret);
    const wrong = await call('POST', '/totp/enrollment/confirm', bearer, {
      code: wrongCodeAt(secret, Date.now()),
    });
    expect(wrong.statusCode, wrong.body).toBe(400);
    expect(wrong.json()).toMatchObject({ code: 'invalid_code' });
    expect(await totpRows(userId)).toEqual([]);

    // The enrolment waits for another code: the right one binds.
    const bound = await call('POST', '/totp/enrollment/confirm', bearer, {
      code: codeAt(secret, Date.now()),
    });
    expect(bound.statusCode, bound.body).toBe(200);
    const result = bound.json<{ enabledAt: string; recoveryCodes: CodeSet }>();
    expect(Date.parse(result.enabledAt)).toBeGreaterThan(Date.now() - 60_000);
    // The account's first second factor issues its first set, answered once.
    expect(result.recoveryCodes.codes).toHaveLength(10);
    for (const code of result.recoveryCodes.codes) expect(code).toMatch(RECOVERY_CODE);
    expect(await totpRows(userId)).toHaveLength(1);
    expect(await eventsOf('user.credential_added', userId)).toEqual([
      {
        data: expect.objectContaining({ type: 'totp', authenticator: 'app' }),
        client_id: CONSOLE_ID,
      },
    ]);

    // One confirmation takes the enrolment; another finds none.
    const again = await call('POST', '/totp/enrollment/confirm', bearer, {
      code: codeAt(secret, Date.now()),
    });
    expect(again.statusCode, again.body).toBe(404);
    // An account with an authenticator app starts no second one.
    const second = await call('POST', '/totp/enrollment', await otpToken(userId));
    expect(second.statusCode, second.body).toBe(409);
    expect(second.json()).toMatchObject({ code: 'conflict' });
    // The status reads the set without its codes.
    const status = await call('GET', '/recovery-codes', bearer);
    expect(status.statusCode, status.body).toBe(200);
    expect(status.json()).toEqual({ remaining: 10, issuedAt: result.recoveryCodes.issuedAt });
  });

  it('refuses an enrolment without a started one, or for an unclaimed account', async () => {
    const userId = await account();
    const none = await call('POST', '/totp/enrollment/confirm', await passwordToken(userId), {
      code: '123456',
    });
    expect(none.statusCode, none.body).toBe(404);
    expect(none.json()).toMatchObject({ code: 'not_found' });

    // An account nobody verified binds no factor (ADR-017 Decision 8).
    const email = `unclaimed-${++accounts}-${Date.now()}@example.com`;
    const registered = await app().inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: 'Correct-Horse-Battery-Staple-42!' },
    });
    expect(registered.statusCode, registered.body).toBe(202);
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      realmId,
      'password',
      email
    );
    if (credential === undefined) throw new Error('no registered account');
    const unclaimed = await call(
      'POST',
      '/totp/enrollment',
      await passwordToken(credential.userId)
    );
    expect(unclaimed.statusCode, unclaimed.body).toBe(409);
    expect(unclaimed.json()).toMatchObject({ code: 'conflict' });
  });

  it('challenges a stale sign-in on every change, and refuses an act-chain token', async () => {
    const userId = await account();
    await enrol(userId);
    const changes = [
      ['POST', '/totp/enrollment', undefined],
      ['POST', '/totp/enrollment/confirm', { code: '123456' }],
      ['DELETE', '/totp', undefined],
      ['POST', '/recovery-codes/regenerate', undefined],
    ] as const;

    const stale = await token(userId, { authTime: signedInAgo(301), amr: ['pwd', 'otp', 'mfa'] });
    for (const [method, path, body] of changes) {
      expectChallenge(await call(method, path, stale, body));
    }

    const delegated = await token(userId, {
      authTime: signedInAgo(5),
      amr: ['pwd', 'otp', 'mfa'],
      act: { sub: 'support-agent' },
    });
    for (const [method, path, body] of changes) {
      const response = await call(method, path, delegated, body);
      expect(response.statusCode, `${method} ${path}: ${response.body}`).toBe(403);
      expect(response.json()).toMatchObject({ code: 'delegated_token_refused' });
    }
    // Nothing changed: the app is still bound.
    expect(await totpRows(userId)).toHaveLength(1);
    // The read takes an act chain and needs no fresh sign-in.
    const read = await call('GET', '/recovery-codes', delegated);
    expect(read.statusCode, read.body).toBe(200);
  });

  it('regenerates a set: the old one stops working, and the new one is answered once', async () => {
    const userId = await account();
    const { first } = await enrol(userId);
    const bearer = await otpToken(userId);

    const regenerated = await call('POST', '/recovery-codes/regenerate', bearer);
    expect(regenerated.statusCode, regenerated.body).toBe(200);
    expect(regenerated.headers['cache-control']).toBe('no-store');
    const next = regenerated.json<CodeSet>();
    expect(next.codes).toHaveLength(10);
    for (const code of next.codes) expect(code).toMatch(RECOVERY_CODE);
    expect(next.codes.some((code) => first.codes.includes(code))).toBe(false);
    expect(await eventsOf('user.recovery_codes_regenerated', userId)).toEqual([
      { data: {}, client_id: CONSOLE_ID },
    ]);

    // Every code of the old set is refused against what is stored now: the
    // new set's ten rows alone, all unused.
    const redeemed = await Promise.all(first.codes.map((code) => redeem(userId, code)));
    expect(redeemed).toEqual(first.codes.map(() => ({ kind: 'refused' })));
    expect(
      await query('SELECT 1 FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NULL', [
        userId,
      ])
    ).toHaveLength(10);

    // Never answered again: the read says how many are left, never which.
    const status = await call('GET', '/recovery-codes', bearer);
    expect(status.json()).toEqual({ remaining: 10, issuedAt: next.issuedAt });
    for (const code of next.codes) expect(status.body).not.toContain(code);

    // The codes as answered (uppercase, in groups) are the ones stored: each
    // new one is redeemed as typed, where every old one was refused above.
    for (const code of next.codes) {
      expect(await redeem(userId, code), code).toEqual({ kind: 'redeemed' });
    }

    // An account with no second factor and no passkey has no set to regenerate.
    const plain = await account();
    const refused = await call('POST', '/recovery-codes/regenerate', await passwordToken(plain));
    expect(refused.statusCode, refused.body).toBe(409);
    expect(refused.json()).toMatchObject({ code: 'conflict' });
  });

  it('names a new app on the sign-in’s session, whose password undo ends it (#1064)', async () => {
    const userId = await account();
    const { bearer, sessionId } = await signedIn(userId, ['pwd']);
    const enrolment = await startEnrolment(bearer);
    const bound = await call('POST', '/totp/enrollment/confirm', bearer, {
      code: codeAt(base32Decode(enrolment.secret), Date.now()),
    });
    expect(bound.statusCode, bound.body).toBe(200);
    const [app] = await query<{ id: string; new_until: string | null }>(
      "SELECT id, new_until FROM user_credentials WHERE user_id = $1 AND provider_type = 'totp'",
      [userId]
    );
    // New: bound after a sign-in that proved the password alone.
    expect(app?.new_until).not.toBeNull();
    const [named] = await query<{ new_credential_ids: string[] }>(
      'SELECT new_credential_ids FROM sessions WHERE id = $1',
      [sessionId]
    );
    expect(named?.new_credential_ids).toEqual([app?.id]);

    // The password alone removes it, and ends the session that bound it.
    const undone = await call('DELETE', '/totp', await passwordToken(userId));
    expect(undone.statusCode, undone.body).toBe(204);
    const [ended] = await query<{ revoked_at: string | null }>(
      'SELECT revoked_at FROM sessions WHERE id = $1',
      [sessionId]
    );
    // Ended: revoked, or gone.
    expect(ended === undefined || ended.revoked_at !== null).toBe(true);
  });

  it('challenges a new binding whose token names no sign-in session, such as a refreshed one', async () => {
    const userId = await account();
    const refreshed = await token(userId, { authTime: signedInAgo(5), amr: ['pwd'] });
    const refused = await call('POST', '/totp/enrollment', refreshed);
    expect(refused.statusCode, refused.body).toBe(401);
    expect(refused.headers['www-authenticate']).toBe(
      'Bearer error="insufficient_user_authentication", max_age="0"'
    );
    expect(await totpRows(userId)).toEqual([]);
  });

  it('lets a recovery-code sign-in rebind a lost app where the policy refuses its removal', async () => {
    const userId = await account();
    await enrol(userId);
    // Past its window: a full factor, the account's strongest.
    await query(
      "UPDATE user_credentials SET new_until = NULL WHERE user_id = $1 AND provider_type = 'totp'",
      [userId]
    );
    const [before] = await query<{ secret: string }>(
      "SELECT credential_data->>'secret' AS secret FROM user_credentials WHERE user_id = $1 AND provider_type = 'totp'",
      [userId]
    );
    policy = POLICY_REQUIRED;
    // The app is lost: the person signs in with a recovery code in its place.
    const { bearer } = await signedIn(userId, ['pwd'], { recoveryCodeUsed: true });

    const removal = await call('DELETE', '/totp', bearer);
    expect(removal.statusCode, removal.body).toBe(409);
    expect(removal.json()).toMatchObject({ code: 'second_factor_required' });

    const enrolment = await startEnrolment(bearer);
    const rebound = await call('POST', '/totp/enrollment/confirm', bearer, {
      code: codeAt(base32Decode(enrolment.secret), Date.now()),
    });
    expect(rebound.statusCode, rebound.body).toBe(200);
    const after = await query<{ secret: string }>(
      "SELECT credential_data->>'secret' AS secret FROM user_credentials WHERE user_id = $1 AND provider_type = 'totp'",
      [userId]
    );
    expect(after).toHaveLength(1);
    expect(after[0]?.secret).not.toBe(before?.secret);
  });

  it('refuses to remove the last second factor the policy requires with second_factor_required', async () => {
    const userId = await account();
    await enrol(userId);
    const bearer = await otpToken(userId);

    policy = POLICY_REQUIRED;
    const refused = await call('DELETE', '/totp', bearer);
    expect(refused.statusCode, refused.body).toBe(409);
    expect(refused.json()).toMatchObject({ code: 'second_factor_required' });
    expect(await totpRows(userId)).toHaveLength(1);

    // Without the policy the app is removed, and the account has none left.
    policy = POLICY_OFF;
    const removed = await call('DELETE', '/totp', bearer);
    expect(removed.statusCode, removed.body).toBe(204);
    expect(await totpRows(userId)).toEqual([]);
    const gone = await call('DELETE', '/totp', bearer);
    expect(gone.statusCode, gone.body).toBe(404);
  });

  it('keeps the secret and the codes out of every log line and every cached answer', async () => {
    const userId = await account();
    const bearer = await passwordToken(userId);
    logLines.length = 0;

    const started = await call('POST', '/totp/enrollment', bearer);
    expect(started.statusCode, started.body).toBe(201);
    const enrolment = started.json<Enrolment>();
    const secret = base32Decode(enrolment.secret);
    // The enrolment keeps only the ciphertext.
    const held = await app().redis.get(REDIS_KEYS.ACCOUNT_TOTP_ENROLMENT(realmId, userId));
    expect(held).toEqual(expect.any(String));
    expect(held).not.toContain(enrolment.secret);
    expect(held).not.toContain(enrolment.secret.toLowerCase());

    const confirmed = await call('POST', '/totp/enrollment/confirm', bearer, {
      code: codeAt(secret, Date.now()),
    });
    expect(confirmed.statusCode, confirmed.body).toBe(200);
    const first = confirmed.json<{ recoveryCodes: CodeSet }>().recoveryCodes;
    const regenerated = await call('POST', '/recovery-codes/regenerate', await otpToken(userId));
    expect(regenerated.statusCode, regenerated.body).toBe(200);
    const next = regenerated.json<CodeSet>();
    const status = await call('GET', '/recovery-codes', bearer);
    const removed = await call('DELETE', '/totp', await otpToken(userId));
    expect(removed.statusCode, removed.body).toBe(204);

    // No answer may be cached anywhere.
    for (const response of [started, confirmed, regenerated, status, removed]) {
      expect(response.headers['cache-control']).toBe('no-store');
    }
    // The server logged (requests at least), and no line holds a secret.
    expect(logLines.length).toBeGreaterThan(0);
    const secrets = [
      enrolment.secret,
      enrolment.secret.toLowerCase(),
      enrolment.otpauthUri,
      ...[...first.codes, ...next.codes].flatMap((code) => [
        code,
        code.toLowerCase(),
        code.replace(/-/g, '').toLowerCase(),
      ]),
    ];
    for (const line of logLines) {
      for (const value of secrets) expect(line).not.toContain(value);
    }
  });
});
