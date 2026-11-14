import * as contract from '@qauth-labs/shared-account-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

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

/**
 * THE ACCOUNT API'S FRESH-AUTHENTICATION GUARD (#663; ADR-017 Decision 8,
 * ADR-019 Decision 7), against a real Postgres and Redis, one case per
 * acceptance criterion:
 *
 * - a sign-in older than five minutes gets the RFC 9470 challenge;
 * - a password-only `amr` at a passkey-bound account gets the challenge;
 * - a fresh passkey sign-in passes;
 * - an act-chain token is refused on the credential, identifier and deletion
 *   operations;
 * - a recovery-code sign-in passes only on the rebind operations.
 *
 * Most account operations that ask for fresh authentication are not served
 * yet (ACC-01 to ACC-05 build them on this guard), so the suite mounts one
 * probe per operation at the contract's own method and path, guarded with the
 * contract's own rules, the way those routes will be. Each probe answers
 * `{ ran }` once the guard lets the call through. The password change is
 * served (#1107): a refusal is checked on its route, whose guard runs before
 * it reads the body, and a call the guard lets through on a probe of the same
 * rules, `account.recoveryCodes.regenerate`. The passkey removal and rename
 * are served (#1108) and called on their routes, at a passkey id no account
 * holds: once the guard lets the call through, the handler answers 404.
 * Tokens are minted as the
 * code exchange mints the account API's (`auth_time`, `amr`, `sid`); the
 * recovery-code suite (`recovery-codes.integration.test.ts`) walks the same
 * rebind through a real sign-in and code exchange.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ACCOUNT_AUDIENCE = contract.ACCOUNT_API_AUDIENCE;
const REFUSED = 'urn:qauth:event:request.account_operation_refused:v1-rc.0';
/** A passkey id no account holds: the served removal answers 404 once its guard lets a call through. */
const PASSKEY_ID = '00000000-0000-4000-8000-0000000000e1';

/** The probed operations: every rule set and every kind of change the guard refuses an act chain on. */
const PROBED = [
  // Credentials: the authenticator app, the recovery codes. The password
  // change (#1107) and the passkey removal and rename (#1108) are served and
  // called where they are.
  'account.totp.enrollment.create',
  'account.totp.delete',
  'account.recoveryCodes.regenerate',
  // An identifier and the contact address.
  'account.addressChange.create',
  // Deleting the account.
  'account.deletion.create',
  // An operation that asks for nothing.
  'account.profile.get',
] as const;

type ProbedOperation = (typeof PROBED)[number];
/** The operations the suite calls: its probes, and the served password change. */
/** The operations called on their served routes. */
type ServedOperation =
  | 'account.password.change'
  | 'account.passkeys.delete'
  | 'account.passkeys.update';
type CalledOperation = ProbedOperation | ServedOperation;

/** The operation's path with its parameters filled, under the account prefix. */
function urlOf(id: CalledOperation): string {
  const { path } = contract.operationNamed(id);
  return `${contract.ACCOUNT_API_PREFIX}${path.replace(/\{[^}]+\}/g, PASSKEY_ID)}`;
}

describe('the account API’s fresh-authentication guard (#663, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;
  let realmId = '';
  let accounts = 0;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, await generateJwtPem()),
        // Each case registers its own account from one address.
        REGISTRATION_RATE_LIMIT: '10000',
      },
      {
        // Imported from the module registry the booted app loaded (the
        // harness resets it per boot), so the errors the guard throws are
        // the classes the app's error handler knows.
        routes: async (scope) => {
          const { accountOperation } = await import('./helpers/account-operation-guard');
          for (const id of PROBED) {
            const operation = contract.operationNamed(id);
            const guarded = accountOperation({
              operationId: operation.id,
              operationClass: operation.class,
              permission: operation.permission,
              freshAuthentication: operation.freshAuthentication,
              actChain: operation.actChain,
            });
            scope.route({
              method: operation.method.toUpperCase() as 'GET' | 'POST' | 'PATCH' | 'DELETE',
              url: `${contract.ACCOUNT_API_PREFIX}${operation.path.replace(/\{([^}]+)\}/g, ':$1')}`,
              preValidation: guarded.guard,
              config: { surface: 'api' },
              handler: async () => ({ ran: id }),
            });
          }
        },
      }
    );
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
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

  /** A verified password account, with a passkey bound when asked. */
  async function account(options: { passkey?: boolean } = {}): Promise<string> {
    const userId = await registerPasswordAccount(
      app(),
      `fresh-${++accounts}-${Date.now()}@example.com`
    );
    if (options.passkey === true) {
      await app().repositories.userCredentials.create({
        userId,
        realmId,
        providerType: 'webauthn',
        externalSub: `cGFzc2tleS0${accounts}`,
        credentialData: {
          public_key: 'pQECAyYgASFYIK_voW-Xypst',
          algorithm: -7,
          sign_count: 0,
          transports: ['internal'],
          backup_eligible: true,
          backed_up: true,
          aaguid: '00000000-0000-0000-0000-000000000000',
          rp_id: 'auth.example.com',
          user_handle: 'dXNlci1oYW5kbGU',
          nickname: null,
          created_at: Date.now(),
          last_used_at: null,
          sign_counter_regressed_at: null,
        },
      });
    }
    return userId;
  }

  /** A sign-in `secondsAgo` old, as the token's `auth_time` keeps it: whole seconds, in ms. */
  function signedInAgo(secondsAgo: number): number {
    return (Math.floor(Date.now() / 1000) - secondsAgo) * 1000;
  }

  /** An account API token, as the code exchange mints it for the account console. */
  async function token(
    userId: string,
    claims: {
      authTime?: number;
      amr?: readonly string[];
      sid?: string;
      act?: { sub: string };
    }
  ): Promise<string> {
    return app().jwtUtils.signAccessToken(
      { id: realmId },
      {
        sub: userId,
        clientId: 'account-console',
        aud: ACCOUNT_AUDIENCE,
        // Both account scopes (#933), so every probed operation's scope passes.
        scope: 'qauth:account:read qauth:account:write',
        ...claims,
      }
    );
  }

  function call(id: CalledOperation, bearer: string): Promise<LightMyRequestResponse> {
    return app().inject({
      method: contract.operationNamed(id).method.toUpperCase() as 'GET',
      url: urlOf(id),
      headers: { authorization: `Bearer ${bearer}` },
    });
  }

  /** The refusals recorded for `userId`, in order. */
  async function refusals(userId: string): Promise<Record<string, unknown>[]> {
    const { rows } = await app().dbPool.query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      [REFUSED, userId]
    );
    return rows.map((row) => row.data);
  }

  function expectChallenge(response: LightMyRequestResponse, maxAge: number): void {
    expect(response.statusCode, response.body).toBe(401);
    expect(response.headers['www-authenticate']).toBe(
      `Bearer error="insufficient_user_authentication", max_age="${maxAge}"`
    );
    expect(response.json()).toEqual({
      type: 'https://docs.qauth.dev/reference/problem-types/#insufficient-user-authentication',
      title: 'Insufficient user authentication',
      status: 401,
      code: 'insufficient_user_authentication',
      trace_id: expect.any(String),
      max_age: maxAge,
    });
  }

  /** The served passkey removal, past its guard: it finds no passkey at {@link PASSKEY_ID}. */
  function expectPastGuard(response: LightMyRequestResponse): void {
    expect(response.statusCode, response.body).toBe(404);
    expect(response.json()).toMatchObject({ code: 'not_found' });
  }

  it('challenges a sign-in older than five minutes with max_age="300", and records it', async () => {
    const userId = await account({ passkey: true });
    const stale = await token(userId, { authTime: signedInAgo(301), amr: ['pop', 'mfa'] });

    expectChallenge(await call('account.password.change', stale), 300);
    expect(await refusals(userId)).toEqual([
      { operation: 'account.password.change', reason: 'authentication_too_old', maxAge: 300 },
    ]);

    // A token that says nothing of its sign-in is as old as can be.
    expectChallenge(await call('account.deletion.create', await token(userId, {})), 300);
  });

  it('challenges a recent password-only sign-in at a passkey-bound account with max_age="0"', async () => {
    const userId = await account({ passkey: true });
    const passwordOnly = await token(userId, { authTime: signedInAgo(10), amr: ['pwd'] });

    expectChallenge(await call('account.password.change', passwordOnly), 0);
    expect(await refusals(userId)).toEqual([
      {
        operation: 'account.password.change',
        reason: 'strongest_factor_missing',
        requiredFactor: 'pop',
        maxAge: 0,
      },
    ]);

    // The same sign-in passes where no passkey is bound: the password is
    // then the strongest factor. On a probe of the same rules: the served
    // password change would go on to read its body.
    const other = await account();
    const response = await call(
      'account.recoveryCodes.regenerate',
      await token(other, { authTime: signedInAgo(10), amr: ['pwd'] })
    );
    expect(response.statusCode, response.body).toBe(200);
  });

  it('lets a fresh passkey sign-in through', async () => {
    const userId = await account({ passkey: true });
    const fresh = await token(userId, { authTime: signedInAgo(5), amr: ['pop', 'mfa'] });

    for (const id of [
      'account.recoveryCodes.regenerate',
      'account.addressChange.create',
      'account.deletion.create',
    ] as const) {
      const response = await call(id, fresh);
      expect(response.statusCode, `${id}: ${response.body}`).toBe(200);
      expect(response.json()).toEqual({ ran: id });
    }
    expectPastGuard(await call('account.passkeys.delete', fresh));
    expect(await refusals(userId)).toEqual([]);
  });

  it('refuses an act-chain token on the credential, identifier and deletion operations', async () => {
    const userId = await account({ passkey: true });
    // Fresh and with the strongest factor: an act chain is refused anyway,
    // and never with a challenge the agent cannot meet.
    const delegated = await token(userId, {
      authTime: signedInAgo(5),
      amr: ['pop', 'mfa'],
      act: { sub: 'support-agent' },
    });
    const refusedOn = [
      'account.password.change',
      'account.passkeys.update',
      'account.totp.delete',
      'account.addressChange.create',
      'account.deletion.create',
    ] as const;

    for (const id of refusedOn) {
      const response = await call(id, delegated);
      expect(response.statusCode, `${id}: ${response.body}`).toBe(403);
      expect(response.json()).toMatchObject({ code: 'delegated_token_refused' });
      expect(response.headers['www-authenticate']).toBe('Bearer realm="OAuth"');
    }
    expect(await refusals(userId)).toEqual(
      refusedOn.map((operation) => ({ operation, reason: 'delegated_token' }))
    );
    // The events name the acting agent, as every delegated event does.
    const { rows } = await app().dbPool.query(
      'SELECT DISTINCT actor_type, actor_id, actor_delegation_chain FROM events WHERE type = $1 AND subject_id = $2',
      [REFUSED, userId]
    );
    expect(rows).toEqual([
      {
        actor_type: 'client',
        actor_id: 'support-agent',
        actor_delegation_chain: ['support-agent'],
      },
    ]);

    // An operation that takes an act chain still does.
    const read = await call('account.profile.get', delegated);
    expect(read.statusCode, read.body).toBe(200);
  });

  it('lets a recovery-code sign-in through on the rebind operations only', async () => {
    const userId = await account({ passkey: true });
    const authTime = signedInAgo(20);
    // The browser session the sign-in started, as the hosted pages record a
    // recovery code in place of the passkey (#663): `amr` holds the password
    // alone.
    const session = await app().repositories.sessions.create({
      realmId,
      userId,
      authTime: authTime + 250,
      amr: ['pwd'],
      recoveryCodeUsed: true,
      expiresAt: Date.now() + 3_600_000,
    });
    const recovered = await token(userId, { authTime, amr: ['pwd'], sid: session.id });

    const enrolment = await call('account.totp.enrollment.create', recovered);
    expect(enrolment.statusCode, enrolment.body).toBe(200);
    expectPastGuard(await call('account.passkeys.delete', recovered));
    for (const id of [
      'account.password.change',
      'account.recoveryCodes.regenerate',
      'account.addressChange.create',
      'account.deletion.create',
    ] as const) {
      expectChallenge(await call(id, recovered), 0);
    }

    // Once the session has ended, the code counts no longer.
    await app().dbPool.query(
      "UPDATE sessions SET revoked_at = $1, revoked_reason = 'sign_out' WHERE id = $2",
      [Date.now(), session.id]
    );
    expectChallenge(await call('account.passkeys.delete', recovered), 0);

    // A session that took no code passes nowhere without the passkey.
    const plain = await app().repositories.sessions.create({
      realmId,
      userId,
      authTime,
      amr: ['pwd'],
      expiresAt: Date.now() + 3_600_000,
    });
    expectChallenge(
      await call(
        'account.passkeys.delete',
        await token(userId, { authTime, amr: ['pwd'], sid: plain.id })
      ),
      0
    );
  });
});
