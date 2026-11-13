import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import * as contract from '@qauth-labs/shared-account-contract';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

// The error handler's logger reads the environment at import; the guard
// itself reads none.
vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'development' } }));

import errorHandler from '../plugins/error-handler';
import {
  ACCOUNT_LOOKUP_RETRY_SECONDS,
  accountOperation,
  type AccountOperationRules,
  ACT_CHAIN_RULES,
  AUTH_TIME_CLOCK_SKEW_LEEWAY_SECONDS,
  checkAccountOperation,
  FRESH_AUTHENTICATION_MAX_AGE_SECONDS,
  FRESH_AUTHENTICATION_RULES,
  holdsNewFactor,
  isFreshSignIn,
  provedOnlyThroughNew,
  requiredFactorOf,
} from './account-operation-guard';

const REALM_ID = '00000000-0000-4000-8000-0000000000aa';
const OTHER_REALM_ID = '00000000-0000-4000-8000-0000000000bb';
const USER_ID = '00000000-0000-4000-8000-000000000001';
const SESSION_ID = '00000000-0000-4000-8000-0000000000c1';
const REFUSED = 'urn:qauth:event:request.account_operation_refused:v1-rc.0';

/** The contract's rules for `id`, as a route hands them to the guard. */
function rulesOf(id: string): AccountOperationRules {
  const operation = contract.operationNamed(id);
  return {
    operationId: operation.id,
    operationClass: operation.class,
    permission: operation.permission,
    freshAuthentication: operation.freshAuthentication,
    actChain: operation.actChain,
  };
}

/** A credential row of `providerType` in `realmId`. */
function credential(providerType: string, realmId = REALM_ID) {
  return { providerType, realmId, userId: USER_ID, disabledAt: null };
}

/** The session row the guard reads for a recovery-code sign-in. */
function session(overrides: Record<string, unknown> = {}) {
  return {
    id: SESSION_ID,
    realmId: REALM_ID,
    userId: USER_ID,
    authTime: Math.floor(Date.now() / 1000) * 1000 - 60_000 + 400,
    amr: ['pwd'],
    recoveryCodeUsed: true,
    expiresAt: Date.now() + 3_600_000,
    revokedAt: null,
    ...overrides,
  };
}

interface Harness {
  readonly app: FastifyInstance;
  readonly events: Array<{ type: string; data: Record<string, unknown>; actor?: unknown }>;
  readonly credentials: ReturnType<typeof vi.fn>;
  readonly sessions: ReturnType<typeof vi.fn>;
  claims: JWTPayload;
}

/** A sign-in `secondsAgo` old, as the token's `auth_time` keeps it (whole seconds, in ms). */
function signedInAgo(secondsAgo: number): number {
  return (Math.floor(Date.now() / 1000) - secondsAgo) * 1000;
}

/**
 * A server with the error handler and one route per rule set, whose
 * `preValidation` stands in for the family's token guard: it hands the guard
 * `harness.claims`, as `requireFamilyToken` leaves them on the request.
 */
async function buildHarness(): Promise<Harness> {
  const events: Harness['events'] = [];
  const credentials = vi.fn(async () => [credential('password')]);
  const sessions = vi.fn(async () => undefined as unknown);
  const app = Fastify({ logger: false });
  const harness: Harness = {
    app,
    events,
    credentials,
    sessions,
    claims: {
      sub: USER_ID,
      clientId: 'account-console',
      aud: contract.ACCOUNT_API_AUDIENCE,
      authTime: signedInAgo(30),
      amr: ['pwd'],
    },
  };
  app.decorate('repositories', {
    userCredentials: { findAllByUserId: credentials },
    sessions: { findById: sessions },
    events: {
      emitInOwnTransaction: async (event: Harness['events'][number]) => {
        events.push(event);
        return 'event-id';
      },
    },
  } as never);
  app.decorateRequest('realm', null);
  app.addHook('onRequest', async (request) => {
    (request as { realm: unknown }).realm = { id: REALM_ID };
  });
  await app.register(errorHandler);
  for (const id of [
    'account.password.change',
    'account.passkeys.delete',
    'account.totp.enrollment.create',
    'account.passkeys.update',
    'account.consents.delete',
  ]) {
    const rules = rulesOf(id);
    app.post(`/account/v1-rc.0/probe/${id}`, {
      preValidation: async (request) => {
        request.jwtPayload = harness.claims;
        await checkAccountOperation(request, rules);
      },
      handler: async () => ({ ran: id }),
    });
  }
  // A removal that names its passkey (#1108), as the account API's route
  // hands it to the guard (`accountOperation`'s `removing`).
  const removal = rulesOf('account.passkeys.delete');
  app.post<{ Params: { passkeyId: string } }>('/account/v1-rc.0/remove/:passkeyId', {
    preValidation: async (request) => {
      request.jwtPayload = harness.claims;
      await checkAccountOperation(request, removal, {
        type: 'passkey',
        id: request.params.passkeyId,
      });
    },
    handler: async () => ({ ran: 'removal' }),
  });
  return harness;
}

/** Remove the passkey `passkeyId` through the route that names it to the guard. */
function remove(harness: Harness, passkeyId: string) {
  return harness.app.inject({
    method: 'POST',
    url: `/account/v1-rc.0/remove/${passkeyId}`,
    headers: { authorization: 'Bearer a.b.c' },
  });
}

function call(harness: Harness, id: string) {
  return harness.app.inject({
    method: 'POST',
    url: `/account/v1-rc.0/probe/${id}`,
    headers: { authorization: 'Bearer a.b.c' },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('the account operation guard (#663)', () => {
  describe('its copy of the contract', () => {
    it('holds the contract’s maximum age and rules', () => {
      expect(FRESH_AUTHENTICATION_MAX_AGE_SECONDS).toBe(
        contract.FRESH_AUTHENTICATION_MAX_AGE_SECONDS
      );
      expect([...FRESH_AUTHENTICATION_RULES]).toEqual([...contract.FRESH_AUTHENTICATION_RULES]);
      expect([...ACT_CHAIN_RULES]).toEqual([...contract.ACT_CHAIN_RULES]);
    });

    it('builds a guard for every operation of the contract, its rules as the schema states them', () => {
      for (const operation of contract.ACCOUNT_OPERATIONS) {
        expect(accountOperation(rulesOf(operation.id)).schema).toEqual({
          operationId: operation.id,
          'x-qauth-class': operation.class,
          'x-qauth-permission': operation.permission,
          'x-qauth-fresh-authentication': operation.freshAuthentication,
          'x-qauth-act-chain': operation.actChain,
        });
      }
    });

    it('refuses at build time an id or a rule the contract does not define', () => {
      expect(() =>
        accountOperation({ ...rulesOf('account.profile.get'), operationId: 'admin.users.delete' })
      ).toThrow(/not an account operation id/);
      expect(() =>
        accountOperation({
          ...rulesOf('account.password.change'),
          freshAuthentication: 'sometimes' as never,
        })
      ).toThrow(/rule the contract does not define/);
      expect(() =>
        accountOperation({ ...rulesOf('account.profile.get'), operationClass: 'security' as never })
      ).toThrow(/no class of an operation of the account API/);
    });
  });

  describe('the required factor (ADR-017 Decision 8)', () => {
    it.each([
      [['password', 'webauthn', 'totp'], 'pop'],
      [['webauthn'], 'pop'],
      [['password', 'totp'], 'otp'],
      [['password'], 'pwd'],
      [[], 'pwd'],
    ] as const)('is the strongest bound one: %j needs %s', (types, factor) => {
      expect(
        requiredFactorOf(
          types.map((type) => credential(type)),
          REALM_ID
        )
      ).toBe(factor);
    });

    it('counts no credential of another realm', () => {
      expect(
        requiredFactorOf([credential('password'), credential('webauthn', OTHER_REALM_ID)], REALM_ID)
      ).toBe('pwd');
    });

    it('counts no credential while it is new, and counts it once its window is over (#1064)', () => {
      const NOW = 1_800_000_000_000;
      const newPasskey = { ...credential('webauthn'), id: 'passkey-new', newUntil: NOW + 1 };
      const rows = [credential('password'), newPasskey];
      expect(requiredFactorOf(rows, REALM_ID, NOW)).toBe('pwd');
      expect(requiredFactorOf(rows, REALM_ID, NOW + 1)).toBe('pop');
      expect(holdsNewFactor('pop', rows, REALM_ID, NOW)).toBe(true);
      expect(holdsNewFactor('otp', rows, REALM_ID, NOW)).toBe(false);
      // A sign-in that named the new passkey proved `pop` only through it.
      expect(provedOnlyThroughNew('pop', ['passkey-new'], rows, REALM_ID, NOW)).toBe(true);
      expect(provedOnlyThroughNew('pop', [], rows, REALM_ID, NOW)).toBe(false);
      expect(provedOnlyThroughNew('pop', ['passkey-new'], rows, REALM_ID, NOW + 1)).toBe(false);
    });
  });

  describe('how fresh a sign-in is', () => {
    it('is fresh up to five minutes, and not one millisecond more', () => {
      const now = 1_800_000_000_000;
      expect(isFreshSignIn(now - 300_000, now)).toBe(true);
      expect(isFreshSignIn(now - 300_001, now)).toBe(false);
      expect(isFreshSignIn(now, now)).toBe(true);
    });

    it('is not fresh when the token says nothing of when it happened', () => {
      expect(isFreshSignIn(undefined, Date.now())).toBe(false);
      expect(isFreshSignIn(Number.NaN, Date.now())).toBe(false);
    });

    it('takes a time up to a minute ahead of the clock, and not one millisecond more', () => {
      const now = 1_800_000_000_000;
      expect(AUTH_TIME_CLOCK_SKEW_LEEWAY_SECONDS).toBe(60);
      expect(isFreshSignIn(now + 60_000, now)).toBe(true);
      expect(isFreshSignIn(now + 60_001, now)).toBe(false);
      expect(isFreshSignIn(now + 86_400_000, now)).toBe(false);
    });
  });

  describe('a call', () => {
    it('passes with a fresh sign-in that proved the strongest bound factor', async () => {
      const harness = await buildHarness();
      harness.credentials.mockResolvedValue([credential('password'), credential('webauthn')]);
      harness.claims = { ...harness.claims, amr: ['pop', 'mfa'] };

      const response = await call(harness, 'account.password.change');

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ ran: 'account.password.change' });
      expect(harness.events).toEqual([]);
      await harness.app.close();
    });

    it('challenges with max_age="300" a sign-in older than five minutes, and records it', async () => {
      const harness = await buildHarness();
      harness.claims = { ...harness.claims, authTime: signedInAgo(301) };

      const response = await call(harness, 'account.password.change');

      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toBe(
        'Bearer error="insufficient_user_authentication", max_age="300"'
      );
      expect(response.json()).toMatchObject({
        code: 'insufficient_user_authentication',
        max_age: 300,
      });
      // Refused before the account is read: its age alone decides.
      expect(harness.credentials).not.toHaveBeenCalled();
      expect(harness.events).toMatchObject([
        {
          type: REFUSED,
          data: {
            operation: 'account.password.change',
            reason: 'authentication_too_old',
            maxAge: 300,
          },
        },
      ]);
      await harness.app.close();
    });

    it('challenges a token that says nothing of its sign-in as a sign-in too old', async () => {
      const harness = await buildHarness();
      const withoutAuthTime = { ...harness.claims };
      delete withoutAuthTime.authTime;
      harness.claims = withoutAuthTime;

      const response = await call(harness, 'account.password.change');

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ max_age: 300 });
      await harness.app.close();
    });

    it('challenges a sign-in dated ahead of the clock as a sign-in too old', async () => {
      const harness = await buildHarness();
      // A node whose clock ran an hour ahead dated it.
      harness.claims = { ...harness.claims, authTime: signedInAgo(-3600) };

      const response = await call(harness, 'account.password.change');

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ max_age: 300 });
      expect(harness.credentials).not.toHaveBeenCalled();
      expect(harness.events).toMatchObject([
        { type: REFUSED, data: { reason: 'authentication_too_old', maxAge: 300 } },
      ]);
      await harness.app.close();
    });

    it('challenges with max_age="0" a recent password sign-in at a passkey-bound account', async () => {
      const harness = await buildHarness();
      harness.credentials.mockResolvedValue([credential('password'), credential('webauthn')]);

      const response = await call(harness, 'account.password.change');

      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toBe(
        'Bearer error="insufficient_user_authentication", max_age="0"'
      );
      expect(response.json()).toMatchObject({ max_age: 0 });
      expect(harness.events).toMatchObject([
        {
          data: {
            operation: 'account.password.change',
            reason: 'strongest_factor_missing',
            requiredFactor: 'pop',
            maxAge: 0,
          },
        },
      ]);
      await harness.app.close();
    });

    it('refuses an act-chain token where the operation takes none, before any challenge', async () => {
      const harness = await buildHarness();
      // Stale and without the factor, too: the delegated caller still gets
      // the refusal, never a challenge it cannot meet.
      harness.claims = {
        ...harness.claims,
        authTime: signedInAgo(3_600),
        act: { sub: 'support-agent' },
      };

      for (const id of ['account.password.change', 'account.passkeys.update']) {
        const response = await call(harness, id);
        expect(response.statusCode, id).toBe(403);
        expect(response.json(), id).toMatchObject({ code: 'delegated_token_refused' });
      }
      expect(harness.events.map((event) => event.data)).toEqual([
        { operation: 'account.password.change', reason: 'delegated_token' },
        { operation: 'account.passkeys.update', reason: 'delegated_token' },
      ]);
      // The event names the acting client, as every delegated event does.
      expect(harness.events[0]?.actor).toMatchObject({ type: 'client', id: 'support-agent' });
      await harness.app.close();
    });

    it('lets an act-chain token through where the operation takes one', async () => {
      const harness = await buildHarness();
      harness.claims = { ...harness.claims, act: { sub: 'support-agent' } };

      const response = await call(harness, 'account.consents.delete');

      expect(response.statusCode).toBe(200);
      expect(harness.events).toEqual([]);
      await harness.app.close();
    });
  });

  describe('a removal of a credential still new (#1064, #1108)', () => {
    /** A password, a settled authenticator app, a settled passkey and a new passkey. */
    function rows(newUntil: number, realmId = REALM_ID) {
      return [
        credential('password'),
        { ...credential('totp'), id: 'totp-settled', newUntil: null },
        { ...credential('webauthn'), id: 'passkey-settled', newUntil: null },
        { ...credential('webauthn', realmId), id: 'passkey-new', newUntil },
      ];
    }

    it('passes on a fresh password sign-in while the passkey it names is new', async () => {
      const harness = await buildHarness();
      harness.credentials.mockResolvedValue(rows(Date.now() + 3_600_000));
      harness.claims = { ...harness.claims, amr: ['pwd'], authTime: signedInAgo(30) };

      const response = await remove(harness, 'passkey-new');

      expect(response.statusCode, response.body).toBe(200);
      expect(harness.events).toEqual([]);
      await harness.app.close();
    });

    it('challenges the same sign-in at a passkey that is not new, and at a call that names none', async () => {
      const harness = await buildHarness();
      harness.credentials.mockResolvedValue(rows(Date.now() + 3_600_000));
      harness.claims = { ...harness.claims, amr: ['pwd'], authTime: signedInAgo(30) };

      for (const response of [
        await remove(harness, 'passkey-settled'),
        await call(harness, 'account.passkeys.delete'),
      ]) {
        expect(response.statusCode).toBe(401);
        expect(response.headers['www-authenticate']).toContain('max_age="0"');
      }
      await harness.app.close();
    });

    it('challenges it once the window is over, or for a passkey of another realm', async () => {
      for (const credentials of [
        rows(Date.now() - 1),
        rows(Date.now() + 3_600_000, OTHER_REALM_ID),
      ]) {
        const harness = await buildHarness();
        harness.credentials.mockResolvedValue(credentials);
        harness.claims = { ...harness.claims, amr: ['pwd'], authTime: signedInAgo(30) };

        const response = await remove(harness, 'passkey-new');

        expect(response.statusCode).toBe(401);
        expect(response.headers['www-authenticate']).toContain('max_age="0"');
        await harness.app.close();
      }
    });

    it('challenges a password sign-in too old, and a sign-in that proved no password', async () => {
      const harness = await buildHarness();
      harness.credentials.mockResolvedValue(rows(Date.now() + 3_600_000));

      harness.claims = { ...harness.claims, amr: ['pwd'], authTime: signedInAgo(301) };
      const old = await remove(harness, 'passkey-new');
      expect(old.statusCode).toBe(401);
      expect(old.headers['www-authenticate']).toContain('max_age="300"');

      harness.claims = { ...harness.claims, amr: ['hwk'], authTime: signedInAgo(30) };
      const other = await remove(harness, 'passkey-new');
      expect(other.statusCode).toBe(401);
      expect(other.headers['www-authenticate']).toContain('max_age="0"');
      await harness.app.close();
    });

    it('refuses an act-chain token before the rule of a new passkey', async () => {
      const harness = await buildHarness();
      harness.credentials.mockResolvedValue(rows(Date.now() + 3_600_000));
      harness.claims = {
        ...harness.claims,
        amr: ['pwd'],
        authTime: signedInAgo(30),
        act: { sub: 'agent-client' },
      };

      const response = await remove(harness, 'passkey-new');

      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({ code: 'delegated_token_refused' });
      expect(harness.credentials).not.toHaveBeenCalled();
      await harness.app.close();
    });
  });

  describe('a recovery-code sign-in (found through the token’s sid)', () => {
    async function recoveryHarness(row: Record<string, unknown> = {}) {
      const harness = await buildHarness();
      harness.credentials.mockResolvedValue([credential('password'), credential('webauthn')]);
      // The token's `auth_time` is the default row's sign-in, to the second.
      const signedIn = session().authTime;
      harness.sessions.mockResolvedValue(session(row));
      harness.claims = {
        ...harness.claims,
        sid: SESSION_ID,
        authTime: Math.floor(signedIn / 1000) * 1000,
      };
      return harness;
    }

    it('passes only where the operation takes one: the rebind routes', async () => {
      const harness = await recoveryHarness();

      for (const id of ['account.passkeys.delete', 'account.totp.enrollment.create']) {
        expect((await call(harness, id)).statusCode, id).toBe(200);
      }
      expect(harness.sessions).toHaveBeenCalledWith(REALM_ID, SESSION_ID);

      const elsewhere = await call(harness, 'account.password.change');
      expect(elsewhere.statusCode).toBe(401);
      expect(elsewhere.json()).toMatchObject({ max_age: 0 });
      await harness.app.close();
    });

    it.each([
      ['no recovery code', { recoveryCodeUsed: false }],
      ['another user', { userId: '00000000-0000-4000-8000-000000000002' }],
      ['an ended session', { revokedAt: Date.now() - 1_000 }],
      ['an expired session', { expiresAt: Date.now() - 1_000 }],
      ['another sign-in', { authTime: Date.now() - 200_000 }],
    ])('challenges a session with %s', async (_case, row) => {
      const harness = await recoveryHarness(row);

      const response = await call(harness, 'account.passkeys.delete');

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ max_age: 0 });
      await harness.app.close();
    });

    it('challenges a token without a sid, and reads no session', async () => {
      const harness = await recoveryHarness();
      const withoutSid = { ...harness.claims };
      delete withoutSid.sid;
      harness.claims = withoutSid;

      const response = await call(harness, 'account.passkeys.delete');

      expect(response.statusCode).toBe(401);
      expect(harness.sessions).not.toHaveBeenCalled();
      await harness.app.close();
    });

    it('refuses the call when the session cannot be read, and records it', async () => {
      const harness = await recoveryHarness();
      harness.sessions.mockRejectedValue(new Error('connection terminated'));

      const response = await call(harness, 'account.passkeys.delete');

      expect(response.statusCode).toBe(503);
      expect(response.headers['retry-after']).toBe(String(ACCOUNT_LOOKUP_RETRY_SECONDS));
      expect(response.json()).toMatchObject({ code: 'service_unavailable' });
      expect(JSON.stringify(response.json())).not.toContain('connection terminated');
      expect(harness.events.map((event) => event.data)).toEqual([
        { operation: 'account.passkeys.delete', reason: 'lookup_failed' },
      ]);
      await harness.app.close();
    });

    it('refuses the call when the account’s factors cannot be read', async () => {
      const harness = await recoveryHarness();
      harness.credentials.mockRejectedValue(new Error('connection terminated'));

      const response = await call(harness, 'account.password.change');

      expect(response.statusCode).toBe(503);
      expect(harness.events.map((event) => event.data)).toEqual([
        { operation: 'account.password.change', reason: 'lookup_failed' },
      ]);
      await harness.app.close();
    });

    it('refuses the call when its refusal cannot be recorded', async () => {
      const harness = await recoveryHarness({ recoveryCodeUsed: false });
      const repositories = harness.app.repositories as unknown as {
        events: { emitInOwnTransaction: () => Promise<string> };
      };
      repositories.events.emitInOwnTransaction = async () => {
        throw new Error('event store down');
      };

      const response = await call(harness, 'account.passkeys.delete');

      expect(response.statusCode).toBe(500);
      await harness.app.close();
    });
  });
});
