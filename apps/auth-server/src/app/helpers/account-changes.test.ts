import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import * as contract from '@qauth-labs/shared-account-contract';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { emitUserEvent, sideRecord, writeSessionSideRecord } = vi.hoisted(() => {
  const sideRecord: { accountCsrfToken?: string } = {};
  return {
    emitUserEvent: vi.fn<(...args: unknown[]) => Promise<string>>(async () => 'event-id'),
    sideRecord,
    writeSessionSideRecord: vi.fn(async (_fastify: unknown, _session: unknown, update: object) => {
      Object.assign(sideRecord, update);
    }),
  };
});
// The helpers' modules read the environment at import; these rules read none of it.
vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));
vi.mock('./user-events', () => ({ emitUserEvent }));
// The realm's providers: `oidc_on` is on; every other is off or unknown.
vi.mock('./upstream-providers', () => ({
  upstreamProviderCatalog: () => ({
    offered: async () => [],
    find: async (_realmId: string, type: string) =>
      type === 'oidc_on' ? { entry: { provider: type, name: 'On' } } : undefined,
  }),
}));
vi.mock('./session-side-record', () => ({
  readSessionSideRecord: vi.fn(async () => ({ ...sideRecord })),
  writeSessionSideRecord,
  deleteSessionSideRecord: vi.fn(async () => undefined),
}));

import {
  ACCOUNT_PAGE_CHANGES,
  accountCsrfAccepted,
  accountCsrfToken,
  checkFreshAuthentication,
  regenerateRecoveryCodes,
  removeCredential,
} from './account-changes';
import { FRESH_AUTHENTICATION_MAX_AGE_SECONDS } from './account-operation-guard';
import type { EngineMailer } from './engine-mail';
import type { InteractionEngines } from './interaction-engines';

const REALM_ID = '00000000-0000-4000-8000-0000000000aa';
const OTHER_REALM_ID = '00000000-0000-4000-8000-0000000000bb';
const USER_ID = '00000000-0000-4000-8000-000000000001';
const SID = '00000000-0000-4000-8000-0000000000c1';
const NOW = Date.UTC(2026, 10, 7, 12);
const REFUSED = 'urn:qauth:event:request.account_operation_refused:v1-rc.0';
const REALM = { id: REALM_ID, issuer: 'https://auth.example.com' };
const REQUEST = { id: 'request-1', realm: REALM } as unknown as FastifyRequest;
const ADDRESS = 'ada@example.com';
const sendUncounted = vi.fn();
const MAILER = { sendUncounted } as unknown as EngineMailer;

/** A browser session of the account, signed in `ageMs` ago with `amr`. */
function session(amr: readonly string[], ageMs = 60_000): BrowserSession {
  return {
    sid: SID,
    realmId: REALM_ID,
    userId: USER_ID,
    authTime: NOW - ageMs,
    amr,
    assuranceLevel: null,
    createdAt: NOW - ageMs,
    lastSeenAt: NOW,
    expiresAt: NOW + 3_600_000,
    idleExpiresAt: null,
  };
}

let nextId = 0;
/** A credential row of `providerType`; `newUntil` makes it new until then (#1064). */
function credential(providerType: string, realmId = REALM_ID, newUntil: number | null = null) {
  nextId += 1;
  return {
    id: `00000000-0000-4000-8000-${String(nextId).padStart(12, '0')}`,
    providerType,
    realmId,
    userId: USER_ID,
    externalSub: providerType === 'password' ? ADDRESS : `${providerType}-${nextId}`,
    disabledAt: null as number | null,
    newUntil,
    createdAt: NOW - 3_600_000,
  };
}

/** One day, in milliseconds: inside the window of a new factor. */
const DAY = 86_400_000;

type Row = ReturnType<typeof credential>;

/** A server whose account holds `rows`, and whose realm's MFA policy is `mfa`. */
function server(
  rows: Row[],
  options: {
    mfa?: 'off' | 'optional' | 'required' | 'required_for_admins';
    admin?: boolean;
    sessionRow?: { userId: string; recoveryCodeUsed: boolean; newCredentialIds?: string[] };
    /**
     * The account's sessions, live unless they say otherwise, of which
     * `listNamingCredential` reads those that name the credential (#1064).
     */
    live?: {
      id: string;
      authTime: number;
      newCredentialIds: string[];
      revokedAt?: number | null;
      expiresAt?: number;
    }[];
  } = {}
) {
  const deleteById = vi.fn(async (_realmId: string, id: string) => {
    const index = rows.findIndex((row) => row.id === id);
    if (index < 0) return undefined;
    const [row] = rows.splice(index, 1);
    return row;
  });
  const fastify = {
    db: { transaction: async (fn: (tx: unknown) => unknown) => fn('tx') },
    signInMfaPolicy: {
      read: async () => ({ realm: options.mfa ?? 'optional', client: 'optional' }),
    },
    log: { error: vi.fn() },
    repositories: {
      userCredentials: {
        findAllByUserId: vi.fn(async () => [...rows]),
        lockUser: vi.fn(async () => true),
        deleteById,
      },
      adminGrants: { listLive: vi.fn(async () => (options.admin === true ? [{}] : [])) },
      sessions: {
        findById: vi.fn(async () =>
          options.sessionRow === undefined
            ? undefined
            : { newCredentialIds: [], ...options.sessionRow }
        ),
        listNamingCredential: vi.fn(async (_realmId: string, _userId: string, id: string) =>
          (options.live ?? [])
            .filter((candidate) => candidate.newCredentialIds.includes(id))
            .map((candidate) => ({ revokedAt: null, expiresAt: NOW + 3_600_000, ...candidate }))
        ),
      },
      authorizationCodes: { invalidateForSessions: vi.fn(async () => 0) },
      refreshTokens: { revokeFamiliesOfSignIns: vi.fn(async () => 0) },
      userRecoveryCodes: { deleteSet: vi.fn(async () => 10) },
    },
    redis: { set: vi.fn(async () => 'OK') },
    sessionService: { revoke: vi.fn(async () => ({ outcome: 'ended' })) },
  } as unknown as FastifyInstance;
  return { fastify, deleteById };
}

beforeEach(() => {
  emitUserEvent.mockClear();
  sendUncounted.mockClear();
  writeSessionSideRecord.mockClear();
  delete sideRecord.accountCsrfToken;
});

describe('ACCOUNT_PAGE_CHANGES (#844)', () => {
  it('holds the account API contract’s fresh-authentication rule of each operation', () => {
    for (const change of Object.values(ACCOUNT_PAGE_CHANGES)) {
      expect(
        contract.operationNamed(change.operationId).freshAuthentication,
        change.operationId
      ).toBe(change.freshAuthentication);
    }
  });
});

describe('checkFreshAuthentication (#844, #663)', () => {
  it('lets a change that asks for none through without a read', async () => {
    const { fastify } = server([]);
    const verdict = await checkFreshAuthentication(
      fastify,
      REQUEST,
      session(['pwd'], 3_600_000),
      ACCOUNT_PAGE_CHANGES.sessionsEndAll,
      NOW
    );
    expect(verdict).toEqual({ kind: 'fresh' });
    expect(fastify.repositories.userCredentials.findAllByUserId).not.toHaveBeenCalled();
    expect(emitUserEvent).not.toHaveBeenCalled();
  });

  it('refuses a sign-in older than five minutes, and records the refusal', async () => {
    const { fastify } = server([credential('password')]);
    const verdict = await checkFreshAuthentication(
      fastify,
      REQUEST,
      session(['pwd'], (FRESH_AUTHENTICATION_MAX_AGE_SECONDS + 1) * 1000),
      ACCOUNT_PAGE_CHANGES.passwordChange,
      NOW
    );
    expect(verdict).toEqual({
      kind: 'refused',
      reason: 'authentication_too_old',
      requiredFactor: 'pwd',
    });
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      REFUSED,
      {
        operation: 'account.password.change',
        reason: 'authentication_too_old',
        maxAge: FRESH_AUTHENTICATION_MAX_AGE_SECONDS,
      },
      { realmId: REALM_ID, userId: USER_ID, clientId: null, actor: 'user' }
    );
  });

  it('asks for the strongest factor the account holds: a passkey over a password', async () => {
    const { fastify } = server([credential('password'), credential('webauthn')]);
    const refused = await checkFreshAuthentication(
      fastify,
      REQUEST,
      session(['pwd']),
      ACCOUNT_PAGE_CHANGES.passwordChange,
      NOW
    );
    expect(refused).toEqual({
      kind: 'refused',
      reason: 'strongest_factor_missing',
      requiredFactor: 'pop',
    });
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      REFUSED,
      {
        operation: 'account.password.change',
        reason: 'strongest_factor_missing',
        requiredFactor: 'pop',
        maxAge: 0,
      },
      expect.objectContaining({ userId: USER_ID })
    );
    const fresh = await checkFreshAuthentication(
      fastify,
      REQUEST,
      session(['pop', 'mfa']),
      ACCOUNT_PAGE_CHANGES.passwordChange,
      NOW
    );
    expect(fresh).toEqual({ kind: 'fresh' });
  });

  it('reads the factors of the session’s realm only', async () => {
    const { fastify } = server([credential('password'), credential('webauthn', OTHER_REALM_ID)]);
    const verdict = await checkFreshAuthentication(
      fastify,
      REQUEST,
      session(['pwd']),
      ACCOUNT_PAGE_CHANGES.passwordChange,
      NOW
    );
    expect(verdict).toEqual({ kind: 'fresh' });
  });

  it('takes a recovery code in place of the strongest factor only where the contract lets it', async () => {
    const rows = [credential('password'), credential('totp')];
    const { fastify } = server(rows, { sessionRow: { userId: USER_ID, recoveryCodeUsed: true } });
    expect(
      await checkFreshAuthentication(
        fastify,
        REQUEST,
        session(['pwd']),
        ACCOUNT_PAGE_CHANGES.totpRemove,
        NOW
      )
    ).toEqual({ kind: 'fresh' });
    expect(
      await checkFreshAuthentication(
        fastify,
        REQUEST,
        session(['pwd']),
        ACCOUNT_PAGE_CHANGES.recoveryCodesRegenerate,
        NOW
      )
    ).toMatchObject({ kind: 'refused', reason: 'strongest_factor_missing', requiredFactor: 'otp' });
  });

  it('never takes another account’s recovery-code sign-in, or a session without one', async () => {
    const rows = [credential('password'), credential('webauthn')];
    for (const sessionRow of [
      { userId: '00000000-0000-4000-8000-000000000002', recoveryCodeUsed: true },
      { userId: USER_ID, recoveryCodeUsed: false },
      undefined,
    ]) {
      const { fastify } = server(rows, sessionRow === undefined ? {} : { sessionRow });
      expect(
        await checkFreshAuthentication(
          fastify,
          REQUEST,
          session(['pwd']),
          ACCOUNT_PAGE_CHANGES.passkeyRemove,
          NOW
        )
      ).toMatchObject({ kind: 'refused', reason: 'strongest_factor_missing' });
    }
  });
});

describe('checkFreshAuthentication with a new factor (#1064)', () => {
  it('counts no new factor as the strongest: the password is fresh enough', async () => {
    const { fastify } = server([
      credential('password'),
      credential('webauthn', REALM_ID, NOW + DAY),
    ]);
    expect(
      await checkFreshAuthentication(
        fastify,
        REQUEST,
        session(['pwd']),
        ACCOUNT_PAGE_CHANGES.passwordChange,
        NOW
      )
    ).toEqual({ kind: 'fresh' });
    // Once its window is over, it is the strongest factor again.
    const { fastify: later } = server([
      credential('password'),
      credential('webauthn', REALM_ID, NOW),
    ]);
    expect(
      await checkFreshAuthentication(
        later,
        REQUEST,
        session(['pwd']),
        ACCOUNT_PAGE_CHANGES.passwordChange,
        NOW
      )
    ).toMatchObject({ kind: 'refused', requiredFactor: 'pop' });
  });

  it('lets the password alone remove a credential while it is new, and only that one', async () => {
    const settled = credential('webauthn');
    const fresh = credential('webauthn', REALM_ID, NOW + DAY);
    const { fastify } = server([credential('password'), settled, fresh]);
    const check = (id: string, amr: readonly string[] = ['pwd']) =>
      checkFreshAuthentication(
        fastify,
        REQUEST,
        session(amr),
        ACCOUNT_PAGE_CHANGES.passkeyRemove,
        NOW,
        { type: 'passkey', id }
      );
    expect(await check(fresh.id)).toEqual({ kind: 'fresh' });
    expect(await check(settled.id)).toMatchObject({ kind: 'refused', requiredFactor: 'pop' });
    // A sign-in that proved no password removes nothing with it.
    expect(await check(fresh.id, ['pop', 'mfa'])).toMatchObject({ kind: 'refused' });
    // An old sign-in is too old for the password too.
    const old = await checkFreshAuthentication(
      fastify,
      REQUEST,
      session(['pwd'], (FRESH_AUTHENTICATION_MAX_AGE_SECONDS + 1) * 1000),
      ACCOUNT_PAGE_CHANGES.passkeyRemove,
      NOW,
      { type: 'passkey', id: fresh.id }
    );
    expect(old).toMatchObject({ kind: 'refused', reason: 'authentication_too_old' });
  });

  it('takes no strongest factor a sign-in proved only through a new credential', async () => {
    const settled = credential('webauthn');
    const fresh = credential('webauthn', REALM_ID, NOW + DAY);
    const verdict = (newCredentialIds: string[]) =>
      checkFreshAuthentication(
        server([credential('password'), settled, fresh], {
          sessionRow: { userId: USER_ID, recoveryCodeUsed: false, newCredentialIds },
        }).fastify,
        REQUEST,
        session(['pop', 'mfa']),
        ACCOUNT_PAGE_CHANGES.passwordChange,
        NOW
      );
    expect(await verdict([fresh.id])).toMatchObject({
      kind: 'refused',
      reason: 'strongest_factor_missing',
    });
    expect(await verdict([])).toEqual({ kind: 'fresh' });
  });
});

describe('the account CSRF value (#844)', () => {
  it('is minted once per session and kept with it', async () => {
    const { fastify } = server([]);
    const first = await accountCsrfToken(fastify, session(['pwd']));
    expect(first.length).toBeGreaterThan(20);
    expect(writeSessionSideRecord).toHaveBeenCalledTimes(1);
    expect(await accountCsrfToken(fastify, session(['pwd']))).toBe(first);
    expect(writeSessionSideRecord).toHaveBeenCalledTimes(1);
  });

  it('accepts the session’s value and records any other post as request.csrf_rejected', async () => {
    const { fastify } = server([]);
    const token = await accountCsrfToken(fastify, session(['pwd']));
    expect(await accountCsrfAccepted(fastify, REQUEST, session(['pwd']), token)).toBe(true);
    expect(emitUserEvent).not.toHaveBeenCalled();
    for (const provided of [undefined, '', `${token}x`]) {
      expect(await accountCsrfAccepted(fastify, REQUEST, session(['pwd']), provided)).toBe(false);
    }
    expect(emitUserEvent).toHaveBeenCalledTimes(3);
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      'urn:qauth:event:request.csrf_rejected:v1-rc.0',
      { form: 'account' },
      { realmId: REALM_ID, userId: USER_ID, clientId: null, actor: 'user' }
    );
  });

  it('refuses every post while the session holds no value', async () => {
    const { fastify } = server([]);
    expect(await accountCsrfAccepted(fastify, REQUEST, session(['pwd']), '')).toBe(false);
    expect(await accountCsrfAccepted(fastify, REQUEST, session(['pwd']), undefined)).toBe(false);
  });
});

describe('removeCredential (#844)', () => {
  it('removes a passkey while another way in stays, and records it in the transaction', async () => {
    const passkey = credential('webauthn');
    const { fastify, deleteById } = server([credential('password'), passkey]);
    expect(
      await removeCredential(
        fastify,
        REQUEST,
        session(['pop']),
        {
          type: 'passkey',
          id: passkey.id,
        },
        MAILER
      )
    ).toEqual({ kind: 'removed' });
    expect(deleteById).toHaveBeenCalledWith(REALM_ID, passkey.id, 'tx');
    // The owner is told at the password's address, after the commit (ADR-020 §3).
    expect(sendUncounted).toHaveBeenCalledWith(REALM, ADDRESS, { template: 'passkey_removed' });
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      'urn:qauth:event:user.credential_removed:v1-rc.0',
      { type: 'passkey', credentialId: passkey.id },
      { tx: 'tx', realmId: REALM_ID, userId: USER_ID, clientId: null, actor: 'user' }
    );
  });

  it('refuses the last way to sign in: an authenticator app is no way in on its own', async () => {
    const only = credential('webauthn');
    const { fastify, deleteById } = server([only, credential('totp')]);
    expect(
      await removeCredential(
        fastify,
        REQUEST,
        session(['pop']),
        { type: 'passkey', id: only.id },
        MAILER
      )
    ).toEqual({ kind: 'last_credential' });
    expect(deleteById).not.toHaveBeenCalled();
    expect(emitUserEvent).not.toHaveBeenCalled();
    expect(sendUncounted).not.toHaveBeenCalled();
  });

  it('counts no marked credential as a way in, nor as the second factor kept (#655)', async () => {
    // A rebind marked the lost passkey: it signs in no more.
    const lost = { ...credential('webauthn'), disabledAt: NOW - 60_000 };
    const live = credential('webauthn');
    const { fastify, deleteById } = server([lost, live]);
    expect(
      await removeCredential(
        fastify,
        REQUEST,
        session(['pop']),
        { type: 'passkey', id: live.id },
        MAILER
      )
    ).toEqual({ kind: 'last_credential' });
    expect(deleteById).not.toHaveBeenCalled();
    // An app turned off after 100 wrong codes is no second factor either.
    const marked = server(
      [credential('password'), { ...credential('totp'), disabledAt: NOW - 60_000 }, live],
      { mfa: 'required' }
    );
    expect(
      await removeCredential(
        marked.fastify,
        REQUEST,
        session(['pop']),
        { type: 'passkey', id: live.id },
        MAILER
      )
    ).toEqual({ kind: 'second_factor_required' });
  });

  it('counts no identity of a provider switched off as a way in (#844)', async () => {
    const upstream = (type: string) => ({
      ...credential(type),
      credentialData: { kind: 'upstream', iss: 'https://idp.example', verified: true },
    });
    const passkey = credential('webauthn');
    const off = server([passkey, upstream('oidc_off')]);
    expect(
      await removeCredential(
        off.fastify,
        REQUEST,
        session(['pop']),
        { type: 'passkey', id: passkey.id },
        MAILER
      )
    ).toEqual({ kind: 'last_credential' });
    expect(off.deleteById).not.toHaveBeenCalled();
    // The identity of a provider that is on is one.
    const on = server([passkey, upstream('oidc_on')]);
    expect(
      await removeCredential(
        on.fastify,
        REQUEST,
        session(['pop']),
        { type: 'passkey', id: passkey.id },
        MAILER
      )
    ).toEqual({ kind: 'removed' });
  });

  it('counts the ways in of the session’s realm only', async () => {
    const only = credential('webauthn');
    const { fastify } = server([only, credential('password', OTHER_REALM_ID)]);
    expect(
      await removeCredential(
        fastify,
        REQUEST,
        session(['pop']),
        { type: 'passkey', id: only.id },
        MAILER
      )
    ).toEqual({ kind: 'last_credential' });
  });

  it('keeps the last second factor the realm requires', async () => {
    const totp = credential('totp');
    const { fastify } = server([credential('password'), totp], { mfa: 'required' });
    expect(
      await removeCredential(fastify, REQUEST, session(['otp']), { type: 'totp' }, MAILER)
    ).toEqual({
      kind: 'second_factor_required',
    });
    const forAdmins = server([credential('password'), credential('totp')], {
      mfa: 'required_for_admins',
      admin: true,
    });
    expect(
      await removeCredential(forAdmins.fastify, REQUEST, session(['otp']), { type: 'totp' }, MAILER)
    ).toEqual({ kind: 'second_factor_required' });
    const notAdmin = server([credential('password'), credential('totp')], {
      mfa: 'required_for_admins',
    });
    expect(
      await removeCredential(notAdmin.fastify, REQUEST, session(['otp']), { type: 'totp' }, MAILER)
    ).toEqual({ kind: 'removed' });
    expect(sendUncounted).toHaveBeenCalledOnce();
    expect(sendUncounted).toHaveBeenCalledWith(REALM, ADDRESS, { template: 'totp_removed' });
  });

  it('ends what a new passkey opened when it is removed, and says so (#1064)', async () => {
    const fresh = credential('webauthn', REALM_ID, NOW + DAY);
    const { fastify } = server([credential('password'), fresh], {
      live: [
        { id: 'sid-opened', authTime: NOW - 120_000, newCredentialIds: [fresh.id] },
        // Signed out since: its families outlive it.
        {
          id: 'sid-ended',
          authTime: NOW - 200_000,
          newCredentialIds: [fresh.id],
          revokedAt: NOW - 100_000,
        },
        // Past its end, never marked ended.
        {
          id: 'sid-lapsed',
          authTime: NOW - 300_000,
          newCredentialIds: [fresh.id],
          expiresAt: NOW,
        },
        { id: SID, authTime: NOW - 60_000, newCredentialIds: [] },
      ],
    });
    expect(
      await removeCredential(
        fastify,
        REQUEST,
        session(['pwd']),
        { type: 'passkey', id: fresh.id },
        MAILER,
        NOW
      )
    ).toEqual({ kind: 'removed' });
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      'urn:qauth:event:user.credential_removed:v1-rc.0',
      { type: 'passkey', credentialId: fresh.id, whileNew: true },
      expect.objectContaining({ tx: 'tx' })
    );
    const { repositories, sessionService, redis } = fastify as unknown as {
      repositories: {
        authorizationCodes: { invalidateForSessions: ReturnType<typeof vi.fn> };
        refreshTokens: { revokeFamiliesOfSignIns: ReturnType<typeof vi.fn> };
        userRecoveryCodes: { deleteSet: ReturnType<typeof vi.fn> };
      };
      sessionService: { revoke: ReturnType<typeof vi.fn> };
      redis: { set: ReturnType<typeof vi.fn> };
    };
    // In the removal's transaction, then once more after the session ended:
    // what every session that named it opened, an ended one's too.
    const named = ['sid-opened', 'sid-ended', 'sid-lapsed'];
    const signIns = [NOW - 120_000, NOW - 200_000, NOW - 300_000];
    expect(repositories.authorizationCodes.invalidateForSessions.mock.calls).toEqual([
      [USER_ID, named, 'tx'],
      [USER_ID, named, undefined],
    ]);
    expect(repositories.refreshTokens.revokeFamiliesOfSignIns.mock.calls).toEqual([
      [USER_ID, signIns, 'new_credential_removed', 'tx'],
      [USER_ID, signIns, 'new_credential_removed', undefined],
    ]);
    // The recovery codes, which may have been shown with it, go in the
    // same transaction; every sign-in in progress is cut after it.
    expect(repositories.userRecoveryCodes.deleteSet.mock.calls).toEqual([
      [REALM_ID, USER_ID, 'tx'],
    ]);
    expect(redis.set).toHaveBeenCalledTimes(1);
    expect(redis.set.mock.calls[0]?.[0]).toContain(USER_ID);
    // Only the live session that bound or proved it ends; this one stays.
    expect(sessionService.revoke).toHaveBeenCalledTimes(1);
    expect(sessionService.revoke).toHaveBeenCalledWith(
      expect.objectContaining({
        realmId: REALM_ID,
        sid: 'sid-opened',
        reason: 'reset',
        userId: USER_ID,
      })
    );
  });

  it('keeps the removal when a session it opened cannot be ended, and logs it', async () => {
    const fresh = credential('webauthn', REALM_ID, NOW + DAY);
    const { fastify } = server([credential('password'), fresh], {
      live: [
        { id: 'sid-a', authTime: NOW - 120_000, newCredentialIds: [fresh.id] },
        { id: 'sid-b', authTime: NOW - 90_000, newCredentialIds: [fresh.id] },
      ],
    });
    const { sessionService, log, repositories, redis } = fastify as unknown as {
      sessionService: { revoke: ReturnType<typeof vi.fn> };
      log: { error: ReturnType<typeof vi.fn> };
      repositories: {
        refreshTokens: { revokeFamiliesOfSignIns: ReturnType<typeof vi.fn> };
      };
      redis: { set: ReturnType<typeof vi.fn> };
    };
    sessionService.revoke.mockRejectedValueOnce(new Error('store down'));
    redis.set.mockRejectedValueOnce(new Error('redis down'));
    expect(
      await removeCredential(
        fastify,
        REQUEST,
        session(['pwd']),
        { type: 'passkey', id: fresh.id },
        MAILER,
        NOW
      )
    ).toEqual({ kind: 'removed' });
    // The other session still ends, and the sweep still runs.
    expect(sessionService.revoke).toHaveBeenCalledTimes(2);
    expect(repositories.refreshTokens.revokeFamiliesOfSignIns).toHaveBeenCalledTimes(2);
    expect(log.error).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM_ID }),
      'a new credential was removed, but a session it opened could not be ended'
    );
    expect(log.error).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM_ID }),
      'a new credential was removed, but the sign-ins in progress could not be ended'
    );
  });

  it('deletes the recovery codes and cuts the sign-ins in progress when no session named it', async () => {
    const fresh = credential('totp', REALM_ID, NOW + DAY);
    const { fastify } = server([credential('password'), fresh]);
    expect(
      await removeCredential(fastify, REQUEST, session(['pwd']), { type: 'totp' }, MAILER, NOW)
    ).toEqual({ kind: 'removed' });
    const { repositories, redis } = fastify as unknown as {
      repositories: { userRecoveryCodes: { deleteSet: ReturnType<typeof vi.fn> } };
      redis: { set: ReturnType<typeof vi.fn> };
    };
    expect(repositories.userRecoveryCodes.deleteSet).toHaveBeenCalledWith(REALM_ID, USER_ID, 'tx');
    expect(redis.set).toHaveBeenCalledTimes(1);
  });

  it('ends nothing more when the passkey is no longer new', async () => {
    const settled = credential('webauthn', REALM_ID, NOW);
    const { fastify } = server([credential('password'), settled], {
      live: [{ id: 'sid-opened', authTime: NOW - 120_000, newCredentialIds: [settled.id] }],
    });
    await removeCredential(
      fastify,
      REQUEST,
      session(['pop']),
      { type: 'passkey', id: settled.id },
      MAILER,
      NOW
    );
    const { sessionService, repositories, redis } = fastify as unknown as {
      sessionService: { revoke: ReturnType<typeof vi.fn> };
      repositories: { userRecoveryCodes: { deleteSet: ReturnType<typeof vi.fn> } };
      redis: { set: ReturnType<typeof vi.fn> };
    };
    expect(sessionService.revoke).not.toHaveBeenCalled();
    // A full factor's removal keeps the recovery codes and the sign-ins in progress.
    expect(repositories.userRecoveryCodes.deleteSet).not.toHaveBeenCalled();
    expect(redis.set).not.toHaveBeenCalled();
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      'urn:qauth:event:user.credential_removed:v1-rc.0',
      { type: 'passkey', credentialId: settled.id },
      expect.anything()
    );
  });

  it('answers not_found for a passkey the account does not hold', async () => {
    const { fastify } = server([credential('password'), credential('webauthn')]);
    expect(
      await removeCredential(
        fastify,
        REQUEST,
        session(['pop']),
        {
          type: 'passkey',
          id: '00000000-0000-4000-8000-0000000000ff',
        },
        MAILER
      )
    ).toEqual({ kind: 'not_found' });
    expect(
      await removeCredential(fastify, REQUEST, session(['pop']), { type: 'totp' }, MAILER)
    ).toEqual({
      kind: 'not_found',
    });
  });
});

describe('regenerateRecoveryCodes (#844)', () => {
  it('issues no set to an account without a second factor', async () => {
    const { fastify } = server([credential('password')]);
    const regenerate = vi.fn();
    const engines = {
      forRequest: (_request: FastifyRequest, fn: () => unknown) => fn(),
      recoveryCodes: { regenerate },
    } as unknown as InteractionEngines;
    expect(await regenerateRecoveryCodes(fastify, REQUEST, engines, session(['pwd']))).toEqual({
      kind: 'conflict',
    });
    expect(regenerate).not.toHaveBeenCalled();
  });

  it('issues a new set and records it', async () => {
    const { fastify } = server([credential('password'), credential('totp')]);
    const engines = {
      forRequest: (_request: FastifyRequest, fn: () => unknown) => fn(),
      recoveryCodes: { regenerate: vi.fn(async () => ({ codes: ['A', 'B'], setId: 'set-2' })) },
    } as unknown as InteractionEngines;
    expect(await regenerateRecoveryCodes(fastify, REQUEST, engines, session(['otp']))).toEqual({
      kind: 'issued',
      codes: ['A', 'B'],
      setId: 'set-2',
    });
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      'urn:qauth:event:user.recovery_codes_regenerated:v1-rc.0',
      {},
      { realmId: REALM_ID, userId: USER_ID, clientId: null, actor: 'user' }
    );
  });
});
