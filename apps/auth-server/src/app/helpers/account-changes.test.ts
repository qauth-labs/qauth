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
vi.mock('./session-side-record', () => ({
  readSessionSideRecord: vi.fn(async () => ({ ...sideRecord })),
  writeSessionSideRecord,
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
import type { InteractionEngines } from './interaction-engines';

const REALM_ID = '00000000-0000-4000-8000-0000000000aa';
const OTHER_REALM_ID = '00000000-0000-4000-8000-0000000000bb';
const USER_ID = '00000000-0000-4000-8000-000000000001';
const SID = '00000000-0000-4000-8000-0000000000c1';
const NOW = Date.UTC(2026, 10, 7, 12);
const REFUSED = 'urn:qauth:event:request.account_operation_refused:v1-rc.0';
const REQUEST = { id: 'request-1' } as unknown as FastifyRequest;

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
/** A credential row of `providerType`. */
function credential(providerType: string, realmId = REALM_ID) {
  nextId += 1;
  return {
    id: `00000000-0000-4000-8000-${String(nextId).padStart(12, '0')}`,
    providerType,
    realmId,
    userId: USER_ID,
    disabledAt: null,
  };
}

type Row = ReturnType<typeof credential>;

/** A server whose account holds `rows`, and whose realm's MFA policy is `mfa`. */
function server(
  rows: Row[],
  options: {
    mfa?: 'off' | 'optional' | 'required' | 'required_for_admins';
    admin?: boolean;
    sessionRow?: { userId: string; recoveryCodeUsed: boolean };
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
      sessions: { findById: vi.fn(async () => options.sessionRow) },
    },
  } as unknown as FastifyInstance;
  return { fastify, deleteById };
}

beforeEach(() => {
  emitUserEvent.mockClear();
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
      await removeCredential(fastify, REQUEST, session(['pop']), {
        type: 'passkey',
        id: passkey.id,
      })
    ).toEqual({ kind: 'removed' });
    expect(deleteById).toHaveBeenCalledWith(REALM_ID, passkey.id, 'tx');
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
      await removeCredential(fastify, REQUEST, session(['pop']), { type: 'passkey', id: only.id })
    ).toEqual({ kind: 'last_credential' });
    expect(deleteById).not.toHaveBeenCalled();
    expect(emitUserEvent).not.toHaveBeenCalled();
  });

  it('counts the ways in of the session’s realm only', async () => {
    const only = credential('webauthn');
    const { fastify } = server([only, credential('password', OTHER_REALM_ID)]);
    expect(
      await removeCredential(fastify, REQUEST, session(['pop']), { type: 'passkey', id: only.id })
    ).toEqual({ kind: 'last_credential' });
  });

  it('keeps the last second factor the realm requires', async () => {
    const totp = credential('totp');
    const { fastify } = server([credential('password'), totp], { mfa: 'required' });
    expect(await removeCredential(fastify, REQUEST, session(['otp']), { type: 'totp' })).toEqual({
      kind: 'second_factor_required',
    });
    const forAdmins = server([credential('password'), credential('totp')], {
      mfa: 'required_for_admins',
      admin: true,
    });
    expect(
      await removeCredential(forAdmins.fastify, REQUEST, session(['otp']), { type: 'totp' })
    ).toEqual({ kind: 'second_factor_required' });
    const notAdmin = server([credential('password'), credential('totp')], {
      mfa: 'required_for_admins',
    });
    expect(
      await removeCredential(notAdmin.fastify, REQUEST, session(['otp']), { type: 'totp' })
    ).toEqual({ kind: 'removed' });
  });

  it('answers not_found for a passkey the account does not hold', async () => {
    const { fastify } = server([credential('password'), credential('webauthn')]);
    expect(
      await removeCredential(fastify, REQUEST, session(['pop']), {
        type: 'passkey',
        id: '00000000-0000-4000-8000-0000000000ff',
      })
    ).toEqual({ kind: 'not_found' });
    expect(await removeCredential(fastify, REQUEST, session(['pop']), { type: 'totp' })).toEqual({
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
