import type { FastifyInstance, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { EngineMailer, MailRealm } from './engine-mail';
import { EVENT_CLIENT_ID_MAX_LENGTH } from './interaction-record';
import { createServerRecoveryCodes, RECOVERY_CODES_FAILED_ALERT } from './recovery-codes';
import { emitUserEvent } from './user-events';

vi.mock('./user-events', () => ({ emitUserEvent: vi.fn(async () => undefined) }));

const REALM_ID = 'realm-1';
const USER_ID = 'user-1';
const CLIENT_ID = 'notes-app';
const ADDRESS = 'owner@example.test';
const REALM = { id: REALM_ID, name: 'default' } as unknown as MailRealm;
const REQUEST = { id: 'request-1' } as unknown as FastifyRequest;
const TX = 'the-transaction';
/** The one unused code of the account, as typed and as stored. */
const TYPED = 'ABCD EFGH-ijkl-MNOP';
const NORMALIZED = 'abcdefghijklmnop';
const USED_URN = 'urn:qauth:event:user.recovery_code_used:v1-rc.0';
const FAILED_URN = 'urn:qauth:event:user.recovery_codes_failed:v1-rc.0';

/**
 * The auth server's recovery codes (#649): the engine's port over
 * `user_recovery_codes` and the password hasher, and the three notices none
 * of which a realm can switch off.
 */
describe('the server recovery codes (#649)', () => {
  let repos: {
    status: ReturnType<typeof vi.fn>;
    findUnused: ReturnType<typeof vi.fn>;
    replaceSet: ReturnType<typeof vi.fn>;
    markUsed: ReturnType<typeof vi.fn>;
  };
  let findCredential: ReturnType<typeof vi.fn>;
  let mailer: {
    sendUncounted: ReturnType<typeof vi.fn>;
    recoveryCodesFailed: ReturnType<typeof vi.fn>;
  };
  let logError: ReturnType<typeof vi.fn>;
  let request: FastifyRequest | undefined;

  beforeEach(() => {
    vi.mocked(emitUserEvent).mockClear();
    repos = {
      status: vi.fn(async () => ({ issued: true, unused: 9, confirmed: true })),
      findUnused: vi.fn(async () => [{ id: 'code-1', codeHash: `h:${NORMALIZED}` }]),
      replaceSet: vi.fn(async (): Promise<string | null> => 'set-1'),
      markUsed: vi.fn(async () => true),
    };
    findCredential = vi.fn(async () => ({ realmId: REALM_ID, externalSub: ADDRESS }));
    mailer = {
      sendUncounted: vi.fn(),
      recoveryCodesFailed: vi.fn(async () => true),
    };
    logError = vi.fn();
    request = REQUEST;
  });

  const build = () =>
    createServerRecoveryCodes(
      {
        repositories: {
          userRecoveryCodes: repos,
          userCredentials: { findByUserIdAndType: findCredential },
        },
        db: { transaction: async (work: (tx: string) => Promise<unknown>) => work(TX) },
        passwordHasher: {
          hashPassword: async (code: string) => `h:${code}`,
          verifyPassword: async (hash: string, code: string) => hash === `h:${code}`,
        },
        log: { error: logError },
      } as unknown as FastifyInstance,
      {
        mailer: mailer as unknown as EngineMailer,
        realmOf: async () => REALM,
        requestOf: () => request,
      }
    );

  const redeem = (clientId = CLIENT_ID) =>
    build().redeem({ realmId: REALM_ID, userId: USER_ID, clientId, code: TYPED });

  it('commits the use and its event with the take, then mails how many codes are left', async () => {
    await expect(redeem()).resolves.toEqual({ kind: 'redeemed' });

    expect(repos.markUsed).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM_ID, userId: USER_ID, id: 'code-1' }),
      TX
    );
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      USED_URN,
      { remaining: 9 },
      { tx: TX, realmId: REALM_ID, userId: USER_ID, clientId: CLIENT_ID, actor: 'user' }
    );
    expect(mailer.sendUncounted).toHaveBeenCalledWith(REALM, ADDRESS, {
      template: 'recovery_code_used',
      unusedCodes: 9,
    });
  });

  it('records no client id the event cannot hold', async () => {
    await redeem('c'.repeat(EVENT_CLIENT_ID_MAX_LENGTH + 1));

    expect(vi.mocked(emitUserEvent).mock.calls[0]?.[3]).toMatchObject({ clientId: null });
  });

  it('takes nothing outside the request that asked: the take and its event commit together', async () => {
    request = undefined;
    // The transaction runs the take and the event: a throw in it is the
    // round's refusal, and no mail follows.
    await expect(redeem()).rejects.toThrow(/outside the request/);
    expect(mailer.sendUncounted).not.toHaveBeenCalled();
  });

  it('mails no address of another realm, and a failed notice changes no redemption', async () => {
    findCredential.mockResolvedValueOnce({ realmId: 'realm-2', externalSub: ADDRESS });
    await expect(redeem()).resolves.toEqual({ kind: 'redeemed' });
    expect(mailer.sendUncounted).not.toHaveBeenCalled();

    findCredential.mockRejectedValueOnce(new Error('database down'));
    await expect(redeem()).resolves.toEqual({ kind: 'redeemed' });
    expect(logError).toHaveBeenCalledWith(
      expect.objectContaining({ step: 'the recovery-code-used notice' }),
      'a recovery code write committed, but a step after it failed'
    );
  });

  it('mails the regenerated notice after the new set is stored', async () => {
    const { codes } = await build().regenerate({ realmId: REALM_ID, userId: USER_ID });

    expect(codes).toHaveLength(10);
    expect(repos.replaceSet).toHaveBeenCalledTimes(1);
    const stored = repos.replaceSet.mock.calls[0]?.[0] as { codeHashes: string[] };
    // Only the hashes are stored, never a code as shown.
    for (const code of codes) expect(stored.codeHashes).not.toContain(code);
    expect(mailer.sendUncounted).toHaveBeenCalledWith(REALM, ADDRESS, {
      template: 'recovery_codes_regenerated',
    });
    expect(repos.replaceSet.mock.invocationCallOrder[0]).toBeLessThan(
      mailer.sendUncounted.mock.invocationCallOrder[0] as number
    );
  });

  it('at the ceiling tells the user, the operator and the security log, once a day', async () => {
    await build().ceilingReached({ realmId: REALM_ID, userId: USER_ID });

    expect(mailer.recoveryCodesFailed).toHaveBeenCalledWith({
      realm: REALM,
      userId: USER_ID,
      address: ADDRESS,
    });
    expect(logError).toHaveBeenCalledWith(
      { realmId: REALM_ID, userId: USER_ID },
      RECOVERY_CODES_FAILED_ALERT
    );
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      FAILED_URN,
      {},
      { realmId: REALM_ID, userId: USER_ID, actor: 'user' }
    );

    // The day's notice is claimed already: the run's later failures add nothing.
    mailer.recoveryCodesFailed.mockResolvedValueOnce(false);
    logError.mockClear();
    vi.mocked(emitUserEvent).mockClear();
    await build().ceilingReached({ realmId: REALM_ID, userId: USER_ID });
    expect(logError).not.toHaveBeenCalled();
    expect(emitUserEvent).not.toHaveBeenCalled();
  });

  it('alerts the operator for an account with no address too', async () => {
    findCredential.mockResolvedValueOnce(undefined);

    await build().ceilingReached({ realmId: REALM_ID, userId: USER_ID });

    expect(mailer.recoveryCodesFailed).toHaveBeenCalledWith({ realm: REALM, userId: USER_ID });
    expect(logError).toHaveBeenCalledWith(
      { realmId: REALM_ID, userId: USER_ID },
      RECOVERY_CODES_FAILED_ALERT
    );
    expect(emitUserEvent).toHaveBeenCalledTimes(1);
  });
});
