import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { EngineMailer, MailRealm } from './engine-mail';
import { createServerTotp, totpCipher, totpSecretContext } from './totp-sign-in';

const REALM_ID = 'realm-1';
const USER_ID = 'user-1';
const CLIENT_ID = 'notes-app';
const ADDRESS = 'owner@example.test';
const REALM = { id: REALM_ID, issuer: 'https://id.example.test/realms/one' } as MailRealm;
const TX = 'the-transaction';

/**
 * The auth server's TOTPs (#653): the signer's `data_at_rest` key under an
 * account-bound context, the hard action's arming, and the notices.
 */
describe('the server TOTPs (#653)', () => {
  let signer: { encrypt: ReturnType<typeof vi.fn>; decrypt: ReturnType<typeof vi.fn> };
  let credentials: Record<string, ReturnType<typeof vi.fn>>;
  let mailer: {
    sendUncounted: ReturnType<typeof vi.fn>;
    secondFactorFailed: ReturnType<typeof vi.fn>;
  };
  let recoveryStatus: ReturnType<
    typeof vi.fn<
      (input: {
        realmId: string;
        userId: string;
      }) => Promise<{ issued: boolean; unused: number; confirmed: boolean }>
    >
  >;
  let resetAccount: ReturnType<
    typeof vi.fn<
      (input: {
        realmId: string;
        userId: string;
        factor: 'totp' | 'recovery_code';
      }) => Promise<void>
    >
  >;
  let logError: ReturnType<typeof vi.fn>;
  let hostedPages: boolean;

  beforeEach(() => {
    signer = {
      encrypt: vi.fn(async () => 'v1.sealed'),
      // A sealed secret opens to 160 bits, as the engine checks.
      decrypt: vi.fn(async () => Buffer.alloc(20, 7)),
    };
    credentials = {
      findByUserIdAndType: vi.fn(async () => ({ realmId: REALM_ID, externalSub: ADDRESS })),
      findAllByUserIdAndType: vi.fn(async () => []),
      findByRealmProviderSub: vi.fn(async () => undefined),
      findAllByUserId: vi.fn(async () => []),
      acceptTotpStep: vi.fn(async () => true),
      upsertTotp: vi.fn(async () => ({ id: 'row-1' })),
      setDisabledAt: vi.fn(async () => ({ id: 'row-1' })),
    };
    mailer = { sendUncounted: vi.fn(), secondFactorFailed: vi.fn(async () => true) };
    recoveryStatus = vi.fn(async () => ({ issued: true, unused: 0, confirmed: true }));
    resetAccount = vi.fn(async () => undefined);
    logError = vi.fn();
    hostedPages = true;
  });

  const fastify = () =>
    ({
      signer,
      repositories: {
        userCredentials: credentials,
        users: { findById: vi.fn(async () => ({ id: USER_ID, enabled: true })) },
      },
      db: { transaction: async (work: (tx: string) => Promise<unknown>) => work(TX) },
      log: { error: logError },
    }) as unknown as FastifyInstance;

  const build = (passkeys = false) =>
    createServerTotp(fastify(), {
      mailer: mailer as unknown as EngineMailer,
      realmOf: async () => REALM,
      recoveryCodes: { status: recoveryStatus },
      ladder: { resetAccount },
      hostedPages,
      passkeys,
    });

  /** Drive the ceiling through the service: the store holds one enabled TOTP. */
  const reachCeiling = async (passkeys = false) => {
    await build(passkeys).ceilingReached({ realmId: REALM_ID, userId: USER_ID });
  };

  it('seals and opens a secret as the api role, under a context bound to the account', async () => {
    const cipher = totpCipher(fastify());
    const secret = new Uint8Array([9, 9, 9]);
    await expect(cipher.seal({ realmId: REALM_ID, userId: USER_ID, secret })).resolves.toBe(
      'v1.sealed'
    );
    expect(signer.encrypt).toHaveBeenCalledWith('api', {
      realmId: REALM_ID,
      plaintext: secret,
      context: `totp-secret:${REALM_ID}:${USER_ID}`,
    });
    expect(totpSecretContext(REALM_ID, USER_ID)).toBe(`totp-secret:${REALM_ID}:${USER_ID}`);

    const plain = Buffer.from([1, 2, 3]);
    signer.decrypt.mockResolvedValueOnce(plain);
    const opened = await cipher.open({ realmId: REALM_ID, userId: USER_ID, sealed: 'v1.sealed' });
    expect(Array.from(opened)).toEqual([1, 2, 3]);
    // The signer's buffer is overwritten once the secret is copied out.
    expect(Array.from(plain)).toEqual([0, 0, 0]);
    expect(signer.decrypt).toHaveBeenCalledWith('api', {
      realmId: REALM_ID,
      ciphertext: 'v1.sealed',
      context: `totp-secret:${REALM_ID}:${USER_ID}`,
    });
  });

  it('shows the host of the realm’s issuer in the authenticator app', async () => {
    const started = await build().start({
      realmId: REALM_ID,
      userId: USER_ID,
      identifier: ADDRESS,
    });
    expect(new URL(started.display.otpauthUri).searchParams.get('issuer')).toBe('id.example.test');
    // What the transaction holds is the signer's ciphertext, never the secret.
    expect(started.sealed).toBe('v1.sealed');
  });

  it('ends the counter’s run after a binding, then mails the "added" notice', async () => {
    await expect(
      build().bind({
        realmId: REALM_ID,
        userId: USER_ID,
        clientId: CLIENT_ID,
        sealed: 'v1.sealed',
        step: 7,
      })
    ).resolves.toEqual({ kind: 'bound' });

    expect(resetAccount).toHaveBeenCalledWith({
      realmId: REALM_ID,
      userId: USER_ID,
      factor: 'totp',
    });
    expect(mailer.sendUncounted).toHaveBeenCalledWith(REALM, ADDRESS, { template: 'totp_added' });

    // A reset that fails is reported, and the notice still goes.
    resetAccount.mockRejectedValueOnce(new Error('redis down'));
    await build().bind({
      realmId: REALM_ID,
      userId: USER_ID,
      clientId: CLIENT_ID,
      sealed: 'v1.sealed',
      step: 8,
    });
    expect(logError).toHaveBeenCalledWith(
      expect.objectContaining({ step: 'the TOTP counter reset' }),
      expect.any(String)
    );
    expect(mailer.sendUncounted).toHaveBeenCalledTimes(2);
  });

  it('disables at the ceiling with an unused recovery code, then mails the notice', async () => {
    recoveryStatus.mockResolvedValueOnce({ issued: true, unused: 3, confirmed: true });
    await reachCeiling();

    expect(credentials.setDisabledAt).toHaveBeenCalledWith(
      REALM_ID,
      'totp',
      USER_ID,
      expect.any(Number)
    );
    expect(mailer.sendUncounted).toHaveBeenCalledWith(REALM, ADDRESS, {
      template: 'second_factor_disabled',
    });
  });

  it('disables nothing with the hosted pages off, nor without another way in', async () => {
    hostedPages = false;
    recoveryStatus.mockResolvedValue({ issued: true, unused: 3, confirmed: true });
    await reachCeiling();
    expect(recoveryStatus).not.toHaveBeenCalled();

    hostedPages = true;
    // A set nobody confirmed was never seen for sure: it is no way back.
    recoveryStatus.mockResolvedValue({ issued: true, unused: 10, confirmed: false });
    await reachCeiling();
    recoveryStatus.mockResolvedValue({ issued: true, unused: 0, confirmed: true });
    await reachCeiling();
    // A passkey counts only while passkey sign-in is on.
    credentials.findAllByUserIdAndType.mockResolvedValue([{ realmId: REALM_ID, disabledAt: null }]);
    await reachCeiling(false);

    expect(credentials.setDisabledAt).not.toHaveBeenCalled();
    expect(mailer.sendUncounted).not.toHaveBeenCalled();
  });

  it('counts a usable passkey of the realm as another second factor while passkey sign-in is on', async () => {
    credentials.findAllByUserIdAndType.mockResolvedValueOnce([
      { realmId: 'realm-2', disabledAt: null },
      { realmId: REALM_ID, disabledAt: 1_700_000_000_000 },
    ]);
    await reachCeiling(true);
    expect(credentials.setDisabledAt).not.toHaveBeenCalled();

    credentials.findAllByUserIdAndType.mockResolvedValueOnce([
      { realmId: REALM_ID, disabledAt: null },
    ]);
    await reachCeiling(true);
    expect(credentials.findAllByUserIdAndType).toHaveBeenLastCalledWith(USER_ID, 'webauthn');
    expect(credentials.setDisabledAt).toHaveBeenCalledTimes(1);
  });

  it('mails no second disabled notice for a TOTP marked already', async () => {
    recoveryStatus.mockResolvedValue({ issued: true, unused: 3, confirmed: true });
    credentials.setDisabledAt.mockResolvedValueOnce(undefined);
    await reachCeiling();
    expect(mailer.sendUncounted).not.toHaveBeenCalled();
  });

  it('claims the wrong-code notice per account, with the address of its password', async () => {
    await build().failedAfterPassword({ realmId: REALM_ID, userId: USER_ID, clientId: CLIENT_ID });
    expect(mailer.secondFactorFailed).toHaveBeenCalledWith({
      realm: REALM,
      userId: USER_ID,
      address: ADDRESS,
    });

    // No address in this realm: the claim still goes, with nothing to mail.
    credentials.findByUserIdAndType.mockResolvedValueOnce({
      realmId: 'realm-2',
      externalSub: ADDRESS,
    });
    await build().failedAfterPassword({ realmId: REALM_ID, userId: USER_ID, clientId: CLIENT_ID });
    expect(mailer.secondFactorFailed).toHaveBeenLastCalledWith({ realm: REALM, userId: USER_ID });
  });
});
