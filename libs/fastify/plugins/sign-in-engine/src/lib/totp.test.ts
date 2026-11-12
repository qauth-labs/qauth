import { createHmac } from 'node:crypto';

import type { TotpCipher } from '@qauth-labs/server-sign-in-engine';
import { describe, expect, it, vi } from 'vitest';

import {
  createRepositoryTotp,
  type RepositoryTotpOptions,
  TOTP_PROVIDER_TYPE,
  type TotpRepositories,
} from './totp';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const OTHER_REALM = '0199fa20-0000-7000-8000-00000000bbbb';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const ACCOUNT = { realmId: REALM, userId: USER };
const CLIENT = 'web-client';
const T0 = 1_800_000_000_000;

/** RFC 4226 §5.3, for the codes a test answers with. */
function codeOf(secret: Uint8Array, step: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', secret).update(message).digest();
  const offset = (mac[mac.length - 1] as number) & 0x0f;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

/** A transaction id, so a test sees which reads and writes shared one. */
interface FakeTx {
  readonly id: number;
}

interface FakeRow {
  id: string;
  userId: string;
  realmId: string;
  providerType: string;
  externalSub: string;
  credentialData: Record<string, unknown>;
  disabledAt: number | null;
  newUntil?: number | null;
}

/** A reversible cipher bound to the account: what the signer's context does. */
const cipher: TotpCipher = {
  async seal({ realmId, userId, secret }) {
    return `v1.k.${Buffer.from(`${realmId}:${userId}`).toString('base64url')}.${Buffer.from(secret).toString('base64url')}`;
  },
  async open({ realmId, userId, sealed }) {
    const [, , context, body] = sealed.split('.');
    if (
      context !== Buffer.from(`${realmId}:${userId}`).toString('base64url') ||
      body === undefined
    ) {
      throw new Error('not this account’s ciphertext');
    }
    return new Uint8Array(Buffer.from(body, 'base64url'));
  },
};

function setup(
  options: {
    user?: { id: string; enabled: boolean; operatorVerifiedAt?: number | null } | undefined;
    rows?: FakeRow[];
    armed?: boolean;
    recordFails?: boolean;
  } = {}
) {
  let clock = T0;
  const rows: FakeRow[] = options.rows ?? [
    {
      id: 'password',
      userId: USER,
      realmId: REALM,
      providerType: 'password',
      externalSub: 'alice@example.com',
      credentialData: {
        password_hash: '$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA',
        email_verified: true,
      },
      disabledAt: null,
    },
  ];
  const user = 'user' in options ? options.user : { id: USER, enabled: true };
  const transactions: FakeTx[] = [];
  const reads: (FakeTx | undefined)[] = [];
  const totpRow = (realmId: string, userId: string) =>
    rows.find(
      (row) =>
        row.realmId === realmId &&
        row.providerType === TOTP_PROVIDER_TYPE &&
        row.externalSub === userId
    );
  const repos: TotpRepositories<FakeTx> = {
    userCredentials: {
      async findByRealmProviderSub(realmId, providerType, externalSub) {
        return rows.find(
          (row) =>
            row.realmId === realmId &&
            row.providerType === providerType &&
            row.externalSub === externalSub
        );
      },
      async findAllByUserId(userId, tx) {
        reads.push(tx);
        return rows.filter((row) => row.userId === userId);
      },
      async acceptTotpStep(realmId, userId, step) {
        const row = totpRow(realmId, userId);
        if (row === undefined || row.disabledAt !== null) return false;
        if ((row.credentialData['last_step'] as number) >= step) return false;
        row.credentialData = { ...row.credentialData, last_step: step };
        return true;
      },
      async upsertTotp({ realmId, userId, credentialData, newUntil }, tx) {
        reads.push(tx);
        const row = totpRow(realmId, userId);
        if (row === undefined) {
          const created: FakeRow = {
            id: `totp-${rows.length}`,
            userId,
            realmId,
            providerType: TOTP_PROVIDER_TYPE,
            externalSub: userId,
            credentialData: { ...credentialData },
            disabledAt: null,
            newUntil: newUntil ?? null,
          };
          rows.push(created);
          return created;
        }
        if (row.userId !== userId) return undefined;
        row.credentialData = { ...credentialData };
        row.disabledAt = null;
        row.newUntil = newUntil ?? null;
        return row;
      },
      async setDisabledAt(realmId, providerType, externalSub, disabledAt) {
        const row = rows.find(
          (candidate) =>
            candidate.realmId === realmId &&
            candidate.providerType === providerType &&
            candidate.externalSub === externalSub &&
            candidate.disabledAt === null
        );
        if (row === undefined) return undefined;
        row.disabledAt = disabledAt;
        return row;
      },
    },
    users: {
      async findById(_realmId, id, tx) {
        reads.push(tx);
        return user?.id === id ? user : undefined;
      },
    },
  };
  const opts = {
    cipher,
    issuerOf: async () => 'auth.example.com',
    hardActionArmed: vi.fn(async () => options.armed ?? true),
    bound: vi.fn(async () => undefined),
    recorded: vi.fn(
      async (_input: { realmId: string; userId: string; credentialId: string }, tx: FakeTx) => {
        reads.push(tx);
        if (options.recordFails === true) throw new Error('the record could not be written');
      }
    ),
    disabled: vi.fn(async () => undefined),
    failedAfterPassword: vi.fn(async () => undefined),
    report: vi.fn(),
    newFactorWindowMs: vi.fn<(realmId: string) => Promise<number>>(async () => WINDOW_MS),
    clock: { now: () => clock, sleep: async () => undefined },
  } satisfies RepositoryTotpOptions<FakeTx>;
  const totp = createRepositoryTotp<FakeTx>(
    repos,
    async (work) => {
      const tx = { id: transactions.length + 1 };
      transactions.push(tx);
      return work(tx);
    },
    opts
  );
  return {
    totp,
    rows,
    reads,
    transactions,
    opts,
    totpRow: () => totpRow(REALM, USER),
    advance: (ms: number) => {
      clock += ms;
    },
    step: () => Math.floor(clock / 30_000),
  };
}

/** Start a set-up and bind it with its first code, as the engine does. */
async function bound(
  built: ReturnType<typeof setup>,
  options: { readonly isNew?: boolean } = {}
): Promise<Uint8Array> {
  const started = await built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
  const secret = await cipher.open({ ...ACCOUNT, sealed: started.sealed });
  const checked = await built.totp.check({
    ...ACCOUNT,
    sealed: started.sealed,
    code: codeOf(secret, built.step()),
  });
  if (checked.kind !== 'valid') throw new Error('the first code was refused');
  expect(
    await built.totp.bind({
      ...ACCOUNT,
      clientId: CLIENT,
      sealed: started.sealed,
      step: checked.step,
      ...(options.isNew === true ? { isNew: true } : {}),
    })
  ).toEqual({ kind: 'bound', credentialId: built.totpRow()?.id });
  return secret;
}

/** The realm's new-factor window in these tests (#1064): 7 days. */
const WINDOW_MS = 7 * 86_400_000;

describe('the TOTP over user_credentials (#653)', () => {
  it('stores when a new binding stops being new, and clears it on a binding that is not (#1064)', async () => {
    const built = setup();
    await bound(built, { isNew: true });
    expect(built.opts.newFactorWindowMs).toHaveBeenCalledWith(REALM);
    expect(built.totpRow()?.newUntil).toBe(T0 + WINDOW_MS);
    expect(built.opts.recorded).toHaveBeenCalledWith(
      { ...ACCOUNT, credentialId: built.totpRow()?.id, newUntil: T0 + WINDOW_MS },
      built.transactions[0]
    );
    built.advance(60_000);
    await bound(built);
    expect(built.totpRow()?.newUntil).toBeNull();
    expect(built.opts.newFactorWindowMs).toHaveBeenCalledTimes(1);
  });

  it('binds nothing when the realm’s window cannot be read (#1064)', async () => {
    const built = setup();
    built.opts.newFactorWindowMs.mockRejectedValueOnce(new Error('the realm is gone'));
    const started = await built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    await expect(
      built.totp.bind({
        ...ACCOUNT,
        clientId: CLIENT,
        sealed: started.sealed,
        step: 1,
        isNew: true,
      })
    ).rejects.toThrow('the realm is gone');
    expect(built.totpRow()).toBeUndefined();
    expect(built.opts.bound).not.toHaveBeenCalled();
  });

  it('binds one row of the account, its secret sealed, its first code spent', async () => {
    const built = setup();
    const secret = await bound(built);
    const row = built.totpRow();
    expect(row).toMatchObject({
      userId: USER,
      realmId: REALM,
      providerType: 'totp',
      externalSub: USER,
      disabledAt: null,
      credentialData: { secret: expect.stringMatching(/^v1\./), last_step: built.step() },
    });
    expect(JSON.stringify(row)).not.toContain(Buffer.from(secret).toString('hex'));
    expect(built.opts.bound).toHaveBeenCalledWith({ ...ACCOUNT, clientId: CLIENT });
    // The account's checks and the write shared one transaction.
    expect(built.transactions).toHaveLength(1);
    expect(built.reads.every((tx) => tx === built.transactions[0])).toBe(true);
    // The first code works no more; the next step's does, once.
    const verify = (code: string) => built.totp.verify({ ...ACCOUNT, clientId: CLIENT, code });
    expect(await verify(codeOf(secret, built.step()))).toEqual({ kind: 'refused' });
    built.advance(30_000);
    expect(await verify(codeOf(secret, built.step()))).toEqual({ kind: 'accepted' });
    expect(await verify(codeOf(secret, built.step()))).toEqual({ kind: 'refused' });
  });

  it('records the binding in its own transaction, and a record that fails binds nothing (#844)', async () => {
    const built = setup();
    await bound(built);
    expect(built.opts.recorded).toHaveBeenCalledWith(
      { ...ACCOUNT, credentialId: built.totpRow()?.id },
      built.transactions[0]
    );

    const failing = setup({ recordFails: true });
    const started = await failing.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    await expect(
      failing.totp.bind({ ...ACCOUNT, clientId: CLIENT, sealed: started.sealed, step: 1 })
    ).rejects.toThrow('the record could not be written');
    expect(failing.opts.bound).not.toHaveBeenCalled();
  });

  it('refuses to bind for an unclaimed, a disabled or a missing account', async () => {
    const unclaimed = setup({
      rows: [
        {
          id: 'password',
          userId: USER,
          realmId: REALM,
          providerType: 'password',
          externalSub: 'alice@example.com',
          credentialData: { password_hash: 'h', email_verified: false },
          disabledAt: null,
        },
      ],
    });
    const started = await unclaimed.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    const bind = (built: ReturnType<typeof setup>) =>
      built.totp.bind({ ...ACCOUNT, clientId: CLIENT, sealed: started.sealed, step: 1 });
    expect(await bind(unclaimed)).toEqual({ kind: 'refused', reason: 'account_unclaimed' });
    expect(unclaimed.totpRow()).toBeUndefined();
    const disabled = setup({ user: { id: USER, enabled: false } });
    expect(await bind(disabled)).toEqual({ kind: 'refused', reason: 'account_disabled' });
    const gone = setup({ user: undefined });
    expect(await bind(gone)).toEqual({ kind: 'refused', reason: 'subject_mismatch' });
    for (const built of [unclaimed, disabled, gone]) {
      expect(built.opts.bound).not.toHaveBeenCalled();
      expect(built.opts.recorded).not.toHaveBeenCalled();
    }
  });

  it('binds for an account an operator verified, its address unconfirmed (#1052)', async () => {
    // An operator's verification claims the account (ADR-017 Decision 8, as
    // amended 2026-11-08).
    const built = setup({
      user: { id: USER, enabled: true, operatorVerifiedAt: T0 },
      rows: [
        {
          id: 'password',
          userId: USER,
          realmId: REALM,
          providerType: 'password',
          externalSub: 'alice@example.com',
          credentialData: { password_hash: 'h', email_verified: false },
          disabledAt: null,
        },
      ],
    });
    const started = await built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    const bound = await built.totp.bind({
      ...ACCOUNT,
      clientId: CLIENT,
      sealed: started.sealed,
      step: 1,
    });
    expect(bound).toEqual({ kind: 'bound', credentialId: built.totpRow()?.id });
    expect(built.totpRow()).toBeDefined();
  });

  it("never rewrites another account's row", async () => {
    const built = setup();
    built.rows.push({
      id: 'theirs',
      userId: 'someone-else',
      realmId: REALM,
      providerType: TOTP_PROVIDER_TYPE,
      externalSub: USER,
      credentialData: { secret: 'v1.k.x.y', last_step: 1 },
      disabledAt: null,
    });
    const started = await built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    expect(
      await built.totp.bind({ ...ACCOUNT, clientId: CLIENT, sealed: started.sealed, step: 2 })
    ).toEqual({ kind: 'refused', reason: 'subject_mismatch' });
    expect(built.rows.find((row) => row.id === 'theirs')?.credentialData).toEqual({
      secret: 'v1.k.x.y',
      last_step: 1,
    });
  });

  it('reads no TOTP of another realm, and fails on a row it cannot read', async () => {
    const built = setup();
    const secret = await bound(built);
    built.advance(30_000);
    expect(
      await built.totp.verify({
        realmId: OTHER_REALM,
        userId: USER,
        clientId: CLIENT,
        code: codeOf(secret, built.step()),
      })
    ).toEqual({ kind: 'refused' });
    const row = built.totpRow();
    if (row === undefined) throw new Error('no row');
    row.credentialData = { secret: 'v1.k.x.y', last_step: 'soon' };
    await expect(
      built.totp.verify({ ...ACCOUNT, clientId: CLIENT, code: '123456' })
    ).rejects.toThrow('a TOTP credential whose data is not one');
  });

  it('disables the TOTP at the ceiling only while armed, and tells the user once', async () => {
    const built = setup();
    const secret = await bound(built);
    await built.totp.ceilingReached(ACCOUNT);
    await built.totp.ceilingReached(ACCOUNT);
    expect(built.totpRow()?.disabledAt).toBe(T0);
    expect(built.opts.disabled).toHaveBeenCalledTimes(1);
    built.advance(30_000);
    expect(
      await built.totp.verify({ ...ACCOUNT, clientId: CLIENT, code: codeOf(secret, built.step()) })
    ).toEqual({ kind: 'refused' });
    // A new binding replaces it and clears the mark.
    await bound(built);
    expect(built.totpRow()?.disabledAt).toBeNull();

    const unarmed = setup({ armed: false });
    await bound(unarmed);
    await unarmed.totp.ceilingReached(ACCOUNT);
    expect(unarmed.totpRow()?.disabledAt).toBeNull();
    expect(unarmed.opts.disabled).not.toHaveBeenCalled();
  });

  it('reports an arming it cannot read, a notice that fails, and changes nothing for them', async () => {
    const built = setup();
    await bound(built);
    built.opts.hardActionArmed.mockRejectedValueOnce(new Error('recovery codes down'));
    await built.totp.ceilingReached(ACCOUNT);
    expect(built.totpRow()?.disabledAt).toBeNull();
    built.opts.disabled.mockRejectedValueOnce(new Error('mail down'));
    await built.totp.ceilingReached(ACCOUNT);
    expect(built.totpRow()?.disabledAt).toBe(T0);
    built.opts.bound.mockRejectedValueOnce(new Error('mail down'));
    await bound(built);
    expect(built.opts.report.mock.calls.map(([, what]) => what)).toEqual([
      'the TOTP hard action',
      'the second-factor-disabled notice',
      'the TOTP-added notice',
    ]);
  });

  it('passes the wrong-code-after-password notice to the caller', async () => {
    const built = setup();
    await built.totp.failedAfterPassword({ ...ACCOUNT, clientId: CLIENT });
    expect(built.opts.failedAfterPassword).toHaveBeenCalledWith({ ...ACCOUNT, clientId: CLIENT });
  });
});
