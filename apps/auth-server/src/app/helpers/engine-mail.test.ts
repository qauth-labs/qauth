import type {
  MailPassBinding,
  SendCapDecision,
  SendCapRequest,
  SendCapStore,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import {
  type CappedMailerDependencies,
  createCappedMailer,
  type MailAccount,
  SEND_CEILING_ALERT,
} from './engine-mail';

const REALM = { id: '9a1f6a1e-5a5b-4c1a-9a7e-3d1c1c2b0a01', issuer: 'https://auth.example.com' };
const ADDRESS = 'owner@example.com';
const PASS = 'P'.repeat(43);
const CODE_MAIL = {
  template: 'code',
  purpose: 'recovery',
  code: '12345678',
  expiresInSeconds: 600,
} as const;

/** A request whose client address is `ip`, as `ladderEndUserIp` reads it. */
const requestFrom = (ip?: string) => ({ ip }) as unknown as FastifyRequest;

interface Harness {
  readonly deps: CappedMailerDependencies;
  readonly reserved: SendCapRequest[];
  readonly claims: string[];
  readonly sent: { to: string; mail: unknown; baseUrl: string }[];
  readonly errors: { details: Record<string, unknown>; message: string }[];
  /** Run every background task started so far. */
  settle(): Promise<void>;
}

function harness(
  options: {
    decision?: SendCapDecision;
    account?: MailAccount;
    knownIp?: boolean;
    claim?: boolean;
  } = {}
): Harness {
  const reserved: SendCapRequest[] = [];
  const claims: string[] = [];
  const sent: Harness['sent'] = [];
  const errors: Harness['errors'] = [];
  const tasks: (() => Promise<unknown>)[] = [];
  const caps: SendCapStore = {
    async reserve(request) {
      reserved.push(request);
      return options.decision ?? { kind: 'send', passSpent: false };
    },
    async mintPass(binding: Omit<MailPassBinding, 'passHash'> & { realmId: string }) {
      claims.push(`mint:${binding.flow}:${binding.addressHmac}`);
      return PASS;
    },
    async peekPass() {
      return undefined;
    },
    async claimNotice(input) {
      claims.push(`claim:${input.kind}:${input.addressHmac}`);
      return options.claim ?? true;
    },
  };
  const deps: CappedMailerDependencies = {
    caps,
    digests: {
      identifierDigest: async ({ identifier }) => `id-${identifier.length}`,
      ipDigest: async ({ identifier }) => `ip-${identifier.replace(/\W/g, '')}`,
    },
    isKnownIp: vi.fn(async () => options.knownIp ?? false),
    accountOf: vi.fn(async () => options.account),
    realmOf: async (realmId) => (realmId === REALM.id ? REALM : undefined),
    mail: {
      sendEngineMail: vi.fn(async (_realmId, to, mail, context) => {
        sent.push({ to, mail, baseUrl: context.baseUrl });
        return { success: true, messageId: 'm' };
      }),
      canSend: vi.fn(async () => true),
    },
    tasks: { run: (task) => void tasks.push(task) },
    log: { error: (details, message) => void errors.push({ details, message }) },
    mockSends: true,
  };
  return {
    deps,
    reserved,
    claims,
    sent,
    errors,
    async settle() {
      while (tasks.length > 0) await (tasks.shift() as () => Promise<unknown>)();
    },
  };
}

describe('the engine mail and its send caps (#637)', () => {
  it('mails a code once the caps let it through, after the answer, from the realm’s issuer', async () => {
    const h = harness();
    const mailer = createCappedMailer(h.deps);

    const outcome = await mailer.sendCode(requestFrom('192.0.2.7'), {
      realm: REALM,
      address: ADDRESS,
      mail: CODE_MAIL,
      flow: 'reset',
    });

    expect(outcome).toEqual({ kind: 'accepted', passSpent: false });
    // Dispatched in the background: nothing is sent before the caller answers.
    expect(h.sent).toEqual([]);
    await h.settle();
    expect(h.sent).toEqual([{ to: ADDRESS, mail: CODE_MAIL, baseUrl: REALM.issuer }]);
    expect(h.reserved).toEqual([
      {
        realmId: REALM.id,
        addressHmac: `id-${ADDRESS.length}`,
        endUserIpHmac: 'ip-192027',
        knownIp: false,
        afterFirstFactor: false,
      },
    ]);
  });

  it('answers a quiet drop and an address with no mail exactly as a send', async () => {
    const quiet = harness({ decision: { kind: 'quiet' } });
    const unknown = harness();
    const sent = harness();
    const input = { realm: REALM, address: ADDRESS, flow: 'reset' as const };

    const outcomes = [
      await createCappedMailer(quiet.deps).sendCode(requestFrom('192.0.2.7'), {
        ...input,
        mail: CODE_MAIL,
      }),
      await createCappedMailer(unknown.deps).sendCode(requestFrom('192.0.2.7'), input),
      await createCappedMailer(sent.deps).sendCode(requestFrom('192.0.2.7'), {
        ...input,
        mail: CODE_MAIL,
      }),
    ];
    await Promise.all([quiet.settle(), unknown.settle(), sent.settle()]);

    expect(new Set(outcomes.map((outcome) => JSON.stringify(outcome))).size).toBe(1);
    expect(quiet.sent).toEqual([]);
    expect(unknown.sent).toEqual([]);
    expect(sent.sent).toHaveLength(1);
    // The address with no mail still counts.
    expect(unknown.reserved).toHaveLength(1);
  });

  it('answers a refused tier with its Retry-After, and alerts the operator at the ceiling by HMAC only', async () => {
    const h = harness({
      decision: { kind: 'refused', tier: 'ceiling', retryAfterMs: 3_600_001, alert: true },
      account: { enabled: true, verified: true },
    });

    const outcome = await createCappedMailer(h.deps).sendCode(requestFrom('192.0.2.7'), {
      realm: REALM,
      address: ADDRESS,
      mail: CODE_MAIL,
      flow: 'reset',
    });

    expect(outcome).toEqual({ kind: 'capped', retryAfterSeconds: 3601 });
    expect(h.errors).toEqual([
      {
        details: { realmId: REALM.id, addressHmac: `id-${ADDRESS.length}` },
        message: SEND_CEILING_ALERT,
      },
    ]);
    expect(JSON.stringify(h.errors)).not.toContain(ADDRESS);
    await h.settle();
    // The code is not sent; the ceiling notice is, with a reset pass.
    expect(h.claims).toEqual([
      `claim:send_ceiling:id-${ADDRESS.length}`,
      `mint:reset:id-${ADDRESS.length}`,
    ]);
    expect(h.sent).toEqual([
      {
        to: ADDRESS,
        mail: { template: 'send_ceiling', flow: 'reset', pass: PASS, passExpiresInSeconds: 86_400 },
        baseUrl: REALM.issuer,
      },
    ]);
  });

  it('alerts once: a later refusal at the ceiling only tries the notice', async () => {
    const h = harness({
      decision: { kind: 'refused', tier: 'ceiling', retryAfterMs: 1000, alert: false },
      account: { enabled: true, verified: true },
      claim: false,
    });

    await createCappedMailer(h.deps).sendCode(requestFrom('192.0.2.7'), {
      realm: REALM,
      address: ADDRESS,
      mail: CODE_MAIL,
      flow: 'reset',
    });
    await h.settle();

    expect(h.errors).toEqual([]);
    // The day's notice was claimed already: no pass, no mail.
    expect(h.claims).toEqual([`claim:send_ceiling:id-${ADDRESS.length}`]);
    expect(h.sent).toEqual([]);
  });

  it.each([
    ['an address with no account at a registration start', undefined, 'register', 'register'],
    ['an address with no account at a reset start', undefined, 'reset', undefined],
    ['a disabled account', { enabled: false, verified: true }, 'reset', undefined],
    [
      'an existing account at a registration start',
      { enabled: true, verified: false },
      'register',
      'reset',
    ],
  ] as const)(
    'sends the ceiling notice to %s as it should',
    async (_label, account, flow, pass) => {
      const h = harness({
        decision: { kind: 'refused', tier: 'ceiling', retryAfterMs: 1000, alert: true },
        ...(account === undefined ? {} : { account }),
      });

      await createCappedMailer(h.deps).sendCode(requestFrom('192.0.2.7'), {
        realm: REALM,
        address: ADDRESS,
        flow,
      });
      await h.settle();

      if (pass === undefined) {
        // No recipient: the day's notice is not used up.
        expect(h.claims).toEqual([]);
        expect(h.sent).toEqual([]);
      } else {
        expect(h.claims).toContain(`mint:${pass}:id-${ADDRESS.length}`);
        expect(h.sent.map((sent) => sent.mail)).toEqual([
          { template: 'send_ceiling', flow: pass, pass: PASS, passExpiresInSeconds: 86_400 },
        ]);
      }
    }
  );

  it('sends no notice and raises no alert at any other tier', async () => {
    for (const tier of ['end_user_ip', 'client', 'after_first_factor', 'address_client'] as const) {
      const h = harness({
        decision: { kind: 'refused', tier, retryAfterMs: 2500, alert: false },
        account: { enabled: true, verified: true },
      });
      const outcome = await createCappedMailer(h.deps).sendCode(requestFrom('192.0.2.7'), {
        realm: REALM,
        address: ADDRESS,
        mail: CODE_MAIL,
        flow: 'reset',
      });
      await h.settle();
      expect(outcome).toEqual({ kind: 'capped', retryAfterSeconds: 3 });
      expect(h.claims).toEqual([]);
      expect(h.sent).toEqual([]);
      expect(h.errors).toEqual([]);
    }
  });

  it('exempts a known IP only for a verified, enabled account', async () => {
    const cases: [boolean, MailAccount | undefined, boolean][] = [
      [true, { enabled: true, verified: true }, true],
      [true, { enabled: true, verified: false }, false],
      [true, { enabled: false, verified: true }, false],
      [true, undefined, false],
      [false, { enabled: true, verified: true }, false],
    ];
    for (const [knownIp, account, exempt] of cases) {
      const h = harness({ knownIp, ...(account === undefined ? {} : { account }) });
      await createCappedMailer(h.deps).sendCode(requestFrom('192.0.2.7'), {
        realm: REALM,
        address: ADDRESS,
        mail: CODE_MAIL,
        flow: 'reset',
      });
      expect(h.reserved[0]?.knownIp).toBe(exempt);
      // The account is read only for a known IP.
      expect(vi.mocked(h.deps.accountOf).mock.calls.length).toBe(knownIp ? 1 : 0);
    }
  });

  it('keys no IP when the request carries no client address, and asks for no known IP', async () => {
    const h = harness({ knownIp: true });
    await createCappedMailer(h.deps).sendCode(requestFrom(undefined), {
      realm: REALM,
      address: ADDRESS,
      mail: CODE_MAIL,
      flow: 'reset',
    });

    expect(h.reserved[0]).not.toHaveProperty('endUserIpHmac');
    expect(h.reserved[0]?.knownIp).toBe(false);
    expect(h.deps.isKnownIp).not.toHaveBeenCalled();
  });

  it('hands the caps the FiPA client, the asserted IP, the first factor and the pass', async () => {
    const h = harness({ decision: { kind: 'send', passSpent: true } });
    const outcome = await createCappedMailer(h.deps).sendCode(requestFrom('192.0.2.7'), {
      realm: REALM,
      address: ADDRESS,
      mail: CODE_MAIL,
      flow: 'reset',
      fipaClientId: 'first-party-app',
      endUserIp: '198.51.100.4',
      afterFirstFactor: true,
      passHash: 'h'.repeat(43),
    });

    expect(outcome).toEqual({ kind: 'accepted', passSpent: true });
    expect(h.reserved[0]).toEqual({
      realmId: REALM.id,
      addressHmac: `id-${ADDRESS.length}`,
      endUserIpHmac: 'ip-198511004',
      clientKey: 'first-party-app',
      knownIp: false,
      afterFirstFactor: true,
      passHash: 'h'.repeat(43),
    });
  });

  it('fails closed when the caps cannot decide', async () => {
    const h = harness();
    h.deps.caps.reserve = async () => {
      throw new Error('send caps: reserve timed out');
    };
    await expect(
      createCappedMailer(h.deps).sendCode(requestFrom('192.0.2.7'), {
        realm: REALM,
        address: ADDRESS,
        mail: CODE_MAIL,
        flow: 'reset',
      })
    ).rejects.toThrow(/timed out/);
    await h.settle();
    expect(h.sent).toEqual([]);
  });

  it('counts only mail with a code, and never holds back mail without one', async () => {
    const h = harness();
    const mailer = createCappedMailer(h.deps);

    await expect(
      mailer.sendCode(requestFrom('192.0.2.7'), {
        realm: REALM,
        address: ADDRESS,
        mail: { template: 'account_exists' } as never,
        flow: 'register',
      })
    ).rejects.toThrow(/carries a code/);
    expect(() => mailer.sendUncounted(REALM, ADDRESS, CODE_MAIL)).toThrow(/send caps/);

    mailer.sendUncounted(REALM, ADDRESS, { template: 'password_changed' });
    await h.settle();
    expect(h.reserved).toEqual([]);
    expect(h.sent).toEqual([
      { to: ADDRESS, mail: { template: 'password_changed' }, baseUrl: REALM.issuer },
    ]);
  });

  it('sends the password-disabled notice once a day, with a reset pass', async () => {
    const h = harness();
    const notices = createCappedMailer(h.deps).passwordDisabledNotices;

    await notices.passwordDisabled({ realmId: REALM.id, userId: 'u', identifier: ADDRESS });

    expect(h.claims).toEqual([
      `claim:password_disabled:id-${ADDRESS.length}`,
      `mint:reset:id-${ADDRESS.length}`,
    ]);
    expect(h.sent).toEqual([
      {
        to: ADDRESS,
        mail: { template: 'password_disabled', pass: PASS, passExpiresInSeconds: 86_400 },
        baseUrl: REALM.issuer,
      },
    ]);

    const claimed = harness({ claim: false });
    await createCappedMailer(claimed.deps).passwordDisabledNotices.passwordDisabled({
      realmId: REALM.id,
      userId: 'u',
      identifier: ADDRESS,
    });
    expect(claimed.sent).toEqual([]);
  });

  it('asks the realm’s transport whether the notice can go out, a mock counting only outside production', async () => {
    const h = harness();
    expect(await createCappedMailer(h.deps).passwordDisabledNotices.canSend(REALM.id)).toBe(true);
    expect(h.deps.mail.canSend).toHaveBeenCalledWith(REALM.id, { mockSends: true });

    const production = harness();
    await createCappedMailer({
      ...production.deps,
      mockSends: false,
    }).passwordDisabledNotices.canSend(REALM.id);
    expect(production.deps.mail.canSend).toHaveBeenCalledWith(REALM.id, { mockSends: false });
  });

  it('refuses a password-disabled notice for a realm that is gone', async () => {
    const h = harness();
    await expect(
      createCappedMailer(h.deps).passwordDisabledNotices.passwordDisabled({
        realmId: '00000000-0000-4000-8000-000000000000',
        userId: 'u',
        identifier: ADDRESS,
      })
    ).rejects.toThrow(/gone/);
    expect(h.claims).toEqual([]);
  });
});
