import { grammarStep } from '@qauth-labs/server-step-grammar';
import { describe, expect, it, vi } from 'vitest';

import { createMemoryTotp } from '../testing/memory-totp';
import type { Clock, TotpAccount } from './ports';
import {
  base32Encode,
  createTotpService,
  hotp,
  matchTotpCode,
  otpauthUri,
  type StoredTotp,
  TOTP_PERIOD_SECONDS,
  TOTP_SECRET_BYTES,
  type TotpCipher,
  totpCode,
  totpStep,
  type TotpStore,
} from './totp';

/**
 * TOTP (#653; ADR-017 Decision 8, ADR-020 §3, RFC 6238): the fixed
 * parameters, a time step accepted once, and a secret that is never stored,
 * returned or reported in clear but by the set-up step's display.
 */

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const ACCOUNT: TotpAccount = { realmId: REALM, userId: USER };
const CLIENT = 'web-client';
/** RFC 6238 Appendix B's SHA-1 seed: the ASCII string "12345678901234567890". */
const RFC_SECRET = new Uint8Array(Buffer.from('12345678901234567890', 'ascii'));
const T0 = 1_800_000_000_000;
const STEP_MS = TOTP_PERIOD_SECONDS * 1000;

function manualClock(start = T0): Clock & { advance(ms: number): void } {
  let now = start;
  return {
    now: () => now,
    sleep: async (ms) => {
      now += ms;
    },
    advance: (ms) => {
      now += ms;
    },
  };
}

describe('the TOTP algorithm (RFC 6238, ADR-020 §3)', () => {
  it("gives RFC 6238 Appendix B's SHA-1 values, cut to six digits", () => {
    // Appendix B lists 8 digits; 6 digits are the same value modulo 10^6.
    const vectors: [number, string][] = [
      [59, '94287082'],
      [1_111_111_109, '07081804'],
      [1_111_111_111, '14050471'],
      [1_234_567_890, '89005924'],
      [2_000_000_000, '69279037'],
      [20_000_000_000, '65353130'],
    ];
    for (const [seconds, eight] of vectors) {
      expect(totpCode(RFC_SECRET, totpStep(seconds * 1000)), String(seconds)).toBe(eight.slice(2));
    }
  });

  it("gives RFC 4226 Appendix D's HOTP values", () => {
    const expected = ['755224', '287082', '359152', '969429', '338314'];
    expected.forEach((value, counter) => expect(hotp(RFC_SECRET, counter)).toBe(value));
    expect(() => hotp(RFC_SECRET, -1)).toThrow();
    expect(() => hotp(RFC_SECRET, 1.5)).toThrow();
  });

  it('counts 30-second steps from the epoch', () => {
    expect(totpStep(0)).toBe(0);
    expect(totpStep(29_999)).toBe(0);
    expect(totpStep(30_000)).toBe(1);
    expect(totpStep(59_000)).toBe(1);
  });

  it("encodes in RFC 4648 §6's base32, unpadded", () => {
    const vectors: [string, string][] = [
      ['', ''],
      ['f', 'MY'],
      ['fo', 'MZXQ'],
      ['foo', 'MZXW6'],
      ['foob', 'MZXW6YQ'],
      ['fooba', 'MZXW6YTB'],
      ['foobar', 'MZXW6YTBOI'],
    ];
    for (const [text, encoded] of vectors) {
      expect(base32Encode(new Uint8Array(Buffer.from(text, 'ascii')))).toBe(encoded);
    }
    expect(base32Encode(new Uint8Array(TOTP_SECRET_BYTES))).toMatch(/^[A-Z2-7]{32}$/);
  });

  it('matches one step of tolerance either way, and no further', () => {
    const now = totpStep(T0);
    for (const offset of [-1, 0, 1]) {
      expect(matchTotpCode(RFC_SECRET, totpCode(RFC_SECRET, now + offset), T0, -1)).toBe(
        now + offset
      );
    }
    for (const offset of [-2, 2]) {
      expect(matchTotpCode(RFC_SECRET, totpCode(RFC_SECRET, now + offset), T0, -1)).toBeNull();
    }
  });

  it('refuses a code of the last accepted step or an earlier one', () => {
    const now = totpStep(T0);
    const previous = totpCode(RFC_SECRET, now - 1);
    expect(matchTotpCode(RFC_SECRET, previous, T0, now - 2)).toBe(now - 1);
    expect(matchTotpCode(RFC_SECRET, previous, T0, now - 1)).toBeNull();
    expect(matchTotpCode(RFC_SECRET, previous, T0, now)).toBeNull();
    expect(matchTotpCode(RFC_SECRET, totpCode(RFC_SECRET, now + 1), T0, now)).toBe(now + 1);
  });

  it('refuses anything but six digits, matching it as long', () => {
    const code = totpCode(RFC_SECRET, totpStep(T0));
    for (const bad of [
      '',
      '12345',
      '1234567',
      ` ${code.slice(1)}`,
      `${code}\n`,
      '12a456',
      '٠١٢٣٤٥',
    ]) {
      expect(matchTotpCode(RFC_SECRET, bad, T0, -1), JSON.stringify(bad)).toBeNull();
    }
  });

  it("builds an otpauth URI the set-up step's grammar accepts", () => {
    const secret = base32Encode(RFC_SECRET);
    const uri = otpauthUri({ secret, issuer: 'auth.example.com', account: 'alice@example.com' });
    expect(uri).toBe(
      `otpauth://totp/auth.example.com:alice%40example.com?secret=${secret}&issuer=auth.example.com&algorithm=SHA1&digits=6&period=30`
    );
    // Whatever the names hold, the URI keeps to the grammar's characters and length.
    const odd = otpauthUri({
      secret,
      issuer: 'Ex "ample" <corp> \\ ünï',
      account: `${'a'.repeat(300)} &secret=AAAA#frag`,
    });
    expect(grammarStep('totp_setup').personal.safeParse({ secret, otpauth_uri: odd }).success).toBe(
      true
    );
    expect(new URL(odd).searchParams.getAll('secret')).toEqual([secret]);
  });
});

/** A store in memory that records every write, for what it is given to keep. */
function recordingStore(initial: StoredTotp | null = null) {
  let row = initial;
  const writes: unknown[] = [];
  const store: TotpStore = {
    async read() {
      return row;
    },
    async accept({ step }) {
      writes.push({ accept: step });
      if (row === null || row.disabled || row.lastStep >= step) return false;
      row = { ...row, lastStep: step };
      return true;
    },
    async bind({ sealed, step }) {
      writes.push({ bind: { sealed, step } });
      row = { sealed, lastStep: step, disabled: false };
      return { kind: 'bound' };
    },
  };
  return { store, writes, row: () => row };
}

/** A cipher that seals reversibly (XOR and a tag), and keeps every secret it opened, to check each is wiped. */
function trackingCipher() {
  const opened: Uint8Array[] = [];
  const pad = (bytes: Uint8Array) => Buffer.from(bytes.map((byte, i) => byte ^ (0x5a + i)));
  const cipher: TotpCipher = {
    async seal({ secret }) {
      return `v1.k.AAAAAAAAAAAAAAAA.${pad(secret).toString('base64url')}`;
    },
    async open({ sealed }) {
      const body = sealed.split('.')[3];
      if (body === undefined) throw new Error('not a ciphertext');
      const secret = new Uint8Array(pad(new Uint8Array(Buffer.from(body, 'base64url'))));
      opened.push(secret);
      return secret;
    },
  };
  return { cipher, opened };
}

function service(
  clock: Clock,
  initial: StoredTotp | null = null,
  overrides: Partial<Parameters<typeof createTotpService>[0]> = {}
) {
  const store = recordingStore(initial);
  const { cipher, opened } = trackingCipher();
  const notices = {
    bound: vi.fn(async () => undefined),
    ceilingReached: vi.fn(async () => undefined),
    failedAfterPassword: vi.fn(async () => undefined),
  };
  const reports: unknown[] = [];
  const totp = createTotpService({
    store: store.store,
    cipher,
    notices,
    issuerOf: async () => 'auth.example.com',
    report: (error, what) => reports.push({ error, what }),
    clock,
    ...overrides,
  });
  return { totp, store, cipher, opened, notices, reports };
}

async function sealedRfcSecret(): Promise<string> {
  return trackingCipher().cipher.seal({ ...ACCOUNT, secret: RFC_SECRET });
}

describe('the TOTP service: a code works once', () => {
  it('accepts a code valid for the previous step once, and refuses it on a second use', async () => {
    const clock = manualClock();
    const now = totpStep(clock.now());
    const built = service(clock, {
      sealed: await sealedRfcSecret(),
      lastStep: now - 5,
      disabled: false,
    });
    const previous = totpCode(RFC_SECRET, now - 1);
    const answer = { ...ACCOUNT, clientId: CLIENT, code: previous };
    expect(await built.totp.verify(answer)).toEqual({ kind: 'accepted' });
    expect(built.store.row()?.lastStep).toBe(now - 1);
    expect(await built.totp.verify(answer)).toEqual({ kind: 'refused' });
    // The same value a step later, still in the window: refused all the same.
    clock.advance(STEP_MS);
    expect(await built.totp.verify(answer)).toEqual({ kind: 'refused' });
  });

  it('refuses an earlier step once a later one was accepted', async () => {
    const clock = manualClock();
    const now = totpStep(clock.now());
    const built = service(clock, {
      sealed: await sealedRfcSecret(),
      lastStep: now - 5,
      disabled: false,
    });
    const verify = (step: number) =>
      built.totp.verify({ ...ACCOUNT, clientId: CLIENT, code: totpCode(RFC_SECRET, step) });
    expect(await verify(now)).toEqual({ kind: 'accepted' });
    expect(await verify(now - 1)).toEqual({ kind: 'refused' });
    expect(await verify(now + 1)).toEqual({ kind: 'accepted' });
  });

  it('takes a step once when two rounds answer the same code at once', async () => {
    const clock = manualClock();
    const now = totpStep(clock.now());
    const built = service(clock, {
      sealed: await sealedRfcSecret(),
      lastStep: now - 5,
      disabled: false,
    });
    const answer = { ...ACCOUNT, clientId: CLIENT, code: totpCode(RFC_SECRET, now) };
    const results = await Promise.all([built.totp.verify(answer), built.totp.verify(answer)]);
    expect(results.filter((result) => result.kind === 'accepted')).toHaveLength(1);
  });

  it('refuses every code of a disabled TOTP, and of none', async () => {
    const clock = manualClock();
    const code = totpCode(RFC_SECRET, totpStep(clock.now()));
    const disabled = service(clock, {
      sealed: await sealedRfcSecret(),
      lastStep: -1,
      disabled: true,
    });
    expect(await disabled.totp.verify({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
      kind: 'refused',
    });
    expect(disabled.store.writes).toEqual([]);
    const none = service(clock);
    expect(await none.totp.verify({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
      kind: 'refused',
    });
  });

  it('refuses a ciphertext that holds no secret as an outage', async () => {
    const clock = manualClock();
    const built = service(
      clock,
      { sealed: 'v1.k.AAAAAAAAAAAAAAAA.AAAA', lastStep: -1, disabled: false },
      {}
    );
    await expect(
      built.totp.verify({ ...ACCOUNT, clientId: CLIENT, code: '123456' })
    ).rejects.toThrow('the ciphertext holds no secret');
  });
});

describe('the TOTP service: the set-up', () => {
  it('draws 160 bits, seals them at once, and checks a first code without binding', async () => {
    const clock = manualClock();
    const built = service(clock);
    const started = await built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    expect(started.display.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(started.display.otpauthUri).toContain(`secret=${started.display.secret}`);
    expect(started.sealed).not.toContain(started.display.secret);
    // Shown again, the same secret.
    expect(
      await built.totp.display({
        ...ACCOUNT,
        identifier: 'alice@example.com',
        sealed: started.sealed,
      })
    ).toEqual(started.display);
    const now = totpStep(clock.now());
    const reopened = await built.cipher.open({ ...ACCOUNT, sealed: started.sealed });
    expect(base32Encode(reopened)).toBe(started.display.secret);
    const code = totpCode(reopened, now);
    const wrong = code === '000000' ? '111111' : '000000';
    expect(await built.totp.check({ ...ACCOUNT, sealed: started.sealed, code: wrong })).toEqual({
      kind: 'refused',
    });
    // A right first code: valid for its step, and still nothing bound.
    expect(await built.totp.check({ ...ACCOUNT, sealed: started.sealed, code })).toEqual({
      kind: 'valid',
      step: now,
    });
    expect(built.store.writes).toEqual([]);
    expect(built.notices.bound).not.toHaveBeenCalled();
  });

  it('binds with the step the first code matched, so that code works no more', async () => {
    const clock = manualClock();
    const built = service(clock);
    const started = await built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    const secret = await built.cipher.open({ ...ACCOUNT, sealed: started.sealed });
    const now = totpStep(clock.now());
    const code = totpCode(secret, now);
    expect(
      await built.totp.bind({ ...ACCOUNT, clientId: CLIENT, sealed: started.sealed, step: now })
    ).toEqual({ kind: 'bound' });
    expect(built.notices.bound).toHaveBeenCalledWith({ ...ACCOUNT, clientId: CLIENT });
    expect(await built.totp.verify({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
      kind: 'refused',
    });
    expect(
      await built.totp.verify({
        ...ACCOUNT,
        clientId: CLIENT,
        code: totpCode(secret, now + 1),
      })
    ).toEqual({ kind: 'accepted' });
  });

  it('binds all the same when the notice fails, and reports it', async () => {
    const clock = manualClock();
    const built = service(clock);
    built.notices.bound.mockRejectedValueOnce(new Error('mail down'));
    const started = await built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    expect(
      await built.totp.bind({ ...ACCOUNT, clientId: CLIENT, sealed: started.sealed, step: 1 })
    ).toEqual({ kind: 'bound' });
    expect(built.reports).toHaveLength(1);
  });

  it('refuses a ciphertext the cipher did not make, before any binding', async () => {
    const clock = manualClock();
    const built = service(clock, null, {
      cipher: {
        seal: async () => '',
        open: async () => new Uint8Array(TOTP_SECRET_BYTES),
      },
    });
    await expect(built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' })).rejects.toThrow(
      'not a ciphertext'
    );
    const failing = service(clock, null, {
      cipher: {
        seal: async () => 'v1.k.iv.ct',
        open: async () => Promise.reject(new Error('wrong context')),
      },
    });
    await expect(
      failing.totp.bind({ ...ACCOUNT, clientId: CLIENT, sealed: 'v1.k.iv.ct', step: 1 })
    ).rejects.toThrow('wrong context');
    expect(failing.store.writes).toEqual([]);
  });
});

describe('the TOTP secret is never stored or logged in clear', () => {
  it('keeps only ciphertexts in the store, wipes every secret it opened, and reports none', async () => {
    const clock = manualClock();
    const reported: string[] = [];
    const log = vi.spyOn(console, 'log');
    const warn = vi.spyOn(console, 'warn');
    const error = vi.spyOn(console, 'error');
    const memory = createMemoryTotp(clock);
    const started = await memory.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    const clear = started.display.secret;
    const again = await memory.display({
      ...ACCOUNT,
      identifier: 'alice@example.com',
      sealed: started.sealed,
    });
    expect(again.secret).toBe(clear);
    const now = totpStep(clock.now());
    // A wrong first code, a right one, a binding with a notice that fails, a
    // wrong code, a right one and a replayed one.
    memory.failNext = 'bound';
    await memory.check({ ...ACCOUNT, sealed: started.sealed, code: '000000' });
    await memory.bind({ ...ACCOUNT, clientId: CLIENT, sealed: started.sealed, step: now });
    const secret = memory.secretOf(USER, REALM);
    for (const code of ['999999', totpCode(secret, now + 1), totpCode(secret, now + 1)]) {
      await memory.verify({ ...ACCOUNT, clientId: CLIENT, code });
    }
    reported.push(...memory.reports);

    const hex = Buffer.from(secret).toString('hex');
    const b64 = Buffer.from(secret).toString('base64');
    const b64url = Buffer.from(secret).toString('base64url');
    const forms = [clear, clear.toLowerCase(), hex, b64, b64url];
    const kept = JSON.stringify([...memory.rows.values()]);
    const logged = JSON.stringify([
      reported,
      memory.notices,
      log.mock.calls,
      warn.mock.calls,
      error.mock.calls,
    ]);
    for (const form of forms) {
      expect(kept).not.toContain(form);
      expect(logged).not.toContain(form);
    }
    expect(reported).toEqual(['the TOTP-added notice: memory totp: the bound notice failed']);
    // The row holds a ciphertext only, in the signer's shape.
    expect([...memory.rows.values()].map((row) => row.sealed)).toEqual([
      expect.stringMatching(/^v1\.memory\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/),
    ]);
    log.mockRestore();
    warn.mockRestore();
    error.mockRestore();
  });

  it('overwrites each secret it opened once it is used', async () => {
    const clock = manualClock();
    const now = totpStep(clock.now());
    const built = service(clock, {
      sealed: await sealedRfcSecret(),
      lastStep: now - 5,
      disabled: false,
    });
    await built.totp.verify({ ...ACCOUNT, clientId: CLIENT, code: totpCode(RFC_SECRET, now) });
    await built.totp.verify({ ...ACCOUNT, clientId: CLIENT, code: '000000' });
    const started = await built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    await built.totp.display({
      ...ACCOUNT,
      identifier: 'alice@example.com',
      sealed: started.sealed,
    });
    await built.totp.check({ ...ACCOUNT, sealed: started.sealed, code: '000000' });
    await built.totp.bind({ ...ACCOUNT, clientId: CLIENT, sealed: started.sealed, step: now });
    // Two codes, a display, a first code and a binding: five secrets opened.
    expect(built.opened).toHaveLength(5);
    for (const secret of built.opened) expect([...secret].every((byte) => byte === 0)).toBe(true);
  });

  it('never puts the secret in an error the store or the cipher throws through it', async () => {
    const clock = manualClock();
    const built = service(clock, null, {
      store: {
        read: async () => Promise.reject(new Error('store down')),
        accept: async () => false,
        bind: async () => Promise.reject(new Error('store down')),
      },
    });
    const started = await built.totp.start({ ...ACCOUNT, identifier: 'alice@example.com' });
    const errors = await Promise.all([
      built.totp
        .verify({ ...ACCOUNT, clientId: CLIENT, code: '123456' })
        .catch((thrown: unknown) => thrown),
      built.totp
        .bind({ ...ACCOUNT, clientId: CLIENT, sealed: started.sealed, step: 1 })
        .catch((thrown: unknown) => thrown),
    ]);
    for (const thrown of errors) {
      expect(String((thrown as Error).message)).not.toContain(started.display.secret);
      expect(JSON.stringify(thrown)).not.toContain(started.display.secret);
    }
  });
});
