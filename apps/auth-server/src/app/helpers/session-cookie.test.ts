import { createHmac } from 'node:crypto';

import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// A pass-through spy: verification runs as it does in production.
const { timingSafeEqualSpy } = vi.hoisted(() => ({
  timingSafeEqualSpy: vi.fn<(a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView) => boolean>(),
}));
vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  timingSafeEqualSpy.mockImplementation(actual.timingSafeEqual);
  return { ...actual, timingSafeEqual: timingSafeEqualSpy };
});

vi.mock('../../config/env', () => ({
  env: {
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
  },
}));

import { createFakeCookieSigner, type FakeCookieSigner } from '../../testing/cookie-keys';
import type { CookieSecretSource } from './cookie-keys';
import {
  clearLoginCsrfCookie,
  clearSessionCookie,
  clearWalletFlowCookie,
  COOKIE_MAC_LABEL,
  csrfTokensEqual,
  findWalletFlowBinder,
  generateCsrfToken,
  LOGIN_CSRF_COOKIE_NAME,
  readCookie,
  readSessionCookie,
  readWalletFlowBindings,
  SESSION_COOKIE_MAX_SESSIONS,
  SESSION_COOKIE_NAME,
  sessionCookieHeader,
  setLoginCsrfCookie,
  setSessionCookie,
  setWalletFlowCookie,
  signSessionCookie,
  verifyLoginCsrfCookie,
  verifySessionCookie,
  WALLET_FLOW_COOKIE_NAME,
} from './session-cookie';

const REALM_A = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const REALM_B = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02';
const SID = '0190d7a2-0000-7000-8000-00000000abcd';
const HOUR_MS = 3_600_000;

/** A fresh signer per test: each one has its own key ring and cache. */
let signer: FakeCookieSigner;
let fastify: { signer: CookieSecretSource };

beforeEach(() => {
  signer = createFakeCookieSigner();
  fastify = { signer };
  timingSafeEqualSpy.mockClear();
});

afterEach(() => {
  vi.useRealTimers();
});

function captureReply() {
  const cookies: string[] = [];
  const reply = {
    header: (name: string, value: string) => {
      if (name === 'Set-Cookie') cookies.push(value);
      return reply;
    },
  };
  return { reply: reply as never, cookies };
}

/** The value of a `Set-Cookie` header: what a browser sends back. */
function valueOf(header: string): string {
  const pair = header.split(';')[0];
  return pair.slice(pair.indexOf('=') + 1);
}

/** The current cookie key of a realm, as the signer hands it out. */
async function currentKey(realmId: string) {
  return (await signer.getCookieSecrets('local', realmId)).current;
}

/** A value signed exactly as the module does: label, cookie name, realm id, kid and payload. */
function signByHand(
  key: { kid: string; secret: Buffer },
  cookieName: string,
  realmId: string,
  payload: string
): string {
  const mac = createHmac('sha256', key.secret)
    .update([COOKIE_MAC_LABEL, cookieName, realmId, key.kid, payload].join('\u0000'))
    .digest('base64url');
  return `${key.kid}.${payload}.${mac}`;
}

function sessionPayload(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

describe('session cookie: signing and verification (#493)', () => {
  it('signs <kid>.<payload>.<mac> with the realm current key, and verifies it', async () => {
    const value = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });

    const [kid, payload, mac] = value.split('.');
    expect(kid).toBe((await currentKey(REALM_A)).kid);
    expect(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))).toEqual({
      s: [SID],
      a: SID,
    });
    expect(mac).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await verifySessionCookie(fastify, REALM_A, value)).toBe(SID);
    expect(await readSessionCookie(fastify, REALM_A, value)).toEqual({
      sessionIds: [SID],
      activeSessionId: SID,
    });
  });

  it('binds the MAC to the label, the cookie name, the realm id, the kid and the payload', async () => {
    const key = await currentKey(REALM_A);
    const byHand = signByHand(
      key,
      SESSION_COOKIE_NAME,
      REALM_A,
      sessionPayload({ s: [SID], a: SID })
    );

    expect(await signSessionCookie(fastify, { sid: SID, realmId: REALM_A })).toBe(byHand);
  });

  it('refuses a tampered MAC, payload or kid', async () => {
    const value = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });
    const [kid, payload, mac] = value.split('.');
    const flip = (text: string) => `${text.slice(0, -1)}${text.endsWith('A') ? 'B' : 'A'}`;
    const flipFirst = (text: string) => `${text.startsWith('A') ? 'B' : 'A'}${text.slice(1)}`;
    const other = sessionPayload({ s: ['someone-else'], a: 'someone-else' });

    for (const tampered of [
      `${kid}.${payload}.${flipFirst(mac)}`,
      `${kid}.${payload}.${flip(mac)}`,
      `${kid}.${other}.${mac}`,
      `${kid}.${flip(payload)}.${mac}`,
      `${flip(kid)}.${payload}.${mac}`,
    ]) {
      expect(await verifySessionCookie(fastify, REALM_A, tampered), tampered).toBeNull();
    }
  });

  it('refuses a MAC spelled with the unused bits of its last character set', async () => {
    const value = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });
    const [kid, payload, mac] = value.split('.');
    // Same 32 bytes, other spelling: the last character's two low bits are unused.
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(mac[42]);
    const respelled = `${mac.slice(0, 42)}${alphabet[last ^ 1]}`;
    expect(Buffer.from(respelled, 'base64url').equals(Buffer.from(mac, 'base64url'))).toBe(true);

    expect(
      await verifySessionCookie(fastify, REALM_A, `${kid}.${payload}.${respelled}`)
    ).toBeNull();
  });

  it('refuses a cookie whose kid names no key of the realm', async () => {
    const key = await currentKey(REALM_A);
    const unknown = signByHand(
      { kid: 'not-a-key-of-this-realm', secret: key.secret },
      SESSION_COOKIE_NAME,
      REALM_A,
      sessionPayload({ s: [SID], a: SID })
    );

    expect(await verifySessionCookie(fastify, REALM_A, unknown)).toBeNull();
  });

  it('refuses a cookie of another realm, even when both realms hold the same key', async () => {
    // Keys shared by mistake: one kid and one secret for both realms.
    const shared = Buffer.alloc(32, 0x5a);
    const sameKey = {
      signer: {
        getCookieSecrets: vi.fn(async () => ({
          current: { kid: 'shared-kid', secret: Buffer.from(shared) },
          previous: null,
        })),
      },
    };
    const value = await signSessionCookie(sameKey, { sid: SID, realmId: REALM_A });

    expect(await verifySessionCookie(sameKey, REALM_A, value)).toBe(SID);
    expect(await verifySessionCookie(sameKey, REALM_B, value)).toBeNull();
    // And with each realm's own key, as the signer hands them out.
    const own = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });
    expect(await verifySessionCookie(fastify, REALM_B, own)).toBeNull();
  });

  it('refuses another signed cookie of the same realm presented as the session cookie', async () => {
    const { reply, cookies } = captureReply();
    await setLoginCsrfCookie(fastify, reply, REALM_A, generateCsrfToken());

    expect(await verifySessionCookie(fastify, REALM_A, valueOf(cookies[0]))).toBeNull();
  });

  it('refuses a cookie in the format before #493, <sid>.<hmac>', async () => {
    const before = `${SID}.${createHmac('sha256', 'test-secret-at-least-32-characters-long-padding')
      .update(SID)
      .digest('base64url')}`;

    expect(await verifySessionCookie(fastify, REALM_A, before)).toBeNull();
  });

  it('returns null for missing, empty and malformed values without throwing', async () => {
    const value = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });
    const [kid, payload, mac] = value.split('.');

    for (const malformed of [
      undefined,
      null,
      '',
      'no-separator',
      'two.parts',
      `.${payload}.${mac}`,
      `${kid}..${mac}`,
      `${kid}.${payload}.`,
      `${kid}.${payload}.${mac}.extra`,
      `${kid}.${payload}.${mac.slice(0, -1)}`,
      `${kid}.${payload}.${mac}=`,
      `kid with space.${payload}.${mac}`,
    ]) {
      expect(await verifySessionCookie(fastify, REALM_A, malformed), String(malformed)).toBeNull();
    }
  });

  it('compares the MAC in constant time, also when it is wrong', async () => {
    const value = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });
    const [kid, payload, mac] = value.split('.');
    const wrong = `${kid}.${payload}.${mac.startsWith('A') ? 'B' : 'A'}${mac.slice(1)}`;
    timingSafeEqualSpy.mockClear();

    expect(await verifySessionCookie(fastify, REALM_A, value)).toBe(SID);
    expect(await verifySessionCookie(fastify, REALM_A, wrong)).toBeNull();

    expect(timingSafeEqualSpy).toHaveBeenCalledTimes(2);
    for (const [presented, expected] of timingSafeEqualSpy.mock.calls) {
      expect(Buffer.from(presented as Uint8Array)).toHaveLength(32);
      expect(Buffer.from(expected as Uint8Array)).toHaveLength(32);
    }
  });

  it('does not answer null for a signer it cannot reach: that is not an invalid cookie', async () => {
    const value = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });
    const down = createFakeCookieSigner();
    down.getCookieSecrets.mockRejectedValue(new TemporarilyUnavailableError(60));

    await expect(verifySessionCookie({ signer: down }, REALM_A, value)).rejects.toBeInstanceOf(
      TemporarilyUnavailableError
    );
    await expect(
      signSessionCookie({ signer: down }, { sid: SID, realmId: REALM_A })
    ).rejects.toBeInstanceOf(TemporarilyUnavailableError);
  });
});

describe('session cookie: key rotation (#493)', () => {
  it('verifies a cookie of the previous key after a rotation, and signs with the new one', async () => {
    const before = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });
    signer.rotate(REALM_A);
    // A process that reads the keys after the rotation.
    const after = { signer };
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 61_000);

    expect(await verifySessionCookie(after, REALM_A, before)).toBe(SID);
    const fresh = await signSessionCookie(after, { sid: SID, realmId: REALM_A });
    expect(fresh.split('.')[0]).toBe((await currentKey(REALM_A)).kid);
    expect(fresh.split('.')[0]).not.toBe(before.split('.')[0]);
  });

  it('refuses a cookie of the previous key once its retention ended', async () => {
    const before = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });
    signer.rotate(REALM_A);
    signer.endRetention(REALM_A);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 61_000);

    expect(await verifySessionCookie(fastify, REALM_A, before)).toBeNull();
  });

  it('refuses a cookie two rotations old: only the current and the previous key verify', async () => {
    const before = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });
    signer.rotate(REALM_A);
    signer.rotate(REALM_A);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 61_000);

    expect(await verifySessionCookie(fastify, REALM_A, before)).toBeNull();
  });
});

describe('session cookie: several sessions on one browser (SES-05)', () => {
  it('verifies a cookie that lists several sessions, and returns the active one', async () => {
    const key = await currentKey(REALM_A);
    const value = signByHand(
      key,
      SESSION_COOKIE_NAME,
      REALM_A,
      sessionPayload({ s: ['sid-1', 'sid-2'], a: 'sid-2' })
    );

    expect(await readSessionCookie(fastify, REALM_A, value)).toEqual({
      sessionIds: ['sid-1', 'sid-2'],
      activeSessionId: 'sid-2',
    });
    expect(await verifySessionCookie(fastify, REALM_A, value)).toBe('sid-2');
  });

  it.each([
    ['an active session the list lacks', { s: ['sid-1'], a: 'sid-2' }],
    ['an empty list', { s: [], a: 'sid-1' }],
    ['a repeated session', { s: ['sid-1', 'sid-1'], a: 'sid-1' }],
    ['a session that is not a string', { s: [1], a: 1 }],
    ['an unknown member', { s: ['sid-1'], a: 'sid-1', u: 'user-1' }],
    [
      'more sessions than a cookie holds',
      {
        s: Array.from({ length: SESSION_COOKIE_MAX_SESSIONS + 1 }, (_, i) => `sid-${i}`),
        a: 'sid-0',
      },
    ],
    ['a list that is not one', { s: 'sid-1', a: 'sid-1' }],
  ])('refuses a signed payload with %s', async (_label, payload) => {
    const key = await currentKey(REALM_A);
    const value = signByHand(key, SESSION_COOKIE_NAME, REALM_A, sessionPayload(payload));

    expect(await readSessionCookie(fastify, REALM_A, value)).toBeNull();
  });

  it('refuses a signed payload that is not JSON', async () => {
    const key = await currentKey(REALM_A);
    const value = signByHand(key, SESSION_COOKIE_NAME, REALM_A, 'bm90LWpzb24');

    expect(await readSessionCookie(fastify, REALM_A, value)).toBeNull();
  });
});

describe('session cookie: the Set-Cookie header (#493)', () => {
  it('sets __Host-, Path=/, HttpOnly, SameSite=Lax and no Domain', async () => {
    const { reply, cookies } = captureReply();
    await setSessionCookie(fastify, reply, {
      sid: SID,
      realmId: REALM_A,
      expiresAt: Date.now() + HOUR_MS,
    });

    expect(cookies).toHaveLength(1);
    const attributes = cookies[0].split('; ');
    expect(attributes[0].startsWith(`${SESSION_COOKIE_NAME}=`)).toBe(true);
    expect(SESSION_COOKIE_NAME.startsWith('__Host-')).toBe(true);
    expect(attributes).toEqual(expect.arrayContaining(['Path=/', 'HttpOnly', 'SameSite=Lax']));
    expect(cookies[0]).not.toMatch(/Domain=/i);
    expect(await verifySessionCookie(fastify, REALM_A, valueOf(cookies[0]))).toBe(SID);
  });

  it('omits Secure only when SESSION_COOKIE_SECURE is false (local-dev override)', async () => {
    // The module-level env mock sets SESSION_COOKIE_SECURE: false. The default
    // in the schema is true (#109): session-cookie-secure.test.ts covers it.
    const header = await sessionCookieHeader(fastify, {
      sid: SID,
      realmId: REALM_A,
      expiresAt: Date.now() + HOUR_MS,
    });
    expect(header).not.toContain('Secure');
  });

  it("sets Max-Age to the time left until the session's absolute end", async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const now = Date.UTC(2026, 9, 31, 12, 0, 0);
    vi.setSystemTime(now);

    const header = await sessionCookieHeader(fastify, {
      sid: SID,
      realmId: REALM_A,
      // 2 h 15 min and half a second: rounded down, never past the session.
      expiresAt: now + 8_100_500,
    });

    expect(header).toContain('Max-Age=8100');
    expect(header).not.toContain('Max-Age=3600');
  });

  it('sets Max-Age=0, which deletes the cookie, for a session already past its end', async () => {
    const header = await sessionCookieHeader(fastify, {
      sid: SID,
      realmId: REALM_A,
      expiresAt: Date.now() - 1_000,
    });

    expect(header).toContain('Max-Age=0');
  });

  it('clearSessionCookie emits Max-Age=0 with the same attributes', () => {
    const { reply, cookies } = captureReply();
    clearSessionCookie(reply);

    expect(cookies[0]).toBe(`${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
  });
});

describe('login-CSRF cookie (#493)', () => {
  it('is signed with the realm cookie key and verifies only in its realm', async () => {
    const token = generateCsrfToken();
    const { reply, cookies } = captureReply();
    await setLoginCsrfCookie(fastify, reply, REALM_A, token);

    const value = valueOf(cookies[0]);
    expect(value.split('.')).toEqual([(await currentKey(REALM_A)).kid, token, expect.any(String)]);
    expect(cookies[0]).toContain(`${LOGIN_CSRF_COOKIE_NAME}=`);
    expect(cookies[0]).toContain('Max-Age=3600');
    expect(cookies[0]).not.toMatch(/Domain=/i);
    expect(await verifyLoginCsrfCookie(fastify, REALM_A, value)).toBe(token);
    expect(await verifyLoginCsrfCookie(fastify, REALM_B, value)).toBeNull();
  });

  it('refuses a session cookie presented as the login-CSRF cookie', async () => {
    const value = await signSessionCookie(fastify, { sid: SID, realmId: REALM_A });

    expect(await verifyLoginCsrfCookie(fastify, REALM_A, value)).toBeNull();
  });

  it('refuses a tampered token', async () => {
    const { reply, cookies } = captureReply();
    await setLoginCsrfCookie(fastify, reply, REALM_A, generateCsrfToken());
    const [kid, , mac] = valueOf(cookies[0]).split('.');

    expect(await verifyLoginCsrfCookie(fastify, REALM_A, `${kid}.forged.${mac}`)).toBeNull();
  });

  it('clearLoginCsrfCookie emits Max-Age=0', () => {
    const { reply, cookies } = captureReply();
    clearLoginCsrfCookie(reply);

    expect(cookies[0]).toBe(
      `${LOGIN_CSRF_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
    );
  });
});

describe('wallet-flow cookie (#493)', () => {
  const binding = (handle: string) => ({
    handle,
    binder: `binder-${handle}`,
    expiresAt: Date.now() + 300_000,
  });

  it('is signed with the realm cookie key and read back only in its realm', async () => {
    const { reply, cookies } = captureReply();
    await setWalletFlowCookie(fastify, reply, REALM_A, [binding('h1'), binding('h2')]);

    const value = valueOf(cookies[0]);
    expect(value.split('.')[0]).toBe((await currentKey(REALM_A)).kid);
    expect(cookies[0]).toContain(`${WALLET_FLOW_COOKIE_NAME}=`);
    expect(cookies[0]).not.toMatch(/Domain=/i);
    expect(
      (await readWalletFlowBindings(fastify, REALM_A, value)).map((entry) => entry.handle)
    ).toEqual(['h1', 'h2']);
    expect(await findWalletFlowBinder(fastify, REALM_A, value, 'h2')).toBe('binder-h2');
    expect(await readWalletFlowBindings(fastify, REALM_B, value)).toEqual([]);
    expect(await findWalletFlowBinder(fastify, REALM_B, value, 'h2')).toBeNull();
  });

  it('reads nothing from a tampered cookie', async () => {
    const { reply, cookies } = captureReply();
    await setWalletFlowCookie(fastify, reply, REALM_A, [binding('h1')]);
    const [kid, , mac] = valueOf(cookies[0]).split('.');
    const forged = `h1:attacker:${Date.now() + 300_000}`;

    expect(await readWalletFlowBindings(fastify, REALM_A, `${kid}.${forged}.${mac}`)).toEqual([]);
  });

  it('clears the cookie when no binding is live', async () => {
    const { reply, cookies } = captureReply();
    await setWalletFlowCookie(fastify, reply, REALM_A, [
      { handle: 'old', binder: 'b', expiresAt: Date.now() - 1 },
    ]);

    expect(cookies[0]).toBe(
      `${WALLET_FLOW_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
    );
  });

  it('clearWalletFlowCookie emits Max-Age=0', () => {
    const { reply, cookies } = captureReply();
    clearWalletFlowCookie(reply);

    expect(cookies[0]).toContain('Max-Age=0');
  });
});

describe('readCookie', () => {
  it('returns the correct cookie value', () => {
    const request = {
      headers: { cookie: 'foo=bar; __Host-qauth_session=signed; baz=qux' },
    } as never;
    expect(readCookie(request, SESSION_COOKIE_NAME)).toBe('signed');
    expect(readCookie(request, 'foo')).toBe('bar');
    expect(readCookie(request, 'missing')).toBeUndefined();
  });

  it('does not read a name that only becomes a __Host- name after trim()', () => {
    // A browser applies the __Host- rules to names that START with the prefix,
    // so a sibling host may set this one; a longer Path sorts it first.
    const planted = ` ${SESSION_COOKIE_NAME}=planted`;
    expect(
      readCookie(
        { headers: { cookie: `${planted}; ${SESSION_COOKIE_NAME}=genuine` } } as never,
        SESSION_COOKIE_NAME
      )
    ).toBe('genuine');
    expect(
      readCookie({ headers: { cookie: planted } } as never, SESSION_COOKIE_NAME)
    ).toBeUndefined();
    // SP and HTAB are what a browser strips too.
    expect(
      readCookie(
        { headers: { cookie: `a=b;\t ${SESSION_COOKIE_NAME}=v \t` } } as never,
        SESSION_COOKIE_NAME
      )
    ).toBe('v');
  });
});

describe('csrfTokensEqual', () => {
  it('is timing-safe and length-aware', () => {
    const t = generateCsrfToken();
    expect(csrfTokensEqual(t, t)).toBe(true);
    expect(csrfTokensEqual(t, t + 'x')).toBe(false);
    expect(csrfTokensEqual(undefined, t)).toBe(false);
    expect(csrfTokensEqual(t, undefined)).toBe(false);
  });
});
