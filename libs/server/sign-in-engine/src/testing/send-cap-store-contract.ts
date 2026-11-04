import { randomUUID } from 'node:crypto';

import { describe, expect, it, type TestContext } from 'vitest';

import {
  SEND_CAP_POLICY,
  type SendCapDecision,
  type SendCapRequest,
  type SendCapStore,
} from '../lib/send-caps';
import { mailPassHash } from './memory-send-caps';

/**
 * TEST SUPPORT — the rules every {@link SendCapStore} keeps (PRO-14, #637;
 * ADR-017 Decision 5), as one suite: the memory store runs it as a unit test,
 * the auth server's Redis script as an integration test, so the two cannot
 * drift. Each case works in a realm of its own, so cases share no counter.
 * The store must use {@link SEND_CAP_POLICY} and a clock the harness moves.
 */
export interface SendCapStoreHarness {
  readonly store: SendCapStore;
  /** Move the store's clock forward by `ms`. */
  advance(ms: number): void;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const P = SEND_CAP_POLICY;

/** A distinct end-user IP HMAC per index. */
const ip = (index: number) => `ip-${index}`;

/**
 * Run the contract against the harness `harness` builds; a harness of
 * `undefined` skips each case (no Docker locally).
 */
export function describeSendCapStore(
  name: string,
  harness: () => Promise<SendCapStoreHarness | undefined>
): void {
  describe(`${name}: the send caps of ADR-017 Decision 5 (#637)`, () => {
    /** The harness, and a request builder for a realm of the case's own. */
    async function setup(context: TestContext) {
      const built = await harness();
      if (built === undefined) {
        context.skip();
        throw new Error('skipped');
      }
      const realmId = randomUUID();
      const request = (overrides: Partial<SendCapRequest> = {}): SendCapRequest => ({
        realmId,
        addressHmac: 'address-victim',
        knownIp: false,
        afterFirstFactor: false,
        ...overrides,
      });
      const send = (overrides: Partial<SendCapRequest> = {}) =>
        built.store.reserve(request(overrides));
      return { ...built, realmId, request, send };
    }

    /** `count` sends of the address, each from its own IP, so no IP or address-IP tier fills. */
    async function spread(
      send: (overrides?: Partial<SendCapRequest>) => Promise<SendCapDecision>,
      count: number,
      from = 0,
      overrides: Partial<SendCapRequest> = {}
    ) {
      const decisions: SendCapDecision[] = [];
      for (let i = 0; i < count; i += 1) {
        decisions.push(await send({ endUserIpHmac: ip(from + i), ...overrides }));
      }
      return decisions;
    }

    it('drops the 4th mail to an address from one IP in 15 minutes quietly, and sends again after', async (context) => {
      const { send, advance } = await setup(context);
      for (let i = 0; i < P.addressIpShort.limit; i += 1) {
        expect(await send({ endUserIpHmac: ip(1) })).toEqual({ kind: 'send', passSpent: false });
      }

      expect(await send({ endUserIpHmac: ip(1) })).toEqual({ kind: 'quiet' });
      // Another IP is not held by this tier.
      expect(await send({ endUserIpHmac: ip(2) })).toEqual({ kind: 'send', passSpent: false });

      advance(P.addressIpShort.windowMs);
      expect(await send({ endUserIpHmac: ip(1) })).toEqual({ kind: 'send', passSpent: false });
    });

    it('drops the 11th mail to an address from one IP in 24 hours quietly', async (context) => {
      const { send, advance } = await setup(context);
      // Spaced so neither the short window nor the per-IP hour fills first.
      for (let i = 0; i < P.addressIpLong.limit; i += 1) {
        expect((await send({ endUserIpHmac: ip(1) })).kind).toBe('send');
        advance(7 * MINUTE);
      }

      expect(await send({ endUserIpHmac: ip(1) })).toEqual({ kind: 'quiet' });
    });

    it('counts a quietly dropped mail on no other tier', async (context) => {
      const { send } = await setup(context);
      for (let i = 0; i < P.addressIpShort.limit; i += 1) await send({ endUserIpHmac: ip(1) });
      for (let i = 0; i < 20; i += 1) {
        expect(await send({ endUserIpHmac: ip(1) })).toEqual({ kind: 'quiet' });
      }

      // The ceiling counted 3, not 23: 27 more go out.
      const later = await spread(send, P.ceiling.limit - P.addressIpShort.limit, 10);
      expect(later.every((decision) => decision.kind === 'send')).toBe(true);
    });

    it('refuses every send past the ceiling with 429, alerts once, and frees as the window slides', async (context) => {
      const { send, advance } = await setup(context);
      const sent = await spread(send, P.ceiling.limit);
      expect(sent.every((decision) => decision.kind === 'send')).toBe(true);

      const first = await send({ endUserIpHmac: ip(100) });
      expect(first).toEqual({
        kind: 'refused',
        tier: 'ceiling',
        retryAfterMs: P.ceiling.windowMs,
        alert: true,
      });
      const second = await send({ endUserIpHmac: ip(101) });
      expect(second).toMatchObject({ kind: 'refused', tier: 'ceiling', alert: false });

      // The oldest send leaves the window: one more goes out.
      advance(P.ceiling.windowMs);
      expect((await send({ endUserIpHmac: ip(102) })).kind).toBe('send');
    });

    it('answers the ceiling the same whatever the address, and from any IP', async (context) => {
      const { send } = await setup(context);
      await spread(send, P.ceiling.limit, 0, { addressHmac: 'address-unknown' });
      await spread(send, P.ceiling.limit, 0, { addressHmac: 'address-known' });

      const unknown = await send({ addressHmac: 'address-unknown', endUserIpHmac: ip(50) });
      const known = await send({ addressHmac: 'address-known', endUserIpHmac: ip(50) });
      expect(unknown).toEqual(known);
      expect(unknown).toMatchObject({ kind: 'refused', tier: 'ceiling' });
      // A request with no IP meets the ceiling too.
      expect(await send({ addressHmac: 'address-known' })).toMatchObject({ tier: 'ceiling' });
    });

    it('alerts once per address per notice interval', async (context) => {
      const { send, advance } = await setup(context);
      await spread(send, P.ceiling.limit);
      expect(await send()).toMatchObject({ tier: 'ceiling', alert: true });
      advance(P.noticeIntervalMs - 1);
      expect(await send()).toMatchObject({ tier: 'ceiling', alert: false });

      // A day on, the window has emptied; filled again, the ceiling alerts again.
      advance(1);
      await spread(send, P.ceiling.limit, 1_000);
      expect(await send()).toMatchObject({ tier: 'ceiling', alert: true });
    });

    it('lets a known IP of a verified account past every per-address tier, uncounted', async (context) => {
      const { send } = await setup(context);
      await spread(send, P.ceiling.limit);
      expect(await send({ endUserIpHmac: ip(7) })).toMatchObject({ tier: 'ceiling' });

      for (let i = 0; i < P.addressIpShort.limit + 2; i += 1) {
        expect(await send({ endUserIpHmac: ip(7), knownIp: true })).toEqual({
          kind: 'send',
          passSpent: false,
        });
      }
    });

    it('still holds a known IP to the per-IP cap', async (context) => {
      const { send } = await setup(context);
      for (let i = 0; i < P.endUserIp.limit; i += 1) {
        expect(
          (await send({ addressHmac: `address-${i}`, endUserIpHmac: ip(1), knownIp: true })).kind
        ).toBe('send');
      }

      expect(await send({ endUserIpHmac: ip(1), knownIp: true })).toEqual({
        kind: 'refused',
        tier: 'end_user_ip',
        retryAfterMs: P.endUserIp.windowMs,
        alert: false,
      });
    });

    it('refuses the 11th send from one IP in an hour, whatever the address', async (context) => {
      const { send, advance } = await setup(context);
      for (let i = 0; i < P.endUserIp.limit; i += 1) {
        expect((await send({ addressHmac: `address-${i}`, endUserIpHmac: ip(1) })).kind).toBe(
          'send'
        );
        advance(MINUTE);
      }

      expect(await send({ addressHmac: 'address-new', endUserIpHmac: ip(1) })).toEqual({
        kind: 'refused',
        tier: 'end_user_ip',
        retryAfterMs: P.endUserIp.windowMs - P.endUserIp.limit * MINUTE,
        alert: false,
      });
    });

    it('lets a pass bound to the address take one start past the ceiling, and spends it', async (context) => {
      const { store, realmId, send } = await setup(context);
      await spread(send, P.ceiling.limit);
      const pass = await store.mintPass({ realmId, addressHmac: 'address-victim', flow: 'reset' });
      const passHash = mailPassHash(pass);

      expect(await send({ endUserIpHmac: ip(60), passHash })).toEqual({
        kind: 'send',
        passSpent: true,
      });
      expect(await store.peekPass(realmId, pass)).toBeUndefined();
      // Spent: the next start meets the ceiling again.
      expect(await send({ endUserIpHmac: ip(60), passHash })).toMatchObject({ tier: 'ceiling' });
    });

    it('takes a pass past the quiet tier too', async (context) => {
      const { store, realmId, send } = await setup(context);
      for (let i = 0; i < P.addressIpShort.limit; i += 1) await send({ endUserIpHmac: ip(1) });
      const pass = await store.mintPass({ realmId, addressHmac: 'address-victim', flow: 'reset' });

      expect(await send({ endUserIpHmac: ip(1), passHash: mailPassHash(pass) })).toEqual({
        kind: 'send',
        passSpent: true,
      });
    });

    it('never spends a pass on a start a per-IP cap refuses', async (context) => {
      const { store, realmId, send } = await setup(context);
      for (let i = 0; i < P.endUserIp.limit; i += 1) {
        await send({ addressHmac: `address-${i}`, endUserIpHmac: ip(1) });
      }
      const pass = await store.mintPass({ realmId, addressHmac: 'address-victim', flow: 'reset' });

      expect(await send({ endUserIpHmac: ip(1), passHash: mailPassHash(pass) })).toMatchObject({
        tier: 'end_user_ip',
      });
      expect(await store.peekPass(realmId, pass)).toEqual({
        passHash: mailPassHash(pass),
        addressHmac: 'address-victim',
        flow: 'reset',
      });
    });

    it('gives a pass no power over another address, and leaves it unspent', async (context) => {
      const { store, realmId, send } = await setup(context);
      await spread(send, P.ceiling.limit, 0, { addressHmac: 'address-other' });
      const pass = await store.mintPass({ realmId, addressHmac: 'address-victim', flow: 'reset' });

      expect(
        await send({
          addressHmac: 'address-other',
          endUserIpHmac: ip(70),
          passHash: mailPassHash(pass),
        })
      ).toMatchObject({ tier: 'ceiling' });
      expect(await store.peekPass(realmId, pass)).toBeDefined();
    });

    it('keeps a pass 24 hours, and peeking never spends it', async (context) => {
      const { store, realmId, advance } = await setup(context);
      const pass = await store.mintPass({
        realmId,
        addressHmac: 'address-victim',
        flow: 'register',
      });

      for (let i = 0; i < 3; i += 1) {
        expect(await store.peekPass(realmId, pass)).toEqual({
          passHash: mailPassHash(pass),
          addressHmac: 'address-victim',
          flow: 'register',
        });
      }
      expect(await store.peekPass(randomUUID(), pass)).toBeUndefined();
      advance(P.passTtlMs);
      expect(await store.peekPass(realmId, pass)).toBeUndefined();
    });

    it('mints a 256-bit pass, a new one each time', async (context) => {
      const { store, realmId } = await setup(context);
      const a = await store.mintPass({ realmId, addressHmac: 'address-victim', flow: 'reset' });
      const b = await store.mintPass({ realmId, addressHmac: 'address-victim', flow: 'reset' });

      expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(a).not.toBe(b);
    });

    it('holds a code after a correct first factor to its own cap, not the ceiling', async (context) => {
      const { send } = await setup(context);
      await spread(send, P.ceiling.limit);
      const after = await spread(send, P.afterFirstFactor.limit, 200, { afterFirstFactor: true });
      expect(after.every((decision) => decision.kind === 'send')).toBe(true);

      expect(await send({ endUserIpHmac: ip(300), afterFirstFactor: true })).toMatchObject({
        kind: 'refused',
        tier: 'after_first_factor',
        alert: false,
      });
    });

    it('refuses the 11th send to an address through one FiPA client in 24 hours', async (context) => {
      const { send } = await setup(context);
      const sent = await spread(send, P.addressClient.limit, 0, { clientKey: 'client-a' });
      expect(sent.every((decision) => decision.kind === 'send')).toBe(true);

      expect(await send({ endUserIpHmac: ip(99), clientKey: 'client-a' })).toMatchObject({
        kind: 'refused',
        tier: 'address_client',
      });
      expect((await send({ endUserIpHmac: ip(99), clientKey: 'client-b' })).kind).toBe('send');
    });

    it('caps a FiPA client whatever the address', async (context) => {
      const { send } = await setup(context);
      for (let i = 0; i < P.client.limit; i += 1) {
        const decision = await send({ addressHmac: `address-${i}`, clientKey: 'client-a' });
        if (decision.kind !== 'send') throw new Error(`send ${i}: ${JSON.stringify(decision)}`);
      }

      expect(await send({ addressHmac: 'address-new', clientKey: 'client-a' })).toMatchObject({
        kind: 'refused',
        tier: 'client',
      });
    });

    it('gives each notice once per address per interval', async (context) => {
      const { store, realmId, advance } = await setup(context);
      const claim = (kind: 'send_ceiling' | 'password_disabled', addressHmac = 'address-victim') =>
        store.claimNotice({ realmId, addressHmac, kind });

      expect(await claim('send_ceiling')).toBe(true);
      expect(await claim('send_ceiling')).toBe(false);
      expect(await claim('password_disabled')).toBe(true);
      expect(await claim('send_ceiling', 'address-other')).toBe(true);
      advance(P.noticeIntervalMs - 1);
      expect(await claim('send_ceiling')).toBe(false);
      advance(1);
      expect(await claim('send_ceiling')).toBe(true);
    });

    it('keeps the realms apart', async (context) => {
      const { send, request, store } = await setup(context);
      await spread(send, P.ceiling.limit);

      expect(
        (await store.reserve({ ...request({ endUserIpHmac: ip(1) }), realmId: randomUUID() })).kind
      ).toBe('send');
    });

    it('waits a day for the oldest send of a full day to leave', async (context) => {
      const { send, advance } = await setup(context);
      await spread(send, P.ceiling.limit - 1);
      advance(HOUR);
      await send({ endUserIpHmac: ip(500) });

      expect(await send({ endUserIpHmac: ip(501) })).toMatchObject({
        tier: 'ceiling',
        retryAfterMs: DAY - HOUR,
      });
    });
  });
}
