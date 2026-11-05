import { randomUUID } from 'node:crypto';

import { describe, expect, it, type TestContext } from 'vitest';

import {
  type CredentialRoundKeys,
  type CredentialRoundOutcome,
  ROUND_LIMIT_POLICY,
  type RoundEnvironment,
  type RoundLimitAlert,
  type RoundLimitDecision,
  type RoundLimitKeys,
  type RoundLimitStore,
} from '../lib/round-limits';

/**
 * TEST SUPPORT — the rules every {@link RoundLimitStore} keeps (PRO-13, #636;
 * ADR-017 Decision 7), as one suite: the memory store runs it as a unit test,
 * the auth server's Redis script as an integration test, so the two cannot
 * drift. Each case works in a realm of its own, so cases share no counter.
 * The store must use {@link ROUND_LIMIT_POLICY} and a clock the harness moves.
 */
export interface RoundLimitStoreHarness {
  readonly store: RoundLimitStore;
  /** Move the store's clock forward by `ms`. */
  advance(ms: number): void;
}

const SECOND = 1_000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const P = ROUND_LIMIT_POLICY;

/**
 * Run the contract against the harness `harness` builds; a harness of
 * `undefined` skips each case (no Docker locally).
 */
export function describeRoundLimitStore(
  name: string,
  harness: () => Promise<RoundLimitStoreHarness | undefined>
): void {
  describe(`${name}: the round limits of ADR-017 Decision 7 (#636)`, () => {
    async function setup(context: TestContext) {
      const built = await harness();
      if (built === undefined) {
        context.skip();
        throw new Error('skipped');
      }
      const realmId = randomUUID();
      let next = 0;
      const keys = (overrides: Partial<RoundLimitKeys> = {}): RoundLimitKeys => ({
        realmId,
        environment: 'production',
        ...overrides,
      });
      /** Reserve one credential round; settle it with `outcome` when it is admitted. */
      const credential = async (
        outcome: CredentialRoundOutcome,
        overrides: Partial<CredentialRoundKeys> & { readonly accountKey?: string } = {}
      ): Promise<{
        readonly decision: RoundLimitDecision;
        readonly alerts: readonly RoundLimitAlert[];
      }> => {
        next += 1;
        const { accountKey, ...rest } = overrides;
        const round: CredentialRoundKeys = {
          ...keys(),
          reservation: `reservation-${String(next).padStart(8, '0')}`,
          ...rest,
        };
        const decision = await built.store.reserveCredential(round);
        if (decision.kind !== 'admitted') return { decision, alerts: [] };
        const alerts = await built.store.settleCredential({
          ...round,
          outcome,
          ...(accountKey === undefined ? {} : { accountKey }),
        });
        return { decision, alerts };
      };
      return { ...built, realmId, keys, credential };
    }

    /** An IP's keys: its HMAC and its bucket's. */
    const ip = (index: number, bucket = 'bucket-a') => ({
      endUserIpHmac: `ip-${index}`,
      ipBucketHmac: bucket,
    });

    it('admits up to 9 failed rounds of an IP with no delay, and delays the next one 30 s from the 10th', async (context) => {
      const { credential, advance } = await setup(context);
      for (let i = 0; i < P.endUserIp.softFailures; i += 1) {
        expect((await credential('failure', ip(1))).decision.kind).toBe('admitted');
      }
      const early = await credential('failure', ip(1));
      expect(early.decision).toMatchObject({
        kind: 'refused',
        limit: 'end_user_ip_delay',
        retryAfterMs: P.endUserIp.delayMs,
      });
      // Another IP of the bucket is not delayed by this one's failures.
      expect((await credential('failure', ip(2))).decision.kind).toBe('admitted');
      advance(P.endUserIp.delayMs);
      expect((await credential('failure', ip(1))).decision.kind).toBe('admitted');
      // Each round while it holds starts the delay again.
      expect((await credential('failure', ip(1))).decision).toMatchObject({
        kind: 'refused',
        limit: 'end_user_ip_delay',
      });
    });

    it('takes a success and a withdrawn round back from the IP’s failures', async (context) => {
      const { credential } = await setup(context);
      for (let i = 0; i < P.endUserIp.softFailures - 1; i += 1) {
        await credential('failure', ip(1));
      }
      for (let i = 0; i < 5; i += 1) {
        expect((await credential('success', { ...ip(1), accountKey: 'owner' })).decision.kind).toBe(
          'admitted'
        );
        expect((await credential('withdrawn', ip(1))).decision.kind).toBe('admitted');
      }
      // Still 9 failures: no delay yet.
      expect((await credential('failure', ip(1))).decision.kind).toBe('admitted');
      expect((await credential('failure', ip(1))).decision).toMatchObject({
        kind: 'refused',
        limit: 'end_user_ip_delay',
      });
    });

    it('refuses every round of an IP for 15 minutes once 30 of its rounds failed, and alerts once', async (context) => {
      const { credential, store, keys, advance } = await setup(context);
      const alerts: RoundLimitAlert[] = [];
      for (let i = 0; i < P.endUserIp.hardFailures; i += 1) {
        const round = await credential('failure', ip(1));
        expect(round.decision.kind).toBe('admitted');
        alerts.push(...round.alerts);
        // Past the 10th, one round per delay.
        advance(P.endUserIp.delayMs);
      }
      expect(alerts).toEqual(['end_user_ip_blocked']);
      const blocked = await credential('failure', ip(1));
      expect(blocked.decision).toMatchObject({ kind: 'refused', limit: 'end_user_ip' });
      const retry = blocked.decision.kind === 'refused' ? blocked.decision.retryAfterMs : 0;
      expect(retry).toBeGreaterThan(P.endUserIp.blockMs - P.endUserIp.delayMs - SECOND);
      expect(retry).toBeLessThanOrEqual(P.endUserIp.blockMs);
      // Every round of it, not only the credential ones.
      expect(await store.admitRound(keys(ip(1)))).toMatchObject({
        kind: 'refused',
        limit: 'end_user_ip',
      });
      expect((await store.admitRound(keys(ip(2)))).kind).toBe('admitted');
      advance(retry);
      expect((await store.admitRound(keys(ip(1)))).kind).toBe('admitted');
    });

    it('never lets parallel reservations of one IP past its hard limit', async (context) => {
      const { store, keys } = await setup(context);
      const decisions = await Promise.all(
        Array.from({ length: P.endUserIp.hardFailures + 20 }, (_, index) =>
          store.reserveCredential({
            ...keys(ip(1)),
            reservation: `parallel-${String(index).padStart(8, '0')}`,
          })
        )
      );
      const admitted = decisions.filter((decision) => decision.kind === 'admitted');
      // The soft threshold's delay admits one round once 10 are held.
      expect(admitted.length).toBe(P.endUserIp.softFailures + 1);
    });

    it('delays the whole bucket and alerts once it fails for more than 20 distinct identifiers in 15 minutes', async (context) => {
      const { credential, advance } = await setup(context);
      const alerts: RoundLimitAlert[] = [];
      // The same identifier again and again counts once.
      for (let i = 0; i < 5; i += 1) {
        await credential('failure', { ...ip(100), identifierHmac: 'id-0' });
      }
      for (let i = 1; i <= P.ipBucket.maxIdentifiers - 1; i += 1) {
        const round = await credential('failure', { ...ip(i), identifierHmac: `id-${i}` });
        expect(round.decision.kind).toBe('admitted');
        alerts.push(...round.alerts);
      }
      // 20 identifiers: no delay. A success takes its identifier back.
      expect(
        (
          await credential('success', {
            ...ip(50),
            identifierHmac: 'id-ok',
            accountKey: 'someone',
          })
        ).decision.kind
      ).toBe('admitted');
      expect(alerts).toEqual([]);
      const crossing = await credential('failure', { ...ip(51), identifierHmac: 'id-21' });
      expect(crossing.decision.kind).toBe('admitted');
      expect(crossing.alerts).toEqual(['ip_bucket_identifiers']);
      // Any IP of the bucket now waits; another bucket does not.
      expect((await credential('failure', { ...ip(52), identifierHmac: 'id-22' })).decision).toMatchObject({
        kind: 'refused',
        limit: 'ip_bucket_delay',
        retryAfterMs: P.ipBucket.delayMs,
      });
      expect(
        (await credential('failure', { ...ip(53, 'bucket-b'), identifierHmac: 'id-22' })).decision
          .kind
      ).toBe('admitted');
      advance(P.ipBucket.delayMs);
      const later = await credential('failure', { ...ip(54), identifierHmac: 'id-23' });
      expect(later.decision.kind).toBe('admitted');
      // Alerted once per window.
      expect(later.alerts).toEqual([]);
      // The identifiers age out of the window.
      advance(P.ipBucket.windowMs);
      expect((await credential('failure', { ...ip(55), identifierHmac: 'id-24' })).decision.kind).toBe(
        'admitted'
      );
      expect((await credential('failure', { ...ip(56), identifierHmac: 'id-25' })).decision.kind).toBe(
        'admitted'
      );
    });

    it('counts sign-ins to one account once toward a client’s failure ratio', async (context) => {
      const { credential } = await setup(context);
      const client = { clientKey: 'native-app' };
      // 199 failures and 199 sign-ins to one account: counted per round, the
      // ratio would be 50 %, not above it; counted once, 199 of 200.
      for (let i = 0; i < P.client.ratioMinRounds - 1; i += 1) {
        expect((await credential('success', { ...client, accountKey: 'owned' })).decision.kind).toBe(
          'admitted'
        );
      }
      const alerts: RoundLimitAlert[] = [];
      for (let i = 0; i < P.client.ratioMinRounds - 1; i += 1) {
        const round = await credential('failure', client);
        expect(round.decision.kind).toBe('admitted');
        alerts.push(...round.alerts);
      }
      expect(alerts).toEqual(['client_failure_ratio']);
      expect((await credential('failure', client)).decision).toMatchObject({
        kind: 'refused',
        limit: 'client_delay',
        retryAfterMs: P.client.delayMs,
      });
    });

    it('keeps a client under its ratio while its sign-ins are to many accounts', async (context) => {
      const { credential } = await setup(context);
      const client = { clientKey: 'native-app' };
      for (let i = 0; i < P.client.ratioMinRounds; i += 1) {
        await credential('success', { ...client, accountKey: `account-${i}` });
        expect((await credential('failure', client)).alerts).toEqual([]);
      }
      expect((await credential('failure', client)).decision.kind).toBe('admitted');
    });

    it('fires the client’s failure budget at any ratio, and alerts once', async (context) => {
      const { credential, advance } = await setup(context);
      const client = { clientKey: 'native-app' };
      for (let i = 0; i < 3 * P.client.failureBudget; i += 1) {
        await credential('success', { ...client, accountKey: `account-${i}` });
      }
      const alerts: RoundLimitAlert[] = [];
      for (let i = 0; i < P.client.failureBudget; i += 1) {
        const round = await credential('failure', client);
        expect(round.decision.kind).toBe('admitted');
        alerts.push(...round.alerts);
      }
      expect(alerts).toEqual([]);
      const crossing = await credential('failure', client);
      expect(crossing.alerts).toEqual(['client_failure_budget']);
      expect((await credential('failure', client)).decision).toMatchObject({
        kind: 'refused',
        limit: 'client_delay',
      });
      advance(P.client.delayMs);
      const next = await credential('failure', client);
      expect(next.decision.kind).toBe('admitted');
      expect(next.alerts).toEqual([]);
      // Another client is not delayed.
      expect((await credential('failure', { clientKey: 'other-app' })).decision.kind).toBe(
        'admitted'
      );
    });

    it('refuses a client’s rounds above its rounds a minute, alerts once, and counts no refused round', async (context) => {
      const { store, keys, advance } = await setup(context);
      const client = keys({ clientKey: 'native-app' });
      for (let i = 0; i < P.client.maxRounds; i += 1) {
        expect((await store.admitRound(client)).kind).toBe('admitted');
      }
      expect(await store.admitRound(client)).toMatchObject({
        kind: 'refused',
        limit: 'client_rounds',
        alerts: ['client_rounds'],
      });
      expect(await store.admitRound(client)).toMatchObject({
        kind: 'refused',
        limit: 'client_rounds',
        alerts: [],
      });
      // A round without the client row is never counted on it.
      expect((await store.admitRound(keys())).kind).toBe('admitted');
      advance(P.client.maxRoundsWindowMs);
      expect((await store.admitRound(client)).kind).toBe('admitted');
    });

    it('refuses the fourth registration start from one IP in an hour', async (context) => {
      const { store, keys, advance } = await setup(context);
      for (let i = 0; i < P.registrationStarts.endUserIp.limit; i += 1) {
        expect((await store.reserveRegistrationStart(keys(ip(1)))).kind).toBe('admitted');
      }
      const fourth = await store.reserveRegistrationStart(keys(ip(1)));
      expect(fourth).toMatchObject({ kind: 'refused', limit: 'registration_end_user_ip' });
      expect(fourth.kind === 'refused' && fourth.retryAfterMs).toBe(HOUR);
      expect((await store.reserveRegistrationStart(keys(ip(2)))).kind).toBe('admitted');
      advance(HOUR);
      expect((await store.reserveRegistrationStart(keys(ip(1)))).kind).toBe('admitted');
    });

    it('caps a client’s registration starts, whatever the IP', async (context) => {
      const { store, keys } = await setup(context);
      for (let i = 0; i < P.registrationStarts.client.limit; i += 1) {
        const start = await store.reserveRegistrationStart(
          keys({ ...ip(i), clientKey: 'native-app' })
        );
        expect(start.kind).toBe('admitted');
      }
      expect(
        await store.reserveRegistrationStart(keys({ ...ip(5_000), clientKey: 'native-app' }))
      ).toMatchObject({ kind: 'refused', limit: 'registration_client' });
      // A start the client cap refused counts on no IP.
      for (let i = 0; i < P.registrationStarts.endUserIp.limit; i += 1) {
        expect((await store.reserveRegistrationStart(keys(ip(5_000)))).kind).toBe('admitted');
      }
    });

    it('relaxes every limit in development, and keeps production values in staging', async (context) => {
      const { credential, store, keys } = await setup(context);
      const as = (environment: RoundEnvironment) => ({ environment });
      for (let i = 0; i < P.endUserIp.hardFailures; i += 1) {
        expect((await credential('failure', { ...ip(1), ...as('development') })).decision.kind).toBe(
          'admitted'
        );
      }
      for (let i = 0; i < P.registrationStarts.endUserIp.limit + 1; i += 1) {
        expect(
          (await store.reserveRegistrationStart(keys({ ...ip(1), ...as('development') }))).kind
        ).toBe('admitted');
      }
      for (let i = 0; i < P.endUserIp.softFailures; i += 1) {
        expect((await credential('failure', { ...ip(2), ...as('staging') })).decision.kind).toBe(
          'admitted'
        );
      }
      expect((await credential('failure', { ...ip(2), ...as('staging') })).decision).toMatchObject({
        kind: 'refused',
        limit: 'end_user_ip_delay',
      });
    });

    it('counts nothing for a round without an address or a client row', async (context) => {
      const { credential } = await setup(context);
      for (let i = 0; i < P.endUserIp.hardFailures + 1; i += 1) {
        expect((await credential('failure')).decision.kind).toBe('admitted');
      }
    });
  });
}
