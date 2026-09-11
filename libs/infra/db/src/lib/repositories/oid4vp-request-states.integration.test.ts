/**
 * Real-Postgres integration tests for the OID4VP request-state store (#233).
 *
 * The property under test cannot be proved anywhere else: single-use redemption
 * has to hold under GENUINE concurrency, against a real MVCC engine, with real
 * row locks. A mocked client can show which statement is emitted (the sibling
 * unit suite does exactly that); only a database can show that two simultaneous
 * posts carrying the same `state` produce exactly one winner.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { Oid4vpRequestStatesRepository } from '../../types';
import { oid4vpRequestStates, realms } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createOid4vpRequestStatesRepository } from './oid4vp-request-states.repository';

describe('oid4vp_request_states integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let requestStates: Oid4vpRequestStatesRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    requestStates = createOid4vpRequestStatesRepository(ctx.database.db);
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  async function seedRealm(): Promise<string> {
    if (!ctx) throw new Error('no ctx');
    const [realm] = await ctx.database.db
      .insert(realms)
      .values({ name: `realm-${Math.random().toString(36).slice(2)}` })
      .returning({ id: realms.id });
    return realm.id;
  }

  async function seedState(overrides: { stateHash?: string; expiresAt?: number } = {}) {
    const realmId = await seedRealm();

    return requestStates.create({
      realmId,
      stateHash: overrides.stateHash ?? `hash-${Math.random().toString(36).slice(2)}`,
      nonce: 'nonce-value',
      verifierProfile: 'oid4vp-1.0-base',
      responseMode: 'direct_post',
      dcqlQuery: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] },
      expiresAt: overrides.expiresAt ?? Date.now() + 300_000,
    });
  }

  it('persists a request state as pending, with the nonce readable verbatim', async () => {
    const created = await seedState();

    expect(created.redeemedAt).toBeNull();
    expect(created.nonce).toBe('nonce-value');
    expect(created.verifierProfile).toBe('oid4vp-1.0-base');
    expect(created.dcqlQuery).toEqual({ credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] });
  });

  it('redeems exactly once — a replay of the same state returns undefined', async () => {
    const created = await seedState();

    const first = await requestStates.redeem(created.stateHash);
    const second = await requestStates.redeem(created.stateHash);

    expect(first?.id).toBe(created.id);
    expect(first?.redeemedAt).toBeGreaterThan(0);
    expect(second).toBeUndefined();
  });

  // The race the single-statement guard exists to close. A read-then-write
  // implementation passes the test above and fails this one.
  it('survives concurrent redemption: exactly one of N simultaneous posts wins', async () => {
    const created = await seedState();

    const results = await Promise.all(
      Array.from({ length: 12 }, () => requestStates.redeem(created.stateHash))
    );

    const winners = results.filter((row) => row !== undefined);

    expect(winners).toHaveLength(1);
    expect(winners[0]?.id).toBe(created.id);
  });

  it('refuses an expired state, and leaves it unredeemed', async () => {
    const created = await seedState({ expiresAt: Date.now() - 1 });

    expect(await requestStates.redeem(created.stateHash)).toBeUndefined();

    // Not "consumed then rejected": expiry is part of the same predicate, so
    // the row is simply never matched.
    const remaining = await requestStates.deleteExpired();
    expect(remaining).toBe(1);
  });

  it('refuses an unknown state', async () => {
    await seedState();

    expect(await requestStates.redeem('never-issued')).toBeUndefined();
  });

  it('enforces the state_hash unique index', async () => {
    const created = await seedState();

    await expect(seedState({ stateHash: created.stateHash })).rejects.toThrow();
  });

  it('rejects a non-object dcql_query at the database level', async () => {
    const realmId = await seedRealm();

    await expect(
      requestStates.create({
        realmId,
        stateHash: 'hash-bad-dcql',
        nonce: 'n',
        verifierProfile: 'oid4vp-1.0-base',
        responseMode: 'direct_post',
        // Deliberately bypassing the typed helper, the way a future caller might.
        dcqlQuery: ['not-an-object'] as unknown as Record<string, unknown>,
        expiresAt: Date.now() + 60_000,
      })
    ).rejects.toThrow();
  });

  it('cascades with its realm', async () => {
    if (!ctx) throw new Error('no ctx');
    const created = await seedState();

    await ctx.database.db.delete(realms);

    expect(await requestStates.redeem(created.stateHash)).toBeUndefined();
  });

  it('deleteExpired removes only past-TTL rows', async () => {
    const live = await seedState({ expiresAt: Date.now() + 300_000 });
    await seedState({ expiresAt: Date.now() - 1_000 });

    expect(await requestStates.deleteExpired()).toBe(1);
    expect((await requestStates.redeem(live.stateHash))?.id).toBe(live.id);
  });

  /**
   * The encrypted-response columns and the second correlator (#377 Phase C).
   *
   * Same properties as the `state_hash` path above, proven against the real
   * partial unique index and the two CHECK constraints migration 0019 added —
   * a mocked client cannot show that Postgres refuses a half-provisioned row.
   */
  describe('direct_post.jwt rows (#377 Phase C)', () => {
    async function seedEncryptedState(
      overrides: { kid?: string; expiresAt?: number; stateHash?: string } = {}
    ) {
      const realmId = await seedRealm();

      return requestStates.create({
        realmId,
        stateHash: overrides.stateHash ?? `hash-${Math.random().toString(36).slice(2)}`,
        nonce: 'nonce-value',
        verifierProfile: 'haip-1.0',
        responseMode: 'direct_post.jwt',
        dcqlQuery: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] },
        expiresAt: overrides.expiresAt ?? Date.now() + 300_000,
        responseEncryptionKid: overrides.kid ?? `kid-${Math.random().toString(36).slice(2)}`,
        responseEncryptionPrivateJwk: '{"kty":"EC","crv":"P-256","d":"x","x":"y","y":"z"}',
        responseEncryptionKeyProtection: 'plain',
      });
    }

    it('persists the three encryption columns and reads them back verbatim', async () => {
      const created = await seedEncryptedState({ kid: 'kid-roundtrip' });

      expect(created.responseMode).toBe('direct_post.jwt');
      expect(created.responseEncryptionKid).toBe('kid-roundtrip');
      expect(created.responseEncryptionPrivateJwk).toContain('"d":"x"');
      expect(created.responseEncryptionKeyProtection).toBe('plain');
    });

    it('leaves the three columns NULL on a plain direct_post row', async () => {
      const created = await seedState();

      expect(created.responseEncryptionKid).toBeNull();
      expect(created.responseEncryptionPrivateJwk).toBeNull();
      expect(created.responseEncryptionKeyProtection).toBeNull();
    });

    /** The row as the TABLE holds it — the repository exposes no read on purpose. */
    async function storedRow(id: string) {
      if (!ctx) throw new Error('no ctx');
      const [row] = await ctx.database.db
        .select({
          redeemedAt: oid4vpRequestStates.redeemedAt,
          responseEncryptionKid: oid4vpRequestStates.responseEncryptionKid,
          responseEncryptionPrivateJwk: oid4vpRequestStates.responseEncryptionPrivateJwk,
          responseEncryptionKeyProtection: oid4vpRequestStates.responseEncryptionKeyProtection,
        })
        .from(oid4vpRequestStates)
        .where(eq(oid4vpRequestStates.id, id));
      return row;
    }

    it('redeems by kid exactly once — a replay returns undefined', async () => {
      const created = await seedEncryptedState();
      const kid = created.responseEncryptionKid as string;

      const first = await requestStates.redeemByEncryptionKid(kid);
      const second = await requestStates.redeemByEncryptionKid(kid);

      expect(first?.id).toBe(created.id);
      expect(first?.stateHash).toBe(created.stateHash);
      expect(first?.responseEncryptionPrivateJwk).toBe(created.responseEncryptionPrivateJwk);
      expect(second).toBeUndefined();
    });

    it('hands the private key over ONCE and leaves none of it in the table (#377 F1)', async () => {
      // The property a mocked client cannot prove: `RETURNING` sees the row
      // after the write, so the pre-update projection has to be shown to work
      // against real Postgres — and the erasure has to be shown to have
      // happened in the same statement, not in a later pass.
      const created = await seedEncryptedState({ kid: 'kid-handoff' });

      const redeemed = await requestStates.redeemByEncryptionKid('kid-handoff');

      // The caller gets the row AS CONSUMED: redeemed, and carrying the key.
      expect(redeemed?.redeemedAt).toBeGreaterThan(0);
      expect(redeemed?.responseEncryptionKid).toBe('kid-handoff');
      expect(redeemed?.responseEncryptionPrivateJwk).toBe(created.responseEncryptionPrivateJwk);
      expect(redeemed?.responseEncryptionKeyProtection).toBe('plain');

      // The table keeps none of it — all three, or the CHECK would refuse.
      const stored = await storedRow(created.id);
      expect(stored?.redeemedAt).toBe(redeemed?.redeemedAt);
      expect(stored?.responseEncryptionKid).toBeNull();
      expect(stored?.responseEncryptionPrivateJwk).toBeNull();
      expect(stored?.responseEncryptionKeyProtection).toBeNull();
    });

    it('a cleartext redemption of an encrypted row erases its key too', async () => {
      // Consumed is consumed: the caller will refuse the mode mismatch, but the
      // row is spent and a spent row keeps no key. The cleartext path has no
      // use for it, so it is not handed back either.
      const created = await seedEncryptedState({ kid: 'kid-cleartext-consumed' });

      const redeemed = await requestStates.redeem(created.stateHash);

      expect(redeemed?.id).toBe(created.id);
      expect(redeemed?.responseEncryptionPrivateJwk).toBeNull();

      const stored = await storedRow(created.id);
      expect(stored?.redeemedAt).not.toBeNull();
      expect(stored?.responseEncryptionKid).toBeNull();
      expect(stored?.responseEncryptionPrivateJwk).toBeNull();
      expect(stored?.responseEncryptionKeyProtection).toBeNull();
    });

    it('consuming by kid also consumes the state, and vice versa — one row, one redemption', async () => {
      // The two correlators name the SAME single-use row. A row redeemed
      // through one must not be redeemable through the other, or the
      // encrypted path would be a second life for every request.
      const byKid = await seedEncryptedState();
      expect(
        await requestStates.redeemByEncryptionKid(byKid.responseEncryptionKid as string)
      ).toBeDefined();
      expect(await requestStates.redeem(byKid.stateHash)).toBeUndefined();

      const byState = await seedEncryptedState();
      expect(await requestStates.redeem(byState.stateHash)).toBeDefined();
      expect(
        await requestStates.redeemByEncryptionKid(byState.responseEncryptionKid as string)
      ).toBeUndefined();
    });

    it('survives concurrent redemption by kid: exactly one of N simultaneous posts wins', async () => {
      const created = await seedEncryptedState();
      const kid = created.responseEncryptionKid as string;

      const results = await Promise.all(
        Array.from({ length: 12 }, () => requestStates.redeemByEncryptionKid(kid))
      );

      const winners = results.filter((row) => row !== undefined);
      expect(winners).toHaveLength(1);
      // The self-join that projects the pre-update key does not weaken the
      // guard, and the one winner is the one holder of the key.
      expect(winners[0]?.responseEncryptionPrivateJwk).toBe(created.responseEncryptionPrivateJwk);
      expect((await storedRow(created.id))?.responseEncryptionPrivateJwk).toBeNull();
    });

    it('refuses an expired kid, and leaves the row unredeemed', async () => {
      const created = await seedEncryptedState({ expiresAt: Date.now() - 1 });

      expect(
        await requestStates.redeemByEncryptionKid(created.responseEncryptionKid as string)
      ).toBeUndefined();
      expect(await requestStates.deleteExpired()).toBe(1);
    });

    it('refuses an unknown kid', async () => {
      await seedEncryptedState();

      expect(await requestStates.redeemByEncryptionKid('never-published')).toBeUndefined();
    });

    it('never matches a plain direct_post row, whose kid is NULL', async () => {
      // `= $kid` is never true of NULL, so the cleartext rows are unreachable
      // from the encrypted path however the parameter is chosen.
      const plain = await seedState();

      expect(await requestStates.redeemByEncryptionKid('')).toBeUndefined();
      expect((await requestStates.redeem(plain.stateHash))?.id).toBe(plain.id);
    });

    it('enforces kid uniqueness over LIVE rows only', async () => {
      // §5.1 guarantees a kid unique only within one request; QAuth mints
      // globally unique ones and the partial index enforces that over rows
      // still redeemable. A redeemed row leaves the index, so a (vanishingly
      // unlikely) collision with a consumed kid is not a failed sign-in.
      const first = await seedEncryptedState({ kid: 'kid-shared' });

      await expect(seedEncryptedState({ kid: 'kid-shared' })).rejects.toThrow();

      expect(await requestStates.redeemByEncryptionKid('kid-shared')).toBeDefined();
      const reused = await seedEncryptedState({ kid: 'kid-shared' });
      expect(reused.id).not.toBe(first.id);
    });

    it('rejects a half-provisioned row at the database level (all three or none)', async () => {
      const realmId = await seedRealm();

      await expect(
        requestStates.create({
          realmId,
          stateHash: 'hash-half',
          nonce: 'n',
          verifierProfile: 'haip-1.0',
          responseMode: 'direct_post.jwt',
          dcqlQuery: { credentials: [] },
          expiresAt: Date.now() + 60_000,
          responseEncryptionKid: 'kid-half',
          // No private JWK and no protection marker: a kid the wallet would
          // echo, naming a key that does not exist.
        })
      ).rejects.toThrow();
    });

    it('rejects a protection marker no build can read', async () => {
      const realmId = await seedRealm();

      await expect(
        requestStates.create({
          realmId,
          stateHash: 'hash-scheme',
          nonce: 'n',
          verifierProfile: 'haip-1.0',
          responseMode: 'direct_post.jwt',
          dcqlQuery: { credentials: [] },
          expiresAt: Date.now() + 60_000,
          responseEncryptionKid: 'kid-scheme',
          responseEncryptionPrivateJwk: '{}',
          responseEncryptionKeyProtection: 'rot13',
        })
      ).rejects.toThrow();
    });
  });
});
