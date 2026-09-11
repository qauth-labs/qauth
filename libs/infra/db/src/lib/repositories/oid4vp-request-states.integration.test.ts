/**
 * Real-Postgres integration tests for the OID4VP request-state store (#233).
 *
 * The property under test cannot be proved anywhere else: single-use redemption
 * has to hold under GENUINE concurrency, against a real MVCC engine, with real
 * row locks. A mocked client can show which statement is emitted (the sibling
 * unit suite does exactly that); only a database can show that two simultaneous
 * posts carrying the same `state` produce exactly one winner — and, since #405,
 * that two simultaneous landings carrying the same Response Code do too.
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

  async function seedState(
    overrides: { stateHash?: string; expiresAt?: number; sameDevice?: boolean } = {}
  ) {
    const realmId = await seedRealm();

    return requestStates.create({
      realmId,
      stateHash: overrides.stateHash ?? `hash-${Math.random().toString(36).slice(2)}`,
      nonce: 'nonce-value',
      verifierProfile: 'oid4vp-1.0-base',
      responseMode: 'direct_post',
      dcqlQuery: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] },
      expiresAt: overrides.expiresAt ?? Date.now() + 300_000,
      ...(overrides.sameDevice === undefined ? {} : { sameDevice: overrides.sameDevice }),
    });
  }

  async function seedEncryptedState(
    overrides: { kid?: string; expiresAt?: number; stateHash?: string; sameDevice?: boolean } = {}
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
      ...(overrides.sameDevice === undefined ? {} : { sameDevice: overrides.sameDevice }),
    });
  }

  /**
   * The Response Code as the caller hands it to a redemption (#405): a fresh
   * digest and a deadline. The code itself never reaches the repository, so
   * the suite never mints one — a random 64-character "digest" is all the
   * table can tell apart.
   */
  function mintedCode(overrides: { codeHash?: string; codeExpiresAt?: number } = {}) {
    return {
      codeHash: overrides.codeHash ?? `code-${Math.random().toString(36).slice(2)}`.padEnd(64, '0'),
      codeExpiresAt: overrides.codeExpiresAt ?? Date.now() + 180_000,
    };
  }

  /** The row as the TABLE holds it — the repository exposes no read on purpose. */
  async function storedRow(id: string) {
    if (!ctx) throw new Error('no ctx');
    const [row] = await ctx.database.db
      .select({
        redeemedAt: oid4vpRequestStates.redeemedAt,
        responseEncryptionKid: oid4vpRequestStates.responseEncryptionKid,
        responseEncryptionPrivateJwk: oid4vpRequestStates.responseEncryptionPrivateJwk,
        responseEncryptionKeyProtection: oid4vpRequestStates.responseEncryptionKeyProtection,
        sameDevice: oid4vpRequestStates.sameDevice,
        responseCodeHash: oid4vpRequestStates.responseCodeHash,
        responseCodeExpiresAt: oid4vpRequestStates.responseCodeExpiresAt,
        responseCodeRedeemedAt: oid4vpRequestStates.responseCodeRedeemedAt,
      })
      .from(oid4vpRequestStates)
      .where(eq(oid4vpRequestStates.id, id));
    return row;
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

    const first = await requestStates.redeem(created.stateHash, mintedCode());
    const second = await requestStates.redeem(created.stateHash, mintedCode());

    expect(first?.id).toBe(created.id);
    expect(first?.redeemedAt).toBeGreaterThan(0);
    expect(second).toBeUndefined();
  });

  // The race the single-statement guard exists to close. A read-then-write
  // implementation passes the test above and fails this one.
  it('survives concurrent redemption: exactly one of N simultaneous posts wins', async () => {
    const created = await seedState();

    const results = await Promise.all(
      Array.from({ length: 12 }, () => requestStates.redeem(created.stateHash, mintedCode()))
    );

    const winners = results.filter((row) => row !== undefined);

    expect(winners).toHaveLength(1);
    expect(winners[0]?.id).toBe(created.id);
  });

  it('refuses an expired state, and leaves it unredeemed', async () => {
    const created = await seedState({ expiresAt: Date.now() - 1 });

    expect(await requestStates.redeem(created.stateHash, mintedCode())).toBeUndefined();

    // Not "consumed then rejected": expiry is part of the same predicate, so
    // the row is simply never matched.
    const remaining = await requestStates.deleteExpired();
    expect(remaining).toBe(1);
  });

  it('refuses an unknown state', async () => {
    await seedState();

    expect(await requestStates.redeem('never-issued', mintedCode())).toBeUndefined();
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

    expect(await requestStates.redeem(created.stateHash, mintedCode())).toBeUndefined();
  });

  it('deleteExpired removes only past-TTL rows', async () => {
    const live = await seedState({ expiresAt: Date.now() + 300_000 });
    await seedState({ expiresAt: Date.now() - 1_000 });

    expect(await requestStates.deleteExpired()).toBe(1);
    expect((await requestStates.redeem(live.stateHash, mintedCode()))?.id).toBe(live.id);
  });

  /**
   * The encrypted-response columns and the second correlator (#377 Phase C).
   *
   * Same properties as the `state_hash` path above, proven against the real
   * partial unique index and the two CHECK constraints migration 0019 added —
   * a mocked client cannot show that Postgres refuses a half-provisioned row.
   */
  describe('direct_post.jwt rows (#377 Phase C)', () => {
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

    it('redeems by kid exactly once — a replay returns undefined', async () => {
      const created = await seedEncryptedState();
      const kid = created.responseEncryptionKid as string;

      const first = await requestStates.redeemByEncryptionKid(kid, mintedCode());
      const second = await requestStates.redeemByEncryptionKid(kid, mintedCode());

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

      const redeemed = await requestStates.redeemByEncryptionKid('kid-handoff', mintedCode());

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

      const redeemed = await requestStates.redeem(created.stateHash, mintedCode());

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
        await requestStates.redeemByEncryptionKid(
          byKid.responseEncryptionKid as string,
          mintedCode()
        )
      ).toBeDefined();
      expect(await requestStates.redeem(byKid.stateHash, mintedCode())).toBeUndefined();

      const byState = await seedEncryptedState();
      expect(await requestStates.redeem(byState.stateHash, mintedCode())).toBeDefined();
      expect(
        await requestStates.redeemByEncryptionKid(
          byState.responseEncryptionKid as string,
          mintedCode()
        )
      ).toBeUndefined();
    });

    it('survives concurrent redemption by kid: exactly one of N simultaneous posts wins', async () => {
      const created = await seedEncryptedState();
      const kid = created.responseEncryptionKid as string;

      const results = await Promise.all(
        Array.from({ length: 12 }, () => requestStates.redeemByEncryptionKid(kid, mintedCode()))
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
        await requestStates.redeemByEncryptionKid(
          created.responseEncryptionKid as string,
          mintedCode()
        )
      ).toBeUndefined();
      expect(await requestStates.deleteExpired()).toBe(1);
    });

    it('refuses an unknown kid', async () => {
      await seedEncryptedState();

      expect(
        await requestStates.redeemByEncryptionKid('never-published', mintedCode())
      ).toBeUndefined();
    });

    it('never matches a plain direct_post row, whose kid is NULL', async () => {
      // `= $kid` is never true of NULL, so the cleartext rows are unreachable
      // from the encrypted path however the parameter is chosen.
      const plain = await seedState();

      expect(await requestStates.redeemByEncryptionKid('', mintedCode())).toBeUndefined();
      expect((await requestStates.redeem(plain.stateHash, mintedCode()))?.id).toBe(plain.id);
    });

    it('enforces kid uniqueness over LIVE rows only', async () => {
      // §5.1 guarantees a kid unique only within one request; QAuth mints
      // globally unique ones and the partial index enforces that over rows
      // still redeemable. A redeemed row leaves the index, so a (vanishingly
      // unlikely) collision with a consumed kid is not a failed sign-in.
      const first = await seedEncryptedState({ kid: 'kid-shared' });

      await expect(seedEncryptedState({ kid: 'kid-shared' })).rejects.toThrow();

      expect(await requestStates.redeemByEncryptionKid('kid-shared', mintedCode())).toBeDefined();
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

  /**
   * The same-device return leg and the THIRD correlator (#405).
   *
   * The Response Code is written by the redemption and consumed by the
   * browser's landing; both are single guarded statements, and what a mocked
   * client cannot show is that the four new columns, the partial unique index
   * and the two CHECKs migration 0020 added behave under a real engine — in
   * particular that twelve simultaneous landings carrying the same code
   * produce exactly one winner, and that housekeeping keeps its hands off a
   * row whose code is still live.
   */
  describe('the same-device return leg (#405)', () => {
    /**
     * Age a request's `expires_at` into the past WITHOUT waiting for it, so a
     * "request answered at its last second" is deterministic. Raw SQL, because
     * the repository has — rightly — no way to do this.
     */
    async function ageRequest(id: string): Promise<void> {
      if (!ctx) throw new Error('no ctx');
      await ctx.database.db
        .update(oid4vpRequestStates)
        .set({ expiresAt: Date.now() - 1_000 })
        .where(eq(oid4vpRequestStates.id, id));
    }

    it('records the device choice verbatim, and defaults to cross-device', async () => {
      const chosen = await seedState({ sameDevice: true });
      const silent = await seedState();

      expect(chosen.sameDevice).toBe(true);
      expect(silent.sameDevice).toBe(false);
      // A pending row carries no code — the code exists only for a redeemed one.
      expect(chosen.responseCodeHash).toBeNull();
      expect(chosen.responseCodeExpiresAt).toBeNull();
      expect(chosen.responseCodeRedeemedAt).toBeNull();
    });

    it('writes the code at redemption, readable back ONLY by consuming it', async () => {
      const created = await seedState({ sameDevice: true });
      const code = mintedCode();

      const redeemed = await requestStates.redeem(created.stateHash, code);

      // The caller sees the digest it handed in, on the row as consumed, and
      // the device choice it needs to decide whether to emit the code.
      expect(redeemed?.responseCodeHash).toBe(code.codeHash);
      expect(redeemed?.responseCodeExpiresAt).toBe(code.codeExpiresAt);
      expect(redeemed?.responseCodeRedeemedAt).toBeNull();
      expect(redeemed?.sameDevice).toBe(true);

      // The table holds the digest, unspent, until the browser lands.
      const before = await storedRow(created.id);
      expect(before?.responseCodeHash).toBe(code.codeHash);
      expect(before?.responseCodeRedeemedAt).toBeNull();

      // The one read there is: the landing, which spends the code and learns
      // the state hash — and nothing else.
      const landed = await requestStates.redeemResponseCode(code.codeHash);
      expect(landed).toEqual({ stateHash: created.stateHash });
      expect(Object.keys(landed ?? {})).toEqual(['stateHash']);

      const after = await storedRow(created.id);
      expect(after?.responseCodeRedeemedAt).toBeGreaterThan(0);
      expect(after?.responseCodeHash).toBe(code.codeHash);
    });

    it('writes the code on the encrypted path too, and the landing never sees a key column', async () => {
      const created = await seedEncryptedState({ sameDevice: true });
      const code = mintedCode();

      const redeemed = await requestStates.redeemByEncryptionKid(
        created.responseEncryptionKid as string,
        code
      );
      expect(redeemed?.responseCodeHash).toBe(code.codeHash);
      expect(redeemed?.sameDevice).toBe(true);

      const landed = await requestStates.redeemResponseCode(code.codeHash);
      expect(landed).toEqual({ stateHash: created.stateHash });

      // Erased at redemption, and in any case never projected by the landing.
      const stored = await storedRow(created.id);
      expect(stored?.responseEncryptionPrivateJwk).toBeNull();
      expect(stored?.responseCodeRedeemedAt).toBeGreaterThan(0);
    });

    // The race the single-statement guard exists to close, on the return leg:
    // twelve browsers landing with the same code at once.
    it('survives concurrent landings: exactly one of N simultaneous redemptions wins', async () => {
      const created = await seedState({ sameDevice: true });
      const code = mintedCode();
      await requestStates.redeem(created.stateHash, code);

      const results = await Promise.all(
        Array.from({ length: 12 }, () => requestStates.redeemResponseCode(code.codeHash))
      );

      const winners = results.filter((row) => row !== undefined);
      expect(winners).toHaveLength(1);
      expect(winners[0]?.stateHash).toBe(created.stateHash);
    });

    it('refuses a replayed code', async () => {
      const created = await seedState({ sameDevice: true });
      const code = mintedCode();
      await requestStates.redeem(created.stateHash, code);

      expect(await requestStates.redeemResponseCode(code.codeHash)).toBeDefined();
      expect(await requestStates.redeemResponseCode(code.codeHash)).toBeUndefined();
    });

    it('refuses an expired code, on its OWN deadline, and leaves it unspent', async () => {
      // The request is still live; only the code has expired. The row's
      // `expires_at` plays no part in the landing.
      const created = await seedState({ sameDevice: true, expiresAt: Date.now() + 300_000 });
      const code = mintedCode({ codeExpiresAt: Date.now() - 1 });
      await requestStates.redeem(created.stateHash, code);

      expect(await requestStates.redeemResponseCode(code.codeHash)).toBeUndefined();
      // Not "consumed then rejected": expiry is in the predicate, so the
      // marker was never written.
      expect((await storedRow(created.id))?.responseCodeRedeemedAt).toBeNull();
    });

    it('refuses an unknown code', async () => {
      const created = await seedState({ sameDevice: true });
      await requestStates.redeem(created.stateHash, mintedCode());

      expect(
        await requestStates.redeemResponseCode('never-minted'.padEnd(64, '0'))
      ).toBeUndefined();
    });

    it("refuses a cross-device row's code, even though its digest is in the table", async () => {
      // The digest is written for every redeemed row — one shape — but the
      // code it names never left the server, and the guard makes it worthless
      // at the one place it could be spent.
      const created = await seedState({ sameDevice: false });
      const code = mintedCode();
      await requestStates.redeem(created.stateHash, code);

      expect((await storedRow(created.id))?.responseCodeHash).toBe(code.codeHash);
      expect(await requestStates.redeemResponseCode(code.codeHash)).toBeUndefined();
      expect((await storedRow(created.id))?.responseCodeRedeemedAt).toBeNull();
    });

    it('refuses a code on a row no wallet answered (redeemed_at IS NULL)', async () => {
      // Unreachable through the repository — the code is only ever written
      // by a redemption — so the row is planted the way a hand-written
      // statement might, and the guard is shown to hold on its own.
      const realmId = await seedRealm();
      const code = mintedCode();
      const planted = await requestStates.create({
        realmId,
        stateHash: 'hash-planted',
        nonce: 'n',
        verifierProfile: 'oid4vp-1.0-base',
        responseMode: 'direct_post',
        dcqlQuery: { credentials: [] },
        expiresAt: Date.now() + 60_000,
        sameDevice: true,
        responseCodeHash: code.codeHash,
        responseCodeExpiresAt: code.codeExpiresAt,
      });
      expect(planted.redeemedAt).toBeNull();

      expect(await requestStates.redeemResponseCode(code.codeHash)).toBeUndefined();
    });

    it('enforces code-digest uniqueness over UNSPENT codes only', async () => {
      // A second live code with the same digest would make the landing's
      // guarded UPDATE ambiguous; a spent one has left the index, so a
      // (vanishingly unlikely) collision with a consumed code is not a failed
      // sign-in.
      const first = await seedState({ sameDevice: true });
      const second = await seedState({ sameDevice: true });
      const shared = mintedCode({ codeHash: 'code-shared'.padEnd(64, '0') });

      expect(await requestStates.redeem(first.stateHash, shared)).toBeDefined();
      await expect(requestStates.redeem(second.stateHash, shared)).rejects.toThrow();

      expect(await requestStates.redeemResponseCode(shared.codeHash)).toEqual({
        stateHash: first.stateHash,
      });
      expect((await requestStates.redeem(second.stateHash, shared))?.id).toBe(second.id);
    });

    it('deleteExpired spares a row with a live code and removes one whose code expired', async () => {
      // Three requests, all past their own expiry: one answered with a code
      // still good, one answered with a code that has also expired, one never
      // answered at all. Only the first survives the sweep — and its return
      // leg still works afterwards.
      const liveCode = await seedState({ sameDevice: true });
      const code = mintedCode({ codeExpiresAt: Date.now() + 180_000 });
      await requestStates.redeem(liveCode.stateHash, code);
      await ageRequest(liveCode.id);

      const deadCode = await seedState({ sameDevice: true });
      await requestStates.redeem(
        deadCode.stateHash,
        mintedCode({ codeExpiresAt: Date.now() - 1_000 })
      );
      await ageRequest(deadCode.id);

      const unanswered = await seedState({ expiresAt: Date.now() - 1_000 });

      expect(await requestStates.deleteExpired()).toBe(2);
      expect(await storedRow(liveCode.id)).toBeDefined();
      expect(await storedRow(deadCode.id)).toBeUndefined();
      expect(await storedRow(unanswered.id)).toBeUndefined();
      expect(await requestStates.redeemResponseCode(code.codeHash)).toEqual({
        stateHash: liveCode.stateHash,
      });
    });

    it('rejects a code digest without a deadline, and a deadline without a digest', async () => {
      const realmId = await seedRealm();
      const base = {
        realmId,
        nonce: 'n',
        verifierProfile: 'oid4vp-1.0-base',
        responseMode: 'direct_post',
        dcqlQuery: { credentials: [] },
        expiresAt: Date.now() + 60_000,
      } as const;

      await expect(
        requestStates.create({
          ...base,
          stateHash: 'hash-digest-only',
          responseCodeHash: 'code-no-deadline'.padEnd(64, '0'),
        })
      ).rejects.toThrow();
      await expect(
        requestStates.create({
          ...base,
          stateHash: 'hash-deadline-only',
          responseCodeExpiresAt: Date.now() + 60_000,
        })
      ).rejects.toThrow();
    });

    it('rejects a spent marker on a row that never had a code', async () => {
      const realmId = await seedRealm();

      await expect(
        requestStates.create({
          realmId,
          stateHash: 'hash-spent-nothing',
          nonce: 'n',
          verifierProfile: 'oid4vp-1.0-base',
          responseMode: 'direct_post',
          dcqlQuery: { credentials: [] },
          expiresAt: Date.now() + 60_000,
          responseCodeRedeemedAt: Date.now(),
        })
      ).rejects.toThrow();
    });
  });
});
