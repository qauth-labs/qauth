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
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { Oid4vpRequestStatesRepository } from '../../types';
import { realms } from '../schema';
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
});
