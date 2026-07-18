/**
 * Real-DB integration tests for the #228 identity repositories.
 *
 * Exercises the SQL-level behavior the mocked route tests cannot:
 * the (realm_id, provider_type, external_sub) unique index, the
 * credential_data jsonb CHECK, jsonb_set sibling-key preservation, and the
 * (user_id, source, attr_key) ON CONFLICT DO UPDATE upsert semantics.
 *
 * Requires Docker; self-skips without it (same pattern as the sibling suites).
 */
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import { isDockerAvailable } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { UserAttributesRepository, UserCredentialsRepository } from '../../types';
import { realms, users } from '../schema';
import { createEmailVerificationTokensRepository } from './email-verification-tokens.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createUserAttributesRepository } from './user-attributes.repository';
import { createUserCredentialsRepository } from './user-credentials.repository';

describe('identity repositories integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let credentials: UserCredentialsRepository;
  let attributes: UserAttributesRepository;

  beforeAll(async () => {
    dockerUp = await isDockerAvailable();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    credentials = createUserCredentialsRepository(ctx.database.db);
    attributes = createUserAttributesRepository(ctx.database.db);
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

  async function seedUser(email = 'user@example.com') {
    if (!ctx) throw new Error('no ctx');
    const db = ctx.database.db;
    const [realm] = await db
      .insert(realms)
      .values({ name: `realm-${email}` })
      .returning({ id: realms.id });
    const [user] = await db.insert(users).values({ realmId: realm.id }).returning();
    return { realmId: realm.id, user };
  }

  it('create + findByRealmProviderSub + findByUserIdAndType round-trip', async () => {
    const { realmId, user } = await seedUser();

    const created = await credentials.create({
      userId: user.id,
      realmId,
      providerType: 'password',
      externalSub: 'user@example.com',
      credentialData: { password_hash: '$argon2id$fake', email_verified: false },
    });

    const bySub = await credentials.findByRealmProviderSub(realmId, 'password', 'user@example.com');
    expect(bySub?.id).toBe(created.id);
    const byUser = await credentials.findByUserIdAndType(user.id, 'password');
    expect(byUser?.id).toBe(created.id);
    expect(byUser?.credentialData).toEqual({
      password_hash: '$argon2id$fake',
      email_verified: false,
    });
  });

  it('maps a (realm, provider, sub) duplicate onto UniqueConstraintError like the users repo', async () => {
    const { realmId, user } = await seedUser();
    const base = {
      userId: user.id,
      realmId,
      providerType: 'password',
      externalSub: 'user@example.com',
      credentialData: { password_hash: 'h', email_verified: false },
    };
    await credentials.create(base);

    await expect(credentials.create(base)).rejects.toThrow(UniqueConstraintError);
  });

  it('rejects non-object credential_data via the jsonb CHECK', async () => {
    const { realmId, user } = await seedUser();

    await expect(
      credentials.create({
        userId: user.id,
        realmId,
        providerType: 'password',
        externalSub: 'user@example.com',
        // Bypasses the typed helper on purpose: the DB CHECK is the last line.
        credentialData: 'not-an-object' as unknown as Record<string, unknown>,
      })
    ).rejects.toThrow();
  });

  it('setEmailVerified flips only email_verified and preserves sibling keys (jsonb_set)', async () => {
    const { realmId, user } = await seedUser();
    // Explicit old timestamps: the DB default rounds to whole seconds (can sit
    // up to 500ms ahead of Date.now()), which would make a freshness
    // comparison against it flaky.
    const SEEDED_AT = 1_600_000_000_000;
    const created = await credentials.create({
      userId: user.id,
      realmId,
      providerType: 'password',
      externalSub: 'user@example.com',
      credentialData: {
        password_hash: '$argon2id$fake',
        email_verified: false,
        future_sibling: 'must-survive',
      },
      createdAt: SEEDED_AT,
      updatedAt: SEEDED_AT,
    });

    const updated = await credentials.setEmailVerified(created.id);

    expect(updated.credentialData).toEqual({
      password_hash: '$argon2id$fake',
      email_verified: true,
      future_sibling: 'must-survive',
    });
    expect(updated.updatedAt).toBeGreaterThan(SEEDED_AT);
    expect(updated.createdAt).toBe(SEEDED_AT);
  });

  it('upsertMany inserts then conflict-updates on (user_id, source, attr_key)', async () => {
    const { user } = await seedUser();

    const inserted = await attributes.upsertMany(user.id, [
      { source: 'self_reported', attrKey: 'email', attrValue: 'user@example.com', verified: false },
    ]);
    expect(inserted).toHaveLength(1);

    // Same key tuple, new value + verified: must UPDATE in place, not duplicate.
    const upserted = await attributes.upsertMany(user.id, [
      { source: 'self_reported', attrKey: 'email', attrValue: 'new@example.com', verified: true },
    ]);
    expect(upserted).toHaveLength(1);
    expect(upserted[0].id).toBe(inserted[0].id);
    expect(upserted[0].attrValue).toBe('new@example.com');
    expect(upserted[0].verified).toBe(true);

    // A different source keeps its own row for the same attr_key.
    const walletRow = await attributes.upsertMany(user.id, [
      { source: 'wallet', attrKey: 'email', attrValue: 'w@example.com', verified: true },
    ]);
    expect(walletRow[0].id).not.toBe(inserted[0].id);
  });

  it('findVerifiedByUserIdAndKey returns only verified rows scoped to (user, key)', async () => {
    const { user } = await seedUser('claims@example.com');
    const { user: otherUser } = await seedUser('other@example.com');
    await attributes.upsertMany(user.id, [
      { source: 'self_reported', attrKey: 'email', attrValue: 'self@example.com', verified: true },
      { source: 'wallet', attrKey: 'email', attrValue: 'wallet@example.com', verified: true },
      // Unverified — must be filtered by the SQL, not the caller.
      { source: 'oidc_google', attrKey: 'email', attrValue: 'oidc@example.com', verified: false },
      // Different key — out of scope.
      { source: 'self_reported', attrKey: 'name', attrValue: 'Someone', verified: true },
    ]);
    await attributes.upsertMany(otherUser.id, [
      { source: 'wallet', attrKey: 'email', attrValue: 'not-yours@example.com', verified: true },
    ]);

    const rows = await attributes.findVerifiedByUserIdAndKey(user.id, 'email');

    expect(rows.map((r) => r.attrValue).sort()).toEqual(['self@example.com', 'wallet@example.com']);
    expect(rows.every((r) => r.verified)).toBe(true);

    // No verified rows → empty array, never undefined.
    const none = await attributes.findVerifiedByUserIdAndKey(otherUser.id, 'name');
    expect(none).toEqual([]);
  });

  it('upsertMany collapses duplicate (source, attr_key) inputs last-wins', async () => {
    const { user } = await seedUser();

    // Without the pre-statement dedup, Postgres rejects this with
    // "ON CONFLICT DO UPDATE command cannot affect row a second time".
    const rows = await attributes.upsertMany(user.id, [
      {
        source: 'self_reported',
        attrKey: 'email',
        attrValue: 'first@example.com',
        verified: false,
      },
      {
        source: 'self_reported',
        attrKey: 'email',
        attrValue: 'second@example.com',
        verified: true,
      },
    ]);

    expect(rows).toHaveLength(1);
    expect(rows[0].attrValue).toBe('second@example.com');
    expect(rows[0].verified).toBe(true);
  });

  it('email-verification markUsed is single-use: the second CAS attempt loses (#258)', async () => {
    if (!ctx) throw new Error('no ctx');
    const db = ctx.database.db;
    const { realmId, user } = await seedUser('cas@example.com');
    const cred = await credentials.create({
      userId: user.id,
      realmId,
      providerType: 'password',
      externalSub: 'cas@example.com',
      credentialData: { password_hash: 'h', email_verified: false },
    });
    const evt = createEmailVerificationTokensRepository(db);
    const token = await evt.create({
      credentialId: cred.id,
      tokenHash: 'f'.repeat(64),
      expiresAt: Date.now() + 3_600_000,
      used: false,
    });

    const first = await evt.markUsed(token.id);
    expect(first?.used).toBe(true);

    // Same real row, second attempt: the used=false predicate fails the CAS.
    const second = await evt.markUsed(token.id);
    expect(second).toBeUndefined();
  });

  it('setVerified targets exactly one (user_id, source, attr_key) row', async () => {
    const { user } = await seedUser();
    await attributes.upsertMany(user.id, [
      { source: 'self_reported', attrKey: 'email', attrValue: 'user@example.com', verified: false },
      { source: 'wallet', attrKey: 'email', attrValue: 'w@example.com', verified: false },
    ]);

    const updated = await attributes.setVerified(user.id, 'self_reported', 'email', true);
    expect(updated?.verified).toBe(true);

    // The wallet-sourced row is untouched.
    const untouched = await attributes.setVerified(user.id, 'wallet', 'email', false);
    expect(untouched?.attrValue).toBe('w@example.com');

    // Missing rows return undefined instead of throwing.
    const missing = await attributes.setVerified(user.id, 'oidc_google', 'email', true);
    expect(missing).toBeUndefined();
  });
});
