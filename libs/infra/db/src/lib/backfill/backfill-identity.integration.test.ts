/**
 * Real-DB integration tests for the ADR-002 identity backfill (#226).
 *
 * Drives `runIdentityBackfill` against a throwaway Postgres 18 container with
 * the real generated migrations applied — the acceptance criteria are all
 * about constraint interactions (the credential unique index vs. drift-window
 * email changes) that mocked repositories cannot exercise:
 *
 *   - AC1: every user ends with exactly one password credential + one email
 *     attribute, with the exact snake_case credential_data shape
 *   - AC2: re-run after success is a pure no-op
 *   - AC3: re-run heals partial state (credential-without-attribute crashes)
 *   - drift window: default runs never touch existing rows; --refresh updates
 *     them in place by user_id; cross-user external_sub reuse is surfaced by
 *     verification and healed by refresh; two-user swaps are reported, never
 *     auto-repaired
 *
 * Requires Docker. When Docker is unavailable the suite self-skips (same
 * pattern as repositories.integration.test.ts); CI runs it via the dedicated
 * `test-integration` target.
 */
import { isDockerAvailable } from '@qauth-labs/shared-testing';
import { asc, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { Database } from '../../types';
import { type IntegrationDb, setupIntegrationDb } from '../repositories/integration-setup';
import { realms, userAttributes, userCredentials, users } from '../schema';
import {
  backfillSucceeded,
  EMAIL_ATTR_KEY,
  MAX_BATCH_SIZE,
  PASSWORD_PROVIDER_TYPE,
  runIdentityBackfill,
  SELF_REPORTED_SOURCE,
  verifyIdentityBackfill,
} from './backfill-identity';

/** Deliberately old, distinct timestamps so provenance-copy assertions can
 * never accidentally pass against wall-clock defaults. */
const SEED_CREATED_AT = 1_600_000_000_000;
const SEED_UPDATED_AT = 1_600_000_100_000;
const DRIFT_UPDATED_AT = 1_600_000_200_000;

describe('identity backfill integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let db: Database;

  beforeAll(async () => {
    dockerUp = await isDockerAvailable();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    db = ctx.database.db;
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

  async function seedRealm(name: string): Promise<string> {
    const [realm] = await db.insert(realms).values({ name }).returning({ id: realms.id });
    return realm.id;
  }

  async function seedUser(
    realmId: string,
    email: string,
    overrides: Partial<typeof users.$inferInsert> = {}
  ): Promise<typeof users.$inferSelect> {
    const [row] = await db
      .insert(users)
      .values({
        realmId,
        email,
        emailNormalized: email.toLowerCase(),
        passwordHash: `$argon2id$fake$${email}`,
        emailVerified: false,
        createdAt: SEED_CREATED_AT,
        updatedAt: SEED_UPDATED_AT,
        ...overrides,
      })
      .returning();
    return row;
  }

  function credentialsOf(userId: string) {
    return db
      .select()
      .from(userCredentials)
      .where(eq(userCredentials.userId, userId))
      .orderBy(asc(userCredentials.id));
  }

  function attributesOf(userId: string) {
    return db
      .select()
      .from(userAttributes)
      .where(eq(userAttributes.userId, userId))
      .orderBy(asc(userAttributes.id));
  }

  it('AC1: migrates every user across realms with the exact credential_data shape', async () => {
    const realmA = await seedRealm('realm-a');
    const realmB = await seedRealm('realm-b');
    // Same normalized email in BOTH realms — legal for users, and both must
    // land as distinct (realm_id, 'password', external_sub) credential rows.
    const alice = await seedUser(realmA, 'Alice@Example.com', { emailVerified: true });
    const aliceB = await seedUser(realmB, 'alice@example.com');
    const bob = await seedUser(realmA, 'bob@example.com');

    const summary = await runIdentityBackfill(db, {});

    expect(summary.usersScanned).toBe(3);
    expect(summary.credentials).toEqual({ created: 3, skipped: 0, refreshed: 0 });
    expect(summary.attributes).toEqual({ created: 3, skipped: 0, refreshed: 0 });
    expect(summary.refreshConflicts).toEqual([]);
    expect(backfillSucceeded(summary)).toBe(true);

    for (const user of [alice, aliceB, bob]) {
      const creds = await credentialsOf(user.id);
      expect(creds).toHaveLength(1);
      expect(creds[0].realmId).toBe(user.realmId);
      expect(creds[0].providerType).toBe(PASSWORD_PROVIDER_TYPE);
      expect(creds[0].externalSub).toBe(user.emailNormalized);
      // Exact snake_case key shape — 'passwordHash' would satisfy every DB
      // constraint and strand every login at the #228 cutover.
      expect(creds[0].credentialData).toEqual({
        password_hash: user.passwordHash,
        email_verified: user.emailVerified,
      });

      const attrs = await attributesOf(user.id);
      expect(attrs).toHaveLength(1);
      expect(attrs[0].source).toBe(SELF_REPORTED_SOURCE);
      expect(attrs[0].attrKey).toBe(EMAIL_ATTR_KEY);
      // Original case preserved, verified mirrors the legacy flag.
      expect(attrs[0].attrValue).toBe(user.email);
      expect(attrs[0].verified).toBe(user.emailVerified);
    }
  });

  it('AC1/Q3: copies created_at/updated_at from users instead of stamping run time', async () => {
    const realmId = await seedRealm('realm-a');
    const user = await seedUser(realmId, 'old@example.com');

    await runIdentityBackfill(db, {});

    const [cred] = await credentialsOf(user.id);
    expect(cred.createdAt).toBe(SEED_CREATED_AT);
    expect(cred.updatedAt).toBe(SEED_UPDATED_AT);
    const [attr] = await attributesOf(user.id);
    expect(attr.createdAt).toBe(SEED_CREATED_AT);
    expect(attr.updatedAt).toBe(SEED_UPDATED_AT);
  });

  it('AC2: a second run is a no-op — nothing created, ids and rows unchanged', async () => {
    const realmId = await seedRealm('realm-a');
    await seedUser(realmId, 'a@example.com');
    await seedUser(realmId, 'b@example.com');

    const first = await runIdentityBackfill(db, {});
    expect(first.credentials.created).toBe(2);
    const credsBefore = await db.select().from(userCredentials).orderBy(asc(userCredentials.id));
    const attrsBefore = await db.select().from(userAttributes).orderBy(asc(userAttributes.id));

    const second = await runIdentityBackfill(db, {});

    expect(second.credentials).toEqual({ created: 0, skipped: 2, refreshed: 0 });
    expect(second.attributes).toEqual({ created: 0, skipped: 2, refreshed: 0 });
    expect(backfillSucceeded(second)).toBe(true);
    expect(await db.select().from(userCredentials).orderBy(asc(userCredentials.id))).toEqual(
      credsBefore
    );
    expect(await db.select().from(userAttributes).orderBy(asc(userAttributes.id))).toEqual(
      attrsBefore
    );
  });

  it('AC3: heals partial state — credential-without-attribute from a crashed run', async () => {
    const realmId = await seedRealm('realm-a');
    const partial = await seedUser(realmId, 'partial@example.com');
    const untouched = await seedUser(realmId, 'untouched@example.com');
    // Simulate a crash between the two inserts of an earlier run: credential
    // row exists, attribute row does not.
    await db.insert(userCredentials).values({
      userId: partial.id,
      realmId,
      providerType: PASSWORD_PROVIDER_TYPE,
      externalSub: partial.emailNormalized,
      credentialData: { password_hash: partial.passwordHash, email_verified: false },
      createdAt: SEED_CREATED_AT,
      updatedAt: SEED_UPDATED_AT,
    });

    const summary = await runIdentityBackfill(db, {});

    // Credential side skipped for the partial user, attribute side healed.
    expect(summary.credentials).toEqual({ created: 1, skipped: 1, refreshed: 0 });
    expect(summary.attributes).toEqual({ created: 2, skipped: 0, refreshed: 0 });
    expect(backfillSucceeded(summary)).toBe(true);
    expect(await credentialsOf(partial.id)).toHaveLength(1);
    expect(await attributesOf(partial.id)).toHaveLength(1);
    expect(await credentialsOf(untouched.id)).toHaveLength(1);
    expect(await attributesOf(untouched.id)).toHaveLength(1);
  });

  it('paginates by keyset and terminates on the zero-row select', async () => {
    const realmId = await seedRealm('realm-a');
    for (let i = 0; i < 5; i++) {
      await seedUser(realmId, `user${i}@example.com`);
    }

    const summary = await runIdentityBackfill(db, { batchSize: 2 });

    // 2 + 2 + 1 non-empty batches; the terminating empty select is not counted.
    expect(summary.batches).toBe(3);
    expect(summary.usersScanned).toBe(5);
    expect(summary.credentials.created).toBe(5);
    expect(backfillSucceeded(summary)).toBe(true);
  });

  it('is a clean no-op on an empty users table', async () => {
    const summary = await runIdentityBackfill(db, {});
    expect(summary).toMatchObject({
      batches: 0,
      usersScanned: 0,
      credentials: { created: 0, skipped: 0, refreshed: 0 },
      attributes: { created: 0, skipped: 0, refreshed: 0 },
    });
    expect(backfillSucceeded(summary)).toBe(true);
  });

  it('rejects an out-of-range batchSize', async () => {
    await expect(runIdentityBackfill(db, { batchSize: 0 })).rejects.toThrow(RangeError);
  });

  it('handles a MAX_BATCH_SIZE batch without exceeding the bind-parameter limit', async () => {
    // 9,500 users in one keyset batch: unchunked, each 7-param-per-row bulk
    // INSERT would bind 66,500 parameters and blow the Postgres 65,535 cap —
    // this locks in the INSERT_CHUNK_SIZE fix at the advertised maximum.
    const realmId = await seedRealm('realm-a');
    const total = 9500;
    const rows = Array.from({ length: total }, (_, i) => ({
      realmId,
      email: `bulk${i}@example.com`,
      emailNormalized: `bulk${i}@example.com`,
      passwordHash: `$argon2id$fake$${i}`,
      emailVerified: false,
      createdAt: SEED_CREATED_AT,
      updatedAt: SEED_UPDATED_AT,
    }));
    // Seeding hits the same wire-protocol limit — chunk it too.
    for (let i = 0; i < rows.length; i += 5000) {
      await db.insert(users).values(rows.slice(i, i + 5000));
    }

    const summary = await runIdentityBackfill(db, { batchSize: MAX_BATCH_SIZE });

    expect(summary.batches).toBe(1);
    expect(summary.usersScanned).toBe(total);
    expect(summary.credentials).toEqual({ created: total, skipped: 0, refreshed: 0 });
    expect(summary.attributes).toEqual({ created: total, skipped: 0, refreshed: 0 });
    expect(backfillSucceeded(summary)).toBe(true);
  }, 120_000);

  it('drift: default re-run never touches existing rows; --refresh updates in place by user_id', async () => {
    const realmId = await seedRealm('realm-a');
    const pwChanged = await seedUser(realmId, 'pw@example.com');
    const verifiedFlipped = await seedUser(realmId, 'flip@example.com');
    const emailChanged = await seedUser(realmId, 'before@example.com');
    // Drifts ONLY via users.updated_at (content stays identical) — exercises
    // the updatedAt-behind clause of credentialIsStale/attributeIsStale, which
    // no content change can cover.
    const touchedOnly = await seedUser(realmId, 'touched@example.com');

    await runIdentityBackfill(db, {});

    // Drift-window writes on the legacy columns (still the authoritative copy).
    await db
      .update(users)
      .set({ passwordHash: '$argon2id$fake$rotated', updatedAt: DRIFT_UPDATED_AT })
      .where(eq(users.id, pwChanged.id));
    await db
      .update(users)
      .set({ emailVerified: true, emailVerifiedAt: DRIFT_UPDATED_AT, updatedAt: DRIFT_UPDATED_AT })
      .where(eq(users.id, verifiedFlipped.id));
    await db
      .update(users)
      .set({
        email: 'After@Example.com',
        emailNormalized: 'after@example.com',
        updatedAt: DRIFT_UPDATED_AT,
      })
      .where(eq(users.id, emailChanged.id));
    await db.update(users).set({ updatedAt: DRIFT_UPDATED_AT }).where(eq(users.id, touchedOnly.id));

    const [staleCred] = await credentialsOf(emailChanged.id);

    // Default re-run: skip everything — no refresh, and crucially no SECOND
    // credential row for the email-changed user (the skip predicate is
    // user_id-based, not conflict-index-based).
    const defaultRun = await runIdentityBackfill(db, {});
    expect(defaultRun.credentials).toEqual({ created: 0, skipped: 4, refreshed: 0 });
    const afterDefault = await credentialsOf(emailChanged.id);
    expect(afterDefault).toHaveLength(1);
    expect(afterDefault[0].externalSub).toBe('before@example.com');
    expect(afterDefault[0].credentialData).toEqual({
      password_hash: emailChanged.passwordHash,
      email_verified: false,
    });

    // --refresh: same row ids updated in place from the legacy columns. All
    // four users refresh on both tables — three via content drift, touchedOnly
    // via the updatedAt-behind clause alone (pinned counts keep that clause
    // regression-detectable).
    const refreshRun = await runIdentityBackfill(db, { refresh: true });
    expect(refreshRun.credentials.created).toBe(0);
    expect(refreshRun.credentials.refreshed).toBe(4);
    expect(refreshRun.attributes.refreshed).toBe(4);
    expect(refreshRun.refreshConflicts).toEqual([]);
    expect(backfillSucceeded(refreshRun)).toBe(true);

    const [touchedCred] = await credentialsOf(touchedOnly.id);
    expect(touchedCred.updatedAt).toBe(DRIFT_UPDATED_AT);
    expect(touchedCred.credentialData).toEqual({
      password_hash: touchedOnly.passwordHash,
      email_verified: false,
    });
    const [touchedAttr] = await attributesOf(touchedOnly.id);
    expect(touchedAttr.updatedAt).toBe(DRIFT_UPDATED_AT);

    const [pwCred] = await credentialsOf(pwChanged.id);
    expect(pwCred.credentialData).toEqual({
      password_hash: '$argon2id$fake$rotated',
      email_verified: false,
    });
    expect(pwCred.updatedAt).toBe(DRIFT_UPDATED_AT);

    const [flipCred] = await credentialsOf(verifiedFlipped.id);
    expect(flipCred.credentialData).toEqual({
      password_hash: verifiedFlipped.passwordHash,
      email_verified: true,
    });
    const [flipAttr] = await attributesOf(verifiedFlipped.id);
    expect(flipAttr.verified).toBe(true);

    const afterRefresh = await credentialsOf(emailChanged.id);
    expect(afterRefresh).toHaveLength(1);
    expect(afterRefresh[0].id).toBe(staleCred.id);
    expect(afterRefresh[0].externalSub).toBe('after@example.com');
    const [changedAttr] = await attributesOf(emailChanged.id);
    expect(changedAttr.attrValue).toBe('After@Example.com');
  });

  it('cross-user slot reuse: verification surfaces the swallowed insert; --refresh heals it in one run', async () => {
    const realmId = await seedRealm('realm-a');
    const userA = await seedUser(realmId, 'a@example.com');
    await runIdentityBackfill(db, {});

    // Drift window: A changes email a@ → b@, freeing nothing in the new
    // tables (A's credential still occupies the 'a@example.com' slot), then a
    // NEW user B registers with the now-free legacy email a@.
    await db
      .update(users)
      .set({
        email: 'b@example.com',
        emailNormalized: 'b@example.com',
        updatedAt: DRIFT_UPDATED_AT,
      })
      .where(eq(users.id, userA.id));
    const userB = await seedUser(realmId, 'a@example.com');

    // Default run: B's credential insert is swallowed by A's stale row on the
    // (realm, 'password', 'a@example.com') slot — created counts look clean,
    // so end-of-run verification is the only detector.
    const defaultRun = await runIdentityBackfill(db, {});
    expect(defaultRun.credentials.created).toBe(0);
    expect(defaultRun.verification.missingCredentials).toBe(1);
    expect(defaultRun.verification.missingCredentialSampleUserIds).toEqual([userB.id]);
    expect(backfillSucceeded(defaultRun)).toBe(false);
    expect(await credentialsOf(userB.id)).toHaveLength(0);

    // Refresh run: A's row is moved off the slot BEFORE inserts run, so B's
    // insert succeeds within the same run.
    const refreshRun = await runIdentityBackfill(db, { refresh: true });
    expect(refreshRun.credentials.refreshed).toBe(1);
    expect(refreshRun.credentials.created).toBe(1);
    expect(refreshRun.refreshConflicts).toEqual([]);
    expect(backfillSucceeded(refreshRun)).toBe(true);

    const [aCred] = await credentialsOf(userA.id);
    expect(aCred.externalSub).toBe('b@example.com');
    const [bCred] = await credentialsOf(userB.id);
    expect(bCred.externalSub).toBe('a@example.com');
  });

  it('two-user email swap: refresh reports conflicts and never auto-repairs', async () => {
    const realmId = await seedRealm('realm-a');
    const userA = await seedUser(realmId, 'a@example.com');
    const userB = await seedUser(realmId, 'b@example.com');
    await runIdentityBackfill(db, {});

    // Swap emails on the legacy side (via a temp value to satisfy the users
    // unique index). Both credential refreshes now target each other's slot.
    await db
      .update(users)
      .set({ email: 'tmp@example.com', emailNormalized: 'tmp@example.com' })
      .where(eq(users.id, userA.id));
    await db
      .update(users)
      .set({
        email: 'a@example.com',
        emailNormalized: 'a@example.com',
        updatedAt: DRIFT_UPDATED_AT,
      })
      .where(eq(users.id, userB.id));
    await db
      .update(users)
      .set({
        email: 'b@example.com',
        emailNormalized: 'b@example.com',
        updatedAt: DRIFT_UPDATED_AT,
      })
      .where(eq(users.id, userA.id));

    const refreshRun = await runIdentityBackfill(db, { refresh: true });

    expect(refreshRun.refreshConflicts).toHaveLength(2);
    expect(refreshRun.refreshConflicts.map((c) => c.userId).sort()).toEqual(
      [userA.id, userB.id].sort()
    );
    expect(backfillSucceeded(refreshRun)).toBe(false);
    // Credential rows are untouched (still one each, on the old slots) — the
    // swap is reported for manual remediation, never auto-repaired.
    const [aCred] = await credentialsOf(userA.id);
    const [bCred] = await credentialsOf(userB.id);
    expect(aCred.externalSub).toBe('a@example.com');
    expect(bCred.externalSub).toBe('b@example.com');
    // Attribute refreshes have no cross-user constraint and DID land.
    const [aAttr] = await attributesOf(userA.id);
    expect(aAttr.attrValue).toBe('b@example.com');
  });

  it('--dry-run reports would-create/would-refresh and writes nothing', async () => {
    const realmId = await seedRealm('realm-a');
    const migrated = await seedUser(realmId, 'done@example.com');
    await runIdentityBackfill(db, {});
    await db
      .update(users)
      .set({ passwordHash: '$argon2id$fake$rotated', updatedAt: DRIFT_UPDATED_AT })
      .where(eq(users.id, migrated.id));
    const fresh = await seedUser(realmId, 'new@example.com');

    const dryRun = await runIdentityBackfill(db, { dryRun: true, refresh: true });

    expect(dryRun.credentials).toEqual({ created: 1, skipped: 0, refreshed: 1 });
    expect(dryRun.attributes.created).toBe(1);
    expect(await credentialsOf(fresh.id)).toHaveLength(0);
    expect(await attributesOf(fresh.id)).toHaveLength(0);
    const [staleCred] = await credentialsOf(migrated.id);
    expect(staleCred.credentialData).toEqual({
      password_hash: migrated.passwordHash,
      email_verified: false,
    });
  });

  it('verifyOnly runs only the read-only checks and performs no writes', async () => {
    const realmId = await seedRealm('realm-a');
    const user = await seedUser(realmId, 'v@example.com');
    await runIdentityBackfill(db, {});
    await db.delete(userAttributes).where(eq(userAttributes.userId, user.id));

    const verifyRun = await runIdentityBackfill(db, { verifyOnly: true });

    expect(verifyRun.usersScanned).toBe(0);
    expect(verifyRun.verification.missingAttributes).toBe(1);
    expect(verifyRun.verification.missingAttributeSampleUserIds).toEqual([user.id]);
    expect(backfillSucceeded(verifyRun)).toBe(false);
    // Still missing afterwards — verify mode wrote nothing.
    expect(await attributesOf(user.id)).toHaveLength(0);

    // A real run heals it, after which standalone verification is clean.
    await runIdentityBackfill(db, {});
    const verification = await verifyIdentityBackfill(db);
    expect(verification.missingAttributes).toBe(0);
    expect(verification.missingCredentials).toBe(0);
    expect(verification.duplicateCredentials).toBe(0);
  });
});
