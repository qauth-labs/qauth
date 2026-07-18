import { and, asc, eq, gt, inArray, isNull, sql } from 'drizzle-orm';

import type { Database } from '../../types';
import { userAttributes, userCredentials, users } from '../schema';

/**
 * ADR-002 identity backfill (issue #226).
 *
 * Populates the additive `user_credentials` / `user_attributes` tables (#225)
 * from every legacy `users` row so no account is orphaned when the auth engine
 * cuts over to reading the new tables (#228). Per user:
 *
 * - one `user_credentials` row: `provider_type='password'`,
 *   `external_sub = users.email_normalized`,
 *   `credential_data = { password_hash, email_verified }` (snake_case JSONB
 *   keys — the shape #228's reader contract is built on, see `identity.ts`)
 * - one `user_attributes` row: `source='self_reported'`, `attr_key='email'`,
 *   `attr_value = users.email` (original case), `verified = users.email_verified`
 *
 * ## Idempotency model
 *
 * All skip/refresh predicates are keyed on `user_id`, NEVER on the
 * `(realm_id, provider_type, external_sub)` unique index. During the drift
 * window (between a backfill run and the #228 cutover the legacy columns keep
 * receiving writes), a user's `email_normalized` can change; a conflict-keyed
 * predicate would then miss the user's old row and insert a second credential
 * for the same user, violating the "exactly one" acceptance criterion.
 * `ON CONFLICT DO NOTHING` remains on the inserts purely as a race guard
 * against concurrent live registrations — it is not the skip logic.
 *
 * The predicates are per-table and independent: a crash between the two
 * inserts of an earlier run (or a pre-existing partial state) is healed on
 * re-run because the missing side is computed separately for each table.
 *
 * ## Refresh mode (pre-cutover only)
 *
 * The default run never touches existing rows ("re-run is a no-op"). With
 * `refresh: true`, rows whose content is behind the authoritative legacy
 * columns are UPDATEd in place (matched by `user_id`), copying
 * `external_sub` / `credential_data` / `verified` and stamping
 * `updated_at = users.updated_at`. Refresh copies FROM the legacy columns and
 * is therefore only correct while those are authoritative — i.e. BEFORE the
 * #228 cutover. Operators are expected to run a final `--refresh` +
 * `--verify-only` pass immediately before cutover.
 *
 * Refresh UPDATEs run row-by-row BEFORE the batch's inserts (freeing a
 * reassigned `external_sub` slot lets a swallowed insert succeed within the
 * same run). A unique violation on the credential slot (two users swapped
 * emails during the drift window) is collected into
 * {@link BackfillSummary.refreshConflicts} for manual remediation instead of
 * aborting the run.
 *
 * ## Batching
 *
 * Keyset pagination over `users.id` (uuidv7 is time-ordered, so users
 * registered mid-run are swept into later batches). Reads happen outside the
 * write transaction; each batch commits one short transaction wrapping the two
 * bulk inserts (chunked to respect the wire-protocol bind-parameter limit),
 * keeping lock windows small on a hot `users` table. The loop terminates when
 * the keyset select returns zero rows.
 *
 * ## Verification
 *
 * {@link verifyIdentityBackfill} counts users missing either row and users
 * with more than one password credential (the duplicate case the DB cannot
 * exclude, since the credential unique index does not contain `user_id`).
 * Write runs always verify at the end; the CLI exits non-zero on any mismatch.
 */

/** `user_credentials.provider_type` value for the password method (ADR-002). */
export const PASSWORD_PROVIDER_TYPE = 'password';
/** `user_attributes.source` for user-asserted attributes (ADR-002). */
export const SELF_REPORTED_SOURCE = 'self_reported';
/** `user_attributes.attr_key` for the email attribute. */
export const EMAIL_ATTR_KEY = 'email';

export const DEFAULT_BATCH_SIZE = 1000;
export const MAX_BATCH_SIZE = 10000;

/**
 * Rows per INSERT statement. Each row binds 7 parameters, and one statement
 * is capped at 65,535 bind parameters by the Postgres wire protocol, so a
 * full-size batch must be split across statements (within one transaction).
 */
const INSERT_CHUNK_SIZE = 5000;

/** Number of offending user ids included per verification finding. */
const VERIFICATION_SAMPLE_SIZE = 10;

/**
 * JSONB shape of `user_credentials.credential_data` for
 * `provider_type='password'`. Keys are snake_case by contract (#225 schema
 * JSDoc); `'passwordHash'` would pass every DB check and strand every login
 * at cutover, so the shape lives in exactly one place — here.
 */
interface PasswordCredentialData extends Record<string, unknown> {
  password_hash: string;
  email_verified: boolean;
}

export interface BackfillOptions {
  /** Users per keyset batch (1..{@link MAX_BATCH_SIZE}); default {@link DEFAULT_BATCH_SIZE}. */
  batchSize?: number;
  /** Update stale existing rows from the legacy columns. PRE-CUTOVER ONLY. */
  refresh?: boolean;
  /** Scan and count would-create / would-refresh, but write nothing. */
  dryRun?: boolean;
  /** Skip the scan entirely and only run the verification queries. */
  verifyOnly?: boolean;
}

export interface BackfillTableCounters {
  /** Rows actually inserted (statement row counts, not estimates). */
  created: number;
  /** Users whose row already existed (including race-guard swallows). */
  skipped: number;
  /** Stale rows updated in place (refresh mode; "would refresh" in dry-run). */
  refreshed: number;
}

/** A refresh UPDATE that hit the credential unique index (email swap case). */
export interface RefreshConflict {
  userId: string;
  /** The `external_sub` the update tried to move the row to. */
  externalSub: string;
}

export interface BackfillVerification {
  /** Users with zero `provider_type='password'` credential rows. */
  missingCredentials: number;
  /** Users with zero `('self_reported','email')` attribute rows. */
  missingAttributes: number;
  /** Users with MORE than one password credential row (AC1 "exactly one"). */
  duplicateCredentials: number;
  missingCredentialSampleUserIds: string[];
  missingAttributeSampleUserIds: string[];
  duplicateCredentialSampleUserIds: string[];
}

export interface BackfillSummary {
  credentials: BackfillTableCounters;
  attributes: BackfillTableCounters;
  /** Non-empty keyset batches processed. */
  batches: number;
  usersScanned: number;
  refreshConflicts: RefreshConflict[];
  verification: BackfillVerification;
}

/** True when verification found nothing wrong and no refresh conflicts remain. */
export function backfillSucceeded(summary: BackfillSummary): boolean {
  const v = summary.verification;
  return (
    v.missingCredentials === 0 &&
    v.missingAttributes === 0 &&
    v.duplicateCredentials === 0 &&
    summary.refreshConflicts.length === 0
  );
}

/** Legacy `users` projection the backfill reads. All columns are NOT NULL. */
interface LegacyUserRow {
  id: string;
  realmId: string;
  email: string;
  emailNormalized: string;
  passwordHash: string;
  emailVerified: boolean;
  createdAt: number;
  updatedAt: number;
}

interface ExistingCredentialRow {
  userId: string;
  externalSub: string;
  credentialData: Record<string, unknown>;
  updatedAt: number;
}

interface ExistingAttributeRow {
  userId: string;
  attrValue: string;
  verified: boolean;
  updatedAt: number;
}

function buildCredentialData(user: LegacyUserRow): PasswordCredentialData {
  return {
    password_hash: user.passwordHash,
    email_verified: user.emailVerified,
  };
}

/**
 * A credential row is stale when any copied field is behind the legacy row.
 * The `updated_at` clause keeps the drift-audit signal
 * (`users.updated_at > user_credentials.updated_at`) clean even when the
 * content happens to compare equal.
 */
function credentialIsStale(existing: ExistingCredentialRow, user: LegacyUserRow): boolean {
  const data = existing.credentialData as Partial<PasswordCredentialData>;
  return (
    existing.externalSub !== user.emailNormalized ||
    data.password_hash !== user.passwordHash ||
    data.email_verified !== user.emailVerified ||
    existing.updatedAt < user.updatedAt
  );
}

function attributeIsStale(existing: ExistingAttributeRow, user: LegacyUserRow): boolean {
  return (
    existing.attrValue !== user.email ||
    existing.verified !== user.emailVerified ||
    existing.updatedAt < user.updatedAt
  );
}

/**
 * Postgres unique-violation detector that survives driver/ORM wrapping
 * (drizzle wraps the pg error; the SQLSTATE lives on the `cause` chain).
 */
function isUniqueViolation(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const candidate = err as { code?: unknown; cause?: unknown };
  if (candidate.code === '23505') return true;
  return isUniqueViolation(candidate.cause);
}

/**
 * Run the ADR-002 identity backfill. See the module JSDoc for semantics.
 *
 * Idempotent and safe to re-run after any partial failure; the recovery
 * strategy for a crashed run is simply to run it again (no checkpoint state).
 *
 * @param db - Root drizzle database (needs `.transaction()`).
 * @throws RangeError when `batchSize` is not an integer in [1, MAX_BATCH_SIZE].
 */
export async function runIdentityBackfill(
  db: Database,
  options: BackfillOptions = {}
): Promise<BackfillSummary> {
  const batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > MAX_BATCH_SIZE) {
    throw new RangeError(
      `batchSize must be an integer in [1, ${MAX_BATCH_SIZE}], got ${batchSize}`
    );
  }
  const refresh = options.refresh ?? false;
  const dryRun = options.dryRun ?? false;

  const summary: BackfillSummary = {
    credentials: { created: 0, skipped: 0, refreshed: 0 },
    attributes: { created: 0, skipped: 0, refreshed: 0 },
    batches: 0,
    usersScanned: 0,
    refreshConflicts: [],
    verification: {
      missingCredentials: 0,
      missingAttributes: 0,
      duplicateCredentials: 0,
      missingCredentialSampleUserIds: [],
      missingAttributeSampleUserIds: [],
      duplicateCredentialSampleUserIds: [],
    },
  };

  if (options.verifyOnly) {
    summary.verification = await verifyIdentityBackfill(db);
    return summary;
  }

  let lastId: string | null = null;
  for (;;) {
    // Keyset read, outside any transaction: uuidv7 ids are time-ordered, so
    // the scan also sweeps users registered while the backfill is running.
    const batch: LegacyUserRow[] = await db
      .select({
        id: users.id,
        realmId: users.realmId,
        email: users.email,
        emailNormalized: users.emailNormalized,
        passwordHash: users.passwordHash,
        emailVerified: users.emailVerified,
        createdAt: users.createdAt,
        updatedAt: users.updatedAt,
      })
      .from(users)
      .where(lastId === null ? undefined : gt(users.id, lastId))
      .orderBy(asc(users.id))
      .limit(batchSize);

    if (batch.length === 0) break;
    summary.batches += 1;
    summary.usersScanned += batch.length;
    lastId = batch[batch.length - 1].id;

    await processBatch(db, batch, { refresh, dryRun }, summary);
  }

  summary.verification = await verifyIdentityBackfill(db);
  return summary;
}

async function processBatch(
  db: Database,
  batch: LegacyUserRow[],
  mode: { refresh: boolean; dryRun: boolean },
  summary: BackfillSummary
): Promise<void> {
  const userIds = batch.map((u) => u.id);

  const existingCredentials: ExistingCredentialRow[] = await db
    .select({
      userId: userCredentials.userId,
      externalSub: userCredentials.externalSub,
      credentialData: userCredentials.credentialData,
      updatedAt: userCredentials.updatedAt,
    })
    .from(userCredentials)
    .where(
      and(
        inArray(userCredentials.userId, userIds),
        eq(userCredentials.providerType, PASSWORD_PROVIDER_TYPE)
      )
    );
  const credentialByUserId = new Map(existingCredentials.map((c) => [c.userId, c]));

  const existingAttributes: ExistingAttributeRow[] = await db
    .select({
      userId: userAttributes.userId,
      attrValue: userAttributes.attrValue,
      verified: userAttributes.verified,
      updatedAt: userAttributes.updatedAt,
    })
    .from(userAttributes)
    .where(
      and(
        inArray(userAttributes.userId, userIds),
        eq(userAttributes.source, SELF_REPORTED_SOURCE),
        eq(userAttributes.attrKey, EMAIL_ATTR_KEY)
      )
    );
  const attributeByUserId = new Map(existingAttributes.map((a) => [a.userId, a]));

  const credentialInserts: (typeof userCredentials.$inferInsert)[] = [];
  const attributeInserts: (typeof userAttributes.$inferInsert)[] = [];
  const credentialRefreshes: LegacyUserRow[] = [];
  const attributeRefreshes: LegacyUserRow[] = [];

  for (const user of batch) {
    const credential = credentialByUserId.get(user.id);
    if (!credential) {
      credentialInserts.push({
        userId: user.id,
        realmId: user.realmId,
        providerType: PASSWORD_PROVIDER_TYPE,
        externalSub: user.emailNormalized,
        credentialData: buildCredentialData(user),
        // Provenance, not run time: the credential has existed since
        // registration, and users.updated_at > user_credentials.updated_at is
        // the drift-staleness signal — DB defaults would erase both.
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      });
    } else if (mode.refresh && credentialIsStale(credential, user)) {
      credentialRefreshes.push(user);
    } else {
      summary.credentials.skipped += 1;
    }

    const attribute = attributeByUserId.get(user.id);
    if (!attribute) {
      attributeInserts.push({
        userId: user.id,
        source: SELF_REPORTED_SOURCE,
        attrKey: EMAIL_ATTR_KEY,
        attrValue: user.email,
        verified: user.emailVerified,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      });
    } else if (mode.refresh && attributeIsStale(attribute, user)) {
      attributeRefreshes.push(user);
    } else {
      summary.attributes.skipped += 1;
    }
  }

  if (mode.dryRun) {
    summary.credentials.created += credentialInserts.length;
    summary.attributes.created += attributeInserts.length;
    summary.credentials.refreshed += credentialRefreshes.length;
    summary.attributes.refreshed += attributeRefreshes.length;
    return;
  }

  // Refresh UPDATEs run first and row-by-row (each its own implicit
  // transaction): moving a reassigned external_sub off its old slot lets a
  // previously swallowed insert for the slot's new owner succeed in this same
  // run. Partial application is safe — re-running heals the rest.
  for (const user of credentialRefreshes) {
    try {
      await db
        .update(userCredentials)
        .set({
          externalSub: user.emailNormalized,
          credentialData: buildCredentialData(user),
          updatedAt: user.updatedAt,
        })
        .where(
          and(
            eq(userCredentials.userId, user.id),
            eq(userCredentials.providerType, PASSWORD_PROVIDER_TYPE)
          )
        );
      summary.credentials.refreshed += 1;
    } catch (err) {
      // Two users swapped emails inside the drift window: both updates hit the
      // (realm_id, provider_type, external_sub) unique index. Deleting rows to
      // break the cycle is deliberately out of scope — report for manual
      // remediation and keep going.
      if (!isUniqueViolation(err)) throw err;
      summary.refreshConflicts.push({ userId: user.id, externalSub: user.emailNormalized });
    }
  }

  for (const user of attributeRefreshes) {
    // (user_id, source, attr_key) is fixed in the WHERE clause, so this UPDATE
    // cannot violate the attributes unique index — no conflict handling.
    await db
      .update(userAttributes)
      .set({
        attrValue: user.email,
        verified: user.emailVerified,
        updatedAt: user.updatedAt,
      })
      .where(
        and(
          eq(userAttributes.userId, user.id),
          eq(userAttributes.source, SELF_REPORTED_SOURCE),
          eq(userAttributes.attrKey, EMAIL_ATTR_KEY)
        )
      );
    summary.attributes.refreshed += 1;
  }

  if (credentialInserts.length === 0 && attributeInserts.length === 0) return;

  // One short transaction per batch: both inserts commit together so a crash
  // cannot leave this batch's users with a credential but no attribute. The
  // inserts are chunked because each row binds 7 parameters and a single
  // statement must stay under the Postgres extended-protocol limit of 65,535
  // bind parameters (Int16) — one unchunked INSERT at MAX_BATCH_SIZE would
  // exceed it. Chunks share the transaction, so batch atomicity is preserved.
  // The ON CONFLICT DO NOTHING is a guard against concurrent live
  // registrations, not the idempotency mechanism (see module JSDoc).
  await db.transaction(async (tx) => {
    for (let i = 0; i < credentialInserts.length; i += INSERT_CHUNK_SIZE) {
      const chunk = credentialInserts.slice(i, i + INSERT_CHUNK_SIZE);
      const result = await tx.insert(userCredentials).values(chunk).onConflictDoNothing();
      const created = result.rowCount ?? 0;
      summary.credentials.created += created;
      // Swallowed by the race guard — either a concurrent writer beat us on
      // this user, or a stale row of ANOTHER user still occupies the slot
      // (cross-user reuse). Verification is what surfaces the latter.
      summary.credentials.skipped += chunk.length - created;
    }
    for (let i = 0; i < attributeInserts.length; i += INSERT_CHUNK_SIZE) {
      const chunk = attributeInserts.slice(i, i + INSERT_CHUNK_SIZE);
      const result = await tx.insert(userAttributes).values(chunk).onConflictDoNothing();
      const created = result.rowCount ?? 0;
      summary.attributes.created += created;
      summary.attributes.skipped += chunk.length - created;
    }
  });
}

/**
 * Read-only acceptance check for AC1: every user has exactly one password
 * credential and one self-reported email attribute. Counts (a) users missing
 * the credential row, (b) users missing the attribute row, and (c) users with
 * MORE than one password credential — the duplicate the DB unique index cannot
 * rule out because it does not include `user_id`. Returns aggregate counts
 * plus a bounded sample of offending user ids for operator triage.
 */
export async function verifyIdentityBackfill(db: Database): Promise<BackfillVerification> {
  const missingCredentialJoin = and(
    eq(userCredentials.userId, users.id),
    eq(userCredentials.providerType, PASSWORD_PROVIDER_TYPE)
  );
  const [missingCredCount] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(users)
    .leftJoin(userCredentials, missingCredentialJoin)
    .where(isNull(userCredentials.id));
  const missingCredSample =
    (missingCredCount?.count ?? 0) > 0
      ? await db
          .select({ id: users.id })
          .from(users)
          .leftJoin(userCredentials, missingCredentialJoin)
          .where(isNull(userCredentials.id))
          .orderBy(asc(users.id))
          .limit(VERIFICATION_SAMPLE_SIZE)
      : [];

  const missingAttributeJoin = and(
    eq(userAttributes.userId, users.id),
    eq(userAttributes.source, SELF_REPORTED_SOURCE),
    eq(userAttributes.attrKey, EMAIL_ATTR_KEY)
  );
  const [missingAttrCount] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(users)
    .leftJoin(userAttributes, missingAttributeJoin)
    .where(isNull(userAttributes.id));
  const missingAttrSample =
    (missingAttrCount?.count ?? 0) > 0
      ? await db
          .select({ id: users.id })
          .from(users)
          .leftJoin(userAttributes, missingAttributeJoin)
          .where(isNull(userAttributes.id))
          .orderBy(asc(users.id))
          .limit(VERIFICATION_SAMPLE_SIZE)
      : [];

  // Count via a subquery and fetch only a bounded sample — mirroring the
  // missing-row checks — so a pathological duplicate count never materializes
  // one row per offending user in memory.
  const duplicateBase = () =>
    db
      .select({ userId: userCredentials.userId })
      .from(userCredentials)
      .where(eq(userCredentials.providerType, PASSWORD_PROVIDER_TYPE))
      .groupBy(userCredentials.userId)
      .having(sql`count(*) > 1`);
  const [duplicateCount] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(duplicateBase().as('duplicate_credentials'));
  const duplicateSample =
    (duplicateCount?.count ?? 0) > 0
      ? await duplicateBase().orderBy(asc(userCredentials.userId)).limit(VERIFICATION_SAMPLE_SIZE)
      : [];

  return {
    missingCredentials: missingCredCount?.count ?? 0,
    missingAttributes: missingAttrCount?.count ?? 0,
    duplicateCredentials: duplicateCount?.count ?? 0,
    missingCredentialSampleUserIds: missingCredSample.map((r) => r.id),
    missingAttributeSampleUserIds: missingAttrSample.map((r) => r.id),
    duplicateCredentialSampleUserIds: duplicateSample.map((r) => r.userId),
  };
}
