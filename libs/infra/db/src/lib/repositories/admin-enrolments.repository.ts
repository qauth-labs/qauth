import { createHash, randomBytes } from 'node:crypto';

import { and, eq, gt, type InferSelectModel, isNull } from 'drizzle-orm';

import type { DbClient } from '../../types';
import { adminEnrolments } from '../schema/admin-enrolments';

/** A stored admin enrolment (issue #602): never its token, only the token's hash. */
export type AdminEnrolment = InferSelectModel<typeof adminEnrolments>;

/** How many random bytes an enrolment token holds (ADR-019 Decision 7, #602). */
export const ADMIN_ENROLMENT_TOKEN_BYTES = 32;

/** How long an enrolment token is valid by default: one hour, in ms. */
export const ADMIN_ENROLMENT_DEFAULT_TTL_MS = 60 * 60 * 1000;

/**
 * An enrolment token as the URL carries it: its 32 bytes in unpadded
 * base64url, 43 characters.
 */
const TOKEN_FORM = /^[A-Za-z0-9_-]{43}$/;

/** A row id: a malformed one is answered without a query. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The stored hash of an enrolment token: SHA-256 over its 32 bytes, or
 * `undefined` for a string that is not a token in its one canonical form, so a
 * second spelling of the same bytes never names the same row.
 */
export function adminEnrolmentTokenHash(token: string): Buffer | undefined {
  if (typeof token !== 'string' || !TOKEN_FORM.test(token)) return undefined;
  const bytes = Buffer.from(token, 'base64url');
  if (bytes.length !== ADMIN_ENROLMENT_TOKEN_BYTES || bytes.toString('base64url') !== token) {
    return undefined;
  }
  return createHash('sha256').update(bytes).digest();
}

/** A new enrolment, as {@link AdminEnrolmentsRepository.issue} takes it. */
export interface NewAdminEnrolment {
  /** The realm the account lives in. */
  readonly realmId: string;
  /** The admin account, of that realm, with no credential yet. */
  readonly userId: string;
  /** Epoch ms: when the token is made. */
  readonly createdAt: number;
  /** Epoch ms: from this moment the token is refused. After `createdAt`. */
  readonly expiresAt: number;
}

/** What {@link AdminEnrolmentsRepository.issue} wrote, and the token it made. */
export interface IssuedAdminEnrolment {
  readonly enrolment: AdminEnrolment;
  /**
   * The token, in the form the enrolment URL carries. It exists only here:
   * the row holds its hash. Print it once and keep it nowhere.
   */
  readonly token: string;
}

/** An enrolment redeemed: the account to register a first passkey for. */
export interface RedeemedAdminEnrolment {
  readonly id: string;
  readonly realmId: string;
  readonly userId: string;
  readonly expiresAt: number;
  readonly usedAt: number;
}

/**
 * One-time admin enrolments (ADR-019 Decision 7, issue #602). See the table
 * (`schema/admin-enrolments.ts`).
 *
 * The repository makes and checks the tokens itself, so the token's form and
 * its hash live in one place: a caller hands the token as the URL carries it,
 * never a hash.
 */
export interface AdminEnrolmentsRepository {
  /**
   * Make a token of {@link ADMIN_ENROLMENT_TOKEN_BYTES} random bytes and store
   * its hash for the account. Only the hash is written.
   */
  issue(enrolment: NewAdminEnrolment, tx?: DbClient): Promise<IssuedAdminEnrolment>;

  /**
   * Redeem `token` for an account of the realm, once: one conditional update
   * marks it used when it is the realm's, unused and not yet expired at `now`,
   * and returns the account. `undefined` for a token that is malformed,
   * unknown, of another realm, used or expired, alike, so a caller answers
   * every one of them the same.
   */
  redeem(
    realmId: string,
    token: string,
    now: number,
    tx?: DbClient
  ): Promise<RedeemedAdminEnrolment | undefined>;

  /** The account's enrolment, in the realm, or `undefined`. */
  findByUser(realmId: string, userId: string, tx?: DbClient): Promise<AdminEnrolment | undefined>;
}

/**
 * @param defaultDb - the database a call without a transaction runs on
 */
export function createAdminEnrolmentsRepository(defaultDb: DbClient): AdminEnrolmentsRepository {
  return {
    async issue(enrolment, tx) {
      if (!(enrolment.expiresAt > enrolment.createdAt)) {
        throw new RangeError('An admin enrolment expires after it is made');
      }
      const bytes = randomBytes(ADMIN_ENROLMENT_TOKEN_BYTES);
      const token = bytes.toString('base64url');
      const tokenHash = createHash('sha256').update(bytes).digest();
      bytes.fill(0);
      const [row] = await (tx ?? defaultDb)
        .insert(adminEnrolments)
        .values({
          realmId: enrolment.realmId,
          userId: enrolment.userId,
          tokenHash,
          createdAt: enrolment.createdAt,
          expiresAt: enrolment.expiresAt,
        })
        .returning();
      if (row === undefined) throw new Error('The admin enrolment was not written');
      return { enrolment: row, token };
    },

    async redeem(realmId, token, now, tx) {
      const tokenHash = adminEnrolmentTokenHash(token);
      if (tokenHash === undefined || !UUID.test(realmId)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .update(adminEnrolments)
        .set({ usedAt: now })
        .where(
          and(
            eq(adminEnrolments.tokenHash, tokenHash),
            eq(adminEnrolments.realmId, realmId),
            isNull(adminEnrolments.usedAt),
            gt(adminEnrolments.expiresAt, now)
          )
        )
        .returning({
          id: adminEnrolments.id,
          realmId: adminEnrolments.realmId,
          userId: adminEnrolments.userId,
          expiresAt: adminEnrolments.expiresAt,
          usedAt: adminEnrolments.usedAt,
        });
      if (row === undefined || row.usedAt === null) return undefined;
      return { ...row, usedAt: row.usedAt };
    },

    async findByUser(realmId, userId, tx) {
      if (!UUID.test(realmId) || !UUID.test(userId)) return undefined;
      const [row] = await (tx ?? defaultDb)
        .select()
        .from(adminEnrolments)
        .where(and(eq(adminEnrolments.realmId, realmId), eq(adminEnrolments.userId, userId)))
        .limit(1);
      return row;
    },
  };
}
