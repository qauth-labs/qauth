import {
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, eq, isNotNull, isNull, sql } from 'drizzle-orm';

import type { NewUserCredential, UserCredential, UserCredentialsRepository } from '../../types';
import { DbClient } from '../db';
import { users } from '../schema/core';
import { userCredentials } from '../schema/identity';

/** The `provider_type` of a password credential (`PASSWORD_PROVIDER_TYPE` of `@qauth-labs/server-federation`). */
const PASSWORD_PROVIDER_TYPE = 'password';

/**
 * The `provider_type` of a TOTP credential (#653; `TOTP_PROVIDER_TYPE` of
 * `@qauth-labs/fastify-plugin-sign-in-engine`): one per account, its
 * `external_sub` the user id, its `credential_data` `{ secret, last_step }`
 * (the secret a `data_at_rest` ciphertext, the last accepted time step).
 */
const TOTP_PROVIDER_TYPE = 'totp';

/**
 * The keys of `credential_data` a password credential's password owns
 * (`passwordCredentialDataSchema` of `@qauth-labs/server-federation`): what
 * {@link UserCredentialsRepository.updatePassword} replaces.
 */
const PASSWORD_DATA_KEYS = `{password_hash,email_verified,password_normalization}`;

/**
 * Insert one credential row, mapping a `(realm_id, provider_type,
 * external_sub)` conflict to {@link UniqueConstraintError}. `isPrimary` is
 * for the users repository's account creation only (#846): the database
 * refuses the mark on any credential but a user's first.
 */
export async function insertUserCredential(
  invoker: DbClient,
  data: NewUserCredential & { readonly isPrimary: boolean }
): Promise<UserCredential> {
  try {
    const [credential] = await invoker.insert(userCredentials).values(data).returning();
    return credential;
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      const constraint =
        extractConstraintName(error) || 'idx_user_credentials_realm_provider_sub_unique';
      throw new UniqueConstraintError(constraint, error);
    }
    throw error;
  }
}

/**
 * Factory for the `user_credentials` repository (ADR-002/ADR-003, #228).
 *
 * `credential_data` stays `Record<string, unknown>` at this layer — shape
 * interpretation belongs to the provider that owns the `provider_type` (for
 * `'password'`: `passwordCredentialDataSchema` in `@qauth-labs/server-federation`),
 * keeping the repository provider-agnostic.
 */
export function createUserCredentialsRepository(defaultDb: DbClient): UserCredentialsRepository {
  return {
    /**
     * Create a credential row for an account that exists: never its primary
     * identity, which the users repository writes with the account (#846).
     *
     * @throws UniqueConstraintError on a `(realm_id, provider_type,
     * external_sub)` conflict — same wire behavior (generic 409) as the users
     * repository's duplicate-email error, so even the pathological path where
     * the credential index fires before the users index maps identically.
     */
    async create(data: NewUserCredential, tx?: DbClient): Promise<UserCredential> {
      return insertUserCredential(tx ?? defaultDb, { ...data, isPrimary: false });
    },

    /**
     * The account's primary identity (ADR-015 Decision 8, #846): the
     * credential that created it, or `undefined` when the account has none
     * (its primary credential was deleted, before migration 0068 marked it
     * or after). A credential of another realm is none.
     */
    async findPrimaryByUserId(
      realmId: string,
      userId: string,
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .select()
        .from(userCredentials)
        .where(
          and(
            eq(userCredentials.realmId, realmId),
            eq(userCredentials.userId, userId),
            eq(userCredentials.isPrimary, true)
          )
        )
        .limit(1);
      return credential;
    },

    /** A credential of the realm by id; one of another realm is not found (#489). */
    async findById(
      realmId: string,
      id: string,
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .select()
        .from(userCredentials)
        .where(and(eq(userCredentials.realmId, realmId), eq(userCredentials.id, id)))
        .limit(1);
      return credential;
    },

    /**
     * The login/resend hot path: unique-index lookup on
     * `(realm_id, provider_type, external_sub)` — same performance profile as
     * the legacy `(realm_id, email_normalized)` lookup it replaces.
     */
    async findByRealmProviderSub(
      realmId: string,
      providerType: string,
      externalSub: string,
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .select()
        .from(userCredentials)
        .where(
          and(
            eq(userCredentials.realmId, realmId),
            eq(userCredentials.providerType, providerType),
            eq(userCredentials.externalSub, externalSub)
          )
        )
        .limit(1);
      return credential;
    },

    /**
     * Resolve a user's credential for one provider type. Rollback-window
     * fallback for verification tokens whose `credential_id` is NULL (#228);
     * exactly one `'password'` row per user is guaranteed by #226/#228 writes.
     */
    async findByUserIdAndType(
      userId: string,
      providerType: string,
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .select()
        .from(userCredentials)
        .where(
          and(eq(userCredentials.userId, userId), eq(userCredentials.providerType, providerType))
        )
        .limit(1);
      return credential;
    },

    /**
     * Every credential in a realm carrying this `external_sub`, ACROSS PROVIDER
     * TYPES (#235/#238, ADR-009 §1).
     *
     * The read behind `SubjectAccountLookup.byAssertedIdentifier`, and the reason
     * it is not {@link findByRealmProviderSub}: `asserted-lookup` must see the
     * `'password'` row that already holds the asserted email, not only wallet
     * rows. An account that exists without a wallet binding is ADR-009's second
     * bootstrap case — a REFUSAL — and a query scoped to `provider_type='wallet'`
     * would report it as "no account found", which the caller is allowed to turn
     * into an enrolment. That is precisely the account takeover the bootstrap
     * rule exists to prevent.
     *
     * No `limit`: the caller (`selectSoleAccount`) must SEE an ambiguity to fail
     * closed on it, and a `limit(1)` here would silently pick the first row —
     * exactly the "never pick one" rule #300's constraint 5 forbids.
     *
     * Bounded by the unique index on `(realm_id, provider_type, external_sub)` —
     * at most one row per provider type, so the result set is the size of the
     * provider registry, not of the realm.
     */
    async findAllByRealmAndExternalSub(
      realmId: string,
      externalSub: string,
      tx?: DbClient
    ): Promise<UserCredential[]> {
      const invoker = tx ?? defaultDb;
      return invoker
        .select()
        .from(userCredentials)
        .where(
          and(eq(userCredentials.realmId, realmId), eq(userCredentials.externalSub, externalSub))
        );
    },

    /**
     * Every credential a user holds for one provider type (#238).
     *
     * The plural sibling of {@link findByUserIdAndType}: an account may hold
     * more than one wallet credential (a second device, a re-issued credential),
     * and account linking has to see all of them rather than whichever the
     * planner returned first.
     */
    async findAllByUserIdAndType(
      userId: string,
      providerType: string,
      tx?: DbClient
    ): Promise<UserCredential[]> {
      const invoker = tx ?? defaultDb;
      return invoker
        .select()
        .from(userCredentials)
        .where(
          and(eq(userCredentials.userId, userId), eq(userCredentials.providerType, providerType))
        );
    },

    /**
     * Every credential a user holds, of every provider type: the account a
     * sign-in proved, read once with all its factors and upstream identities
     * (#639). Bounded by the user's own credentials.
     */
    async findAllByUserId(userId: string, tx?: DbClient): Promise<UserCredential[]> {
      const invoker = tx ?? defaultDb;
      return invoker.select().from(userCredentials).where(eq(userCredentials.userId, userId));
    },

    /**
     * Replace `credential_data` wholesale (#238).
     *
     * @throws NotFoundError if the credential does not exist.
     */
    async updateCredentialData(
      id: string,
      credentialData: Record<string, unknown>,
      tx?: DbClient
    ): Promise<UserCredential> {
      const invoker = tx ?? defaultDb;

      const [credential] = await invoker
        .update(userCredentials)
        .set({ credentialData, updatedAt: Date.now() })
        .where(eq(userCredentials.id, id))
        .returning();

      if (!credential) {
        throw new NotFoundError('UserCredential', id);
      }
      return credential;
    },

    /**
     * Flip `credential_data.email_verified` to true in place.
     *
     * A single `jsonb_set` statement — no read-modify-write — so a concurrent
     * writer touching a sibling key can never be clobbered. The ONLY
     * `credential_data` mutation shipped in #228.
     *
     * @throws NotFoundError if the credential does not exist.
     */
    async setEmailVerified(id: string, tx?: DbClient): Promise<UserCredential> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [credential] = await invoker
        .update(userCredentials)
        .set({
          credentialData: sql`jsonb_set(${userCredentials.credentialData}, '{email_verified}', 'true'::jsonb)`,
          updatedAt: now,
        })
        .where(eq(userCredentials.id, id))
        .returning();

      if (!credential) {
        throw new NotFoundError('UserCredential', id);
      }
      return credential;
    },

    /**
     * Replace a `password` credential's password (#642): the owner's reset.
     * One statement, so a concurrent writer of a sibling key keeps it: the
     * three keys the password shape owns are dropped and `passwordData`
     * merged in, and the disabled mark cleared with them. An expected hash
     * is compared in the same statement's `WHERE`, which Postgres checks
     * again on the row a concurrent writer left (#844).
     */
    async updatePassword(
      realmId: string,
      id: string,
      passwordData: Readonly<Record<string, unknown>>,
      tx?: DbClient,
      options?: { readonly expectedPasswordHash?: string }
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const expected = options?.expectedPasswordHash;
      const [credential] = await invoker
        .update(userCredentials)
        .set({
          credentialData: sql`(${userCredentials.credentialData} - ${PASSWORD_DATA_KEYS}::text[]) || ${JSON.stringify(passwordData)}::jsonb`,
          disabledAt: null,
          updatedAt: Date.now(),
        })
        .where(
          and(
            eq(userCredentials.realmId, realmId),
            eq(userCredentials.id, id),
            eq(userCredentials.providerType, PASSWORD_PROVIDER_TYPE),
            expected === undefined
              ? undefined
              : sql`${userCredentials.credentialData} ->> 'password_hash' = ${expected}`
          )
        )
        .returning();
      return credential;
    },

    /**
     * Set the failure ladder's disabled mark (ADR-017 Decision 7, #615) on
     * the credential the unique `(realm_id, provider_type, external_sub)`
     * names, in one statement that changes only an unmarked row: of two
     * callers at once, one sets the mark and gets the row back, the other
     * gets `undefined`, so the hard action fires once per mark.
     */
    async setDisabledAt(
      realmId: string,
      providerType: string,
      externalSub: string,
      disabledAt: number,
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .update(userCredentials)
        .set({ disabledAt, updatedAt: Date.now() })
        .where(
          and(
            eq(userCredentials.realmId, realmId),
            eq(userCredentials.providerType, providerType),
            eq(userCredentials.externalSub, externalSub),
            isNull(userCredentials.disabledAt)
          )
        )
        .returning();
      return credential;
    },

    /**
     * Take the TOTP time step `step` for the account (#653; RFC 6238 §5.2),
     * in one statement that changes only an enabled TOTP whose last accepted
     * step is lower: of two rounds with the same code, one takes the step.
     * A last step that is not a number matches nothing rather than failing.
     */
    async acceptTotpStep(
      realmId: string,
      userId: string,
      step: number,
      tx?: DbClient
    ): Promise<boolean> {
      if (!Number.isSafeInteger(step) || step < 0) return false;
      const invoker = tx ?? defaultDb;
      const lastStep = sql`${userCredentials.credentialData} -> 'last_step'`;
      const rows = await invoker
        .update(userCredentials)
        .set({
          credentialData: sql`jsonb_set(${userCredentials.credentialData}, '{last_step}', to_jsonb(${step}::bigint))`,
          updatedAt: Date.now(),
        })
        .where(
          and(
            eq(userCredentials.realmId, realmId),
            eq(userCredentials.providerType, TOTP_PROVIDER_TYPE),
            eq(userCredentials.externalSub, userId),
            eq(userCredentials.userId, userId),
            isNull(userCredentials.disabledAt),
            sql`CASE WHEN jsonb_typeof(${lastStep}) = 'number' THEN (${lastStep})::numeric < ${step}::numeric ELSE false END`
          )
        )
        .returning({ id: userCredentials.id });
      return rows.length === 1;
    },

    /**
     * Bind a TOTP to the account (#653), replacing the one it holds: one
     * statement inserts the row, or rewrites the account's own with the new
     * `credential_data` and clears its disabled mark. A row of the realm's
     * `(totp, user id)` that names another user is never rewritten.
     *
     * @returns the credential; `undefined` when such a row of another user
     *   stood in the way
     */
    async upsertTotp(
      input: {
        readonly realmId: string;
        readonly userId: string;
        readonly credentialData: Readonly<Record<string, unknown>>;
        readonly at: number;
      },
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .insert(userCredentials)
        .values({
          userId: input.userId,
          realmId: input.realmId,
          providerType: TOTP_PROVIDER_TYPE,
          externalSub: input.userId,
          credentialData: { ...input.credentialData },
          createdAt: input.at,
          updatedAt: input.at,
        })
        .onConflictDoUpdate({
          target: [
            userCredentials.realmId,
            userCredentials.providerType,
            userCredentials.externalSub,
          ],
          set: {
            credentialData: sql`excluded.credential_data`,
            disabledAt: null,
            updatedAt: input.at,
          },
          setWhere: eq(userCredentials.userId, input.userId),
        })
        .returning();
      return credential;
    },

    /**
     * Clear the disabled mark (#615) of the credential `(realm_id,
     * provider_type, external_sub)` names, in one statement that changes
     * only a marked row.
     */
    async clearDisabledAt(
      realmId: string,
      providerType: string,
      externalSub: string,
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .update(userCredentials)
        .set({ disabledAt: null, updatedAt: Date.now() })
        .where(
          and(
            eq(userCredentials.realmId, realmId),
            eq(userCredentials.providerType, providerType),
            eq(userCredentials.externalSub, externalSub),
            isNotNull(userCredentials.disabledAt)
          )
        )
        .returning();
      return credential;
    },

    /**
     * Lock the user's row until `tx` ends (#670): `SELECT … FOR NO KEY
     * UPDATE`, which serializes every change to one account's set of
     * credentials that takes it and lets an insert that only references the
     * user through. `false` when the realm has no such user.
     */
    async lockUser(realmId: string, userId: string, tx: DbClient): Promise<boolean> {
      const [user] = await tx
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.realmId, realmId), eq(users.id, userId)))
        .limit(1)
        .for('no key update');
      return user !== undefined;
    },

    /** Delete one credential of the realm by id (#670); the deleted row, or `undefined`. */
    async deleteById(
      realmId: string,
      id: string,
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .delete(userCredentials)
        .where(and(eq(userCredentials.realmId, realmId), eq(userCredentials.id, id)))
        .returning();
      return credential;
    },
  };
}
