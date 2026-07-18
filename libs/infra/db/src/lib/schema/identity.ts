import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  index,
  jsonb,
  pgTable,
  text,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

import { realms, users } from './core';
import { EPOCH_MS_NOW, JSONB_EMPTY_OBJECT } from './sql-helpers';

/**
 * Three-table identity model — credentials + attributes (ADR-002, issue #225).
 *
 * ADR-002 abstracts identity away from email/password: `users` is the pure
 * identity anchor, `user_credentials` holds one row per authentication method,
 * and `user_attributes` holds claims as data (with source-based trust ordering).
 *
 * As of the auth-engine refactor (#228) these two tables ARE the live runtime
 * path: login resolves password credentials via
 * `(realm_id, provider_type, external_sub)`, and register/verify/resend write
 * both tables. The legacy `users.email` / `users.email_normalized` /
 * `users.password_hash` columns are dual-written rollback shims until #230
 * removes them; the idempotent backfill (#226,
 * `../backfill/backfill-identity.ts`) populated existing rows from those
 * columns. Attribute/claim trust-order resolution (#229) and legacy column
 * removal (#230) are separate, later issues.
 */

/**
 * One row per authentication method per user (ADR-002 §Decision.2).
 *
 * `providerType` discriminates the method (`'password'`, `'wallet'`, `'oidc_*'`,
 * `'did'`); `externalSub` is the method-specific subject identifier (normalized
 * email for password, DID/issuer subject for wallet, upstream `sub` for OIDC);
 * `credentialData` is a method-specific JSONB blob (password hash +
 * `email_verified` flag for `'password'`, wallet metadata for `'wallet'`,
 * upstream claims for `'oidc_*'`).
 *
 * `providerType` is deliberately a plain `text` column rather than a Postgres
 * enum: `'oidc_*'` is an open-ended family (one value per upstream OIDC
 * provider), so adding a new provider type must not require an enum-widening
 * schema migration.
 *
 * The unique constraint on `(realm_id, provider_type, external_sub)` enforces
 * per-method uniqueness with the same query performance the legacy
 * `(realm_id, email_normalized)` index gave password login.
 */
export const userCredentials = pgTable(
  'user_credentials',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /**
     * Authentication method discriminator: `'password' | 'wallet' | 'oidc_*' |
     * 'did'`. Plain text (not a pgEnum) so the open-ended `oidc_*` family can
     * gain new members without a schema migration.
     */
    providerType: text('provider_type').notNull(),
    /** Method-specific subject identifier (email / DID / upstream `sub`). */
    externalSub: text('external_sub').notNull(),
    /**
     * Method-specific JSONB payload. For `'password'`: `{ password_hash,
     * email_verified }`. For `'wallet'`: wallet/VC metadata. For `'oidc_*'`:
     * upstream claims. Guarded by a `jsonb_typeof = 'object'` CHECK so a
     * malformed (non-object) value cannot be persisted even if a future writer
     * bypasses the typed `$type` helper — mirrors the array guards on
     * `oauth_clients.audience` and `audit_logs.delegation_chain`.
     */
    credentialData: jsonb('credential_data')
      .notNull()
      .default(JSONB_EMPTY_OBJECT)
      .$type<Record<string, unknown>>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    uniqueIndex('idx_user_credentials_realm_provider_sub_unique').on(
      t.realmId,
      t.providerType,
      t.externalSub
    ),
    index('idx_user_credentials_user_id').on(t.userId),
    index('idx_user_credentials_realm_id').on(t.realmId),
    check(
      'user_credentials_credential_data_is_object',
      sql`jsonb_typeof(${t.credentialData}) = 'object'`
    ),
  ]
);

/**
 * Claims and attributes as data, not identity anchors (ADR-002 §Decision.3).
 *
 * Each row records one attribute (`attrKey`/`attrValue`, e.g. `email`) with the
 * `source` it came from (`'self_reported'`, `'wallet'`, `'oidc_google'`, …) and
 * whether it is `verified`. Email lives here, never on `users`.
 *
 * `source` is a plain `text` column (not a pgEnum) for the same open-ended
 * reason as `user_credentials.provider_type`. The claim-resolution trust order
 * (`wallet > oidc_* > self_reported`) is enforced in application code (issue
 * #229), NOT as a DB constraint.
 *
 * A unique constraint on `(user_id, source, attr_key)` IS enforced at the DB
 * level: one value per attribute per source per user (e.g. at most one
 * `source='wallet', attr_key='email'` row). Writers must account for it: the
 * #226 backfill (`../backfill/backfill-identity.ts`) inserts with
 * `ON CONFLICT DO NOTHING` as a race guard and keys its skip/refresh logic on
 * `user_id`, while the runtime writer (`upsertMany`, shipped in #228) upserts
 * (`ON CONFLICT (user_id, source, attr_key) DO UPDATE`). Multiple *sources*
 * can still each hold their own value for the same `attr_key` — trust-order
 * resolution across those rows is the application-code concern noted above.
 */
export const userAttributes = pgTable(
  'user_attributes',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /**
     * Origin of the attribute, e.g. `'self_reported' | 'wallet' | 'oidc_google'`.
     * Drives claim-resolution trust order in app code (#229). Plain text so new
     * upstream sources need no schema migration.
     */
    source: text('source').notNull(),
    /** Attribute name, e.g. `'email'`, `'name'`, `'birthdate'`. */
    attrKey: text('attr_key').notNull(),
    /** Attribute value as text. */
    attrValue: text('attr_value').notNull(),
    verified: boolean('verified').notNull().default(false),
    /** Optional expiry for VC-derived attributes; null for self-reported ones. */
    expiresAt: bigint('expires_at', { mode: 'number' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    uniqueIndex('idx_user_attributes_user_source_key_unique').on(t.userId, t.source, t.attrKey),
    index('idx_user_attributes_user_id').on(t.userId),
  ]
);

export const userCredentialsRelations = relations(userCredentials, ({ one }) => ({
  user: one(users, { fields: [userCredentials.userId], references: [users.id] }),
  realm: one(realms, { fields: [userCredentials.realmId], references: [realms.id] }),
}));

export const userAttributesRelations = relations(userAttributes, ({ one }) => ({
  user: one(users, { fields: [userAttributes.userId], references: [users.id] }),
}));
