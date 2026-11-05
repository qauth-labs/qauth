import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  integer,
  jsonb,
  pgTable,
  text,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

import { realms } from './core';
import { EPOCH_MS_NOW } from './sql-helpers';

/**
 * The generic upstream OpenID Connect providers a realm signs people in
 * through (ADR-020, issue #639): one row per provider. The admin API writes
 * the rows (#714); the sign-in pages list the enabled ones, and the upstream
 * callback loads the one a sign-in went out through.
 *
 * - `type` is the provider's AuthMethod type, `oidc_` plus a lower-case alias
 *   (`oidc_corp`, `oidc_partner_sso`), unique within the realm. The CHECK is
 *   `UPSTREAM_OIDC_TYPE_PATTERN` of the federation contract. An alias holds no
 *   `:` or `/`, so it can never equal an ID-JAG type, `oidc_<issuer URL>`.
 * - `display_name` is what the sign-in page shows on the provider's button.
 * - `display_order` sorts the sign-in page's list, lowest first; ties fall to
 *   `type`.
 * - `hidden` keeps the provider off the sign-in page's list ("hide on login
 *   page"). A hidden provider that is enabled stays reachable by the
 *   direct-routing parameter, which names it.
 * - `enabled` switches the provider off for the realm without deleting it.
 * - `marks_verified` is the provider's verified switch (ADR-020 §3). On, an
 *   account created through the provider counts as verified, and its email
 *   attribute carries the provider's `email_verified` claim. Off, QAuth asks
 *   for its own verification of the address.
 * - `config` is the provider's stored config, the `StoredUpstreamOidcConfig`
 *   of `@qauth-labs/server-upstream-oidc`: issuer, client id, scopes and the
 *   like. Its client secret is sealed with the realm's `data_at_rest` key and
 *   never stored in the clear. The database library does not import that
 *   package, so the column is typed as a plain object here and the package
 *   parses what it reads.
 *
 * Deleting the realm deletes its rows.
 */
export const realmUpstreamProviders = pgTable(
  'realm_upstream_providers',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The provider's AuthMethod type, `oidc_` plus a lower-case alias. */
    type: text('type').notNull(),
    /** What the sign-in page shows for the provider. */
    displayName: text('display_name').notNull(),
    /** The provider's place in the sign-in page's list, lowest first. */
    displayOrder: integer('display_order').notNull().default(0),
    /** Left off the sign-in page's list; still reachable by direct routing. */
    hidden: boolean('hidden').notNull().default(false),
    /** Whether the realm offers the provider at all. */
    enabled: boolean('enabled').notNull().default(true),
    /** Whether an account created through the provider counts as verified. */
    marksVerified: boolean('marks_verified').notNull().default(true),
    /** The provider's stored config, its client secret sealed. */
    config: jsonb('config').$type<Record<string, unknown>>().notNull(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    // One provider per type in a realm. Its leading `realm_id` also serves
    // the realm foreign key's cascade and the listing of a realm's providers,
    // which are few enough to sort in memory.
    uniqueIndex('idx_realm_upstream_providers_realm_type_unique').on(t.realmId, t.type),
    // `UPSTREAM_OIDC_TYPE_PATTERN` of the federation contract.
    check('realm_upstream_providers_type_form', sql`${t.type} ~ '^oidc_[a-z0-9][a-z0-9_]{0,57}$'`),
    check(
      'realm_upstream_providers_display_name_length',
      sql`char_length(${t.displayName}) BETWEEN 1 AND 64`
    ),
    check('realm_upstream_providers_config_object', sql`jsonb_typeof(${t.config}) = 'object'`),
  ]
);

export const realmUpstreamProvidersRelations = relations(realmUpstreamProviders, ({ one }) => ({
  realm: one(realms, { fields: [realmUpstreamProviders.realmId], references: [realms.id] }),
}));
