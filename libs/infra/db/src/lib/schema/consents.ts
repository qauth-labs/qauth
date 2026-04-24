import { relations, sql } from 'drizzle-orm';
import { bigint, index, jsonb, pgTable, uniqueIndex, uuid } from 'drizzle-orm/pg-core';

import { oauthClients, realms, users } from './core';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY } from './sql-helpers';

/**
 * OAuth user consent records.
 *
 * One row per (user, client, realm) — stores the set of scopes the user has
 * granted. Consent is indefinite once granted; revocation sets `revokedAt`
 * and the row is retained for audit purposes.
 *
 * Scope-subset check: a new authorization request can skip the consent screen
 * iff every requested scope is present in an active (not revoked) consent
 * record's `scopes` array. See `apps/auth-server/.../helpers/consent.ts`.
 */
export const oauthConsents = pgTable(
  'oauth_consents',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    oauthClientId: uuid('oauth_client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    scopes: jsonb('scopes').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    grantedAt: bigint('granted_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    revokedAt: bigint('revoked_at', { mode: 'number' }),
  },
  (t) => [
    // Active (not revoked) consent per (user, client) is unique — a revoke
    // followed by a new grant creates a new row rather than mutating.
    uniqueIndex('idx_oauth_consents_user_client_active')
      .on(t.userId, t.oauthClientId)
      .where(sql`${t.revokedAt} IS NULL`),
    index('idx_oauth_consents_user_id').on(t.userId),
    index('idx_oauth_consents_client_id').on(t.oauthClientId),
    index('idx_oauth_consents_realm_id').on(t.realmId),
  ]
);

export const oauthConsentsRelations = relations(oauthConsents, ({ one }) => ({
  user: one(users, { fields: [oauthConsents.userId], references: [users.id] }),
  oauthClient: one(oauthClients, {
    fields: [oauthConsents.oauthClientId],
    references: [oauthClients.id],
  }),
  realm: one(realms, { fields: [oauthConsents.realmId], references: [realms.id] }),
}));
