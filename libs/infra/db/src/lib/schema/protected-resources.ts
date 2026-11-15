import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  integer,
  jsonb,
  pgTable,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { realms } from './core';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY } from './sql-helpers';

/**
 * One scope a protected resource defines (#1087): its value, the consent
 * text the consent step shows for it by BCP 47 locale (`en` always among
 * them, the fallback), and whether the realm flags it as sensitive. The
 * shape of a scope catalog entry (#702).
 */
export interface ProtectedResourceScope {
  readonly scope: string;
  readonly text: Readonly<Record<string, string>>;
  readonly sensitive: boolean;
}

/**
 * The protected resources a realm registered (RFC 8707 resource indicators,
 * RFC 9728 protected resources; issue #1087), with the scopes each defines
 * and the clients that may ask for them.
 *
 * A scope a registered resource defines is bound to it: `/oauth/authorize`
 * grants it only when the request names the resource (`resource`), and then
 * to any client the resource is open to, CIMD and dynamically registered
 * clients included, whatever the client's own `scopes` list holds; asked for
 * without the resource, or with another, it is dropped. So a token's `aud`
 * and the resource scopes it carries always agree. The user's consent is
 * still required, and is recorded per resource (`oauth_consents.resource_scopes`).
 *
 * - `resource` is the resource indicator, matched exactly: an absolute URI
 *   with no fragment, never a QAuth API audience (`urn:qauth:aud:`). One row
 *   per realm and resource.
 * - `scopes` holds the {@link ProtectedResourceScope} entries, one per scope
 *   value. None is one of QAuth's own scopes (`openid`, `profile`, `email`,
 *   `offline_access`, `agent:*`, `qauth:*`): the writers refuse them.
 * - `any_client`: every client of the realm may ask for the scopes. When it
 *   is false, `client_ids` lists the `client_id`s that may (a CIMD client by
 *   its URL), and every other client gets none of them. A listed client
 *   that does not exist matches nothing; one deleted and registered again
 *   under the same `client_id` matches again.
 * - `version` rises by one with every write: the admin API's entity tag.
 *
 * Written by the admin API (`protectedResources.*`, security operations) and
 * the seed manifest's `resources` section; read by every path that grants a
 * user's scopes. Deleting the realm deletes its rows.
 */
export const protectedResources = pgTable(
  'protected_resources',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The RFC 8707 resource indicator, matched exactly. */
    resource: varchar('resource', { length: 2048 }).notNull(),
    /** The scopes the resource defines, with their consent texts. */
    scopes: jsonb('scopes').$type<ProtectedResourceScope[]>().notNull().default(JSONB_EMPTY_ARRAY),
    /** Whether every client of the realm may ask for the scopes. */
    anyClient: boolean('any_client').notNull().default(false),
    /** The `client_id`s that may, when {@link anyClient} is false. */
    clientIds: jsonb('client_ids').$type<string[]>().notNull().default(JSONB_EMPTY_ARRAY),
    /** Raised by one with every write. */
    version: integer('version').notNull().default(1),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    // Also the index of a realm's list: `realm_id` leads it.
    unique('protected_resources_realm_resource').on(t.realmId, t.resource),
    check(
      'protected_resources_resource_form',
      sql`${t.resource} <> '' AND strpos(${t.resource}, '#') = 0`
    ),
    check('protected_resources_scopes_array', sql`jsonb_typeof(${t.scopes}) = 'array'`),
    check('protected_resources_client_ids_array', sql`jsonb_typeof(${t.clientIds}) = 'array'`),
    // Open to every client, or to the listed ones: never both.
    check(
      'protected_resources_any_client_lists_none',
      sql`NOT ${t.anyClient} OR ${t.clientIds} = '[]'::jsonb`
    ),
    check('protected_resources_version_positive', sql`${t.version} > 0`),
  ]
);
