import { sql } from 'drizzle-orm';
import { bigint, check, pgTable, primaryKey, text, uuid, varchar } from 'drizzle-orm/pg-core';

import { realms } from './core';
import { EPOCH_MS_NOW } from './sql-helpers';

/**
 * The values of a realm's secret policy fields (ADR-019 Decisions 9 and 10,
 * issue #529), such as the SMTP password and the Resend API key of its mail
 * transport. The realm policies never hold them: the policy document, the
 * admin API's representation and the realm file name a secret only as
 * `<name>Set`.
 *
 * One row per realm and field path (`name`, as the policy registry names the
 * field: `mail.smtp.password`).
 *
 * - `ciphertext` is the value encrypted with the realm's `data_at_rest` key by
 *   the signer (`v1.<kid>.<iv>.<ciphertext>`), under a context that names the
 *   field, so a ciphertext copied to another field or realm does not decrypt.
 *   No other form is ever stored: the CHECKs refuse a value that is not in the
 *   signer's format, or whose `kid` is not `key_id`, so a plaintext written by
 *   mistake fails the write.
 * - `key_id` is the `kid` of the key that encrypted it, in a column of its own
 *   so a key rotation can find the rows to encrypt again.
 * - A row whose `ciphertext` and `key_id` are both NULL is a secret that holds
 *   no value: one an admin cleared, or one the environment did not seed when
 *   the realm's secrets were first seeded. The row stays, so the boot never
 *   seeds that field again from the environment.
 *
 * Deleting the realm deletes its secrets.
 */
export const realmSecrets = pgTable(
  'realm_secrets',
  {
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The secret field's path in the realm policy schema, such as `mail.smtp.password`. */
    name: varchar('name', { length: 128 }).notNull(),
    /** The value, encrypted by the signer with the realm's `data_at_rest` key; NULL when none is set. */
    ciphertext: text('ciphertext'),
    /** The `kid` of the `data_at_rest` key that encrypted `ciphertext`; NULL exactly when it is. */
    keyId: varchar('key_id', { length: 255 }),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    primaryKey({ columns: [t.realmId, t.name], name: 'realm_secrets_pk' }),
    // A dotted path of lower camelCase words, as the policy registry writes one.
    check('realm_secrets_name_form', sql`${t.name} ~ '^[a-z][a-zA-Z0-9]*(\\.[a-z][a-zA-Z0-9]*)+$'`),
    check(
      'realm_secrets_value_and_key_together',
      sql`(${t.ciphertext} IS NULL) = (${t.keyId} IS NULL)`
    ),
    // Only the signer's `data_at_rest` format, never a plaintext: version,
    // kid, nonce and ciphertext, each base64url, and the kid is `key_id`.
    check(
      'realm_secrets_ciphertext_form',
      sql`${t.ciphertext} IS NULL OR (${t.ciphertext} ~ '^v1\\.[A-Za-z0-9_-]{1,255}\\.[A-Za-z0-9_-]{16}\\.[A-Za-z0-9_-]{22,}$' AND split_part(${t.ciphertext}, '.', 2) = ${t.keyId})`
    ),
  ]
);
