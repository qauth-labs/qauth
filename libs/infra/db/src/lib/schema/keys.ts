import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  jsonb,
  pgTable,
  primaryKey,
  smallint,
  text,
  unique,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { realms } from './core';
import { realmKeyStatusEnum } from './enums';
import { bytea, EPOCH_MS_NOW } from './sql-helpers';

/**
 * A realm's keys, envelope-encrypted (ADR-019 Decision 9, issue #461).
 *
 * One row per key, per realm and per purpose: token signing, event signing,
 * the cookie HMAC, data at rest and the rest of ADR-019's list. The purpose
 * vocabulary is data owned by the keys library (`KEY_PURPOSES`, #463), so
 * `purpose` and `algorithm` are plain strings here, the way
 * `user_credentials.provider_type` and `oid4vp_request_states.verifier_profile`
 * are.
 *
 * ## The secret columns
 *
 * `ciphertext` is the key material encrypted under a per-key data key (DEK)
 * with AES-256-GCM and `iv`; `wrapped_dek` is that DEK wrapped by the
 * key-encryption key (KEK) that `kek_ref` names. `aad_version` names the
 * layout of the associated data the envelope bound in (realm, purpose, scope,
 * `kid`, algorithm), so a row copied to another realm fails to decrypt. A KEK
 * rotation re-wraps `wrapped_dek` only and rewrites `kek_ref` (#545).
 *
 * Only the signer's database user may read this table (ADR-019 Decision 9; the
 * grants are #498). Every other role reads {@link realmPublicKeys}. Inside the
 * code base the same rule holds one level up: the repository returns the
 * three secret columns from ONE method, `getWrappedForSigner`, and no other
 * method selects them.
 *
 * ## Lifecycle
 *
 * `status` moves `next` → `active` → `retired`, or to `compromised` from any
 * of them (emergency retirement). The time columns record the schedule and
 * the facts, all epoch ms:
 *
 * - `publish_at` / `unpublish_at` — the JWKS window. NULL for symmetric
 *   purposes (cookie HMAC, data at rest, webhook secrets), which are never
 *   published.
 * - `activate_at` — when the key starts to sign or encrypt.
 * - `retire_at` — when it stops; it still verifies or decrypts after.
 * - `compromised_at` — set exactly when `status = 'compromised'` (a CHECK).
 *
 * ## Scoped keys and hybrid pairs
 *
 * `scope_id` names the one thing a scoped purpose belongs to: the webhook
 * subscription of a webhook signing key, or the upstream provider of a
 * client-assertion key (#547). It is a string with no foreign key because
 * those owners live in different tables (or in configuration), and the
 * owner's deletion removes its key rows. NULL for every unscoped purpose.
 *
 * `pair_id` is shared by the Ed25519 and ML-DSA-65 keys of a hybrid signing
 * pair (ADR-005), so the two rotate and retire together. It is a group id, not
 * a row reference.
 */
export const realmKeys = pgTable(
  'realm_keys',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** Owning realm. A deleted realm takes its keys with it. */
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** Key purpose, e.g. `token_signing` or `cookie_hmac` (`KEY_PURPOSES`, #463). */
    purpose: varchar('purpose', { length: 64 }).notNull(),
    /** Owner of a scoped key (subscription or upstream provider id); NULL when unscoped. */
    scopeId: varchar('scope_id', { length: 255 }),
    /** Algorithm the key is for, e.g. `EdDSA`, `ML-DSA-65`, `ES256`, `HS256`. */
    algorithm: varchar('algorithm', { length: 32 }).notNull(),
    /**
     * Key id: the RFC 7638 thumbprint for an asymmetric key, a random id for a
     * symmetric one (#463). Unique within the realm, across every purpose and
     * status, so a `kid` in a token header names exactly one key.
     */
    kid: varchar('kid', { length: 255 }).notNull(),
    status: realmKeyStatusEnum('status').notNull(),
    /** Shared by both keys of a hybrid pair; NULL for a key outside a pair. */
    pairId: uuid('pair_id'),
    /** Key material, AES-256-GCM-encrypted under the data key. */
    ciphertext: bytea('ciphertext').notNull(),
    /** GCM nonce used for `ciphertext`. */
    iv: bytea('iv').notNull(),
    /** The data key, wrapped by the KEK `kek_ref` names. */
    wrappedDek: bytea('wrapped_dek').notNull(),
    /**
     * Which KEK wrapped `wrapped_dek`: a fingerprint for the local provider,
     * the key version for a KMS adapter. `text` because an adapter's key
     * version name is the adapter's to choose.
     */
    kekRef: text('kek_ref').notNull(),
    /** Version of the associated-data layout the envelope bound in. */
    aadVersion: smallint('aad_version').notNull(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    publishAt: bigint('publish_at', { mode: 'number' }),
    activateAt: bigint('activate_at', { mode: 'number' }),
    retireAt: bigint('retire_at', { mode: 'number' }),
    unpublishAt: bigint('unpublish_at', { mode: 'number' }),
    compromisedAt: bigint('compromised_at', { mode: 'number' }),
  },
  (t) => [
    unique('realm_keys_realm_id_kid_unique').on(t.realmId, t.kid),
    // The target of `realm_public_keys_realm_key_fk`. Already unique through
    // `(realm_id, kid)`; it exists so the public row's copies of `purpose`,
    // `algorithm` and `status` are checked against this row and follow it on
    // update. A constraint rather than an index because drizzle-kit adds
    // foreign keys before it creates indexes.
    unique('realm_keys_public_mirror_unique').on(
      t.realmId,
      t.kid,
      t.purpose,
      t.algorithm,
      t.status
    ),
    // One key signs or encrypts per realm, purpose, scope and algorithm. A
    // hybrid pair is two algorithms, so both of its keys may be active.
    // `scope_id` goes through `coalesce` because a unique index treats NULLs
    // as distinct: without it, any number of unscoped keys could be active.
    // The empty string is free to stand for NULL because the CHECK below
    // refuses it as a real scope.
    uniqueIndex('idx_realm_keys_one_active')
      .on(t.realmId, t.purpose, sql`coalesce(${t.scopeId}, '')`, t.algorithm)
      .where(sql`${t.status} = 'active'`),
    check('realm_keys_scope_id_not_empty', sql`${t.scopeId} <> ''`),
    // Both directions: a compromised key always says when, and only a
    // compromised key carries the timestamp.
    check(
      'realm_keys_compromised_at_matches_status',
      sql`(${t.status} = 'compromised') = (${t.compromisedAt} is not null)`
    ),
    check(
      'realm_keys_unpublish_not_before_publish',
      sql`${t.unpublishAt} is null or ${t.publishAt} is null or ${t.unpublishAt} >= ${t.publishAt}`
    ),
  ]
);

/**
 * The public half of every published realm key (ADR-019 Decision 9, #461).
 *
 * Every role may read this table; only the signer writes it, in the same
 * transaction as the {@link realmKeys} row it mirrors. It is what lets a role
 * that holds no key and cannot read `realm_keys` still serve the JWKS (#494)
 * and verify tokens (#497).
 *
 * Symmetric purposes (cookie HMAC, data at rest, webhook secrets) have no row
 * here: the CHECKs on `public_jwk` require a `kty` other than `oct` and refuse
 * every private JWK member, so a bug in the writer cannot hand secret material
 * to the roles that read this table.
 *
 * Keyed by `(realm_id, kid)`. The foreign key to the key row also covers
 * `purpose`, `algorithm` and `status`, with `ON UPDATE CASCADE`:
 *
 * - a public key always has a stored key behind it, with the same purpose,
 *   algorithm and status;
 * - a status change on the key row (`next` → `active` → `retired`, or
 *   `compromised`) reaches this row in the same statement, so the JWKS and
 *   the verifiers never see a stale status. A writer changes the status on
 *   `realm_keys` only; setting it here first fails the foreign key;
 * - deleting the key row removes its public row.
 *
 * `publish_at` and `unpublish_at` are this row's own: they are the JWKS window,
 * and the signer sets them here.
 */
export const realmPublicKeys = pgTable(
  'realm_public_keys',
  {
    kid: varchar('kid', { length: 255 }).notNull(),
    realmId: uuid('realm_id').notNull(),
    purpose: varchar('purpose', { length: 64 }).notNull(),
    algorithm: varchar('algorithm', { length: 32 }).notNull(),
    status: realmKeyStatusEnum('status').notNull(),
    /** The public JWK as published in the JWKS (RFC 7517). */
    publicJwk: jsonb('public_jwk').notNull().$type<Record<string, unknown>>(),
    publishAt: bigint('publish_at', { mode: 'number' }).notNull(),
    unpublishAt: bigint('unpublish_at', { mode: 'number' }),
  },
  (t) => [
    primaryKey({ columns: [t.realmId, t.kid], name: 'realm_public_keys_pk' }),
    foreignKey({
      columns: [t.realmId, t.kid, t.purpose, t.algorithm, t.status],
      foreignColumns: [
        realmKeys.realmId,
        realmKeys.kid,
        realmKeys.purpose,
        realmKeys.algorithm,
        realmKeys.status,
      ],
      name: 'realm_public_keys_realm_key_fk',
    })
      .onDelete('cascade')
      .onUpdate('cascade'),
    check('realm_public_keys_public_jwk_object', sql`jsonb_typeof(${t.publicJwk}) = 'object'`),
    // A JWK must name its key type (RFC 7517 §4.1), and `oct` is a symmetric
    // key, whose only value is the secret itself (RFC 7518 §6.4).
    check(
      'realm_public_keys_public_jwk_asymmetric',
      sql`${t.publicJwk} ? 'kty' and ${t.publicJwk} ->> 'kty' <> 'oct'`
    ),
    // The private members of every JWK key type: `d` (EC, OKP, RSA; RFC 7518
    // §6.2.2, RFC 8037 §2), the RSA CRT members and `oth` (RFC 7518 §6.3.2),
    // `k` (oct; RFC 7518 §6.4) and `priv` (AKP / ML-DSA; RFC 9964).
    check(
      'realm_public_keys_public_jwk_no_private_members',
      sql`not (${t.publicJwk} ?| array['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'])`
    ),
    check(
      'realm_public_keys_unpublish_not_before_publish',
      sql`${t.unpublishAt} is null or ${t.unpublishAt} >= ${t.publishAt}`
    ),
  ]
);

export const realmKeysRelations = relations(realmKeys, ({ one }) => ({
  realm: one(realms, {
    fields: [realmKeys.realmId],
    references: [realms.id],
  }),
}));

export const realmPublicKeysRelations = relations(realmPublicKeys, ({ one }) => ({
  key: one(realmKeys, {
    fields: [
      realmPublicKeys.realmId,
      realmPublicKeys.kid,
      realmPublicKeys.purpose,
      realmPublicKeys.algorithm,
      realmPublicKeys.status,
    ],
    references: [
      realmKeys.realmId,
      realmKeys.kid,
      realmKeys.purpose,
      realmKeys.algorithm,
      realmKeys.status,
    ],
  }),
}));
