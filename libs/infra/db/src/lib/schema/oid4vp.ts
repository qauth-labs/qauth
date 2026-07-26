import { relations, sql } from 'drizzle-orm';
import { bigint, check, index, jsonb, pgTable, text, uuid, varchar } from 'drizzle-orm/pg-core';

import { realms } from './core';
import { EPOCH_MS_NOW } from './sql-helpers';

/**
 * Outbound OID4VP presentation-request state (ADR-004, issue #233).
 *
 * One row per Authorization Request QAuth-as-Verifier sends to a wallet. It is
 * the ONLY thing that ties the wallet's later, unauthenticated POST to the
 * `response_uri` back to a request we actually made, which makes it the
 * single-use, expiring correlator the whole `direct_post` intake path rests on.
 *
 * Modelled on `authorization_codes` — an unguessable value, an `expires_at`, and
 * a used/redeemed transition performed as ONE guarded `UPDATE` so a concurrent
 * double-post cannot consume it twice.
 *
 * ## `state_hash`, not `state`
 *
 * The `state` is presented to us as a bearer credential: whoever holds it can
 * consume the request. Only its SHA-256 digest is stored, so a read-only leak of
 * this table yields nothing redeemable — the same posture as
 * `email_verification_tokens.token_hash` and `refresh_tokens.token_hash`, and
 * one step stronger than `authorization_codes.code`, which is looked up in the
 * clear. Lookup is a unique-index probe on the digest, so there is no comparison
 * to make timing-safe.
 *
 * ## `nonce` in the clear, deliberately
 *
 * The `nonce` is never presented to us and is never a lookup key; it must be
 * handed to #234 VERBATIM to be compared against the Key Binding JWT's `nonce`
 * claim (OID4VP 1.0 §14.1). Hashing it would destroy the one job it has, and a
 * leaked nonce alone consumes nothing.
 *
 * ## No user, no subject — on purpose
 *
 * There is no `user_id` column and there must not be one. This table records a
 * transport exchange, not an authentication: a redeemed row proves someone held
 * the `state` and posted something credential-shaped, never who they are.
 * Identity needs credential validation (#234) and issuer trust (#236), and there
 * is no protocol-guaranteed stable wallet subject identifier at all (ADR-009 /
 * #300) — so nothing here may derive or persist an `external_sub`.
 */
export const oid4vpRequestStates = pgTable(
  'oid4vp_request_states',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /**
     * Realm the presentation request was created in. Cascades: a deleted realm
     * takes its in-flight presentation requests with it.
     */
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** SHA-256 hash of the request `state` (64 hex characters). */
    stateHash: varchar('state_hash', { length: 64 }).notNull().unique(),
    /**
     * The request `nonce`, stored in the clear because #234 must compare it
     * against the Key Binding JWT byte-for-byte. `text` rather than a bounded
     * varchar for the same reason `authorization_codes.nonce` is: the storage
     * layer must never be the thing that truncates a protocol value.
     */
    nonce: text('nonce').notNull(),
    /**
     * `VerifierProfile` id (#299) in force when the request was BUILT.
     *
     * Plain text, not an enum: profiles are DATA in
     * `@qauth-labs/server-federation`, and #299's acceptance criterion is that
     * adding one requires editing that table and nothing else. A pg enum here
     * would make every new profile a migration.
     *
     * Read at redemption to refuse a response whose request was built under a
     * different posture than the deployment now runs.
     */
    verifierProfile: text('verifier_profile').notNull(),
    /** Response Mode the request asked for (`direct_post` today). */
    responseMode: text('response_mode').notNull(),
    /**
     * The DCQL query that was sent (OID4VP 1.0 §6), replayed at redemption to
     * correlate the `vp_token` map's keys against the Credential Query ids we
     * actually asked for.
     */
    dcqlQuery: jsonb('dcql_query').notNull().$type<Record<string, unknown>>(),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    /**
     * Redemption timestamp — and the single-use marker.
     *
     * NULL means pending. A separate boolean/enum `status` column would be a
     * second source of truth for the same fact and would let the two disagree;
     * one nullable timestamp cannot. The redemption `UPDATE` is guarded by
     * `redeemed_at IS NULL`, which is what makes consumption atomic.
     */
    redeemedAt: bigint('redeemed_at', { mode: 'number' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    // The redemption path: digest lookup restricted to live, unredeemed rows.
    index('idx_oid4vp_request_states_active')
      .on(t.stateHash, t.expiresAt)
      .where(sql`${t.redeemedAt} is null`),
    index('idx_oid4vp_request_states_expires_at').on(t.expiresAt),
    index('idx_oid4vp_request_states_realm_id').on(t.realmId),
    // Mirrors the `oauth_clients.audience` / `user_credentials.credential_data`
    // guards: a jsonb column that must hold an object should say so in the DB,
    // not only in the type parameter.
    check('oid4vp_request_states_dcql_query_object', sql`jsonb_typeof(${t.dcqlQuery}) = 'object'`),
  ]
);

export const oid4vpRequestStatesRelations = relations(oid4vpRequestStates, ({ one }) => ({
  realm: one(realms, {
    fields: [oid4vpRequestStates.realmId],
    references: [realms.id],
  }),
}));
