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
  varchar,
} from 'drizzle-orm/pg-core';

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
 * ## The encrypted-response columns (#377 Phase C), nullable as a set
 *
 * Under `direct_post.jwt` (HAIP 1.0 §5.1) the wallet's response is ONE JWE and
 * carries no cleartext `state`, so the digest above cannot be the lookup key.
 * What the wallet is REQUIRED to expose outside the ciphertext is the JWE `kid`
 * (OID4VP 1.0 §8.3), which QAuth minted per request and published in
 * `client_metadata` (§5.1). `response_encryption_kid` is therefore a SECOND
 * single-use correlator, and the row keeps the private half of the pair that
 * `kid` names, because the response arrives on a different HTTP request than
 * the one that minted it.
 *
 * Three columns, and either all three are set or none is (the
 * `..._response_encryption_complete` CHECK). A row built for plain
 * `direct_post` carries nothing here; a row built for `direct_post.jwt` carries
 * a `kid` the wallet will echo, the private JWK that opens the response, and a
 * marker saying how that JWK was written — `plain` by default, `aes-256-gcm`
 * when the deployment opted into `OID4VP_RESPONSE_KEY_SECRET`. The marker is
 * per ROW rather than per deployment so switching the option on never orphans
 * a request already in flight. It sits beside `nonce`, which this table already
 * stores in the clear for its own stated reason; see
 * `@qauth-labs/server-federation`'s `response-encryption` module for why plain
 * is the default and what the envelope protects against.
 *
 * All three are cleared by the redemption `UPDATE` itself — a consumed row
 * carries no key, whichever correlator consumed it. See
 * `responseEncryptionPrivateJwk` below for why, and the repository for how the
 * private half still reaches the one caller that has to decrypt with it.
 *
 * ## The same-device return leg (#405): a THIRD single-use correlator
 *
 * A same-device presentation (HAIP 1.0 §5.1) ends with the wallet following a
 * `redirect_uri` back into the browser the flow started in, and that URI has
 * to carry "a fresh secret (Response Code)" the frontend must present before
 * the presentation may complete (OID4VP 1.0 §14.2). The code is minted at the
 * response endpoint and its digest written by the SAME `UPDATE` that consumes
 * the row — `response_code_hash`, `response_code_expires_at` — so through the
 * repository a code exists only for a row that was actually redeemed.
 * `response_code_redeemed_at` is the code's own single-use marker, and
 * `same_device` records, from the moment the row is created, whether a
 * return leg is expected at all.
 *
 * Four columns, three of them nullable as a pair-plus-one: the hash and its
 * expiry are set together or not at all (the `..._response_code_complete`
 * CHECK), and a code can only have been redeemed if it was written
 * (`..._response_code_redeemed_requires_hash`). The DDL deliberately does NOT
 * tie the pair to `redeemed_at` — that would make the INSERT shape depend on
 * the redemption shape — so `redeemResponseCode` requires `redeemed_at` in
 * its own predicate. The digest is written for EVERY redeemed row — the
 * repository has one shape — but the code itself leaves the server only for
 * a `same_device` row, and `redeemResponseCode` refuses anything else, so a
 * cross-device row's digest names a secret nobody holds.
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
    /**
     * Response Mode the request asked for: `direct_post`, or `direct_post.jwt`
     * for a request built with an encryption key (#377 Phase C).
     *
     * Read at redemption alongside `verifier_profile`: a submission must arrive
     * in the mode its request asked for, so a cleartext post cannot consume a
     * row whose profile made encryption REQUIRED — the bidirectional enforcement
     * `CapabilityPosture` promises.
     */
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
    /**
     * JWE `kid` of the per-request ephemeral encryption key (#377 Phase C),
     * when the request was built for `direct_post.jwt`; NULL otherwise.
     *
     * The lookup key for an ENCRYPTED response, read out of the JWE protected
     * header before anything is decrypted (OID4VP 1.0 §8.3). Minted by QAuth
     * from 128 bits of CSPRNG output (22 base64url characters) — §5.1 promises
     * uniqueness only "within the context of the request", which is not enough
     * to key a table, so global uniqueness is enforced below over live rows.
     * `varchar(64)` because the value is bounded at the edge to the same width
     * (`MAX_ENCRYPTION_KID_LENGTH`) before it reaches a query: the column is
     * not the thing that truncates an attacker-supplied header.
     *
     * An OPAQUE INDEX and nothing more. §14.5: an encrypted response has no
     * integrity protection, so the `kid` is attacker-controlled; a wrong value
     * finds no row and is refused, and the trusted binding is the `state`
     * inside the decrypted payload, checked against `state_hash`.
     */
    responseEncryptionKid: varchar('response_encryption_kid', { length: 64 }),
    /**
     * The PRIVATE half of the ephemeral ECDH-ES pair, serialized — as the JWK
     * document itself under `plain`, or as a versioned AES-256-GCM envelope
     * under `aes-256-gcm` (see `responseEncryptionKeyProtection`).
     *
     * `text` for the reason `nonce` is: the storage layer must never be the
     * thing that truncates a protocol value, and an envelope's length depends
     * on the scheme that wrote it.
     *
     * LIVES ONLY AS LONG AS THE ROW IS REDEEMABLE. The redemption `UPDATE`
     * clears this column — and its two siblings — in the same statement that
     * sets `redeemed_at`, projecting the pre-update value to the one caller
     * that needs it (the repository's `redeemByEncryptionKid`). The key's only
     * job is to open the one response its `kid` names, and that job ends the
     * instant the row is consumed; a key that outlives its response is pure
     * exposure, because a later dump of this table combined with the encrypted
     * POST bodies a load balancer or WAF may have logged would decrypt every
     * historical presentation retroactively. The at-rest envelope narrows that
     * window for a LIVE row; erasure at consumption closes it for a consumed
     * one, under either protection scheme. Expired-but-never-redeemed rows keep
     * their key until `deleteExpired` removes them — they were never answered,
     * so there is no response for the key to expose.
     */
    responseEncryptionPrivateJwk: text('response_encryption_private_jwk'),
    /**
     * How `response_encryption_private_jwk` was written: `'plain'` or
     * `'aes-256-gcm'`, read back by the ROW's marker rather than by the
     * deployment's current setting.
     *
     * Plain `text` with a CHECK rather than a pg enum, for the reason
     * `verifier_profile` is: the vocabulary is data in
     * `@qauth-labs/server-federation` (`Oid4vpEphemeralKeyProtection`), and a
     * future scheme should be a code change plus a widened CHECK, not an enum
     * migration. The CHECK is what stops a row from carrying a label no build
     * can read; `parseEphemeralKeyProtection` refuses such a row anyway, but
     * the database should say so too.
     */
    responseEncryptionKeyProtection: text('response_encryption_key_protection'),
    /**
     * Whether the flow that minted this request expects the wallet to bring
     * the user agent BACK (#405, HAIP 1.0 §5.1 "same-device"), or was started
     * as a cross-device (QR) flow that completes by polling. Chosen by the
     * user at flow start and written with the row; default `false` so a row
     * from a binary that predates the column, or a caller that says nothing,
     * is a cross-device row and nothing about its behaviour changes.
     *
     * A BOOLEAN, deliberately — not a flow handle, a session id, or anything
     * else that could name the browser. The wallet-facing side of this table
     * (the response endpoint) must never be able to reach a browser session:
     * the row is joined to its flow only by `state_hash`, one way, from the
     * browser's side. This column says a return is EXPECTED; it says nothing
     * about where. Projected by the redemption `UPDATE` so the response
     * endpoint can decide whether a `redirect_uri` goes back to the wallet,
     * and read by `redeemResponseCode` as a hard guard so a code that was
     * never emitted can never be redeemed.
     */
    sameDevice: boolean('same_device').notNull().default(false),
    /**
     * SHA-256 hash of the Response Code (64 hex characters) minted for the
     * same-device return leg (OID4VP 1.0 §8.2 / §14.2), written by the SAME
     * `UPDATE` that sets `redeemed_at`; NULL until the row is consumed.
     *
     * Only the digest, for the reason `state_hash` gives: the code travels in
     * a `redirect_uri` and is presented back to us as a bearer credential, so
     * a read-only leak of this table must yield nothing a browser could hand
     * in. It is a unique-index probe (`idx_oid4vp_request_states_response_code`,
     * over codes not yet redeemed), so there is no comparison to make
     * timing-safe. `varchar(64)` because a hex SHA-256 is exactly that wide.
     */
    responseCodeHash: varchar('response_code_hash', { length: 64 }),
    /**
     * The Response Code's OWN deadline (epoch ms), INDEPENDENT of `expires_at`.
     *
     * `expires_at` bounds how long a wallet may take to answer the request;
     * it is consumed the moment the wallet posts. The code is minted at that
     * same moment and has to survive the wallet's "Done" tap, an app switch
     * and a browser cold start, none of which the request's budget was sized
     * for — a code inheriting `expires_at` would be dead on arrival for any
     * presentation posted near the end of the request's life. So the code
     * carries its own, shorter, fixed TTL, set by the caller from
     * `WALLET_RETURN_CODE_TTL_MS`, and `redeemResponseCode` guards on THIS
     * column, never on `expires_at`.
     *
     * The housekeeping consequence: a row whose request expired may still
     * carry a LIVE code (the request was answered at its last second), so
     * `deleteExpired` spares a row until both deadlines have passed — see the
     * repository. Set together with `response_code_hash` or not at all (the
     * `..._response_code_complete` CHECK).
     */
    responseCodeExpiresAt: bigint('response_code_expires_at', { mode: 'number' }),
    /**
     * When the Response Code was presented back and accepted — and the code's
     * single-use marker, for the reason `redeemed_at` is the row's: NULL means
     * not yet redeemed, one nullable timestamp cannot disagree with itself,
     * and the redemption `UPDATE` is guarded by `response_code_redeemed_at IS
     * NULL`, which is what makes the return leg consume exactly once under
     * concurrency. A second timestamp rather than reusing `redeemed_at`
     * because the two events are distinct and ordered: the wallet's POST
     * consumes the row (`redeemed_at`), then the browser's return consumes the
     * code — and the second can only ever happen after the first, which is why
     * `redeemResponseCode` also requires `redeemed_at IS NOT NULL`.
     *
     * Can only be set on a row that has a hash (the
     * `..._response_code_redeemed_requires_hash` CHECK): a redeemed code that
     * was never written is not a state a row may be in.
     */
    responseCodeRedeemedAt: bigint('response_code_redeemed_at', { mode: 'number' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    // The redemption path: digest lookup restricted to live, unredeemed rows.
    index('idx_oid4vp_request_states_active')
      .on(t.stateHash, t.expiresAt)
      .where(sql`${t.redeemedAt} is null`),
    index('idx_oid4vp_request_states_expires_at').on(t.expiresAt),
    index('idx_oid4vp_request_states_realm_id').on(t.realmId),
    // The ENCRYPTED redemption path (#377 Phase C): kid lookup restricted to
    // live, unredeemed rows — the mirror of `idx_oid4vp_request_states_active`
    // for the second correlator. UNIQUE, because OID4VP 1.0 §5.1 guarantees a
    // kid's uniqueness only within one request and the redemption `UPDATE`
    // needs it unique across the table to consume exactly one row. Partial
    // over `redeemed_at IS NULL` so a redeemed row never collides with a new
    // one, and so NULL kids (plain `direct_post` rows) never enter the index.
    uniqueIndex('idx_oid4vp_request_states_encryption_kid')
      .on(t.responseEncryptionKid)
      .where(sql`${t.redeemedAt} is null`),
    // The RETURN-LEG redemption path (#405): Response Code digest lookup
    // restricted to codes not yet presented back — the third correlator's
    // mirror of the two indexes above. UNIQUE so `redeemResponseCode`'s
    // guarded `UPDATE` can match at most one row; partial over
    // `response_code_redeemed_at IS NULL` so a spent code leaves the index and
    // so NULL digests (every row not yet consumed by a wallet, and every row
    // from before the column existed) never enter it.
    uniqueIndex('idx_oid4vp_request_states_response_code')
      .on(t.responseCodeHash)
      .where(sql`${t.responseCodeRedeemedAt} is null`),
    // Mirrors the `oauth_clients.audience` / `user_credentials.credential_data`
    // guards: a jsonb column that must hold an object should say so in the DB,
    // not only in the type parameter.
    check('oid4vp_request_states_dcql_query_object', sql`jsonb_typeof(${t.dcqlQuery}) = 'object'`),
    // All-or-nothing across the three encrypted-response columns: a row with a
    // kid but no key would be redeemable and then undecryptable — a live
    // correlator for an exchange that can never complete — and a key with no
    // kid could never be found. Half-provisioned is not a state a row may be in.
    check(
      'oid4vp_request_states_response_encryption_complete',
      sql`(${t.responseEncryptionKid} is null and ${t.responseEncryptionPrivateJwk} is null and ${t.responseEncryptionKeyProtection} is null) or (${t.responseEncryptionKid} is not null and ${t.responseEncryptionPrivateJwk} is not null and ${t.responseEncryptionKeyProtection} is not null)`
    ),
    // The marker vocabulary, pinned in the DB as well as in
    // `Oid4vpEphemeralKeyProtection`. Widening it is a migration on purpose: a
    // new at-rest scheme is a change every reader has to know about.
    check(
      'oid4vp_request_states_response_encryption_key_protection_valid',
      sql`${t.responseEncryptionKeyProtection} is null or ${t.responseEncryptionKeyProtection} in ('plain', 'aes-256-gcm')`
    ),
    // The Response Code digest and its deadline are one value (#405): a hash
    // with no expiry would be a code that never dies, and an expiry with no
    // hash names nothing. Written together by the redemption `UPDATE`, and the
    // database should refuse any other shape.
    check(
      'oid4vp_request_states_response_code_complete',
      sql`(${t.responseCodeHash} is null) = (${t.responseCodeExpiresAt} is null)`
    ),
    // A code can only have been redeemed if it was written. `redeemResponseCode`
    // guards on the hash so this cannot happen through the repository; the
    // CHECK is what stops a hand-written statement from doing it.
    check(
      'oid4vp_request_states_response_code_redeemed_requires_hash',
      sql`${t.responseCodeRedeemedAt} is null or ${t.responseCodeHash} is not null`
    ),
  ]
);

export const oid4vpRequestStatesRelations = relations(oid4vpRequestStates, ({ one }) => ({
  realm: one(realms, {
    fields: [oid4vpRequestStates.realmId],
    references: [realms.id],
  }),
}));
