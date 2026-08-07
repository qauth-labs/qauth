/**
 * The Token Status List VERSION PIN and its wire vocabulary (issue #297).
 *
 * ## Why a pin, and why it lives alone in this file
 *
 * HAIP 1.0 §9.4 normatively references **Token Status List draft-14
 * (2025-12-10)** and instructs implementations to prefer the pinned version
 * over later finals. The live IETF draft has since moved on, and the wire format
 * is still being edited between revisions — `bits` gained values, the CWT
 * profile's claim keys were renumbered, the aggregation endpoint appeared. A
 * verifier that silently tracked "whatever the latest draft says" would drift
 * out of HAIP conformance without a single line of its own code changing.
 *
 * So the version is a CONSTANT, in its own module, imported everywhere it is
 * needed and hard-coded nowhere. When HAIP repins, this file is the diff.
 *
 * ## Scope: the JWT profile only
 *
 * draft-14 defines both a JWT and a CWT representation of a Status List Token.
 * QAuth implements the JWT profile: SD-JWT VC credentials are JOSE all the way
 * down, `@qauth-labs/core-crypto` verifies JWS, and HAIP §6.1 pairs
 * `dc+sd-jwt` with the JWT form. The CWT constants are deliberately absent
 * rather than declared-and-unused — an unused constant reads as a supported
 * path.
 */

/**
 * The Token Status List revision this implementation targets.
 *
 * Informational (it never goes on the wire) but load-bearing: it is what a
 * reviewer, an audit log line, and a conformance report cite. Changing it
 * without changing the code below is a lie; changing the code below without
 * changing it is a silent conformance break.
 */
export const TOKEN_STATUS_LIST_DRAFT = 'draft-ietf-oauth-status-list-14' as const;

/**
 * The `typ` protected-header value a Status List Token MUST carry
 * (draft-14 §5.1).
 *
 * Checked against the header the SIGNATURE covers, never the unverified one, so
 * a Status List Token cannot be swapped in for a credential (or vice versa) —
 * the JOSE type-confusion defence RFC 8725 §3.11 asks for.
 */
export const STATUS_LIST_TOKEN_TYP = 'statuslist+jwt' as const;

/**
 * The media type the status endpoint MUST serve (draft-14 §6).
 *
 * Sent as `Accept` and required of the response `Content-Type`. Requiring it on
 * the way back is not ceremony: it is what stops a status fetch that landed on
 * an HTML error page, a login redirect, or an unrelated JSON document from
 * being parsed as a token at all.
 */
export const STATUS_LIST_TOKEN_MEDIA_TYPE = 'application/statuslist+jwt' as const;

/**
 * Bit widths draft-14 §4.1 permits for `status_list.bits`.
 *
 * 1, 2, 4 or 8 — every value divides 8, which is what keeps a lookup inside a
 * single byte. Anything else is rejected rather than generalised: a width that
 * straddles a byte boundary is exactly the arithmetic the specification
 * eliminated on purpose, and implementing it would mean implementing a format
 * no compliant issuer can emit.
 */
export const STATUS_LIST_BIT_WIDTHS = Object.freeze([1, 2, 4, 8] as const);

/** A `status_list.bits` value this implementation accepts. */
export type StatusListBitWidth = (typeof STATUS_LIST_BIT_WIDTHS)[number];

/**
 * Registered status values (draft-14 §7.1).
 *
 * Only these three are named. Every other value — the application-specific
 * range included — is UNKNOWN to this verifier, and an unknown status is not a
 * valid one: a deployment that has not been told what `0x03` means in its
 * ecosystem cannot conclude the credential is good.
 */
export const CREDENTIAL_STATUS = Object.freeze({
  /** `0x00` — valid, correct, legal. The only accepting value. */
  VALID: 0,
  /** `0x01` — revoked, annulled, taken back, recalled or cancelled. */
  INVALID: 1,
  /** `0x02` — temporarily invalid; suspended, hanging, debarred. */
  SUSPENDED: 2,
} as const);

/**
 * Largest `status_list.lst` payload accepted BEFORE decompression, in bytes of
 * base64url text.
 *
 * The first of two decompression-bomb bounds. A DEFLATE stream can expand by
 * roughly 1000:1, so bounding only the output still lets a small allocation
 * loop run for a long time; bounding the input as well keeps the work
 * proportional to something an attacker cannot inflate.
 *
 * 4 MiB of base64url is a ~3 MiB compressed list. At the observed compression
 * of a sparse revocation bitmap that is comfortably more than a
 * hundred-million-entry list, and far more than any real issuer publishes.
 */
export const MAX_ENCODED_STATUS_LIST_BYTES = 4 * 1024 * 1024;

/**
 * Largest DECOMPRESSED status list accepted, in bytes.
 *
 * The second bound, and the one that actually stops the bomb: it is passed to
 * `zlib` as `maxOutputLength`, so the inflate ABORTS at the limit instead of
 * inflating 3 MiB into gigabytes and then being measured. Measuring after the
 * fact is not a defence — the allocation already happened.
 *
 * 16 MiB is 134 million single-bit entries. An issuer that needs more is
 * expected to shard across several lists, which draft-14 §12.4 anticipates.
 */
export const MAX_DECOMPRESSED_STATUS_LIST_BYTES = 16 * 1024 * 1024;

/**
 * Largest Status List Token accepted from the network, in bytes.
 *
 * Bounds the response body before any parsing, so an endpoint that streams
 * indefinitely cannot exhaust memory. Sized to hold
 * {@link MAX_ENCODED_STATUS_LIST_BYTES} of `lst` plus JOSE overhead and an
 * `x5c` chain.
 */
export const MAX_STATUS_LIST_TOKEN_BYTES = 6 * 1024 * 1024;
