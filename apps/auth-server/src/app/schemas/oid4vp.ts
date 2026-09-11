import {
  MAX_ENCRYPTED_RESPONSE_LENGTH,
  MAX_VP_TOKEN_LENGTH,
} from '@qauth-labs/fastify-plugin-federation';
import { z } from 'zod';

/**
 * Schemas for the OID4VP 1.0 `direct_post` response endpoint (ADR-004, #233).
 *
 * Edge validation ONLY. Everything here answers "is this a well-formed
 * `application/x-www-form-urlencoded` OID4VP Authorization Response" — nothing
 * here, and nothing behind it in this issue, authenticates anyone. See the route
 * and `direct-post.ts` in `@qauth-labs/server-federation` for the safety
 * boundary.
 */

/**
 * Upper bound on the `state` a wallet echoes back.
 *
 * QAuth mints `state` itself (32 CSPRNG bytes → 43 base64url characters), so
 * unlike an OAuth client's opaque `state` there is no third party entitled to
 * pack context into it. The bound is generous enough to survive a wallet that
 * round-trips with padding, and tight enough that an anonymous POST cannot make
 * the endpoint hash a megabyte.
 */
export const OID4VP_STATE_MAX_LENGTH = 512;

/**
 * The CLEARTEXT `POST /oid4vp/response` body — `response_mode=direct_post`
 * (OID4VP 1.0 §8.1–§8.2).
 *
 * A wallet sends one of two shapes to the same `response_uri`:
 *
 *   - SUCCESS — `vp_token` plus the `state` from the request.
 *   - ERROR — `error` (+ optional `error_description`) plus `state`, when the
 *     wallet refuses or fails the request.
 *
 * Both are accepted here and separated in the handler, because both consume the
 * request state exactly once: a request the wallet declined is finished, and
 * leaving its state redeemable until TTL would keep a live correlator around for
 * an exchange that is already over.
 *
 * `state` is REQUIRED in both. Without it there is nothing to correlate against
 * and the POST is indistinguishable from an unsolicited one — which is exactly
 * what it would be.
 *
 * Unknown fields are stripped rather than rejected (Zod's default): OID4VP
 * profiles add parameters (`presentation_submission` in older drafts, HAIP
 * additions), and a Verifier that 400s on an unrecognised field breaks against
 * conformant wallets without gaining any security — every field this endpoint
 * ACTS on is named here.
 *
 * Exactly the schema the endpoint accepted before #377 Phase C, unchanged: the
 * base profile's wire contract is this object, byte for byte.
 */
export const oid4vpCleartextDirectPostRequestSchema = z.object({
  /**
   * JSON-encoded object keyed by DCQL Credential Query id (§8.1). Bounded at
   * the edge so an unauthenticated body never reaches `JSON.parse` unbounded;
   * the same constant bounds the structural parser behind it.
   */
  vp_token: z.string().min(1).max(MAX_VP_TOKEN_LENGTH).optional(),
  state: z.string().min(1).max(OID4VP_STATE_MAX_LENGTH),
  /** Wallet-reported error code (§8.2), e.g. `access_denied`. */
  error: z.string().min(1).max(256).optional(),
  error_description: z.string().max(1024).optional(),
});

export type Oid4vpCleartextDirectPostRequest = z.infer<
  typeof oid4vpCleartextDirectPostRequestSchema
>;

/**
 * The ENCRYPTED `POST /oid4vp/response` body — `response_mode=direct_post.jwt`
 * (OID4VP 1.0 §8.3; HAIP 1.0 §5.1), #377 Phase C.
 *
 * ONE parameter. The whole Authorization Response — `vp_token` or `error`, and
 * the `state` — travels inside a compact JWE encrypted to the per-request key
 * QAuth published in `client_metadata`. There is no cleartext `state` because
 * there is no cleartext anything; the row is found by the JWE `kid` instead.
 *
 * Bounded at the edge by `MAX_ENCRYPTED_RESPONSE_LENGTH` — the `vp_token` bound
 * plus JWE overhead — so an unauthenticated body never reaches a JOSE parser
 * unbounded. `min(1)` because an empty `response` is not an encrypted anything.
 *
 * The cleartext members are NOT declared here and are therefore STRIPPED if a
 * wallet sends them beside `response`, rather than refused: the same tolerance
 * the cleartext schema extends to unknown fields, for the same reason. What the
 * handler acts on is `response`, and only `response` — a `state` riding beside
 * it is never a correlator, because the one that counts is INSIDE the JWE
 * (§5.3), and a cleartext copy anyone who read the request object could send
 * must not be what finds the row.
 */
export const oid4vpEncryptedDirectPostRequestSchema = z.object({
  response: z.string().min(1).max(MAX_ENCRYPTED_RESPONSE_LENGTH),
});

export type Oid4vpEncryptedDirectPostRequest = z.infer<
  typeof oid4vpEncryptedDirectPostRequestSchema
>;

/**
 * `POST /oid4vp/response` body: the cleartext shape OR the encrypted one.
 *
 * A union rather than one object with everything optional, so the handler
 * narrows to a shape whose REQUIRED members the type guarantees — a cleartext
 * body always has its `state`, an encrypted body always has its `response` —
 * instead of re-checking presence by hand on every path.
 *
 * ORDER IS LOAD-BEARING. Zod tries members in sequence and returns the first
 * that parses, and the ENCRYPTED member is listed FIRST: a body carrying a
 * usable `response` is an encrypted submission, whatever else rides beside it.
 *
 * It has to be this way round because OID4VP 1.0 is SILENT on whether a wallet
 * may send `state` next to `response` under `direct_post.jwt` — §8.3 says the
 * response "is a single JWE" and says nothing forbidding extra form fields — so
 * a conformant wallet MAY post both. Cleartext-first would parse that body as
 * the cleartext member, strip the `response`, consume the row by the stray
 * `state`, and then refuse the submission as a mode downgrade: a conformant
 * wallet's user locked out, with the row spent. Encrypted-first routes the same
 * body by the JWE `kid`, opens it, and binds it by the `state` INSIDE — the
 * cleartext copy is stripped and never looked at.
 *
 * The base profile's intake is still bit-for-bit unchanged: a `direct_post`
 * wallet never sends `response` — the parameter exists only in §8.3 — so no
 * body the endpoint accepted before Phase C reaches the encrypted member, and
 * the cleartext member parses it exactly as it always did. The fallback is
 * the old contract; only bodies that carry `response` see the new one.
 *
 * Neither member is refused for carrying the OTHER's fields: a refusal there
 * would have to name which field was unexpected, and this endpoint's refusals
 * are deliberately uniform. The handler decides which path a parsed body takes
 * by which member it is, and the request-state row decides whether that mode
 * is the one its request asked for.
 */
export const oid4vpDirectPostRequestSchema = z.union([
  oid4vpEncryptedDirectPostRequestSchema,
  oid4vpCleartextDirectPostRequestSchema,
]);

export type Oid4vpDirectPostRequest = z.infer<typeof oid4vpDirectPostRequestSchema>;

/**
 * Whether a parsed body is the encrypted member of the union.
 *
 * A type guard rather than an `in` check at the call site, because the union's
 * two members are structurally disjoint only by which REQUIRED member they
 * carry — `state` or `response` — and the guard is where that fact is written
 * down once. The cleartext member can never carry `response` (it is stripped),
 * so its presence is the discriminant.
 */
export function isEncryptedDirectPostRequest(
  body: Oid4vpDirectPostRequest
): body is Oid4vpEncryptedDirectPostRequest {
  return 'response' in body && typeof body.response === 'string';
}

/**
 * `POST /oid4vp/response` success body (OID4VP 1.0 §8.2; #405, ADR-013).
 *
 * §8.2: a Response URI that has processed an Authorization Response or an
 * Authorization Error Response "MUST respond with an HTTP status code of 200
 * with Content-Type of application/json and a JSON object in the response
 * body", and defines exactly one member for that object — `redirect_uri`,
 * OPTIONAL, "String containing a URI. When this parameter is present the
 * Wallet MUST redirect the user agent to this URI." The URI "MUST include a
 * fresh, cryptographically random value" — the Response Code of §14.2 — and
 * "MAY" be returned "in response to successful Authorization Responses or for
 * Error Responses".
 *
 * QAuth emits the member for a SAME-DEVICE request only: an absolute URI under
 * the issuer, `/ui/wallet-login/return?response_code=<43 base64url chars>`,
 * on both the accepted path and the wallet-reported-error path, because HAIP
 * 1.0 §5.1 makes it a MUST there and its MUST has no success qualifier. A
 * CROSS-DEVICE request gets the empty object — §14.2: the technique "is not
 * applicable to cross-device scenarios because the browser used by the Wallet
 * will not have the original session" — and the wallet stops, as §13.3's step
 * 6 note describes; the waiting browser completes by polling as before.
 *
 * Declared with Zod's default strip behaviour, as every other response schema
 * in this app is: the serializer writes the members it knows and nothing
 * else, so the acknowledgement can never grow a field by accident. `z.url()`
 * (the Zod v4 standalone form) rather than a bare string, because the ONE
 * thing §8.2 says about the value's shape is that it is "an absolute URI as
 * defined by RFC 3986 Section 4.3" — a serializer that let a relative path
 * through would be handing the wallet something it cannot open.
 *
 * Still a TRANSPORT-LEVEL ACK. It means "this submission was well-formed and
 * correlated with a request we made" — never "you are authenticated". The
 * `redirect_uri` does not change that: whoever follows it must ALSO hold the
 * binder cookie of the flow the code names, and the return route decides
 * that, not this body.
 */
export const oid4vpDirectPostResponseSchema = z
  .object({
    /**
     * Where the wallet MUST send the user agent (§8.2) — present for a
     * same-device request only. Carries the Response Code as its
     * `response_code` query parameter and nothing else.
     */
    redirect_uri: z.url().optional(),
  })
  .describe(
    'Transport-level acknowledgement (OID4VP 1.0 §8.2): HTTP 200 with a JSON object. Confirms the response was well-formed and correlated with a pending presentation request. For a same-device request the object carries `redirect_uri` — an absolute URI under the issuer with a fresh, single-use Response Code — which the wallet MUST redirect the user agent to (HAIP 1.0 §5.1); for a cross-device request it is empty and the wallet is not required to perform any further steps. It does NOT assert that any credential was verified or that any user was authenticated.'
  );

export type Oid4vpDirectPostResponse = z.infer<typeof oid4vpDirectPostResponseSchema>;
