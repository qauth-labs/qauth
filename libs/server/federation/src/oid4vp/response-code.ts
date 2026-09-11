/**
 * The Response Code of the same-device return leg (issue #405, ADR-013).
 *
 * When a wallet posts an Authorization Response to the `direct_post`
 * Response Endpoint, OID4VP 1.0 §8.2 lets the Verifier answer with a
 * `redirect_uri` the wallet MUST follow, and puts one requirement on that URL:
 * *"The Verifier MUST include a fresh, cryptographically random value in the
 * URL. This value is used to ensure only the receiver of the redirect can fetch
 * and process the Authorization Response. […] It is RECOMMENDED to use a
 * cryptographic random value of 128 bits or more."* §14.2 names that value the
 * Response Code and states the job it does: the Response URI *"MUST require the
 * frontend to pass the respective Response Code"*, which *"stops session
 * fixation attacks as long as the attacker is unable to get access to the
 * Response Code"*. HAIP 1.0 §5.1 makes the whole arrangement a MUST for the
 * same-device flow. This module mints, digests and shape-checks that value; the
 * return route and the response endpoint in `apps/auth-server` are its callers.
 *
 * ## The same posture as `state`, for the same reason
 *
 * A Response Code is a bearer secret exactly as the request `state` is: whoever
 * presents it to the return route spends it, once. So it is handled the way
 * `request-state.ts` handles `state` — 256 bits of CSPRNG, only its SHA-256
 * persisted (`response_code_hash`, mirroring `state_hash`), and redeemed by a
 * unique-index probe on the digest rather than a comparison, so there is no
 * timing channel to close and a read-only leak of the table yields nothing a
 * wallet's browser could present.
 *
 * What the code is NOT is a session. The return route pairs it with the
 * browser-binder cookie of the flow it belongs to; a valid code arriving from a
 * browser that does not hold that cookie is the case §14.2 warns about (*"the
 * Wallet uses a browser different from the one used on the presentation
 * request"*) and HAIP §5.1 tells the Verifier to reject — so the route burns
 * the code first and only then asks whose browser it landed in.
 *
 * ## Why the shape is exact, not bounded
 *
 * 32 bytes base64url-encoded without padding are always 43 characters, so the
 * shape check is `{43}` rather than "up to 43": a value of any other length was
 * not minted here, and refusing it before the database is touched denies an
 * attacker a table probe per guess while costing a legitimate wallet nothing.
 * The base64url alphabet is also what lets the code ride in a query parameter
 * with no percent-encoding, which is what §8.2 permits ("as a parameter to the
 * URL") and what every log-redaction and shape rule downstream can rely on.
 */

import { createHash, randomBytes } from 'node:crypto';

/**
 * Entropy of a Response Code, in bytes.
 *
 * 256 bits — twice the 128 OID4VP 1.0 §8.2 RECOMMENDS, and the same size as
 * `OID4VP_SECRET_BYTES` so `state`, `nonce` and the code are one unguessable
 * size across the transport rather than three. The code is a single-use
 * consumption credential, so it needs the full margin `state` has.
 */
export const OID4VP_RESPONSE_CODE_BYTES = 32;

/**
 * Length of a Response Code on the wire, in characters.
 *
 * {@link OID4VP_RESPONSE_CODE_BYTES} base64url-encoded without padding:
 * `ceil(32 * 4 / 3)` = 43. Used as the Zod `.max()` on the return route's
 * querystring so an over-long value is refused at the edge, before the shape
 * check runs.
 */
export const MAX_OID4VP_RESPONSE_CODE_LENGTH = 43;

/**
 * Exact shape of a Response Code QAuth minted: 43 base64url characters, no
 * padding, nothing else.
 *
 * Anchored at both ends and without the `m` flag, so a trailing newline, a
 * padding `=`, whitespace or any character outside the base64url alphabet is a
 * refusal rather than a near miss.
 */
export const OID4VP_RESPONSE_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * Mint one Response Code.
 *
 * `randomBytes` (CSPRNG) and nothing derived from the request, the row, a
 * clock or a counter: the code is what stands between an attacker who relayed
 * an Authorization Request to a victim's wallet and the victim's session, and
 * it fails completely if predictable. Minted once per accepted response and
 * never re-used — the digest is written into the row's redemption `UPDATE`,
 * and the row is redeemed exactly once.
 */
export function generateOid4vpResponseCode(): string {
  return randomBytes(OID4VP_RESPONSE_CODE_BYTES).toString('base64url');
}

/**
 * Digest a Response Code for storage or lookup.
 *
 * The SAME function must be used on both sides — the response endpoint writing
 * `response_code_hash` and the return route redeeming by it — or a legitimate
 * return never correlates. A plain SHA-256 (not a password hash) is correct
 * here for the reason `hashOid4vpState` gives: 256 bits of CSPRNG entropy
 * leave no dictionary to slow down, and redemption sits on the request path.
 *
 * @param code - the raw Response Code, as it appears in the `redirect_uri`.
 */
export function hashOid4vpResponseCode(code: string): string {
  return createHash('sha256').update(code, 'utf8').digest('hex');
}

/**
 * Whether an untrusted value has the exact shape of a Response Code.
 *
 * The return route's first gate, run BEFORE anything is looked up: only a
 * string that matches {@link OID4VP_RESPONSE_CODE_PATTERN} reaches the
 * database. A type predicate rather than a boolean so the caller's `unknown`
 * narrows to `string` on the accepting branch and nothing else has to cast.
 *
 * @param value - whatever the querystring parser produced.
 */
export function isOid4vpResponseCode(value: unknown): value is string {
  return typeof value === 'string' && OID4VP_RESPONSE_CODE_PATTERN.test(value);
}
