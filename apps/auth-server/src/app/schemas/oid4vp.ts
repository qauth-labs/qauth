import { MAX_VP_TOKEN_LENGTH } from '@qauth-labs/fastify-plugin-federation';
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
 * `POST /oid4vp/response` body (OID4VP 1.0 §8.1–§8.2).
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
 */
export const oid4vpDirectPostRequestSchema = z.object({
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

export type Oid4vpDirectPostRequest = z.infer<typeof oid4vpDirectPostRequestSchema>;

/**
 * `POST /oid4vp/response` success body.
 *
 * OID4VP 1.0 §8.3: the Verifier answers a `direct_post` submission with HTTP
 * 200 and a JSON object, which MAY carry a `redirect_uri` for the wallet to send
 * the user to. QAuth emits the empty object: there is no post-presentation
 * destination to send anyone to, because nothing here logs anyone in. The wallet
 * login UI that would own such a destination is #239.
 *
 * A TRANSPORT-LEVEL ACK. It means "this submission was well-formed and
 * correlated with a request we made" — never "you are authenticated".
 */
export const oid4vpDirectPostResponseSchema = z
  .object({})
  .describe(
    'Transport-level acknowledgement (OID4VP 1.0 §8.3). Confirms the response was well-formed and correlated with a pending presentation request. It does NOT assert that any credential was verified or that any user was authenticated.'
  );
