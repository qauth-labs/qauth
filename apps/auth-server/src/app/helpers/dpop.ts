import { DpopProofError, type DpopRejectionReason } from '@qauth-labs/fastify-plugin-dpop';
import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import {
  InvalidDpopProofError,
  InvalidRequestError,
  JWTInvalidError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { withEventReason } from './user-events';

/**
 * DPoP-bound tokens (RFC 9449; ADR-014 §3, ADR-017 phase F3, issue #480).
 *
 * `fastify.dpop` is the shared verifier, or `null` while `DPOP_ENABLED` is
 * off; then nothing here reads a `DPoP` header and every response is the one
 * the server gave before DPoP.
 */

/**
 * The `reason` of a failure event for a refused proof: `dpop_` and the
 * verifier's reason in `snake_case`, such as `dpop_replayed`. The wire answer
 * names no reason.
 */
export function dpopEventReason(reason: DpopRejectionReason): string {
  return `dpop_${reason.replaceAll('-', '_')}`;
}

/**
 * Check the `DPoP` proof of a token request (RFC 9449 §5) and return the
 * thumbprint of its key, the `cnf.jkt` of the tokens the request is issued.
 *
 * A proof is checked when the request carries a `DPoP` header, and required
 * when the client is registered with `dpop_bound_access_tokens` (§5.2): such a
 * client's request without one is refused with `missing-proof`. Otherwise, and
 * always while DPoP is off, there is nothing to check and the tokens are
 * Bearer tokens.
 *
 * At the token endpoint the proof carries no `ath` and is checked against no
 * expected key: a code or refresh token bound to a key is compared with the
 * returned thumbprint by its grant handler.
 *
 * @throws DpopProofError when the proof fails a check (the caller answers
 *   `invalid_dpop_proof`, §5)
 */
export async function verifyTokenRequestProof(
  fastify: FastifyInstance,
  request: FastifyRequest,
  client: { dpopBoundAccessTokens?: boolean }
): Promise<string | undefined> {
  if (!fastify.dpop) return undefined;
  if (request.headers.dpop === undefined && client.dpopBoundAccessTokens !== true) {
    return undefined;
  }
  const { thumbprint } = await fastify.dpop.verifyRequest(request);
  return thumbprint;
}

/**
 * Check the `DPoP` proof of a request to one of this server's protected
 * resources that came with `Authorization: DPoP <token>` (RFC 9449 §7.1): the
 * JWT plugin's `verifyDpopProof`, called by `requireJwt` after the token
 * verified.
 *
 * The proof must be for this request's method and URL, carry the token's hash
 * as `ath`, and be signed by the key the token's `cnf.jkt` names. A proof
 * under another key is `invalid_token` (the token is not bound to it, RFC 9449
 * Figure 16); any other refusal is `invalid_dpop_proof`. Both are 401 with a
 * `DPoP` challenge, and the reason goes only to the log and the event.
 */
export async function verifyResourceRequestProof(
  fastify: FastifyInstance,
  request: FastifyRequest,
  token: string,
  claims: JWTPayload
): Promise<void> {
  if (!fastify.dpop || claims.cnf === undefined) {
    throw new JWTInvalidError('The access token is not bound to a DPoP key');
  }
  try {
    await fastify.dpop.verifyRequest(request, {
      accessToken: token,
      expectedThumbprint: claims.cnf.jkt,
    });
  } catch (error) {
    if (!(error instanceof DpopProofError)) throw error;
    // A replay store outage refuses every proof: the server's error, not the
    // caller's.
    request.log[error.reason === 'replay-store-unavailable' ? 'error' : 'warn'](
      { reason: error.reason },
      'DPoP proof refused at a protected resource'
    );
    const refusal =
      error.reason === 'key-mismatch'
        ? new JWTInvalidError('Invalid DPoP key binding')
        : new InvalidDpopProofError(undefined, { atResource: true });
    throw withEventReason(refusal, dpopEventReason(error.reason));
  }
}

/** The form of a `dpop_jkt`: a base64url RFC 7638 SHA-256 JWK thumbprint. */
const DPOP_JKT = /^[A-Za-z0-9_-]{43}$/;

/** What an authorization request's `dpop_jkt` binds its code to. */
export type AuthorizationDpopJkt =
  | { readonly kind: 'bound'; readonly jkt: string }
  | { readonly kind: 'unbound' }
  | { readonly kind: 'malformed' };

/**
 * What a malformed `dpop_jkt` is told (#513): in the error redirect of the
 * authorization endpoint and in the refusal of the consent endpoint alike.
 */
export const MALFORMED_DPOP_JKT_DESCRIPTION =
  'dpop_jkt must be the base64url SHA-256 JWK thumbprint of a DPoP key';

/** The refusal of a `dpop_jkt` {@link readAuthorizationDpopJkt} reads as malformed. */
export function malformedDpopJktError(): InvalidRequestError {
  return new InvalidRequestError(MALFORMED_DPOP_JKT_DESCRIPTION);
}

/**
 * Read the `dpop_jkt` parameter of an authorization request (RFC 9449 §10):
 * the thumbprint of the DPoP key the code is bound to, which the token request
 * must then prove.
 *
 * While DPoP is off the parameter is not read at all, so the request goes on
 * as it did before DPoP and the code is unbound. While it is on, a value that
 * is not a base64url SHA-256 thumbprint is `malformed`: the caller refuses it
 * (`invalid_request`) rather than issue an unbound code to a client that asked
 * for a bound one.
 */
export function readAuthorizationDpopJkt(
  fastify: FastifyInstance,
  value: unknown
): AuthorizationDpopJkt {
  if (!fastify.dpop || value === undefined) return { kind: 'unbound' };
  // A repeated parameter arrives as a list: one key per code, so malformed.
  return typeof value === 'string' && DPOP_JKT.test(value)
    ? { kind: 'bound', jkt: value }
    : { kind: 'malformed' };
}
