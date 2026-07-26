/**
 * `direct_post` response intake — STRUCTURAL PARSING ONLY (issue #233, Phase A).
 *
 * OID4VP 1.0 §8.1: with `response_mode=direct_post` the wallet POSTs an
 * `application/x-www-form-urlencoded` body to the Verifier's `response_uri`,
 * carrying `vp_token` and the `state` from the request. `vp_token` is a
 * JSON-encoded object whose keys are DCQL Credential Query ids and whose values
 * are arrays of Presentations matching that query.
 *
 * ## THE SAFETY BOUNDARY — read before adding anything here
 *
 * This module answers exactly two questions:
 *
 *   1. Does this POST correlate with a presentation request WE made, which is
 *      still alive and has not been consumed? (the request-state store)
 *   2. Is the posted `vp_token` SHAPED like a response to that request?
 *
 * It answers NO other question. It does not check a signature, a disclosure
 * digest, a Key Binding JWT, a `vct`, an issuer, a revocation status or an
 * assurance level. It therefore establishes NO identity, and `WalletProvider`
 * must keep throwing:
 *
 * > Under ADR-003 the auth engine mints a QAuth token for whatever `externalSub`
 * > a provider returns. A response at this endpoint proves the poster held our
 * > `state` and could produce something credential-shaped — it proves nothing
 * > about WHO they are. If anything here resolved a subject, every party able to
 * > round-trip the transport would self-register as a user.
 *
 * What makes a wallet login meaningful is the credential (#234) and its issuer's
 * trustworthiness (#236). Until both land, this layer's output is
 * ATTACKER-CONTROLLED DATA that is stored nowhere and authenticates nobody.
 *
 * There is also no protocol-guaranteed stable wallet subject identifier
 * (ADR-009 / #300, OID4VP §15.5–§15.6 treat wallet cryptography as a linkability
 * defect wallets rotate away), so this layer must not derive or persist any
 * `external_sub` — not from a JWK thumbprint, not from a DID, not from anything.
 */

import { InvalidRequestError } from '@qauth-labs/shared-errors';

import type { CredentialFormat } from '../profiles/verifier-profile.types';
import type { PresentedCredential } from './credential-format';
import { resolveCredentialFormatAdapter } from './credential-format';
import type { DcqlQuery } from './dcql';

/**
 * The ONLY client-facing description any correlation or parse failure produces.
 *
 * Non-enumerating by construction: "unknown state", "expired state", "already
 * redeemed", "malformed vp_token" and "vp_token does not match the query" are
 * indistinguishable on the wire. An attacker holding a candidate `state` learns
 * nothing about whether it ever existed, whether it is still alive, or whether
 * someone else already consumed it — and a legitimate wallet needs no more
 * detail than "this response was not accepted", because the specific reason is
 * never actionable from its side.
 *
 * The precise reason is carried separately for SERVER-SIDE logging; see
 * {@link Oid4vpTransportRejection}.
 */
export const OID4VP_REJECTION_DESCRIPTION =
  'The presentation response was not accepted for this request.';

/**
 * A refused `direct_post` submission.
 *
 * Splits the two audiences that a single error message cannot serve at once:
 * `toClientError()` renders the fixed, non-enumerating wire response, while
 * {@link logReason} stays server-side for the operator who has to debug a wallet
 * integration. Keeping them in one object is what stops the detailed reason from
 * being handed to the caller by accident.
 */
export class Oid4vpTransportRejection extends Error {
  /** Server-side detail. NEVER put this on the wire. */
  readonly logReason: string;

  constructor(logReason: string) {
    super(`OID4VP direct_post response rejected: ${logReason}`);
    this.name = 'Oid4vpTransportRejection';
    this.logReason = logReason;
    Object.setPrototypeOf(this, Oid4vpTransportRejection.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, Oid4vpTransportRejection);
    }
  }

  /**
   * The client-facing error: RFC 6749-shaped `invalid_request` carrying the
   * fixed {@link OID4VP_REJECTION_DESCRIPTION}, identical for every rejection.
   */
  toClientError(): InvalidRequestError {
    return new InvalidRequestError(OID4VP_REJECTION_DESCRIPTION);
  }
}

/**
 * The request-state row a `state` redeemed, reduced to what this layer needs.
 *
 * Structural rather than the DB row type: `libs/server/*` must not depend on
 * `libs/infra/*` (the workspace's module boundaries), and this module has no
 * business knowing what else the row carries.
 */
export interface RedeemedOid4vpRequestState {
  /** Request-state row id, for correlation in logs and audit records. */
  readonly id: string;
  /** Realm the request was created in. */
  readonly realmId: string;
  /**
   * The `nonce` this request was created with, VERBATIM.
   *
   * Unused at this layer by design — nothing here opens the Key Binding JWT it
   * belongs in. It is surfaced so #234 can bind the Presentation to this exact
   * request (OID4VP §14.1) without a second store lookup.
   */
  readonly nonce: string;
  /** `VerifierProfile` id in force when the request was BUILT. */
  readonly verifierProfile: string;
  /** The DCQL query that was sent, replayed for response correlation. */
  readonly dcqlQuery: DcqlQuery;
}

/**
 * Bound on the encoded `vp_token` we will parse.
 *
 * The endpoint is unauthenticated by construction — a wallet holds no client
 * credentials — so the body limit must not be the only thing standing between an
 * anonymous POST and a JSON parse.
 */
export const MAX_VP_TOKEN_LENGTH = 512 * 1024;

/** Bound on total Presentations accepted across all Credential Queries. */
export const MAX_PRESENTATIONS_PER_RESPONSE = 32;

/** Reject anything that is not a plain JSON object. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Structurally parse a `vp_token` against the DCQL query it answers
 * (OID4VP 1.0 §8.1).
 *
 * The checks, and why each one is here:
 *
 *   - **JSON object, keyed by Credential Query id.** The 1.0 Final shape. A
 *     bare string is the superseded Draft-22 shape and is rejected rather than
 *     accommodated.
 *   - **No unrequested keys.** A wallet answering questions we did not ask is
 *     either broken or probing; either way there is no query to correlate the
 *     entry with, so it cannot be validated later.
 *   - **Every requested key present.** We emit no `credential_sets`, so every
 *     Credential Query is mandatory (§6). A partial response must not look like
 *     a complete one to #234.
 *   - **Array-valued, with `multiple` respected.** §8.1: the value is an array,
 *     and "the number of entries MUST be 1 unless `multiple` is `true`".
 *   - **Each entry recognised by its format adapter.** Structure only — see the
 *     module JSDoc.
 *
 * @param rawVpToken - the `vp_token` form field, JSON-encoded.
 * @param query - the DCQL query from the redeemed request state.
 * @param permittedFormats - credential formats the active profile permits.
 * @returns the parsed Presentations — UNVERIFIED, carrying no identity.
 * @throws Oid4vpTransportRejection on any structural mismatch.
 */
export function parseVpToken(
  rawVpToken: string,
  query: DcqlQuery,
  permittedFormats: readonly CredentialFormat[]
): readonly PresentedCredential[] {
  if (rawVpToken.length > MAX_VP_TOKEN_LENGTH) {
    throw new Oid4vpTransportRejection(
      `vp_token exceeds the ${MAX_VP_TOKEN_LENGTH}-character bound`
    );
  }

  let decoded: unknown;

  try {
    decoded = JSON.parse(rawVpToken);
  } catch {
    throw new Oid4vpTransportRejection('vp_token is not valid JSON');
  }

  if (!isPlainObject(decoded)) {
    throw new Oid4vpTransportRejection(
      'vp_token is not a JSON object keyed by DCQL Credential Query id (OID4VP 1.0 §8.1)'
    );
  }

  const requestedIds = new Set(query.credentials.map((credential) => credential.id));

  for (const key of Object.keys(decoded)) {
    if (!requestedIds.has(key)) {
      throw new Oid4vpTransportRejection(
        `vp_token carries an entry for '${key}', which was not requested by the DCQL query`
      );
    }
  }

  const presentations: PresentedCredential[] = [];

  for (const credential of query.credentials) {
    const entry = decoded[credential.id];

    if (entry === undefined) {
      throw new Oid4vpTransportRejection(
        `vp_token has no entry for the requested Credential Query '${credential.id}'`
      );
    }

    if (!Array.isArray(entry)) {
      throw new Oid4vpTransportRejection(
        `vp_token entry for '${credential.id}' is not an array (OID4VP 1.0 §8.1)`
      );
    }

    if (entry.length === 0) {
      throw new Oid4vpTransportRejection(`vp_token entry for '${credential.id}' is an empty array`);
    }

    if (entry.length > 1 && credential.multiple !== true) {
      throw new Oid4vpTransportRejection(
        `vp_token entry for '${credential.id}' carries ${entry.length} Presentations, but the Credential Query did not set 'multiple'`
      );
    }

    if (presentations.length + entry.length > MAX_PRESENTATIONS_PER_RESPONSE) {
      throw new Oid4vpTransportRejection(
        `vp_token carries more than ${MAX_PRESENTATIONS_PER_RESPONSE} Presentations`
      );
    }

    let adapter;

    try {
      adapter = resolveCredentialFormatAdapter(credential.format, permittedFormats);
    } catch (error) {
      // A format the profile no longer permits, or one QAuth cannot read. Either
      // way the response is unusable and the reason stays server-side.
      throw new Oid4vpTransportRejection(
        `no usable format adapter for '${credential.id}': ${error instanceof Error ? error.message : String(error)}`
      );
    }

    for (const value of entry) {
      try {
        presentations.push(adapter.parsePresentation(credential.id, value));
      } catch (error) {
        throw new Oid4vpTransportRejection(error instanceof Error ? error.message : String(error));
      }
    }
  }

  return presentations;
}

/**
 * The outcome of a structurally accepted `direct_post` submission.
 *
 * Note what is NOT on this type: no subject, no claims, no user, no session.
 * Accepting a submission means "the transport was well-formed and correlated" —
 * see the module JSDoc.
 */
export interface Oid4vpDirectPostOutcome {
  /** The redeemed request state, for #234 to bind against. */
  readonly state: RedeemedOid4vpRequestState;
  /** Structurally parsed, UNVERIFIED Presentations. */
  readonly presentations: readonly PresentedCredential[];
}

/**
 * Assert the profile that BUILT the request is still the profile in force
 * (issue #233).
 *
 * A deployment that changed `OID4VP_VERIFIER_PROFILE` between sending a request
 * and receiving its response has changed its posture mid-flight. Accepting the
 * response would validate it under a posture the wallet was never told about —
 * and if the change tightened the profile, under a weaker one than the operator
 * now intends. Fail-closed: pending requests from the previous posture are
 * refused and simply expire.
 *
 * @throws Oid4vpTransportRejection when the postures differ.
 */
export function assertProfileUnchanged(requestProfileId: string, activeProfileId: string): void {
  if (requestProfileId !== activeProfileId) {
    throw new Oid4vpTransportRejection(
      `request was built under verifier profile '${requestProfileId}' but '${activeProfileId}' is now in force`
    );
  }
}
