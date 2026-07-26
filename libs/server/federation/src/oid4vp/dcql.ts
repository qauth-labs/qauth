/**
 * DCQL — Digital Credentials Query Language (OID4VP 1.0 Final §6), issue #233.
 *
 * DCQL is the ONLY query mechanism OID4VP 1.0 defines. `presentation_definition`
 * (DIF Presentation Exchange) belonged to OID4VP Draft 22 and is superseded —
 * ADR-004's spec refresh records this as a forward constraint, so there is
 * nothing to migrate here, only a wrong turn to avoid. Nothing in this module
 * may grow a `presentation_definition` path.
 *
 * These are TRANSPORT types. A DCQL query says which Credentials a Verifier
 * wants; it says nothing about whether the response is trustworthy. Deciding
 * that is #234 (presentation validation) and #236 (issuer trust).
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html §6
 */

import type { CredentialFormat } from '../profiles/verifier-profile.types';

/**
 * A DCQL Claims Query (OID4VP 1.0 §6.4) — one claim the Verifier asks for.
 *
 * `path` is a claims path pointer (§6.4.1): each component selects an object
 * key (string), an array index (number), or ALL array elements (`null`).
 */
export interface DcqlClaimsQuery {
  /** Optional identifier, referenced from a Claim Set (§6.4.2). */
  readonly id?: string;
  /** Claims path pointer into the credential's claim structure (§6.4.1). */
  readonly path: readonly (string | number | null)[];
  /** Optional set of accepted values (§6.4). */
  readonly values?: readonly (string | number | boolean)[];
}

/**
 * A DCQL Credential Query (OID4VP 1.0 §6.1) — one Credential the Verifier wants.
 *
 * `meta` is format-specific by design (§6.1: "an object defining additional
 * properties requested … that are specific to the Credential Format"), which is
 * exactly the seam the format-adapter boundary sits on: `dc+sd-jwt` fills it
 * with `vct_values`, and a future `mso_mdoc` adapter fills it with
 * `doctype_value` — without this type changing.
 */
export interface DcqlCredentialQuery {
  /** Identifier for this query; the `vp_token` response is keyed by it (§8.1). */
  readonly id: string;
  readonly format: CredentialFormat;
  /** Whether more than one matching Presentation may be returned (§6.1). */
  readonly multiple?: boolean;
  /** Format-specific constraints — owned by the format adapter. */
  readonly meta?: Readonly<Record<string, unknown>>;
  readonly claims?: readonly DcqlClaimsQuery[];
}

/** A DCQL query (OID4VP 1.0 §6), carried as the request's `dcql_query`. */
export interface DcqlQuery {
  readonly credentials: readonly DcqlCredentialQuery[];
}

/**
 * OID4VP 1.0 §6.1: a Credential Query `id` "MUST consist of alphanumeric,
 * underscore (`_`) or hyphen (`-`) characters".
 *
 * Enforced on the way OUT (we must not emit a non-conformant id a wallet would
 * reject) and relied on when correlating the `vp_token` map on the way IN.
 */
export const DCQL_ID_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Upper bound on Credential Queries in one request.
 *
 * Not a spec limit — a self-imposed bound so a misconfigured caller cannot ask a
 * wallet for an unbounded number of credentials, and so the response parser has
 * a finite key space to correlate against.
 */
export const MAX_DCQL_CREDENTIAL_QUERIES = 16;

/**
 * Validate a DCQL query we are about to SEND (issue #233).
 *
 * Outbound-only: a wallet is entitled to reject a malformed request, and
 * discovering that from a wallet's `invalid_request` is far worse than
 * discovering it here. Inbound correlation is
 * {@link module:oid4vp/direct-post}'s job and validates different things.
 *
 * @param query - the query about to be embedded as `dcql_query`.
 * @throws Error when the query is empty, oversized, or carries duplicate or
 * non-conformant Credential Query ids.
 */
export function assertValidDcqlQuery(query: DcqlQuery): void {
  if (query.credentials.length === 0) {
    throw new Error(
      'A DCQL query must contain at least one Credential Query (OID4VP 1.0 §6). An empty query asks a wallet for nothing and cannot be correlated with any response.'
    );
  }

  if (query.credentials.length > MAX_DCQL_CREDENTIAL_QUERIES) {
    throw new Error(
      `A DCQL query may carry at most ${MAX_DCQL_CREDENTIAL_QUERIES} Credential Queries (QAuth bound, not a spec limit); received ${query.credentials.length}.`
    );
  }

  const seen = new Set<string>();

  for (const credential of query.credentials) {
    if (!DCQL_ID_PATTERN.test(credential.id)) {
      throw new Error(
        `DCQL Credential Query id '${credential.id}' is not conformant: OID4VP 1.0 §6.1 allows only alphanumeric, underscore or hyphen characters.`
      );
    }

    if (seen.has(credential.id)) {
      throw new Error(
        `DCQL Credential Query id '${credential.id}' is duplicated. Ids key the 'vp_token' response object (OID4VP 1.0 §8.1), so duplicates make the response uncorrelatable.`
      );
    }

    seen.add(credential.id);
  }
}

/**
 * Re-hydrate a DCQL query that was persisted with its request state (#233).
 *
 * The row's `dcql_query` is jsonb: TypeScript's `$type<Record<string, unknown>>`
 * is an assertion about what we wrote, not a guarantee about what comes back. A
 * bare cast would let a hand-edited row, a partially-applied migration or a
 * future schema change surface as `undefined.map is not a function` deep inside
 * response correlation — on the unauthenticated response path, where the failure
 * is least debuggable.
 *
 * Structural only: it checks the shape the response parser walks (a
 * `credentials` array of `{ id, format }` objects) and leaves format-specific
 * `meta` alone, which is the format adapter's business.
 *
 * ## Caller contract on the response path
 *
 * A failure here is a SERVER data-integrity failure, not a client one — nothing
 * a caller sends reaches this column. It is deliberately a plain `Error` rather
 * than an {@link module:oid4vp/direct-post.Oid4vpTransportRejection}, because
 * that is what it is.
 *
 * But the `direct_post` route can only reach it AFTER the `state` has been
 * redeemed, so letting it surface as its own status would make it the one
 * response shape a real, live, unconsumed `state` uniquely produces — an
 * enumeration oracle on an otherwise uniformly-refusing endpoint. The route
 * therefore logs it at `error` and re-throws it as the standard rejection. Any
 * future caller on an unauthenticated path owes the same treatment: loud in the
 * log, indistinguishable on the wire.
 *
 * @param value - the deserialized `dcql_query` column.
 * @throws Error when the stored value is not a usable DCQL query.
 */
export function parseStoredDcqlQuery(value: unknown): DcqlQuery {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Stored dcql_query is not a JSON object.');
  }

  const credentials = (value as { credentials?: unknown }).credentials;

  if (!Array.isArray(credentials)) {
    throw new Error("Stored dcql_query has no 'credentials' array.");
  }

  for (const credential of credentials) {
    if (typeof credential !== 'object' || credential === null) {
      throw new Error('Stored dcql_query contains a non-object Credential Query.');
    }

    const { id, format } = credential as { id?: unknown; format?: unknown };

    if (typeof id !== 'string' || typeof format !== 'string') {
      throw new Error(
        "Stored dcql_query contains a Credential Query without a string 'id'/'format'."
      );
    }
  }

  return value as DcqlQuery;
}
