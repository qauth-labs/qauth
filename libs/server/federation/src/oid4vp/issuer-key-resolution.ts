/**
 * Issuer key resolution — the PORT presentation validation verifies against
 * (issue #234).
 *
 * ## Why this is a port and not a function
 *
 * "Which key signed this credential?" has two answers in OID4VP, and they are
 * answered by completely different machinery:
 *
 *  - **`issuer-metadata`** — the key is published by the issuer at its HTTPS
 *    issuer identifier (SD-JWT VC's JWT VC Issuer Metadata). The base-profile
 *    path; a deployment may pin the key set in configuration or fetch it.
 *  - **`x5c`** — the key is the subject public key of the leaf certificate in the
 *    credential's `x5c` JOSE header, accepted only once the chain validates to a
 *    trust anchor the deployment provisioned (HAIP §6.1.1).
 *
 * The second needs operator-provisioned trust anchors and an X.509 chain
 * validator; the first needs an HTTP client, a cache and SSRF controls. Neither
 * belongs inside an SD-JWT parser, and `server-federation` is a pure
 * `scope:server` library with no HTTP client and no configuration of its own.
 *
 * So the validator states what it needs — a key, an issuer identifier that key
 * resolution CONFIRMED, and which method confirmed it — and a deployment plugs
 * in the backend. {@link createStaticIssuerKeyResolver} ships as the
 * configuration-pinned `issuer-metadata` implementation; a fetching resolver and
 * a chain-validating `x5c` resolver are additional implementations of this same
 * port, and adding either requires no change to the validator.
 *
 * ## The one rule a resolver must not break
 *
 * {@link ResolvedIssuerKey.identifier} is what #236 will make a trust decision
 * about. It must be the identifier the resolution ESTABLISHED — the entry a
 * configured key set was found under, or the identity carried by a validated
 * certificate chain — and never the credential's own unverified `iss`. A
 * resolver that echoes {@link IssuerKeyResolutionRequest.issuer} back without
 * having proven anything re-opens the exact bypass `ValidatedIssuer` exists to
 * close, and no type can catch that for you.
 */

import {
  importPublicSigningJwk,
  type JwsAlgorithm,
  type SigningKey,
} from '@qauth-labs/core-crypto';
import type { JWK } from 'jose';

import {
  canonicalizeIssuerIdentifier,
  type IssuerKeyResolutionMethod,
} from '../trust/issuer-identity';

/**
 * What the validator knows about a credential when it needs a key — all of it
 * UNVERIFIED, because nothing can be verified before a key exists.
 */
export interface IssuerKeyResolutionRequest {
  /**
   * The `iss` the credential CLAIMS. Attacker-controlled text: use it to look a
   * key up, never as an established identity.
   */
  readonly issuer: string;
  /** The Issuer-signed JWS protected header's `kid`, when it carried one. */
  readonly keyId?: string;
  /**
   * The Issuer-signed JWS protected header's `x5c` chain, when it carried one —
   * base64 (not base64url) DER certificates, leaf first (RFC 7515 §4.1.6).
   *
   * Surfaced verbatim so a chain-validating backend can be added later without
   * the validator changing: the SD-JWT layer never interprets these bytes.
   */
  readonly x5c?: readonly string[];
  /**
   * The algorithm the credential's header declares, already checked against the
   * caller's permitted set. Passed so the resolver can import the key PINNED to
   * it — a key must be imported for one primitive, not left algorithm-ambiguous.
   */
  readonly algorithm: JwsAlgorithm;
}

/** A verification key, plus the identity that obtaining it established. */
export interface ResolvedIssuerKey {
  /** The public key to verify the Issuer-signed JWS with. */
  readonly key: SigningKey;
  /**
   * The issuer identifier this resolution CONFIRMED — see the module JSDoc.
   * Canonicalized by {@link ValidatedIssuer} before any comparison.
   */
  readonly identifier: string;
  /** Which of the two resolutions produced {@link key}. */
  readonly keyResolution: IssuerKeyResolutionMethod;
}

/**
 * Resolve the key an Issuer-signed JWS must verify under.
 *
 * Returns `undefined` — rather than throwing — when no key can be obtained, so
 * "unknown issuer" is an ordinary refusal on an attacker-reachable path rather
 * than an exception shape a caller might mistake for an infrastructure fault. A
 * resolver that throws anyway is CONTAINED by the validator and treated as
 * `undefined` (fail-closed: a backend that cannot answer has established
 * nothing), which is the same containment `assertIssuerTrusted` applies to a
 * `TrustRegistry` backend.
 */
export type IssuerKeyResolver = (
  request: IssuerKeyResolutionRequest
) => Promise<ResolvedIssuerKey | undefined>;

/**
 * One issuer's published verification keys, as a deployment configures them.
 */
export interface StaticIssuerKeyEntry {
  /** The issuer's HTTPS identifier; canonicalized at construction. */
  readonly issuer: string;
  /**
   * The issuer's public JWKs. More than one is normal (key rotation), and a
   * credential then MUST carry a `kid` — see
   * {@link createStaticIssuerKeyResolver}.
   */
  readonly jwks: readonly JWK[];
}

/**
 * A resolver over key sets pinned in deployment configuration (`issuer-metadata`).
 *
 * The shipped base-profile backend, and the one every test uses. It is a real
 * production path, not a stub: an enterprise issuing to its own workforce pins
 * one issuer's key set and never wants a network fetch on the authentication
 * path. A fetching resolver (JWT VC Issuer Metadata over HTTPS, with caching and
 * SSRF controls) is a drop-in replacement implementing the same port.
 *
 * Selection rules, all fail-closed:
 *
 *  - the requested `iss` must canonicalize and must be a configured entry;
 *  - when the credential carries a `kid`, exactly the JWK with that `kid` is
 *    used — a `kid` naming no configured key resolves to nothing rather than
 *    falling back to "try them all", because a fallback would make `kid` a hint
 *    an attacker can drop to widen the key set;
 *  - when it carries no `kid`, the entry must hold exactly ONE key. An ambiguous
 *    key set is a configuration the credential cannot address, and guessing
 *    which key was meant is how a rotated-out key stays live;
 *  - the JWK must import under the algorithm the caller pinned. This is
 *    `importPublicSigningJwk`'s job (#298) and it rejects a `kty`/`crv`/`alg`
 *    mismatch, private material, and a key its publisher marked `use: 'enc'`.
 *
 * @param entries - the configured issuers and their key sets.
 * @returns an {@link IssuerKeyResolver} closing over a frozen lookup.
 * @throws Error when an entry is unusable. A plain `Error` on purpose: a
 * malformed allowlist is a MIS-PROVISIONED DEPLOYMENT (a 500 with a stack trace
 * is the right signal), not an attacker-reachable outcome — construction happens
 * at bootstrap, never on the request path.
 */
export function createStaticIssuerKeyResolver(
  entries: readonly StaticIssuerKeyEntry[]
): IssuerKeyResolver {
  const keysByIssuer = new Map<string, readonly JWK[]>();

  for (const entry of entries) {
    const identifier = canonicalizeIssuerIdentifier(entry.issuer);

    if (identifier === undefined) {
      throw new Error(
        `Issuer key set entry '${String(entry.issuer)}' is not a usable issuer identity. An issuer identifier must be an absolute https: URL with no userinfo, query or fragment.`
      );
    }

    if (entry.jwks.length === 0) {
      throw new Error(
        `Issuer key set for '${identifier}' is empty. An issuer with no keys can never verify a credential, so configuring one is always a mistake.`
      );
    }

    if (keysByIssuer.has(identifier)) {
      throw new Error(
        `Issuer '${identifier}' is configured twice. Two key sets for one issuer make key selection order-dependent.`
      );
    }

    keysByIssuer.set(identifier, Object.freeze([...entry.jwks]));
  }

  return async (request: IssuerKeyResolutionRequest): Promise<ResolvedIssuerKey | undefined> => {
    const identifier = canonicalizeIssuerIdentifier(request.issuer);
    if (identifier === undefined) return undefined;

    const jwks = keysByIssuer.get(identifier);
    if (jwks === undefined) return undefined;

    const jwk =
      request.keyId === undefined
        ? jwks.length === 1
          ? jwks[0]
          : undefined
        : jwks.find((candidate) => candidate.kid === request.keyId);

    if (jwk === undefined) return undefined;

    try {
      const key = await importPublicSigningJwk(jwk, request.algorithm);
      return { key, identifier, keyResolution: 'issuer-metadata' };
    } catch {
      // A configured key that cannot be imported under the algorithm the
      // credential declares is not a match. Resolving nothing is the fail-closed
      // answer; the alternative would be verifying under a key that was
      // published for a different primitive.
      return undefined;
    }
  };
}
