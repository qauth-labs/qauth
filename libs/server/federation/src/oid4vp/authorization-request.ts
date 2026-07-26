/**
 * OID4VP 1.0 Authorization Request generation — the `oid4vp-1.0-base` profile
 * (issue #233, Phase B).
 *
 * Builds the request QAuth-as-Verifier sends to a wallet:
 * `response_type=vp_token`, `response_mode=direct_post`, a `response_uri`, a
 * `nonce`, a `state`, a DCQL `dcql_query` and `client_metadata`.
 *
 * ## Everything here is profile-gated, fail-closed
 *
 * The builder takes a RESOLVED `VerifierProfile` — one that came out of
 * `resolveVerifierProfile`, which refuses when no profile is selected and throws
 * when the selected one is not provisioned. A deployment that selected nothing
 * therefore cannot reach this function with anything to pass it, which is #296's
 * locked posture: *"There is never a permissive fallback to the more capable
 * profile."*
 *
 * On top of that the builder re-asks the profile about every capability it is
 * about to exercise (response mode, response encryption, client-id prefix,
 * request signing, credential format). Passing a profile in is not the same as
 * honouring it, and `CapabilityPosture` is only real if something reads it.
 *
 * ## What is NOT here
 *
 * - **Signed requests.** `x509_san_dns` (base) and `x509_hash` (HAIP) both need
 *   a JAR signed with ES256, which `@qauth-labs/core-crypto` cannot produce
 *   until #298. Refused explicitly rather than silently downgraded to the
 *   unsigned path — a downgrade is exactly the "half-configured verifier" #299
 *   forbids.
 * - **`request_uri` / JAR delivery and encrypted responses**
 *   (`direct_post.jwt`). Phase C, deferred with #298 and the `haip-1.0` profile.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html §5, §8
 */

import {
  assertPrefixProvisioned,
  assertRequestSigningPosture,
  NO_VERIFIER_MATERIAL,
  type ProvisionedVerifierMaterial,
} from '../profiles/verifier-identity';
import type {
  ClientIdPrefix,
  CredentialFormat,
  ResponseMode,
  VerifierProfile,
} from '../profiles/verifier-profile.types';
import { buildRedirectUriClientId, UNSIGNED_CLIENT_ID_PREFIX } from './client-identifier';
import { type CredentialRequestSpec, resolveCredentialFormatAdapter } from './credential-format';
import { assertValidDcqlQuery, type DcqlQuery } from './dcql';

/** OID4VP 1.0 §5: the Response Type for a presentation request is always this. */
export const OID4VP_RESPONSE_TYPE = 'vp_token';

/** The base OID4VP 1.0 Response Mode this issue implements (§8.2). */
export const DIRECT_POST_RESPONSE_MODE = 'direct_post' satisfies ResponseMode;

/**
 * Verifier metadata sent as `client_metadata` (OID4VP 1.0 §5.1).
 *
 * `vp_formats_supported` is the load-bearing member: it tells the wallet which
 * Credential Formats — and which algorithms within them — this Verifier accepts.
 * It is derived from the active profile rather than hardcoded, so a profile
 * change is the only way to change what QAuth advertises.
 */
export interface VerifierClientMetadata {
  /** Per-format algorithm support, keyed by Credential Format identifier. */
  readonly vp_formats_supported: Readonly<Record<string, Readonly<Record<string, string[]>>>>;
  /** Human-readable Verifier name, when the deployment configured one. */
  readonly client_name?: string;
}

/**
 * The Authorization Request, as it goes on the wire.
 *
 * **There is deliberately no `redirect_uri` member, and there must never be
 * one.** OID4VP 1.0 §8.2: with `response_mode=direct_post` the `response_uri`
 * parameter is REQUIRED and `redirect_uri` MUST NOT be present — a conformant
 * wallet that receives both answers `invalid_request`. Making it
 * unrepresentable in the type is the first of two guards; the second is
 * {@link assertNoRedirectUriParameter}, which catches a value that reached the
 * object through an untyped path.
 */
export interface Oid4vpAuthorizationRequest {
  readonly client_id: string;
  readonly response_type: typeof OID4VP_RESPONSE_TYPE;
  readonly response_mode: typeof DIRECT_POST_RESPONSE_MODE;
  readonly response_uri: string;
  readonly nonce: string;
  readonly state: string;
  readonly dcql_query: DcqlQuery;
  readonly client_metadata: VerifierClientMetadata;
}

/** Inputs to {@link buildOid4vpAuthorizationRequest}. */
export interface BuildOid4vpAuthorizationRequestOptions {
  /**
   * The ACTIVE profile, as returned by `resolveVerifierProfile`.
   *
   * Reading an entry out of `VERIFIER_PROFILES` directly is a lookup, not a
   * resolution — it carries no claim that this deployment can operate the
   * profile. Anything building a live request must come through the resolver.
   */
  readonly profile: VerifierProfile;
  /** Absolute URI of QAuth's `direct_post` endpoint (§8.2, REQUIRED). */
  readonly responseUri: string;
  /** What the Verifier is asking for; at least one entry. */
  readonly credentials: readonly CredentialRequestSpec[];
  /** The request `state`, minted by `generateOid4vpRequestSecrets`. */
  readonly state: string;
  /** The request `nonce`, minted by `generateOid4vpRequestSecrets`. */
  readonly nonce: string;
  /** Prefix to present; defaults to the profile's preferred one. */
  readonly clientIdPrefix?: ClientIdPrefix;
  /** X.509 material the operator provisioned; defaults to none (fail-closed). */
  readonly provisioned?: ProvisionedVerifierMaterial;
  /** Optional human-readable Verifier name for `client_metadata`. */
  readonly clientName?: string;
}

/**
 * Reject a `response_uri` that is not a usable absolute endpoint (§8.2).
 *
 * The `response_uri` is both where the wallet posts and — under the
 * `redirect_uri` prefix — the Verifier's own identifier, so a malformed one is
 * not a cosmetic problem: it is an unidentifiable Verifier.
 *
 * HTTPS is required except on loopback, which mirrors how OAuth 2.1 treats
 * redirect URIs and keeps local development workable without opening a
 * plaintext presentation channel on a real host.
 */
export function assertValidResponseUri(responseUri: string): void {
  let parsed: URL;

  try {
    parsed = new URL(responseUri);
  } catch {
    throw new Error(
      `'response_uri' must be an absolute URI (OID4VP 1.0 §8.2); received '${responseUri}'.`
    );
  }

  const isLoopback =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '[::1]';

  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopback)) {
    throw new Error(
      `'response_uri' must use https (loopback http is allowed for local development); received '${responseUri}'.`
    );
  }

  if (parsed.hash !== '') {
    throw new Error(`'response_uri' must not contain a fragment; received '${responseUri}'.`);
  }
}

/**
 * Assert the request carries no `redirect_uri` parameter (OID4VP 1.0 §8.2).
 *
 * The second of the two guards described on {@link Oid4vpAuthorizationRequest}.
 * It exists because the type-level guarantee only covers values that arrived
 * through the typed path: a request assembled from a spread, a JSON round-trip
 * or a future caller merging extra parameters could still carry the key, and the
 * failure mode is a wallet-side `invalid_request` on every single presentation —
 * a total outage that no local test of the builder would have caught.
 *
 * Exported so callers that extend the request can re-assert it.
 *
 * @throws Error when a `redirect_uri` key is present.
 */
export function assertNoRedirectUriParameter(request: object): void {
  if (Object.prototype.hasOwnProperty.call(request, 'redirect_uri')) {
    throw new Error(
      "An OID4VP request using 'response_mode=direct_post' MUST NOT carry a 'redirect_uri' parameter (OID4VP 1.0 §8.2) — a conformant wallet receiving both it and 'response_uri' returns 'invalid_request'. Under this Response Mode 'redirect_uri' survives only as the Client Identifier Prefix inside 'client_id' (§5.9.3)."
    );
  }
}

/**
 * Advertise per-format algorithm support in `client_metadata` (§5.1).
 *
 * Derived from the profile's `signingAlgs`, which is the profile's statement
 * about acceptable JOSE algorithms. These values describe what QAuth is willing
 * to ACCEPT once #234 validates presentations; nothing at this layer verifies a
 * signature, and the request must still be honest about the posture the
 * deployment declared.
 */
function buildVpFormatsSupported(
  profile: VerifierProfile,
  formats: readonly CredentialFormat[]
): Record<string, Record<string, string[]>> {
  const algs = [...profile.signingAlgs];
  const supported: Record<string, Record<string, string[]>> = {};

  for (const format of formats) {
    supported[format] = {
      'sd-jwt_alg_values': algs,
      'kb-jwt_alg_values': algs,
    };
  }

  return supported;
}

/**
 * Choose the Client Identifier Prefix to present, and refuse the ones QAuth
 * cannot honour yet.
 *
 * Order matters. The profile questions are asked FIRST — permitted set, then
 * provisioned material — so a caller that asks for a prefix the profile does not
 * present gets that answer rather than "#298 is missing", which would invite
 * widening the profile's prefix list to work around a crypto gap.
 */
function selectClientIdPrefix(
  profile: VerifierProfile,
  requested: ClientIdPrefix | undefined,
  provisioned: ProvisionedVerifierMaterial
): typeof UNSIGNED_CLIENT_ID_PREFIX {
  const preferred = profile.verifierIdentity.presentedPrefixes[0];

  if (preferred === undefined) {
    throw new Error(
      `Verifier profile '${profile.id}' presents no Client Identifier Prefix, so QAuth cannot identify itself to a wallet.`
    );
  }

  const prefix = requested ?? preferred.prefix;

  if (!profile.clientIdPrefixes.includes(prefix)) {
    throw new Error(
      `Verifier profile '${profile.id}' does not present the '${prefix}' Client Identifier Prefix (permitted: ${profile.clientIdPrefixes.join(', ')}).`
    );
  }

  assertPrefixProvisioned(profile, prefix, provisioned);

  if (prefix !== UNSIGNED_CLIENT_ID_PREFIX) {
    throw new Error(
      `The '${prefix}' Client Identifier Prefix requires a SIGNED Authorization Request, and this deployment cannot sign one: '@qauth-labs/core-crypto' is EdDSA-only and OID4VP signed requests need ES256 (#298). Refusing rather than falling back to the unsigned '${UNSIGNED_CLIENT_ID_PREFIX}' prefix, which would present a weaker verifier identity than the caller asked for.`
    );
  }

  return prefix;
}

/**
 * Build an `oid4vp-1.0-base` Authorization Request (issue #233, Phase B).
 *
 * Pure: no I/O, no clock, no randomness — `state` and `nonce` are minted by
 * `generateOid4vpRequestSecrets` and passed in, and persisting the request state
 * is the caller's job. That keeps the wire format exhaustively testable without
 * a database, and keeps the single-use redemption story in one place
 * (the request-state store) rather than split across two modules.
 *
 * @param options - see {@link BuildOid4vpAuthorizationRequestOptions}.
 * @returns the request parameters, ready to be delivered to a wallet.
 * @throws Error when the active profile forbids anything the request needs, when
 * the deployment cannot honour a capability (signing, encryption), or when the
 * inputs are malformed.
 */
export function buildOid4vpAuthorizationRequest(
  options: BuildOid4vpAuthorizationRequestOptions
): Oid4vpAuthorizationRequest {
  const { profile, credentials, responseUri } = options;
  const provisioned = options.provisioned ?? NO_VERIFIER_MATERIAL;

  assertValidResponseUri(responseUri);

  // Response mode. `haip-1.0` permits only 'direct_post.jwt' (HAIP §5.1), so it
  // lands here — correctly: the encrypted mode is Phase C and needs #298's JWE
  // stack. The profile's own list decides, so no profile is named.
  if (!profile.responseModes.includes(DIRECT_POST_RESPONSE_MODE)) {
    throw new Error(
      `Verifier profile '${profile.id}' does not permit the '${DIRECT_POST_RESPONSE_MODE}' Response Mode (permitted: ${profile.responseModes.join(', ')}). The encrypted 'direct_post.jwt' mode is deferred with #298 (JWE) and is not implemented by #233.`
    );
  }

  // Response encryption is a separate posture from the mode, and 'required'
  // means the JWE stack must exist outright — it does not yet (#298).
  if (profile.responseEncryption === 'required') {
    throw new Error(
      `Verifier profile '${profile.id}' requires encrypted Authorization Responses, and this deployment has no JWE stack (#298). Refusing rather than asking a wallet for a response it cannot encrypt to us.`
    );
  }

  // Verifier identity. Called for its refusals: it narrows to the one prefix
  // this deployment can present, and every other outcome is a throw.
  selectClientIdPrefix(profile, options.clientIdPrefix, provisioned);

  // The request we are about to build is unsigned. Stated explicitly so a
  // profile declaring `requestSigning: 'required'` refuses here rather than
  // having its posture quietly ignored.
  assertRequestSigningPosture(profile, { signed: false });

  if (credentials.length === 0) {
    throw new Error(
      'An OID4VP Authorization Request must ask for at least one Credential; a request with an empty DCQL query cannot be answered.'
    );
  }

  const dcqlQuery: DcqlQuery = {
    credentials: credentials.map((spec) =>
      resolveCredentialFormatAdapter(spec.format, profile.credentialFormats).buildCredentialQuery(
        spec
      )
    ),
  };

  assertValidDcqlQuery(dcqlQuery);

  const request: Oid4vpAuthorizationRequest = {
    // §5.9.3 under `direct_post`: the identifier IS the Response URI.
    // `selectClientIdPrefix` narrows to the single unsigned prefix, so there is
    // no branch here to get wrong — when #298 makes a signed prefix reachable,
    // its return type widens and this line stops compiling, which is the point.
    client_id: buildRedirectUriClientId(responseUri),
    response_type: OID4VP_RESPONSE_TYPE,
    response_mode: DIRECT_POST_RESPONSE_MODE,
    response_uri: responseUri,
    nonce: options.nonce,
    state: options.state,
    dcql_query: dcqlQuery,
    client_metadata: {
      vp_formats_supported: buildVpFormatsSupported(
        profile,
        dcqlQuery.credentials.map((credential) => credential.format)
      ),
      ...(options.clientName === undefined ? {} : { client_name: options.clientName }),
    },
  };

  assertNoRedirectUriParameter(request);

  return request;
}

/**
 * Render the request as a wallet invocation URI.
 *
 * OID4VP 1.0 §5 delivers request parameters as query parameters of the wallet's
 * Authorization Endpoint (custom scheme or universal link). `dcql_query` and
 * `client_metadata` are JSON-valued parameters and are serialized as JSON
 * strings, per §5.
 *
 * This is the UNSIGNED delivery form. Signed delivery — a JAR passed by
 * `request_uri` — is Phase C (HAIP) and needs #298.
 *
 * @param walletAuthorizationEndpoint - e.g. `openid4vp://` or a universal link.
 * @param request - the built request.
 */
export function encodeOid4vpRequestUri(
  walletAuthorizationEndpoint: string,
  request: Oid4vpAuthorizationRequest
): string {
  assertNoRedirectUriParameter(request);

  const params = new URLSearchParams({
    client_id: request.client_id,
    response_type: request.response_type,
    response_mode: request.response_mode,
    response_uri: request.response_uri,
    nonce: request.nonce,
    state: request.state,
    dcql_query: JSON.stringify(request.dcql_query),
    client_metadata: JSON.stringify(request.client_metadata),
  });

  const separator = walletAuthorizationEndpoint.includes('?') ? '&' : '?';

  return `${walletAuthorizationEndpoint}${separator}${params.toString()}`;
}
