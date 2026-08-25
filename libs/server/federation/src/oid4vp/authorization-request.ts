/**
 * OID4VP 1.0 Authorization Request generation (issues #233 Phase B, #377).
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
 * ## Signed requests (#377)
 *
 * A request is signed exactly when its Client Identifier Prefix says so, and the
 * prefix comes from the profile. `redirect_uri` can never be signed (OID4VP 1.0
 * §5.9.3 — such a request is unverifiable, so a signature asserts nothing);
 * `x509_hash` is always signed, because the wallet establishes the Verifier's
 * identity from the `x5c` header of the request object and checks it against the
 * `client_id` digest. There is no third state and no downgrade path: a caller
 * that asks for the signed prefix without provisioning material gets a refusal,
 * never the unsigned prefix it did not ask for.
 *
 * The JWT itself is `request-object.ts`; DELIVERY is
 * {@link encodeOid4vpRequestUri}, which refuses to put a signed request on the
 * wire as query parameters at all — HAIP §5.1 mandates `request_uri`, so the
 * unsigned form has to be unreachable rather than merely unpreferred.
 *
 * ## What is NOT here
 *
 * - **`x509_san_dns`.** The other signed prefix base OID4VP permits. HAIP
 *   mandates `x509_hash` and only that, so #377 builds one signed identity
 *   rather than two, and this refuses the other explicitly rather than
 *   silently downgrading it.
 * - **Encrypted responses** (`direct_post.jwt`). Phase C of #377: the response
 *   mode, the `client_metadata` encryption key and the decrypting intake all
 *   land together, because publishing any one of them alone asks a wallet for a
 *   response QAuth has nowhere to hand to.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html §5, §8
 */

import {
  assertPrefixProvisioned,
  assertRequestSigningAllowed,
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
import type { VerifierSigningMaterial } from '../x509/verifier-signing-material';
import {
  buildRedirectUriClientId,
  buildX509HashClientId,
  CLIENT_ID_PREFIX_SEPARATOR,
  UNSIGNED_CLIENT_ID_PREFIX,
  X509_HASH_CLIENT_ID_PREFIX,
} from './client-identifier';
import { type CredentialRequestSpec, resolveCredentialFormatAdapter } from './credential-format';
import { assertValidDcqlQuery, type DcqlQuery } from './dcql';

/** OID4VP 1.0 §5: the Response Type for a presentation request is always this. */
export const OID4VP_RESPONSE_TYPE = 'vp_token';

/** The base OID4VP 1.0 Response Mode this issue implements (§8.2). */
export const DIRECT_POST_RESPONSE_MODE = 'direct_post' satisfies ResponseMode;

/**
 * The Client Identifier Prefixes this builder can actually render.
 *
 * Narrower than `ClientIdPrefix`, which also names `x509_san_dns`. The narrowing
 * is what makes the `client_id` branch below EXHAUSTIVE: adding a third prefix
 * to this union stops that branch compiling until it is given an answer, which
 * is the same "no capability by silence" property `satisfies Record<...>` gives
 * `deriveCryptoCapabilities`.
 */
export type RenderableClientIdPrefix =
  typeof UNSIGNED_CLIENT_ID_PREFIX | typeof X509_HASH_CLIENT_ID_PREFIX;

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
  /**
   * The VALIDATED verifier key and chain (#377), required by any signed prefix.
   *
   * Distinct from {@link provisioned}, which is a set of marker strings saying
   * WHAT KIND of material exists. This is the material itself, and only
   * `createVerifierSigningMaterial` can produce one — so a request whose
   * `client_id` is an `x509_hash` digest is, by construction, a request whose
   * chain validated at boot. Build the marker set from this value with
   * {@link verifierMaterialProvisionedBy} so the two cannot disagree.
   */
  readonly signingMaterial?: VerifierSigningMaterial;
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
 * cannot honour (#233, #377).
 *
 * Order matters. The profile questions are asked FIRST — permitted set, then
 * provisioned material — so a caller that asks for a prefix the profile does not
 * present gets that answer rather than "this build cannot do it", which would
 * invite widening the profile's prefix list to work around an implementation
 * gap. Only once the profile has said yes does the question become what this
 * build can render.
 */
function selectClientIdPrefix(
  profile: VerifierProfile,
  requested: ClientIdPrefix | undefined,
  provisioned: ProvisionedVerifierMaterial,
  signingMaterial: VerifierSigningMaterial | undefined
): RenderableClientIdPrefix {
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

  if (prefix === UNSIGNED_CLIENT_ID_PREFIX) return prefix;

  if (prefix === X509_HASH_CLIENT_ID_PREFIX) {
    // The per-prefix signing rule, in the module that owns it. It re-asks the
    // permitted-set and provisioning questions above and adds the two this
    // function cannot answer on its own: that `redirect_uri` may never be
    // signed, and that the profile does not FORBID signing. Written down once,
    // there, rather than restated here.
    assertRequestSigningAllowed(profile, prefix, provisioned);

    if (signingMaterial === undefined) {
      throw new Error(
        `The '${prefix}' Client Identifier Prefix identifies QAuth by a digest of its own leaf certificate, so the request must be SIGNED with the key that certificate belongs to — and no verifier signing material was passed to the builder. This is a caller-wiring bug rather than an operator misconfiguration: '${prefix}' passed the provisioning check, so the material exists and was simply not threaded through (#377).`
      );
    }

    return prefix;
  }

  throw new Error(
    `The '${prefix}' Client Identifier Prefix requires a signed Authorization Request identified by a certificate SAN, which QAuth does not implement. HAIP 1.0 §5 mandates '${X509_HASH_CLIENT_ID_PREFIX}' and only that, so #377 builds one signed verifier identity rather than two. Refusing rather than falling back to the unsigned '${UNSIGNED_CLIENT_ID_PREFIX}' prefix, which would present a weaker verifier identity than the caller asked for.`
  );
}

/**
 * Build an OID4VP 1.0 Authorization Request (issues #233 Phase B, #377).
 *
 * Pure: no I/O, no clock, no randomness — `state` and `nonce` are minted by
 * `generateOid4vpRequestSecrets` and passed in, and persisting the request state
 * is the caller's job. That keeps the wire format exhaustively testable without
 * a database, and keeps the single-use redemption story in one place
 * (the request-state store) rather than split across two modules.
 *
 * Purity is also why SIGNING is not done here: producing a JWS is asynchronous
 * and needs a key import, so `request-object.ts` owns it and this function stays
 * a synchronous function of its inputs. What this decides is WHETHER the request
 * is signed — the prefix in `client_id` is that decision, and it is binding on
 * every layer downstream.
 *
 * @param options - see {@link BuildOid4vpAuthorizationRequestOptions}.
 * @returns the request parameters, ready to be signed and/or delivered.
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
  // lands here — correctly: the encrypted mode is Phase C of #377 and arrives
  // with the decrypting intake. The profile's own list decides, so no profile is
  // named.
  if (!profile.responseModes.includes(DIRECT_POST_RESPONSE_MODE)) {
    throw new Error(
      `Verifier profile '${profile.id}' does not permit the '${DIRECT_POST_RESPONSE_MODE}' Response Mode (permitted: ${profile.responseModes.join(', ')}). The encrypted 'direct_post.jwt' mode is Phase C of #377 and is not implemented yet.`
    );
  }

  // Response encryption is a separate posture from the mode, and 'required'
  // means the JWE stack must be WIRED outright — the primitives exist in
  // `@qauth-labs/core-crypto` (#298), but nothing publishes an encryption key or
  // decrypts a response until Phase C of #377.
  if (profile.responseEncryption === 'required') {
    throw new Error(
      `Verifier profile '${profile.id}' requires encrypted Authorization Responses, and this deployment has no wired JWE path (Phase C of #377). Refusing rather than asking a wallet for a response it cannot encrypt to us.`
    );
  }

  // Verifier identity. Called for its refusals AND its answer: it narrows to the
  // prefixes this build can render, and every other outcome is a throw.
  const prefix = selectClientIdPrefix(
    profile,
    options.clientIdPrefix,
    provisioned,
    options.signingMaterial
  );

  // Whether this request is signed follows from the prefix and nothing else —
  // OID4VP 1.0 §5.9.3 makes `redirect_uri` unsignable and `x509_hash`
  // unverifiable unsigned. Stated explicitly so a profile declaring
  // `requestSigning: 'required'` refuses an unsigned request here rather than
  // having its posture quietly ignored, and so a profile that FORBIDS signing
  // refuses a signed one.
  assertRequestSigningPosture(profile, { signed: prefix !== UNSIGNED_CLIENT_ID_PREFIX });

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
    // The break the #233 comment predicted, taken rather than routed around:
    // `selectClientIdPrefix` no longer narrows to a single value, so this line
    // has to branch, and the union's exhaustiveness is what makes a future third
    // prefix a compile error instead of a silent fall-through to the unsigned
    // identity.
    //
    // §5.9.3 under `direct_post`: the unsigned identifier IS the Response URI.
    // Under `x509_hash` it is the digest of the leaf certificate the request
    // object's `x5c` header carries — the same certificate, stated twice, so a
    // wallet can check the two agree.
    client_id:
      prefix === UNSIGNED_CLIENT_ID_PREFIX
        ? buildRedirectUriClientId(responseUri)
        : // `selectClientIdPrefix` throws when the signed prefix has no material,
          // so this is a narrowing rather than an assumption.
          buildX509HashClientId((options.signingMaterial as VerifierSigningMaterial).leafDer),
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
 * How the request reaches the wallet (#377).
 *
 * A discriminated union rather than an optional `requestUri?: string`, because
 * "by reference, to nowhere" is not a valid state and the type should say so.
 */
export type Oid4vpRequestDelivery =
  | {
      /** OID4VP 1.0 §5: the parameters travel as query parameters, unsigned. */
      readonly mode: 'query-parameters';
    }
  | {
      /** RFC 9101 / HAIP §5.1: the wallet fetches a signed request object. */
      readonly mode: 'request-uri';
      /** Absolute URI the wallet GETs the signed request object from. */
      readonly requestUri: string;
    };

/** Delivery for an unsigned request — the base-profile default. */
export const QUERY_PARAMETER_DELIVERY: Oid4vpRequestDelivery = Object.freeze({
  mode: 'query-parameters',
});

/** Whether a `client_id` names the one prefix that is never signed (§5.9.3). */
function isUnsignedClientId(clientId: string): boolean {
  return clientId.startsWith(`${UNSIGNED_CLIENT_ID_PREFIX}${CLIENT_ID_PREFIX_SEPARATOR}`);
}

/**
 * Render the request as a wallet invocation URI.
 *
 * Two forms, and WHICH ONE is not the caller's choice — it follows from the
 * Client Identifier Prefix inside `client_id`:
 *
 * - **Unsigned (`redirect_uri`)** — OID4VP 1.0 §5 delivers the parameters as
 *   query parameters of the wallet's Authorization Endpoint. `dcql_query` and
 *   `client_metadata` are JSON-valued and are serialized as JSON strings, per §5.
 * - **Signed (`x509_hash`)** — HAIP 1.0 §5.1 requires JAR *"with the
 *   `request_uri` parameter"*, so only `client_id` and `request_uri` go on the
 *   wire and everything else lives inside the signed object. Emitting the query
 *   form for a signed request is REFUSED, not merely avoided: a signed request
 *   flattened into query parameters is an unsigned request that happens to carry
 *   a certificate digest as its identifier, which is precisely the downgrade the
 *   mandate exists to prevent.
 *
 * The prefix is read from `client_id` rather than taken as an argument so the
 * two cannot be passed inconsistently — the identifier a wallet will act on IS
 * the statement about signedness.
 *
 * @param walletAuthorizationEndpoint - e.g. `openid4vp://` or a universal link.
 * @param request - the built request.
 * @param delivery - how the request reaches the wallet; defaults to the unsigned
 * query-parameter form, which is refused for a signed request.
 * @throws Error when the delivery form contradicts the request's prefix.
 */
export function encodeOid4vpRequestUri(
  walletAuthorizationEndpoint: string,
  request: Oid4vpAuthorizationRequest,
  delivery: Oid4vpRequestDelivery = QUERY_PARAMETER_DELIVERY
): string {
  assertNoRedirectUriParameter(request);

  const unsigned = isUnsignedClientId(request.client_id);

  if (!unsigned && delivery.mode !== 'request-uri') {
    throw new Error(
      "A signed OID4VP Authorization Request MUST be delivered by 'request_uri' (HAIP 1.0 §5.1 — JAR with the request_uri parameter). Refusing to flatten it into query parameters, which would put the request on the wire unsigned while still naming a certificate-derived Client Identifier (#377)."
    );
  }

  if (unsigned && delivery.mode === 'request-uri') {
    throw new Error(
      `A request using the '${UNSIGNED_CLIENT_ID_PREFIX}' Client Identifier Prefix cannot be delivered by 'request_uri': there is no request object to fetch, because OID4VP 1.0 §5.9.3 makes such a request unverifiable and QAuth therefore never signs one (#377).`
    );
  }

  const separator = walletAuthorizationEndpoint.includes('?') ? '&' : '?';

  if (delivery.mode === 'request-uri') {
    // RFC 9101 §5.2.2: `client_id` stays OUTSIDE the request object so the
    // wallet knows whose identity to establish before it fetches anything.
    // Nothing else does: every other parameter is inside the signature, and
    // duplicating one out here would create a second, unsigned copy a wallet
    // could be steered by.
    const reference = new URLSearchParams({
      client_id: request.client_id,
      request_uri: delivery.requestUri,
    });

    return `${walletAuthorizationEndpoint}${separator}${reference.toString()}`;
  }

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

  return `${walletAuthorizationEndpoint}${separator}${params.toString()}`;
}
