/**
 * Which token types each signing purpose may sign (ADR-019 Decision 9, issue
 * #464).
 *
 * A JWS names what it is in its protected `typ` header (RFC 8725 §3.11), and a
 * verifier that checks `typ` refuses a token of another type. Binding each
 * purpose to its types, and each role to the types it may ask for
 * (`SIGNER_POLICY`), means a role allowed to sign one kind of token cannot
 * obtain another kind with the right `typ`: `delivery` cannot get an `at+jwt`
 * or an ID token, and `api` cannot get a `logout+jwt`.
 *
 * The protection reaches as far as the verifier checks `typ`. QAuth's own
 * verifiers resolve access tokens against `token_signing` keys only, and the
 * two purposes are published apart (d-1026-09): the realm JWKS holds only
 * `token_signing` keys ({@link REALM_JWKS_PURPOSES}), and the SSF transmitter
 * serves the `event_signing` keys at its own `jwks_uri`. A relying party that
 * reads the realm JWKS and skips the `typ` check therefore still cannot take a
 * Security Event Token for an access token, nor the other way round.
 *
 * A logout token is signed with the keys that sign ID tokens (OpenID Connect
 * Back-Channel Logout 1.0 §2.4), so `logout+jwt` is a `token_signing` type,
 * signed in the ID tokens' algorithm ({@link idTokenAlgorithm}), and a relying
 * party verifies it at the realm JWKS (§2.6; #624, ADR-019 Decision 9 as
 * amended 2026-11-04). It is told from an ID token by its `typ` and its
 * `events` claim, and it never carries a `nonce` (§2.4): the signer holds it to
 * that kind (`eventTokenClaimsProblem`).
 *
 * A purpose that is not listed is not signed through `signJws` at all. The
 * scoped purposes have their own operations (`signWebhook`,
 * `signClientAssertion`, #547), and so does the OID4VP request key
 * (`signRequestObject`, #546): a request object names its client in `iss` and
 * carries its certificate chain in `x5c`, neither of which `signJws` lets a
 * caller set.
 */
export const JWS_TYP_BY_PURPOSE = Object.freeze({
  /**
   * `at+jwt` is an RFC 9068 §2.1 access token; `JWT` is the `typ` QAuth stamps
   * on an OIDC ID token (`ID_TOKEN_TYP` in `@qauth-labs/server-jwt`);
   * `oauth-id-jag+jwt` is an Identity Assertion JWT Authorization Grant
   * (draft-ietf-oauth-identity-assertion-authz-grant), which a target
   * authorization server verifies against the realm JWKS; `logout+jwt` is an
   * OpenID Connect Back-Channel Logout 1.0 logout token, which the keys of the
   * ID tokens sign (§2.4, #624).
   */
  token_signing: Object.freeze(['at+jwt', 'JWT', 'oauth-id-jag+jwt', 'logout+jwt'] as const),
  /** `secevent+jwt` is a Security Event Token (RFC 8417 §2.3). */
  event_signing: Object.freeze(['secevent+jwt'] as const),
});

/** A purpose `signJws` signs with. See {@link JWS_TYP_BY_PURPOSE}. */
export type JwsSigningPurpose = keyof typeof JWS_TYP_BY_PURPOSE;

/** The purposes `signJws` signs with, in the order of {@link JWS_TYP_BY_PURPOSE}. */
export const JWS_SIGNING_PURPOSES: readonly JwsSigningPurpose[] = Object.freeze(
  Object.keys(JWS_TYP_BY_PURPOSE) as JwsSigningPurpose[]
);

/** A `typ` that `purpose` may sign. */
export type JwsTyp<P extends JwsSigningPurpose = JwsSigningPurpose> =
  (typeof JWS_TYP_BY_PURPOSE)[P][number];

/** Whether `purpose` is one `signJws` signs with. */
export function isJwsSigningPurpose(purpose: unknown): purpose is JwsSigningPurpose {
  return typeof purpose === 'string' && Object.hasOwn(JWS_TYP_BY_PURPOSE, purpose);
}

/** Whether a key of `purpose` may sign a token of type `typ`. The comparison is exact. */
export function isTypAllowed(purpose: JwsSigningPurpose, typ: unknown): typ is JwsTyp {
  return (JWS_TYP_BY_PURPOSE[purpose] as readonly unknown[]).includes(typ);
}

/** Every `typ` that `signJws` signs, in the order of {@link JWS_TYP_BY_PURPOSE}. */
export const JWS_TYPS: readonly JwsTyp[] = Object.freeze(
  JWS_SIGNING_PURPOSES.flatMap((purpose): readonly JwsTyp[] => JWS_TYP_BY_PURPOSE[purpose])
);

/**
 * The purpose whose keys sign tokens of type `typ`, or `undefined` for a type
 * `signJws` does not sign. No two purposes share a type, so the type names the
 * key: a logout token is a `token_signing` type (#624).
 */
export function jwsPurposeOfTyp(typ: unknown): JwsSigningPurpose | undefined {
  return JWS_SIGNING_PURPOSES.find((purpose) => isTypAllowed(purpose, typ));
}

/**
 * The algorithm a realm signs its ID tokens with, and so its logout tokens
 * (OpenID Connect Back-Channel Logout 1.0 §2.4, #624): `RS256` while the realm
 * holds an active RS256 `token_signing` key, which the OpenID certification
 * suite verifies (#309), and `EdDSA` otherwise. The auth server's ID tokens
 * and the signer's logout tokens both take it from here.
 *
 * @param activeAlgorithms - the algorithms of the realm's active `token_signing` keys
 */
export function idTokenAlgorithm(activeAlgorithms: Iterable<string>): 'RS256' | 'EdDSA' {
  for (const algorithm of activeAlgorithms) {
    if (algorithm === 'RS256') return 'RS256';
  }
  return 'EdDSA';
}

/**
 * The purposes whose published keys make up the realm's JWKS (`jwks_uri`):
 * the keys that verify the realm's access tokens, ID tokens and logout tokens
 * (Back-Channel Logout 1.0 §2.6, #624). The
 * `event_signing` keys are published apart, at the SSF transmitter's own JWKS
 * (`getVerificationKeys`, d-1026-09), so a token of one purpose never verifies
 * against the key set of the other. The other published purposes appear
 * elsewhere too: the federation keys in the entity configuration, the OID4VP
 * keys in the request object and its certificate, and an upstream
 * client-assertion key in the JWKS served to that provider
 * (`getUpstreamJwks`, #547).
 */
export const REALM_JWKS_PURPOSES: readonly JwsSigningPurpose[] = Object.freeze([
  'token_signing',
] as const);

/**
 * The `typ` of a client assertion: a client authentication JWT, explicitly
 * typed as draft-ietf-oauth-rfc7523bis §4 asks. It is a `typ` no realm verifier
 * accepts, so an assertion is never usable as a QAuth token.
 */
export const CLIENT_ASSERTION_TYP = 'client-authentication+jwt';

/**
 * The `typ` of an OID4VP request object: a JWT-Secured Authorization Request
 * (RFC 9101 §10.8), which `signRequestObject` stamps (#546). No realm verifier
 * accepts it, so a request object is never usable as a QAuth token, and no
 * other operation signs it. `@qauth-labs/server-federation` names the same
 * string (`OID4VP_REQUEST_OBJECT_TYP`); this library may not import it, so a
 * test of the auth server pins the two equal.
 */
export const OID4VP_REQUEST_OBJECT_TYP = 'oauth-authz-req+jwt';

/**
 * The purposes whose published keys `getVerificationKeys` lists: the
 * `signJws` purposes and the OID4VP request key (#546). Nothing in QAuth
 * verifies a request object; the auth server reads the request key's public
 * half to check, at boot, that the configured certificate chain names it, on
 * a process that holds no key.
 */
export const VERIFICATION_KEY_PURPOSES = Object.freeze([
  ...JWS_SIGNING_PURPOSES,
  'oid4vp_request_signing',
] as const);

/** A purpose whose verification keys the signer lists. See {@link VERIFICATION_KEY_PURPOSES}. */
export type VerificationKeyPurpose = JwsSigningPurpose | 'oid4vp_request_signing';

/** Whether `purpose` is one whose verification keys the signer lists. */
export function isVerificationKeyPurpose(purpose: unknown): purpose is VerificationKeyPurpose {
  return (
    typeof purpose === 'string' &&
    (VERIFICATION_KEY_PURPOSES as readonly string[]).includes(purpose)
  );
}
