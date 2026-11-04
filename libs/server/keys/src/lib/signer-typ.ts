/**
 * Which token types each signing purpose may sign (ADR-019 Decision 9, issue
 * #464).
 *
 * A JWS names what it is in its protected `typ` header (RFC 8725 §3.11), and a
 * verifier that checks `typ` refuses a token of another type. Binding each
 * purpose to its types means a role allowed to sign one kind of token cannot
 * obtain another kind with the right `typ`: `delivery` cannot get an `at+jwt`,
 * and `api` cannot get a `logout+jwt`.
 *
 * The protection reaches as far as the verifier checks `typ`. QAuth's own
 * verifiers resolve access tokens against `token_signing` keys only, by
 * purpose (`getVerificationKeys`), never against the realm JWKS.
 *
 * Each `event_signing` key signs one kind of event token
 * ({@link EVENT_TOKEN_ALGORITHM}, #624): the Ed25519 key signs Security Event
 * Tokens, and the SSF transmitter serves it at its own `jwks_uri`; the RS256
 * key signs logout tokens, as ID tokens are signed, and the realm JWKS
 * publishes it, because a relying party verifies a logout token there (OpenID
 * Connect Back-Channel Logout 1.0 §2.6; {@link isRealmJwksKey}). So a key the
 * realm JWKS lists never signs a SET (d-1026-09), and the realm JWKS keeps one
 * Ed25519 key, the token key. A relying party tells a logout token from an ID
 * token by `typ`, as RFC 8725 §3.11 and Back-Channel Logout 1.0 §2.4 ask; a
 * logout token carries no `nonce`, which an ID token of a request that sent
 * one must, and the signer holds it to its kind (`eventTokenClaimsProblem`).
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
   * authorization server verifies against the realm JWKS.
   */
  token_signing: Object.freeze(['at+jwt', 'JWT', 'oauth-id-jag+jwt'] as const),
  /**
   * `secevent+jwt` is a Security Event Token (RFC 8417 §2.3); `logout+jwt` is
   * an OpenID Connect Back-Channel Logout 1.0 §2.4 logout token.
   */
  event_signing: Object.freeze(['secevent+jwt', 'logout+jwt'] as const),
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

/**
 * The algorithm each kind of event token is signed with (#624, d-1104-08,
 * d-1104-10). A Security Event Token is signed with the realm's Ed25519
 * `event_signing` key; a logout token with its RS256 one, the algorithm
 * OpenID Connect signs ID tokens with by default and a fresh realm signs its
 * ID tokens with. The signer signs no event token in the other algorithm, so
 * each key signs one kind.
 */
export const EVENT_TOKEN_ALGORITHM = Object.freeze({
  'secevent+jwt': 'EdDSA',
  'logout+jwt': 'RS256',
} as const satisfies Record<JwsTyp<'event_signing'>, string>);

/**
 * The purposes whose published keys make up the realm's JWKS (`jwks_uri`), in
 * their order there: the keys that verify the realm's access tokens and ID
 * tokens, then the `event_signing` keys that verify its logout tokens, which
 * a relying party reads there (OpenID Connect Back-Channel Logout 1.0 §2.6,
 * #624). Of `event_signing`, only the logout-token algorithm's keys
 * ({@link isRealmJwksKey}); the SSF transmitter serves the SET keys at its own
 * JWKS (d-1026-09). The other published purposes appear elsewhere: the
 * federation keys in the entity configuration, the OID4VP keys in the request
 * object and its certificate, and an upstream client-assertion key in the
 * JWKS served to that provider (`getUpstreamJwks`, #547).
 */
export const REALM_JWKS_PURPOSES: readonly JwsSigningPurpose[] = Object.freeze([
  'token_signing',
  'event_signing',
] as const);

/**
 * Whether the realm JWKS lists a published key of this purpose and algorithm:
 * every `token_signing` key, and the `event_signing` keys that sign logout
 * tokens ({@link EVENT_TOKEN_ALGORITHM}), never the ones that sign SETs.
 */
export function isRealmJwksKey(key: {
  readonly purpose: string;
  readonly algorithm: string;
}): boolean {
  if (key.purpose === 'token_signing') return true;
  return key.purpose === 'event_signing' && key.algorithm === EVENT_TOKEN_ALGORITHM['logout+jwt'];
}

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
