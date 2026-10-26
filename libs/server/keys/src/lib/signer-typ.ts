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
 * verifiers resolve access tokens against `token_signing` keys only, and the
 * two purposes are published apart (d-1026-09): the realm JWKS holds only
 * `token_signing` keys ({@link REALM_JWKS_PURPOSES}), and the SSF transmitter
 * serves the `event_signing` keys at its own `jwks_uri`. A relying party that
 * reads the realm JWKS and skips the `typ` check therefore still cannot take a
 * Security Event Token for an access token, nor the other way round.
 *
 * A logout token is verified against the realm JWKS (OpenID Connect
 * Back-Channel Logout 1.0 §2.6), which holds no `event_signing` key. Where
 * back-channel logout publishes its keys is for its own issue to settle
 * before it ships.
 *
 * A purpose that is not listed is not signed through `signJws` at all. The
 * scoped purposes have their own operations (`signWebhook`,
 * `signClientAssertion`, #547); the OID4VP request key (#546) gets its own
 * operation or an entry here.
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
 * The purposes whose published keys make up the realm's JWKS (`jwks_uri`):
 * the keys that verify the realm's access tokens and ID tokens. The
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
