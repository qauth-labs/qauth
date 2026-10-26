import type { HybridSignedToken, SignatureAlgorithm } from '@qauth-labs/core-crypto';
import type {
  AccessTokenCredential,
  ActClaim,
  ConfirmationClaim,
  JWTPayload,
} from '@qauth-labs/server-jwt';
import type { RealmJwks, Signer } from '@qauth-labs/server-keys';
import type { FastifyPluginOptions, FastifyRequest } from 'fastify';

/**
 * The signer operations the JWT plugin uses (ADR-019 Decision 9, #491): it
 * signs every token through `signJws` and `signHybrid`, and verifies with the
 * public keys `getVerificationKeys` lists. It holds no key of its own.
 */
export type TokenSigner = Pick<
  Signer,
  'signJws' | 'signHybrid' | 'getVerificationKeys' | 'getJwks'
>;

/**
 * The realm a token is signed for or verified in (ADR-019 Decision 1). The
 * signer sets `iss` from the realm row and `kid` from the realm's active key,
 * so signing needs only the `id`; verification also pins the `issuer`.
 */
export interface TokenRealm {
  /** The realm id: its keys sign the token and verify it. */
  readonly id: string;
  /** The realm's issuer, the `iss` its tokens carry (the realm row's, without a trailing slash). */
  readonly issuer: string;
}

/**
 * JWT plugin configuration options
 */
export interface JwtPluginOptions extends FastifyPluginOptions {
  /**
   * The signer (`fastify.signer` of `@qauth-labs/fastify-plugin-signer`).
   * Every token is signed through it with the realm's active key, and verified
   * with the realm's published keys it lists. The plugin is given no key.
   */
  signer: TokenSigner;
  /**
   * The realm a request belongs to, for `requireJwt` and
   * `verifyRequestAccessToken`: a token verifies only with that realm's keys
   * and only when its `iss` is that realm's issuer.
   */
  requestRealm: (request: FastifyRequest) => TokenRealm;
  /** Access token expiration in seconds */
  accessTokenLifespan: number;
  /** Refresh token expiration in seconds */
  refreshTokenLifespan: number;
  /**
   * Require the RFC 9068 `typ: at+jwt` protected header on every access token
   * this server verifies (#283). Default `false`.
   *
   * PHASE 2 OF A TWO-DEPLOY ROLLOUT. Phase 1 (this build) starts STAMPING `typ`
   * on issuance and already rejects a token whose signed `typ` is present but
   * wrong — that is unconditional and needs no flag, because no token issued
   * before #283 carries a `typ` at all. Only the "`typ` must be PRESENT" half
   * is breaking: enabling it in the same deploy that begins stamping would
   * reject every access token minted by the previous build that is still inside
   * {@link accessTokenLifespan} (default 900s).
   *
   * Turn this on in a LATER deploy, at least one `ACCESS_TOKEN_LIFESPAN` after
   * the build that introduced stamping has fully rolled out.
   */
  requireAccessTokenTyp?: boolean;
  /**
   * Turn on LIVE hybrid (Ed25519 + ML-DSA-65) access-token issuance (#275).
   * Sourced from `HYBRID_SIGNING_ENABLED`, default off. The signer signs the
   * hybrid token with the realm's hybrid pair; a realm without one refuses to
   * sign (`SignerKeyNotFoundError`), and the key boot step refuses to start a
   * deployment whose realm holds half a pair.
   *
   * Turning it on without `enabledSignatureAlgorithms` that enable ML-DSA-65
   * throws at registration: a half-configured hybrid deployment must fail fast,
   * never silently degrade to classical-only.
   */
  hybridSigningEnabled?: boolean;
  /**
   * Operator-enabled signature algorithms (`SIGNING_ALGORITHM_MODE`, threaded
   * from `cryptoEnv.enabledSignatureAlgorithms`).
   *
   * The ML-DSA-65 backend that verifies a hybrid token's second signature is
   * resolved through this list (#248 F7/F11), so the operator allowlist, not a
   * hardcoded literal, decides whether ML-DSA-65 is usable. Absent: no hybrid
   * token verifies here.
   */
  enabledSignatureAlgorithms?: readonly SignatureAlgorithm[];
  /**
   * Optional revocation denylist check (RFC 7009). When provided, the
   * `requireJwt` preHandler calls it AFTER a successful signature/issuer
   * verification with the verified token's `jti`; a truthy result rejects the
   * request as if the token were invalid. Kept as a callback so the JWT plugin
   * stays store-agnostic — the auth-server supplies a Redis-backed denylist.
   */
  isTokenRevoked?: (jti: string | undefined) => Promise<boolean> | boolean;
  /**
   * DPoP at the routes `requireJwt` protects (RFC 9449 §7, #480). When set,
   * `requireJwt` also accepts `Authorization: DPoP <token>` for a DPoP-bound
   * token, and calls this with the request, the token and its verified claims
   * after the signature, issuer and revocation checks. It must throw unless
   * the request carries a valid DPoP proof for that token under the key its
   * `cnf.jkt` names. Kept as a callback so the JWT plugin stays free of the
   * DPoP verifier and its replay store, as {@link isTokenRevoked} keeps it
   * free of Redis.
   *
   * When absent (`DPOP_ENABLED` off), a `DPoP` header is no credential, as
   * before DPoP. A DPoP-bound token sent as a Bearer token is refused either
   * way (RFC 9449 §7.2).
   */
  verifyDpopProof?: (request: FastifyRequest, token: string, claims: JWTPayload) => Promise<void>;
}

/**
 * How a route's access-token check departs from `requireJwt`'s (#509), for
 * `verifyRequestAccessToken`. Each member only changes what it names; the
 * signature, expiry, revocation and DPoP checks always run.
 */
export interface AccessTokenCheckPolicy {
  /**
   * Decide whether the verified token's `iss` is one the route accepts. It
   * replaces the comparison with the issuer of the request's realm, and runs
   * after the signature check with that realm's keys, so it never sees an
   * unverified claim, and it can only narrow which of the realm's tokens
   * pass: a token another realm's keys signed is refused before it runs. A
   * token with no `iss` is refused before it is called. Absent: `iss` must
   * equal the realm's issuer.
   */
  acceptIssuer?: (issuer: string, request: FastifyRequest) => boolean | Promise<boolean>;
  /**
   * Require the RFC 9068 `typ: at+jwt` protected header whatever
   * {@link JwtPluginOptions.requireAccessTokenTyp} says. It can only tighten:
   * `false` or absent leaves the operator's setting in force.
   */
  requireTyp?: boolean;
}

/**
 * JWKS envelope as served by `/.well-known/jwks.json` (RFC 7517 §5): the
 * realm's published `token_signing` keys, as the signer lists them. Ed25519
 * `OKP` keys, `RSA` keys for RS256 ID tokens (#309) and, with hybrid signing,
 * ML-DSA-65 `AKP` keys (#246), each under its own `kid`.
 */
export type Jwks = RealmJwks;

/**
 * JWT payload structure and the RFC 8693 `act` (actor) claim shape.
 * Re-exported to avoid apps needing direct dependency on @qauth-labs/server-jwt
 */
export type { AccessTokenCredential, ActClaim, ConfirmationClaim, HybridSignedToken, JWTPayload };

/**
 * JWT utilities interface
 * Provides JWT token generation and refresh token utilities
 */
export interface JwtUtils {
  /**
   * Sign an access token.
   *
   * Pass `email` / `email_verified` only when the grant includes the `email`
   * scope (the auth-server resolves them with `resolveEmailClaimsForScopes`);
   * omit them otherwise. For client_credentials grants omit them and set
   * `sub` to the `clientId`. `scope` is space-separated per RFC 6749. `aud`
   * falls back to `clientId` when undefined.
   *
   * For the RFC 8693 token-exchange grant, pass `act` to stamp the acting
   * agent into the delegated token (`sub` stays the end-user). `act` is
   * omitted for every non-delegated token. Pass `expiresInOverride` to clamp
   * the delegated token's lifetime to the subject token's remaining lifetime.
   *
   * The signer signs it with the realm's active EdDSA key: `iss` is the
   * realm's issuer and the protected header names the key's `kid`.
   */
  signAccessToken(
    realm: Pick<TokenRealm, 'id'>,
    payload: {
      sub: string;
      email?: string;
      email_verified?: boolean;
      clientId: string;
      scope?: string;
      aud?: string | string[];
      act?: ActClaim;
      /** RFC 9449 §6.1 `cnf.jkt` of a DPoP-bound token; omitted for a Bearer token. */
      cnf?: ConfirmationClaim;
      /**
       * Override the access-token lifespan (seconds). Intended to SHORTEN a token
       * below the configured default — the token-exchange grant clamps the
       * delegated token so it never outlives the subject token. Omitted for
       * normal grants (uses the configured lifespan).
       */
      expiresInOverride?: number;
    }
  ): Promise<string>;
  /**
   * Whether LIVE hybrid issuance is enabled on this server (#275). Routes
   * branch on this to decide between a classical and a hybrid access token.
   */
  isHybridSigningEnabled(): boolean;
  /**
   * Sign a HYBRID access token (ADR-005 / #275): an ordinary Ed25519 compact
   * JWS plus a detached ML-DSA-65 signature over the identical signing-input.
   *
   * Claim shaping is byte-identical to {@link signAccessToken} (both go through
   * `buildAccessTokenClaims`), so the bearer token a client receives is
   * indistinguishable from the classical one — the PQC material is delivered
   * out-of-band via introspection (`reference` delivery, #247).
   *
   * The signer signs it with the realm's hybrid pair: the protected header
   * names the EdDSA key's `kid` and the ML-DSA-65 key's `pqc_kid`.
   *
   * @throws Error if hybrid signing is not enabled on this server.
   */
  signHybridAccessToken(
    realm: Pick<TokenRealm, 'id'>,
    payload: {
      sub: string;
      email?: string;
      email_verified?: boolean;
      clientId: string;
      scope?: string;
      aud?: string | string[];
      act?: ActClaim;
      /** RFC 9449 §6.1 `cnf.jkt` of a DPoP-bound token; omitted for a Bearer token. */
      cnf?: ConfirmationClaim;
      /** Narrow the lifespan below the configured default (never widens). */
      expiresInOverride?: number;
    }
  ): Promise<HybridSignedToken>;
  /**
   * Verify a hybrid access token: the Ed25519 component always, plus the
   * ML-DSA-65 component whenever the ISSUER-SIGNED `pqc_alg` header asserts it
   * (binding regardless of `requirePqc`, #248 F1). Both keys are the realm's:
   * the Ed25519 key by the token's `kid`, the ML-DSA key by the signed
   * `pqc_kid` (#248 F5). `iss` must be the realm's issuer.
   *
   * @throws JWTInvalidError if PQC verification is not configured here, or no
   *   key of the realm has the token's `kid`.
   * @throws CryptoVerificationError on any verification failure, including a
   *   stripped detached signature on a token whose header asserts `pqc_alg`.
   */
  verifyHybridAccessToken(
    realm: TokenRealm,
    hybrid: HybridSignedToken,
    options: { audience?: string | string[]; requirePqc: boolean }
  ): Promise<JWTPayload>;
  /**
   * Sign an OIDC ID token (OpenID Connect Core 1.0 §2).
   *
   * Issued by the token endpoint when the granted scope includes `openid`.
   * Signed with the realm's active RS256 `token_signing` key when it has one
   * (#309, what OIDC Basic/Config certification requires), otherwise with its
   * EdDSA key, and with the lifespan of access tokens; `aud` is the client
   * identifier, `nonce` is echoed when the client supplied one in the
   * authorization request. Identity claims (`email`, `email_verified`,
   * `name`) are included when the caller passes them; the token route passes
   * each only under the scope that releases it (`email`, `profile`).
   */
  signIdToken(
    realm: Pick<TokenRealm, 'id'>,
    payload: {
      sub: string;
      audience: string;
      email?: string;
      email_verified?: boolean;
      name?: string;
      nonce?: string;
      /**
       * OIDC Core §2 `auth_time` — the end-user authentication time in epoch
       * MILLISECONDS (session establishment). `signIdToken` maps it to the
       * `auth_time` claim in epoch SECONDS (floored). Omitted when unknown.
       */
      authTime?: number;
      /**
       * OIDC Core §2 `acr` — the authentication event's assurance level, already
       * mapped to the deployment's vocabulary (#237). Omitted (claim absent)
       * whenever no assurance above `low` was established, which is every password
       * login.
       *
       * This payload type is structurally duplicated from `SignIdTokenPayload` in
       * `@qauth-labs/server-jwt` (the decorator surface may not import it), so a
       * new field must be added in BOTH places or the app cannot pass it.
       */
      acr?: string;
      /**
       * OIDC `sid` — the browser session behind the authorization code (#549),
       * as back-channel logout names it. Passed only by the code exchange, and
       * only when a browser session backs the code; omitted (claim absent)
       * otherwise.
       */
      sid?: string;
    }
  ): Promise<string>;
  /**
   * Generate a refresh token pair (token and hash)
   */
  generateRefreshToken(): { token: string; tokenHash: string };
  /**
   * Hash a refresh token
   */
  hashRefreshToken(token: string): string;
  /**
   * Verify an access token of `realm` and return payload.
   *
   * The token verifies only with one of the realm's verification keys: the
   * one its `kid` names, or, for a token with no `kid` (issued before tokens
   * named their key, #491), each EdDSA key of the realm. Its `iss` MUST be the
   * realm's issuer (RFC 9700 mix-up defence). When `audience` is provided,
   * the token's `aud` claim MUST match (string or array intersection per
   * RFC 7519 §4.1.3).
   * @throws JWTExpiredError if token has expired
   * @throws JWTInvalidError if token is invalid, no key of the realm verifies
   *   it, the audience mismatches, or the issuer mismatches
   */
  verifyAccessToken(
    realm: TokenRealm,
    token: string,
    options?: { audience?: string | string[] }
  ): Promise<JWTPayload>;
  /**
   * Extract JWT token from Authorization header
   * @param authHeader - Authorization header value (e.g., "Bearer <token>")
   * @returns JWT token string or null if header is missing or invalid format
   */
  extractFromHeader(authHeader: string | undefined): string | null;
  /**
   * Extract the access token of an `Authorization` header with its scheme:
   * `Bearer`, or `DPoP` when the plugin was given `verifyDpopProof` (RFC 9449
   * §7.1). A `DPoP` header is no credential on a server that does not verify
   * DPoP proofs.
   */
  extractCredentialFromHeader(authHeader: string | undefined): AccessTokenCredential | null;
  /**
   * Decode a JWT token without verification
   * WARNING: This does NOT verify the signature. Only use for:
   * - Reading claims from expired tokens (e.g., logout with expired token)
   * - Debugging/logging purposes
   * @throws JWTInvalidError if token is malformed
   */
  decodeTokenUnsafe(token: string): JWTPayload;
  /**
   * Get access token lifespan in seconds
   */
  getAccessTokenLifespan(): number;
  /**
   * Get refresh token lifespan in seconds
   */
  getRefreshTokenLifespan(): number;
  /**
   * The `id_token_signing_alg_values_supported` values discovery must advertise
   * for `realm` (OIDC Discovery 1.0), reflecting its active `token_signing`
   * keys: `['RS256','EdDSA']` when it has an RS256 key (#309, RS256 is the
   * default ID-token signature then), otherwise `['EdDSA']`.
   */
  getIdTokenSigningAlgValuesSupported(realm: Pick<TokenRealm, 'id'>): Promise<string[]>;
  /**
   * The realm's JWKS, ready to serve at `/.well-known/jwks.json` (RFC 7517):
   * its published `token_signing` keys, as the signer lists them.
   */
  getJwks(realm: Pick<TokenRealm, 'id'>): Promise<Jwks>;
}
