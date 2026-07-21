import type { HybridSignedToken, SignatureAlgorithm } from '@qauth-labs/core-crypto';
import type { ActClaim, AkpJwk, JWTPayload, PublicJwk, Rs256Jwk } from '@qauth-labs/server-jwt';
import type { FastifyPluginOptions } from 'fastify';

/**
 * JWT plugin configuration options
 */
export interface JwtPluginOptions extends FastifyPluginOptions {
  /** JWT private key in PEM format */
  privateKey: string;
  /** JWT public key in PEM format (optional, can be derived from private key) */
  publicKey?: string;
  /** JWT issuer URL */
  issuer: string;
  /** Access token expiration in seconds */
  accessTokenLifespan: number;
  /** Refresh token expiration in seconds */
  refreshTokenLifespan: number;
  /**
   * Optional stable key identifier published in the JWKS `kid` member.
   * Required once key rotation is enabled; absent for a single-active-key setup.
   */
  keyId?: string;
  /**
   * Optional RS256 (RSASSA-PKCS1-v1_5 + SHA-256) private key in PKCS#8 PEM (#309).
   *
   * OPTIONAL and env-provisioned (`JWT_RS256_PRIVATE_KEY`/`_PATH`). When present:
   * - `getJwks()` additionally publishes the derived RSA PUBLIC key as an `RSA`
   *   JWK (with a `kid` distinct from the EdDSA key);
   * - `signIdToken()` signs ID tokens with RS256 by DEFAULT (access tokens stay
   *   EdDSA);
   * - discovery advertises `id_token_signing_alg_values_supported: ['RS256','EdDSA']`.
   *
   * Absent → behaviour is exactly as before: EdDSA-only ID tokens, single JWKS
   * key, discovery lists `['EdDSA']`. This unblocks OIDC Basic/Config OP
   * certification (#286), which hard-fails an EdDSA-only OP. It is deliberately
   * NOT generated at boot: a boot-generated RSA key would break JWKS stability
   * across restarts and across instances.
   */
  rs256PrivateKey?: string;
  /**
   * Optional RS256 public key in SPKI PEM (#309). When omitted, the public key
   * is derived from {@link rs256PrivateKey} (public material only). Provide it
   * only when the private key is not available to this process.
   */
  rs256PublicKey?: string;
  /**
   * Stable `kid` for the RS256 key published in the RSA JWK (#309). Optional,
   * but recommended so the RSA entry carries a `kid` DISTINCT from the EdDSA
   * key; enforced distinct at boot via `assertDistinctJwksKeyIds`.
   */
  rs256KeyId?: string;
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
   * Optional ML-DSA-65 private key as a base64url 32-byte seed (#246). When
   * present, `getJwks()` additionally publishes the derived ML-DSA PUBLIC key
   * as an `AKP` JWK alongside the Ed25519 `OKP` entry, so PQC-capable verifiers
   * can retrieve it. Supplied by the auth-server only when hybrid signing is
   * enabled (`HYBRID_SIGNING_ENABLED`); no ML-DSA-signed token is issued by
   * this plugin. Absent → JWKS is EdDSA-only, exactly as before.
   */
  mlDsaSeed?: string;
  /** Stable `kid` for the ML-DSA key published in the AKP JWK (#246). */
  mlDsaKeyId?: string;
  /**
   * Turn on LIVE hybrid (Ed25519 + ML-DSA-65) token issuance (#275). Sourced
   * from `HYBRID_SIGNING_ENABLED`, default off.
   *
   * When true the plugin retains the ML-DSA PRIVATE key and exposes
   * {@link JwtUtils.signHybridAccessToken}; when false only the derived public
   * key is kept (JWKS publication, #246) and no hybrid token can be minted.
   * Enabling it without `mlDsaSeed` throws at registration — a half-configured
   * hybrid deployment must fail fast, never silently degrade to classical-only.
   */
  hybridSigningEnabled?: boolean;
  /**
   * Operator-enabled signature algorithms (`SIGNING_ALGORITHM_MODE`, threaded
   * from `cryptoEnv.enabledSignatureAlgorithms`).
   *
   * REQUIRED whenever {@link mlDsaSeed} is set (#248 F7/F11): boot-time ML-DSA
   * key derivation resolves its backend through `getSignatureBackend`, so the
   * operator allowlist — not a hardcoded literal — decides whether ML-DSA-65 is
   * usable at all, and a registered native backend (#244) is selectable.
   */
  enabledSignatureAlgorithms?: readonly SignatureAlgorithm[];
  /**
   * Retired Ed25519 verification keys to keep publishing in the JWKS (#248 F9).
   *
   * After a signing-key rotation, tokens signed by the previous key stay valid
   * until they expire; publishing the retired PUBLIC key under its OWN `kid`
   * lets verifiers resolve them. Each `keyId` MUST be distinct from every other
   * published `kid` (enforced at boot) — see `assertDistinctJwksKeyIds`.
   */
  retiredKeys?: readonly { publicKey: string; keyId: string }[];
  /**
   * Retired ML-DSA-65 verification keys, as base64url raw PUBLIC keys, published
   * as `AKP` JWKs under their own `kid` (#248 F9). PUBLIC material only — a
   * retired key is never configured as a seed.
   */
  retiredMlDsaPublicKeys?: readonly { publicKey: string; keyId: string }[];
  /**
   * Optional revocation denylist check (RFC 7009). When provided, the
   * `requireJwt` preHandler calls it AFTER a successful signature/issuer
   * verification with the verified token's `jti`; a truthy result rejects the
   * request as if the token were invalid. Kept as a callback so the JWT plugin
   * stays store-agnostic — the auth-server supplies a Redis-backed denylist.
   */
  isTokenRevoked?: (jti: string | undefined) => Promise<boolean> | boolean;
}

/**
 * JWKS envelope as served by `/.well-known/jwks.json` (RFC 7517 §5).
 */
export interface Jwks {
  /**
   * Ed25519 `OKP` keys; when an RS256 key is configured, the `RSA` key (#309);
   * and, when hybrid signing is configured, ML-DSA `AKP` keys (#246).
   */
  keys: (PublicJwk | Rs256Jwk | AkpJwk)[];
}

/**
 * JWT payload structure and the RFC 8693 `act` (actor) claim shape.
 * Re-exported to avoid apps needing direct dependency on @qauth-labs/server-jwt
 */
export type { ActClaim, HybridSignedToken, JWTPayload };

/**
 * JWT utilities interface
 * Provides JWT token generation and refresh token utilities
 */
export interface JwtUtils {
  /**
   * Sign an access token.
   *
   * For user-context grants (authorization_code, refresh_token, password
   * login) pass `email` / `email_verified`. For client_credentials grants
   * omit them and set `sub` to the `clientId`. `scope` is space-separated
   * per RFC 6749. `aud` falls back to `clientId` when undefined.
   *
   * For the RFC 8693 token-exchange grant, pass `act` to stamp the acting
   * agent into the delegated token (`sub` stays the end-user). `act` is
   * omitted for every non-delegated token. Pass `expiresInOverride` to clamp
   * the delegated token's lifetime to the subject token's remaining lifetime.
   */
  signAccessToken(payload: {
    sub: string;
    email?: string;
    email_verified?: boolean;
    clientId: string;
    scope?: string;
    aud?: string | string[];
    act?: ActClaim;
    /**
     * Override the access-token lifespan (seconds). Intended to SHORTEN a token
     * below the configured default — the token-exchange grant clamps the
     * delegated token so it never outlives the subject token. Omitted for
     * normal grants (uses the configured lifespan).
     */
    expiresInOverride?: number;
  }): Promise<string>;
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
   * @throws Error if hybrid signing is not enabled on this server.
   */
  signHybridAccessToken(payload: {
    sub: string;
    email?: string;
    email_verified?: boolean;
    clientId: string;
    scope?: string;
    aud?: string | string[];
    act?: ActClaim;
    /** Narrow the lifespan below the configured default (never widens). */
    expiresInOverride?: number;
  }): Promise<HybridSignedToken>;
  /**
   * Verify a hybrid access token: the Ed25519 component always, plus the
   * ML-DSA-65 component whenever the ISSUER-SIGNED `pqc_alg` header asserts it
   * (binding regardless of `requirePqc`, #248 F1). The ML-DSA key is resolved
   * from the signed `pqc_kid` (#248 F5).
   *
   * @throws JWTInvalidError if PQC verification is not configured here.
   * @throws CryptoVerificationError on any verification failure, including a
   *   stripped detached signature on a token whose header asserts `pqc_alg`.
   */
  verifyHybridAccessToken(
    hybrid: HybridSignedToken,
    options: { audience?: string | string[]; issuer?: string; requirePqc: boolean }
  ): Promise<JWTPayload>;
  /**
   * Sign an OIDC ID token (OpenID Connect Core 1.0 §2).
   *
   * Issued by the token endpoint when the granted scope includes `openid`.
   * Uses the same EdDSA signing key and lifespan as access tokens; `aud` is
   * the client identifier, `nonce` is echoed when the client supplied one in
   * the authorization request. Identity claims (`email`, `email_verified`,
   * `name`) are included when available.
   */
  signIdToken(payload: {
    sub: string;
    audience: string;
    email?: string;
    email_verified?: boolean;
    name?: string;
    nonce?: string;
  }): Promise<string>;
  /**
   * Generate a refresh token pair (token and hash)
   */
  generateRefreshToken(): { token: string; tokenHash: string };
  /**
   * Hash a refresh token
   */
  hashRefreshToken(token: string): string;
  /**
   * Verify an access token and return payload.
   * When `audience` is provided, the token's `aud` claim MUST match
   * (string or array intersection per RFC 7519 §4.1.3). When `issuer` is
   * provided, the token's `iss` claim MUST equal it (RFC 9700 mix-up
   * defence); omit it only when the caller deliberately accepts any issuer.
   * @throws JWTExpiredError if token has expired
   * @throws JWTInvalidError if token is invalid, audience mismatches, or the
   *   issuer mismatches
   */
  verifyAccessToken(
    token: string,
    options?: { audience?: string | string[]; issuer?: string }
  ): Promise<JWTPayload>;
  /**
   * Extract JWT token from Authorization header
   * @param authHeader - Authorization header value (e.g., "Bearer <token>")
   * @returns JWT token string or null if header is missing or invalid format
   */
  extractFromHeader(authHeader: string | undefined): string | null;
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
   * Get the configured issuer URL (the `iss` claim value used when signing).
   * Used by discovery endpoints (RFC 8414 / OIDC Discovery 1.0).
   */
  getIssuer(): string;
  /**
   * The `id_token_signing_alg_values_supported` values discovery must advertise
   * (OIDC Discovery 1.0), reflecting the keys actually configured on this
   * server: `['RS256','EdDSA']` when an RS256 key is present (#309, RS256 is the
   * default ID-token signature then), otherwise `['EdDSA']`.
   */
  getIdTokenSigningAlgValuesSupported(): string[];
  /**
   * Export the server's active public key(s) as a JWKS document, ready to
   * serve at `/.well-known/jwks.json` (RFC 7517).
   */
  getJwks(): Promise<Jwks>;
}
