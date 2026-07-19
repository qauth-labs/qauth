/**
 * JWT validation against the QAuth AS JWKS.
 *
 * This is the recommended, offline validation path. It verifies the bearer's
 * signature with the AS public keys (RFC 7517 JWKS), pins the algorithm to
 * defend against algorithm-confusion, and enforces `iss` and — the core
 * no-passthrough control — that `aud` contains THIS resource (RFC 8707).
 *
 * QAuth contract (auth-server): tokens are EdDSA-signed compact JWTs with
 * claims `sub`, `client_id`, `scope` (space-separated), `aud` (string or
 * array), `iss`, `iat`, `exp`; JWKS is served at
 * `${authorizationServer}/.well-known/jwks.json`.
 */

import {
  createRemoteJWKSet,
  customFetch,
  errors as joseErrors,
  type FetchImplementation,
  type JWTPayload as JoseJWTPayload,
  jwtVerify,
} from 'jose';

import type { ValidatedToken } from '../types';
import { InvalidTokenError } from './errors';
import { parseScopes } from './scope';

export interface JwtValidatorOptions {
  /** JWKS document URL. */
  jwksUri: string;
  /** Expected issuer (`iss`) — the AS identifier. */
  issuer: string;
  /** Resource identifier that MUST appear in `aud`. */
  audience: string;
  /** Permitted signature algorithms. Defaults to `['EdDSA']`. */
  allowedAlgorithms?: string[];
  /**
   * Require the RFC 9068 `typ: at+jwt` protected header to be PRESENT (#283).
   * Defaults to `false`. See {@link ACCESS_TOKEN_TYP} for why a WRONG `typ` is
   * rejected unconditionally while a MISSING one is gated on this flag.
   */
  requireAccessTokenTyp?: boolean;
  /** JWKS reuse window in ms (jose cooldown). Defaults to 300_000 (5m). */
  cacheTtlMs?: number;
  /** Injectable fetch passed through to jose's remote JWKS loader. */
  fetch?: FetchImplementation;
}

/**
 * RFC 9068 §2.1 `typ` of a JWT OAuth 2.0 access token.
 *
 * A resource server is the party this defends: the AS signs access tokens AND
 * OIDC ID tokens with the SAME key, so both resolve to the same JWKS entry and
 * both pass signature verification here. `typ` is the standard structural
 * discriminator between them, checked before any claim is read.
 *
 * Duplicated as a literal rather than imported from `@qauth-labs/server-jwt`
 * on purpose: `mcp-guard` is the resource-server-side library and depends only
 * on `jose`. Its value is fixed by RFC 9068, not by QAuth.
 */
const ACCESS_TOKEN_TYP = 'at+jwt';

/**
 * Normalise a jose payload to {@link ValidatedToken}. `aud` is guaranteed
 * present and matching by the time we get here (jose checked it).
 */
function toValidatedToken(payload: JoseJWTPayload): ValidatedToken {
  const aud = payload.aud;
  const audience = aud == null ? [] : Array.isArray(aud) ? aud : [aud];
  return {
    sub: payload.sub,
    clientId: typeof payload['client_id'] === 'string' ? payload['client_id'] : undefined,
    scopes: parseScopes(payload['scope'] as string | undefined),
    audience,
    issuer: payload.iss,
    expiresAt: payload.exp,
    issuedAt: payload.iat,
    raw: payload as Record<string, unknown>,
  };
}

/**
 * A reusable JWT validator. Construct once (the JWKS is cached/refreshed
 * internally by jose) and call {@link JwtValidator.validate} per request.
 */
export class JwtValidator {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  private readonly issuer: string;
  private readonly audience: string;
  private readonly algorithms: string[];
  private readonly requireAccessTokenTyp: boolean;

  constructor(options: JwtValidatorOptions) {
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.algorithms = options.allowedAlgorithms ?? ['EdDSA'];
    this.requireAccessTokenTyp = options.requireAccessTokenTyp === true;
    const ttl = options.cacheTtlMs ?? 300_000;
    this.jwks = createRemoteJWKSet(new URL(options.jwksUri), {
      // `cooldownDuration` is the minimum interval between JWKS refetches and
      // `cacheMaxAge` the maximum age before a refetch is forced; together they
      // bound how stale a key set can be. We tie both to the configured TTL so
      // a rotated AS key is picked up within `cacheTtlMs`.
      cooldownDuration: ttl,
      cacheMaxAge: ttl,
      ...(options.fetch ? { [customFetch]: options.fetch } : {}),
    });
  }

  /**
   * Verify a bearer token. Resolves to the normalised claims on success.
   *
   * @throws {InvalidTokenError} for any verification failure — bad signature,
   * expiry, wrong issuer, wrong/absent audience, disallowed algorithm, or a
   * `typ` that is not `at+jwt` (#283). The reason is short and non-sensitive
   * (safe for `error_description`/logs); the token is never included.
   */
  async validate(token: string): Promise<ValidatedToken> {
    let payload: JoseJWTPayload;
    let protectedHeader: Record<string, unknown>;
    try {
      ({ payload, protectedHeader } = await jwtVerify(token, this.jwks, {
        algorithms: this.algorithms,
        issuer: this.issuer,
        // jose enforces audience membership: the token's `aud` (string or
        // array) MUST contain this resource. This is the RFC 8707 binding
        // that prevents accepting tokens minted for another audience.
        audience: this.audience,
      }));
    } catch (error) {
      throw new InvalidTokenError(describeJoseError(error));
    }
    // #283 RFC 9068 §2.1. `protectedHeader` is the header the verified
    // SIGNATURE covers — never `decodeProtectedHeader`, whose output an
    // attacker rewrites at will. Outside the try/catch above so this rejection
    // is not laundered into a generic jose-error string.
    this.assertAccessTokenTyp(protectedHeader['typ']);
    return toValidatedToken(payload);
  }

  /**
   * Reject a token that is not an RFC 9068 access token (#283).
   *
   * Two cases, gated differently because only one is a rollout hazard:
   *
   * - `typ` present but not `at+jwt` → ALWAYS rejected. This is the control
   *   that stops an ID token (`typ: JWT`, same signing key, same JWKS entry)
   *   being replayed as a bearer token, and it is safe to enforce immediately
   *   because no token issued before #283 carries any `typ`.
   * - `typ` absent → accepted unless `requireAccessTokenTyp` is set. An AS that
   *   has not yet deployed #283, or one still draining tokens minted by its
   *   previous build, emits `typ`-less access tokens that are otherwise
   *   entirely valid; rejecting them by default would break every such
   *   deployment on upgrade of THIS library.
   */
  private assertAccessTokenTyp(signedTyp: unknown): void {
    if (signedTyp === undefined) {
      if (this.requireAccessTokenTyp) {
        throw new InvalidTokenError('token is missing the required at+jwt type');
      }
      return;
    }
    if (signedTyp !== ACCESS_TOKEN_TYP) {
      throw new InvalidTokenError('token is not an access token (typ is not at+jwt)');
    }
  }
}

/**
 * Map a jose verification error to a short, non-sensitive reason string.
 * Deliberately coarse — we do not want to give an attacker a precise oracle,
 * but the categories below are standard and safe to surface.
 */
function describeJoseError(error: unknown): string {
  if (error instanceof joseErrors.JWTExpired) {
    return 'token expired';
  }
  if (error instanceof joseErrors.JWTClaimValidationFailed) {
    // Covers issuer/audience mismatch — the no-passthrough rejection lands here.
    if (error.claim === 'aud') {
      return 'token audience does not match this resource';
    }
    if (error.claim === 'iss') {
      return 'token issuer not trusted';
    }
    return 'token claim validation failed';
  }
  if (error instanceof joseErrors.JWSSignatureVerificationFailed) {
    return 'signature verification failed';
  }
  if (error instanceof joseErrors.JOSEAlgNotAllowed) {
    return 'token algorithm not allowed';
  }
  if (error instanceof joseErrors.JWKSNoMatchingKey) {
    return 'no matching signing key';
  }
  if (error instanceof joseErrors.JOSEError) {
    return 'token verification failed';
  }
  return 'token verification failed';
}
