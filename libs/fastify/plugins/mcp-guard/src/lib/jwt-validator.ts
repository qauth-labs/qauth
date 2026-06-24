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
  /** JWKS reuse window in ms (jose cooldown). Defaults to 300_000 (5m). */
  cacheTtlMs?: number;
  /** Injectable fetch passed through to jose's remote JWKS loader. */
  fetch?: FetchImplementation;
}

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

  constructor(options: JwtValidatorOptions) {
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.algorithms = options.allowedAlgorithms ?? ['EdDSA'];
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
   * expiry, wrong issuer, wrong/absent audience, or disallowed algorithm. The
   * reason is short and non-sensitive (safe for `error_description`/logs); the
   * token is never included.
   */
  async validate(token: string): Promise<ValidatedToken> {
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        algorithms: this.algorithms,
        issuer: this.issuer,
        // jose enforces audience membership: the token's `aud` (string or
        // array) MUST contain this resource. This is the RFC 8707 binding
        // that prevents accepting tokens minted for another audience.
        audience: this.audience,
      });
      return toValidatedToken(payload);
    } catch (error) {
      throw new InvalidTokenError(describeJoseError(error));
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
