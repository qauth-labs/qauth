/**
 * Token validation via RFC 7662 introspection against the QAuth AS.
 *
 * Used when tokens are opaque, or when the RS must honour near-real-time
 * revocation rather than rely on a token's `exp`. RFC 7662 requires the
 * introspection caller to authenticate; QAuth accepts `client_secret_basic`
 * and `client_secret_post`. We use Basic auth.
 *
 * QAuth contract (auth-server introspect route): returns
 * `{ active, sub, client_id, exp, iat, iss, aud, scope, token_type }` and
 * `{ active: false }` for invalid / cross-audience tokens. The AS itself
 * already enforces audience-authoritative introspection; `mcp-guard`
 * additionally re-checks `aud` locally so the no-passthrough guarantee does
 * not depend solely on AS-side configuration.
 */

import type { FetchLike, IntrospectionClientCredentials, ValidatedToken } from '../types';
import { InvalidTokenError } from './errors';
import { parseScopes } from './scope';

export interface IntrospectionValidatorOptions {
  /** Full URL of the AS introspection endpoint. */
  endpoint: string;
  /** Resource identifier that MUST appear in the token's `aud`. */
  audience: string;
  /** Confidential client credentials (RFC 7662 requires client auth). */
  client: IntrospectionClientCredentials;
  /** Injectable fetch. Defaults to the global `fetch`. */
  fetch?: FetchLike;
}

/** Shape of the RFC 7662 introspection response QAuth returns. */
interface IntrospectionResponse {
  active: boolean;
  sub?: string;
  client_id?: string;
  exp?: number;
  iat?: number;
  iss?: string;
  aud?: string | string[];
  scope?: string;
  token_type?: string;
}

function audienceList(aud: string | string[] | undefined): string[] {
  if (aud == null) {
    return [];
  }
  return Array.isArray(aud) ? aud : [aud];
}

/** Reusable RFC 7662 introspection validator. */
export class IntrospectionValidator {
  private readonly endpoint: string;
  private readonly audience: string;
  private readonly authorization: string;
  private readonly fetchImpl: FetchLike;

  constructor(options: IntrospectionValidatorOptions) {
    this.endpoint = options.endpoint;
    this.audience = options.audience;
    const basic = Buffer.from(`${options.client.clientId}:${options.client.clientSecret}`).toString(
      'base64'
    );
    this.authorization = `Basic ${basic}`;
    this.fetchImpl = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
  }

  /**
   * Introspect a token and, if active and audience-bound, return normalised
   * claims.
   *
   * @throws {InvalidTokenError} when the token is inactive, the endpoint is
   * unreachable / errors, or `aud` does not include this resource. Reasons are
   * short and non-sensitive; the token is never echoed.
   */
  async validate(token: string): Promise<ValidatedToken> {
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
          authorization: this.authorization,
        },
        // RFC 7662 §2.1 — `token` (and optional hint) in the form body.
        body: new URLSearchParams({
          token,
          token_type_hint: 'access_token',
        }).toString(),
      });
    } catch {
      // Network / transport failure. Fail closed; do not leak details.
      throw new InvalidTokenError('introspection endpoint unreachable');
    }

    if (!response.ok) {
      // 401 here means OUR introspection client is misconfigured; still fail
      // closed for the bearer, but the reason is generic to the caller.
      throw new InvalidTokenError('introspection request failed');
    }

    let body: IntrospectionResponse;
    try {
      body = (await response.json()) as IntrospectionResponse;
    } catch {
      throw new InvalidTokenError('malformed introspection response');
    }

    if (!body.active) {
      throw new InvalidTokenError('token is not active');
    }

    // Defence-in-depth no-passthrough check: even though the AS only returns
    // active=true to an audience-authoritative introspection client, re-verify
    // the binding locally (RFC 8707) so a misconfigured AS client cannot widen
    // what this RS will accept.
    const auds = audienceList(body.aud);
    if (!auds.includes(this.audience)) {
      throw new InvalidTokenError('token audience does not match this resource');
    }

    return {
      sub: body.sub,
      clientId: body.client_id,
      scopes: parseScopes(body.scope),
      audience: auds,
      issuer: body.iss,
      expiresAt: body.exp,
      issuedAt: body.iat,
      raw: body as unknown as Record<string, unknown>,
    };
  }
}
