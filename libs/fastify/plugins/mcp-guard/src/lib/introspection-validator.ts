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
import { IntrospectionError, InvalidTokenError } from './errors';
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
    // `btoa` is a standard global in every modern runtime (Node 16+, Deno,
    // Bun, Cloudflare Workers) — unlike the Node-only `Buffer` — so the
    // framework-agnostic core stays portable. Client credentials are ASCII, so
    // `btoa`'s latin1-only limitation does not apply here.
    const basic = btoa(`${options.client.clientId}:${options.client.clientSecret}`);
    this.authorization = `Basic ${basic}`;
    this.fetchImpl = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
  }

  /**
   * Introspect a token and, if active and audience-bound, return normalised
   * claims.
   *
   * Two error classes, deliberately distinct (RFC 6750 §3.1 semantics):
   *
   * @throws {InvalidTokenError} when the AS authoritatively says the *token* is
   * unusable — inactive (revoked/expired/unknown) or bound to a different
   * audience. Maps to a 401 `invalid_token` Bearer challenge.
   * @throws {IntrospectionError} when the *introspection call itself* fails for
   * a reason that is not the token's fault — the AS is unreachable, returns a
   * non-2xx (e.g. THIS RS's introspection credentials are misconfigured → 401
   * from the AS to *us*), or sends a malformed body. This is an operational /
   * server-side fault and must surface as a 5xx, not a 401 that wrongly blames
   * the client's token and can trigger pointless refresh loops.
   *
   * Reasons are short and non-sensitive; the token is never echoed.
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
    } catch (err) {
      // Network / transport failure: the AS could not be reached. This is an
      // RS-side operational fault, not an invalid token — surface as 5xx.
      throw new IntrospectionError(
        `introspection endpoint unreachable: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    if (!response.ok) {
      // A non-2xx from the introspection endpoint means OUR request was
      // rejected — typically a 401 because this RS's introspection client
      // credentials are misconfigured, or a 5xx from the AS. Either way it is
      // an operational fault on the server side, NOT a verdict that the
      // bearer's token is invalid. Do not collapse it into 401 invalid_token.
      throw new IntrospectionError(`introspection request failed with status ${response.status}`);
    }

    let body: IntrospectionResponse;
    try {
      body = (await response.json()) as IntrospectionResponse;
    } catch {
      // A 2xx with an unparseable body is a broken/misbehaving AS — again an
      // operational fault rather than an invalid token.
      throw new IntrospectionError('malformed introspection response');
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
