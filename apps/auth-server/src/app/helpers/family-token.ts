import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import { InsufficientScopeError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { API_FAMILY_AUDIENCES, type ApiFamily } from '../api-conventions/families';

/**
 * Decides whether a family accepts a token's `iss` (#509). Called with the
 * claim after the signature check, and with the request, so a rule may depend
 * on what the request names.
 *
 * The default, {@link deploymentIssuer}, accepts only the deployment's issuer.
 * The admin family supplies its own (#510): an operator-realm admin's token
 * names the operator realm's issuer, and a realm-local admin's names its own
 * realm's.
 */
export type IssuerResolver = (
  issuer: string,
  request: FastifyRequest
) => boolean | Promise<boolean>;

/**
 * The default {@link IssuerResolver}: the deployment's issuer (`JWT_ISSUER`),
 * the one every token this server mints carries today.
 */
export const deploymentIssuer: IssuerResolver = (issuer, request) =>
  issuer === request.server.jwtUtils.getIssuer();

/** What a family route asks of a token beyond the family's own rules. */
export interface FamilyTokenOptions {
  /** The issuer rule. Default: {@link deploymentIssuer}. */
  readonly issuerResolver?: IssuerResolver;
  /**
   * Scopes the token must carry, every one of them. A token that lacks one is
   * refused with 403 `insufficient_scope`, and the challenge names them all
   * (RFC 6750 §3.1). The account and developer families define no scopes yet,
   * so their routes pass none.
   */
  readonly requiredScopes?: readonly string[];
}

/**
 * The `aud` values of a token: none, or the string or list it carries.
 */
function audiencesOf(claims: JWTPayload): string[] {
  return claims.aud === undefined ? [] : [claims.aud].flat();
}

/**
 * Refuse a verified token that is not a token for `family` (#509, ADR-019
 * Decision 7). Each refusal is a `JWTInvalidError`: 401 with the RFC 6750
 * `invalid_token` challenge, because the token is not valid for this resource.
 *
 * - `sub`, `exp` and `jti` are present. RFC 9068 §2.2 requires all three, an
 *   expiry is what bounds the token, and a token without a `jti` could not be
 *   revoked.
 * - `aud` holds exactly one value, the family's audience. A token with several
 *   audiences is refused even when one of them is the family's: another
 *   resource server received the same token and could replay it here.
 * - The developer family refuses a delegated token (an RFC 8693 `act` claim):
 *   a token acting for an agent never manages the developer's clients, the
 *   rule the developer routes' guard (`assertManagementToken`) keeps today.
 */
function assertFamilyClaims(family: ApiFamily, claims: JWTPayload): void {
  // A structural check of the claims, not the refusal of a subject that names
  // no active user, which the route makes (`inactiveSubjectError`) once it
  // resolves the subject.
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
    throw new JWTInvalidError('Access token lacks a sub claim');
  }
  if (claims.exp === undefined || claims.jti === undefined) {
    throw new JWTInvalidError('Access token lacks an expiry or a token id');
  }
  const audiences = audiencesOf(claims);
  if (audiences.length !== 1 || audiences[0] !== API_FAMILY_AUDIENCES[family]) {
    throw new JWTInvalidError(`Access token audience is not the ${family} API`);
  }
  if (family === 'developer' && claims.act !== undefined && claims.act !== null) {
    throw new JWTInvalidError('A delegated access token cannot use the developer API');
  }
}

/**
 * The preHandler that admits a request to an API family route only with a
 * token for that family (#509, ADR-019 Decision 7). Every family has its own
 * audience, so a token for one family never works on another.
 *
 * It runs every check `requireJwt` makes — the credential (Bearer, or DPoP
 * while `DPOP_ENABLED` is on), the signature and expiry, revocation and the
 * DPoP binding — with two differences: the issuer rule is
 * `options.issuerResolver`, and the RFC 9068 `typ: at+jwt` header is required
 * whatever `requireAccessTokenTyp` says. Then the family's own rules (see
 * {@link assertFamilyClaims}) and `options.requiredScopes`. On success the
 * claims are on `request.jwtPayload`.
 *
 * The answers follow RFC 6750 §3.1, in a problem document, as every family
 * route answers an error (ADR-019 Decision 7):
 *
 * - no credentials (`MissingAccessTokenError`): 401 `unauthorized`, with a
 *   challenge that names no error, `WWW-Authenticate: Bearer realm="OAuth"`;
 * - a refused token: 401 `invalid_access_token` (or `access_token_expired`),
 *   with `error="invalid_token"` in the challenge;
 * - a missing scope: 403 `insufficient_scope`, whose challenge names the
 *   scopes the route needs.
 *
 * So a route behind the guard lists 401 in its `x-qauth-errors`, and 403 too
 * when it passes `requiredScopes`.
 *
 * The guard proves the token is one for the family, not who its subject is. It
 * does not check that `sub` names a user, that the user is enabled, or that
 * the token belongs to the request's realm: every realm's tokens carry the
 * deployment's issuer until per-realm issuers ship, and a client an operator
 * gave a family audience may hold a `client_credentials` token whose `sub` is
 * its own id. A route resolves its subject and realm itself, as
 * `assertManagementToken` does for the routes that still use it.
 */
export function requireFamilyToken(
  family: ApiFamily,
  options: FamilyTokenOptions = {}
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  const issuerResolver = options.issuerResolver ?? deploymentIssuer;
  const requiredScopes = [...(options.requiredScopes ?? [])];

  return async function requireFamilyTokenHandler(request) {
    const claims = await request.server.verifyRequestAccessToken(request, {
      acceptIssuer: issuerResolver,
      requireTyp: true,
    });
    assertFamilyClaims(family, claims);

    if (requiredScopes.length > 0) {
      const granted = new Set((claims.scope ?? '').split(/\s+/).filter((s) => s.length > 0));
      if (!requiredScopes.every((scope) => granted.has(scope))) {
        throw new InsufficientScopeError(
          requiredScopes,
          'The access token lacks a scope this operation needs'
        );
      }
    }

    request.jwtPayload = claims;
  };
}
