import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import { ForbiddenError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { API_FAMILY_AUDIENCES, type ApiFamily } from '../api-conventions/families';
import { isClientUsable } from './client-status';
import { realmIssuer } from './realm-url';
import { requestRealm } from './request-realm';
import { inactiveSubjectError } from './token-subject';

/**
 * Decides whether a family accepts a token's `iss` (#509). Called with the
 * claim after the signature check, and with the request, so a rule may depend
 * on what the request names.
 *
 * The default, {@link requestRealmIssuer}, accepts only the issuer of the
 * request's realm. A family may supply its own (#510). The signature is
 * checked with the request realm's keys first (#491), so a rule can only
 * narrow which of that realm's tokens pass: a token another realm issued,
 * such as an operator-realm admin's at a tenant realm, verifies with none of
 * them, and admitting one needs a way to verify with that realm's keys, which
 * a rule does not choose.
 */
export type IssuerResolver = (
  issuer: string,
  request: FastifyRequest
) => boolean | Promise<boolean>;

/**
 * The default {@link IssuerResolver}: the issuer of the request's realm
 * (ADR-019 Decision 1), the `iss` the signer gives every token the realm
 * issues (#491), as the issuer pins of `requireJwt`, introspection,
 * revocation and logout. The token has already verified with the realm's own
 * keys, so a token minted in another realm never reaches this rule.
 */
export const requestRealmIssuer: IssuerResolver = (issuer, request) =>
  issuer === realmIssuer(requestRealm(request));

/**
 * What a token's `sub` may name on a family route (#509):
 *
 * - `user`: a user, the subject of every grant but `client_credentials`;
 * - `client`: a client acting as itself, a `client_credentials` token, whose
 *   `sub` is its own `client_id`.
 */
export type FamilySubjectKind = 'user' | 'client';

/** What a family route asks of a token beyond the family's own rules. */
export interface FamilyTokenOptions {
  /** The issuer rule. Default: {@link requestRealmIssuer}. */
  readonly issuerResolver?: IssuerResolver;
  /**
   * Which subjects the route admits. Required, and never empty: the guard
   * resolves the subject in the request's realm (ADR-019 Decision 1) and
   * refuses a token whose subject is of another kind, names nothing there, or
   * is disabled there.
   */
  readonly subjects: readonly FamilySubjectKind[];
  /**
   * Scopes the token must carry, every one of them. A token that lacks one is
   * refused with 403 `forbidden`, and the `insufficient_scope` challenge names
   * them all (RFC 6750 §3.1). The account and developer families define no
   * scopes yet, so their routes pass none.
   */
  readonly requiredScopes?: readonly string[];
}

/**
 * `users.id` is a uuid column: a subject that is not a UUID names no user, and
 * is refused before it reaches Postgres (22P02 → 500).
 */
const uuidSubjectSchema = z.uuid();

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
 * - `sub`, `exp` and `jti` are present, `sub` and `jti` as non-empty strings.
 *   RFC 9068 §2.2 requires all three, an expiry is what bounds the token, and
 *   a token without a `jti` could not be revoked.
 * - `aud` holds exactly one value, the family's audience. A token with several
 *   audiences is refused even when one of them is the family's: another
 *   resource server received the same token and could replay it here.
 * - The developer family refuses a delegated token (an RFC 8693 `act` claim):
 *   a token acting for an agent never manages the developer's clients, the
 *   rule the developer routes' guard (`assertManagementToken`) keeps today.
 */
function assertFamilyClaims(family: ApiFamily, claims: JWTPayload): void {
  // A structural check of the claims, not the refusal of a subject that names
  // no active user, which `assertSubjectOfRealm` makes once it resolves the
  // subject.
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
    throw new JWTInvalidError('Access token lacks a sub claim');
  }
  if (claims.exp === undefined || typeof claims.jti !== 'string' || claims.jti.length === 0) {
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
 * Refuse a token whose subject is not an active user or client of the
 * request's realm (ADR-019 Decision 1, #509).
 *
 * A family audience reads the same in every realm. The default issuer rule
 * admits a token only at the realm whose token issuer it names, but a family
 * may supply its own rule (#510), and the subject must belong to the realm
 * whatever the rule. So the guard resolves `sub` in `requestRealm(request)`:
 *
 * - a `client_credentials` token (`sub` is its own `client_id`) names a client
 *   of this realm that is enabled and not suspended;
 * - any other token names a user of this realm who is enabled.
 *
 * A subject of a kind the route does not admit is refused the same way. A
 * user is refused with the one wording every route uses for a subject that is
 * not an active user (`inactiveSubjectError`), so the answer does not say
 * whether the account exists in another realm. A `client_id` names a client
 * per realm, but a token verifies only with the keys of the realm that issued
 * it and under its issuer (#491), so a token of a `client_id` that two realms
 * enable passes only at the realm that minted it.
 */
async function assertSubjectOfRealm(
  request: FastifyRequest,
  claims: JWTPayload & { sub: string },
  subjects: ReadonlySet<FamilySubjectKind>
): Promise<void> {
  const realm = requestRealm(request);
  const { repositories } = request.server;
  if (claims.clientId !== undefined && claims.sub === claims.clientId) {
    const client = subjects.has('client')
      ? await repositories.oauthClients.findByClientId(realm.id, claims.sub)
      : undefined;
    if (!client || !isClientUsable(client)) {
      throw new JWTInvalidError('Access token client is not an active client of this realm');
    }
    return;
  }
  if (!subjects.has('user') || !uuidSubjectSchema.safeParse(claims.sub).success) {
    throw inactiveSubjectError();
  }
  const user = await repositories.users.findById(claims.sub);
  if (!user || !user.enabled || user.realmId !== realm.id) {
    throw inactiveSubjectError();
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
 * {@link assertFamilyClaims}), the subject in the request's realm (see
 * {@link assertSubjectOfRealm}) and `options.requiredScopes`. On success the
 * claims are on `request.jwtPayload`.
 *
 * The answers follow RFC 6750 §3.1, in a problem document, as every family
 * route answers an error (ADR-019 Decision 7):
 *
 * - no credentials (`MissingAccessTokenError`): 401 `unauthorized`, with a
 *   challenge that names no error, `WWW-Authenticate: Bearer realm="OAuth"`;
 * - a refused token: 401 `invalid_access_token` (or `access_token_expired`),
 *   with `error="invalid_token"` in the challenge;
 * - a missing scope: 403 `forbidden`, with an `insufficient_scope` challenge
 *   whose `scope` names the scopes the route needs, as every route that a
 *   wider token would let through answers.
 *
 * So a route behind the guard lists 401 in its `x-qauth-errors`, and 403 too
 * when it passes `requiredScopes`.
 *
 * What the route does for its subject beyond that, such as reading the user's
 * row again or checking a role, is its own.
 */
export function requireFamilyToken(
  family: ApiFamily,
  options: FamilyTokenOptions
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  const issuerResolver = options.issuerResolver ?? requestRealmIssuer;
  const subjects = new Set(options.subjects);
  if (subjects.size === 0) {
    throw new Error('requireFamilyToken: a family route admits at least one kind of subject');
  }
  const requiredScopes = [...(options.requiredScopes ?? [])];

  return async function requireFamilyTokenHandler(request) {
    const claims = await request.server.verifyRequestAccessToken(request, {
      acceptIssuer: issuerResolver,
      requireTyp: true,
    });
    assertFamilyClaims(family, claims);
    await assertSubjectOfRealm(request, claims as JWTPayload & { sub: string }, subjects);

    if (requiredScopes.length > 0) {
      const granted = new Set((claims.scope ?? '').split(/\s+/).filter((s) => s.length > 0));
      if (!requiredScopes.every((scope) => granted.has(scope))) {
        throw new ForbiddenError('The access token lacks a scope this operation needs', {
          requiredScope: requiredScopes,
        });
      }
    }

    request.jwtPayload = claims;
  };
}
