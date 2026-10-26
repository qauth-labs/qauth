import { InvalidRequestError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { resolveUserinfoEndpoint } from '../../helpers/discovery';
import { resolveEmailClaimsForScopes } from '../../helpers/email-claims';
import { resolveProfileClaimsForScopes } from '../../helpers/profile-claims';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { inactiveSubjectError } from '../../helpers/token-subject';
import { emitUserEvent, failureData, withEventReason } from '../../helpers/user-events';
import { userinfoResponseSchema } from '../../schemas/oauth';

/**
 * Whether a verified access token is addressed to this userinfo endpoint.
 *
 * A token is accepted only by an audience it names (RFC 8707, RFC 9068 §4;
 * `docs/security/threat-model.md`). The `aud` of a QAuth access token is one of:
 *
 *  - the token's own `client_id`. `resolveAudience` falls back to it when the
 *    grant named no RFC 8707 `resource` and the operator configured no
 *    `audience` for the client. That is the token an OIDC client gets from its
 *    own code flow (OIDC Core §5.3), and the `/auth/login` token the developer
 *    portal sends here (`client_id` and `aud` are both the system client). A
 *    delegated token keeps the subject token's audience, which GATE 3c makes
 *    contain the agent's `client_id`, so it qualifies unless it was narrowed to
 *    another server.
 *  - the `resource` values the grant named, or the client's configured
 *    `audience`: a token for those resource servers.
 *
 * Userinfo accepts the first kind, and a token whose `aud` contains this
 * endpoint's URL as discovery publishes it, which a client that binds its
 * grant to resource servers can request beside them. A token whose `aud` names
 * only other resource servers is refused: a resource server that received one
 * must not be able to read the user's claims with it.
 */
function isAddressedToUserinfo(
  payload: { aud?: string | string[]; clientId?: string },
  userinfoEndpoint: string
): boolean {
  const audiences = payload.aud === undefined ? [] : [payload.aud].flat();
  if (audiences.includes(userinfoEndpoint)) {
    return true;
  }
  return (
    typeof payload.clientId === 'string' &&
    payload.clientId.length > 0 &&
    audiences.includes(payload.clientId)
  );
}

/**
 * Whether a verified access token names an end-user as its subject (#754).
 *
 * The `client_credentials` grant mints `sub = client_id` (`handleClientCredentials`
 * in `token.ts`): the client acts as itself and there is no end-user. Every
 * other grant sets `sub` to a `users.id` and `client_id` to the client, so
 * `sub === client_id` is the positive mark of a machine token — the signal
 * introspection already uses. The UUID shape of `sub` cannot decide it: a
 * dynamically registered client's id is a random UUID.
 *
 * Such a token passes {@link isAddressedToUserinfo} whenever its `aud` fell
 * back to its own `client_id`, which is why this is checked separately.
 */
function hasUserSubject(payload: { sub: string; clientId?: string }): boolean {
  return payload.sub !== payload.clientId;
}

/**
 * Shared userinfo handler for GET and POST (OIDC Core §5.3.1: the userinfo
 * endpoint MUST support both). By the time this runs, the access token has
 * already been verified by a preHandler and its claims are on
 * `request.jwtPayload` — GET via `fastify.requireJwt` (header), POST via
 * {@link resolveUserinfoTokenPreHandler} (header OR form body). The claim set
 * returned is identical regardless of method. `requireJwt` checks signature,
 * issuer, expiry and revocation but no audience; this handler applies the
 * audience rule ({@link isAddressedToUserinfo}) for both methods.
 */
async function handleUserinfo(fastify: FastifyInstance, request: FastifyRequest) {
  const startTime = Date.now();
  let userId: string | null = null;
  let realmId: string | null = null;

  try {
    const payload = request.jwtPayload;

    if (!payload || !payload.sub) {
      throw withEventReason(new JWTInvalidError('Missing JWT payload'), 'missing_token');
    }

    // Audience before anything else: a token for another resource server is
    // refused (401, RFC 6750 §3.1 `invalid_token`) without a user lookup, so
    // its holder learns nothing about the subject.
    if (!isAddressedToUserinfo(payload, resolveUserinfoEndpoint(fastify.jwtUtils.getIssuer()))) {
      throw withEventReason(
        new JWTInvalidError('Access token audience does not include the userinfo endpoint'),
        'audience_mismatch'
      );
    }

    // A token with no end-user has no claims to return. Refused before the
    // user lookup, so a `client_id` is never read as a `users.id` (#754; OIDC
    // Core §5.3.3, RFC 6750 §3.1 `invalid_token`).
    if (!hasUserSubject(payload)) {
      throw withEventReason(inactiveSubjectError(), 'subject_not_a_user');
    }

    const user = await fastify.repositories.users.findById(payload.sub);

    // A subject that names no user — deleted since the token was minted — is
    // the same refusal: the token is not valid for this endpoint any more.
    // RFC 6750 §3.1 defines no "not found" for a protected resource.
    if (!user) {
      throw withEventReason(inactiveSubjectError(), 'subject_not_a_user');
    }

    userId = user.id;
    realmId = user.realmId;

    // A token outlives the login that minted it; a user disabled since gets
    // no claims, as introspection reports the token inactive and every grant
    // refuses to mint for the user (401, RFC 6750 §3.1 `invalid_token`).
    if (!user.enabled) {
      throw withEventReason(inactiveSubjectError(), 'user_disabled');
    }

    // OIDC Core §5.4: userinfo claims are gated by the scopes the access
    // token was granted. `sub` is ALWAYS returned; `email`/`email_verified`
    // require the `email` scope; `name` (a profile claim) requires
    // `profile`. Parsing the space-delimited `scope` claim into a set is the
    // same convention used across the token/authorize paths.
    const grantedScopes = new Set((payload.scope ?? '').split(/\s+/).filter((s) => s.length > 0));

    const responseBody: {
      sub: string;
      email?: string;
      email_verified?: boolean;
      name?: string;
    } = {
      sub: user.id,
    };

    // BREAKING (#229, ADR-002): under the `email` scope, the claims
    // resolve from verified user_attributes via the trust order; both are
    // OMITTED (never null) when no verified email exists — OIDC Core
    // §5.3.2 permits omission of unavailable claims. The resolver query
    // is skipped entirely when the scope was not granted; the same helper
    // applies the same rule at every token mint site.
    Object.assign(responseBody, await resolveEmailClaimsForScopes(fastify, user.id, grantedScopes));

    // OIDC Core §5.1 `name` — the end-user display name, derived from the
    // stored first/last name parts. Released only under the `profile` scope;
    // omitted when neither part is set. The ID token resolves it through the
    // same helper (#755), so the two release the same profile claims.
    Object.assign(responseBody, resolveProfileClaimsForScopes(user, grantedScopes));

    await emitUserEvent(
      request,
      'urn:qauth:event:userinfo.served:v1-rc.0',
      {},
      {
        realmId: user.realmId,
        userId: user.id,
        clientId: payload.clientId,
        actor: 'client',
        act: payload.act,
      }
    );

    await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.USERINFO);

    // Return the payload for Fastify to serialize through `userinfoResponseSchema`
    // (identical to `reply.send`); a plain return keeps the shared handler's type
    // aligned with the route's response schema across both GET and POST.
    return responseBody;
  } catch (error) {
    // Only a subject the lookup above confirmed is the event's subject. Any
    // other token subject (a `client_id`, a deleted user's id) names no user,
    // so the event has none.
    const payload = request.jwtPayload;
    await emitUserEvent(
      request,
      'urn:qauth:event:userinfo.request_failed:v1-rc.0',
      failureData(error),
      {
        realmId,
        userId,
        clientId: payload?.clientId,
        actor: 'client',
        act: payload?.act,
      }
    );

    await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.USERINFO);

    throw error;
  }
}

/**
 * POST /oauth/userinfo token-resolution preHandler (RFC 6750 §2).
 *
 * Exactly two transmission methods are supported: (a) the
 * `Authorization: Bearer` header, and (b) the form-encoded `access_token` body
 * parameter (RFC 6750 §2.2, which REQUIRES `application/x-www-form-urlencoded`).
 * Both are validated through the SAME verification path as GET — the body
 * method presents its token as a Bearer credential and delegates to
 * `fastify.requireJwt`, so the EdDSA-pinned `verifyAccessToken` + issuer pin +
 * revocation denylist all run identically. No weaker, hand-rolled check is
 * introduced.
 *
 * RFC 6750 §2.2 forbids supplying the token by more than one method at once,
 * and the URI query-parameter method (§2.3) is not supported; both are rejected
 * here (`invalid_request`) rather than silently preferring one source.
 */
async function resolveUserinfoTokenPreHandler(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  // A `DPoP` header counts as a header token only while DPoP is on (RFC 9449
  // §7.1); off, it is no credential, as before.
  const headerToken = fastify.jwtUtils.extractCredentialFromHeader(
    request.headers.authorization
  )?.token;

  // RFC 6750 §2.2: the body method is valid ONLY for a form-encoded entity body.
  const contentType = String(request.headers['content-type'] ?? '');
  const isFormEncoded = /^application\/x-www-form-urlencoded\b/i.test(contentType);
  const body = request.body as { access_token?: unknown } | undefined;
  const bodyToken =
    isFormEncoded && body && typeof body.access_token === 'string' && body.access_token.length > 0
      ? body.access_token
      : undefined;

  // RFC 6750 §2.3: the URI query-parameter method is NOT supported. Reject a
  // token supplied that way instead of falling back to it.
  const query = request.query as { access_token?: unknown } | undefined;
  if (query && query.access_token !== undefined) {
    throw new InvalidRequestError('access token must not be passed as a query parameter');
  }

  // RFC 6750 §2.2: more than one transmission method → invalid_request.
  if (headerToken && bodyToken) {
    throw new InvalidRequestError('access token supplied by more than one method');
  }

  // Normalise the body token to a Bearer credential so the shared `requireJwt`
  // verification path handles it exactly as the header method. With neither a
  // header nor a body token, `requireJwt` throws the same JWTInvalidError a
  // header-less request would, yielding an identical 401 challenge. A
  // DPoP-bound token is refused there: the body method is a Bearer method
  // (RFC 6750 §2.2), and RFC 9449 §7.2 forbids accepting such a token as one.
  if (bodyToken) {
    request.headers.authorization = `Bearer ${bodyToken}`;
  }

  await fastify.requireJwt(request, reply);
}

/**
 * /oauth/userinfo — OIDC userinfo endpoint (OIDC Core §5.3).
 *
 * Supports GET and POST (OIDC Core §5.3.1). Both return the SAME claims for the
 * authenticated end-user, gated by the access token's granted scopes.
 */
export default async function (fastify: FastifyInstance) {
  // ONE rate-limit config shared by both methods so POST is throttled
  // identically to GET.
  const rateLimit = {
    max: env.USERINFO_RATE_LIMIT,
    timeWindow: env.USERINFO_RATE_WINDOW * 1000,
    keyGenerator: realmRateLimitKey,
  };

  const handler = (request: FastifyRequest) => handleUserinfo(fastify, request);

  const app = fastify.withTypeProvider<ZodTypeProvider>();

  app.get(
    '/userinfo',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          "OIDC userinfo endpoint (GET). Returns claims for the authenticated user. Requires a Bearer access token whose `aud` contains its own `client_id` or this endpoint's URL; a token for another resource server gets 401, as does a token whose subject is not a user (a client_credentials token). With DPoP on, a DPoP-bound token is accepted only under the `DPoP` scheme with a valid proof (RFC 9449 §7), and refused as a Bearer token.",
        tags: ['OAuth', 'Userinfo'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401],
        security: [{ bearerAuth: [] }],
        response: {
          200: userinfoResponseSchema,
        },
      },
      config: {
        surface: 'api',
        // An OAuth protocol endpoint: errors answer the RFC 6750 §3 body and
        // challenge (ADR-019 Decision 7, #513).
        errorFormat: 'oauth',
        rateLimit,
      },
    },
    handler
  );

  // OIDC Core §5.3.1: the userinfo endpoint MUST also accept POST. The access
  // token may arrive in the Authorization header OR as a form-encoded
  // `access_token` body parameter (RFC 6750 §2.2); both go through the same
  // verification path (see `resolveUserinfoTokenPreHandler`).
  app.post(
    '/userinfo',
    {
      preHandler: (request: FastifyRequest, reply: FastifyReply) =>
        resolveUserinfoTokenPreHandler(fastify, request, reply),
      schema: {
        description:
          "OIDC userinfo endpoint (POST). Returns claims for the authenticated user. Accepts a Bearer access token in the Authorization header or a form-encoded access_token body parameter (RFC 6750 §2.2). The token's `aud` must contain its own `client_id` or this endpoint's URL; a token for another resource server gets 401, as does a token whose subject is not a user (a client_credentials token). With DPoP on, a DPoP-bound token is accepted only under the `DPoP` scheme with a valid proof (RFC 9449 §7), and refused as a Bearer token or a body parameter.",
        tags: ['OAuth', 'Userinfo'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401],
        security: [{ bearerAuth: [] }],
        response: {
          200: userinfoResponseSchema,
        },
      },
      config: {
        surface: 'api',
        // An OAuth protocol endpoint: errors answer the RFC 6750 §3 body and
        // challenge (ADR-019 Decision 7, #513).
        errorFormat: 'oauth',
        rateLimit,
      },
    },
    handler
  );
}
