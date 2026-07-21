import { InvalidRequestError, JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { resolveEmailClaims } from '../../helpers/email-claims';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { userinfoResponseSchema } from '../../schemas/oauth';

/**
 * Shared userinfo handler for GET and POST (OIDC Core §5.3.1: the userinfo
 * endpoint MUST support both). By the time this runs, the access token has
 * already been verified by a preHandler and its claims are on
 * `request.jwtPayload` — GET via `fastify.requireJwt` (header), POST via
 * {@link resolveUserinfoTokenPreHandler} (header OR form body). The claim set
 * returned is identical regardless of method.
 */
async function handleUserinfo(fastify: FastifyInstance, request: FastifyRequest) {
  const startTime = Date.now();
  let userId: string | null = null;

  try {
    const payload = request.jwtPayload;

    if (!payload || !payload.sub) {
      throw new JWTInvalidError('Missing JWT payload');
    }

    userId = payload.sub;

    const user = await fastify.repositories.users.findById(userId);

    if (!user) {
      throw new NotFoundError('User', userId);
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
    // is skipped entirely when the scope was not granted.
    if (grantedScopes.has('email')) {
      Object.assign(responseBody, await resolveEmailClaims(fastify, user.id));
    }

    // OIDC Core §5.1 `name` — the end-user display name, derived from the
    // stored first/last name parts. Released only under the `profile` scope;
    // omitted when neither part is set, keeping the claim set consistent
    // with the ID token.
    if (grantedScopes.has('profile')) {
      const nameParts = [user.firstName, user.lastName].filter(
        (p): p is string => typeof p === 'string' && p.trim().length > 0
      );
      if (nameParts.length > 0) {
        responseBody.name = nameParts.join(' ');
      }
    }

    await fastify.repositories.auditLogs.create({
      userId: user.id,
      oauthClientId: null,
      event: 'oauth.userinfo.success',
      eventType: 'token',
      success: true,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {},
    });

    await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.USERINFO);

    // Return the payload for Fastify to serialize through `userinfoResponseSchema`
    // (identical to `reply.send`); a plain return keeps the shared handler's type
    // aligned with the route's response schema across both GET and POST.
    return responseBody;
  } catch (error) {
    await fastify.repositories.auditLogs.create({
      userId: userId,
      oauthClientId: null,
      event: 'oauth.userinfo.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {
        error: error instanceof Error ? error.message : 'Unknown error',
      },
    });

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
  const headerToken = fastify.jwtUtils.extractFromHeader(request.headers.authorization);

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
  // header-less request would, yielding an identical 401 challenge.
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
    keyGenerator: (request: FastifyRequest) => request.ip || 'unknown',
  };

  const handler = (request: FastifyRequest) => handleUserinfo(fastify, request);

  const app = fastify.withTypeProvider<ZodTypeProvider>();

  app.get(
    '/userinfo',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          'OIDC userinfo endpoint (GET). Returns claims for the authenticated user. Requires a Bearer access token.',
        tags: ['OAuth', 'Userinfo'],
        security: [{ bearerAuth: [] }],
        response: {
          200: userinfoResponseSchema,
        },
      },
      config: {
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
          'OIDC userinfo endpoint (POST). Returns claims for the authenticated user. Accepts a Bearer access token in the Authorization header or a form-encoded access_token body parameter (RFC 6750 §2.2).',
        tags: ['OAuth', 'Userinfo'],
        security: [{ bearerAuth: [] }],
        response: {
          200: userinfoResponseSchema,
        },
      },
      config: {
        rateLimit,
      },
    },
    handler
  );
}
