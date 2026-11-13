import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { END_SESSION_BODY_LIMIT_BYTES } from '../../constants';
import { answerEndSession, answerEndSessionStatus, resendAsGet } from '../../helpers/end-session';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import { type EndSessionParams, endSessionParamsSchema } from '../../schemas/end-session';

/**
 * GET and POST /oauth/end-session, and GET /oauth/end-session/status (#675):
 * OpenID Connect RP-Initiated Logout 1.0. An app sends the browser here to
 * sign it out, and gets it back at a URI it registered. The rules are in
 * `helpers/end-session.ts`; the flow graph is `graphs/flows/core/logout`.
 *
 * Both methods share one handler: §2 has the OP support the query of a GET
 * and the form body of a POST alike. A POST that arrives without the session
 * cookie, as a cross-site POST does (the cookie is `SameSite=Lax`), is sent
 * again as a GET with the same parameters (`resendAsGet`). Browser routes: they read and clear the
 * session cookie, on the realm's own host (#486). Their budget is the
 * authorization endpoint's, per client address and realm, with its
 * environment-aware cap (ADR-008 §5).
 */
export default async function (fastify: FastifyInstance) {
  const config = {
    surface: 'browser' as const,
    rateLimit: {
      max: (request: FastifyRequest) =>
        resolveRealmRateLimitMax(request.realm, {
          lenientMax: env.AUTHORIZE_RATE_LIMIT_LENIENT,
          strictMax: env.AUTHORIZE_RATE_LIMIT,
        }),
      timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
      keyGenerator: realmRateLimitKey,
    },
  };
  const description =
    'OpenID Connect RP-Initiated Logout 1.0 end-session endpoint. A valid id_token_hint that names the browser session (its account by sub, the session by sid) ends that session at once; otherwise a signed-in browser is asked to confirm, and nothing ends until it answers. Goes back to a registered post_logout_redirect_uri with state, or shows a page; an unregistered one gets an information page and never a redirect. A client the operator did not set up is not redirected to before the browser has seen a QAuth page: the signed-out page links to its return URI. A realm that names its ceremony app’s error page (its ceremonyApp.errorPage policy) gets 303 to that page, on the realm’s own origin, in place of each of these pages. Refresh tokens are not revoked here.';

  const app = fastify.withTypeProvider<ZodTypeProvider>();
  app.get(
    '/end-session',
    {
      schema: {
        description: `${description} Parameters in the query.`,
        tags: ['OAuth', 'OIDC'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 429],
        querystring: endSessionParamsSchema,
      },
      config,
    },
    async (request, reply) => answerEndSession(fastify, request, reply, request.query)
  );
  app.post(
    '/end-session',
    {
      schema: {
        description: `${description} Parameters form-encoded in the body. A POST without the session cookie, as a cross-site one, is answered 303 to the same endpoint as a GET with the same parameters, so the browser sends its cookie.`,
        tags: ['OAuth', 'OIDC'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 429],
        body: endSessionParamsSchema,
      },
      config,
      // A handful of short, individually bounded form fields: bound the
      // unauthenticated body at the edge, as the authorization endpoint does.
      bodyLimit: END_SESSION_BODY_LIMIT_BYTES,
    },
    async (request, reply) => {
      const params = request.body as EndSessionParams;
      return (
        resendAsGet(request, reply, params) ?? answerEndSession(fastify, request, reply, params)
      );
    }
  );
  app.get(
    '/end-session/status',
    {
      schema: {
        description:
          'The sign-out status page of RP-initiated logout: whether this browser is still signed in. Takes no parameter. A realm that names its ceremony app’s error page (its ceremonyApp.errorPage policy) gets 303 to that page instead, with code=logout_finished and signed_out.',
        tags: ['OAuth', 'OIDC'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [429],
      },
      config,
    },
    async (request, reply) => answerEndSessionStatus(fastify, request, reply)
  );
}
