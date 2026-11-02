import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import { ceremonyPagePath } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { AUTHORIZE_BODY_LIMIT_BYTES } from '../../constants';
import { sendAuthorizationError } from '../../helpers/authorization-error';
import {
  authorizationInteractionStart,
  recordUnshowableConsent,
} from '../../helpers/authorization-interaction';
import {
  type AuthorizationOutcome,
  type AuthorizationTarget,
  checkAuthorizationRequest,
  decideAuthorization,
} from '../../helpers/authorization-request';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { startInteraction } from '../../helpers/interaction';
import { redirectToLoginWithPendingAuthorization } from '../../helpers/pending-authorization';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import { type AuthorizeQuery, authorizeQuerySchema } from '../../schemas/oauth';

/**
 * The authorize request expressed as a URL with its parameters in the query
 * string. On GET this is simply `request.url`. On POST (OIDC Core §3.1.2.1)
 * the parameters arrived form-encoded in the body, so we reconstruct an
 * equivalent authorize URL from the validated body: the /ui/login +
 * /ui/consent round-trips bounce the user back to the authorization endpoint
 * via a GET — so a POST request must round-trip through a query string all the
 * same.
 *
 * This string is ONLY ever forwarded, for the receiving route to parse and
 * validate again. Never read a parameter back out of it: a second parser does
 * not split every string the way Fastify's does, so it can find a value the
 * schema never saw. Parameters come from the validated `query`.
 */
function buildAuthorizeUrlWithParams(request: FastifyRequest): string {
  if (request.method !== 'POST') {
    return request.url;
  }
  const path = request.url.split('?')[0];
  const body = (request.body ?? {}) as Record<string, unknown>;
  const usp = new URLSearchParams();
  for (const [key, value] of Object.entries(body)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) usp.append(key, String(item));
    } else {
      usp.append(key, String(value));
    }
  }
  const qs = usp.toString();
  return qs.length > 0 ? `${path}?${qs}` : path;
}

/**
 * GET /oauth/authorize
 * OAuth 2.1 Authorization Code Flow with PKCE.
 *
 * The user authenticates with the browser session (issue #150): the signed
 * __Host-qauth_session cookie. No session → redirect to /ui/login with a
 * `return_to` pointing at `/ui/resume/<handle>`; the authorize URL itself is
 * parked server-side (see helpers/pending-authorization.ts, #316). Session +
 * no prior consent covering the requested scopes, or an agent client
 * (ADR-015 Decision 11) → redirect to the consent screen at /ui/consent.
 * Otherwise issue a code directly.
 *
 * With INTERACTION_UI_ENABLED on (#628, ADR-019 Decision 6), the sign-in and
 * the consent are interactions instead of those pages: the endpoint starts
 * one that holds the validated request and redirects to the ceremony page
 * with the interaction id only. The checks and the decision are the same
 * code in both modes (helpers/authorization-request.ts); when the
 * interaction finishes, the Interaction API decides the request again and
 * issues the code (helpers/authorization-interaction.ts). `prompt=none`
 * starts no interaction in either mode.
 *
 * An operator-flagged first-party client (ADR-017 Decision 9) skips the
 * screen without a stored consent for its non-dangerous scopes: the
 * administrative consent, audited on every code as `consent.administrative`.
 * A `native_backend` client's request is treated as `prompt=login` whatever
 * it says, so its browser leg always meets a visible login.
 *
 * The legacy Bearer path, which authenticated the user from the developer
 * portal's access token with no sign-in and no consent screen, is retired
 * (#524): an `Authorization` header authenticates no one here, and a request
 * with only that header is treated as one without a session.
 */
export default async function (fastify: FastifyInstance) {
  // OIDC Core §3.1.2.1: the authorization endpoint MUST support BOTH GET (params
  // in the query string) and POST (params form-encoded in the body). ONE shared
  // config and ONE shared handler back both methods, so their behaviour —
  // validation, PKCE, redirect-uri checks, step-up, rate limiting, error shapes —
  // is byte-for-byte identical; only where the parameters are read differs.
  const config = {
    // Reads and sets the browser session cookie: the realm host only (#486).
    surface: 'browser' as const,
    // An OAuth protocol endpoint: an error it does not redirect answers the
    // RFC 6749 body, not a problem document (ADR-019 Decision 7, #513).
    errorFormat: 'oauth' as const,
    rateLimit: {
      // Environment-aware cap (ADR-008 §5, #209): a production realm ceiling
      // forces the strict cap; a development/staging ceiling permits the
      // lenient cap. Resolved from the request's realm (#487) because rate
      // limiting runs before the client is authenticated. Fail-safe to strict.
      max: (request: FastifyRequest) =>
        resolveRealmRateLimitMax(request.realm, {
          lenientMax: env.AUTHORIZE_RATE_LIMIT_LENIENT,
          strictMax: env.AUTHORIZE_RATE_LIMIT,
        }),
      timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
      keyGenerator: realmRateLimitKey,
    },
  };

  const handler = async (request: FastifyRequest, reply: FastifyReply) => {
    // OIDC Core §3.1.2.1: read the validated params from the body on POST and
    // the query on GET. The SAME Zod schema (`authorizeQuerySchema`) validates
    // both, so `query` is identically shaped and every check below is unchanged.
    const query = (request.method === 'POST' ? request.body : request.query) as AuthorizeQuery;

    // The checks that need no user: the client, its redirect URI, the
    // environment policy, the grant and response type, then `dpop_jkt`
    // (helpers/authorization-request.ts). A failure of the first four throws
    // a 400 that never redirects.
    const checked = await checkAuthorizationRequest(fastify, request, query);
    if (checked.kind === 'refused') {
      return sendAuthorizationError(reply, checked.client, query.redirect_uri, checked.params);
    }
    const { target } = checked;

    // User authentication: the browser session cookie. The legacy Bearer
    // path is retired (#524), so an `Authorization` header counts for
    // nothing: without a session the user signs in first.
    const browserSession = await resolveBrowserSession(fastify, request, reply);
    const outcome = await decideAuthorization(fastify, request, target, query, browserSession);

    switch (outcome.kind) {
      case 'code':
        return reply.redirect(outcome.location, 302);
      case 'error':
        // Before the person has seen any QAuth page: shown on the issuer
        // for a client no operator provisioned (RFC 9700 §4.11.2).
        return sendAuthorizationError(reply, target.client, query.redirect_uri, outcome.params);
      case 'sign_in':
      case 'consent':
        if (env.INTERACTION_UI_ENABLED) {
          return startCeremony(request, reply, target, query, outcome, browserSession);
        }
        return sendToPage(request, reply, outcome);
    }
  };

  /**
   * INTERACTION_UI_ENABLED (#628, ADR-019 Decision 6): start an interaction
   * that holds the validated request, bound to this browser by the flow
   * cookie, and redirect to the ceremony page with its id and nothing else.
   * The sign-in starts at the identifier step, `login_hint` as its prefill;
   * a consent at the consent step, for the signed-in user. A request too
   * large to hold is refused with `invalid_request`, as the stash refuses it.
   */
  const startCeremony = async (
    request: FastifyRequest,
    reply: FastifyReply,
    target: AuthorizationTarget,
    query: AuthorizeQuery,
    outcome: Extract<AuthorizationOutcome, { kind: 'sign_in' | 'consent' }>,
    browserSession: BrowserSession | null
  ) => {
    const start = authorizationInteractionStart(outcome, query, target.iss, browserSession);
    if ('error' in start) {
      // Only a consent, which is always for a session, can be refused here.
      if (browserSession !== null) {
        await recordUnshowableConsent(request, target, browserSession, start.error);
      }
      return sendAuthorizationError(reply, target.client, query.redirect_uri, start.error);
    }
    const started = await startInteraction(request, reply, { request: query, ...start });
    return reply.redirect(ceremonyPagePath(started.id), 302);
  };

  /**
   * The server-rendered pages, while INTERACTION_UI_ENABLED is off: the
   * sign-in goes through `/ui/login` and comes back through
   * `/ui/resume/{handle}`, the authorize URL parked server-side under the
   * handle rather than nested into `return_to` (#316 follow-up: a 2048-char
   * raw-JSON `state` nested into the login URL produced a ~10.4 KB Location
   * header, which a reverse proxy rejects before the login page ever
   * renders). The consent screen gets the authorize parameters in its query.
   */
  const sendToPage = (
    request: FastifyRequest,
    reply: FastifyReply,
    outcome: Extract<AuthorizationOutcome, { kind: 'sign_in' | 'consent' }>
  ) => {
    const requestUrlWithParams = buildAuthorizeUrlWithParams(request);
    if (outcome.kind === 'sign_in') {
      return redirectToLoginWithPendingAuthorization(fastify, reply, requestUrlWithParams);
    }
    // Guard the `?` index: `buildAuthorizeUrlWithParams` can return a
    // query-less path (empty reconstructed POST body), and `slice(-1)` would
    // yield a corrupt `/ui/consent<lastchar>`.
    const qIndex = requestUrlWithParams.indexOf('?');
    const returnQuery = qIndex >= 0 ? requestUrlWithParams.slice(qIndex) : '';
    return reply.redirect(`/ui/consent${returnQuery}`, 302);
  };

  const app = fastify.withTypeProvider<ZodTypeProvider>();
  app.get(
    '/authorize',
    {
      schema: {
        description:
          'OAuth 2.1 authorization endpoint (GET). Issues an authorization code with PKCE and redirects to the client redirect_uri.',
        tags: ['OAuth', 'Authorization'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        querystring: authorizeQuerySchema,
      },
      config,
    },
    handler
  );
  // OIDC Core §3.1.2.1: the POST form of the SAME endpoint. Identical schema
  // (validated as the body), config, and handler — only the parameter source
  // differs (form-encoded body vs query string).
  app.post(
    '/authorize',
    {
      schema: {
        description:
          'OAuth 2.1 authorization endpoint (POST). Identical to GET; parameters are form-encoded in the request body (OIDC Core §3.1.2.1).',
        tags: ['OAuth', 'Authorization'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        body: authorizeQuerySchema,
      },
      config,
      // The authorize endpoint is unauthenticated and its body is a handful of
      // short form fields, all individually bounded by `authorizeQuerySchema`.
      // Fastify's 1 MB default has no purpose here and would let a caller push
      // a megabyte through body parsing and Zod on every request before any of
      // those bounds apply. Matches PENDING_AUTHORIZATION_MAX_URL_BYTES's
      // reasoning: bound the pre-authentication surface at the edge.
      bodyLimit: AUTHORIZE_BODY_LIMIT_BYTES,
    },
    handler
  );
}
