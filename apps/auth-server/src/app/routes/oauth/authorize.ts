import { randomBytes } from 'node:crypto';

import { BadRequestError, isUniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { AUTHORIZATION_CODE_TTL_MS } from '../../constants';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { resolveAudience } from '../../helpers/client-auth';
import { canSkipConsent, filterRequestedScopes } from '../../helpers/consent';
import { getOrCreateSystemClient } from '../../helpers/oauth-client';
import { buildRedirectUrl } from '../../helpers/oauth-redirect';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { type AuthorizeQuery, authorizeQuerySchema } from '../../schemas/oauth';

/**
 * GET /oauth/authorize
 * OAuth 2.1 Authorization Code Flow with PKCE.
 *
 * Accepts two user-auth mechanisms:
 *   1. Browser-driven (issue #150): signed __Host-qauth_session cookie.
 *      No session → redirect to /ui/login with return_to. Session + no
 *      prior consent covering the requested scopes → redirect to the
 *      consent screen at /ui/consent. Otherwise issue a code directly.
 *   2. Legacy/machine: Authorization: Bearer <access_token>. Retained for
 *      backwards compatibility with first-party callers that have not yet
 *      migrated to the browser flow. MUST NOT be relied on once dynamic
 *      client registration is opened up.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/authorize',
    {
      schema: {
        description:
          'OAuth 2.1 authorization endpoint. Issues authorization code with PKCE. Requires Bearer access token for user context. Redirects to client redirect_uri.',
        tags: ['OAuth', 'Authorization'],
        querystring: authorizeQuerySchema,
      },
      config: {
        rateLimit: {
          max: env.AUTHORIZE_RATE_LIMIT,
          timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
          keyGenerator: (req) => req.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const query = request.query as AuthorizeQuery;
      const redirectUri = query.redirect_uri;
      const state = query.state;

      const realm = await getOrCreateDefaultRealm(fastify);

      const client = await fastify.repositories.oauthClients.findByClientId(
        realm.id,
        query.client_id
      );

      if (!client) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'invalid_client', client_id: query.client_id },
        });
        throw new BadRequestError('invalid_client');
      }

      if (!client.redirectUris.includes(redirectUri)) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'redirect_uri not registered', client_id: query.client_id },
        });
        throw new BadRequestError('redirect_uri not registered');
      }

      if (!client.enabled) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'unauthorized_client', client_id: query.client_id },
        });
        return reply.redirect(
          buildRedirectUrl(redirectUri, {
            error: 'unauthorized_client',
            state: state ?? undefined,
          }),
          302
        );
      }

      if (!client.grantTypes.includes('authorization_code')) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'unauthorized_client', client_id: query.client_id },
        });
        return reply.redirect(
          buildRedirectUrl(redirectUri, {
            error: 'unauthorized_client',
            state: state ?? undefined,
          }),
          302
        );
      }

      if (!client.responseTypes.includes('code')) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'unauthorized_client', client_id: query.client_id },
        });
        return reply.redirect(
          buildRedirectUrl(redirectUri, {
            error: 'unauthorized_client',
            state: state ?? undefined,
          }),
          302
        );
      }

      // -----------------------------------------------------------------
      // User authentication. Prefer the session cookie; fall back to
      // Bearer for backwards compat. When both are absent we kick to the
      // login page with a return_to URL so the user can establish a
      // session and come back.
      // -----------------------------------------------------------------
      const browserSession = await resolveBrowserSession(fastify, request, reply);
      const bearer = fastify.jwtUtils.extractFromHeader(request.headers.authorization);

      if (!browserSession && !bearer) {
        // No auth at all → browser flow. Redirect to login, then the user
        // lands back on this very URL and the session cookie path takes
        // over. We preserve the exact query string so PKCE challenge,
        // scope, and state survive the round-trip.
        const returnTo = `${request.url}`;
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent(returnTo)}`, 302);
      }

      let userId: string;
      if (browserSession) {
        userId = browserSession.userId;
      } else {
        // bearer path
        try {
          const systemClient = await getOrCreateSystemClient(realm.id, fastify);
          const payload = await fastify.jwtUtils.verifyAccessToken(bearer as string, {
            audience: resolveAudience(systemClient),
          });
          userId = payload.sub;
        } catch {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: client.id,
            event: 'oauth.authorize.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: 'access_denied', client_id: query.client_id },
          });
          return reply.redirect(
            buildRedirectUrl(redirectUri, {
              error: 'access_denied',
              error_description: 'Invalid or expired token',
              state: state ?? undefined,
            }),
            302
          );
        }
      }

      // Deny-by-default: when a client has no scope allowlist configured we
      // grant nothing, matching `validateScopes` on the client_credentials
      // path. Previously an empty allowlist silently over-granted every
      // requested scope on the auth-code flow.
      const scopes = filterRequestedScopes(query.scope, client);

      // Browser-driven flow: show the consent screen unless a previous
      // grant already covers the requested scopes. Bearer-token callers
      // skip the consent step entirely — they are first-party and the
      // Bearer path is not exposed to dynamically-registered clients.
      if (browserSession) {
        const existingConsent = await fastify.repositories.oauthConsents.findActive(
          userId,
          client.id
        );
        if (!canSkipConsent(existingConsent, client, scopes)) {
          return reply.redirect(`/ui/consent${request.url.slice(request.url.indexOf('?'))}`, 302);
        }
      }

      const expiresAt = Date.now() + AUTHORIZATION_CODE_TTL_MS;

      const createCode = async (): Promise<string> => {
        const code = randomBytes(32).toString('base64url');
        await fastify.repositories.authorizationCodes.create({
          code,
          oauthClientId: client.id,
          userId,
          redirectUri,
          codeChallenge: query.code_challenge,
          codeChallengeMethod: 'S256',
          nonce: query.nonce ?? null,
          scopes,
          state: query.state ?? null,
          expiresAt,
        });
        return code;
      };

      const MAX_CREATE_ATTEMPTS = 3;
      let code: string | null = null;
      for (let attempt = 0; attempt < MAX_CREATE_ATTEMPTS; attempt++) {
        try {
          code = await createCode();
          break;
        } catch (err) {
          if (!isUniqueConstraintError(err)) throw err;
          if (attempt === MAX_CREATE_ATTEMPTS - 1) throw err;
        }
      }
      if (!code) throw new Error('Unreachable');

      await fastify.repositories.auditLogs.create({
        userId,
        oauthClientId: client.id,
        event: 'oauth.authorize.success',
        eventType: 'token',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: { redirectUri },
      });

      return reply.redirect(
        buildRedirectUrl(redirectUri, { code, state: state ?? undefined }),
        302
      );
    }
  );
}
