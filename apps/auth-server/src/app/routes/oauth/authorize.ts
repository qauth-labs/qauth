import { randomBytes } from 'node:crypto';

import { BadRequestError, isUniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { AUTHORIZATION_CODE_TTL_MS } from '../../constants';
import { buildRedirectUrl } from '../../helpers/oauth-redirect';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { type AuthorizeQuery, authorizeQuerySchema } from '../../schemas/oauth';

/**
 * GET /oauth/authorize
 * OAuth 2.1 Authorization Code Flow with PKCE.
 * Requires Authorization: Bearer <access_token> for user context (MVP).
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

      const token = fastify.jwtUtils.extractFromHeader(request.headers.authorization);
      if (!token) {
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
            error_description: 'Missing or invalid Authorization header',
            state: state ?? undefined,
          }),
          302
        );
      }

      let userId: string;
      try {
        const payload = await fastify.jwtUtils.verifyAccessToken(token);
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

      const requestedScopes = query.scope
        ? query.scope.split(/\s+/).filter((s) => s.length > 0)
        : [];
      const scopes =
        client.scopes.length > 0
          ? requestedScopes.filter((s) => client.scopes.includes(s))
          : requestedScopes;

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
