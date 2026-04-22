import { InvalidClientError, JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { authenticateClient, extractClientCredentials } from '../../helpers/client-auth';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import {
  type IntrospectRequest,
  introspectRequestSchema,
  introspectResponseSchema,
} from '../../schemas/oauth';

/**
 * POST /oauth/introspect
 * RFC 7662 token introspection endpoint.
 *
 * - Accepts access token in application/x-www-form-urlencoded body.
 * - Requires confidential client authentication (client_id + client_secret).
 * - Returns token activity and selected claims for valid tokens.
 * - Returns active: false for invalid, expired, or cross-client tokens.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/introspect',
    {
      schema: {
        description:
          'RFC 7662 token introspection. Send access token and client credentials in application/x-www-form-urlencoded body. Returns active and claims when token is valid for the client.',
        tags: ['OAuth', 'Introspection'],
        body: introspectRequestSchema,
        response: {
          200: introspectResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.INTROSPECT_RATE_LIMIT,
          timeWindow: env.INTROSPECT_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const body = request.body as IntrospectRequest;
      const { token } = body;

      try {
        const realm = await getOrCreateDefaultRealm(fastify);

        // Accept both `client_secret_post` (body) and `client_secret_basic`
        // (Authorization header) per RFC 6749 §2.3.
        let client;
        try {
          const creds = extractClientCredentials(request, body.client_id, body.client_secret);
          client = await authenticateClient(fastify, realm.id, creds);
        } catch (err) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: null,
            event: 'oauth.introspect.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: 'Client authentication failed' },
          });
          throw err;
        }

        let payload;
        try {
          // Note: Currently checks signature and expiry only.
          // TODO: integrate access token revocation (e.g. jti-based store) when available.
          payload = await fastify.jwtUtils.verifyAccessToken(token);
        } catch (error) {
          if (error instanceof JWTExpiredError || error instanceof JWTInvalidError) {
            await fastify.repositories.auditLogs.create({
              userId: null,
              oauthClientId: client.id,
              event: 'oauth.introspect.failure',
              eventType: 'token',
              success: false,
              ipAddress: request.ip,
              userAgent: request.headers['user-agent'] || null,
              metadata: {
                error: error.message || 'Invalid or expired token',
              },
            });

            await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

            return reply.send({
              active: false as const,
            });
          }

          throw error;
        }

        // Restrict clients to introspecting only their own tokens
        if (payload.clientId !== client.clientId) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: client.id,
            event: 'oauth.introspect.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: {
              error: 'Token client mismatch',
            },
          });

          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

          return reply.send({
            active: false as const,
          });
        }

        await fastify.repositories.auditLogs.create({
          userId: payload.sub,
          oauthClientId: client.id,
          event: 'oauth.introspect.success',
          eventType: 'token',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            tokenClientId: payload.clientId,
          },
        });

        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

        return reply.send({
          active: true as const,
          sub: payload.sub,
          client_id: payload.clientId,
          exp: payload.exp,
          iat: payload.iat,
          iss: payload.iss,
          aud: payload.aud,
          scope: payload.scope,
          token_type: 'Bearer' as const,
        });
      } catch (error) {
        if (error instanceof InvalidClientError) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);
          throw error;
        }

        const fallbackOauthClientId = body.client_id ?? null;

        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: fallbackOauthClientId,
          event: 'oauth.introspect.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });

        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

        throw error;
      }
    }
  );
}
