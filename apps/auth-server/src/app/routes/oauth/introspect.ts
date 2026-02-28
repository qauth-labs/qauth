import { InvalidCredentialsError, JWTExpiredError, JWTInvalidError } from '@qauth/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { introspectRequestSchema, introspectResponseSchema } from '../../schemas/oauth';

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
      const { token, client_id, client_secret } = request.body;

      try {
        const realm = await getOrCreateDefaultRealm(fastify);

        // Client lookup
        const client = await fastify.repositories.oauthClients.findByClientId(realm.id, client_id);

        if (!client || !client.enabled) {
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

          throw new InvalidCredentialsError('Client authentication failed');
        }

        // Client authentication (client_secret_post)
        const clientSecretValid = await fastify.passwordHasher.verifyPassword(
          client.clientSecretHash,
          client_secret
        );

        if (!clientSecretValid) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: client.id,
            event: 'oauth.introspect.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: 'Client authentication failed' },
          });

          throw new InvalidCredentialsError('Client authentication failed');
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
                error:
                  error instanceof Error && error.message
                    ? error.message
                    : 'Invalid or expired token',
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
          token_type: 'Bearer' as const,
        });
      } catch (error) {
        if (error instanceof InvalidCredentialsError) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);
          throw error;
        }

        const fallbackOauthClientId =
          typeof request.body.client_id === 'string' ? request.body.client_id : null;

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
