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
 *
 * Authorization model (who may introspect what):
 *   1. Same-client: a client may always introspect tokens it itself issued
 *      (`payload.client_id === client.client_id`).
 *   2. Audience-bound: a resource server holds a confidential introspection
 *      client whose `audience` column lists the audiences it is authoritative
 *      for. If the token's `aud` is a member of the client's `audience`, the
 *      introspection is allowed. This is what lets a single resource server
 *      validate tokens minted by many distinct callers, without giving the
 *      resource server the ability to mint tokens for those audiences itself.
 *   Any other cross-client introspection returns `active: false`.
 */

/**
 * Canonical hex UUID shape (8-4-4-4-12). Used to gate writes to
 * `audit_logs.user_id`, which is strictly a uuid column: non-UUID subjects
 * (client_credentials client slugs, future service-account identifiers)
 * must not be cast into that column.
 */
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Returns true if the introspecting client is authoritative for the token's
 * audience: every token-aud value appears in the client's configured audience
 * list. Undefined/null/empty on either side returns false. Accepts both string
 * and string[] shapes for `payload.aud` per RFC 7519.
 */
function isClientAuthoritativeForAudience(
  payloadAud: string | string[] | undefined,
  clientAudience: string[] | null
): boolean {
  if (
    !payloadAud ||
    (Array.isArray(payloadAud) && payloadAud.length === 0) ||
    !clientAudience ||
    clientAudience.length === 0
  ) {
    return false;
  }
  const tokenAuds = Array.isArray(payloadAud) ? payloadAud : [payloadAud];
  return tokenAuds.every((a) => clientAudience.includes(a));
}
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

        // Authorize the introspection: same-client OR audience-authoritative.
        const sameClient = payload.clientId === client.clientId;
        const audAuthoritative = isClientAuthoritativeForAudience(payload.aud, client.audience);
        if (!sameClient && !audAuthoritative) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: client.id,
            event: 'oauth.introspect.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: {
              error: 'Client not authorized for this token',
            },
          });

          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

          return reply.send({
            active: false as const,
          });
        }

        // `audit_logs.user_id` is strictly a uuid column. A token's `sub`
        // is a user UUID for authorization_code flows but a client slug
        // for client_credentials flows — and future grant types could
        // introduce service-account or prefixed subjects. Rather than
        // couple this audit write to qauth's current emission convention,
        // gate on the schema invariant itself: only write `sub` into
        // `user_id` when it parses as a UUID. Non-UUID subs are preserved
        // in `metadata.tokenSub` so audit-trail parity holds.
        const subIsUuid = payload.sub !== undefined && UUID_REGEX.test(payload.sub);
        await fastify.repositories.auditLogs.create({
          userId: subIsUuid ? payload.sub : null,
          oauthClientId: client.id,
          event: 'oauth.introspect.success',
          eventType: 'token',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            tokenClientId: payload.clientId,
            ...(subIsUuid ? {} : { tokenSub: payload.sub }),
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
