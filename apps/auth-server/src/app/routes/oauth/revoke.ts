import { InvalidClientError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { authenticateClient, extractClientCredentials } from '../../helpers/client-auth';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { revokeJti } from '../../helpers/token-revocation';
import { type RevokeRequest, revokeRequestSchema } from '../../schemas/oauth';

/**
 * POST /oauth/revoke
 * RFC 7009 OAuth 2.0 Token Revocation.
 *
 * - Accepts a `token` (access or refresh) in an
 *   `application/x-www-form-urlencoded` body, with an advisory
 *   `token_type_hint`.
 * - Requires confidential client authentication (client_secret_basic or
 *   client_secret_post), reusing the same path as introspection.
 * - Only the client that owns a token may revoke it. A token belonging to a
 *   different client (or an unknown/invalid token) is a NO-OP — never an error,
 *   per RFC 7009 §2.2, so the endpoint cannot be used to probe token existence
 *   or ownership.
 * - ALWAYS returns HTTP 200 with an empty body on success (RFC 7009 §2.2),
 *   regardless of whether anything was actually revoked. The only non-200
 *   outcome is a client-authentication failure (`invalid_client`, §2.2.1),
 *   matching the introspection endpoint.
 *
 * Revocation mechanics:
 * - Refresh token: looked up by hash; if owned by the authenticated client, the
 *   whole token family is revoked (consistent with the rotation/replay model in
 *   the token endpoint) so no descendant can be exchanged.
 * - Access token (stateless JWT): verified, and if it was issued to the
 *   authenticated client its `jti` is added to the Redis denylist with a TTL of
 *   its remaining lifetime. The `requireJwt` preHandler and the introspection
 *   endpoint both consult that denylist.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/revoke',
    {
      schema: {
        description:
          'RFC 7009 token revocation. Send the token and confidential client credentials in an application/x-www-form-urlencoded body. Always returns 200 with an empty body on success.',
        tags: ['OAuth', 'Revocation'],
        body: revokeRequestSchema,
      },
      config: {
        rateLimit: {
          // Consistent with introspection — both are confidential-client,
          // token-bearing endpoints (#211 follow-up; reuses the introspect cap).
          max: env.INTROSPECT_RATE_LIMIT,
          timeWindow: env.INTROSPECT_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const body = request.body as RevokeRequest;
      const { token, token_type_hint } = body;

      const realm = await getOrCreateDefaultRealm(fastify);

      // Confidential client authentication (RFC 7009 §2.1). A failure here is
      // the ONLY non-200 outcome (`invalid_client`, §2.2.1).
      let client;
      try {
        const creds = extractClientCredentials(request, body.client_id, body.client_secret);
        client = await authenticateClient(fastify, realm.id, creds);
      } catch (err) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'oauth.revoke.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'Client authentication failed' },
        });
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);
        throw err;
      }

      // Try refresh-token revocation first unless the hint says access_token.
      // RFC 7009 §2.1: the hint is advisory; if it is wrong we still attempt the
      // other type. Either way the response is an empty 200.
      let revoked = false;

      if (token_type_hint !== 'access_token') {
        revoked = await tryRevokeRefreshToken(fastify, client.id, token);
      }

      if (!revoked) {
        await tryRevokeAccessToken(fastify, client.clientId, token);
      }

      await fastify.repositories.auditLogs.create({
        userId: null,
        oauthClientId: client.id,
        event: 'oauth.revoke.success',
        eventType: 'token',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        // No token material is logged; only the (advisory) hint.
        metadata: { tokenTypeHint: token_type_hint ?? null },
      });

      await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

      // RFC 7009 §2.2: empty body, HTTP 200.
      return reply.code(200).send();
    }
  );
}

/**
 * Revoke a refresh token (and its whole family) IFF it hashes to a stored row
 * owned by the authenticated client. Returns true when a matching, owned token
 * was found (regardless of prior revoked state — re-revocation is idempotent),
 * false otherwise. A token owned by a DIFFERENT client is a no-op (returns
 * false) so cross-client revocation is impossible.
 */
async function tryRevokeRefreshToken(
  fastify: FastifyInstance,
  clientRowId: string,
  token: string
): Promise<boolean> {
  const hash = fastify.jwtUtils.hashRefreshToken(token);
  const stored = await fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked(hash);
  if (!stored) return false;
  // Ownership: only the owning client may revoke. A mismatch is a silent no-op.
  if (stored.oauthClientId !== clientRowId) return false;
  // Revoke the entire family so no rotated descendant remains exchangeable
  // (consistent with the replay-revocation model in the token endpoint).
  await fastify.repositories.refreshTokens.revokeFamily(stored.familyId, 'client_revocation');
  return true;
}

/**
 * Revoke an access token by denylisting its `jti` IFF it is a valid JWT issued
 * to the authenticated client. A token belonging to another client, an invalid
 * token, or one already expired is a silent no-op (RFC 7009 §2.2).
 */
async function tryRevokeAccessToken(
  fastify: FastifyInstance,
  clientId: string,
  token: string
): Promise<void> {
  let payload;
  try {
    payload = await fastify.jwtUtils.verifyAccessToken(token, {
      issuer: fastify.jwtUtils.getIssuer(),
    });
  } catch {
    // Invalid/expired/foreign-issuer token — nothing to revoke.
    return;
  }
  // Ownership: only the client the token was issued for may revoke it.
  if (payload.clientId !== clientId) return;
  if (!payload.jti || payload.exp === undefined) return;
  const remainingSeconds = payload.exp - Math.floor(Date.now() / 1000);
  await revokeJti(fastify, payload.jti, remainingSeconds);
}
