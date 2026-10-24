import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { logAuthEvent } from '../../helpers/auth-events';
import { endBrowserSessions } from '../../helpers/browser-session';
import { clientAddressKey } from '../../helpers/client-address';
import { assertManagementToken } from '../../helpers/management-token';
import {
  clearSessionCookie,
  readCookie,
  SESSION_COOKIE_NAME,
  verifySignedSessionId,
} from '../../helpers/session-cookie';
import { revokeJti } from '../../helpers/token-revocation';
import { logoutHeadersSchema, logoutResponseSchema } from '../../schemas/auth';

/**
 * Logout route
 * Handles JWT verification, refresh token revocation, and audit logging
 * Allows logout even with expired tokens (user is ending their session anyway)
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/logout',
    {
      schema: {
        description:
          "Log out the current user. Ends the user's hosted browser sessions, revokes all refresh tokens and unredeemed authorization codes for the user, and the access token presented. Accepts expired access tokens.",
        tags: ['Auth'],
        'x-qauth-stability': 'stable',
        headers: logoutHeadersSchema,
        response: {
          200: logoutResponseSchema,
        },
      },
      config: {
        surface: 'api',
        rateLimit: {
          max: env.LOGOUT_RATE_LIMIT,
          timeWindow: env.LOGOUT_RATE_WINDOW * 1000,
          keyGenerator: clientAddressKey,
        },
      },
    },
    async (request, reply) => {
      // `userId` is set only once the lookup below confirms a user owns the
      // token's subject; until then the subject is only `tokenSub`.
      let userId: string | undefined;
      let tokenSub: string | undefined;
      let isExpired = false;

      try {
        // Extract JWT from Authorization header
        const authHeader = request.headers.authorization;
        const token = fastify.jwtUtils.extractFromHeader(authHeader);

        if (!token) {
          throw new JWTInvalidError(
            'Missing or invalid Authorization header. Expected format: "Bearer <token>"'
          );
        }

        // Try to verify JWT token
        // For logout, we allow expired tokens - user is ending their session anyway
        let claims: JWTPayload;
        try {
          claims = await fastify.jwtUtils.verifyAccessToken(token, {
            // RFC 9700 mix-up defence: only accept a token this AS issued.
            issuer: fastify.jwtUtils.getIssuer(),
          });
        } catch (error) {
          if (error instanceof JWTExpiredError) {
            // Token expired - its signature verified, so decode it to read the claims
            isExpired = true;
            claims = fastify.jwtUtils.decodeTokenUnsafe(token);
          } else {
            // Token is invalid (bad signature, malformed, etc.)
            throw error;
          }
        }

        // Logout revokes the user's refresh tokens at EVERY client, and every
        // user access token carries the user's id as `sub`. Accept only the
        // first-party token `/auth/login` mints, expired or not, so a token
        // issued to another client or audience cannot end the user's sessions.
        // A disabled user may still sign out: logout only ends access.
        await assertManagementToken(fastify, claims, { requireActiveUser: false });
        tokenSub = claims.sub;

        if (!tokenSub) {
          throw new JWTInvalidError('Invalid JWT token');
        }

        // A subject that names no user, deleted since the token was minted,
        // is refused as userinfo refuses it (#754; RFC 6750 §3.1
        // `invalid_token`): there is nothing left to sign out.
        const user = await fastify.repositories.users.findById(tokenSub);
        if (!user) {
          throw new JWTInvalidError('Access token subject is not a user');
        }
        userId = user.id;

        // End the user's hosted browser sessions first, so none of them can
        // obtain a new authorization code once the codes are invalidated
        // below. The portal calls this route from its server, so they are
        // found through the per-user index, not a cookie; the request's own
        // cookie is cleared when it names one of them.
        const endedSessions = await endBrowserSessions(fastify, userId);
        const requestSessionId = verifySignedSessionId(readCookie(request, SESSION_COOKIE_NAME));
        if (requestSessionId && endedSessions.includes(requestSessionId)) {
          clearSessionCookie(reply);
        }

        // Invalidate unredeemed authorization codes next: one redeemed after
        // the sweep below would mint a refresh token that survives the logout.
        // This also waits for a redemption in flight, which keeps its code row
        // locked until its refresh token is committed for the sweep to see.
        await fastify.repositories.authorizationCodes.invalidateForUser(userId);

        // Revoke all active refresh tokens for user
        // This ensures user is logged out from all devices
        await fastify.repositories.refreshTokens.revokeAllForUser(userId, 'logout');

        // End the token this request was made with as well, as `/oauth/revoke`
        // ends one presented to it: otherwise it keeps working at the
        // management API until it expires. An expired token is already inert.
        if (!isExpired && claims.jti && claims.exp !== undefined) {
          await revokeJti(fastify, claims.jti, claims.exp - Math.floor(Date.now() / 1000));
        }

        // Log audit event (success)
        await fastify.repositories.auditLogs.create({
          userId: user.id,
          oauthClientId: null,
          event: 'user.logout.success',
          eventType: 'auth',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            tokenExpired: isExpired,
          },
        });

        // Structured success log (#124).
        logAuthEvent(request, 'user.logout.success', true, { userId: user.id });

        return reply.send({
          success: true as const,
          message: 'Successfully logged out' as const,
        });
      } catch (error) {
        // Structured failure log (#124).
        logAuthEvent(request, 'user.logout.failure', false, {
          userId: userId ?? null,
          reason: error instanceof Error ? error.name : 'unknown_error',
        });

        // Log failed logout attempt. `audit_logs.user_id` references `users`:
        // a subject no user owns would fail the insert and turn the refusal
        // into a 500, so it is kept in `metadata.tokenSub` instead.
        await fastify.repositories.auditLogs.create({
          userId: userId ?? null,
          oauthClientId: null,
          event: 'user.logout.failure',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: error instanceof Error ? error.message : 'Unknown error',
            ...(userId === undefined && tokenSub ? { tokenSub } : {}),
          },
        });

        throw error;
      }
    }
  );
}
