import { type JWTPayload, refuseBoundTokenAsBearer } from '@qauth-labs/fastify-plugin-jwt';
import { JWTExpiredError, MissingAccessTokenError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { accessTokenIssuedAt, issuedBeforeDisablement } from '../../helpers/account-validity';
import { logAuthEvent } from '../../helpers/auth-events';
import { endBrowserSessions } from '../../helpers/browser-session';
import { assertManagementToken } from '../../helpers/management-token';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { tokenRealm } from '../../helpers/realm-url';
import { requestRealm } from '../../helpers/request-realm';
import {
  clearSessionCookie,
  readCookie,
  SESSION_COOKIE_NAME,
  verifySessionCookie,
} from '../../helpers/session-cookie';
import { revokeJti } from '../../helpers/token-revocation';
import { inactiveSubjectError } from '../../helpers/token-subject';
import { emitUserEvent, failureData, withEventReason } from '../../helpers/user-events';
import { logoutHeadersSchema, logoutResponseSchema } from '../../schemas/auth';

/**
 * The `reason` of a refused sign-out: the one tagged where it was thrown,
 * else `invalid_token` for a refused token and `internal_error` for anything
 * unexpected.
 */
function signOutFailureReason(error: unknown): string {
  const { error: code, reason } = failureData(error);
  return reason ?? (code === 'server_error' ? 'internal_error' : code);
}

/**
 * Logout route
 * Handles JWT verification, refresh token revocation, and its sign-out events
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
        'x-qauth-errors': [400, 401],
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
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      // `userId` (and the user's realm) is set only once the lookup below
      // confirms a user owns the token's subject.
      let userId: string | undefined;
      let realmId: string | undefined;
      let isExpired = false;

      try {
        // Extract JWT from Authorization header
        const authHeader = request.headers.authorization;
        const token = fastify.jwtUtils.extractFromHeader(authHeader);

        if (!token) {
          // No credential is not a refused token (RFC 6750 §3.1): 401
          // `unauthorized`, with a challenge that names no error.
          throw withEventReason(
            new MissingAccessTokenError(
              'Missing or invalid Authorization header. Expected format: "Bearer <token>"'
            ),
            'missing_token'
          );
        }

        // Try to verify JWT token
        // For logout, we allow expired tokens - user is ending their session anyway
        const realm = requestRealm(request);
        let claims: JWTPayload;
        try {
          // RFC 9700 mix-up defence: only accept a token this realm issued,
          // under its keys and its issuer (#491).
          claims = await fastify.jwtUtils.verifyAccessToken(tokenRealm(realm), token);
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
        // A disabled user may still sign out: logout only ends access. The
        // token must still be one of this host's realm (#487). A live portal
        // token minted before #524, with the system client's id as audience,
        // still signs out for this release, so a developer whose portal
        // session began on a node of the previous release keeps no tokens
        // when the upgrade rolls. REMOVE IN THE NEXT RELEASE.
        await assertManagementToken(fastify, realm, claims, {
          requireActiveUser: false,
          acceptPreDeveloperAudience: !isExpired,
        });
        // RFC 9449 §7.2 (#480): this route reads a Bearer token, and a
        // DPoP-bound token is never one.
        refuseBoundTokenAsBearer(claims);
        const tokenSub = claims.sub;

        if (!tokenSub) {
          throw withEventReason(inactiveSubjectError(), 'subject_not_a_user');
        }

        // A subject that names no user, deleted since the token was minted,
        // is refused as userinfo refuses it (#754; RFC 6750 §3.1
        // `invalid_token`): there is nothing left to sign out. Looked up in
        // the request's realm (#489), so a user of another realm is refused
        // the same way and nothing of theirs is ended here.
        const user = await fastify.repositories.users.findById(realm.id, tokenSub);
        if (!user) {
          throw withEventReason(inactiveSubjectError(), 'subject_not_a_user');
        }
        userId = user.id;
        realmId = user.realmId;

        // Once the account is enabled again, a token minted before it was
        // last disabled ends nothing (#748): whoever held it then must not
        // sign the owner out of the sessions they started since. While the
        // account is disabled its user may still sign out, as above.
        if (user.enabled && issuedBeforeDisablement(user, accessTokenIssuedAt(claims))) {
          throw withEventReason(inactiveSubjectError(), 'issued_before_disablement');
        }

        // End the user's hosted browser sessions first, so none of them can
        // obtain a new authorization code once the codes are invalidated
        // below. The portal calls this route from its server, so they are
        // found by the user in Postgres, never through a cookie or Redis
        // (#912); the request's own cookie is cleared when it names one.
        const endedSessions = await endBrowserSessions(fastify, user.realmId, userId);
        // Best effort (#493): the cookie verifies only with the realm's cookie
        // keys, and a process that cannot read them (no signer role, a signer
        // outage) must still end everything below. The cookie then names an
        // ended session, and the next page that reads it clears it.
        let requestSessionId: string | null = null;
        try {
          requestSessionId = await verifySessionCookie(
            fastify,
            user.realmId,
            readCookie(request, SESSION_COOKIE_NAME)
          );
        } catch (error) {
          request.log.warn(
            { reason: error instanceof Error ? error.name : 'unknown_error' },
            'the session cookie could not be checked at logout; the next page that reads it clears it'
          );
        }
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

        // Record the sign-out
        await emitUserEvent(
          request,
          'urn:qauth:event:user.signed_out:v1-rc.0',
          {},
          { realmId: user.realmId, userId: user.id, actor: 'user' }
        );

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

        // Record the refused sign-out. Only a subject the lookup above
        // confirmed is the event's subject: any other token subject names no
        // user.
        await emitUserEvent(
          request,
          'urn:qauth:event:user.sign_out_failed:v1-rc.0',
          { reason: signOutFailureReason(error) },
          { realmId, userId: userId ?? null, actor: 'user' }
        );

        throw error;
      }
    }
  );
}
