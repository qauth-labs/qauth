import { InvalidCredentialsError, TooManyRequestsError } from '@qauth-labs/shared-errors';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import { randomUUID } from 'crypto';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { accountPoliciesOf } from '../../helpers/account-policies';
import { withoutAdminAudience } from '../../helpers/admin-scopes';
import { hashEmail, logAuthEvent } from '../../helpers/auth-events';
import { clientAddressKey } from '../../helpers/client-address';
import { resolveAudience } from '../../helpers/client-auth';
import { verifyPasswordCredential } from '../../helpers/credential-auth';
import { recordSuccessfulLogin, registerLoginAttempt } from '../../helpers/failed-login';
import { issueAccessToken } from '../../helpers/hybrid-token';
import { getOrCreateSystemClient } from '../../helpers/oauth-client';
import { tokenLifetimesOf } from '../../helpers/realm-policy-readers';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { refreshFamilyEnd, refreshTokenExpiresAt } from '../../helpers/refresh-family';
import { requestRealm } from '../../helpers/request-realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { emitUserEvent } from '../../helpers/user-events';
import { type LoginRequest, loginResponseSchema, loginSchema } from '../../schemas/auth';

/**
 * Login route
 * Handles user authentication with password verification, JWT generation,
 * refresh token storage, session management, and its sign-in events
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/login',
    {
      schema: {
        description:
          'Authenticate with email and password. Returns access token, refresh token, and expiration. Requires valid credentials.',
        tags: ['Auth'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401],
        body: loginSchema,
        response: {
          200: loginResponseSchema,
        },
      },
      config: {
        surface: 'api',
        rateLimit: {
          max: env.LOGIN_RATE_LIMIT,
          timeWindow: env.LOGIN_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const { email, password } = request.body as LoginRequest;

      // Normalize email up front so it is available to lockout tracking and
      // structured logging on every code path (#115, #124, #125).
      const normalizedEmail = normalizeEmail(email);
      // Identifiers tracked for failed-login throttling (#115): the email is
      // hashed so the cache never stores raw addresses, plus the source IP
      // (an IPv6 client by its /64, as in the rate limits).
      const emailHash = hashEmail(normalizedEmail);
      const emailIdentifier = `email:${emailHash}`;
      const lockoutIdentifiers = [emailIdentifier, `ip:${clientAddressKey(request)}`];
      // The realm of the host the request named (#487): the account is looked
      // up in it, and its lockout and events are its own.
      const realm = requestRealm(request);

      try {
        // The realm's verified-account gate and brute-force policy (#528),
        // from the resolver's row: no query.
        const policies = accountPoliciesOf(fastify, realm);

        // Reject early if this identifier is currently locked out; otherwise
        // count the attempt now, before the password is looked at, so that
        // guesses sent concurrently cannot outrun the counter (#115).
        const lockout = await registerLoginAttempt(
          fastify.redis,
          realm.id,
          policies.bruteForce,
          lockoutIdentifiers
        );
        if (lockout.locked) {
          fastify.metrics.loginAttempts.inc({ result: 'failure', reason: 'locked_out' });
          logAuthEvent(request, 'user.login.failure', false, {
            emailHash,
            reason: 'locked_out',
          });
          if (lockout.retryAfterSeconds !== undefined) {
            reply.header('Retry-After', String(lockout.retryAfterSeconds));
          }
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);
          throw new TooManyRequestsError('Too many failed login attempts. Please try again later.');
        }

        // Password check via the user_credentials read path (#228): lookup on
        // (realm_id, 'password', external_sub), argon2 against
        // credential_data.password_hash, provider-normalized identity.
        const check = await verifyPasswordCredential(fastify, {
          realmId: realm.id,
          email: normalizedEmail,
          password,
        });

        // Verified-account gate (F-08): the realm's
        // `accounts.requireVerifiedAccount` (#528), on by default, which
        // `REQUIRE_VERIFIED_ACCOUNT` (old name `REQUIRE_EMAIL_VERIFIED`) seeds
        // in a new realm. For a password account the proof is the confirmed
        // address: since #228 the gate reads credential_data.email_verified,
        // the authoritative source (the legacy users.email_verified column was
        // dropped in #261).
        //
        // An unverified account is refused EXACTLY like a wrong password: the
        // same 401 and message, the same floor, the same order of work, the
        // attempt left counted. A distinct answer (it used to be 403
        // EMAIL_NOT_VERIFIED) is an enumeration oracle: anyone may register
        // any address with a password of their choice, and logging in with it
        // then told a free address (the new, unverified account: 403) from a
        // registered one (the owner's password: 401). ANT-2026-SPEMY9GU.
        // Only the server-side log line and event keep the reason.
        const unverified =
          check.status === 'ok' && !check.emailVerified && policies.requireVerifiedAccount;

        // The users row supplies the stable subject id plus session/event/log
        // fields. The row must exist for any live credential (FK), so a miss
        // is treated as invalid below.
        // The refresh family's start, taken before the account is read
        // (#748): a disablement that commits after the read is not seen by
        // it, and a start stamped later could fall past its time.
        const issuedAt = Date.now();
        const user =
          check.status === 'ok' && !unverified
            ? await fastify.repositories.users.findById(realm.id, check.credential.userId)
            : undefined;
        if (check.status === 'ok' && !unverified && !user) {
          fastify.log.error(
            { credentialId: check.credential.id },
            'password credential without a users row'
          );
        }

        // If credentials are invalid, the account is unverified under the
        // gate, or the account is disabled, throw the same generic error. None
        // of them may get a token, and none may be distinguishable from a
        // wrong password (same 401, same timing floor, same failed-attempt
        // accounting) — as /ui/login does. The attempt, counted before
        // verification, stays counted (#115).
        if (check.status !== 'ok' || unverified || !user || !user.enabled) {
          // Structured log of the failed login (#125): IP + email *hash* only,
          // never the password or the raw email. The metric label stays
          // `invalid_credentials` for an unverified account too: `/metrics` is
          // unauthenticated, so a label of its own would be the oracle again.
          fastify.metrics.loginAttempts.inc({ result: 'failure', reason: 'invalid_credentials' });
          logAuthEvent(request, 'user.login.failure', false, {
            emailHash,
            reason: unverified ? 'email_not_verified' : 'invalid_credentials',
          });

          // Ensure minimum response time to prevent timing attacks
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);

          // Record the refused sign-in. Never the address: the person is the
          // subject only when the password checked out (an unverified account).
          await emitUserEvent(
            request,
            'urn:qauth:event:user.sign_in_failed:v1-rc.0',
            {
              method: 'password',
              reason: unverified ? 'email_not_verified' : 'invalid_credentials',
            },
            {
              realmId: realm.id,
              userId: unverified ? check.credential.userId : null,
              actor: 'user',
            }
          );

          throw new InvalidCredentialsError('Invalid email or password');
        }

        // Get or create system OAuth client
        const systemClient = await getOrCreateSystemClient(realm.id, fastify);

        // The realm's token lifetimes (#527), from the resolver's row: no
        // query. This first-party sign-in has no client environment, so its
        // access token gets the `short` tier, the realm's access lifetime.
        const tokenLifetimes = tokenLifetimesOf(fastify, realm);
        const accessTokenExpiresIn = tokenLifetimes.accessTokenLifespanSeconds;

        // Generate access token (JWT) using JWT plugin. No `email` /
        // `email_verified`: an access token carries them only under the
        // `email` scope, and this first-party token is granted no scope
        // (ANT-2026-2O0T72HY). Nothing that accepts it reads them; the
        // session below keeps the sign-in address for display.
        const accessToken = await issueAccessToken(fastify, realm, {
          sub: user.id,
          clientId: systemClient.clientId,
          // Never the admin API's audience: this sign-in checks no admin
          // grant (#510), whatever the system client's row lists.
          aud: withoutAdminAudience(resolveAudience(systemClient), systemClient.clientId),
          // Signed with the lifetime `expires_in` names.
          expiresInOverride: accessTokenExpiresIn,
        });

        // Generate refresh token using JWT plugin
        const { token: refreshToken, tokenHash: refreshTokenHash } =
          fastify.jwtUtils.generateRefreshToken();

        // The refresh token's expiry: the realm's refresh lifetime, and its
        // `sso_max_lifespan` caps the refresh-token family from its start
        // (ADR-019 Decision 3, #552). No browser session backs this sign-in,
        // so no session end caps it.
        const familyCreatedAt = issuedAt;
        const refreshExpiresAt = refreshTokenExpiresAt(
          familyCreatedAt,
          tokenLifetimes.refreshTokenLifespanSeconds,
          refreshFamilyEnd(familyCreatedAt, realm.ssoMaxLifespan, null)
        );

        // Store refresh token in database (hashed). Each login starts a
        // new refresh-token family — every rotation at /oauth/token
        // inherits this `familyId` for replay-detection revocation, and
        // this start time, which the family's age counts from.
        await fastify.repositories.refreshTokens.create({
          userId: user.id,
          oauthClientId: systemClient.id,
          tokenHash: refreshTokenHash,
          familyId: randomUUID(),
          familyCreatedAt,
          familySessionExpiresAt: null,
          expiresAt: refreshExpiresAt,
          scopes: [],
        });

        // Record the sign-in
        await emitUserEvent(
          request,
          'urn:qauth:event:user.signed_in:v1-rc.0',
          { method: 'password' },
          {
            realmId: realm.id,
            userId: user.id,
            clientId: systemClient.clientId,
            actor: 'user',
          }
        );

        // Update user lastLoginAt timestamp
        await fastify.repositories.users.updateLastLogin(realm.id, user.id);

        // Successful login: clear the account's failed-attempt counter and
        // lockout (#115) and emit structured success log + metrics (#123,
        // #124, #126). The source address only gets back this attempt's own
        // count: its counter holds the failures of every account guessed at
        // from it, and registration is open, so logging in to an account of
        // one's own must not clear them.
        await recordSuccessfulLogin(fastify.redis, realm.id, policies.bruteForce, lockout, [
          emailIdentifier,
        ]);
        fastify.metrics.loginAttempts.inc({ result: 'success' });
        fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'password' });
        fastify.metrics.tokensIssued.inc({ type: 'refresh', grant_type: 'password' });
        logAuthEvent(request, 'user.login.success', true, {
          userId: user.id,
          clientId: systemClient.clientId,
          email: check.credential.externalSub,
        });

        // RFC 6749 §5.1: token responses MUST NOT be cached by intermediaries.
        reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');

        // Return tokens
        return reply.send({
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: accessTokenExpiresIn,
          token_type: 'Bearer' as const,
        });
      } catch (error) {
        // InvalidCredentialsError (delay/logging already handled above) and
        // TooManyRequestsError (lockout, handled above) are re-thrown as-is.
        if (error instanceof InvalidCredentialsError || error instanceof TooManyRequestsError) {
          throw error;
        }

        // Log other errors as failed login attempts (structured log + event).
        fastify.metrics.loginAttempts.inc({ result: 'failure', reason: 'error' });
        logAuthEvent(request, 'user.login.failure', false, {
          emailHash,
          reason: 'error',
        });

        await emitUserEvent(
          request,
          'urn:qauth:event:user.sign_in_failed:v1-rc.0',
          { method: 'password', reason: 'internal_error' },
          { realmId: realm.id, userId: null, actor: 'user' }
        );

        // Ensure minimum response time even on errors
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);

        throw error;
      }
    }
  );
}
