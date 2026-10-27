import {
  EmailAlreadyVerifiedError,
  InvalidCredentialsError,
  InvalidTokenError,
  TooManyRequestsError,
} from '@qauth-labs/shared-errors';
import { passwordSchema } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { verifyEmailAddress } from '../../helpers/email-verification';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { requestRealm } from '../../helpers/request-realm';
import {
  csrfTokensEqual,
  generateCsrfToken,
  LOGIN_CSRF_COOKIE_NAME,
  readCookie,
  setLoginCsrfCookie,
  verifyLoginCsrfCookie,
} from '../../helpers/session-cookie';
import { sendVerifyEmailPage, VERIFY_FORM_ERRORS } from '../../helpers/verify-email-page';
import { verificationTokenSchema } from '../../schemas/auth';

const verifyFormSchema = z.object({
  // The same token schema as the JSON body of POST /auth/verify.
  token: verificationTokenSchema,
  password: passwordSchema.min(1),
  // Signed double-submit CSRF token, compared against the __Host- login-CSRF cookie.
  csrf_token: z.string().min(1),
});

type VerifyForm = z.infer<typeof verifyFormSchema>;

/**
 * The form of the emailed verification link's page (`GET /auth/verify`,
 * `routes/auth/verify-page.ts`).
 *
 * The verification itself is `verifyEmailAddress()`, the function
 * `POST /auth/verify` calls, so the two cannot drift apart. This route is its
 * browser transport: the body is the form, and the answer is a page with the
 * status the JSON route answers for the same outcome —
 *
 * | Outcome                                       | Status | Page                    |
 * | --------------------------------------------- | ------ | ----------------------- |
 * | Verified                                      | 200    | verified                |
 * | Unknown, expired or used token (one answer)   | 400    | link no longer valid    |
 * | Wrong password (nothing consumed)             | 401    | the form, with an error |
 * | Already verified                              | 409    | already verified        |
 * | Account or address locked out (`Retry-After`) | 429    | the form, with an error |
 *
 * — so the form tells a caller nothing the JSON route does not. A malformed
 * body is refused by the schema with the same `400` problem document as there.
 *
 * The token is looked up in the realm the host named (#489), so the link
 * verifies only at a host of its account's realm, whose issuer it names
 * (#870); at another realm's host it is an unknown token (`400`).
 *
 * Under `/ui/*` with the other browser forms, not on `POST /auth/verify`: that
 * route is the stable JSON API, answers on endpoint hosts and reads no cookie,
 * and this one needs the login-CSRF cookie (a `browser` route).
 *
 * The CSRF pair is checked before anything else, so a forged cross-site POST
 * never reaches the token lookup or the password check. The rate limit is the
 * JSON route's (`VERIFICATION_RATE_LIMIT` per `VERIFICATION_RATE_WINDOW`), and
 * wrong passwords count toward the failed-login lockout through the helper.
 *
 * Interim: the email-code step (#638) and the hosted account verification UI
 * (#644) replace link verification.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/verify',
    {
      schema: {
        description:
          'Submit the form of the emailed verification link (GET /auth/verify): the token and the account password. Verifies as POST /auth/verify does and answers a page with the status that route answers.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        // As on POST /ui/login: the schema's 400 (and the rate limiter's 429,
        // listed for every limited route) are problem documents; the outcomes
        // in the table above, and the 403 of a failed CSRF check, are pages.
        'x-qauth-errors': [400],
        body: verifyFormSchema,
      },
      config: {
        surface: 'browser',
        rateLimit: {
          max: env.VERIFICATION_RATE_LIMIT,
          timeWindow: env.VERIFICATION_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const body = request.body as VerifyForm;

      // Signed double-submit CSRF, as POST /ui/login checks it: the cookie's
      // signature, then a timing-safe comparison with the submitted field.
      const cookieCsrf = verifyLoginCsrfCookie(readCookie(request, LOGIN_CSRF_COOKIE_NAME));
      if (!cookieCsrf || !csrfTokensEqual(cookieCsrf, body.csrf_token)) {
        // Re-render with a fresh token so the person can retry legitimately.
        const freshCsrf = generateCsrfToken();
        setLoginCsrfCookie(reply, freshCsrf);
        return sendVerifyEmailPage(reply, 403, {
          kind: 'form',
          token: body.token,
          csrfToken: freshCsrf,
          error: VERIFY_FORM_ERRORS.sessionExpired,
        });
      }

      // The form again, for the two refusals that leave the token usable. The
      // CSRF cookie is still valid, so its token is reused.
      const formWithError = (statusCode: number, error: string) =>
        sendVerifyEmailPage(reply, statusCode, {
          kind: 'form',
          token: body.token,
          csrfToken: cookieCsrf,
          error,
        });

      try {
        const { email } = await verifyEmailAddress(fastify, request, reply, {
          // The token is looked up in the realm the host named only (#489).
          realmId: requestRealm(request).id,
          token: body.token,
          password: body.password,
        });
        return sendVerifyEmailPage(reply, 200, { kind: 'verified', email });
      } catch (error) {
        if (error instanceof InvalidTokenError) {
          return sendVerifyEmailPage(reply, error.statusCode, { kind: 'invalid-link' });
        }
        if (error instanceof InvalidCredentialsError) {
          return formWithError(error.statusCode, VERIFY_FORM_ERRORS.wrongPassword);
        }
        if (error instanceof EmailAlreadyVerifiedError) {
          return sendVerifyEmailPage(reply, error.statusCode, { kind: 'already-verified' });
        }
        if (error instanceof TooManyRequestsError) {
          // `Retry-After` is already on the reply.
          return formWithError(error.statusCode, VERIFY_FORM_ERRORS.lockedOut);
        }
        throw error;
      }
    }
  );
}
