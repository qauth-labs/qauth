import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { verifyEmailAddress } from '../../helpers/email-verification';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { requestRealm } from '../../helpers/request-realm';
import { type VerifyBody, verifyBodySchema, verifyResponseSchema } from '../../schemas/auth';

/**
 * Email verification route
 * Verifies user email addresses using tokens sent via email
 *
 * The rules — token hashed before the lookup, one generic error for every
 * unusable token, single use, token AND password, the shared failed-login
 * lockout — live in `verifyEmailAddress()` (`helpers/email-verification.ts`),
 * which the emailed link's form (`POST /ui/verify`) calls too. This route is
 * the JSON transport: errors reach the error handler as problem documents.
 *
 * Rate limiting prevents brute-force attacks (VERIFICATION_RATE_LIMIT requests
 * per VERIFICATION_RATE_WINDOW per address and realm, 10 per 15 minutes by
 * default); `POST /ui/verify` has the same limit.
 *
 * POST, never a verifying GET. Verifying is a state change with consequences:
 * it marks the credential's email as verified, and relying parties may link
 * accounts by verified email. A GET that verified on any fetch of the emailed
 * link — a mail gateway's link scanner, a browser prefetch, or a page that
 * calls the API as it loads — would let an account someone else registered
 * with this address, and whose password they hold, be verified without the
 * mailbox owner ever choosing to. The token travels in the body. The emailed
 * link (`GET /auth/verify?token=…`, `verify-page.ts`) only renders a form that
 * asks for the password, and the portal's /verify page calls this route only
 * when the reader presses its confirm button.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/verify',
    {
      schema: {
        description:
          'Verify email address using the token sent via email, in the request body. Single-use; marks token as used. POST so no link fetch or prefetch can verify an address on its own.',
        tags: ['Auth'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 409],
        body: verifyBodySchema,
        response: {
          200: verifyResponseSchema,
        },
      },
      config: {
        surface: 'api',
        rateLimit: {
          max: env.VERIFICATION_RATE_LIMIT,
          timeWindow: env.VERIFICATION_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const { token, password } = request.body as VerifyBody;

      // The realm of the host the request named (#487): the token is looked up
      // in it only (#489).
      const { email } = await verifyEmailAddress(fastify, request, reply, {
        realmId: requestRealm(request).id,
        token,
        password,
      });

      return {
        message: 'Email verified successfully',
        email,
      };
    }
  );
}
