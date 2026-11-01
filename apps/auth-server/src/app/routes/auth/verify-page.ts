import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { requestRealm } from '../../helpers/request-realm';
import {
  generateCsrfToken,
  LOGIN_CSRF_COOKIE_NAME,
  readCookie,
  setLoginCsrfCookie,
  verifyLoginCsrfCookie,
} from '../../helpers/session-cookie';
import { sendVerifyEmailPage } from '../../helpers/verify-email-page';
import { verificationTokenSchema } from '../../schemas/auth';

/**
 * The landing page of the emailed verification link: `GET /auth/verify?token=…`.
 *
 * The verification mail links here (`libs/server/email`, `EMAIL_BASE_URL`
 * plus `/auth/verify?token=<64 hex>`), and a mail client opens a link with
 * GET. Since verification became a POST that also needs the account's
 * password (42c4d1e4), nothing answered that GET, so a new account could not
 * be verified from its mail. ADR-019 Decision 6: a link QAuth mails points at
 * the auth server, and opening it starts an interaction in that browser.
 *
 * Opening the link changes nothing. The page holds the token in a hidden
 * field and asks for the password; only submitting the form
 * (`POST /ui/verify`, `routes/ui/verify.ts`) verifies, through the same
 * `verifyEmailAddress()` as `POST /auth/verify`. So a mail gateway's link
 * scanner or a browser prefetch that fetches the link verifies nothing, and
 * the database is not even read: a malformed token is told apart by its shape
 * alone, and an unknown or expired one only when the form is submitted.
 *
 * The token never leaves this page by another way: `Referrer-Policy:
 * no-referrer` on every answer, `Cache-Control: no-store`, and the request log
 * censors the `token` query value (`LOG_REDACTED_QUERY_PARAMETERS`).
 *
 * A `browser` route: it sets the login-CSRF cookie the form's double-submit
 * check needs, the same signed cookie the pre-authentication forms
 * (`/ui/login`, `/ui/wallet-login`) use, so it answers on the realm's primary
 * host only.
 *
 * The link verifies only at a host of its account's realm, whose issuer the
 * link names (#870): the form's token is looked up in the realm the host
 * named (#489), so at another realm's host it is an unknown token.
 *
 * Interim: the email-code step (#638) and the hosted account verification UI
 * (#644) replace link verification.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/verify',
    {
      schema: {
        description:
          'Landing page of the emailed verification link. Renders a form that asks for the account password; opening it verifies nothing. The form posts to POST /ui/verify.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        querystring: z.object({
          // Checked in the handler, not here: a missing or damaged token gets
          // the page with a message rather than a problem document.
          token: z.string().optional(),
        }),
      },
      config: { surface: 'browser' },
    },
    async (request, reply) => {
      const { token } = request.query as { token?: string };

      const parsed = verificationTokenSchema.safeParse(token);
      if (!parsed.success) {
        // No form: there is nothing to submit. Never a 500, and the value
        // that was sent is not echoed back.
        return sendVerifyEmailPage(reply, 400, { kind: 'incomplete-link' });
      }

      // Signed double-submit CSRF, as GET /ui/login does: keep a valid cookie
      // the browser already has, otherwise mint a token and set it.
      const existing = await verifyLoginCsrfCookie(
        fastify,
        requestRealm(request).id,
        readCookie(request, LOGIN_CSRF_COOKIE_NAME)
      );
      const csrfToken = existing ?? generateCsrfToken();
      if (!existing) {
        await setLoginCsrfCookie(fastify, reply, requestRealm(request).id, csrfToken);
      }

      return sendVerifyEmailPage(reply, 200, { kind: 'form', token: parsed.data, csrfToken });
    }
  );
}
