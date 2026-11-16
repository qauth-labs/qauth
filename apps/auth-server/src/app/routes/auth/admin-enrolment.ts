import { ceremonyPagePath } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import {
  ADMIN_ENROLMENT_RESULTS,
  answerAdminEnrolmentStatus,
  sendAdminEnrolmentRefused,
  startAdminEnrolment,
} from '../../helpers/admin-enrolment';
import { refuseForbidden } from '../../helpers/interaction';
import { comesFromRealmOrigin } from '../../helpers/realm-origin';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import { requestRealm } from '../../helpers/request-realm';

/**
 * POST /auth/admin-enrolment and GET /auth/admin-enrolment/status (#621;
 * ADR-019 Decision 7): the start and the end of the one-time enrolment of an
 * admin account the break-glass CLI created. The rules are in
 * `helpers/admin-enrolment.ts`; the flow graph is
 * `graphs/flows/core/admin-enrolment`.
 *
 * The ceremony app's page `/ui/admin-enrolment` reads the token from its
 * URL's fragment and, when the person asks, posts it here as a form with
 * the one member `token`, from the realm origin. A start from another origin
 * gets the Interaction API's generic `403`, audited as
 * `request.csrf_rejected`. A token that starts an enrolment gets `303` to
 * the ceremony page of the new interaction, whose flow cookie this answer
 * sets; any other gets one answer, whatever the reason, and no interaction,
 * as every start does while passkey sign-in is off.
 * The token is read in the handler, never echoed, never logged, and leaves
 * the answer by no `Referer`.
 *
 * Browser routes (#486): the start sets the flow cookie, so both answer on
 * the realm's primary host only. Their budget is the authorization
 * endpoint's, per client address and realm, with its environment-aware cap
 * (ADR-008 §5).
 */

/** The start's body bound: one token of 43 characters, and room for a form's overhead. */
export const ADMIN_ENROLMENT_BODY_LIMIT = 1024;

export default async function (fastify: FastifyInstance) {
  const config = {
    surface: 'browser' as const,
    rateLimit: {
      max: (request: FastifyRequest) =>
        resolveRealmRateLimitMax(request.realm, {
          lenientMax: env.AUTHORIZE_RATE_LIMIT_LENIENT,
          strictMax: env.AUTHORIZE_RATE_LIMIT,
        }),
      timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
      keyGenerator: realmRateLimitKey,
    },
  };
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  app.post(
    '/admin-enrolment',
    {
      schema: {
        description:
          'Start the one-time enrolment of an admin account the break-glass CLI created (ADR-019 Decision 7): the ceremony app’s enrolment page posts the token of the enrolment URL’s fragment as a form, from the realm origin. A token that may still be redeemed starts an interaction at the admin_enrolment step in this browser and redirects (303) to its ceremony page; starting does not spend it. A malformed, unknown, used or expired token gets one HTML page (400), and no interaction, as does every start while passkey sign-in is off (WEBAUTHN_ENABLED); a realm that names its ceremony app’s error page (its ceremonyApp.errorPage policy) gets 303 to that page instead, with code=admin_enrolment_refused. A request from another origin is refused with 403.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 403, 413, 415, 429],
        consumes: ['application/x-www-form-urlencoded'],
        // Read in the handler, not refused here: a damaged token gets the
        // refusal every other token gets, not a problem document.
        body: z
          .object({
            token: z.string().optional(),
          })
          .nullish(),
      },
      attachValidation: true,
      bodyLimit: ADMIN_ENROLMENT_BODY_LIMIT,
      config,
    },
    async (request, reply) => {
      if (!comesFromRealmOrigin(request.headers, requestRealm(request), 'required')) {
        await refuseForbidden(request, 'origin');
      }
      const token =
        request.validationError === undefined ? (request.body ?? undefined)?.token : undefined;
      const started = await startAdminEnrolment(fastify, request, reply, token);
      if (started.kind === 'refused') return sendAdminEnrolmentRefused(fastify, request, reply);
      reply.header('Cache-Control', 'no-store');
      reply.header('Referrer-Policy', 'no-referrer');
      return reply.redirect(ceremonyPagePath(started.id), 303);
    }
  );

  app.get(
    '/admin-enrolment/status',
    {
      schema: {
        description:
          'The page an admin enrolment ends on when the realm names no ceremony error page: result=enrolled (the account’s first passkey was stored), cancelled (nothing was stored; the enrolment URL works until it expires) or refused (the enrolment URL enrolled nothing). Any other value reads as refused. A realm that names its ceremony app’s error page (its ceremonyApp.errorPage policy) gets 303 to that page instead, with code=admin_enrolment_finished and enrolled, or code=admin_enrolment_refused.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [429],
        querystring: z.object({
          // Any value is answered: one that is not a result reads as refused.
          result: z
            .string()
            .optional()
            .describe(`How the enrolment ended: ${ADMIN_ENROLMENT_RESULTS.join(', ')}.`),
        }),
      },
      config,
    },
    async (request, reply) =>
      answerAdminEnrolmentStatus(fastify, request, reply, request.query.result)
  );
}
