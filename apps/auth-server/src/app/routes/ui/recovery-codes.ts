import {
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_PATTERN,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { ceremonyPagePath, stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import {
  readInteractionPersonalData,
  readInteractionStep,
  refuseForbidden,
} from '../../helpers/interaction';
import { InteractionExpiredError } from '../../helpers/interaction-expired';
import { isInteractionId } from '../../helpers/interaction-record';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import { buildRealmUrl } from '../../helpers/realm-url';
import {
  recoveryCodePage,
  recoveryCodesPage,
  recoveryPageExpired,
} from '../../helpers/recovery-code-pages';
import { requestRealm } from '../../helpers/request-realm';

/**
 * THE RECOVERY CODES' PAGES ON THE HOSTED PAGES (#649; ADR-017 Decision 8),
 * under `/ui`, for an interaction of the Interaction API whose current step
 * is one of the two Interaction-API-only recovery steps:
 *
 * - `GET /ui/recovery-codes/<interaction id>`: "save your recovery codes",
 *   the new set shown once (the step's personal data), for the browser whose
 *   flow cookie binds the interaction, and never from another site;
 * - `GET /ui/recovery-code/<interaction id>`: "use a recovery code", in
 *   place of the second factor the sign-in asks for.
 *
 * Each form posts to the Interaction API's answer endpoint
 * (`/interaction/v1-rc.0/<id>/answer`), which checks the origin, the flow
 * cookie and the CSRF value, runs the engine's round and sends the browser
 * on with `303`. An interaction at another step goes to its ceremony page.
 * Every page is `Cache-Control: no-store`.
 */

const RECOVERY_CODES_STEP = stepUrn('recovery_codes');
const RECOVERY_CODE_STEP = stepUrn('recovery_code');

/** The step's personal data when it is a set: 10 distinct codes of the shown form. */
const shownCodesSchema = z.object({
  codes: z
    .array(z.string().regex(RECOVERY_CODE_PATTERN))
    .length(RECOVERY_CODE_COUNT)
    .refine((codes) => new Set(codes).size === codes.length),
});

export default async function (fastify: FastifyInstance) {
  const app = fastify.withTypeProvider<ZodTypeProvider>();
  // A page is read once per step: the authorization endpoint's budget, as
  // the Interaction API's step read.
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
  const params = z.object({ interactionId: z.string().max(64) });

  const sendPage = (reply: FastifyReply, body: string, status = 200) =>
    reply
      .code(status)
      .header('Cache-Control', 'no-store')
      .header('Content-Type', 'text/html; charset=utf-8')
      .send(body);
  /** The answer endpoint and the ceremony page of the interaction, on the realm's origin. */
  const urlsOf = (request: FastifyRequest, id: string) => {
    const realm = requestRealm(request);
    return {
      action: buildRealmUrl(realm, `/interaction/v1-rc.0/${id}/answer`),
      ceremony: buildRealmUrl(realm, ceremonyPagePath(id)),
    };
  };
  /** An interaction that is unknown, expired or finished gets its page, `410`. */
  const expiredOr = async (
    reply: FastifyReply,
    work: () => Promise<FastifyReply>
  ): Promise<FastifyReply> => {
    try {
      return await work();
    } catch (error) {
      if (!(error instanceof InteractionExpiredError)) throw error;
      return sendPage(reply, recoveryPageExpired({ cspNonce: reply.cspNonce.style }), 410);
    }
  };

  app.get(
    '/recovery-codes/:interactionId',
    {
      schema: {
        description:
          'The "save your recovery codes" page (#649): the new set of recovery codes of the interaction\'s `recovery_codes` step, shown once, and the confirmation the step needs. Needs the flow cookie; refused from another site. `Cache-Control: no-store`.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [403, 410],
        params,
      },
      config,
    },
    async (request, reply) => {
      const id = request.params.interactionId;
      // The codes are personal data: a page another site opened or framed
      // never shows them.
      const site = request.headers['sec-fetch-site'];
      if (site !== undefined && site !== 'same-origin' && site !== 'none') {
        await refuseForbidden(request, 'origin');
      }
      return expiredOr(reply, async () => {
        if (!isInteractionId(id)) throw new InteractionExpiredError();
        const personal = await readInteractionPersonalData(request, id);
        const urls = urlsOf(request, id);
        if (personal.step !== RECOVERY_CODES_STEP) return reply.redirect(urls.ceremony, 303);
        const shown = shownCodesSchema.safeParse(personal.data);
        if (!shown.success) throw new Error('the recovery_codes step holds no set of codes');
        const view = await readInteractionStep(request, id);
        if (view.step.name !== RECOVERY_CODES_STEP) return reply.redirect(urls.ceremony, 303);
        return sendPage(
          reply,
          recoveryCodesPage({
            cspNonce: reply.cspNonce.style,
            codes: shown.data.codes,
            action: urls.action,
            type: RECOVERY_CODES_STEP,
            csrf: view.csrf,
          })
        );
      });
    }
  );

  app.get(
    '/recovery-code/:interactionId',
    {
      schema: {
        description:
          'The "use a recovery code" page (#649): the form of the interaction\'s `recovery_code` step, with the error of a refused code. `Cache-Control: no-store`.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [410],
        params,
      },
      config,
    },
    async (request, reply) => {
      const id = request.params.interactionId;
      return expiredOr(reply, async () => {
        if (!isInteractionId(id)) throw new InteractionExpiredError();
        const view = await readInteractionStep(request, id);
        const urls = urlsOf(request, id);
        if (view.step.name !== RECOVERY_CODE_STEP) return reply.redirect(urls.ceremony, 303);
        return sendPage(
          reply,
          recoveryCodePage({
            cspNonce: reply.cspNonce.style,
            refused: view.step.error === 'invalid_credentials',
            action: urls.action,
            type: RECOVERY_CODE_STEP,
            csrf: view.csrf,
          })
        );
      });
    }
  );
}
