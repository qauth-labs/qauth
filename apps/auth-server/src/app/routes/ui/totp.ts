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
import { recoveryPageExpired } from '../../helpers/recovery-code-pages';
import { requestRealm } from '../../helpers/request-realm';
import { totpPage, totpSetupPage } from '../../helpers/totp-pages';

/**
 * THE AUTHENTICATOR APP'S PAGES ON THE HOSTED PAGES (#653; ADR-017
 * Decisions 7 and 8, ADR-020 §3), under `/ui`, for an interaction of the
 * Interaction API whose current step is a TOTP step:
 *
 * - `GET /ui/totp/<interaction id>`: "enter the code from your
 *   authenticator app", after the password, with a recovery code in its
 *   place when the step offers one;
 * - `GET /ui/totp-setup/<interaction id>`: "set up an authenticator app",
 *   the new secret as a QR code and as text (the step's personal data), for
 *   the browser whose flow cookie binds the interaction, and never from
 *   another site.
 *
 * Each form posts to the Interaction API's answer endpoint
 * (`/interaction/v1-rc.0/<id>/answer`), which checks the origin, the flow
 * cookie and the CSRF value, runs the engine's round and sends the browser
 * on with `303`. An interaction at another step goes to its ceremony page.
 * Every page is `Cache-Control: no-store`.
 */

const TOTP_STEP = stepUrn('totp');
const TOTP_SETUP_STEP = stepUrn('totp_setup');
const RECOVERY_CODE_STEP = stepUrn('recovery_code');

/**
 * The set-up step's personal data: the secret, and the URI the QR code holds.
 * The URI's label and issuer are `encodeURIComponent` output, joined by
 * `:`, `?`, `=` and `&`: nothing else is shown.
 */
const setupPersonalSchema = z.object({
  secret: z.string().regex(/^[A-Z2-7]{32}$/),
  otpauth_uri: z
    .string()
    .max(1024)
    .regex(/^otpauth:\/\/totp\/[A-Za-z0-9_.!~*'()%:?=&-]+$/),
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
    '/totp/:interactionId',
    {
      schema: {
        description:
          'The "enter the code from your authenticator app" page (#653): the form of the interaction\'s `totp` step, with the error of a refused code and, when the step offers it, a recovery code in its place. `Cache-Control: no-store`.',
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
        if (view.step.name !== TOTP_STEP) return reply.redirect(urls.ceremony, 303);
        const form = { action: urls.action, csrf: view.csrf };
        return sendPage(
          reply,
          totpPage({
            cspNonce: reply.cspNonce.style,
            refused: view.step.error === 'invalid_credentials',
            ...form,
            type: TOTP_STEP,
            ...(view.step.alternatives.includes(RECOVERY_CODE_STEP)
              ? { recoveryCode: { ...form, type: RECOVERY_CODE_STEP } }
              : {}),
          })
        );
      });
    }
  );

  app.get(
    '/totp-setup/:interactionId',
    {
      schema: {
        description:
          'The "set up an authenticator app" page (#653): the new secret of the interaction\'s `totp_setup` step as a QR code and as text, and the form of its first code, which binds the secret. Needs the flow cookie; refused from another site. `Cache-Control: no-store`.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [403, 410],
        params,
      },
      config,
    },
    async (request, reply) => {
      const id = request.params.interactionId;
      // The secret is personal data: a page another site opened or framed
      // never shows it.
      const site = request.headers['sec-fetch-site'];
      if (site !== undefined && site !== 'same-origin' && site !== 'none') {
        await refuseForbidden(request, 'origin');
      }
      return expiredOr(reply, async () => {
        if (!isInteractionId(id)) throw new InteractionExpiredError();
        const personal = await readInteractionPersonalData(request, id);
        const urls = urlsOf(request, id);
        if (personal.step !== TOTP_SETUP_STEP) return reply.redirect(urls.ceremony, 303);
        const shown = setupPersonalSchema.safeParse(personal.data);
        if (!shown.success) throw new Error('the totp_setup step holds no secret');
        const view = await readInteractionStep(request, id);
        if (view.step.name !== TOTP_SETUP_STEP) return reply.redirect(urls.ceremony, 303);
        return sendPage(
          reply,
          totpSetupPage({
            cspNonce: reply.cspNonce.style,
            refused: view.step.error === 'invalid_credentials',
            secret: shown.data.secret,
            otpauthUri: shown.data.otpauth_uri,
            action: urls.action,
            type: TOTP_SETUP_STEP,
            csrf: view.csrf,
          })
        );
      });
    }
  );
}
