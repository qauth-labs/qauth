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
import { passkeyEnrolmentPage, passkeySignInPage } from '../../helpers/passkey-pages';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import { buildRealmUrl } from '../../helpers/realm-url';
import { recoveryPageExpired } from '../../helpers/recovery-code-pages';
import { requestRealm } from '../../helpers/request-realm';

/**
 * THE PASSKEY PAGES ON THE HOSTED PAGES (#651; ADR-017 Decisions 4 and 10),
 * under `/ui` on the realm's origin, for an interaction of the Interaction
 * API that offers a passkey step:
 *
 * - `GET /ui/passkey/<interaction id>`: "sign in with a passkey", while the
 *   `webauthn_get` step is the current step (passkey-first, or the downgrade
 *   rule after a password) or offered beside the password. Its request
 *   options name no account.
 * - `GET /ui/passkey-enrolment/<interaction id>`: "add a passkey", while the
 *   `webauthn_create` step is the current step, after a sign-in, for the
 *   browser whose flow cookie binds the interaction and never from another
 *   site: its options carry the account's name.
 *
 * Each runs the browser's ceremony and posts the result to the Interaction
 * API's answer endpoint (`/interaction/v1-rc.0/<id>/answer`), which checks
 * the origin, the flow cookie and the CSRF value, runs the engine's round and
 * sends the browser on with `303`. An interaction at another step goes to its
 * ceremony page. Every page is `Cache-Control: no-store`.
 */

const WEBAUTHN_GET_STEP = stepUrn('webauthn_get');
const WEBAUTHN_CREATE_STEP = stepUrn('webauthn_create');

/** The request options a page passes to the browser, as the step grammar keeps them. */
const requestOptionsSchema = z.looseObject({ challenge: z.string(), rpId: z.string() });

/** The `webauthn_create` step's params. */
const creationParamsSchema = z.looseObject({
  optional: z.boolean(),
  options: z.looseObject({ challenge: z.string(), rp: z.looseObject({}) }),
});

/** The `webauthn_create` step's personal data: the account's user entity and its passkeys. */
const creationPersonalSchema = z.looseObject({
  user: z.looseObject({ id: z.string(), name: z.string(), displayName: z.string() }),
  excludeCredentials: z.array(z.looseObject({ id: z.string() })),
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
    '/passkey/:interactionId',
    {
      schema: {
        description:
          'The "sign in with a passkey" page (#651): runs the browser\'s passkey ceremony for the interaction\'s `webauthn_get` step, current or offered beside the password, and posts the result to the answer endpoint. Its options name no account. `Cache-Control: no-store`.',
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
        const current = view.step.name === WEBAUTHN_GET_STEP;
        const offered = current
          ? view.step.params
          : view.step.alternatives.includes(WEBAUTHN_GET_STEP)
            ? view.step.alternativeParams?.[WEBAUTHN_GET_STEP]
            : undefined;
        const options = requestOptionsSchema.safeParse(offered);
        if (!options.success) return reply.redirect(urls.ceremony, 303);
        return sendPage(
          reply,
          passkeySignInPage({
            cspNonce: reply.cspNonce.style,
            scriptNonce: reply.cspNonce.script,
            refused: current && view.step.error === 'invalid_credentials',
            options: options.data,
            action: urls.action,
            type: WEBAUTHN_GET_STEP,
            csrf: view.csrf,
          })
        );
      });
    }
  );

  app.get(
    '/passkey-enrolment/:interactionId',
    {
      schema: {
        description:
          'The "add a passkey" page (#651): runs the browser\'s registration ceremony for the interaction\'s `webauthn_create` step, offered after a sign-in, and posts the result to the answer endpoint, or declines the offer. Needs the flow cookie; refused from another site. `Cache-Control: no-store`.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [403, 410],
        params,
      },
      config,
    },
    async (request, reply) => {
      const id = request.params.interactionId;
      // The options carry the account's name: a page another site opened or
      // framed never shows them.
      const site = request.headers['sec-fetch-site'];
      if (site !== undefined && site !== 'same-origin' && site !== 'none') {
        await refuseForbidden(request, 'origin');
      }
      return expiredOr(reply, async () => {
        if (!isInteractionId(id)) throw new InteractionExpiredError();
        const personal = await readInteractionPersonalData(request, id);
        const urls = urlsOf(request, id);
        if (personal.step !== WEBAUTHN_CREATE_STEP) return reply.redirect(urls.ceremony, 303);
        const view = await readInteractionStep(request, id);
        if (view.step.name !== WEBAUTHN_CREATE_STEP) return reply.redirect(urls.ceremony, 303);
        const step = creationParamsSchema.safeParse(view.step.params);
        const account = creationPersonalSchema.safeParse(personal.data);
        if (!step.success || !account.success) {
          throw new Error('the webauthn_create step holds no creation options');
        }
        return sendPage(
          reply,
          passkeyEnrolmentPage({
            cspNonce: reply.cspNonce.style,
            scriptNonce: reply.cspNonce.script,
            refused: view.step.error === 'invalid_credentials',
            optional: step.data.optional,
            options: {
              ...step.data.options,
              user: account.data.user,
              excludeCredentials: account.data.excludeCredentials,
            },
            action: urls.action,
            type: WEBAUTHN_CREATE_STEP,
            csrf: view.csrf,
          })
        );
      });
    }
  );
}
