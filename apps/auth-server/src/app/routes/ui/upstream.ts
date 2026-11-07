import { ceremonyPagePath } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { accountPoliciesOf } from '../../helpers/account-policies';
import { createBackgroundTasks } from '../../helpers/background-tasks';
import {
  answerInteraction,
  type InteractionAnswerResult,
  readInteractionStep,
} from '../../helpers/interaction';
import { createInteractionEngines, decisionOf } from '../../helpers/interaction-engines';
import { InteractionExpiredError } from '../../helpers/interaction-expired';
import { isInteractionId } from '../../helpers/interaction-record';
import {
  normalizeInternalAuthorizeUrl,
  peekPendingAuthorization,
  RESUME_PATH_PREFIX,
} from '../../helpers/pending-authorization';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import { buildRealmUrl } from '../../helpers/realm-url';
import { recoveryPageExpired } from '../../helpers/recovery-code-pages';
import { requestRealm } from '../../helpers/request-realm';
import { roundEnvironment } from '../../helpers/round-limits';
import { sendUpstreamPage, upstreamLinkChoicePage } from '../../helpers/upstream-pages';
import { upstreamProviderCatalog } from '../../helpers/upstream-providers';
import {
  auditUpstreamRefusal,
  authorizeUrlOf,
  ceremonyPageUrlOf,
  sendUpstreamErrorPage,
  sendUpstreamLinkRefusedPage,
  sendUpstreamWaitingPage,
  UPSTREAM_LINK_STEP,
  upstreamRoundContext,
  type UpstreamSignInMode,
  UpstreamSignInRefusal,
  type UpstreamStarted,
  upstreamStarter,
} from '../../helpers/upstream-sign-in';

/**
 * THE HOSTED PAGES' WAY INTO AN UPSTREAM PROVIDER (#639), under `/ui`:
 *
 * - `GET /ui/upstream/<type>?return_to=...`: a provider button of the sign-in
 *   page, a plain link. It sends the browser back to the authorization
 *   request the page was opened for, with the routing parameter
 *   (`qauth_upstream=<type>`) that starts that provider. The request is the
 *   one the sign-in page's `return_to` names: a parked one
 *   (`/ui/resume/<handle>`, read without spending it) or an inline
 *   authorize URL.
 * - `GET /ui/upstream/<type>/start?interaction=<id>`: where the
 *   authorization endpoint sends a request that routes to a provider, once
 *   it started the interaction. The interaction's first round starts the
 *   provider (the engine records it, the flow keeps its transaction bound
 *   to the flow cookie) and the waiting page sends the browser on.
 *
 * - `GET /ui/upstream-link/<interaction id>` (#670): the `upstream_link`
 *   step's page, "I already have an account" or a new account, for an
 *   identity no account holds. Its form posts to the Interaction API's
 *   answer endpoint, which checks the origin, the flow cookie and the CSRF
 *   value. An interaction at another step goes to its ceremony page.
 * - `GET /ui/upstream-link-refused?provider=<type>&reason=<reason>` (#670):
 *   the page of a link the finish refused; it shows the reason and changes
 *   nothing.
 *
 * None changes anything unless the request's realm has the provider on
 * (hidden or not). All are rate-limited as the authorization endpoint is.
 */
export default async function (fastify: FastifyInstance) {
  const catalog = upstreamProviderCatalog(fastify);
  // The engines are built on the first routed start, and their mail's
  // background tasks now: those register a hook, which Fastify refuses once
  // the server started.
  const tasks = createBackgroundTasks(fastify);
  let engines: ReturnType<typeof createInteractionEngines> | undefined;
  const enginesOf = () => (engines ??= createInteractionEngines(fastify, { tasks }));
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

  app.get(
    '/upstream/:type',
    {
      schema: {
        description:
          "A provider button of the sign-in page (#639): back to the page's authorization request, routed to the upstream provider `type` with `qauth_upstream`.",
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        params: z.object({ type: z.string().max(64) }),
        querystring: z.object({
          return_to: z
            .string()
            .max(16 * 1024)
            .optional(),
        }),
      },
      config,
    },
    async (request, reply) => {
      const { type } = request.params;
      const realm = requestRealm(request);
      const provider = await catalog.find(realm.id, type);
      const returnTo = request.query.return_to;
      const authorizeUrl =
        returnTo === undefined
          ? null
          : returnTo.startsWith(RESUME_PATH_PREFIX)
            ? await peekPendingAuthorization(fastify, returnTo.slice(RESUME_PATH_PREFIX.length))
            : normalizeInternalAuthorizeUrl(returnTo);
      if (provider === undefined || authorizeUrl === null) {
        await auditUpstreamRefusal(
          request,
          provider === undefined ? 'upstream_unavailable' : 'request_expired'
        );
        return sendUpstreamErrorPage(request, reply);
      }
      reply.header('Cache-Control', 'no-store');
      const separator = authorizeUrl.includes('?') ? '&' : '?';
      return reply.redirect(
        `${authorizeUrl}${separator}qauth_upstream=${encodeURIComponent(provider.entry.provider)}`,
        302
      );
    }
  );

  app.get(
    '/upstream/:type/start',
    {
      schema: {
        description:
          'Start the upstream provider `type` an authorization request routes to (#639), in the interaction the authorization endpoint started: the waiting page sends the browser to the provider.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        params: z.object({ type: z.string().max(64) }),
        querystring: z.object({ interaction: z.string().max(64) }),
      },
      config,
    },
    async (request, reply) => {
      const receivedAt = Date.now();
      const realm = requestRealm(request);
      const interactionId = request.query.interaction;
      const provider = await catalog.find(realm.id, request.params.type);
      if (provider === undefined) {
        await auditUpstreamRefusal(request, 'upstream_unavailable');
        return sendUpstreamErrorPage(request, reply);
      }
      const engine = enginesOf().of(accountPoliciesOf(fastify, realm).requireVerifiedAccount);
      const mode: UpstreamSignInMode = env.INTERACTION_UI_ENABLED ? 'interaction' : 'pages';
      let started: UpstreamStarted | undefined;
      let wayBack: string | undefined;
      let result: InteractionAnswerResult;
      try {
        // The interaction's first round, which nobody has answered yet: the
        // engine starts the routed provider at once.
        result = await answerInteraction(
          request,
          reply,
          { id: interactionId, revision: 0 },
          async (state) => {
            if (state.purpose !== 'authorization') {
              throw new UpstreamSignInRefusal('transaction_mismatch');
            }
            // A link the request asked for (#670) starts only the provider it
            // named, before the provider proved anyone, in an interaction.
            const link = state.upstreamLink;
            if (
              link !== undefined &&
              (link.state !== 'requested' ||
                link.provider !== provider.method.type ||
                mode !== 'interaction')
            ) {
              throw new UpstreamSignInRefusal('transaction_mismatch');
            }
            const back =
              mode === 'interaction'
                ? ceremonyPageUrlOf(realm, interactionId)
                : authorizeUrlOf(state.request);
            wayBack = back;
            const round = await engine.advance(
              state.signInTransaction,
              null,
              upstreamRoundContext(request, state, {
                receivedAt,
                environment: await roundEnvironment(fastify, realm, state.request.client_id),
                upstreamRoute: provider.entry,
                startUpstream: upstreamStarter(
                  fastify,
                  request,
                  catalog,
                  { interactionId, revision: state.revision + 1, mode, wayBack: back },
                  (start) => {
                    started = start;
                  }
                ),
              })
            );
            // The provider could not start: the engine audited it.
            if (round.kind !== 'upstream') {
              throw new UpstreamSignInRefusal('upstream_unavailable', round.kind === 'step');
            }
            return decisionOf(reply, round, receivedAt);
          }
        );
      } catch (error) {
        if (error instanceof UpstreamSignInRefusal) {
          if (!error.audited) await auditUpstreamRefusal(request, error.reason);
          return sendUpstreamErrorPage(request, reply, wayBack);
        }
        if (error instanceof InteractionExpiredError) {
          await auditUpstreamRefusal(request, 'interaction_expired');
          return sendUpstreamErrorPage(request, reply);
        }
        throw error;
      }
      if (result.kind !== 'step' || started === undefined || wayBack === undefined) {
        // Started already (a reload of the waiting page), or the interaction
        // moved on: the person starts again.
        await auditUpstreamRefusal(request, 'interaction_expired');
        return sendUpstreamErrorPage(request, reply, wayBack);
      }
      return sendUpstreamWaitingPage(reply, started, wayBack);
    }
  );

  const linkPageParams = z.object({ interactionId: z.string().max(64) });
  const choiceParamsSchema = z.object({
    provider: z.object({ name: z.string().min(1).max(64) }),
    create: z.boolean(),
  });

  app.get(
    '/upstream-link/:interactionId',
    {
      schema: {
        description:
          'The `upstream_link` step\'s page (#670): an upstream provider proved an identity no account holds; "I already have an account", which goes on to the sign-in to that account, or a new account when the realm allows one. The form posts to the Interaction API\'s answer endpoint. `Cache-Control: no-store`.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [410],
        params: linkPageParams,
      },
      config,
    },
    async (request, reply) => {
      const id = request.params.interactionId;
      const realm = requestRealm(request);
      try {
        if (!isInteractionId(id)) throw new InteractionExpiredError();
        const view = await readInteractionStep(request, id);
        if (view.step.name !== UPSTREAM_LINK_STEP) {
          reply.header('Cache-Control', 'no-store');
          return reply.redirect(buildRealmUrl(realm, ceremonyPagePath(id)), 303);
        }
        const params = choiceParamsSchema.parse(view.step.params);
        return sendUpstreamPage(
          reply,
          upstreamLinkChoicePage({
            cspNonce: reply.cspNonce.style,
            providerName: params.provider.name,
            create: params.create,
            action: buildRealmUrl(realm, `/interaction/v1-rc.0/${id}/answer`),
            type: UPSTREAM_LINK_STEP,
            csrf: view.csrf,
          })
        );
      } catch (error) {
        if (!(error instanceof InteractionExpiredError)) throw error;
        return sendUpstreamPage(
          reply,
          recoveryPageExpired({ cspNonce: reply.cspNonce.style }),
          410
        );
      }
    }
  );

  app.get(
    '/upstream-link-refused',
    {
      schema: {
        description:
          'The page of an upstream link the finish refused (#670): the identity is already linked to another account, the account already has one of the provider, or the account cannot be linked. Nothing was changed, and nothing goes to the client. `Cache-Control: no-store`.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        querystring: z.object({
          provider: z.string().max(64),
          reason: z.enum(['already_linked', 'provider_linked', 'account_unavailable']),
        }),
      },
      config,
    },
    async (request, reply) => {
      const provider = await catalog.find(requestRealm(request).id, request.query.provider);
      return sendUpstreamLinkRefusedPage(
        reply,
        request.query.reason,
        provider?.entry.name ?? 'sign-in provider'
      );
    }
  );
}
