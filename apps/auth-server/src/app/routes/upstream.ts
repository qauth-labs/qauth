import {
  authMethodRoutesPlugin,
  completeUpstreamStep,
} from '@qauth-labs/fastify-plugin-federation';
import { BadRequestError } from '@qauth-labs/shared-errors';
import type { FastifyPluginAsync } from 'fastify';

import { authMethodPluginContext, authMethodPluginEnabledIn } from '../helpers/auth-method-plugins';
import { answerRouteNotFound } from '../helpers/request-bounds';
import { requestRealm } from '../helpers/request-realm';

/**
 * THE ROUTES OF AuthMethod PLUGINS (ADR-019 Decision 12, issues #599 and
 * #600): each loaded plugin's routes, under `/upstream/<type>` on the realm
 * host, mounted by `authMethodRoutesPlugin` from the provider registry.
 *
 * A route of a plugin the request's realm has not enabled answers as a path
 * no route serves: the `not_found` problem document, from a `preParsing`
 * hook, before the body is read, so neither its status nor a validation
 * error gives the plugin away. It runs after the request ceiling, so a
 * flood of such requests is limited before it reaches the database.
 *
 * The upstream step that sends a browser to a provider, and keeps its
 * transaction, comes with the upstream sign-in flow (#639). Until then no
 * transaction is ever pending, so every callback ends as
 * `transaction_mismatch` before the method runs, and the host answers it
 * with a 400; a fault of the method (a bounce route that throws) ends as the
 * generic error.
 */

/** The `<type>` segment of a mounted route's path, `/upstream/<type>/...`. */
function routeType(url: string | undefined): string | undefined {
  const match = /^\/upstream\/([^/]+)\//.exec(url ?? '');
  return match?.[1];
}

const upstreamRoutes: FastifyPluginAsync = async (fastify) => {
  // No plugin loaded: no route, and no hook.
  if (fastify.providerRegistry.authMethods().length === 0) return;

  // Checked in `preParsing`, after the request ceiling (a route-level
  // `onRequest` hook) and before the body is read: a flood of requests to an
  // installed plugin's paths meets the rate limit before it reaches the
  // database.
  fastify.addHook('preParsing', async (request, reply, payload) => {
    const type = routeType(request.routeOptions.url);
    const plugin = type === undefined ? undefined : fastify.authMethodPlugins.ofType(type);
    if (
      plugin !== undefined &&
      (await authMethodPluginEnabledIn(fastify, requestRealm(request).id, plugin))
    ) {
      return payload;
    }
    return answerRouteNotFound(request, reply);
  });

  await fastify.register(authMethodRoutesPlugin, {
    host: {
      contextFor: (method, request) => authMethodPluginContext(fastify, request, method),
      // No upstream step is offered before #639, so no transaction is pending.
      peekTransaction: async () => undefined,
      takeTransaction: async () => undefined,
      async complete(method, outcome) {
        // A fault of the method (its bounce or its context failed) ends as
        // every fault does: the generic error and its trace id.
        await completeUpstreamStep(method, outcome);
        throw new BadRequestError('No sign-in through this provider is pending in this browser');
      },
    },
  });
};

export default upstreamRoutes;
