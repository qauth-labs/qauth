import {
  type AuthMethodRouteHost,
  completeUpstreamStep,
  mountAuthMethodRoutes,
} from '@qauth-labs/fastify-plugin-federation';
import { BadRequestError } from '@qauth-labs/shared-errors';
import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

import { authMethodPluginContext, authMethodPluginEnabledIn } from '../helpers/auth-method-plugins';
import { answerRouteNotFound } from '../helpers/request-bounds';
import { requestRealm } from '../helpers/request-realm';

/**
 * THE ROUTES OF AuthMethod PLUGINS (ADR-019 Decision 12, issues #599 and
 * #600): each loaded plugin's routes, under `/upstream/<type>` on the realm
 * host, mounted by `mountAuthMethodRoutes` from the provider registry's
 * method of each installed plugin's type, and no other method's. A built-in
 * AuthMethod, such as a provider of the generic upstream OpenID Connect
 * client, is no plugin: its realm state is not a plugin row, so the gate
 * below would answer 404 for it forever. Provider administration (#714)
 * mounts the built-in AuthMethods with a context of their own when it
 * registers them.
 *
 * A route of a plugin the request's realm has not enabled answers as a path
 * no route serves: the `not_found` problem document, from a `preParsing`
 * hook, before the body is read, without the request ceiling's headers, so
 * neither its status, its body nor a validation error says whether the realm
 * has the plugin on. It runs after the request ceiling, so a flood of such
 * requests is limited before it reaches the database; a flood past the
 * ceiling answers 429 where an unknown path answers 404, which tells that a
 * plugin of that type is installed in the deployment, never which realms
 * have it on.
 *
 * The upstream step that sends a browser to a provider, and keeps its
 * transaction, comes with the upstream sign-in flow (#639). Until then no
 * transaction is ever pending, so every callback ends as
 * `transaction_mismatch` before the method runs, and the host answers it
 * with a 400; a fault of the method (a bounce route that throws) ends as the
 * generic error.
 */

/** The headers the request ceiling sets before a route answers. */
const RATE_LIMIT_HEADERS = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset'];

/** The `<type>` segment of a mounted route's path, `/upstream/<type>/...`. */
function routeType(url: string | undefined): string | undefined {
  const match = /^\/upstream\/([^/]+)\//.exec(url ?? '');
  return match?.[1];
}

const upstreamRoutes: FastifyPluginAsync = async (fastify) => {
  // The registry's method of each installed plugin's type: the snapshot the
  // registry checked. A built-in AuthMethod is mounted with its own context
  // when #714 registers it, never here, behind the plugin gate.
  const methods = fastify.providerRegistry
    .authMethods()
    .filter((method) => fastify.authMethodPlugins.ofType(method.type) !== undefined);
  // No plugin loaded: no route, and no hook.
  if (methods.length === 0) return;

  // Checked in `preParsing`, after the request ceiling (a route-level
  // `onRequest` hook) and before the body is read: a flood of requests to an
  // installed plugin's paths meets the rate limit before it reaches the
  // database.
  const refused = new WeakSet<FastifyRequest>();
  fastify.addHook('preParsing', async (request, reply, payload) => {
    const type = routeType(request.routeOptions.url);
    const plugin = type === undefined ? undefined : fastify.authMethodPlugins.ofType(type);
    if (
      plugin !== undefined &&
      (await authMethodPluginEnabledIn(fastify, requestRealm(request).id, plugin))
    ) {
      return payload;
    }
    refused.add(request);
    // A path no route serves is answered before the limiter, with none of
    // its headers: the answer for an off plugin carries none either.
    for (const header of RATE_LIMIT_HEADERS) reply.removeHeader(header);
    return answerRouteNotFound(request, reply);
  });
  // A request refused above never reaches a handler, even when its client
  // closed the connection before the answer was written.
  fastify.addHook('preHandler', async (request) => {
    if (refused.has(request)) {
      throw new Error(
        'A request to an AuthMethod plugin route the realm has off reached its handler'
      );
    }
  });

  const host: AuthMethodRouteHost = {
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
  };
  for (const method of methods) mountAuthMethodRoutes(fastify, method, host);
};

export default upstreamRoutes;
