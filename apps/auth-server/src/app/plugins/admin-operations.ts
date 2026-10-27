import { PreconditionFailedError, PreconditionRequiredError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyPluginOptions, FastifyRequest, RouteOptions } from 'fastify';
import fp from 'fastify-plugin';

import {
  type AdminOperation,
  classifyRequest,
  deepFreeze,
  ifMatchAllows,
  OPERATION_REGISTRY,
  type OperationClassification,
  type OperationRegistry,
  operationSchemaExtensions,
  operationStateVersion,
} from '../helpers/admin-operations';

declare module 'fastify' {
  interface FastifyContextConfig {
    /**
     * The admin operation the route performs: its id in the operation
     * registry (#508). Optional in the type, required at boot on every route
     * of an instance that registers {@link adminOperationsPlugin}.
     */
    operation?: string;
  }

  interface FastifyRequest {
    /**
     * What this request needs, as the admin pipeline classified it (#508):
     * frozen, and neither writable nor configurable once set. Absent on an
     * instance without {@link adminOperationsPlugin}, and before its stage.
     * Read it with {@link requestClassification}, which throws rather than
     * give a request without one any default.
     */
    readonly adminOperation?: OperationClassification;
  }
}

/** Options for {@link adminOperationsPlugin}. */
export interface AdminOperationsPluginOptions extends FastifyPluginOptions {
  /** The registry routes name their operations in. Defaults to the server's own. */
  registry?: OperationRegistry;
  /**
   * The authorization stage: refuses, by throwing, a caller that does not
   * hold every permission of `classification` (and its scopes). Required: the
   * stage refuses to load without it, and calls it on every request right
   * after classifying, before any later stage or the handler, so no route of
   * the admin listener runs on a classification nothing checked.
   */
  authorize: (request: FastifyRequest, classification: OperationClassification) => unknown;
}

export const ADMIN_OPERATIONS_PLUGIN_NAME = '@qauth-labs/admin-operations';

/** The schema members a route copies from the registry, in the order they are compared. */
const SCHEMA_MEMBERS = [
  'operationId',
  'x-qauth-class',
  'x-qauth-permission',
  'x-qauth-effects',
  'x-qauth-two-admin',
] as const;

/** A list member as a sorted list: a single id and a one-item list say the same. */
const asSortedList = (value: unknown): unknown =>
  typeof value === 'string' ? [value] : Array.isArray(value) ? [...value].sort() : value;

/** The members compared as sets: their order says nothing. */
const LIST_MEMBERS: ReadonlySet<string> = new Set(['x-qauth-permission', 'x-qauth-effects']);

/** The parts of a request `classify` saw, which no later stage may change. */
const CLASSIFIED_PARTS = ['params', 'query', 'body'] as const;

/** What an empty Fastify instance prints for its routes. */
const NO_ROUTES = '(empty tree)';

/**
 * Why `route` cannot be booted on an admin listener, or `undefined` when it
 * can: it names no registered operation, or its schema says something about
 * the operation that the registry does not.
 */
export function adminRouteProblem(
  route: Pick<RouteOptions, 'method' | 'url' | 'config' | 'schema'>,
  registry: OperationRegistry
): string | undefined {
  const methods = Array.isArray(route.method) ? route.method.join(',') : route.method;
  const where = `${methods} ${route.url}`;
  const id = route.config?.operation;
  if (id === undefined) {
    return `${where} has no admin operation: every route of the admin listener names one in config.operation, registered in helpers/admin-operations.ts (#508)`;
  }
  const operation: AdminOperation | undefined =
    typeof id === 'string' ? registry.get(id) : undefined;
  if (operation === undefined) {
    return `${where} names the admin operation ${JSON.stringify(id)}, which the operation registry does not hold`;
  }
  const expected: Record<string, unknown> = { ...operationSchemaExtensions(operation) };
  const schema = (route.schema ?? {}) as Record<string, unknown>;
  for (const member of SCHEMA_MEMBERS) {
    const want = LIST_MEMBERS.has(member) ? asSortedList(expected[member]) : expected[member];
    const have = LIST_MEMBERS.has(member) ? asSortedList(schema[member]) : schema[member];
    if (JSON.stringify(have) !== JSON.stringify(want)) {
      return `${where}: its schema's ${member} is ${JSON.stringify(schema[member])}, but the registry's ${operation.id} gives ${JSON.stringify(expected[member])}; spread operationSchemaExtensions(operation) into the schema`;
    }
  }
  return undefined;
}

/**
 * The classification of `request`, as the admin pipeline put it there.
 *
 * @throws {Error} when the request has none: the route is not on an admin
 *   listener, or the stage has not run yet. Never a lower default.
 */
export function requestClassification(request: FastifyRequest): OperationClassification {
  const classification = request.adminOperation;
  if (classification === undefined || (classification as unknown) === null) {
    throw new Error('The request has no admin operation classification');
  }
  return classification;
}

/**
 * The classification stage of the admin pipeline (ADR-019 Decision 7, #508),
 * for the admin listener (#511). Register it at the listener's root, before
 * any route: it refuses to load on an instance that already has a route,
 * whose boot check would have been skipped, and its hooks reach only the
 * scope it is registered in and that scope's children.
 *
 * - AT BOOT, an `onRoute` hook refuses every route that names no registered
 *   operation in `config.operation`, and every route whose schema's
 *   `operationId`, `x-qauth-class`, `x-qauth-permission`, `x-qauth-effects`
 *   or `x-qauth-two-admin` differs from the registry's
 *   (`operationSchemaExtensions`), so the boot fails.
 * - ON EVERY REQUEST, a `preHandler` hook, after validation and before the
 *   handler, checks the route again as it was finally built (once per route;
 *   a later `onRoute` hook may have changed it), reads the operation's
 *   current state (`loadState`) and its version (`stateVersion`), answers
 *   428 when such a request has no `If-Match` and 412 when it names another
 *   version, and classifies
 *   the request (`classifyRequest`, which fails closed). The classification
 *   carries the state version, which the handler's write must be conditional
 *   on, and the digest of a binary body, which cannot be frozen. It sets the
 *   result as
 *   `request.adminOperation`, a frozen value on a property that is neither
 *   writable nor configurable, so the handler and every later stage (the
 *   approval gate, the audit row) read one classification and none can lower
 *   it. It then freezes the path parameters, query and body it classified and
 *   makes those properties permanent too, so what runs is what was
 *   classified: a later stage that changes them fails the request. Then it
 *   calls `authorize(request, classification)`; a rejection fails the
 *   request. A request whose route fails the check, whose state or state
 *   version cannot be read, or whose property an earlier stage already took
 *   fails and runs nothing. A classification that failed closed is logged at
 *   `warn`, with the operation and the reason only.
 *
 * Scope-level hooks run in registration order, so the listener registers
 * the earlier stages (the token guard, the realm lookup, the caller's
 * authority) as hooks before this plugin's and the approval gate after them.
 * A request that matches no route is not classified, so a custom not-found
 * handler on the listener must not act.
 */
export const adminOperationsPlugin = fp<AdminOperationsPluginOptions>(
  async (fastify: FastifyInstance, options: AdminOperationsPluginOptions) => {
    const registry = options.registry ?? OPERATION_REGISTRY;
    const authorize: unknown = options.authorize;
    if (typeof authorize !== 'function') {
      throw new Error(
        'The admin operations stage needs authorize(request, classification): no route of the admin listener runs on a classification nothing checked'
      );
    }

    if (fastify.printRoutes() !== NO_ROUTES) {
      throw new Error(
        'The admin operations stage must be registered before any route of the admin listener: a route registered earlier never passes its boot check'
      );
    }

    fastify.decorateRequest('adminOperation', undefined);

    fastify.addHook('onRoute', (route) => {
      const problem = adminRouteProblem(route, registry);
      if (problem !== undefined) throw new Error(problem);
    });

    /** Each route's problem as it was finally built, by its config object, checked once. */
    const checkedRoutes = new WeakMap<object, string | undefined>();

    fastify.addHook('preHandler', async (request: FastifyRequest) => {
      if (request.is404) return;
      const route = request.routeOptions;
      const key = route.config as object;
      if (!checkedRoutes.has(key)) {
        checkedRoutes.set(
          key,
          adminRouteProblem(
            {
              method: route.method,
              url: route.url ?? '',
              config: route.config,
              schema: route.schema,
            },
            registry
          )
        );
      }
      const problem = checkedRoutes.get(key);
      const operation =
        problem === undefined ? registry.get(route.config.operation as string) : undefined;
      if (operation === undefined) {
        throw new Error(problem ?? `${request.method} ${route.url ?? ''} has no admin operation`);
      }

      let currentState: unknown;
      let stateVersion: string | null = null;
      if (operation.loadState !== undefined) {
        // What the request needs depends on the state it meets: it names the
        // version it was written against, or it does not run.
        if (request.headers['if-match'] === undefined) {
          throw new PreconditionRequiredError({ operation: operation.id });
        }
        currentState = await operation.loadState(request);
        stateVersion = operationStateVersion(operation, currentState);
        // The request was written against another version: what it would
        // change, and so its classification, may differ from this state's.
        if (!ifMatchAllows(request.headers['if-match'], stateVersion)) {
          throw new PreconditionFailedError({ operation: operation.id });
        }
      }
      const classification = classifyRequest(
        registry,
        operation,
        {
          method: request.method,
          params: request.params,
          query: request.query,
          body: request.body,
        },
        currentState,
        stateVersion
      );
      if (classification.failedClosed !== null) {
        request.log.warn(
          { operation: operation.id, reason: classification.failedClosed },
          'Admin operation classification failed closed; the request needs the operation as declared'
        );
      }

      // Throws when an earlier stage already made the property permanent:
      // the request then fails rather than run with that value.
      Object.defineProperty(request, 'adminOperation', {
        value: classification,
        enumerable: true,
        writable: false,
        configurable: false,
      });
      for (const part of CLASSIFIED_PARTS) {
        Object.defineProperty(request, part, {
          value: deepFreeze(request[part]),
          enumerable: true,
          writable: false,
          configurable: false,
        });
      }

      await (authorize as AdminOperationsPluginOptions['authorize'])(request, classification);
    });
  },
  { name: ADMIN_OPERATIONS_PLUGIN_NAME }
);

export default adminOperationsPlugin;
