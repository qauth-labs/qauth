import type { FastifyInstance, FastifyPluginOptions, FastifyRequest, RouteOptions } from 'fastify';
import fp from 'fastify-plugin';

import {
  type AdminOperation,
  classifyRequest,
  OPERATION_REGISTRY,
  type OperationClassification,
  type OperationRegistry,
  operationSchemaExtensions,
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
     * frozen, and neither writable nor configurable once set. `null` on an
     * instance without {@link adminOperationsPlugin}, and before its stage.
     * Read it with {@link requestClassification}.
     */
    adminOperation: OperationClassification | null;
  }
}

/** Options for {@link adminOperationsPlugin}. */
export interface AdminOperationsPluginOptions extends FastifyPluginOptions {
  /** The registry routes name their operations in. Defaults to the server's own. */
  registry?: OperationRegistry;
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

/** A permission member as a sorted list: a single id and a one-item list say the same. */
const asSortedList = (value: unknown): unknown =>
  typeof value === 'string' ? [value] : Array.isArray(value) ? [...value].sort() : value;

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
    const want =
      member === 'x-qauth-permission' ? asSortedList(expected[member]) : expected[member];
    const have = member === 'x-qauth-permission' ? asSortedList(schema[member]) : schema[member];
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
  if (classification === null || classification === undefined) {
    throw new Error('The request has no admin operation classification');
  }
  return classification;
}

/**
 * The classification stage of the admin pipeline (ADR-019 Decision 7, #508),
 * for the admin listener (#511).
 *
 * - AT BOOT, an `onRoute` hook refuses every route that names no registered
 *   operation in `config.operation`, and every route whose schema's
 *   `operationId`, `x-qauth-class`, `x-qauth-permission`, `x-qauth-effects`
 *   or `x-qauth-two-admin` differs from the registry's
 *   (`operationSchemaExtensions`), so the boot fails. `onRoute` is not
 *   retroactive: register this plugin before the routes.
 * - ON EVERY REQUEST, a `preHandler` hook, after validation and before the
 *   handler, reads the operation's current state (`loadState`) and classifies
 *   the request (`classifyRequest`, which fails closed). It sets the result as
 *   `request.adminOperation`, a frozen value on a property that is neither
 *   writable nor configurable, so the handler and every later stage (the
 *   approval gate, the audit row) read one classification and none can lower
 *   it. A request whose route escaped the boot check, or whose property was
 *   already taken, fails and runs nothing. A classification that failed closed
 *   is logged at `warn`, with the operation and the reason only.
 *
 * Scope-level hooks run in registration order, so the listener registers
 * this plugin where the stage belongs: after the token guard, the realm
 * lookup and the caller's authority, before the approval gate. The
 * permission check reads `requestClassification(request).permissions`.
 */
export const adminOperationsPlugin = fp<AdminOperationsPluginOptions>(
  async (fastify: FastifyInstance, options: AdminOperationsPluginOptions) => {
    const registry = options.registry ?? OPERATION_REGISTRY;

    fastify.decorateRequest('adminOperation', null);

    fastify.addHook('onRoute', (route) => {
      const problem = adminRouteProblem(route, registry);
      if (problem !== undefined) throw new Error(problem);
    });

    fastify.addHook('preHandler', async (request: FastifyRequest) => {
      if (request.is404) return;
      const id = request.routeOptions.config?.operation;
      const operation = typeof id === 'string' ? registry.get(id) : undefined;
      if (operation === undefined) {
        // Only a route registered before this plugin gets here; it runs nothing.
        throw new Error(
          `${request.method} ${request.routeOptions.url ?? ''} has no registered admin operation`
        );
      }

      const currentState =
        operation.loadState === undefined ? undefined : await operation.loadState(request);
      const classification = classifyRequest(
        registry,
        operation,
        {
          method: request.method,
          params: request.params,
          query: request.query,
          body: request.body,
        },
        currentState
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
    });
  },
  { name: ADMIN_OPERATIONS_PLUGIN_NAME }
);

export default adminOperationsPlugin;
