import { NotFoundError } from '@qauth-labs/shared-errors';
import { SECURITY_EFFECTS } from '@qauth-labs/shared-validation';
import type { FastifyRequest } from 'fastify';

import type {
  AdminOperation,
  AdminOperationDefinition,
  Classification,
} from '../../helpers/admin-operations';
import type { PermissionRegistry } from '../../helpers/admin-permissions';
import { approvalStanding, approvalVersion, callerAccount } from './standing';

/**
 * THE APPROVAL ENGINE'S OWN OPERATIONS (ADR-019 Decision 7, issue #512).
 *
 * - `approvals.create` files an approval for one request of a security
 *   operation, and `approvals.cancel` withdraws one. Each takes the
 *   classification of the operation the approval is for (a dynamic
 *   `classify`): whoever files or withdraws an approval needs every
 *   permission that operation declares, and `qauth:admin:security`. Their
 *   declaration is the strictest any approval can need, every effect and
 *   every permission of the catalog, which a request gets when the operation
 *   it names is unknown or is not a security operation.
 * - `approvals.get` reads one, with `approvals.read`. Only its requester, an
 *   account that approved it and one that may still approve it read it;
 *   anyone else gets 404.
 *
 * Approving happens through the factor (`approvals.approve`, `./engine.ts`),
 * on the approval page, never through an admin route.
 *
 * Filing and withdrawing are security operations by their classification, so
 * the approval gate lets these two through by identity
 * ({@link isApprovalEngineOperation}): an approval is not needed to ask for
 * one.
 */

/** The ids of the engine's operations. */
export const APPROVAL_OPERATION_IDS = Object.freeze({
  create: 'approvals.create',
  get: 'approvals.get',
  cancel: 'approvals.cancel',
} as const);

/** Marks the `classify` functions the engine made, across module copies. */
const ENGINE_CLASSIFY = Symbol.for('qauth.adminApprovals.engineClassify');

const ENGINE_IDS: ReadonlySet<string> = new Set([
  APPROVAL_OPERATION_IDS.create,
  APPROVAL_OPERATION_IDS.cancel,
]);

/** `classify`, marked as the engine's own. */
function engineClassify<T extends object>(classify: T): T {
  Object.defineProperty(classify, ENGINE_CLASSIFY, { value: true });
  return classify;
}

/**
 * Whether `operation` is `approvals.create` or `approvals.cancel` as the
 * engine defines them: its id and its `classify` both. The approval gate lets
 * these through, and no renderer is asked of them.
 */
export function isApprovalEngineOperation(operation: AdminOperation | undefined): boolean {
  const classify = operation?.classify as (object & { [ENGINE_CLASSIFY]?: unknown }) | undefined;
  return (
    operation !== undefined &&
    ENGINE_IDS.has(operation.id) &&
    classify !== undefined &&
    classify[ENGINE_CLASSIFY] === true
  );
}

/**
 * The classification of the operation `id` names: its declaration, which
 * holds for every request of it.
 *
 * @throws {Error} when `id` names no security operation of the registry, or
 *   one of the engine's own: the request then fails closed
 */
function declarationOf(
  lookup: (id: string) => AdminOperation | undefined,
  id: unknown
): Classification {
  const operation = typeof id === 'string' ? lookup(id) : undefined;
  if (
    operation === undefined ||
    operation.class !== 'security' ||
    isApprovalEngineOperation(operation)
  ) {
    throw new Error('the approval names no security operation of this server');
  }
  return {
    class: operation.class,
    effects: [...operation.effects],
    permissions: [...operation.permissions],
  };
}

/** What `approvals.cancel` classifies against: the approval it withdraws. */
interface CancelState {
  readonly operationId: string;
  readonly version: string;
}

/**
 * The approval a cancellation names, for its classification. An approval the
 * caller may not read is answered as one that does not exist: 404 before any
 * permission is checked.
 */
async function loadCancelState(request: FastifyRequest): Promise<CancelState> {
  const caller = request.adminPipeline?.authority;
  if (caller === undefined) {
    throw new Error('approvals.cancel reads its approval only behind the admin pipeline');
  }
  const { approvalId } = request.params as { approvalId: string };
  const approval = await request.server.repositories.adminApprovals.findById(
    caller.targetRealm.id,
    approvalId
  );
  if (
    approval === undefined ||
    !approvalStanding(
      approval,
      callerAccount(caller),
      caller.rolePermissions.has('approvals.approve')
    ).mayRead
  ) {
    throw new NotFoundError('Approval', approvalId);
  }
  return { operationId: approval.operationId, version: approvalVersion(approval) };
}

/**
 * The engine's operations, as definitions for `createOperationRegistry`.
 * `lookup` finds an operation in the registry being built; it is read only
 * when a request is classified.
 */
export function approvalOperationDefinitions(
  permissions: PermissionRegistry,
  lookup: (id: string) => AdminOperation | undefined
): AdminOperationDefinition[] {
  const every = {
    class: 'security' as const,
    effects: [...SECURITY_EFFECTS],
    permissions: permissions.active.map((permission) => permission.id),
  };
  return [
    {
      id: APPROVAL_OPERATION_IDS.create,
      ...every,
      description:
        'File an approval request for one request of a security operation: it needs what that operation needs.',
      classify: engineClassify((request: { readonly body: unknown }) =>
        declarationOf(lookup, (request.body as { operation?: unknown } | null)?.operation)
      ),
    },
    {
      id: APPROVAL_OPERATION_IDS.get,
      class: 'read',
      effects: [],
      permissions: ['approvals.read'],
      description:
        'Read an approval request: its requester, an approver of it, or an admin who may approve it.',
    },
    {
      id: APPROVAL_OPERATION_IDS.cancel,
      ...every,
      description:
        'Withdraw an approval request the caller filed: it needs what the operation it is for needs.',
      loadState: loadCancelState,
      stateVersion: (state: unknown) => (state as CancelState).version,
      classify: engineClassify((_request: unknown, state: unknown) =>
        declarationOf(lookup, (state as CancelState).operationId)
      ),
    } as AdminOperationDefinition,
  ];
}
