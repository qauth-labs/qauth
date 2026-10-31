import type { AdminApproval } from '@qauth-labs/fastify-plugin-db';
import {
  BadRequestError,
  ForbiddenError,
  NotFoundError,
  PreconditionFailedError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import {
  type AdminOperation,
  OPERATION_ID_PATTERN,
  operationSchemaExtensions,
} from '../../helpers/admin-operations';
import { ApprovalStateError } from '../../helpers/approval-required';
import { requestClassification } from '../../plugins/admin-operations';
import {
  type AdminCaller,
  type AdminChange,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
  type RouteSchemaPart,
} from '../pipeline';
import {
  canonicalRequest,
  CanonicalRequestError,
  newApprovalNonce,
  opHashOf,
  requestHashOf,
} from './canonical-request';
import { renderOperation } from './display';
import {
  APPROVAL_LIFETIME_MS,
  approvalResource,
  approvalsRequiredFor,
  approvalUrlOf,
} from './engine';
import { APPROVAL_OPERATION_IDS, isApprovalEngineOperation } from './operations';
import { approvalStanding, approvalVersion, callerAccount, parseApprovalVersion } from './standing';

/**
 * THE APPROVAL ROUTES OF THE ADMIN API (ADR-019 Decision 7, issue #512).
 *
 * - `POST /admin/v1-rc.0/realms/{realmId}/approvals` files an approval for
 *   one request of a security operation (`approvals.create`).
 * - `GET  …/approvals/{approvalId}` reads one (`approvals.get`).
 * - `POST …/approvals/{approvalId}/cancel` withdraws one
 *   (`approvals.cancel`), with `If-Match` naming the version its `ETag` gave.
 *
 * They sit behind the admin pipeline like every admin route, so each call is
 * authorized, runs in one transaction and writes its audit row. An approval
 * the caller may not read answers 404, exactly as an unknown one. Approving
 * is not here: it happens through the factor on the approval page
 * (`./engine.ts`).
 */

const APPROVALS_PATH = '/admin/v1-rc.0/realms/:realmId/approvals';

const realmParams = z.object({ realmId: z.uuid() });
const approvalParams = z.object({ realmId: z.uuid(), approvalId: z.uuid() });

/** A path parameter or a query value, as HTTP carries it: text. */
const textValue = z.string().max(2048);

const createBody = z
  .strictObject({
    operation: z
      .string()
      .max(128)
      .regex(OPERATION_ID_PATTERN)
      .meta({ description: 'The id of the security operation the approval is for.' }),
    params: z.record(z.string().max(128), textValue).optional().meta({
      description:
        "The operation's path parameters but `realmId`, which is the realm of the approval's path.",
    }),
    query: z
      .record(z.string().max(128), z.union([textValue, z.array(textValue).max(32)]))
      .optional()
      .meta({ description: "The operation's query, as its URL carries it." }),
    body: z.unknown().optional().meta({ description: "The operation's body, as it will be sent." }),
    reason: z.string().min(1).max(500).optional().meta({
      description:
        'Why the requester asks. An approver sees it as quoted text, never as the operation.',
    }),
  })
  .meta({ description: 'The request of a security operation an approval is filed for.' });

const isoTime = z.iso.datetime();

const approvalSchema = z
  .object({
    id: z.uuid(),
    realmId: z.uuid(),
    status: z.enum(['pending', 'approved', 'denied', 'cancelled', 'consumed', 'expired']),
    operation: z.string(),
    method: z.string(),
    params: z.record(z.string(), z.unknown()),
    query: z.record(z.string(), z.unknown()),
    reason: z.string().nullable(),
    requester: z.object({
      kind: z.enum(['human', 'service_account']),
      realmId: z.uuid(),
      accountId: z.uuid(),
    }),
    approvalsRequired: z.int().min(1).max(2),
    approvals: z.array(
      z.object({
        realmId: z.uuid(),
        accountId: z.uuid(),
        credential: z.string(),
        factor: z.string(),
        approvedAt: isoTime,
      })
    ),
    createdAt: isoTime,
    expiresAt: isoTime,
    usedAt: isoTime.nullable(),
    approvalUrl: z.url().meta({ description: "The approval page, on the requester's realm." }),
    display: z
      .object({
        operation: z.string(),
        title: z.string(),
        fields: z.array(
          z.object({ label: z.string(), value: z.string(), before: z.string().optional() })
        ),
        reason: z
          .object({ type: z.literal('quote'), source: z.literal('requester'), text: z.string() })
          .nullable(),
      })
      .meta({
        description:
          'The operation as an approver sees it, rendered from the stored request: typed display data, never HTML.',
      }),
  })
  .meta({ description: 'An approval request for one request of a security operation.' });

/** The audit diff of an approval: what was filed, never the body it was filed with. */
function approvalSummary(approval: AdminApproval): NonNullable<AdminChange['change']['after']> {
  const stored = approval.canonicalRequest;
  return {
    id: approval.id,
    operation: approval.operationId,
    method: String(stored['method']),
    params: (stored['params'] ?? {}) as Record<string, string>,
    query: (stored['query'] ?? {}) as Record<string, string>,
    reason: approval.reason,
    status: approval.status,
    approvalsRequired: approval.approvalsRequired,
    expiresAt: approval.expiresAt,
  };
}

/** `value` as the route's schema part parses it, or a refusal naming the part. */
function parsedPart(part: RouteSchemaPart | undefined, value: unknown, name: string): unknown {
  if (part === undefined) return value;
  const parsed = part.safeParse(value);
  if (!parsed.success) {
    throw new BadRequestError(`The ${name} of the operation do not pass its route's validation`);
  }
  return parsed.data;
}

/** The URL of the approval page, from the row of the realm the requester lives in. */
async function approvalUrlFor(
  request: FastifyRequest,
  caller: AdminCaller,
  approval: AdminApproval
): Promise<string> {
  const realm =
    approval.requesterRealmId === caller.issuerRealm.id
      ? caller.issuerRealm
      : await request.server.repositories.realms.findById(
          approval.requesterRealmId,
          adminTransaction(request)
        );
  if (realm === undefined) throw new Error("The approval's requester realm is gone");
  return approvalUrlOf(realm, approval.id);
}

/** The approval of the path, in the caller's realm, or 404 when the caller may not read it. */
async function readableApproval(
  request: FastifyRequest,
  caller: AdminCaller,
  approvalId: string
): Promise<{ approval: AdminApproval; isRequester: boolean }> {
  const approval = await request.server.repositories.adminApprovals.findById(
    caller.targetRealm.id,
    approvalId,
    adminTransaction(request)
  );
  const standing =
    approval &&
    approvalStanding(
      approval,
      callerAccount(caller),
      caller.rolePermissions.has('approvals.approve')
    );
  if (approval === undefined || !standing?.mayRead) {
    throw new NotFoundError('Approval', approvalId);
  }
  return { approval, isRequester: standing.isRequester };
}

/** The engine's operations in the pipeline's registry. */
function engineOperations(fastify: FastifyInstance): {
  create: AdminOperation;
  get: AdminOperation;
  cancel: AdminOperation;
} {
  const { registry } = fastify.adminApi;
  const create = registry.get(APPROVAL_OPERATION_IDS.create);
  const get = registry.get(APPROVAL_OPERATION_IDS.get);
  const cancel = registry.get(APPROVAL_OPERATION_IDS.cancel);
  if (
    !isApprovalEngineOperation(create) ||
    get === undefined ||
    !isApprovalEngineOperation(cancel) ||
    create === undefined ||
    cancel === undefined
  ) {
    throw new Error(
      'The admin operation registry holds no approval operations: build it with createAdminOperationRegistry'
    );
  }
  return { create, get, cancel };
}

/** Register the approval routes behind the admin pipeline. */
export const approvalRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const { registry } = fastify.adminApi;
  const operations = engineOperations(fastify);
  const common = {
    'x-qauth-stability': 'experimental' as const,
    security: [{ bearerAuth: [] }],
  };

  typed.post(
    APPROVALS_PATH,
    {
      config: { operation: operations.create.id },
      schema: {
        ...operationSchemaExtensions(operations.create),
        ...common,
        summary: 'File an approval for one request of a security operation',
        'x-qauth-errors': [400, 401, 403, 404],
        params: realmParams,
        body: createBody,
        response: { 201: approvalSchema },
      },
    },
    async (request, reply) => {
      const caller = requestAdminCaller(request);
      const { operation: operationId, params = {}, query = {}, body, reason } = request.body;
      const operation = registry.get(operationId);
      if (
        operation === undefined ||
        operation.class !== 'security' ||
        isApprovalEngineOperation(operation)
      ) {
        throw new BadRequestError('The approval names no security operation of this server');
      }
      const route = fastify.adminApi.routeOf(operation.id);
      if (route === undefined) {
        throw new BadRequestError('No route of this listener performs the operation');
      }
      if (Object.hasOwn(params, 'realmId')) {
        throw new BadRequestError(
          "The operation's realm is the realm of the approval's path: params do not name it"
        );
      }
      const realmId = caller.targetRealm.id;

      let canonical;
      try {
        canonical = canonicalRequest({
          operationId: operation.id,
          method: route.method,
          params: parsedPart(route.params, { ...params, realmId }, 'path parameters'),
          query: parsedPart(route.querystring, query, 'query'),
          body: parsedPart(route.body, body, 'body'),
          realmId,
          requester: callerAccount(caller),
        });
      } catch (error) {
        if (error instanceof CanonicalRequestError) throw new BadRequestError(error.message);
        throw error;
      }

      const nonce = newApprovalNonce();
      const now = Date.now();
      const approval = await request.server.repositories.adminApprovals.create(
        {
          realmId,
          requesterKind: 'human',
          requesterRealmId: caller.issuerRealm.id,
          requesterId: caller.userId,
          operationId: operation.id,
          canonicalRequest: { ...canonical },
          requestHash: requestHashOf(canonical),
          opHash: opHashOf(canonical, nonce),
          nonce,
          reason: reason ?? null,
          classification: {
            class: operation.class,
            effects: [...operation.effects],
            permissions: [...operation.permissions],
          },
          approvalsRequired: approvalsRequiredFor(),
          createdAt: now,
          expiresAt: now + APPROVAL_LIFETIME_MS,
        },
        adminTransaction(request)
      );
      // Rendered before the commit: an operation whose renderer fails on this
      // request files nothing an approver could not be shown.
      const display = renderOperation(approval, registry);
      recordAdminChange(request, {
        change: { before: null, after: approvalSummary(approval) },
        annotations: {},
      });
      reply
        .code(201)
        .header('etag', `"${approvalVersion(approval)}"`)
        .header('location', `/admin/v1-rc.0/realms/${realmId}/approvals/${approval.id}`);
      return approvalResource(approval, {
        now,
        approvalUrl: approvalUrlOf(caller.issuerRealm, approval.id),
        display,
      });
    }
  );

  typed.get(
    `${APPROVALS_PATH}/:approvalId`,
    {
      config: { operation: operations.get.id },
      schema: {
        ...operationSchemaExtensions(operations.get),
        ...common,
        summary: 'Read an approval request',
        'x-qauth-errors': [400, 401, 403, 404],
        params: approvalParams,
        response: { 200: approvalSchema },
      },
    },
    async (request, reply) => {
      const caller = requestAdminCaller(request);
      const { approval } = await readableApproval(request, caller, request.params.approvalId);
      reply.header('etag', `"${approvalVersion(approval)}"`);
      return approvalResource(approval, {
        now: Date.now(),
        approvalUrl: await approvalUrlFor(request, caller, approval),
        display: renderOperation(approval, registry),
      });
    }
  );

  typed.post(
    `${APPROVALS_PATH}/:approvalId/cancel`,
    {
      config: { operation: operations.cancel.id },
      schema: {
        ...operationSchemaExtensions(operations.cancel),
        ...common,
        summary: 'Withdraw an approval request the caller filed',
        'x-qauth-errors': [400, 401, 403, 404, 409, 412, 428],
        params: approvalParams,
        headers: z.looseObject({
          'if-match': z.string().meta({
            description: "The approval's version, as its ETag gave it.",
          }),
        }),
        response: { 200: approvalSchema },
      },
    },
    async (request, reply) => {
      const caller = requestAdminCaller(request);
      const version = requestClassification(request).stateVersion ?? '';
      const expected = parseApprovalVersion(version);
      if (expected === undefined) {
        throw new Error('approvals.cancel was classified against no version of its approval');
      }
      const { approval, isRequester } = await readableApproval(
        request,
        caller,
        request.params.approvalId
      );
      if (!isRequester) {
        throw new ForbiddenError(
          'Only its requester withdraws an approval request; an approver declines it on the approval page'
        );
      }
      const now = Date.now();
      const cancelled = await request.server.repositories.adminApprovals.cancel(
        approval.realmId,
        approval.id,
        {
          requesterRealmId: caller.issuerRealm.id,
          requesterId: caller.userId,
          expected,
          now,
        },
        adminTransaction(request)
      );
      if (cancelled === undefined) {
        // The write is conditional on the version the classification read.
        if (approvalVersion(approval) !== version) {
          throw new PreconditionFailedError({ operation: operations.cancel.id });
        }
        throw new ApprovalStateError();
      }
      recordAdminChange(request, {
        change: { before: approvalSummary(approval), after: approvalSummary(cancelled) },
        annotations: {},
      });
      reply.header('etag', `"${approvalVersion(cancelled)}"`);
      return approvalResource(cancelled, {
        now,
        approvalUrl: await approvalUrlFor(request, caller, cancelled),
        display: renderOperation(cancelled, registry),
      });
    }
  );
};
