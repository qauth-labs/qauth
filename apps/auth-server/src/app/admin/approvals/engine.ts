import type { AdminApproval, AdminApprovalEntry } from '@qauth-labs/fastify-plugin-db';
import { ForbiddenError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import { resolveAdminAuthority } from '../../helpers/admin-authority';
import { OPERATION_REGISTRY, type OperationRegistry } from '../../helpers/admin-operations';
import { ADMIN_SCOPE_LIST } from '../../helpers/admin-scopes';
import { ApprovalStateError } from '../../helpers/approval-required';
import { buildRealmUrl, type RealmUrlSource } from '../../helpers/realm-url';
import { type DisplayField, type OperationDisplay, renderOperation } from './display';
import {
  type ApprovalChallenge,
  type ApprovalFactor,
  ApprovalFactorError,
  type ApprovalForFactor,
  type Approver,
} from './factor';
import { approvalStanding, shownStatus } from './standing';

/**
 * THE APPROVAL ENGINE (ADR-019 Decision 7, ADR-014 §14, issue #512).
 *
 * A security operation runs only with a fresh approval bound to that exact
 * operation. The flow:
 *
 * 1. The client calls the operation without an approval and gets
 *    `approval_required` (the admin pipeline's gate).
 * 2. It files an approval with the same operation, path parameters, query
 *    and body, and an optional reason (`approvals.create`, `./routes.ts`).
 *    The answer carries `approvalUrl`, the approval page, built from the
 *    requester's realm row.
 * 3. An approver confirms on that page with the factor
 *    ({@link startApproval}, {@link completeApproval}), or declines
 *    ({@link denyApproval}). The Interaction API step of the approval page
 *    (#617) and the passkey factor (#623) call these.
 * 4. The client reads the approval, then repeats the original call with
 *    `QAuth-Approval: <approvalId>`.
 * 5. The pipeline checks the approval, and consumes it in the transaction of
 *    the operation: the retry runs with the requester's own authorization of
 *    that moment, and a rolled-back operation leaves the approval approved
 *    until it expires.
 *
 * Every state change writes the admin audit log of the approval's realm:
 * filed and cancelled by the pipeline's rows of `approvals.create` and
 * `approvals.cancel`, approved and declined here (`approvals.approve`,
 * `approvals.deny`), consumed by the operation's own row, which lists the
 * approvals it ran on and the approval's `op_hash` as its request digest.
 */

/** How long an approval counts after it is filed, used or not. A constant, not a setting. */
export const APPROVAL_LIFETIME_MS = 5 * 60 * 1000;

/**
 * The path of the approval page on the auth server:
 * `/approvals/{realmId}/{approvalId}` under the issuer of the requester's
 * realm, `realmId` being the realm the approval acts on. A link to the auth
 * server, not to `/ui/*` (ADR-019 Decision 6): opening it starts the
 * interaction of the approval step, which #617 serves.
 *
 * The page finds the approval in the realm the URL names, as every read of an
 * approval does: an operator-realm admin's approval for a tenant realm lives
 * in the tenant realm, not in the realm whose issuer serves the page.
 */
export const APPROVAL_PAGE_PATH_PREFIX = '/approvals/';

/**
 * The approval page of `approval`, on the realm the requester's account
 * lives in, where the requester's own step-up is given. Built from the realm
 * row (ADR-019 Decision 1), never from the request.
 */
export function approvalUrlOf(
  requesterRealm: RealmUrlSource,
  approval: Pick<AdminApproval, 'realmId' | 'id'>
): string {
  return buildRealmUrl(
    requesterRealm,
    `${APPROVAL_PAGE_PATH_PREFIX}${approval.realmId}/${approval.id}`
  );
}

/**
 * How many approvals one request of an operation needs: one, the
 * requester's own fresh step-up, or a human admin's in a service account's
 * place. The two-admin rule (#521) raises it to two where the realm makes a
 * second admin mandatory.
 */
export function approvalsRequiredFor(): number {
  return 1;
}

/**
 * The display data of `approval` while it is open, rendered from the stored
 * request (`renderOperation`); `null` once it is used, cancelled, denied or
 * expired: no approver is shown it any more, and its body may be gone.
 */
export function openApprovalDisplay(
  approval: AdminApproval,
  registry: OperationRegistry,
  now: number
): OperationDisplay | null {
  const status = shownStatus(approval, now);
  return status === 'pending' || status === 'approved' ? renderOperation(approval, registry) : null;
}

/** What a factor sees of `approval`. */
export function approvalForFactor(approval: AdminApproval): ApprovalForFactor {
  return { id: approval.id, realmId: approval.realmId, opHash: approval.opHash };
}

/** One approval, as the API shows it. */
export interface ApprovalResourceEntry {
  readonly realmId: string;
  readonly accountId: string;
  /** The factor's id of the credential, such as a passkey's. */
  readonly credential: string;
  readonly factor: string;
  readonly approvedAt: string;
}

/** An approval, as the approval routes answer it. The body it was filed with is not in it. */
export interface ApprovalResource {
  readonly id: string;
  readonly realmId: string;
  readonly status: ReturnType<typeof shownStatus>;
  readonly operation: string;
  readonly method: string;
  readonly params: Readonly<Record<string, unknown>>;
  readonly query: Readonly<Record<string, unknown>>;
  readonly reason: string | null;
  readonly requester: {
    readonly kind: AdminApproval['requesterKind'];
    readonly realmId: string;
    readonly accountId: string;
  };
  readonly approvalsRequired: number;
  readonly approvals: ApprovalResourceEntry[];
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly usedAt: string | null;
  readonly approvalUrl: string;
  /**
   * The operation as an approver sees it, while the approval is open
   * (`pending` or `approved`); `null` once it is not, its body dropped.
   */
  readonly display: (Omit<OperationDisplay, 'fields'> & { readonly fields: DisplayField[] }) | null;
}

const isoTime = (epochMs: number) => new Date(epochMs).toISOString();

/** `approval` as the API shows it at `now`. */
export function approvalResource(
  approval: AdminApproval,
  context: {
    readonly now: number;
    readonly approvalUrl: string;
    readonly display: OperationDisplay | null;
  }
): ApprovalResource {
  const stored = approval.canonicalRequest;
  return {
    id: approval.id,
    realmId: approval.realmId,
    status: shownStatus(approval, context.now),
    operation: approval.operationId,
    method: String(stored['method']),
    params: (stored['params'] ?? {}) as Record<string, unknown>,
    query: (stored['query'] ?? {}) as Record<string, unknown>,
    reason: approval.reason,
    requester: {
      kind: approval.requesterKind,
      realmId: approval.requesterRealmId,
      accountId: approval.requesterId,
    },
    approvalsRequired: approval.approvalsRequired,
    approvals: approval.approvals.map((given) => ({
      realmId: given.approverRealmId,
      accountId: given.approverId,
      credential: given.credentialId,
      factor: given.factor,
      approvedAt: isoTime(given.approvedAt),
    })),
    createdAt: isoTime(approval.createdAt),
    expiresAt: isoTime(approval.expiresAt),
    usedAt: approval.usedAt === null ? null : isoTime(approval.usedAt),
    approvalUrl: context.approvalUrl,
    display:
      context.display === null ? null : { ...context.display, fields: [...context.display.fields] },
  };
}

/** The admin audit log's entry, as the repository takes it. */
type AuditEntry = Parameters<
  FastifyInstance['repositories']['adminAuditLog']['appendAdminAudit']
>[1];

/** The transaction an audit row is appended in. */
type AuditTransaction = Parameters<
  FastifyInstance['repositories']['adminAuditLog']['appendAdminAudit']
>[0];

/** One approval, as an admin audit row records it. */
export function auditApproval(
  given: AdminApprovalEntry
): NonNullable<AuditEntry['approvals']>[number] {
  return {
    approverId: given.approverId,
    credentialId: given.credentialId,
    // Who created the approver's account is recorded once admin accounts
    // record their creator (#521, #679).
    approverCreatedBy: null,
    approvedAt: given.approvedAt,
  };
}

/** The audit row of an approver's decision on `approval`. */
function decisionEntry(
  approval: AdminApproval,
  decision: ApprovalDecision,
  operationId: 'approvals.approve' | 'approvals.deny',
  outcome: AuditEntry['outcome'],
  change: { before: AdminApproval; after: AdminApproval } | null,
  given: AdminApprovalEntry | null
): AuditEntry {
  const summary = (state: AdminApproval) => ({
    id: state.id,
    status: state.status,
    approvals: state.approvals.length,
  });
  return {
    realmId: approval.realmId,
    actorKind: 'human_admin',
    actorId: decision.approver.accountId,
    actorRealmId: decision.approver.realmId,
    actChain: null,
    operationId,
    operationClass: 'security',
    effects: [...approval.classification.effects],
    outcome,
    diff:
      change === null
        ? null
        : {
            change: { before: summary(change.before), after: summary(change.after) },
            annotations: {},
          },
    approvals: given === null ? [] : [auditApproval(given)],
    requestDigest: approval.opHash,
    traceId: decision.traceId ?? null,
  };
}

async function appendAudit(
  fastify: FastifyInstance,
  tx: AuditTransaction,
  entry: AuditEntry
): Promise<void> {
  await fastify.repositories.adminAuditLog.appendAdminAudit(tx, entry);
}

/** One approver's decision on one approval, as the approval page hands it over. */
export interface ApprovalDecision {
  /** The realm the approval acts on, as the approval page's URL names it ({@link approvalUrlOf}). */
  readonly realmId: string;
  readonly approvalId: string;
  /** The account signed in on the approval page. */
  readonly approver: Approver;
  /**
   * When the approval page's browser session was issued (its `createdAt`), in
   * epoch milliseconds. A session issued before the approver's account was
   * last disabled decides nothing (#748), as a token issued before it does not.
   */
  readonly sessionIssuedAtMs: number;
  /** The id under which the page's request was logged, for the audit row. */
  readonly traceId?: string;
}

/** Options of the engine's functions. */
export interface ApprovalEngineOptions {
  /** The registry the approval's operation renders from. Defaults to the server's own. */
  readonly registry?: OperationRegistry;
  /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/**
 * What `approver` may do on the realm `targetRealmId`: its grants there,
 * read as the admin API reads a caller's, with every admin scope, since the
 * approval page's factor, not a token, is the fresh step. The page's session,
 * issued at `sessionIssuedAtMs` (epoch ms), stands in for the token's `iat`.
 */
export async function approverAuthority(
  fastify: FastifyInstance,
  approver: Approver,
  targetRealmId: string,
  sessionIssuedAtMs: number
) {
  const realm = await fastify.repositories.realms.findById(approver.realmId);
  if (realm === undefined || !realm.enabled || realm.issuer === null) {
    return { allowed: false as const, refusal: 'issuer_unknown' as const };
  }
  return resolveAdminAuthority(fastify, {
    iss: realm.issuer,
    sub: approver.accountId,
    // In whole seconds, as a token's `iat`: the milliseconds dropped make the
    // session at most one second older, which only refuses one issued within
    // two seconds after the account was enabled again (#748).
    iat: Math.floor(sessionIssuedAtMs / 1000),
    scopes: ADMIN_SCOPE_LIST,
    targetRealmId,
  });
}

/**
 * The approval `decision` names, once the approver may give it an approval
 * now: an approval it may not read is not found; one that is not pending, or
 * has expired, is a conflict; one it may read but not approve (its own
 * request once its step-up is in, an approval it already gave, an admin
 * without `approvals.approve`) is forbidden.
 *
 * With it, the approver as the database names its account. The page may hand
 * over a UUID in upper case, which finds the same account: compared as it
 * came, it would pass for another approver, and the requester could give an
 * approval that needs a different account. Every later step (the standing,
 * the factor's challenge, the stored approval, the audit row) uses this one.
 */
async function approvalTheApproverMayDecide(
  fastify: FastifyInstance,
  decision: ApprovalDecision,
  now: number
): Promise<{ readonly approval: AdminApproval; readonly approver: Approver }> {
  const notFound = () => new NotFoundError('Approval', decision.approvalId);
  const approval = await fastify.repositories.adminApprovals.findById(
    decision.realmId,
    decision.approvalId
  );
  if (approval === undefined) throw notFound();
  const authority = await approverAuthority(
    fastify,
    decision.approver,
    approval.realmId,
    decision.sessionIssuedAtMs
  );
  if (!authority.allowed) throw notFound();
  const approver: Approver = { realmId: authority.issuerRealm.id, accountId: authority.userId };
  const standing = approvalStanding(
    approval,
    { ...approver, kind: 'human' },
    authority.rolePermissions.has('approvals.approve')
  );
  if (!standing.mayRead) throw notFound();
  if (shownStatus(approval, now) !== 'pending') throw new ApprovalStateError();
  if (!standing.mayApprove) {
    throw new ForbiddenError('This account cannot give this approval an approval');
  }
  return { approval, approver };
}

/**
 * Begin an approval on the approval page: the challenge the approver's
 * factor answers, and the operation as the page shows it.
 *
 * @throws as {@link completeApproval} does, before the factor is asked
 */
export async function startApproval(
  fastify: FastifyInstance,
  factor: ApprovalFactor,
  decision: ApprovalDecision,
  options: ApprovalEngineOptions = {}
): Promise<{
  readonly challenge: ApprovalChallenge;
  readonly display: OperationDisplay;
  readonly expiresAt: number;
}> {
  const now = (options.now ?? Date.now)();
  const { approval, approver } = await approvalTheApproverMayDecide(fastify, decision, now);
  const display = renderOperation(approval, options.registry ?? OPERATION_REGISTRY);
  const challenge = await factor.createChallenge(approvalForFactor(approval), approver);
  return { challenge, display, expiresAt: approval.expiresAt };
}

/**
 * Give an approval with the factor: verify the approver's answer to its
 * challenge, then add the approval, in one transaction with its audit row
 * (`approvals.approve`, `succeeded`, naming the credential). The approval is
 * `approved` once it holds every approval it needs. An answer the factor
 * refuses ({@link ApprovalFactorError}) writes a `denied` row and approves
 * nothing. Any other failure of the factor is the server's: it approves
 * nothing either, writes no row, and is thrown as it came.
 *
 * @throws {NotFoundError} when the approver may not read the approval
 * @throws {ApprovalStateError} when it is not pending any more, or has expired
 * @throws {ForbiddenError} when the approver may not give it an approval, or
 *   the factor refused the answer
 */
export async function completeApproval(
  fastify: FastifyInstance,
  factor: ApprovalFactor,
  decision: ApprovalDecision & { readonly response: unknown },
  options: ApprovalEngineOptions = {}
): Promise<AdminApproval> {
  const clock = options.now ?? Date.now;
  const { approval, approver } = await approvalTheApproverMayDecide(fastify, decision, clock());
  const decided = { ...decision, approver };

  let credentialId: string;
  try {
    credentialId = await factor.verify({
      approval: approvalForFactor(approval),
      approver,
      response: decision.response,
    });
  } catch (error) {
    if (!(error instanceof ApprovalFactorError)) throw error;
    fastify.log.warn(
      { err: error, approvalId: approval.id, factor: factor.name },
      'An approval factor refused an answer: nothing was approved'
    );
    try {
      await fastify.db.transaction((tx) =>
        appendAudit(
          fastify,
          tx,
          decisionEntry(approval, decided, 'approvals.approve', 'denied', null, null)
        )
      );
    } catch (auditError) {
      fastify.log.error(
        { err: auditError, approvalId: approval.id },
        'The audit row of a refused approval could not be written'
      );
    }
    throw new ForbiddenError('The approval was not given: the factor did not verify the answer');
  }
  if (typeof credentialId !== 'string' || credentialId === '') {
    throw new Error(
      `The approval factor ${factor.name} verified an answer but named no credential`
    );
  }

  const now = clock();
  const given: AdminApprovalEntry = {
    approverRealmId: approver.realmId,
    approverId: approver.accountId,
    credentialId,
    factor: factor.name,
    approvedAt: now,
  };
  return fastify.db.transaction(async (tx) => {
    const updated = await fastify.repositories.adminApprovals.addApproval(
      approval.realmId,
      approval.id,
      { expectedCount: approval.approvals.length, entry: given, now },
      tx
    );
    if (updated === undefined) throw new ApprovalStateError();
    await appendAudit(
      fastify,
      tx,
      decisionEntry(
        updated,
        decided,
        'approvals.approve',
        'succeeded',
        { before: approval, after: updated },
        given
      )
    );
    return updated;
  });
}

/**
 * Decline an approval: it becomes `denied`, for good, in one transaction with
 * its audit row (`approvals.deny`). Whoever may give it an approval now may
 * decline it instead; declining needs no factor, since it only keeps the
 * operation from running.
 *
 * @throws as {@link completeApproval} does, but for the factor
 */
export async function denyApproval(
  fastify: FastifyInstance,
  decision: ApprovalDecision,
  options: ApprovalEngineOptions = {}
): Promise<AdminApproval> {
  const now = (options.now ?? Date.now)();
  const { approval, approver } = await approvalTheApproverMayDecide(fastify, decision, now);
  return fastify.db.transaction(async (tx) => {
    const updated = await fastify.repositories.adminApprovals.deny(
      approval.realmId,
      approval.id,
      { expectedCount: approval.approvals.length, now },
      tx
    );
    if (updated === undefined) throw new ApprovalStateError();
    await appendAudit(
      fastify,
      tx,
      decisionEntry(
        updated,
        { ...decision, approver },
        'approvals.deny',
        'succeeded',
        { before: approval, after: updated },
        null
      )
    );
    return updated;
  });
}
