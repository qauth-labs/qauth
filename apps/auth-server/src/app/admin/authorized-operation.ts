/**
 * The capability of an approved security operation (ADR-019 Decision 7,
 * issue #523).
 *
 * Some writes may happen only inside an admin operation that a second factor
 * approved: minting an act-chain token for an admin who acts for a user is
 * one (`mintActChainToken`). Such a write takes an {@link AuthorizedOperation}
 * as its first argument, and only the admin pipeline creates one: in the
 * handler's transaction, right after it consumed the approval of a security
 * operation whose classification names the write's effect. So the write
 * cannot be reached from a route, a job or a script that did not go through
 * the pipeline, its authority stage and its approval gate.
 *
 * - **Not forgeable.** The type carries a brand no other module can name, so
 *   an object literal is not one (a type test holds it), and the write checks
 *   at run time that the object is one the pipeline issued: a cast or a copy
 *   is refused.
 * - **Bound to its call.** It holds the call's transaction, caller, approval
 *   and approved request, and the write reads them from it, never from its
 *   own arguments.
 * - **Short-lived and single-use.** It works only while the handler that it
 *   was issued for runs, and for one write: the pipeline retires it when the
 *   handler returns or throws, and the write spends it.
 *
 * Only `admin/pipeline.ts` calls {@link issueAuthorizedOperation} and
 * {@link retireAuthorizedOperation}; a test holds that no other module of
 * the server names them.
 */
import type { SecurityEffect } from '@qauth-labs/shared-validation';
import type { FastifyRequest } from 'fastify';

import type { AdminCaller, AdminTransaction } from './pipeline';

/** The brand of an {@link AuthorizedOperation}: a key no other module can name. */
declare const authorizedOperationBrand: unique symbol;

/**
 * An approved security operation, while its handler runs: the first argument
 * of a write that only such an operation may make. Only the admin pipeline
 * creates one; see this module.
 */
export interface AuthorizedOperation {
  readonly [authorizedOperationBrand]: true;
  /** The admin operation, such as `users.actChainTokens.create`. */
  readonly operationId: string;
  /** The security effects its classification names. */
  readonly effects: readonly SecurityEffect[];
  /** The permissions of the admin catalog it needed, all of them. */
  readonly permissions: readonly string[];
  /** The approval it consumed, in the target realm. */
  readonly approvalId: string;
}

/** The admin token the operation was called with: who the admin is, and its key. */
export interface AuthorizedAdminToken {
  /** The token's `iss`: the issuer of the admin's realm. */
  readonly issuer: string;
  /** The token's `client_id`: the client the admin called through. */
  readonly clientId: string;
  /** The token's `cnf.jkt`: the DPoP key the admin holds. */
  readonly jkt: string;
}

/** What the pipeline hands over when it issues an {@link AuthorizedOperation}. */
export interface AuthorizedOperationGrant {
  readonly request: FastifyRequest;
  readonly transaction: AdminTransaction;
  readonly caller: AdminCaller;
  readonly operationId: string;
  readonly effects: readonly SecurityEffect[];
  readonly permissions: readonly string[];
  readonly approvalId: string;
  readonly adminToken: AuthorizedAdminToken;
  /** The approved request's path parameters, as validated. */
  readonly params: unknown;
  /** The approved request's body, as validated. */
  readonly body: unknown;
}

/** What a write reads of the operation it spends. */
export interface AuthorizedOperationContext {
  readonly request: FastifyRequest;
  readonly transaction: AdminTransaction;
  readonly caller: AdminCaller;
  readonly operationId: string;
  readonly effects: readonly SecurityEffect[];
  readonly permissions: readonly string[];
  readonly approvalId: string;
  readonly adminToken: AuthorizedAdminToken;
  /** The approved request's path parameters, a frozen copy. */
  readonly params: Readonly<Record<string, unknown>>;
  /** The approved request's body, a frozen copy. */
  readonly body: unknown;
}

interface IssuedOperation {
  readonly context: AuthorizedOperationContext;
  /** Until the pipeline retires it: while its handler runs. */
  live: boolean;
  /** Whether a write spent it. */
  spent: boolean;
}

/** The operations the pipeline issued, by the object it handed to the handler. */
const issued = new WeakMap<object, IssuedOperation>();

/** The refusal of a capability that is not, or no longer, one the pipeline issued. */
export class AuthorizedOperationRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthorizedOperationRefusedError';
  }
}

/** A deep copy of `value`, frozen: what the write reads cannot change under it. */
function frozenCopy<T>(value: T): T {
  if (value === undefined) return value;
  const copy = structuredClone(value);
  const freeze = (inner: unknown): void => {
    if (typeof inner !== 'object' || inner === null || Object.isFrozen(inner)) return;
    // A typed array's elements cannot be frozen; its copy is the handler's own.
    if (ArrayBuffer.isView(inner)) return;
    Object.freeze(inner);
    for (const member of Object.values(inner)) freeze(member);
  };
  freeze(copy);
  return copy;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Issue the capability of the security operation `grant` describes. Only the
 * admin pipeline calls it, in the handler's transaction, after it consumed the
 * operation's approval.
 *
 * @throws {Error} for a grant with no approval, no effect or no admin key
 */
export function issueAuthorizedOperation(grant: AuthorizedOperationGrant): AuthorizedOperation {
  if (grant.approvalId.length === 0 || grant.effects.length === 0) {
    throw new Error('Only an approved security operation is issued a capability');
  }
  const { issuer, clientId, jkt } = grant.adminToken;
  if (issuer.length === 0 || clientId.length === 0 || jkt.length === 0) {
    throw new Error('A capability is issued for a DPoP-bound admin token naming its client');
  }
  const effects = Object.freeze([...grant.effects]);
  const permissions = Object.freeze([...grant.permissions]);
  const operation = Object.freeze({
    operationId: grant.operationId,
    effects,
    permissions,
    approvalId: grant.approvalId,
  }) as unknown as AuthorizedOperation;
  const params = frozenCopy(grant.params);
  issued.set(operation, {
    context: Object.freeze({
      request: grant.request,
      transaction: grant.transaction,
      caller: grant.caller,
      operationId: grant.operationId,
      effects,
      permissions,
      approvalId: grant.approvalId,
      adminToken: Object.freeze({ issuer, clientId, jkt }),
      params: isPlainRecord(params) ? params : Object.freeze({}),
      body: frozenCopy(grant.body),
    }),
    live: true,
    spent: false,
  });
  return operation;
}

/** End the capability's life: its handler returned or threw. Only the admin pipeline calls it. */
export function retireAuthorizedOperation(operation: AuthorizedOperation): void {
  const entry = issued.get(operation);
  if (entry !== undefined) entry.live = false;
}

/**
 * Spend `operation` for a write that needs `effect`, and answer what the
 * write reads of it. The write calls this first, before it reads or writes
 * anything.
 *
 * @throws {AuthorizedOperationRefusedError} for an object the pipeline did not
 *   issue, one retired or already spent, and one whose operation does not name
 *   `effect`
 */
export function spendAuthorizedOperation(
  operation: AuthorizedOperation,
  effect: SecurityEffect
): AuthorizedOperationContext {
  const entry =
    typeof operation === 'object' && operation !== null ? issued.get(operation) : undefined;
  if (entry === undefined) {
    throw new AuthorizedOperationRefusedError(
      'Not an approved operation: only the admin pipeline issues one'
    );
  }
  if (!entry.live) {
    throw new AuthorizedOperationRefusedError(
      'The approved operation is over: its capability works only while its handler runs'
    );
  }
  if (entry.spent) {
    throw new AuthorizedOperationRefusedError('The approved operation has made its one write');
  }
  if (!entry.context.effects.includes(effect)) {
    throw new AuthorizedOperationRefusedError(
      `The approved operation's classification names no '${effect}' effect`
    );
  }
  entry.spent = true;
  return entry.context;
}
