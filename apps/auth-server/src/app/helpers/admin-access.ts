/**
 * THE ACCOUNT API AND THE ADMINS WHO ACT FOR ITS USERS (ADR-019 Decision 7,
 * issue #523).
 *
 * An admin who acts for a user holds an act-chain token, minted by an
 * approved security operation of the admin API (`admin/act-chain-tokens.ts`),
 * which wrote the token's `admin_act_sessions` row. The user is not asked:
 * visibility is the control. So the account API:
 *
 * - **Holds the token to its row on every call** ({@link checkAdminActChain}):
 *   the row is there, unexpired, names the token's user, admin and client,
 *   and its approval is still `consumed`; the admin's account is enabled; and
 *   the admin's live grants on the user's realm still hold every permission
 *   the operation that minted it needed. So revoking the grant or the approval
 *   stops the token on its next use, with 401 `invalid_token`.
 * - **Audits every call made with it** ({@link registerAdminActChainAudit}):
 *   one row of the admin audit log, with the full act chain, the operation and
 *   its outcome, refused calls included once the token's row is found. The
 *   row goes in through the functions of migration 0082, which take its actor
 *   and act chain from the token's row: the account API's database user holds
 *   nothing on the log. A call whose row cannot be written gets 503 for an
 *   answer that would have succeeded. A route whose scope has no audit hook
 *   takes no such token.
 * - **Lists them for the user** ({@link listAdminAccess}): who acted for them,
 *   when, and on which approval.
 *
 * Whether an operation takes an act-chain token at all is its own rule
 * (`x-qauth-act-chain`, `account-operation-guard.ts`); the family guard
 * refuses one by default (`family-token.ts`). An act-chain token never counts
 * as the user's fresh sign-in (`requireFreshAuthentication`).
 */
import type { AdminActSession } from '@qauth-labs/fastify-plugin-db';
import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import { JWTInvalidError, TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import type { FamilyOperationClass } from '../api-conventions/families';
import { DelegatedTokenRefusedError } from './account-operation-errors';
import { accountCredentialRefusal } from './account-validity';
import { isAdminActChain } from './admin-act-chain';
import { grantCoversRealm, grantedPermissionIds } from './admin-grant-rules';
import { effectivePermissions } from './admin-roles';
import { ADMIN_SCOPE_LIST } from './admin-scopes';
import { requestRealm } from './request-realm';

/** The decorator of a scope whose replies {@link registerAdminActChainAudit} audits. */
export const ADMIN_ACT_CHAIN_AUDIT_DECORATOR = 'adminActChainAudit';

/** The `Retry-After` of a call whose audit row could not be written. */
export const ADMIN_ACT_CHAIN_AUDIT_RETRY_SECONDS = 5;

/** What the account operation a call reached tells its audit row. */
export interface AdminActChainOperation {
  /** The account operation, such as `account.sessions.list`. */
  readonly operationId: string;
  readonly operationClass: FamilyOperationClass;
}

/** One call made with an admin's act-chain token, admitted by {@link checkAdminActChain}. */
interface AdminActChainCall {
  readonly session: AdminActSession;
  readonly user: string;
  readonly act: { readonly sub: string; readonly iss: string; readonly client_id: string };
  readonly operation: AdminActChainOperation;
  audited: boolean;
}

/** The calls in flight made with an admin's act-chain token, by request. */
const calls = new WeakMap<FastifyRequest, AdminActChainCall>();

/** A request id the audit row can hold: printable ASCII, at most 128 characters. */
const STORABLE_TRACE_ID = /^[\x21-\x7e]{1,128}$/;

/**
 * The trace id of the call's audit row: the request's id, which on the public
 * listener is the caller's `X-Request-Id` when it sends one, or `null` when
 * the column could not hold it. Never a reason for the row to fail.
 */
function traceIdOf(request: FastifyRequest): string | null {
  return STORABLE_TRACE_ID.test(request.id) ? request.id : null;
}

/** The one answer to an act-chain token that is no longer live, whatever the reason. */
function noLongerValid(): JWTInvalidError {
  return new JWTInvalidError('The act-chain token is no longer valid');
}

/** The single actor of an admin's act chain, or `undefined` for any other shape. */
function adminActorOf(
  claims: JWTPayload
): { readonly sub: string; readonly iss: string; readonly client_id: string } | undefined {
  const act: unknown = claims.act;
  if (typeof act !== 'object' || act === null || Array.isArray(act)) return undefined;
  const { sub, iss, client_id: clientId, ...rest } = act as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return undefined;
  if (typeof sub !== 'string' || typeof iss !== 'string' || typeof clientId !== 'string') {
    return undefined;
  }
  return { sub, iss, client_id: clientId };
}

/**
 * Hold an admin's act-chain token to its `admin_act_sessions` row (see this
 * module), and mark the call for its audit row. A token with no `act`, or an
 * agent's, passes untouched: the operation's own rule decides on it.
 *
 * Once the token's row is found, the call is marked whatever comes next, so a
 * call refused because the token expired, its approval or the admin's grant
 * was revoked, or the admin was disabled is audited too, as `denied`.
 *
 * Runs after the family guard verified the token and resolved its subject in
 * the request's realm, and before the operation's rules.
 *
 * @throws {DelegatedTokenRefusedError} on a route whose scope has no audit hook
 * @throws {JWTInvalidError} for a token that is no longer live
 */
export async function checkAdminActChain(
  request: FastifyRequest,
  claims: JWTPayload,
  operation: AdminActChainOperation
): Promise<void> {
  if (!isAdminActChain(claims.act)) return;
  // A route no audit hook covers never takes an admin's token.
  if (!request.server.hasDecorator(ADMIN_ACT_CHAIN_AUDIT_DECORATOR)) {
    throw new DelegatedTokenRefusedError();
  }
  const act = adminActorOf(claims);
  if (act === undefined || typeof claims.jti !== 'string' || typeof claims.sub !== 'string') {
    throw noLongerValid();
  }
  const realm = requestRealm(request);
  const records = request.server.repositories.adminActSessions;
  const live = await records.findLive(realm.id, claims.jti, Date.now());
  const session = live ?? (await records.findByJti(realm.id, claims.jti));
  if (
    session === undefined ||
    session.userId !== claims.sub ||
    session.adminUserId !== act.sub ||
    session.adminClientId !== act.client_id ||
    session.adminClientId !== claims.clientId
  ) {
    throw noLongerValid();
  }
  // From here the call is this token's: audited, whether it is admitted or not.
  calls.set(request, { session, user: claims.sub, act, operation, audited: false });
  if (live === undefined) throw noLongerValid();

  // The admin, as the admin API's authority stage reads one (#510): an
  // enabled account of an enabled realm whose issuer the actor names.
  const adminRealm = await request.server.repositories.realms.findById(session.adminRealmId);
  if (adminRealm === undefined || !adminRealm.enabled || adminRealm.issuer !== act.iss) {
    throw noLongerValid();
  }
  const admin = await request.server.repositories.users.findById(
    adminRealm.id,
    session.adminUserId
  );
  if (admin === undefined || accountCredentialRefusal(admin, session.createdAt) !== null) {
    throw noLongerValid();
  }
  // Every permission the minting operation needed, still held through a live
  // grant on this realm: a revoked grant stops the token here.
  const grants = await request.server.repositories.adminGrants.listLive(adminRealm.id, admin.id);
  const held = effectivePermissions(
    grants
      .filter((grant) => grantCoversRealm(grant, adminRealm, realm.id))
      .flatMap((grant) => grantedPermissionIds(grant)),
    ADMIN_SCOPE_LIST
  );
  if (session.permissionIds.length === 0 || !session.permissionIds.every((id) => held.has(id))) {
    throw noLongerValid();
  }
}

/** The outcome of a call, from its status: as the admin pipeline records one. */
function outcomeOf(statusCode: number): 'succeeded' | 'denied' | 'failed' {
  if (statusCode >= 500) return 'failed';
  return statusCode >= 400 ? 'denied' : 'succeeded';
}

/**
 * Append the audit row of a call made with an admin's act-chain token, once,
 * as its reply is sent.
 *
 * @throws {TemporarilyUnavailableError} when the row of a call that would
 *   succeed cannot be written: its answer is withheld
 */
async function auditAdminActChainCall(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const call = calls.get(request);
  if (call === undefined || call.audited) return;
  call.audited = true;
  const outcome = outcomeOf(reply.statusCode);
  const { session, act, operation } = call;
  try {
    await request.server.db.transaction((tx) =>
      request.server.repositories.adminAuditLog.appendActChainCall(tx, {
        realmId: session.realmId,
        tokenJti: session.tokenJti,
        actorId: session.adminUserId,
        actorRealmId: session.adminRealmId,
        actChain: { sub: call.user, act: { sub: act.sub, iss: act.iss, client_id: act.client_id } },
        operationId: operation.operationId,
        operationClass: operation.operationClass,
        outcome,
        traceId: traceIdOf(request),
      })
    );
  } catch (error) {
    request.log.error(
      { err: error, operation: operation.operationId, session: session.id },
      'the call made with an act-chain token could not be audited'
    );
    if (outcome === 'succeeded') {
      throw new TemporarilyUnavailableError(ADMIN_ACT_CHAIN_AUDIT_RETRY_SECONDS, {
        reason: 'act-chain audit unavailable',
      });
    }
  }
}

/**
 * Audit every call made with an admin's act-chain token in `fastify`'s scope:
 * its routes, and its children's. Register it before the routes. A route
 * outside such a scope takes no admin's token ({@link checkAdminActChain}).
 */
export function registerAdminActChainAudit(fastify: FastifyInstance): void {
  fastify.decorate(ADMIN_ACT_CHAIN_AUDIT_DECORATOR, true);
  fastify.addHook('onSend', async (request, reply, payload) => {
    await auditAdminActChainCall(request, reply);
    return payload;
  });
}

/** One act-chain token an admin was issued to act for the user. */
export interface AdminAccessEntry {
  /** The token's `admin_act_sessions` row. */
  readonly id: string;
  /** The admin's account. */
  readonly adminId: string;
  /** The realm the admin's account lives in. */
  readonly adminRealmId: string;
  /** The approval of the security operation that issued the token. */
  readonly approvalId: string;
  /** That operation, such as `users.actChainTokens.create`. */
  readonly operationId: string;
  /** What the token let the admin do: account API scopes. */
  readonly scopes: readonly string[];
  /** Epoch ms: when the admin was issued the token. */
  readonly actedAt: number;
  /** Epoch ms: when the token expired, or expires. */
  readonly expiresAt: number;
}

/**
 * Who acted for `userId` of `realmId`, newest first: one entry per act-chain
 * token an admin was issued for them, at most `limit` (100 by default and at
 * most). The account page shows it ("an administrator acted for you").
 */
export async function listAdminAccess(
  fastify: FastifyInstance,
  realmId: string,
  userId: string,
  options: { readonly limit?: number } = {}
): Promise<AdminAccessEntry[]> {
  const rows = await fastify.repositories.adminActSessions.listForUser(realmId, userId, options);
  return rows.map((row) =>
    Object.freeze({
      id: row.id,
      adminId: row.adminUserId,
      adminRealmId: row.adminRealmId,
      approvalId: row.approvalId,
      operationId: row.operationId,
      scopes: Object.freeze([...row.scopes]),
      actedAt: row.createdAt,
      expiresAt: row.expiresAt,
    })
  );
}
