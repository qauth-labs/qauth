import rateLimit from '@fastify/rate-limit';
import {
  ForbiddenError,
  JWTExpiredError,
  JWTInvalidError,
  MissingAccessTokenError,
  TooManyRequestsError,
} from '@qauth-labs/shared-errors';
import type {
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
  RouteHandlerMethod,
  RouteOptions,
} from 'fastify';

import {
  type AdminAuthority,
  adminAuthorityError,
  deploymentRealmIssuerDirectory,
  resolveAdminAuthority,
} from '../helpers/admin-authority';
import {
  OPERATION_REGISTRY,
  type OperationClass,
  type OperationClassification,
  type OperationRegistry,
} from '../helpers/admin-operations';
import type { PermissionRegistry } from '../helpers/admin-permissions';
import { ADMIN_SCOPES, tokenScopeSet } from '../helpers/admin-scopes';
import { ApprovalRequiredError } from '../helpers/approval-required';
import { requireFamilyToken } from '../helpers/family-token';
import {
  adminOperationsPlugin,
  DEFAULT_ADMIN_RATE_LIMIT,
  requestClassification,
} from '../plugins/admin-operations';
import { intendedStatusCode } from '../plugins/error-handler';
import { adminRealmRouteProblem } from './route-placement';

/**
 * THE ADMIN API'S REQUEST PIPELINE (ADR-019 Decision 7, issue #511).
 *
 * Every route of the admin listener sits behind the same stages, in this
 * order. Each stage is a hook of the scope the routes register in, and
 * Fastify runs a scope's hooks in the order they were added, before a
 * route's own:
 *
 * 1. Request id and trace id: the listener's request-id plugin echoes the id
 *    every log line and problem document carries (`trace_id`).
 * 2. Token guard (#509): the admin family's guard, with the keys of the realm
 *    the token's issuer names (see {@link adminTokenStage}). A call without a
 *    valid admin token stops here, before any realm is looked up, so an
 *    unauthenticated caller learns nothing about realms. The listener's
 *    address grants nothing: a call from loopback needs a token too.
 * 3. DPoP check: an empty stage that #520 fills. Until then the token guard
 *    takes only the Bearer scheme.
 * 4. Realm lookup from the path, `/admin/v1-rc.0/realms/{realmId}/...`. The
 *    listener never routes by host (ADR-019 Decision 1).
 * 5. Authority from grants and scopes (#510, `resolveAdminAuthority`). A
 *    realm outside the caller's grants answers 404 exactly as a realm that
 *    does not exist; the call is logged and NOT written to that realm's audit
 *    chain, so a stranger cannot add rows to it.
 * 6. Classification and permission check (#508, `adminOperationsPlugin`).
 * 7. Approval gate: a security operation needs an approval bound to it
 *    (#512). Until approvals ship the gate fails closed: every request
 *    classified `security` answers `approval_required` and never runs.
 * 8. Handler, inside one database transaction (`adminTransaction`), its
 *    answer serialized before the commit. A route's own preHandler hooks run
 *    before it, after stage 7, and refuse by throwing, never by answering.
 * 9. Audit append (#448): one row in the target realm's chain, in the
 *    handler's transaction, reads included.
 * 10. Error mapping to problem+json: the listener's error handler.
 *
 * Beside them, two request ceilings, each refused before the realm is read,
 * so a refused call writes no audit row: by client address, which counts the
 * calls the token guard refuses and, past its count, refuses a call with no
 * token before the guard; and by token subject, right after the guard. A
 * route's own early hooks would run before stages 6 and 7, so a route may
 * have none, in its options (`earlyRouteHookProblem`) or added by its module
 * (`refuseEarlyScopeHooks`).
 *
 * Every call that reaches a realm within the caller's grants writes exactly
 * one audit row: a call that succeeds writes `succeeded` in the handler's
 * transaction, with the change the handler recorded and after its answer
 * serialized, so the answer and the row agree; a call refused after
 * that point (a missing permission, a missing approval, a precondition, a
 * request that fails validation) writes `denied`, and one that fails on the
 * server, its handler or commit included, writes `failed`, each in a new
 * transaction and with no diff. A `denied` or `failed` row that cannot be
 * written is logged, not retried, and the call has no row.
 */

/** The admin audit log, as the database plugin builds it. */
type AdminAuditLog = FastifyInstance['repositories']['adminAuditLog'];

/** The transaction an admin handler runs in. */
export type AdminTransaction = Parameters<AdminAuditLog['appendAdminAudit']>[0];

/** One row of the admin audit log, as the pipeline hands it over. */
type AdminAuditEntry = Parameters<AdminAuditLog['appendAdminAudit']>[1];

/** The change a handler records for its audit row, with its secret fields annotated. */
export type AdminChange = NonNullable<AdminAuditEntry['diff']>;

/** The caller and the realm it acts on, as the authority stage resolved them. */
export type AdminCaller = Extract<AdminAuthority, { allowed: true }>;

/** What the pipeline knows of one request, stage by stage. */
export interface AdminPipelineState {
  /** Set by the authority stage: from here on the call has an audit row. */
  authority?: AdminCaller;
  /** The handler's transaction, while the handler runs. */
  transaction?: AdminTransaction;
  /** The change the handler recorded, for the `succeeded` row. */
  change?: AdminChange;
  /**
   * Whether stage 8 started, from the opening of the handler's transaction:
   * a later failure is `failed`, an earlier refusal `denied`.
   */
  handlerStarted: boolean;
  /** Whether the handler's transaction, and with it the `succeeded` row, committed. */
  committed: boolean;
  /**
   * Set once the call owes an audit row: tells {@link AdminCallsInFlight}
   * that it owes none any more, its row written or past writing.
   */
  rowSettled?: () => void;
}

/** How often {@link AdminCallsInFlight.drained} looks again. */
const DRAIN_POLL_MS = 25;

/**
 * The admin calls that owe an audit row (#511): from the authority stage on,
 * until the row is written, in the handler's transaction or after a refusal
 * or failure, or the answer is out. When the server closes, the listener
 * waits for them before the database closes, so a call whose connection it
 * had to close still writes its row.
 */
export class AdminCallsInFlight {
  private readonly calls = new Set<FastifyRequest>();

  /** `request` owes a row from now on, until its state's `rowSettled` runs. */
  open(request: FastifyRequest): void {
    this.calls.add(request);
    pipelineState(request).rowSettled = () => {
      this.calls.delete(request);
    };
  }

  /** How many calls owe a row. */
  get size(): number {
    return this.calls.size;
  }

  /** Resolves `true` once no call owes a row, or `false` after `timeoutMs`. */
  async drained(timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (this.calls.size > 0) {
      if (Date.now() >= deadline) return false;
      await new Promise((resolve) => setTimeout(resolve, DRAIN_POLL_MS));
    }
    return true;
  }
}

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * The admin pipeline's state for this request (#511): `null` until its
     * first stage runs, and on every request outside the admin listener.
     * Read it through {@link requestAdminCaller}, {@link adminTransaction}
     * and {@link recordAdminChange}.
     */
    adminPipeline: AdminPipelineState | null;
  }
}

/**
 * A count of the listener's, made with `createRateLimit`: counts the request
 * against its key, or with `{ increment: false }` only reads the count.
 */
export type AdminRateLimitCheck = ReturnType<FastifyInstance['createRateLimit']>;

/** Options for {@link adminPipeline}. */
export interface AdminPipelineOptions {
  /** The registry routes name their operations in. Defaults to the server's own. */
  readonly registry?: OperationRegistry;
  /**
   * The count, per client address, of the calls the token guard refuses.
   * An address past it has a call that presents no token refused before the
   * guard, and a call the guard refuses answered 429.
   */
  readonly refusalsByAddress: AdminRateLimitCheck;
  /** The count of calls per token subject, checked right after the token guard. */
  readonly callsBySubject: AdminRateLimitCheck;
  /** Where the pipeline counts the calls that owe an audit row. Its own when unset. */
  readonly calls?: AdminCallsInFlight;
  /** Registers the routes behind the pipeline. */
  readonly routes: (scope: FastifyInstance) => void | Promise<void>;
}

/**
 * The handlers the pipeline made, each running a route's own in the
 * pipeline's transaction ({@link inTransaction}): a route is never wrapped
 * twice, and no module can mark a handler of its own as one. Read at boot
 * only ({@link keepWrapped}): Fastify runs a bound copy of the handler.
 */
const wrappedHandlers = new WeakSet<object>();

/** The pipeline state of `request`, which the first stage created. */
function pipelineState(request: FastifyRequest): AdminPipelineState {
  const state = request.adminPipeline;
  if (state === null || state === undefined) {
    throw new Error('The request has not been through the admin pipeline');
  }
  return state;
}

/**
 * The caller of an admin request and the realm it acts on, as the authority
 * stage resolved them.
 *
 * @throws {Error} outside the admin pipeline, or before its authority stage
 */
export function requestAdminCaller(request: FastifyRequest): AdminCaller {
  const authority = request.adminPipeline?.authority;
  if (authority === undefined) {
    throw new Error('The request has no admin caller: it has not passed the authority stage');
  }
  return authority;
}

/**
 * The transaction the handler of an admin route runs in. Every write the
 * handler makes goes through it: the audit row commits with them, or neither
 * does.
 *
 * @throws {Error} outside the handler of an admin route
 */
export function adminTransaction(request: FastifyRequest): AdminTransaction {
  const transaction = request.adminPipeline?.transaction;
  if (transaction === undefined) {
    throw new Error('There is no admin transaction outside the handler of an admin route');
  }
  return transaction;
}

/**
 * Record the change the handler made, for its audit row: the resource's state
 * before and after, with the annotations that name its secret fields. The
 * audit log masks them before it stores the diff. One change per call.
 *
 * @throws {Error} outside the handler of an admin route, or when a change is
 *   already recorded
 */
export function recordAdminChange(request: FastifyRequest, change: AdminChange): void {
  const state = request.adminPipeline;
  if (state?.transaction === undefined) {
    throw new Error('An admin change is recorded only inside the handler of an admin route');
  }
  if (state.change !== undefined) {
    throw new Error('An admin call records one change: its audit row holds one diff');
  }
  state.change = change;
}

/**
 * The description of every refusal of the token guard. Whether a token names
 * no realm's issuer, fails the keys of the realm it names, or fails a later
 * check, the answer reads the same, so it says nothing about realms. Each
 * refusal keeps its kind: no credential, an expired token, an invalid one.
 */
const ADMIN_TOKEN_REFUSAL = 'The request carries no admin access token this listener accepts';

/** The longest issuer the guard looks up: far longer than any realm's URL. */
const MAX_ISSUER_LENGTH = 2048;

/** C0 controls and DEL: no realm's issuer holds one, and Postgres refuses `\u0000`. */
// eslint-disable-next-line no-control-regex -- matching control characters is the entire purpose of this pattern
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;

/**
 * The issuer a token names, read before its signature is checked: only to
 * find the realm whose keys then verify it. A token that does not decode, or
 * names no issuer, or one no realm could have, is refused as any invalid
 * token is, before the lookup.
 */
function unverifiedIssuer(request: FastifyRequest, token: string): string {
  let issuer: unknown;
  try {
    issuer = request.server.jwtUtils.decodeTokenUnsafe(token).iss;
  } catch {
    throw new JWTInvalidError('Access token is not valid');
  }
  if (typeof issuer !== 'string' || issuer.length === 0) {
    throw new JWTInvalidError('Access token lacks an issuer');
  }
  if (issuer.length > MAX_ISSUER_LENGTH || CONTROL_CHARACTERS.test(issuer)) {
    throw new JWTInvalidError('Access token issuer is not one a realm could have');
  }
  return issuer;
}

/**
 * `error` with {@link ADMIN_TOKEN_REFUSAL} as its description, when it is a
 * refusal of the token; any other error, such as a database failure, as it is.
 */
function uniformTokenRefusal(error: unknown): unknown {
  if (error instanceof MissingAccessTokenError) {
    return new MissingAccessTokenError(ADMIN_TOKEN_REFUSAL);
  }
  if (error instanceof JWTExpiredError) return new JWTExpiredError(ADMIN_TOKEN_REFUSAL);
  if (error instanceof JWTInvalidError) return new JWTInvalidError(ADMIN_TOKEN_REFUSAL);
  return error;
}

/** The admin family's guard: an admin acts as itself, so its token names a user. */
const adminFamilyGuard = requireFamilyToken('admin', { subjects: ['user'] });

/**
 * Stage 2, the token guard. The listener has no host to pick a realm by, and
 * every realm signs its tokens with its own keys under its own issuer (#491).
 * So the realm whose keys verify the token is the one its `iss` names: an
 * enabled realm whose stored issuer it is. The request's realm is that realm
 * while the admin family's guard runs, which then checks the signature with
 * its keys, its issuer, its expiry and revocation, `typ`, the admin audience
 * alone, no `act`, and an enabled account of that realm as the subject.
 *
 * A call with no token, or a token that fails any of these, gets 401 here,
 * whatever its network position, and before any realm of the path is read,
 * with one description ({@link ADMIN_TOKEN_REFUSAL}). The `DPoP` scheme is
 * not taken until #520 checks its proof against the listener's own URL: it is
 * answered as a request with no credential, as with DPOP_ENABLED off.
 */
async function adminTokenStage(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  request.adminPipeline = { handlerStarted: false, committed: false };
  try {
    const credential = request.server.jwtUtils.extractCredentialFromHeader(
      request.headers.authorization
    );
    if (credential === null || credential.scheme !== 'Bearer') {
      throw new MissingAccessTokenError('Missing or malformed Authorization header');
    }
    const issuer = unverifiedIssuer(request, credential.token);
    const issuerRealm = await deploymentRealmIssuerDirectory(request.server).realmForIssuer(issuer);
    if (issuerRealm === undefined || !issuerRealm.enabled || issuerRealm.issuer === null) {
      throw new JWTInvalidError('Access token issuer is not accepted here');
    }
    request.realm = issuerRealm;
    await adminFamilyGuard(request, reply);
  } catch (error) {
    throw uniformTokenRefusal(error);
  }
}

/** Whether `error` is a refusal of the token guard: no credential, or a token refused. */
function isTokenRefusal(error: unknown): boolean {
  return (
    error instanceof MissingAccessTokenError ||
    error instanceof JWTInvalidError ||
    error instanceof JWTExpiredError
  );
}

/** Whether `request` presents a token under the one scheme the token guard takes. */
function presentsBearerToken(request: FastifyRequest): boolean {
  const credential = request.server.jwtUtils.extractCredentialFromHeader(
    request.headers.authorization
  );
  return credential?.scheme === 'Bearer';
}

/** Answer 429, with `Retry-After`, for a ceiling's count. */
function tooManyRequests(reply: FastifyReply, count: { ttlInSeconds: number }): never {
  reply.header('retry-after', String(count.ttlInSeconds));
  throw new TooManyRequestsError();
}

/**
 * Stage 3, the DPoP check. Empty: requiring a DPoP-bound admin token, and
 * checking its proof against the listener's own URL, is #520's. Until then
 * the token guard takes only the Bearer scheme, and refuses a DPoP-bound
 * token sent under it.
 */
async function adminDpopStage(): Promise<void> {
  // Filled by #520.
}

/** Stage 4: the realm the request acts on, from its path. */
function targetRealmIdOf(request: FastifyRequest): string {
  const realmId = (request.params as { realmId?: unknown } | undefined)?.realmId;
  if (typeof realmId !== 'string') {
    // The boot check keeps every route under the realm prefix.
    throw new Error(`${request.method} ${request.routeOptions.url ?? ''} names no realm`);
  }
  return realmId;
}

/**
 * Stages 4 and 5: the realm from the path, and what the caller may do there.
 * A realm outside the grants is refused like a realm that does not exist, and
 * logged with the caller, not written to that realm's chain. From here on the
 * request's realm is the realm it acts on, and neither it nor the caller can
 * be changed.
 */
async function adminAuthorityStage(request: FastifyRequest): Promise<void> {
  const state = pipelineState(request);
  const targetRealmId = targetRealmIdOf(request);
  const claims = request.jwtPayload;
  if (claims?.iss === undefined) {
    throw new Error('The admin token guard set no claims');
  }
  const authority = await resolveAdminAuthority(request.server, {
    iss: claims.iss,
    sub: claims.sub,
    scopes: claims.scope,
    targetRealmId,
  });
  if (!authority.allowed) {
    if (authority.refusal === 'realm_not_found') {
      request.log.warn(
        { adminCaller: { issuer: claims.iss, subject: claims.sub }, realmId: targetRealmId },
        "An admin call named a realm outside the caller's grants: refused, and not written to that realm's audit chain"
      );
    }
    throw adminAuthorityError(authority.refusal, targetRealmId);
  }
  const caller = Object.freeze(authority);
  Object.defineProperty(request, 'realm', {
    value: caller.targetRealm,
    enumerable: true,
    writable: false,
    configurable: false,
  });
  state.authority = caller;
}

/**
 * Stage 6's check: the caller holds every permission the classification
 * names. The effective permissions are the grants' roles intersected with the
 * token's scopes. When the roles hold every missing permission, only the
 * token's scopes withhold them: the 403 carries the `insufficient_scope`
 * challenge naming the scopes a wider token needs (RFC 6750 §3.1). When a
 * role lacks one, no token would pass, and the challenge names no scope.
 */
function authorizeAdminRequest(
  request: FastifyRequest,
  classification: OperationClassification,
  permissions: PermissionRegistry
) {
  const caller = requestAdminCaller(request);
  const missing = classification.permissions.filter((id) => !caller.permissions.has(id));
  if (missing.length === 0) return;
  const granted = tokenScopeSet(request.jwtPayload?.scope ?? '');
  const scopes = missing.every((id) => caller.rolePermissions.has(id))
    ? [
        ...new Set(
          missing
            .map((id) => permissions.get(id)?.class)
            .filter((permissionClass) => permissionClass !== undefined)
            .map((permissionClass) => ADMIN_SCOPES[permissionClass])
            .filter((scope) => !granted.has(scope))
        ),
      ]
    : [];
  throw new ForbiddenError(
    'The caller lacks a permission this admin operation needs',
    scopes.length > 0 ? { requiredScope: scopes } : {}
  );
}

/**
 * Stage 7, the approval gate. A request classified `security` needs a fresh
 * approval bound to it (ADR-019 Decision 7). Approvals arrive with #512;
 * until then the gate fails closed, and no security operation ever runs.
 */
async function adminApprovalGate(request: FastifyRequest): Promise<void> {
  if (requestClassification(request).class === 'security') {
    throw new ApprovalRequiredError();
  }
}

/** The operation a row records: the request's classification, or the route's operation as declared. */
function auditedOperation(
  request: FastifyRequest,
  registry: OperationRegistry
): { operationId: string; operationClass: OperationClass; effects: readonly string[] } {
  const classification = request.adminOperation;
  if (classification !== undefined && classification !== null) {
    return {
      operationId: classification.operationId,
      operationClass: classification.class,
      effects: classification.effects,
    };
  }
  const id = request.routeOptions.config.operation;
  const operation = typeof id === 'string' ? registry.get(id) : undefined;
  if (operation === undefined) {
    throw new Error(`${request.method} ${request.routeOptions.url ?? ''} has no admin operation`);
  }
  return { operationId: operation.id, operationClass: operation.class, effects: operation.effects };
}

/** The audit row of `request`, with `outcome`. */
function auditEntry(
  request: FastifyRequest,
  registry: OperationRegistry,
  caller: AdminCaller,
  outcome: AdminAuditEntry['outcome'],
  change: AdminChange | undefined
): AdminAuditEntry {
  return {
    realmId: caller.targetRealm.id,
    // The guard admits only a user as the subject: an admin account. Service
    // accounts arrive with #522.
    actorKind: 'human_admin',
    actorId: caller.userId,
    actorRealmId: caller.issuerRealm.id,
    // The admin family refuses a delegated token.
    actChain: null,
    ...auditedOperation(request, registry),
    outcome,
    diff: change ?? null,
    // The approvals the operation ran on, and the digest they bind, arrive
    // with #512.
    approvals: [],
    requestDigest: null,
    traceId: request.id,
  };
}

/** What a handler or a route's own preHandler that tries to answer is refused with. */
const SEND_REFUSAL =
  'An admin handler answers by returning its body, and a preHandler refuses by throwing, never by sending or hijacking the reply: the answer would leave before its change and audit row commit';

/** The reply methods that would answer from inside the handler, before the commit. */
const ANSWERING_METHODS = ['send', 'hijack'] as const;

/**
 * Make `reply.send()` and `reply.hijack()`, and so `reply.redirect()`, throw
 * until {@link allowAnswering}: an answer sent by the route's own code would
 * leave before its change and audit row commit, and Fastify runs no `onError`
 * hook once a reply is out.
 */
function refuseAnswering(reply: FastifyReply): void {
  for (const method of ANSWERING_METHODS) {
    Object.defineProperty(reply, method, {
      configurable: true,
      value: () => {
        throw new Error(SEND_REFUSAL);
      },
    });
  }
}

/** Undo {@link refuseAnswering}. */
function allowAnswering(reply: FastifyReply): void {
  for (const method of ANSWERING_METHODS) Reflect.deleteProperty(reply, method);
}

/** Refused all the same: an answer written to the raw response, around the reply, even only its head. */
function assertNothingAnswered(reply: FastifyReply): void {
  if (reply.sent || reply.raw.headersSent) throw new Error(SEND_REFUSAL);
}

/** A preHandler hook of a route, in either of the forms Fastify takes. */
type RoutePreHandler = (
  this: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  done: (error?: unknown) => void
) => unknown;

/** The route preHandlers the pipeline made, each running one of a route's own. */
const wrappedPreHandlers = new WeakSet<object>();

/**
 * A route's own preHandler, run so that it cannot answer: it refuses by
 * throwing, and the error goes through `onError`, which writes the call's
 * audit row. A hook that sends or hijacks the reply fails the call instead.
 */
function refusingPreHandler(hook: RoutePreHandler) {
  const wrapped = async function adminRoutePreHandler(
    this: FastifyInstance,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> {
    refuseAnswering(reply);
    try {
      await new Promise<void>((resolve, reject) => {
        const done = (error?: unknown) => (error ? reject(error) : resolve());
        const result = hook.call(this, request, reply, done);
        if (result !== null && typeof result === 'object' && 'then' in result) {
          (result as PromiseLike<unknown>).then(() => resolve(), reject);
        }
      });
    } finally {
      allowAnswering(reply);
    }
    assertNothingAnswered(reply);
  };
  wrappedPreHandlers.add(wrapped);
  return wrapped;
}

/** Whether `body` is one Fastify sends as it is, with no serializer: none, text, bytes or a stream. */
function sentAsItIs(body: unknown): boolean {
  return (
    body === undefined ||
    typeof body === 'string' ||
    Buffer.isBuffer(body) ||
    (body !== null &&
      typeof body === 'object' &&
      typeof (body as { pipe?: unknown }).pipe === 'function')
  );
}

/**
 * The answer of a handler that returned `body`: serialized here, as Fastify
 * would serialize it after the handler, with the route's response schema for
 * the status the reply has, so a body the schema refuses fails inside the
 * transaction. A body Fastify sends as it is, or one under a content type
 * that is not JSON, is left as it is.
 */
function prepareAnswer(
  reply: FastifyReply,
  body: unknown
): { readonly serialized: string } | { readonly body: unknown } {
  const contentType = reply.getHeader('content-type');
  if (sentAsItIs(body) || (contentType !== undefined && !String(contentType).includes('json'))) {
    return { body };
  }
  return { serialized: String(reply.serialize(body)) };
}

/**
 * Stages 8 and 9: run `handler` inside one transaction, serialize its answer
 * and append the `succeeded` row in it once the handler returns. The handler
 * answers by returning its body. While it runs, `reply.send()` and
 * `reply.hijack()` throw ({@link refuseAnswering}). A body its response
 * schema refuses fails the call before the commit, so the change rolls back
 * and the call is `failed`: the answer and the row always agree. The answer
 * is sent after the commit.
 */
function inTransaction(handler: RouteHandlerMethod, registry: OperationRegistry) {
  const wrapped = async function adminTransactionStage(
    this: FastifyInstance,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<unknown> {
    const state = pipelineState(request);
    const caller = requestAdminCaller(request);
    // From here on a failure is the server's, the transaction's opening
    // included: the call was authorized and approved.
    state.handlerStarted = true;
    let answer: { readonly serialized: string } | { readonly body: unknown };
    try {
      answer = await request.server.db.transaction(async (tx) => {
        state.transaction = tx;
        refuseAnswering(reply);
        let result: unknown;
        try {
          result = await handler.call(this, request, reply);
        } finally {
          allowAnswering(reply);
          state.transaction = undefined;
        }
        assertNothingAnswered(reply);
        const prepared = prepareAnswer(reply, result);
        await request.server.repositories.adminAuditLog.appendAdminAudit(
          tx,
          auditEntry(request, registry, caller, 'succeeded', state.change)
        );
        return prepared;
      });
    } catch (error) {
      // A reply already out runs no `onError` hook: its row is written here.
      // One whose head alone went out still runs it, and is written there.
      if (reply.sent) await auditRefusal(request, registry, true);
      throw error;
    }
    state.committed = true;
    state.rowSettled?.();
    if ('serialized' in answer) {
      if (!reply.hasHeader('content-type')) reply.type('application/json; charset=utf-8');
      return reply.send(answer.serialized);
    }
    if (answer.body === undefined) return reply.send();
    return answer.body;
  };
  wrappedHandlers.add(wrapped);
  return wrapped;
}

/**
 * The audit row of a call refused or failed after the authority stage:
 * `failed` once stage 8 started or when the server failed (`serverFailure`,
 * a 5xx answer), `denied` for a refusal before. Written in a new
 * transaction, with no diff: the handler's own rolled back. A call that never
 * reached a realm within the caller's grants writes nothing; a call whose
 * transaction already committed has its row.
 */
async function auditRefusal(
  request: FastifyRequest,
  registry: OperationRegistry,
  serverFailure: boolean
): Promise<void> {
  const state = request.adminPipeline;
  if (state === null || state.authority === undefined || state.committed) return;
  const caller = state.authority;
  const outcome = state.handlerStarted || serverFailure ? 'failed' : 'denied';
  try {
    const entry = auditEntry(request, registry, caller, outcome, undefined);
    await request.server.db.transaction(async (tx) => {
      await request.server.repositories.adminAuditLog.appendAdminAudit(tx, entry);
    });
  } catch (error) {
    request.log.error(
      { err: error, outcome, realmId: caller.targetRealm.id },
      'The audit row of a refused or failed admin call could not be written'
    );
  } finally {
    state.rowSettled?.();
  }
}

/**
 * The hooks of a route's own that run before the permission check and the
 * approval gate: a route's `onRequest`, `preParsing` and `preValidation`
 * hooks run after the scope's hooks of the same kind, but before its
 * `preHandler` hooks, where those two stages are. An admin route may not have
 * them: no code of an operation runs before the caller is authorized for it.
 */
const EARLY_ROUTE_HOOKS = ['onRequest', 'preParsing', 'preValidation'] as const;

/** Why `route` has a hook of its own that would run before authorization, or `undefined`. */
function earlyRouteHookProblem(route: RouteOptions): string | undefined {
  const early = EARLY_ROUTE_HOOKS.filter((name) => {
    const hooks: unknown = route[name];
    return Array.isArray(hooks) ? hooks.length > 0 : hooks !== undefined && hooks !== null;
  });
  if (early.length === 0) return undefined;
  const methods = Array.isArray(route.method) ? route.method.join(',') : route.method;
  return `${methods} ${route.url} has its own ${early.join(', ')} hook, which would run before the admin pipeline authorizes the caller; use a preHandler hook or the handler`;
}

/**
 * Refuse, from now on, every {@link EARLY_ROUTE_HOOKS} hook added to `scope`
 * with `addHook`: a scope's hooks of those kinds run before its `preHandler`
 * hooks, where stages 6 and 7 are, whoever adds them. A `preHandler` hook a
 * route module adds runs as a route's own does ({@link refusingPreHandler}):
 * it refuses by throwing, never by answering. A scope registered in `scope`
 * inherits its `addHook` (Fastify makes it with `Object.create`), and a
 * plugin wrapped in `fastify-plugin` adds to the scope it is registered in,
 * so both reach every route module behind the pipeline.
 */
function refuseEarlyScopeHooks(scope: FastifyInstance): void {
  const addHook = scope.addHook;
  Object.defineProperty(scope, 'addHook', {
    value: function addAdminScopeHook(this: FastifyInstance, name: unknown, ...rest: unknown[]) {
      if ((EARLY_ROUTE_HOOKS as readonly unknown[]).includes(name)) {
        throw new Error(
          `An admin route module adds an ${String(name)} hook, which would run before the admin pipeline authorizes the caller; use a preHandler hook or the handler`
        );
      }
      const [hook, ...after] = rest;
      return name === 'preHandler' && typeof hook === 'function'
        ? Reflect.apply(addHook, this, [
            name,
            refusingPreHandler(hook as RoutePreHandler),
            ...after,
          ])
        : Reflect.apply(addHook, this, [name, ...rest]);
    },
  });
}

/** `hooks`, each a route preHandler the pipeline made ({@link refusingPreHandler}), in place. */
function wrapPreHandlers(hooks: unknown[]): unknown[] {
  hooks.forEach((hook, index) => {
    if (!wrappedPreHandlers.has(hook as object)) {
      hooks[index] = refusingPreHandler(hook as RoutePreHandler);
    }
  });
  return hooks;
}

/**
 * Make `route`'s handler and preHandlers the pipeline's, for good: each
 * becomes an accessor of the route's options that wraps whatever is
 * assigned to it. Fastify reads `handler` and the hooks from these options
 * once every `onRoute` hook has run, so a later hook, such as one of a scope
 * registered behind the pipeline, that puts the route's own handler back, or
 * assigns or pushes a preHandler, gets it wrapped all the same. Fastify binds
 * the handler it reads, so nothing can check at request time which handler
 * runs: it is made sure of here.
 */
function keepWrapped(route: RouteOptions, registry: OperationRegistry): void {
  let handler = route.handler;
  const wrapHandler = (value: RouteHandlerMethod) =>
    wrappedHandlers.has(value) ? value : (inTransaction(value, registry) as RouteHandlerMethod);
  handler = wrapHandler(handler);
  Object.defineProperty(route, 'handler', {
    configurable: true,
    enumerable: true,
    get: () => handler,
    set: (value: RouteHandlerMethod) => {
      handler = wrapHandler(value);
    },
  });

  // Kept as one array, wrapped in place whenever it is read, so a hook a
  // later `onRoute` hook pushes onto it is wrapped too.
  let preHandlers: unknown[] | undefined =
    route.preHandler === undefined || route.preHandler === null
      ? undefined
      : [route.preHandler].flat();
  Object.defineProperty(route, 'preHandler', {
    configurable: true,
    enumerable: true,
    get: () => (preHandlers === undefined ? undefined : wrapPreHandlers(preHandlers)),
    set: (value: unknown) => {
      preHandlers = value === undefined || value === null ? undefined : [value].flat();
    },
  });
}

/**
 * The admin pipeline: its stages as hooks of an encapsulated scope, then the
 * routes `options.routes` registers in it. Register it on the admin listener,
 * after the request id and the listener's `@fastify/rate-limit`, whose
 * counts it takes, and before any other route: the classification stage
 * refuses to load on an instance that already has one.
 */
export async function adminPipeline(
  fastify: FastifyInstance,
  options: AdminPipelineOptions
): Promise<void> {
  const registry = options.registry ?? OPERATION_REGISTRY;
  const calls = options.calls ?? new AdminCallsInFlight();

  fastify.decorateRequest('adminPipeline', null);

  // At boot: every route acts on a realm named in its path, runs its
  // handler in the pipeline's transaction, and its own preHandlers so that
  // they refuse by throwing.
  fastify.addHook('onRoute', (route) => {
    const problem = adminRealmRouteProblem(route) ?? earlyRouteHookProblem(route);
    if (problem !== undefined) throw new Error(problem);
    keepWrapped(route, registry);
  });

  // Every route behind the pipeline authorizes, so none runs without a
  // request ceiling. The listener registers `@fastify/rate-limit` before the
  // pipeline, for its counts by address and by subject, and keeps it. A
  // scope without one gets the classification stage's default here, as
  // `adminOperationsPlugin` would give it, and ahead of the stages, where
  // CodeQL's `js/missing-rate-limiting` can see it: it cannot follow the
  // listener's registration into this plugin. After the `onRoute` check
  // above, so the check sees each route before the limit adds its hook.
  if (!fastify.hasDecorator('rateLimit')) {
    await fastify.register(rateLimit, {
      global: true,
      max: DEFAULT_ADMIN_RATE_LIMIT.max,
      timeWindow: DEFAULT_ADMIN_RATE_LIMIT.timeWindow,
    });
  }

  const { refusalsByAddress, callsBySubject } = options;
  // The ceiling per address, before stage 2. It counts only the calls the
  // token guard refuses: an address past its count has a call that presents
  // no token refused here. A call with a token goes on to the guard, so a
  // caller with a valid token is never held back by the refusals of others
  // at its address.
  fastify.addHook('onRequest', async (request, reply) => {
    if (presentsBearerToken(request)) return;
    const count = await refusalsByAddress(request, { increment: false });
    if (!count.isAllowed && count.remaining === 0) tooManyRequests(reply, count);
  });
  // Stage 2. Each refusal counts against the address, and past its count
  // the answer is 429.
  fastify.addHook('onRequest', async (request, reply) => {
    try {
      await adminTokenStage(request, reply);
    } catch (error) {
      if (isTokenRefusal(error)) {
        const count = await refusalsByAddress(request);
        if (!count.isAllowed && count.isExceeded) tooManyRequests(reply, count);
      }
      throw error;
    }
  });
  // The ceiling per subject, which needs the subject.
  fastify.addHook('onRequest', async (request, reply) => {
    const count = await callsBySubject(request);
    if (!count.isAllowed && count.isExceeded) tooManyRequests(reply, count);
  });
  // Stage 3.
  fastify.addHook('onRequest', adminDpopStage);
  // Stages 4 and 5. Before the body is read, so a caller with no grant on the
  // realm never has its body parsed.
  fastify.addHook('onRequest', adminAuthorityStage);
  // From here on the call owes its audit row.
  fastify.addHook('onRequest', async (request) => {
    calls.open(request);
  });

  // Stage 9's other half: a call refused or failed after stage 5, recorded
  // `failed` when it answers a 5xx, as the error handler will answer it.
  fastify.addHook('onError', async (request, _reply, error) => {
    await auditRefusal(request, registry, intendedStatusCode(error) >= 500);
  });
  // An answer out: its row is written, or the call wrote none.
  fastify.addHook('onResponse', async (request) => {
    request.adminPipeline?.rowSettled?.();
  });

  // Stage 6.
  await fastify.register(adminOperationsPlugin, {
    registry,
    authorize: (request, classification) =>
      authorizeAdminRequest(request, classification, registry.permissions),
  });

  // Stage 7, after stage 6's `preHandler`.
  fastify.addHook('preHandler', adminApprovalGate);

  // The stages are in place: no route module may add a hook that would run
  // before stages 6 and 7.
  refuseEarlyScopeHooks(fastify);

  await options.routes(fastify);
}
