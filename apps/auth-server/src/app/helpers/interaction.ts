import { randomUUID } from 'node:crypto';

import type { SessionAssuranceLevel } from '@qauth-labs/fastify-plugin-sessions';
import { InvalidRequestError } from '@qauth-labs/shared-errors';
import type { EventDataOf, RegisteredEventType } from '@qauth-labs/shared-events';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { createBrowserSession, endBrowserSession } from './browser-session';
import {
  flowBindingOf,
  matchFlowSecret,
  mintFlowSecret,
  nextFlowSecrets,
  readFlowSecrets,
  setFlowCookie,
} from './flow-cookie';
import { InteractionExpiredError } from './interaction-expired';
import {
  deleteInteraction,
  eventClientIdOf,
  IDENTIFIER_STEP,
  insertInteraction,
  INTERACTION_RECORD_VERSION,
  interactionIdHash,
  type InteractionPersonalData,
  type InteractionRecord,
  type InteractionRequest,
  InteractionRequestTooLargeError,
  type InteractionStep,
  interactionStepSchema,
  type InteractionTransaction,
  isInteractionId,
  mintInteractionId,
  readInteractionRecord,
  returnInteractionTurn,
  takeInteractionTurn,
  writeInteractionState,
} from './interaction-record';
import { requestRealm } from './request-realm';
import { setSessionCookie } from './session-cookie';
import { emitUserEvent } from './user-events';

/**
 * THE INTERACTION API'S STATE AND ITS RULES (#592, ADR-019 Decision 6).
 *
 * An interaction is one browser ceremony: the authorization endpoint starts
 * one (#628), the ceremony app reads and answers its steps (#616), and it
 * ends in a redirect. The record (`interaction-record.ts`) lives in Redis; the
 * flow cookie (`flow-cookie.ts`) binds it to the browser that started it.
 *
 * What a request may do with an interaction:
 *
 * | Operation                          | Needs                                  |
 * | ---------------------------------- | -------------------------------------- |
 * | {@link readInteractionStep}        | the id: display data, no personal data |
 * | {@link readInteractionPersonalData}| the id and the flow cookie             |
 * | {@link answerInteraction}          | the id, the flow cookie, the revision  |
 * | {@link cancelInteraction}          | the id and the flow cookie             |
 * | {@link switchInteractionUser}      | the id and the flow cookie             |
 *
 * (The answer and cancel routes add the step's CSRF value and the same-origin
 * check, #616.) A malformed id, an unknown one, an expired interaction, a
 * finished one and a cookie that does not bind it are one case: each throws
 * {@link InteractionExpiredError}, whose answer is the same bytes whatever the
 * cause. The cause is logged, never the id or the cookie; events name the
 * interaction by its audit reference only.
 *
 * Every operation reads the realm with `requestRealm`, and the record is keyed
 * by it, so an id never reaches an interaction of another realm and
 * host-based realm resolution needs nothing more here.
 *
 * ## Answers: burn first, then bind
 *
 * An answer first checks the binding on a plain read, so a request that holds
 * only the id cannot take the turn of the browser that owns the interaction.
 * It then takes the interaction's turn with `GETDEL` and reads the record
 * again, checking that it is still the state and the binding it was given
 * for (ADR-013 §5, ADR-017 Decision 6). Of two concurrent answers to one
 * step, only the one that took the turn is processed; the other gets `stale`.
 * The record stays readable while the engine works. If anything fails
 * before the next state is written, the turn is given back and the
 * interaction stays at its step, unchanged: a retry answers it again, as after
 * a refused answer, so a store that is briefly down does not end the
 * ceremony. A browser session the failed answer created is ended. An answer
 * that outlasts the interaction's expiry is refused, and so is a finish or a
 * cancel that the expiry sweep beat to the interaction: what the sweep reports
 * expired never also finishes.
 */

/** The step view a reader of the interaction id may see: no personal data. */
export interface InteractionView {
  readonly step: InteractionStep;
  /** The `client_id` of the request the interaction is for. */
  readonly clientId: string;
  /** The absolute expiry, in epoch milliseconds. */
  readonly expiresAt: number;
  /**
   * Which state of the interaction this is. An answer names it, so it applies
   * to the step view it was given for and to no later one.
   */
  readonly revision: number;
}

/** The current step's personal data, for the browser holding the flow cookie. */
export interface InteractionPersonalView {
  readonly step: string;
  readonly data: InteractionPersonalData;
}

/** What the engine sees when it decides an answer. */
export interface InteractionState {
  readonly request: InteractionRequest;
  readonly step: InteractionStep;
  readonly personal: InteractionPersonalData;
  readonly transaction: InteractionTransaction;
  readonly revision: number;
}

/** Who an answer proved, for {@link InteractionDecision} `authenticated`. */
export interface InteractionSignIn {
  readonly userId: string;
  /** The identifier the user signed in with, shown on the consent screen. */
  readonly identifier?: string;
  readonly assuranceLevel?: SessionAssuranceLevel | null;
  /** When the caller read the account; see `createBrowserSession`. */
  readonly issuedAt?: number;
  /** The RFC 8176 `amr` values the answer proved. */
  readonly amr: readonly string[];
}

/** What the engine made of an answer. */
export type InteractionDecision =
  /** Another step, or the same one again with its `error` set. */
  | {
      readonly kind: 'step';
      readonly step: InteractionStep;
      readonly personal?: InteractionPersonalData;
      /** The `amr` values the answer proved, when it proved a factor. */
      readonly amr?: readonly string[];
    }
  /**
   * The answer proved who the user is: a new browser session (a new `sid`)
   * and a new flow binding, then the next step.
   */
  | {
      readonly kind: 'authenticated';
      readonly signIn: InteractionSignIn;
      readonly step: InteractionStep;
      readonly personal?: InteractionPersonalData;
    }
  /** The interaction is done: the caller completes or denies the request. */
  | { readonly kind: 'finished' };

/** What {@link answerInteraction} did. */
export type InteractionAnswerResult =
  /**
   * The browser holds the interaction, but the answer was not processed: it
   * named a step view that is no longer current, or another answer is being
   * processed. Nothing changed.
   */
  | { readonly kind: 'stale' }
  /** The answer was processed; the interaction waits at this step. */
  | { readonly kind: 'step'; readonly view: InteractionView }
  /** The answer finished the interaction. */
  | {
      readonly kind: 'finished';
      readonly request: InteractionRequest;
      readonly transaction: InteractionTransaction;
    };

/** What {@link cancelInteraction} did. */
export type InteractionCancelResult =
  | { readonly kind: 'stale' }
  | { readonly kind: 'cancelled'; readonly request: InteractionRequest };

/** What {@link switchInteractionUser} did. */
export type InteractionSwitchResult =
  | { readonly kind: 'stale' }
  /** The new interaction: its id, for the redirect to its ceremony page. */
  | { readonly kind: 'switched'; readonly id: string; readonly expiresAt: number };

/** Why a request was refused: logged, never answered. */
type RefusalReason = 'malformed' | 'unknown' | 'expired' | 'binding';

function refuse(request: FastifyRequest, reason: RefusalReason): never {
  request.log.info({ interactionRefused: reason }, 'interaction request refused');
  throw new InteractionExpiredError();
}

/** The interaction's lifetime, in milliseconds. */
function lifetimeMs(): number {
  return env.INTERACTION_TTL * 1000;
}

/** The step view of a record. */
function viewOf(record: InteractionRecord): InteractionView {
  return {
    step: record.step,
    clientId: record.request.client_id,
    expiresAt: record.expiresAt,
    revision: record.revision,
  };
}

/** Emit one of the interaction events, about the record's client and user. */
async function emitInteractionEvent<Type extends RegisteredEventType>(
  request: FastifyRequest,
  record: InteractionRecord,
  type: Type,
  data: EventDataOf<Type>
): Promise<void> {
  await emitUserEvent(request, type, data, {
    realmId: record.realmId,
    clientId: eventClientIdOf(record),
    userId: record.transaction.userId ?? null,
    actor: 'user',
  });
}

/** A record found by id, not yet checked against the flow cookie. */
interface Located {
  readonly record: InteractionRecord;
  readonly idHash: string;
}

/** The live record `id` names in the request's realm, or a refusal. */
async function locate(request: FastifyRequest, id: unknown): Promise<Located> {
  if (!isInteractionId(id)) refuse(request, 'malformed');
  const realmId = requestRealm(request).id;
  const idHash = interactionIdHash(id);
  const record = await readInteractionRecord(request.server.redis, request.log, realmId, idHash);
  if (record === null) refuse(request, 'unknown');
  if (record.expiresAt <= Date.now()) refuse(request, 'expired');
  return { record, idHash };
}

/** A located record and the flow secret of this browser that binds it. */
interface Bound extends Located {
  readonly secret: string;
  readonly secrets: readonly string[];
}

/** {@link locate}, then the binding: the request's flow cookie must hold the secret. */
async function locateBound(request: FastifyRequest, id: unknown): Promise<Bound> {
  const located = await locate(request, id);
  const secrets = readFlowSecrets(request);
  const secret = matchFlowSecret(located.record.flowBinding, secrets);
  if (secret === undefined) refuse(request, 'binding');
  return { ...located, secret, secrets };
}

/**
 * Take the turn of the interaction a bound request located, then read the
 * record again and check that it is still the state at `revision` and the
 * binding the request was checked against: burn first, then bind. `null` when
 * the request lost a race: another request holds the turn, or the
 * interaction moved on or ended (a turn taken for a later state is given
 * back).
 */
async function takeBound(
  request: FastifyRequest,
  bound: Bound,
  revision: number = bound.record.revision
): Promise<InteractionRecord | null> {
  const { redis } = request.server;
  const { realmId, ref, flowBinding } = bound.record;
  const turn = await takeInteractionTurn(redis, request.log, realmId, bound.idHash);
  if (turn === null) return null;
  const current = await readInteractionRecord(redis, request.log, realmId, bound.idHash);
  if (current === null || current.ref !== ref) return null;
  if (current.expiresAt <= Date.now()) {
    // The turn stays taken; the sweep audits the expiry.
    refuse(request, 'expired');
  }
  if (turn !== revision || current.revision !== revision || current.flowBinding !== flowBinding) {
    if (turn === current.revision) {
      await returnInteractionTurn(redis, current, bound.idHash, turn);
    }
    return null;
  }
  return current;
}

/** The input of {@link startInteraction}. */
export interface StartInteractionInput {
  /** The authorization request, as `/oauth/authorize` validated it. */
  readonly request: InteractionRequest;
  /** The first step the engine asks for. */
  readonly step: InteractionStep;
  readonly personal?: InteractionPersonalData;
}

/** What {@link startInteraction} returns. */
export interface StartedInteraction {
  /** The interaction id: for the redirect to the ceremony path, and nothing else. */
  readonly id: string;
  readonly expiresAt: number;
}

/**
 * Create an interaction, bound to this browser by a new flow secret, and
 * audit it. The new secret joins the others the browser's flow cookie holds.
 */
async function createInteraction(
  request: FastifyRequest,
  reply: FastifyReply,
  input: StartInteractionInput & {
    readonly secrets: readonly string[];
    readonly replace?: { readonly secret: string; readonly ref: string };
    /** The absolute expiry, when it is not `INTERACTION_TTL` from now. */
    readonly expiresAt?: number;
  }
): Promise<StartedInteraction> {
  const step = interactionStepSchema.parse(input.step);
  const id = mintInteractionId();
  const secret = mintFlowSecret();
  const now = Date.now();
  const record: InteractionRecord = {
    v: INTERACTION_RECORD_VERSION,
    ref: randomUUID(),
    realmId: requestRealm(request).id,
    purpose: 'authorization',
    request: input.request,
    step,
    personal: input.personal ?? {},
    transaction: { amr: [] },
    flowBinding: flowBindingOf(secret),
    revision: 0,
    createdAt: now,
    expiresAt: input.expiresAt ?? now + lifetimeMs(),
  };
  try {
    await insertInteraction(request.server.redis, interactionIdHash(id), record);
  } catch (error) {
    // Caller-driven: the request is too large to hold through a ceremony,
    // as the pending-authorization stash refuses one.
    if (error instanceof InteractionRequestTooLargeError) {
      throw new InvalidRequestError('authorization request is too large');
    }
    throw error;
  }
  setFlowCookie(
    reply,
    nextFlowSecrets(input.secrets, { remove: input.replace?.secret, add: secret }),
    env.INTERACTION_TTL
  );
  await emitInteractionEvent(request, record, 'urn:qauth:event:interaction.created:v1-rc.0', {
    interaction: record.ref,
    purpose: record.purpose,
    step: record.step.name,
    ...(input.replace === undefined ? {} : { replaces: input.replace.ref }),
  });
  return { id, expiresAt: record.expiresAt };
}

/**
 * Start an interaction for an authorization request, in the request's realm,
 * bound to this browser: the record, a new secret in the flow cookie, and the
 * `interaction.created` event.
 *
 * @throws {InvalidRequestError} when the request and the first step are too
 *   large to hold (`INTERACTION_MAX_RECORD_BYTES`)
 */
export async function startInteraction(
  request: FastifyRequest,
  reply: FastifyReply,
  input: StartInteractionInput
): Promise<StartedInteraction> {
  return createInteraction(request, reply, { ...input, secrets: readFlowSecrets(request) });
}

/**
 * The current step, for anyone holding the interaction id: the ceremony app's
 * server reads it while the proxy strips QAuth's cookies. No personal data,
 * and no change to the interaction.
 *
 * @throws {InteractionExpiredError} for an id that names no live interaction
 */
export async function readInteractionStep(
  request: FastifyRequest,
  id: unknown
): Promise<InteractionView> {
  const { record } = await locate(request, id);
  return viewOf(record);
}

/**
 * The current step's personal data, such as the account chooser's list: only
 * for the browser whose flow cookie binds the interaction.
 *
 * @throws {InteractionExpiredError} as {@link readInteractionStep}, and when
 *   the flow cookie does not bind the interaction
 */
export async function readInteractionPersonalData(
  request: FastifyRequest,
  id: unknown
): Promise<InteractionPersonalView> {
  const { record } = await locateBound(request, id);
  return { step: record.step.name, data: record.personal };
}

/** The `amr` list with `added` appended, each value once. */
function withAmr(amr: readonly string[], added: readonly string[] = []): string[] {
  return [...new Set([...amr, ...added])];
}

/**
 * Answer the current step: take the state, let the engine `decide`, and write
 * what it decided. Only the browser holding the flow cookie may answer, and
 * only the step view of `revision`.
 *
 * - `step`: the next state is written (the revision moves on) and its view
 *   returned.
 * - `authenticated`: the user is proved. A new browser session with a new
 *   `sid` is created and its cookie set (whatever session cookie the browser
 *   sent: the session-fixation defence), and the interaction is bound to a new
 *   flow secret that replaces the old one in the cookie. One subject per
 *   transaction: a transaction that already proved another user refuses.
 * - `finished`: the interaction ends; its secret leaves the cookie, and the
 *   request and the transaction go back to the caller, which completes or
 *   denies the authorization request (#628).
 *
 * Each processed answer is audited (`interaction.answered`).
 *
 * @throws {InteractionExpiredError} when the id names no live interaction or
 *   the flow cookie does not bind it
 */
export async function answerInteraction(
  request: FastifyRequest,
  reply: FastifyReply,
  answer: { readonly id: unknown; readonly revision: number },
  decide: (state: InteractionState) => Promise<InteractionDecision>
): Promise<InteractionAnswerResult> {
  const bound = await locateBound(request, answer.id);
  if (bound.record.revision !== answer.revision) return { kind: 'stale' };
  const taken = await takeBound(request, bound, answer.revision);
  if (taken === null) return { kind: 'stale' };

  // From here the turn is taken. Until the next state is written (or the
  // interaction deleted), a failure gives the turn back, so the interaction
  // stays at its step, unchanged, and never reads as live while no one can
  // answer it. Past its expiry the turn stays taken: the sweep reports it.
  // A browser session created for an answer that was not written is ended.
  const settled: Settlement = { done: false };
  try {
    return await settleAnswer(request, reply, bound, taken, decide, settled);
  } catch (error) {
    if (settled.session !== undefined) {
      await endUnusedSession(request, settled.session);
    }
    if (!settled.done && taken.expiresAt > Date.now()) {
      await returnInteractionTurn(request.server.redis, taken, bound.idHash, taken.revision);
    }
    throw error;
  }
}

/** How far {@link settleAnswer} got, for the clean-up of a failure. */
interface Settlement {
  /** The next state is written or the interaction deleted: nothing to give back. */
  done: boolean;
  /** A browser session created for the answer and not yet in the next state. */
  session?: { readonly realmId: string; readonly sid: string };
}

/**
 * End a browser session that an answer created but whose interaction state
 * was never written: no browser holds its cookie. Ended as `sign_out`, the
 * closest of the recorded reasons: the session ends before anyone used it.
 */
async function endUnusedSession(
  request: FastifyRequest,
  session: { readonly realmId: string; readonly sid: string }
): Promise<void> {
  await endBrowserSession(request.server, session.realmId, session.sid, 'sign_out');
}

/** {@link answerInteraction} once the turn is taken: decide, then write what was decided. */
async function settleAnswer(
  request: FastifyRequest,
  reply: FastifyReply,
  bound: Bound,
  taken: InteractionRecord,
  decide: (state: InteractionState) => Promise<InteractionDecision>,
  settled: Settlement
): Promise<InteractionAnswerResult> {
  const { redis } = request.server;
  const decision = await decide(
    Object.freeze({
      request: taken.request,
      step: taken.step,
      personal: taken.personal,
      transaction: taken.transaction,
      revision: taken.revision,
    })
  );
  // The engine may take a while (a password hash): an interaction that
  // expired meanwhile is not answered. The turn stays taken; the sweep reports it.
  if (taken.expiresAt <= Date.now()) refuse(request, 'expired');
  const answered = (
    outcome: 'next_step' | 'authenticated' | 'finished',
    record: InteractionRecord
  ) =>
    emitInteractionEvent(request, record, 'urn:qauth:event:interaction.answered:v1-rc.0', {
      interaction: record.ref,
      step: taken.step.name,
      outcome,
    });

  if (decision.kind === 'finished') {
    const owned = await deleteInteraction(redis, taken, bound.idHash);
    settled.done = true;
    // The sweep claimed it first and reports it expired: it does not finish.
    if (!owned) refuse(request, 'expired');
    setFlowCookie(
      reply,
      nextFlowSecrets(bound.secrets, { remove: bound.secret }),
      env.INTERACTION_TTL
    );
    await answered('finished', taken);
    return { kind: 'finished', request: taken.request, transaction: taken.transaction };
  }

  if (decision.kind === 'step') {
    const next: InteractionRecord = {
      ...taken,
      step: interactionStepSchema.parse(decision.step),
      personal: decision.personal ?? {},
      transaction: { ...taken.transaction, amr: withAmr(taken.transaction.amr, decision.amr) },
      revision: taken.revision + 1,
    };
    const written = await writeInteractionState(redis, bound.idHash, next);
    settled.done = true;
    // The record was gone (the expiry sweep took it): nothing to answer.
    if (!written) refuse(request, 'expired');
    await answered('next_step', next);
    return { kind: 'step', view: viewOf(next) };
  }

  const { signIn } = decision;
  const step = interactionStepSchema.parse(decision.step);
  if (taken.transaction.userId !== undefined && taken.transaction.userId !== signIn.userId) {
    // An engine bug, never a user's doing: the user switch starts a new
    // interaction. Thrown before anything is written, so the interaction ends.
    throw new Error('an interaction has one subject; switch users with a new interaction');
  }
  const session = await createBrowserSession(request.server, request, {
    realmId: taken.realmId,
    userId: signIn.userId,
    ...(signIn.identifier === undefined ? {} : { identifier: signIn.identifier }),
    ...(signIn.assuranceLevel === undefined ? {} : { assuranceLevel: signIn.assuranceLevel }),
    ...(signIn.issuedAt === undefined ? {} : { issuedAt: signIn.issuedAt }),
  });
  settled.session = { realmId: session.realmId, sid: session.sid };
  const secret = mintFlowSecret();
  const next: InteractionRecord = {
    ...taken,
    step,
    personal: decision.personal ?? {},
    transaction: {
      userId: signIn.userId,
      sid: session.sid,
      authTime: session.authTime,
      amr: withAmr(taken.transaction.amr, signIn.amr),
    },
    flowBinding: flowBindingOf(secret),
    revision: taken.revision + 1,
  };
  const written = await writeInteractionState(redis, bound.idHash, next);
  settled.done = true;
  if (!written) refuse(request, 'expired');
  settled.session = undefined;
  setSessionCookie(reply, session.sid);
  // A second authentication in one interaction (step-up) replaces the session
  // the first created: the browser's cookie no longer names it, so it ends.
  if (taken.transaction.sid !== undefined && taken.transaction.sid !== session.sid) {
    await endUnusedSession(request, { realmId: taken.realmId, sid: taken.transaction.sid });
  }
  setFlowCookie(
    reply,
    nextFlowSecrets(bound.secrets, { remove: bound.secret, add: secret }),
    env.INTERACTION_TTL
  );
  await answered('authenticated', next);
  return { kind: 'step', view: viewOf(next) };
}

/**
 * End an interaction at the request of the browser that started it: the
 * record is taken, its secret leaves the flow cookie, and the cancel is
 * audited. The caller sends the client `access_denied` (#616, #628).
 *
 * @throws {InteractionExpiredError} as {@link answerInteraction}
 */
export async function cancelInteraction(
  request: FastifyRequest,
  reply: FastifyReply,
  id: unknown
): Promise<InteractionCancelResult> {
  const bound = await locateBound(request, id);
  const taken = await takeBound(request, bound);
  if (taken === null) return { kind: 'stale' };
  // The sweep claimed it first and reports it expired: it is not cancelled.
  if (!(await deleteInteraction(request.server.redis, taken, bound.idHash))) {
    refuse(request, 'expired');
  }
  setFlowCookie(
    reply,
    nextFlowSecrets(bound.secrets, { remove: bound.secret }),
    env.INTERACTION_TTL
  );
  await emitInteractionEvent(request, taken, 'urn:qauth:event:interaction.cancelled:v1-rc.0', {
    interaction: taken.ref,
    step: taken.step.name,
    reason: 'user',
  });
  return { kind: 'cancelled', request: taken.request };
}

/**
 * The user switch ("Not you?", "Use another account"; #619, #658): end this
 * interaction and start a new one for the same authorization request, at the
 * identifier step, bound to a new flow secret that replaces this one's.
 * Nothing proved here carries over (ADR-017, one subject per transaction):
 * the new transaction is empty. The old id gets the generic expired answer
 * from now on. The new interaction keeps the request's absolute expiry: one
 * authorization request has one lifetime, and switching never extends it.
 *
 * @param identifierStep - the identifier step as the engine offers it (its
 *   alternatives); the plain identifier step when absent
 * @throws {InteractionExpiredError} as {@link answerInteraction}
 */
export async function switchInteractionUser(
  request: FastifyRequest,
  reply: FastifyReply,
  id: unknown,
  identifierStep: InteractionStep = { name: IDENTIFIER_STEP, params: {}, alternatives: [] }
): Promise<InteractionSwitchResult> {
  if (interactionStepSchema.parse(identifierStep).name !== IDENTIFIER_STEP) {
    throw new Error('a user switch starts at the identifier step');
  }
  const bound = await locateBound(request, id);
  const taken = await takeBound(request, bound);
  if (taken === null) return { kind: 'stale' };
  if (!(await deleteInteraction(request.server.redis, taken, bound.idHash))) {
    refuse(request, 'expired');
  }
  await emitInteractionEvent(request, taken, 'urn:qauth:event:interaction.cancelled:v1-rc.0', {
    interaction: taken.ref,
    step: taken.step.name,
    reason: 'user_switch',
  });
  const started = await createInteraction(request, reply, {
    request: taken.request,
    step: identifierStep,
    secrets: bound.secrets,
    replace: { secret: bound.secret, ref: taken.ref },
    // One authorization request, one absolute lifetime: switching users
    // never extends it.
    expiresAt: taken.expiresAt,
  });
  return { kind: 'switched', ...started };
}
