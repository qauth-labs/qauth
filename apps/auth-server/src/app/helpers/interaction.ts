import { randomUUID } from 'node:crypto';

import { PASSWORD_PROVIDER_TYPE } from '@qauth-labs/fastify-plugin-federation';
import type { SessionAssuranceLevel } from '@qauth-labs/fastify-plugin-sessions';
import type { SignInTransaction } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { ForbiddenError, InvalidRequestError } from '@qauth-labs/shared-errors';
import type { EventDataOf, RegisteredEventType } from '@qauth-labs/shared-events';
import type { ClientDisplay } from '@qauth-labs/shared-interaction-client';
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
import { interactionCsrf, matchesInteractionCsrf, mintCsrfKey } from './interaction-csrf';
import { InteractionExpiredError } from './interaction-expired';
import {
  type CarriedSession,
  deleteInteraction,
  eventClientIdOf,
  IDENTIFIER_STEP,
  insertInteraction,
  INTERACTION_RECORD_VERSION,
  interactionDeadline,
  interactionIdHash,
  type InteractionPersonalData,
  type InteractionRecord,
  InteractionRecordTooLargeError,
  type InteractionRequest,
  InteractionRequestTooLargeError,
  type InteractionStep,
  interactionStepSchema,
  type InteractionTransaction,
  isInteractionId,
  mintInteractionId,
  readInteractionRecord,
  returnInteractionTurn,
  SELECT_ACCOUNT_STEP,
  takeInteractionTurn,
  writeInteractionState,
} from './interaction-record';
import { requestRealm } from './request-realm';
import {
  clearSessionCookie,
  readCookie,
  SESSION_COOKIE_NAME,
  sessionCookieHeader,
  verifySessionCookie,
} from './session-cookie';
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
 * | {@link answerInteraction}          | the id, the flow cookie, the CSRF value|
 * | {@link cancelInteraction}          | the id, the flow cookie, the CSRF value|
 * | {@link switchInteractionUser}      | the id and the flow cookie             |
 *
 * (The answer and cancel routes check the same origin first, #616; the route
 * that will call the switch, #619, must check the origin and the CSRF value
 * too, #964.) The CSRF
 * value (`interaction-csrf.ts`) is checked after the flow cookie: a value
 * that is not the current step view's is refused with a generic `403`
 * (`ForbiddenError`) and audited (`request.csrf_rejected`), and nothing else
 * happens. A malformed id, an unknown one, an expired interaction, a
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
 * expired never also finishes. A finish is refused the same way when the
 * browser session its sign-in started has ended since (#963): a sign-out in
 * another tab, a revoke, the session's own end, or a user switch that ended it
 * and then failed. No request completes under a session that was signed out.
 * Nothing was written, so the turn is given back, as after a refused answer:
 * the interaction can still be cancelled or switched until it expires.
 *
 * ## Expiry
 *
 * An interaction expires at its absolute expiry, `INTERACTION_TTL` after the
 * request that started it, or sooner while nobody has answered it: an
 * unanswered interaction expires `INTERACTION_UNANSWERED_TTL_MS` after it was
 * created, and the first answer the server processes lifts that deadline to
 * the absolute expiry, which never moves (`interactionDeadline`). Every
 * operation refuses an expired interaction, whichever deadline it reached.
 */

/** The step view a reader of the interaction id may see: no personal data. */
export interface InteractionView {
  readonly step: InteractionStep;
  /** The `client_id` of the request the interaction is for. */
  readonly clientId: string;
  /**
   * Who the client is, for a step that names it (the consent step, #629): the
   * display data the interaction started with. Absent for any other step.
   */
  readonly client?: ClientDisplay;
  /**
   * The absolute expiry, in epoch milliseconds. An interaction nobody has
   * answered yet ends sooner (`INTERACTION_UNANSWERED_TTL_MS` after it was
   * created); the first processed answer lifts that deadline, never this one.
   */
  readonly expiresAt: number;
  /**
   * When the server refuses the interaction: the absolute expiry, or sooner
   * while nobody has answered it (`interactionDeadline`).
   */
  readonly deadline: number;
  /**
   * Which state of the interaction this is. An answer names it, so it applies
   * to the step view it was given for and to no later one.
   */
  readonly revision: number;
  /**
   * The CSRF value of this step view (#616): what an answer or a cancel of
   * the browser holding the flow cookie must carry. It names the revision.
   */
  readonly csrf: string;
}

/** The current step's personal data, for the browser holding the flow cookie. */
export interface InteractionPersonalView {
  readonly step: string;
  readonly data: InteractionPersonalData;
  /** The current step whose personal data this is, as the record keeps it. */
  readonly current: InteractionStep;
}

/** What the engine sees when it decides an answer. */
export interface InteractionState {
  readonly request: InteractionRequest;
  readonly step: InteractionStep;
  readonly personal: InteractionPersonalData;
  readonly transaction: InteractionTransaction;
  /** The sign-in engine's transaction, `null` before its first round (#616). */
  readonly signInTransaction: SignInTransaction | null;
  readonly revision: number;
  /** Who the client is, as the step read showed it (#629): the consent step's. */
  readonly client?: ClientDisplay;
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
      /** The sign-in engine's transaction to keep; absent keeps the stored one. */
      readonly signInTransaction?: SignInTransaction | null;
    }
  /**
   * The answer proved who the user is: a new browser session (a new `sid`)
   * and a new flow binding, then the next step. With no next step, the
   * interaction finishes with it, as `finished` does: the session is created,
   * the interaction ends and the caller completes the request (#616). The
   * engine's transaction ends either way: the sign-in is complete.
   */
  | {
      readonly kind: 'authenticated';
      readonly signIn: InteractionSignIn;
      readonly step?: InteractionStep;
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
      /** What the next interaction of the same request starts from (#628). */
      readonly continuation: InteractionContinuation;
    };

/**
 * What a finished interaction leaves for the next one of the same
 * authorization request (#628): when finishing the request needs the person
 * again (a consent after a sign-in), {@link continueInteraction} starts it
 * from here.
 */
export interface InteractionContinuation {
  /** The flow secrets the browser keeps once the finished interaction's left its cookie. */
  readonly secrets: readonly string[];
  /** The finished interaction's absolute expiry: one authorization request, one lifetime. */
  readonly expiresAt: number;
}

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
type RefusalReason = 'malformed' | 'unknown' | 'expired' | 'binding' | 'session_ended';

/** Why a request at an interaction was forbidden (#616): logged, never answered. */
export type ForbiddenReason = 'origin' | 'csrf';

/**
 * Refuse an answer or a cancel that does not come from the realm origin, or
 * whose CSRF value is not the current step view's (#616, ADR-019 Decision 6):
 * a generic `403` that names neither, audited as `request.csrf_rejected`.
 * Nothing else happens: the interaction is not read further, and the engine is
 * not called. `record` is the interaction when the flow cookie already bound
 * it, so the event names its client and user.
 */
export async function refuseForbidden(
  request: FastifyRequest,
  reason: ForbiddenReason,
  record?: InteractionRecord
): Promise<never> {
  request.log.info({ interactionRefused: reason }, 'interaction request forbidden');
  await emitUserEvent(
    request,
    'urn:qauth:event:request.csrf_rejected:v1-rc.0',
    { form: 'interaction' },
    record === undefined
      ? { actor: 'user' }
      : {
          realmId: record.realmId,
          clientId: eventClientIdOf(record),
          userId: record.transaction.userId ?? null,
          actor: 'user',
        }
  );
  throw new ForbiddenError('The request is not allowed.');
}

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
    // Written only by `createInteraction`, from `clientDisplay`'s output.
    ...(record.client === undefined ? {} : { client: record.client as unknown as ClientDisplay }),
    expiresAt: record.expiresAt,
    deadline: interactionDeadline(record),
    revision: record.revision,
    csrf: interactionCsrf(record),
  };
}

/**
 * Emit one of the interaction events, about the record's client and user:
 * the transaction's, or `userId` when the caller names another, such as the
 * user whose session a user switch ended.
 */
async function emitInteractionEvent<Type extends RegisteredEventType>(
  request: FastifyRequest,
  record: InteractionRecord,
  type: Type,
  data: EventDataOf<Type>,
  userId: string | null = record.transaction.userId ?? null
): Promise<void> {
  await emitUserEvent(request, type, data, {
    realmId: record.realmId,
    clientId: eventClientIdOf(record),
    userId,
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
  if (interactionDeadline(record) <= Date.now()) refuse(request, 'expired');
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
  if (interactionDeadline(current) <= Date.now()) {
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
  /**
   * Who the interaction is for when the browser is already signed in (#628):
   * the browser session's user, `sid` and authentication time, for a step that
   * needs no sign-in, such as consent. Absent, the transaction starts empty
   * and the person signs in. A finish needs this session to be live, as it
   * needs the one a sign-in in the interaction started (#963).
   */
  readonly transaction?: InteractionTransaction;
  /**
   * The browser session the authorization request came with, when the
   * browser was already signed in (#964): for a consent, the session the
   * transaction is for; for a sign-in the request asks for again (`max_age`,
   * `prompt=login`, a dangerous scope), the session the person signs in
   * over. A user switch ("Not you?") ends it while nobody else has signed in
   * during the interaction ({@link switchInteractionUser}). Absent for a
   * browser that was not signed in.
   */
  readonly carriedSession?: CarriedSession;
  /**
   * Who the client is, for a step that names it (the consent step, #629):
   * `clientDisplay`'s output, which the step read returns as `client`.
   */
  readonly client?: ClientDisplay;
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
    transaction: input.transaction ?? { amr: [] },
    ...(input.carriedSession === undefined ? {} : { carriedSession: input.carriedSession }),
    ...(input.client === undefined ? {} : { client: { ...input.client } }),
    flowBinding: flowBindingOf(secret),
    csrfKey: mintCsrfKey(),
    signInTransaction: null,
    revision: 0,
    createdAt: now,
    expiresAt: input.expiresAt ?? now + lifetimeMs(),
  };
  try {
    await insertInteraction(request.server.redis, interactionIdHash(id), record);
  } catch (error) {
    // The request, or the request with its first step, is too large to hold
    // through a ceremony, as the pending-authorization stash refuses one.
    if (
      error instanceof InteractionRequestTooLargeError ||
      error instanceof InteractionRecordTooLargeError
    ) {
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
 * `interaction.created` event. Until its first answer is processed, the
 * interaction lives `INTERACTION_UNANSWERED_TTL_MS` at most.
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
 * Start the next interaction of an authorization request whose interaction
 * just finished (#628), on the same reply: when finishing the request needs
 * the person again, such as a consent after the sign-in. As
 * {@link startInteraction}, except that the flow cookie is built from the
 * secrets the finish left (its own secret is gone), and the new interaction
 * keeps the finished one's absolute expiry: one authorization request has one
 * lifetime, and continuing never extends it.
 *
 * @throws {InvalidRequestError} as {@link startInteraction}
 */
export async function continueInteraction(
  request: FastifyRequest,
  reply: FastifyReply,
  after: InteractionContinuation,
  input: StartInteractionInput
): Promise<StartedInteraction> {
  return createInteraction(request, reply, {
    ...input,
    secrets: after.secrets,
    expiresAt: after.expiresAt,
  });
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
  return { step: record.step.name, data: record.personal, current: record.step };
}

/** The `amr` list with `added` appended, each value once. */
function withAmr(amr: readonly string[], added: readonly string[] = []): string[] {
  return [...new Set([...amr, ...added])];
}

/**
 * What an answer names: the interaction id, and the step view it answers, by
 * the CSRF value of that view (the Interaction API, #616) or by its revision
 * (a caller that checked the view itself, such as this module's tests).
 */
export type InteractionAnswerTarget =
  | { readonly id: unknown; readonly csrf: unknown }
  | { readonly id: unknown; readonly revision: number };

/**
 * Answer the current step: take the state, let the engine `decide`, and write
 * what it decided. Only the browser holding the flow cookie may answer, and
 * only the step view the answer names. A CSRF value that is not the current
 * view's is refused (`refuseForbidden`) after the cookie is checked and before
 * the turn is taken.
 *
 * - `step`: the next state is written (the revision moves on) and its view
 *   returned.
 * - `authenticated`: the user is proved. A new browser session with a new
 *   `sid` is created and its cookie set (whatever session cookie the browser
 *   sent: the session-fixation defence), and the interaction is bound to a new
 *   flow secret that replaces the old one in the cookie. One subject per
 *   transaction: a transaction that already proved another user refuses. A
 *   browser that loses this response keeps only the old secret, so its retry
 *   gets the uniform `interaction_expired` and the ceremony starts over: the
 *   transport (#616) must submit credential steps by `fetch`, or guard a form
 *   post against a double submit, so a second click never sends the answer
 *   again with the old cookie.
 * - `finished`: the interaction ends; its secret leaves the cookie, and the
 *   request and the transaction go back to the caller, which completes or
 *   denies the authorization request (#628), or continues it in a next
 *   interaction ({@link continueInteraction}). Only while the browser session
 *   the sign-in started is live (#963): a finish after it ended gets the
 *   answer an ended interaction gets, and the interaction stays at its step.
 *
 * Each processed answer is audited (`interaction.answered`).
 *
 * @throws {InteractionExpiredError} when the id names no live interaction or
 *   the flow cookie does not bind it
 */
export async function answerInteraction(
  request: FastifyRequest,
  reply: FastifyReply,
  answer: InteractionAnswerTarget,
  decide: (state: InteractionState) => Promise<InteractionDecision>
): Promise<InteractionAnswerResult> {
  const bound = await locateBound(request, answer.id);
  let revision: number;
  if ('csrf' in answer) {
    if (!matchesInteractionCsrf(bound.record, answer.csrf)) {
      await refuseForbidden(request, 'csrf', bound.record);
    }
    revision = bound.record.revision;
  } else {
    if (bound.record.revision !== answer.revision) return { kind: 'stale' };
    revision = answer.revision;
  }
  const taken = await takeBound(request, bound, revision);
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
    // The turn first: it is what keeps the interaction answerable. Each step
    // of the clean-up is on its own, so one that fails skips no other, and
    // the answer fails with its own error.
    if (!settled.done) await giveTurnBack(request, taken, bound.idHash);
    if (settled.session !== undefined) {
      await bestEffort(request, 'end the session of an answer that was not written', () =>
        endUnusedSession(request, settled.session as { realmId: string; sid: string })
      );
    }
    throw error;
  }
}

/**
 * Run a clean-up step, and log rather than throw when it fails: the request
 * is already failing, or has already done what it was for.
 */
async function bestEffort(
  request: FastifyRequest,
  what: string,
  step: () => Promise<void>
): Promise<void> {
  try {
    await step();
  } catch (error) {
    request.log.warn({ err: error }, `interaction clean-up failed: ${what}`);
  }
}

/**
 * Give the turn of `taken` back after a failure, so the interaction stays at
 * its step and can be answered again. Only while the interaction is live and
 * Redis still holds the state it was taken for: when a write whose reply was
 * lost did land, the record has moved on and the turn of the new state is
 * already there, so nothing is given back.
 */
async function giveTurnBack(
  request: FastifyRequest,
  taken: InteractionRecord,
  idHash: string
): Promise<void> {
  if (interactionDeadline(taken) <= Date.now()) return;
  await bestEffort(request, 'give the turn back', async () => {
    const { redis } = request.server;
    const current = await readInteractionRecord(redis, request.log, taken.realmId, idHash);
    if (current === null || current.ref !== taken.ref || current.revision !== taken.revision) {
      return;
    }
    await returnInteractionTurn(redis, current, idHash, taken.revision);
  });
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
 * QAuth ends it, not the user: the `system` actor (#550).
 */
async function endUnusedSession(
  request: FastifyRequest,
  session: { readonly realmId: string; readonly sid: string }
): Promise<void> {
  await endBrowserSession(request.server, session.realmId, session.sid, 'sign_out', {
    type: 'system',
  });
}

/**
 * Whether the browser session the interaction's sign-in started is still live,
 * for a finish (#963): the session service holds it in the interaction's
 * realm, for the interaction's user, before its end and its idle limit. A
 * sign-out in another tab, a sign-out everywhere, a revoke and a user switch
 * that ended it each leave it not live. A transaction with no session, where
 * nobody authenticated, has none to check. A session service that cannot
 * answer throws: the finish fails, closed, and the turn is given back.
 */
async function signInSessionIsLive(
  request: FastifyRequest,
  taken: InteractionRecord
): Promise<boolean> {
  const { sid, userId } = taken.transaction;
  if (sid === undefined) return true;
  const session = await request.server.sessionService.get({ realmId: taken.realmId, sid });
  return session !== null && session.userId === userId;
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
      signInTransaction: taken.signInTransaction,
      revision: taken.revision,
      // Written only by `createInteraction`, from `clientDisplay`'s output.
      ...(taken.client === undefined ? {} : { client: taken.client as unknown as ClientDisplay }),
    })
  );
  // The engine may take a while (a password hash): an interaction that
  // expired meanwhile is not answered. The turn stays taken; the sweep reports it.
  if (interactionDeadline(taken) <= Date.now()) refuse(request, 'expired');
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
    // The request completes under the session the sign-in started: one that
    // has ended since is refused before anything ends (#963). Nothing is
    // written, so the turn is given back.
    if (!(await signInSessionIsLive(request, taken))) refuse(request, 'session_ended');
    const owned = await deleteInteraction(redis, taken, bound.idHash);
    settled.done = true;
    // The sweep claimed it first and reports it expired: it does not finish.
    if (!owned) refuse(request, 'expired');
    const secrets = nextFlowSecrets(bound.secrets, { remove: bound.secret });
    setFlowCookie(reply, secrets, env.INTERACTION_TTL);
    await answered('finished', taken);
    return {
      kind: 'finished',
      request: taken.request,
      transaction: taken.transaction,
      continuation: { secrets, expiresAt: taken.expiresAt },
    };
  }

  if (decision.kind === 'step') {
    const next: InteractionRecord = {
      ...taken,
      step: interactionStepSchema.parse(decision.step),
      personal: decision.personal ?? {},
      transaction: { ...taken.transaction, amr: withAmr(taken.transaction.amr, decision.amr) },
      ...(decision.signInTransaction === undefined
        ? {}
        : {
            // The engine's own type, read-only; the record's schema checks it
            // again when the state is written.
            signInTransaction: decision.signInTransaction as InteractionRecord['signInTransaction'],
          }),
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
  const step = decision.step === undefined ? undefined : interactionStepSchema.parse(decision.step);
  if (taken.transaction.userId !== undefined && taken.transaction.userId !== signIn.userId) {
    // An engine bug, never a user's doing: the user switch starts a new
    // interaction. Thrown before anything is written: the turn is given back
    // and the interaction stays with the first user.
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
  // Signed now, with the realm's cookie key from the signer (#493): a signer
  // that cannot answer fails the answer here, before the record is bound to a
  // new secret, and the session just created ends with the turn given back.
  const sessionCookie = await sessionCookieHeader(request.server, session);
  const proved: InteractionTransaction = {
    userId: signIn.userId,
    sid: session.sid,
    authTime: session.authTime,
    amr: withAmr(taken.transaction.amr, signIn.amr),
  };
  if (step === undefined) {
    // The sign-in finishes the interaction (#616): it ends as a finish does,
    // under the session just created, whose cookie goes with the answer.
    const owned = await deleteInteraction(redis, taken, bound.idHash);
    settled.done = true;
    // The sweep claimed it first and reports it expired: the session ends
    // with the refusal, and nothing finishes.
    if (!owned) refuse(request, 'expired');
    settled.session = undefined;
    reply.header('Set-Cookie', sessionCookie);
    const secrets = nextFlowSecrets(bound.secrets, { remove: bound.secret });
    setFlowCookie(reply, secrets, env.INTERACTION_TTL);
    await answered('finished', { ...taken, transaction: proved });
    await endReplacedSession(request, taken, session.sid);
    return {
      kind: 'finished',
      request: taken.request,
      transaction: proved,
      continuation: { secrets, expiresAt: taken.expiresAt },
    };
  }
  const secret = mintFlowSecret();
  const next: InteractionRecord = {
    ...taken,
    step,
    personal: decision.personal ?? {},
    transaction: proved,
    // The sign-in is complete: a later one in this interaction starts afresh.
    signInTransaction: null,
    flowBinding: flowBindingOf(secret),
    revision: taken.revision + 1,
  };
  const written = await writeInteractionState(redis, bound.idHash, next);
  settled.done = true;
  if (!written) refuse(request, 'expired');
  settled.session = undefined;
  // Both cookies together, before anything else can fail: the record is now
  // bound to the new secret, and a browser without it could not go on.
  reply.header('Set-Cookie', sessionCookie);
  setFlowCookie(
    reply,
    nextFlowSecrets(bound.secrets, { remove: bound.secret, add: secret }),
    env.INTERACTION_TTL
  );
  await answered('authenticated', next);
  await endReplacedSession(request, taken, session.sid);
  return { kind: 'step', view: viewOf(next) };
}

/**
 * A second authentication in one interaction (step-up) replaces the session
 * the first created: the browser's cookie no longer names it, so it ends.
 */
async function endReplacedSession(
  request: FastifyRequest,
  taken: InteractionRecord,
  sid: string
): Promise<void> {
  const replaced = taken.transaction.sid;
  if (replaced !== undefined && replaced !== sid) {
    await bestEffort(request, 'end the session a later authentication replaced', () =>
      endUnusedSession(request, { realmId: taken.realmId, sid: replaced })
    );
  }
}

/**
 * {@link deleteInteraction} for a cancel or a user switch that holds the
 * turn. When the delete fails (Redis briefly down), the turn is given back,
 * so the interaction is left as it was rather than live and unanswerable.
 */
async function deleteTaken(
  request: FastifyRequest,
  taken: InteractionRecord,
  idHash: string
): Promise<boolean> {
  try {
    return await deleteInteraction(request.server.redis, taken, idHash);
  } catch (error) {
    await giveTurnBack(request, taken, idHash);
    throw error;
  }
}

/**
 * End an interaction at the request of the browser that started it: the
 * record is taken, its secret leaves the flow cookie, and the cancel is
 * audited. The caller sends the client `access_denied` (#616, #628).
 *
 * @param proof - the CSRF value of the current step view, which the
 *   Interaction API's cancel carries (#616); a value that is not it is
 *   refused as {@link answerInteraction} refuses one. Absent for a caller that
 *   checked the request itself, such as this module's tests.
 * @throws {InteractionExpiredError} as {@link answerInteraction}
 */
export async function cancelInteraction(
  request: FastifyRequest,
  reply: FastifyReply,
  id: unknown,
  proof?: { readonly csrf: unknown }
): Promise<InteractionCancelResult> {
  const bound = await locateBound(request, id);
  if (proof !== undefined && !matchesInteractionCsrf(bound.record, proof.csrf)) {
    await refuseForbidden(request, 'csrf', bound.record);
  }
  const taken = await takeBound(request, bound);
  if (taken === null) return { kind: 'stale' };
  // The sweep claimed it first and reports it expired: it is not cancelled.
  if (!(await deleteTaken(request, taken, bound.idHash))) refuse(request, 'expired');
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

/** Who a user switch leaves, and the sessions of theirs the interaction holds. */
interface SwitchedUser {
  readonly userId: string;
  readonly sids: readonly string[];
}

/**
 * The account a "Not you?" switch leaves (#896, #964): the account the screen
 * shows, and no other. That is the user who signed in during the interaction
 * or the one the transaction is for (a consent for the signed-in browser,
 * #628); while nobody has, the user the sign-in's first factor proved, else
 * the account the identifier the person gave names. Its sessions the record
 * holds: the transaction's, and the carried-in one when it is that account's.
 * A carried session of another account stays: the screen does not show it,
 * whether someone else signed in over it during the interaction or the person
 * gave another identifier. `undefined` when the record holds no session of the
 * account shown, or the screen shows none yet.
 *
 * The identifier is looked up only when the interaction carried a session in
 * and nobody has signed in during it: otherwise the record holds no session
 * the lookup could match. It is the lookup the sign-in engine makes for that
 * identifier (`findByIdentifier`), so a shown identifier names the account a
 * sign-in with it would.
 */
async function switchedUserOf(
  request: FastifyRequest,
  record: InteractionRecord
): Promise<SwitchedUser | undefined> {
  const { userId, sid } = record.transaction;
  const carried = record.carriedSession;
  const shown = userId ?? (carried === undefined ? undefined : await signInUserOf(request, record));
  if (shown === undefined) return undefined;
  const sids = new Set<string>();
  if (userId !== undefined && sid !== undefined) sids.add(sid);
  if (carried !== undefined && carried.userId === shown) sids.add(carried.sid);
  return sids.size === 0 ? undefined : { userId: shown, sids: [...sids] };
}

/**
 * The user the sign-in in progress shows, before it completes: the one its
 * first factor proved, else the one whose password credential holds the
 * identifier it was given, if any. `undefined` before the sign-in has an
 * identifier, as at a discoverable passkey.
 */
async function signInUserOf(
  request: FastifyRequest,
  record: InteractionRecord
): Promise<string | undefined> {
  const signIn = record.signInTransaction;
  if (signIn === null) return undefined;
  if (signIn.subject !== undefined) return signIn.subject;
  if (signIn.identifier === undefined) return undefined;
  const credential = await request.server.repositories.userCredentials.findByRealmProviderSub(
    record.realmId,
    PASSWORD_PROVIDER_TYPE,
    signIn.identifier
  );
  return credential?.userId;
}

/**
 * End the browser sessions a "Not you?" switch leaves behind (#896, #964):
 * those of the account the screen shows ({@link switchedUserOf}), whether a
 * sign-in during the interaction started them or the interaction started for
 * an already signed-in browser and carried its session in, and the session
 * the browser's cookie names when that is a later one of the same account,
 * such as a sign-in again in another tab. Kept, any of them would sign the
 * browser in as that account wherever the person goes next, should they
 * abandon the new ceremony: on a shared device, the next person or the next
 * client would get the previous user's session. That is the common "Not
 * you?": the screen names the signed-in user, and someone else is at the
 * keyboard. A session of an account the screen does not show stays: the
 * person did not say they are not that account. The ceremony app's label says
 * that the switch signs out.
 *
 * The account chooser's "Use another account" (a switch at the
 * `select_account` step, #658) ends nothing: it adds an account, and the
 * accounts it lists stay signed in (ADR-019 Decision 3, #548). Today the
 * cookie names one session and is cleared whole; #548, which brings several
 * accounts to one cookie, must make "Not you?" a sign-out of the account it
 * leaves alone (`signOutAccount`): its sessions the cookie lists, not only the
 * active one, and the cookie keeping the others.
 *
 * The person ends them as that account, as a sign-out does: the switch is
 * made by the browser that holds the flow cookie of the interaction, which
 * the carried-in session came from as well. Ended while the switch holds the
 * turn and before the interaction is deleted: when the account lookup or an
 * end fails, or the session service cannot read the cookie's session, the
 * turn is given back and the interaction stays as it was, so a retry switches
 * again; the switch never goes on while a session it ends is still live.
 * Ending a session twice is safe, so a retry ends nothing new.
 *
 * @returns `undefined` when the switch ends nothing ("Use another account",
 *   or no session of the account shown); otherwise the account it left and
 *   whether the browser's cookie names a session this ended, and is to be
 *   cleared
 */
async function endSwitchedSessions(
  request: FastifyRequest,
  taken: InteractionRecord,
  idHash: string
): Promise<{ readonly userId: string; readonly clearCookie: boolean } | undefined> {
  if (taken.step.name === SELECT_ACCOUNT_STEP) return undefined;
  const { realmId } = taken;
  try {
    const switched = await switchedUserOf(request, taken);
    if (switched === undefined) return undefined;
    const { userId, sids } = switched;
    for (const sid of sids) await endFirstUserSession(request, realmId, sid, userId);
    const named = await switchCookieSessionId(request, realmId);
    if (named === null || sids.includes(named)) return { userId, clearCookie: named !== null };
    const later = await request.server.sessionService.get({ realmId, sid: named });
    if (later === null || later.userId !== userId) return { userId, clearCookie: false };
    await endFirstUserSession(request, realmId, named, userId);
    return { userId, clearCookie: true };
  } catch (error) {
    await giveTurnBack(request, taken, idHash);
    throw error;
  }
}

/** End one of the left user's sessions at a user switch: a sign-out by that user. */
async function endFirstUserSession(
  request: FastifyRequest,
  realmId: string,
  sid: string,
  userId: string
): Promise<void> {
  await endBrowserSession(
    request.server,
    realmId,
    sid,
    'sign_out',
    { type: 'user', id: userId },
    userId
  );
}

/**
 * The session the browser's session cookie names at a user switch, read as
 * `/auth/logout` reads it, or `null` when it names none that verifies. Best
 * effort (#493): the cookie verifies only with the realm's cookie keys, and a
 * signer this process cannot reach must not fail a switch. Then this is
 * `null`, logged: the sessions the interaction holds still end, the cookie
 * stays, and the next page that reads it clears it if its session has ended.
 */
async function switchCookieSessionId(
  request: FastifyRequest,
  realmId: string
): Promise<string | null> {
  try {
    return await verifySessionCookie(
      request.server,
      realmId,
      readCookie(request, SESSION_COOKIE_NAME)
    );
  } catch (error) {
    request.log.warn(
      { reason: error instanceof Error ? error.name : 'unknown_error' },
      'the session cookie could not be checked at a user switch; it stays, and only the sessions the interaction held were ended'
    );
    return null;
  }
}

/**
 * The user switch ("Not you?", "Use another account"; #619, #658): end this
 * interaction and start a new one for the same authorization request, at the
 * identifier step, bound to a new flow secret that replaces this one's.
 * Nothing proved here carries over (ADR-017, one subject per transaction):
 * the new transaction is empty, and the new interaction carries no session.
 *
 * Which sessions end depends on the step the switch is made at (#964):
 *
 * - "Not you?", at any step but the account chooser: the sessions of the
 *   account the screen shows end, and no other account's, as a sign-out by
 *   that account. That is the session a sign-in during the interaction
 *   started (#896); the browser session the interaction started for
 *   (`carriedSession`: a consent or a sign-in again for an already signed-in
 *   browser), when the screen shows its account: the consent's user, or,
 *   while nobody has signed in during it, the account the sign-in's first
 *   factor proved or its identifier names; and the session the browser's
 *   cookie names when it is a later one of that account. The cookie is
 *   cleared when it names one of them, and `interaction.cancelled` records
 *   it (`sessionEnded`), about that account.
 * - "Use another account", at the `select_account` step: no session ends.
 *
 * A switch while the screen shows no account with a session the interaction
 * holds (a browser that was not signed in, before anyone signed in; or
 * another identifier than the carried-in account's) ends no session. The old id gets the generic expired
 * answer from now on. The new interaction keeps the request's absolute
 * expiry: one authorization request has one lifetime, and switching never
 * extends it.
 *
 * No Interaction API operation calls this yet (#619). The route that does
 * must check the realm origin and the current step's CSRF value first, as
 * the answer and cancel routes do: a switch can sign the browser out of the
 * session it was signed in with before the interaction, so a cross-site or
 * replayed request must not reach it.
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
  // The left user's sessions end first. When the sweep claimed the
  // interaction meanwhile, they stay ended: the person asked to leave them,
  // and the cookie that names one is cleared on its next read.
  const ended = await endSwitchedSessions(request, taken, bound.idHash);
  if (!(await deleteTaken(request, taken, bound.idHash))) refuse(request, 'expired');
  if (ended?.clearCookie === true) clearSessionCookie(reply);
  await emitInteractionEvent(
    request,
    taken,
    'urn:qauth:event:interaction.cancelled:v1-rc.0',
    {
      interaction: taken.ref,
      step: taken.step.name,
      reason: 'user_switch',
      ...(ended === undefined ? {} : { sessionEnded: true }),
    },
    ended?.userId ?? taken.transaction.userId ?? null
  );
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
