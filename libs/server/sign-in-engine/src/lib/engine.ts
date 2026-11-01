import {
  createInteractionMapper,
  isStepName,
  type OfferedStep,
  type ReadAnswer,
  STEP_NAMES,
  STEP_URNS,
  StepAnswerError,
  type StepErrorCode,
  type StepName,
  stepNameOfUrn,
  type StepOffer,
  transactionAmr,
} from '@qauth-labs/server-step-grammar';

import {
  factorStrength,
  FIRST_FACTOR_STRENGTH,
  provenFactorStrength,
  provesMfa,
  secondFactorRequired,
  strongestBoundFactor,
} from './factors';
import { type HookRound, NO_LADDER, type SignInHooks } from './hooks';
import { readIdentifier } from './identifier';
import {
  type AccountDirectory,
  type Clock,
  type IdentifierDigest,
  MFA_MODES,
  type MfaPolicy,
  type MfaPolicyReader,
  type PasswordVerifier,
  type SignInAccount,
  type SignInAuditReason,
  type SignInAuditRecord,
  SYSTEM_CLOCK,
} from './ports';
import type { RoundAnswer, RoundContext, RoundResult } from './round';
import type {
  AnyStepHandler,
  ProvedAccount,
  StepHandler,
  StepRound,
  StepVerdict,
} from './steps/handler';
import { createIdentifierStep } from './steps/identifier';
import { createPasswordStep } from './steps/password';
import { fromStore, SignInStoreUnavailableError } from './store';
import {
  freezeTransaction,
  newSignInTransaction,
  readSignInTransaction,
  SIGN_IN_TRANSACTION_CLOCK_SKEW_MS,
  SIGN_IN_TRANSACTION_MAX_AGE_MS,
  type SignInTransaction,
} from './transaction';

/**
 * THE SIGN-IN ENGINE (PRO-09, #614; ADR-017 Decisions 4 and 7, ADR-019
 * Decision 6): one engine decides every step of a sign-in, whatever the
 * transport. The Interaction API (browser ceremonies) and the FiPA
 * authorization challenge endpoint (native apps) each call
 * {@link SignInEngine.advance} once per round, and map its answer onto their
 * wire with the step grammar's mappers. The flow is graphed in
 * `graphs/flows/core/sign-in/flow.yaml`.
 *
 * Each round runs the rules of ADR-017 Decision 4 in order; the first unmet
 * one produces the answer. The transport's own checks (rule 1) and client
 * authentication (rule 2) come before the call.
 *
 * 3. The MFA policy is read (a policy that cannot be read refuses the round),
 *    then the limiters' hook.
 * 4. The transport's request checks' hook.
 * 5. The bot challenge's hook: a due challenge comes before every other step.
 * 6. The identifier: the request's `login_hint`, else an answer's. The first
 *    one is fixed; a different one ends the transaction (`subject_mismatch`).
 *    With none, the identifier step, or a discoverable first factor before it
 *    once #651 adds one.
 * 7. The first factor, offered alike to every account: the password here, and
 *    from #651 a passkey beside it. Its answer is reserved on the ladder's hook
 *    before it is verified.
 * 8. After a first factor: the downgrade rule (the account's strongest bound
 *    factor, a disabled one included), then the MFA policy just read.
 * 9. Complete: the transport mints the session or the code.
 *
 * Until a factor succeeds, nothing the engine answers depends on the account:
 * an unknown identifier, a password-only, passkey-only, disabled or locked
 * account and an unverified one under `REQUIRE_VERIFIED_ACCOUNT` get the same
 * offer, in body and in timing. Every round answers no earlier than
 * {@link SIGN_IN_MIN_RESPONSE_TIME_MS} after it arrived.
 *
 * An answer is verified only when its step is the one the engine asks for
 * next (an eager answer); any other is ignored, with no verification and no
 * failure counted.
 */

/** Every round answers no earlier than this after it arrived: `MIN_RESPONSE_TIME_MS.LOGIN` (ADR-017 Decision 7). */
export const SIGN_IN_MIN_RESPONSE_TIME_MS = 500;

/** What the engine is built from. */
export interface SignInEngineDependencies {
  readonly accounts: AccountDirectory;
  readonly passwords: PasswordVerifier;
  /** The realm's and the client's MFA policy, read on every round. */
  readonly policy: MfaPolicyReader;
  readonly identifierDigest: IdentifierDigest;
  /** `REQUIRE_VERIFIED_ACCOUNT`, as the deployment set it. */
  readonly requireVerifiedAccount: boolean;
  readonly hooks?: SignInHooks;
  /**
   * The steps later issues add (passkeys, TOTP, the bot challenge), in the
   * order they are preferred. The identifier and password steps are the
   * engine's own.
   */
  readonly steps?: readonly AnyStepHandler[];
  readonly clock?: Clock;
  /**
   * Told when a store refused a round, or when settling a ladder reservation
   * failed (which changes no answer), for the transport's log.
   */
  readonly onUnavailable?: (error: SignInStoreUnavailableError) => void;
}

/** The engine. */
export interface SignInEngine {
  /**
   * Run one round of a sign-in: `transaction` is what the last round
   * returned (`null` for round 0), `answer` the round's answer, if any.
   * The returned transaction is the one to keep. A completed sign-in, a
   * redirect and a refusal that ends the transaction return `null` in its
   * place. A failed audit write rejects.
   *
   * The transaction is not sealed, so the engine trusts what it says once it
   * is well formed, of `context`'s realm and client, and young enough: the
   * transport must keep it server-side under an unguessable handle bound to
   * the realm and the client, and never take one back from the client.
   */
  advance(
    transaction: SignInTransaction | null,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult>;
}

/**
 * The steps whose answer may carry the identifier: the identifier step, and
 * the password step for a page that asks for both at once. An answer to any
 * other step the engine did not ask for is ignored, its `login_hint` too.
 */
const STEPS_WITH_LOGIN_HINT: ReadonlySet<StepName> = new Set<StepName>(['identifier', 'password']);

/** An identifier HMAC: HMAC-SHA-256, base64url without padding. */
const IDENTIFIER_HMAC_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const TRANSACTION_ENDED: RoundResult = Object.freeze({
  kind: 'refused' as const,
  reason: 'transaction_ended' as const,
  transaction: null,
});

/** The steps no role may take: an email code is never an authenticator (ADR-017 Decision 5). */
const NEVER_A_FACTOR: readonly StepName[] = Object.freeze(['email_code']);

/** Check the handlers a deployment adds, and order every handler by role. */
function buildHandlers(deps: SignInEngineDependencies) {
  const identifier = createIdentifierStep();
  const password = createPasswordStep({
    accounts: deps.accounts,
    passwords: deps.passwords,
    ladder: deps.hooks?.ladder ?? NO_LADDER,
    requireVerifiedAccount: deps.requireVerifiedAccount,
    ...(deps.onUnavailable === undefined ? {} : { onSettleFailure: deps.onUnavailable }),
  });
  const extra = deps.steps ?? [];
  const byStep = new Map<StepName, AnyStepHandler>([
    ['identifier', identifier],
    ['password', password],
  ]);
  for (const handler of extra) {
    if (!isStepName(handler.step)) throw new Error(`sign-in engine: unknown step ${handler.step}`);
    if (byStep.has(handler.step)) {
      throw new Error(`sign-in engine: step ${handler.step} has a handler already`);
    }
    if (NEVER_A_FACTOR.includes(handler.step)) {
      throw new Error(`sign-in engine: ${handler.step} is never a sign-in step`);
    }
    if ((handler.role === 'challenge') !== (handler.step === 'captcha')) {
      throw new Error('sign-in engine: the bot challenge is the captcha step, and only it');
    }
    if (handler.role === 'identifier') {
      throw new Error('sign-in engine: the identifier step is the engine’s own');
    }
    if (
      (handler.role === 'first_factor' || handler.role === 'second_factor') &&
      handler.factor === undefined
    ) {
      throw new Error(`sign-in engine: factor step ${handler.step} names no factor`);
    }
    if (
      handler.role === 'first_factor' &&
      handler.factor !== undefined &&
      FIRST_FACTOR_STRENGTH[handler.factor] === undefined
    ) {
      throw new Error(`sign-in engine: ${handler.factor} is not a first factor`);
    }
    if (handler.discoverable === true && handler.role !== 'first_factor') {
      throw new Error(`sign-in engine: only a first factor is discoverable (${handler.step})`);
    }
    byStep.set(handler.step, handler);
  }
  const ofRole = (role: AnyStepHandler['role']) => extra.filter((handler) => handler.role === role);
  const firstFactors = [...ofRole('first_factor'), password];
  return Object.freeze({
    byStep,
    identifier,
    challenge: ofRole('challenge')[0],
    // The first factors that need an identifier (the password) come before
    // the discoverable ones once the transaction holds one (ADR-017
    // Decision 4: "the same password-required shape for every account, with
    // webauthn_get offered").
    firstFactors: Object.freeze([
      ...firstFactors.filter((handler) => handler.discoverable !== true),
      ...firstFactors.filter((handler) => handler.discoverable === true),
    ]),
    discoverable: Object.freeze(firstFactors.filter((handler) => handler.discoverable === true)),
    secondFactors: Object.freeze(ofRole('second_factor')),
  });
}

/** A policy the reader returned, checked: a value outside the known modes is a store fault. */
function checkedPolicy(policy: unknown): MfaPolicy {
  const modes = MFA_MODES as readonly unknown[];
  const value = policy as Partial<MfaPolicy> | null;
  if (value === null || typeof value !== 'object') {
    throw new SignInStoreUnavailableError('policy', new Error('not a policy'));
  }
  if (!modes.includes(value.realm) || !modes.includes(value.client)) {
    throw new SignInStoreUnavailableError('policy', new Error('unknown MFA mode'));
  }
  return { realm: value.realm as MfaPolicy['realm'], client: value.client as MfaPolicy['client'] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The transaction a round works on: what a refusal hands back is as far as the round took it. */
interface RoundState {
  transaction: SignInTransaction;
}

/** Build a sign-in engine. */
export function createSignInEngine(deps: SignInEngineDependencies): SignInEngine {
  const handlers = buildHandlers(deps);
  const hooks = deps.hooks ?? {};
  const clock = deps.clock ?? SYSTEM_CLOCK;
  // The step grammar's one answer reader, shared with both transports.
  const grammar = createInteractionMapper();
  const factorOf = (step: StepName) => handlers.byStep.get(step)?.factor;

  async function advance(
    stored: SignInTransaction | null,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult> {
    const startedAt = context.receivedAt ?? clock.now();
    try {
      return await round(stored, answer, context);
    } finally {
      // The timing floor, success or failure: no round tells its outcome by
      // its time.
      const left = SIGN_IN_MIN_RESPONSE_TIME_MS - (clock.now() - startedAt);
      if (left > 0) await clock.sleep(left);
    }
  }

  /**
   * End a transaction the round may not use, before anything in it is read.
   * The record names nobody: nothing in such a transaction can be trusted to
   * name the person. It names the answered step when the engine has a
   * handler for it, else the identifier step, where every transaction starts.
   */
  async function endUnusable(
    answer: RoundAnswer | null,
    context: RoundContext,
    reason: 'transaction_invalid' | 'transaction_expired'
  ): Promise<RoundResult> {
    const named =
      answer !== null && typeof answer.step === 'string' ? stepNameOfUrn(answer.step) : undefined;
    const step = named !== undefined && handlers.byStep.has(named) ? named : 'identifier';
    await context.audit(Object.freeze({ outcome: 'ended', step, reason }));
    return TRANSACTION_ENDED;
  }

  async function round(
    stored: SignInTransaction | null,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult> {
    const now = clock.now();
    const found =
      stored === null
        ? newSignInTransaction({
            realmId: context.realm.id,
            clientId: context.client.id,
            createdAt: now,
          })
        : readSignInTransaction(stored);
    // A transaction that is not well formed ends: nothing in it can be trusted.
    if (found === null) return endUnusable(answer, context, 'transaction_invalid');
    // Nor can one of another realm or client, or one that starts in the future.
    if (
      found.realmId !== context.realm.id ||
      found.clientId !== context.client.id ||
      found.createdAt > now + SIGN_IN_TRANSACTION_CLOCK_SKEW_MS
    ) {
      return endUnusable(answer, context, 'transaction_invalid');
    }
    if (now - found.createdAt > SIGN_IN_TRANSACTION_MAX_AGE_MS) {
      return endUnusable(answer, context, 'transaction_expired');
    }
    // A subject without an identifier comes only from a discoverable factor.
    if (
      found.subject !== undefined &&
      found.identifier === undefined &&
      !found.verified.some((step) => handlers.byStep.get(step.step)?.discoverable === true)
    ) {
      return endUnusable(answer, context, 'transaction_invalid');
    }
    const state: RoundState = { transaction: found };
    try {
      return await rules(state, answer, context);
    } catch (error) {
      if (!(error instanceof SignInStoreUnavailableError)) throw error;
      deps.onUnavailable?.(error);
      return Object.freeze({
        kind: 'refused',
        reason: 'unavailable',
        transaction: freezeTransaction(state.transaction),
      });
    }
  }

  async function rules(
    state: RoundState,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult> {
    const found = state.transaction;
    const realmId = context.realm.id;
    const clientId = context.client.id;
    const served = new Set<StepName>(context.serves ?? STEP_NAMES);
    const answeredName =
      answer !== null && typeof answer.step === 'string' ? stepNameOfUrn(answer.step) : undefined;
    /** The round's answer while no step has taken it. */
    const turn: { pending: { readonly name: StepName; readonly answer: RoundAnswer } | null } = {
      pending:
        answer !== null && answeredName !== undefined ? { name: answeredName, answer } : null,
    };

    let hmac: Promise<string> | undefined;
    const identifierHmac = (): Promise<string> => {
      const { identifier } = state.transaction;
      if (identifier === undefined) throw new Error('sign-in engine: no identifier to digest');
      hmac ??= fromStore('identifierDigest', async () => {
        const digest = await deps.identifierDigest({ realmId, identifier });
        if (typeof digest !== 'string' || !IDENTIFIER_HMAC_PATTERN.test(digest)) {
          throw new Error('not an identifier HMAC');
        }
        return digest;
      });
      return hmac;
    };
    const stepRound = (): StepRound =>
      Object.freeze({
        realmId,
        clientId,
        transaction: state.transaction,
        ...(state.transaction.identifier === undefined
          ? {}
          : { identifier: state.transaction.identifier }),
        identifierHmac,
      });

    /**
     * Write one audit record. The person is named by the transaction's
     * subject once a factor fixed one, by the identifier's HMAC before; with
     * neither (a bot challenge or a discoverable factor refused before any
     * identifier), the record names nobody, and is still written.
     */
    const audit = async (
      outcome: SignInAuditRecord['outcome'],
      step: StepName,
      reason?: SignInAuditReason
    ): Promise<void> => {
      const base = { outcome, step, ...(reason === undefined ? {} : { reason }) };
      let record: SignInAuditRecord;
      const { subject, identifier } = state.transaction;
      if (subject !== undefined) record = { ...base, userId: subject };
      else if (identifier !== undefined)
        record = { ...base, identifierHmac: await identifierHmac() };
      else record = base;
      await context.audit(Object.freeze(record));
    };

    const ended = async (step: StepName, reason: SignInAuditReason): Promise<RoundResult> => {
      await audit('ended', step, reason);
      return TRANSACTION_ENDED;
    };
    const throttled = (retryAfterSeconds: number): RoundResult =>
      Object.freeze({
        kind: 'refused',
        reason: 'throttled',
        retryAfterSeconds,
        transaction: freezeTransaction(state.transaction),
      });
    /** Refuse a malformed answer to `step`, audited: nothing was verified or counted. */
    const invalidAnswer = async (step: StepName): Promise<RoundResult> => {
      await audit('refused', step, 'invalid_answer');
      return Object.freeze({
        kind: 'refused',
        reason: 'invalid_answer',
        transaction: freezeTransaction(state.transaction),
      });
    };
    /**
     * The step a refusal of the whole round names: the answered one when the
     * engine has a handler for it, else the identifier step, where every
     * transaction starts. Never a step only the client named.
     */
    const roundStep = (): StepName =>
      answeredName !== undefined && handlers.byStep.has(answeredName) ? answeredName : 'identifier';
    const redirect = (reason: 'step_not_available' | 'request'): RoundResult =>
      Object.freeze({ kind: 'redirect', reason, transaction: null });

    /** The offer of `steps`, the first one current, with their params for this round. */
    const offerOf = async (
      steps: readonly AnyStepHandler[],
      options: { readonly preferred?: boolean } = {}
    ): Promise<StepOffer> => {
      const current = stepRound();
      const offered = await Promise.all(
        steps.map(async (handler) => ({
          step: handler.step,
          params: await (handler as StepHandler).params(current),
        }))
      );
      const [first, ...alternatives] = offered;
      if (first === undefined) throw new Error('sign-in engine: an empty offer');
      return Object.freeze({
        current: Object.freeze(first),
        alternatives: Object.freeze(alternatives.map((step) => Object.freeze(step))),
        // A step that one of its alternatives may replace (a discoverable
        // passkey before any identifier) is preferred, not required.
        ...(options.preferred === true && alternatives.length > 0 ? { required: false } : {}),
      } as StepOffer);
    };
    const offerStep = (offer: StepOffer, error?: StepErrorCode): RoundResult => {
      const current =
        error === undefined
          ? offer.current
          : Object.freeze({ ...offer.current, error } as StepOffer['current']);
      const handler = handlers.byStep.get(current.step) as StepHandler | undefined;
      return Object.freeze({
        kind: 'step',
        transaction: freezeTransaction(state.transaction),
        offer: Object.freeze({ ...offer, current }),
        personal: Object.freeze({ ...(handler?.personal?.(stepRound()) ?? {}) }),
      });
    };
    /** Whether the round's answer is to one of `offer`'s steps. */
    const answers = (offer: StepOffer): boolean => {
      const { pending } = turn;
      return (
        pending !== null &&
        [offer.current.step, ...offer.alternatives.map((step) => step.step)].includes(pending.name)
      );
    };
    /** Read the pending answer against `offer` with the step grammar; `null` when it is malformed. */
    const readPending = (offer: StepOffer): ReadAnswer | null => {
      const { pending } = turn;
      if (pending === null) throw new Error('sign-in engine: no answer to read');
      try {
        return grammar.readAnswer(
          offer,
          STEP_URNS[pending.name],
          pending.answer.fields,
          pending.answer.encoding ?? 'form'
        );
      } catch (error) {
        if (error instanceof StepAnswerError) return null;
        throw error;
      }
    };
    /** Offer `offer` again with the refused step current and its error; the others stay alternatives. */
    const refusedOffer = (offer: StepOffer, step: StepName): StepOffer => {
      const all = [offer.current, ...offer.alternatives];
      const refused = all.find((offered) => offered.step === step);
      if (refused === undefined) throw new Error(`sign-in engine: ${step} was not offered`);
      const others = all.filter((offered) => offered.step !== step);
      // A preferred step refused stays preferred: its alternatives may still replace it.
      const preferred = offer.required === false && offer.current.step === step;
      return Object.freeze({
        current: Object.freeze({
          step: refused.step,
          params: refused.params,
        } as StepOffer['current']),
        alternatives: Object.freeze(
          others.map((offered) => Object.freeze({ step: offered.step, params: offered.params }))
        ) as StepOffer['alternatives'],
        ...(preferred && others.length > 0 ? { required: false } : {}),
      });
    };
    const refuseAnswer = async (
      offer: StepOffer,
      step: StepName,
      error: StepErrorCode,
      reason: SignInAuditReason
    ): Promise<RoundResult> => {
      await audit('refused', step, reason);
      return offerStep(refusedOffer(offer, step), error);
    };

    /**
     * A factor proved an account. The engine checks what every handler must
     * have checked (an enabled account, verified under the gate) and refuses
     * it like a wrong answer if not, so no step it adds later can fix a
     * disabled user as the subject. Then one subject per transaction, and the
     * step and the time are recorded.
     */
    const prove = async (
      offer: StepOffer,
      account: ProvedAccount,
      read: ReadAnswer
    ): Promise<RoundResult | null> => {
      // Another user's proof ends the transaction, whatever that user's state.
      const { subject } = state.transaction;
      if (subject !== undefined && subject !== account.userId) {
        return ended(read.step, 'subject_mismatch');
      }
      if (!account.enabled) {
        return refuseAnswer(offer, read.step, 'invalid_credentials', 'account_disabled');
      }
      if (!account.verified && deps.requireVerifiedAccount) {
        return refuseAnswer(offer, read.step, 'invalid_credentials', 'email_not_verified');
      }
      state.transaction = {
        ...state.transaction,
        subject: account.userId,
        verified: [
          ...state.transaction.verified,
          { step: read.step, params: read.params } as OfferedStep,
        ],
        authTime: clock.now(),
      };
      await audit('passed', read.step);
      return null;
    };

    /**
     * Verify the pending answer against `offer`, after the step grammar read
     * it. Returns the round's result when the answer ends the round, or
     * `null` when it proved a factor or passed a challenge and the rules go on.
     */
    const verifyPending = async (offer: StepOffer): Promise<RoundResult | null> => {
      const { pending } = turn;
      if (pending === null) throw new Error('sign-in engine: no answer to verify');
      const read = readPending(offer);
      if (read === null) return invalidAnswer(pending.name);
      turn.pending = null;
      const handler = handlers.byStep.get(read.step) as StepHandler;
      const verdict: StepVerdict = await handler.verify(stepRound(), {
        params: read.params,
        answer: read.answer,
      });
      switch (verdict.kind) {
        case 'refused':
          return refuseAnswer(offer, read.step, verdict.error, verdict.audit.reason);
        case 'throttled':
          await audit('refused', read.step, verdict.audit.reason);
          return throttled(verdict.retryAfterSeconds);
        case 'proved':
          if (handler.role !== 'first_factor' && handler.role !== 'second_factor') {
            throw new Error(`sign-in engine: ${read.step} proved an account`);
          }
          return prove(offer, verdict.account, read);
        case 'passed':
          if (handler.role !== 'challenge') throw new Error(`sign-in engine: ${read.step} passed`);
          state.transaction = {
            ...state.transaction,
            verified: [
              ...state.transaction.verified,
              { step: read.step, params: read.params } as OfferedStep,
            ],
          };
          return null;
        default:
          throw new Error(`sign-in engine: ${read.step} answered ${verdict.kind}`);
      }
    };

    // Rule 8's input, read on every round and never kept: a policy that
    // cannot be read refuses the round (ADR-017 Decision 4).
    const policy = checkedPolicy(
      await fromStore('policy', () => deps.policy.read({ realmId, clientId }))
    );

    const hookRound: HookRound = Object.freeze({
      realmId,
      clientId,
      transaction: found,
      ...(turn.pending === null ? {} : { answered: turn.pending.name }),
    });

    // Rule 3: the limiters.
    const { limits, request, botChallenge } = hooks;
    if (limits !== undefined) {
      const verdict = await fromStore('limits', () => limits(hookRound));
      if (verdict.kind === 'throttled') {
        await audit('refused', roundStep(), 'rate_limited');
        return throttled(verdict.retryAfterSeconds);
      }
    }

    // Rule 4: the transport's request checks.
    if (request !== undefined) {
      const verdict = await fromStore('request', () => request(hookRound));
      if (verdict.kind === 'refuse') {
        await audit('refused', roundStep(), 'request_refused');
        return Object.freeze({
          kind: 'refused',
          reason: 'request_refused',
          code: verdict.code,
          transaction: found,
        });
      }
      if (verdict.kind === 'redirect') return redirect('request');
    }

    // Rule 5: a due bot challenge comes before every other step. Any other
    // answer is ignored, so no password is checked while one is due.
    if (botChallenge !== undefined) {
      const verdict = await fromStore('botChallenge', () => botChallenge(hookRound));
      if (verdict.kind === 'due') {
        const challenge = handlers.challenge;
        if (challenge === undefined || !served.has(challenge.step)) {
          return throttled(verdict.retryAfterSeconds);
        }
        const offer = await offerOf([challenge]);
        if (!answers(offer)) return offerStep(offer);
        const result = await verifyPending(offer);
        if (result !== null) return result;
      }
    }

    // Rule 6: the identifier. The request's login_hint first, then an
    // answer's; the first is fixed, and a different one ends the transaction.
    const brought: { readonly identifier: string; readonly step: StepName }[] = [];
    if (context.loginHint !== undefined) {
      const identifier = readIdentifier(context.loginHint);
      if (identifier !== null) brought.push({ identifier, step: 'identifier' });
    }
    if (turn.pending !== null && STEPS_WITH_LOGIN_HINT.has(turn.pending.name)) {
      const fields = turn.pending.answer.fields;
      if (isRecord(fields) && Object.hasOwn(fields, 'login_hint')) {
        const identifier = readIdentifier(fields['login_hint']);
        if (identifier === null) return invalidAnswer(turn.pending.name);
        brought.push({ identifier, step: turn.pending.name });
      } else if (turn.pending.name === 'identifier') {
        return invalidAnswer('identifier');
      }
    }
    const beforeIdentifier = state.transaction;
    const heldBefore = beforeIdentifier.identifier;
    for (const { identifier, step } of brought) {
      if (state.transaction.identifier === undefined) {
        // A discoverable factor fixed the subject without an identifier: one
        // brought now cannot be checked against it, so it ends the
        // transaction.
        if (state.transaction.subject !== undefined) return ended(step, 'subject_mismatch');
        state.transaction = { ...state.transaction, identifier };
      } else if (state.transaction.identifier !== identifier) {
        return ended(step, 'subject_mismatch');
      }
    }

    if (state.transaction.subject === undefined) {
      if (state.transaction.identifier === undefined) {
        // Nobody is named yet: the identifier step, the same for everyone, or
        // a discoverable first factor before it, with the identifier step and
        // the other first factors beside it (ADR-017 Decision 4).
        const discoverable = handlers.discoverable.filter((handler) => served.has(handler.step));
        const others = handlers.firstFactors.filter(
          (handler) => handler.discoverable !== true && served.has(handler.step)
        );
        if (discoverable.length === 0) {
          // No discoverable factor is registered (this issue's shape): the
          // identifier step alone. One is registered, but this transport cannot
          // serve it: the password it can serve, with the identifier step
          // beside it (ADR-017 Decision 4, amended 2026-10-31).
          const steps =
            handlers.discoverable.length === 0
              ? [handlers.identifier]
              : [...others, handlers.identifier];
          return offerStep(await offerOf(steps, { preferred: true }));
        }
        // A password offered here is answered with its login_hint, which
        // the identifier rule above has already taken.
        const offer = await offerOf([...discoverable, ...others, handlers.identifier], {
          preferred: true,
        });
        const pendingName = turn.pending?.name;
        if (!discoverable.some((handler) => handler.step === pendingName)) return offerStep(offer);
        const result = await verifyPending(offer);
        if (result !== null) return result;
      } else {
        if (heldBefore === undefined) {
          // The identifier is fixed together with its audit record: a round
          // that fails before the record is written keeps no identifier, so
          // the next round records it.
          try {
            if (turn.pending?.name === 'identifier') {
              // The identifier step was the one asked for: its answer is read
              // by the grammar like any other, and its handler confirms it.
              const offer = await offerOf([handlers.identifier]);
              const read = readPending(offer);
              if (read === null) {
                state.transaction = beforeIdentifier;
                return await invalidAnswer('identifier');
              }
              turn.pending = null;
              const verdict = await handlers.identifier.verify(stepRound(), {
                params: {},
                answer: read.answer as { login_hint: string },
              });
              if (
                verdict.kind !== 'identified' ||
                verdict.identifier !== state.transaction.identifier
              ) {
                throw new Error(
                  'sign-in engine: the identifier step disagrees with the identifier'
                );
              }
            }
            await audit('passed', 'identifier');
          } catch (error) {
            state.transaction = beforeIdentifier;
            throw error;
          }
        }
        // The same identifier again: nothing more to do with that answer.
        if (turn.pending?.name === 'identifier') turn.pending = null;

        // Rule 7: the first factor, offered alike to every account until one
        // succeeds. Only an answer to it is verified; any other is ignored.
        const firstFactors = handlers.firstFactors.filter((handler) => served.has(handler.step));
        if (firstFactors.length === 0) return redirect('step_not_available');
        const offer = await offerOf(firstFactors);
        if (!answers(offer)) return offerStep(offer);
        const result = await verifyPending(offer);
        if (result !== null) return result;
      }
    }

    // Rule 8: after a first factor. The account is read again, every factor
    // included, now that a factor proved it.
    const subject = state.transaction.subject;
    if (subject === undefined) throw new Error('sign-in engine: rule 8 without a subject');
    const readAccount = (): Promise<SignInAccount | null> =>
      fromStore('accounts', () => deps.accounts.findByUserId(realmId, subject));
    const provenAccount = await readAccount();
    if (provenAccount === null || provenAccount.userId !== subject)
      return ended('identifier', 'subject_mismatch');
    if (!provenAccount.enabled) return ended('identifier', 'account_disabled');
    let account: SignInAccount = provenAccount;

    for (;;) {
      const current: SignInAccount = account;
      const verifiedSteps = new Set(state.transaction.verified.map((step) => step.step));
      const candidate = (handler: AnyStepHandler) =>
        served.has(handler.step) &&
        !verifiedSteps.has(handler.step) &&
        (handler.usableBy?.(current) ?? false);
      let needed: AnyStepHandler[] | null = null;
      const strongest = strongestBoundFactor(current);
      if (provenFactorStrength(state.transaction.verified, factorOf) < strongest) {
        // The downgrade rule: only a factor as strong as the strongest bound
        // one, a disabled one included, completes the sign-in.
        needed = handlers.firstFactors.filter(
          (handler) => candidate(handler) && factorStrength(handler.factor) >= strongest
        );
      } else if (secondFactorRequired(policy, current) && !provesMfa(state.transaction.verified)) {
        // The MFA policy: the transaction's amr must carry mfa.
        needed = [...handlers.secondFactors, ...handlers.firstFactors].filter(candidate);
      }
      if (needed === null) break;
      // No step can meet the rule yet, or the transport cannot serve one.
      if (needed.length === 0) return redirect('step_not_available');
      const offer = await offerOf(needed);
      if (!answers(offer)) return offerStep(offer);
      const result = await verifyPending(offer);
      if (result !== null) return result;
      const reread = await readAccount();
      if (reread === null || reread.userId !== subject)
        return ended('identifier', 'subject_mismatch');
      if (!reread.enabled) return ended('identifier', 'account_disabled');
      account = reread;
    }

    // Rule 9: complete. The transport mints the session or the code, and the
    // transaction ends with it.
    const amr = transactionAmr(state.transaction.verified);
    const { authTime, identifier } = state.transaction;
    if (amr === undefined || authTime === undefined) {
      throw new Error('sign-in engine: complete without a factor');
    }
    return Object.freeze({
      kind: 'complete',
      transaction: null,
      signIn: Object.freeze({
        subject,
        ...(identifier === undefined ? {} : { identifier }),
        amr,
        authTime,
      }),
    });
  }

  return Object.freeze({ advance });
}
