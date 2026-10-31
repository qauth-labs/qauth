import {
  createInteractionMapper,
  grammarStep,
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
import type { AnyStepHandler, StepHandler, StepRound, StepVerdict } from './steps/handler';
import { createIdentifierStep } from './steps/identifier';
import { createPasswordStep } from './steps/password';
import { fromStore, SignInStoreUnavailableError } from './store';
import {
  freezeTransaction,
  newSignInTransaction,
  readSignInTransaction,
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
 * 7. The first factor, offered alike to every account: the password here, a
 *    passkey before it from #651. Its answer is reserved on the ladder's hook
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
   * engine's own; a first factor added here is preferred to the password.
   */
  readonly steps?: readonly AnyStepHandler[];
  readonly clock?: Clock;
  /** Told when a store refused a round, for the transport's log. */
  readonly onUnavailable?: (error: SignInStoreUnavailableError) => void;
}

/** The engine. */
export interface SignInEngine {
  /**
   * Run one round of a sign-in: `transaction` is what the last round
   * returned (`null` for round 0), `answer` the round's answer, if any.
   * The returned transaction is the one to keep; a refusal that ends the
   * transaction returns `null` in its place. A failed audit write rejects.
   */
  advance(
    transaction: SignInTransaction | null,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult>;
}

/** The steps whose answer carries an identifier (`login_hint`), from the grammar. */
const STEPS_WITH_LOGIN_HINT: ReadonlySet<StepName> = new Set(
  STEP_NAMES.filter((name) => {
    const shape = (grammarStep(name).answer as { shape?: Record<string, unknown> }).shape;
    return shape !== undefined && Object.hasOwn(shape, 'login_hint');
  })
);

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
    byStep.set(handler.step, handler);
  }
  const ofRole = (role: AnyStepHandler['role']) => extra.filter((handler) => handler.role === role);
  return Object.freeze({
    byStep,
    identifier,
    challenge: ofRole('challenge')[0],
    // A first factor a later issue adds (a passkey) comes before the password.
    firstFactors: Object.freeze([...ofRole('first_factor'), password]),
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

/** Build a sign-in engine. */
export function createSignInEngine(deps: SignInEngineDependencies): SignInEngine {
  const handlers = buildHandlers(deps);
  const hooks = deps.hooks ?? {};
  const clock = deps.clock ?? SYSTEM_CLOCK;
  // The step grammar's one answer reader, shared with both transports.
  const grammar = createInteractionMapper();

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

  async function round(
    stored: SignInTransaction | null,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult> {
    const found = stored === null ? newSignInTransaction() : readSignInTransaction(stored);
    // A transaction the engine did not write ends: nothing in it can be trusted.
    if (found === null) return TRANSACTION_ENDED;
    try {
      return await rules(found, answer, context);
    } catch (error) {
      if (!(error instanceof SignInStoreUnavailableError)) throw error;
      deps.onUnavailable?.(error);
      return Object.freeze({ kind: 'refused', reason: 'unavailable', transaction: found });
    }
  }

  async function rules(
    found: SignInTransaction,
    answer: RoundAnswer | null,
    context: RoundContext
  ): Promise<RoundResult> {
    const realmId = context.realm.id;
    const clientId = context.client.id;
    const served = new Set<StepName>(context.serves ?? STEP_NAMES);
    let transaction = found;
    const answeredName =
      answer !== null && typeof answer.step === 'string' ? stepNameOfUrn(answer.step) : undefined;
    /** The round's answer while no step has taken it. */
    let pending: { readonly name: StepName; readonly answer: RoundAnswer } | null =
      answer !== null && answeredName !== undefined ? { name: answeredName, answer } : null;

    let hmac: Promise<string> | undefined;
    const identifierHmac = (): Promise<string> => {
      const { identifier } = transaction;
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
        transaction,
        ...(transaction.identifier === undefined ? {} : { identifier: transaction.identifier }),
        identifierHmac,
      });

    /** Write one audit record, naming the user once resolved and the identifier HMAC before. */
    const audit = async (
      outcome: SignInAuditRecord['outcome'],
      step: StepName,
      reason?: SignInAuditReason,
      userId?: string
    ): Promise<void> => {
      const base = { outcome, step, ...(reason === undefined ? {} : { reason }) };
      let record: SignInAuditRecord;
      if (userId !== undefined) record = { ...base, userId };
      else if (transaction.identifier !== undefined) {
        record = { ...base, identifierHmac: await identifierHmac() };
      } else return; // nobody to name: a bot challenge before any identifier
      await context.audit(Object.freeze(record));
    };

    const ended = async (step: StepName, reason: SignInAuditReason): Promise<RoundResult> => {
      await audit('ended', step, reason, transaction.subject);
      return TRANSACTION_ENDED;
    };
    const throttled = (retryAfterSeconds: number): RoundResult =>
      Object.freeze({
        kind: 'refused',
        reason: 'throttled',
        retryAfterSeconds,
        transaction: found,
      });
    const invalidAnswer = (): RoundResult =>
      Object.freeze({ kind: 'refused', reason: 'invalid_answer', transaction: found });
    const redirect = (reason: 'step_not_available' | 'request'): RoundResult =>
      Object.freeze({ kind: 'redirect', reason, transaction: freezeTransaction(transaction) });

    /** The offer of `steps`, the first one current, with their params for this round. */
    const offerOf = async (
      steps: readonly AnyStepHandler[],
      options: { readonly preferred?: boolean } = {}
    ): Promise<StepOffer> => {
      const round = stepRound();
      const offered = await Promise.all(
        steps.map(async (handler) => ({
          step: handler.step,
          params: await (handler as StepHandler).params(round),
        }))
      );
      const [current, ...alternatives] = offered;
      if (current === undefined) throw new Error('sign-in engine: an empty offer');
      return Object.freeze({
        current: Object.freeze(current),
        alternatives: Object.freeze(alternatives.map((step) => Object.freeze(step))),
        // A step that one of its alternatives may replace (a passkey offered
        // before the first factor) is preferred, not required.
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
        transaction: freezeTransaction(transaction),
        offer: Object.freeze({ ...offer, current }),
        personal: Object.freeze({ ...(handler?.personal?.(stepRound()) ?? {}) }),
      });
    };
    /** Whether the round's answer is to one of `offer`'s steps. */
    const answers = (offer: StepOffer): boolean =>
      pending !== null &&
      [offer.current.step, ...offer.alternatives.map((step) => step.step)].includes(pending.name);
    /** Read the pending answer against `offer` with the step grammar; `null` when it is malformed. */
    const readPending = (offer: StepOffer): ReadAnswer | null => {
      if (pending === null) throw new Error('sign-in engine: no answer to read');
      const { name, answer: raw } = pending;
      try {
        return grammar.readAnswer(offer, STEP_URNS[name], raw.fields, raw.encoding ?? 'form');
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
      return Object.freeze({
        current: Object.freeze({
          step: refused.step,
          params: refused.params,
        } as StepOffer['current']),
        alternatives: Object.freeze(
          others.map((offered) => Object.freeze({ step: offered.step, params: offered.params }))
        ) as StepOffer['alternatives'],
      });
    };

    /**
     * A factor proved an account: one subject per transaction, then record
     * the step and the time. `null` when the transaction ended.
     */
    let proven: SignInAccount | null = null;
    const prove = async (account: SignInAccount, read: ReadAnswer): Promise<boolean> => {
      if (transaction.subject !== undefined && transaction.subject !== account.userId) {
        return false;
      }
      transaction = {
        ...transaction,
        subject: account.userId,
        verified: [
          ...transaction.verified,
          { step: read.step, params: read.params } as OfferedStep,
        ],
        authTime: clock.now(),
      };
      proven = account;
      await audit('passed', read.step, undefined, account.userId);
      return true;
    };

    /**
     * Verify the pending answer against `offer`, after the step grammar read
     * it. Returns the round's result when the answer ends the round, or
     * `null` when it proved a factor or passed a challenge and the rules go on.
     */
    const verifyPending = async (offer: StepOffer): Promise<RoundResult | null> => {
      const read = readPending(offer);
      if (read === null) return invalidAnswer();
      pending = null;
      const handler = handlers.byStep.get(read.step) as StepHandler;
      const verdict: StepVerdict = await handler.verify(stepRound(), {
        params: read.params,
        answer: read.answer,
      });
      switch (verdict.kind) {
        case 'refused':
          await audit('refused', read.step, verdict.audit.reason, verdict.audit.userId);
          return offerStep(refusedOffer(offer, read.step), verdict.error);
        case 'throttled':
          await audit('refused', read.step, verdict.audit.reason, verdict.audit.userId);
          return throttled(verdict.retryAfterSeconds);
        case 'proved':
          if (!(await prove(verdict.account, read))) return ended(read.step, 'subject_mismatch');
          return null;
        case 'passed':
          if (handler.role !== 'challenge') throw new Error(`sign-in engine: ${read.step} passed`);
          transaction = {
            ...transaction,
            verified: [
              ...transaction.verified,
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
      ...(pending === null ? {} : { answered: pending.name }),
    });

    // Rule 3: the limiters.
    const { limits, request, botChallenge } = hooks;
    if (limits !== undefined) {
      const verdict = await fromStore('limits', () => limits(hookRound));
      if (verdict.kind === 'throttled') return throttled(verdict.retryAfterSeconds);
    }

    // Rule 4: the transport's request checks.
    if (request !== undefined) {
      const verdict = await fromStore('request', () => request(hookRound));
      if (verdict.kind === 'refuse') {
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
    if (pending !== null && STEPS_WITH_LOGIN_HINT.has(pending.name)) {
      const fields = pending.answer.fields;
      if (isRecord(fields) && Object.hasOwn(fields, 'login_hint')) {
        const identifier = readIdentifier(fields['login_hint']);
        if (identifier === null) return invalidAnswer();
        brought.push({ identifier, step: pending.name });
      } else if (pending.name === 'identifier') {
        return invalidAnswer();
      }
    }
    const heldBefore = transaction.identifier;
    for (const { identifier, step } of brought) {
      if (transaction.identifier === undefined) {
        transaction = { ...transaction, identifier };
      } else if (transaction.identifier !== identifier) {
        return ended(step, 'subject_mismatch');
      }
    }
    if (transaction.identifier === undefined) {
      // Nobody is named yet: the identifier step, the same for everyone.
      return offerStep(await offerOf([handlers.identifier]));
    }
    const identifier = transaction.identifier;
    if (heldBefore === undefined) {
      if (pending?.name === 'identifier') {
        // The identifier step was the one asked for: its answer is read by the
        // grammar like any other, and its handler confirms the identifier.
        const offer = await offerOf([handlers.identifier]);
        const read = readPending(offer);
        if (read === null) return invalidAnswer();
        pending = null;
        const verdict = await handlers.identifier.verify(stepRound(), {
          params: {},
          answer: read.answer as { login_hint: string },
        });
        if (verdict.kind !== 'identified' || verdict.identifier !== transaction.identifier) {
          throw new Error('sign-in engine: the identifier step disagrees with the identifier');
        }
      }
      await audit('passed', 'identifier');
    }
    if (pending?.name === 'identifier') pending = null; // the same identifier again: nothing to do

    // Rule 7: the first factor, offered alike to every account until one
    // succeeds. Only an answer to it is verified; any other is ignored.
    if (transaction.subject === undefined) {
      const firstFactors = handlers.firstFactors.filter((handler) => served.has(handler.step));
      if (firstFactors.length === 0) return redirect('step_not_available');
      const offer = await offerOf(firstFactors, { preferred: true });
      if (!answers(offer)) return offerStep(offer);
      const result = await verifyPending(offer);
      if (result !== null) return result;
    }

    // Rule 8: after a first factor. The account is the one the factor just
    // proved, or read again on a later round.
    let account: SignInAccount | null =
      proven ??
      (await fromStore('accounts', () => deps.accounts.findByIdentifier(realmId, identifier)));
    if (account === null || account.userId !== transaction.subject) {
      return ended('identifier', 'subject_mismatch');
    }
    if (!account.enabled) return ended('identifier', 'account_disabled');

    for (;;) {
      const current: SignInAccount = account;
      const verifiedSteps = new Set(transaction.verified.map((step) => step.step));
      const candidate = (handler: AnyStepHandler) =>
        served.has(handler.step) &&
        !verifiedSteps.has(handler.step) &&
        (handler.usableBy?.(current) ?? false);
      const strength = (handler: AnyStepHandler) =>
        handler.factor === undefined ? 0 : (FIRST_FACTOR_STRENGTH[handler.factor] ?? 0);
      let needed: AnyStepHandler[] | null = null;
      const strongest = strongestBoundFactor(account);
      if (provenFactorStrength(transaction.verified) < strongest) {
        // The downgrade rule: only a factor as strong as the strongest bound
        // one, a disabled one included, completes the sign-in.
        needed = handlers.firstFactors.filter(
          (handler) => candidate(handler) && strength(handler) >= strongest
        );
      } else if (secondFactorRequired(policy, account) && !provesMfa(transaction.verified)) {
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
      account = proven ?? account;
    }

    // Rule 9: complete. The transport mints the session or the code.
    const amr = transactionAmr(transaction.verified);
    const { subject, authTime } = transaction;
    if (amr === undefined || subject === undefined || authTime === undefined) {
      throw new Error('sign-in engine: complete without a factor');
    }
    const final = freezeTransaction(transaction);
    return Object.freeze({
      kind: 'complete',
      transaction: final,
      signIn: Object.freeze({
        subject,
        identifier,
        amr,
        authTime,
      }),
    });
  }

  return Object.freeze({ advance });
}
