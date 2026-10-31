import { StepMappingError } from './mapping-error';
import {
  grammarStep,
  isStepName,
  type StepError,
  type StepErrorCode,
  type StepName,
  type StepParams,
} from './steps';

/**
 * What the engine offers next, before a transport puts it in its envelope: the
 * step it asks for, with its params and, after a refused answer, that step's
 * error; and the other steps it accepts as the next answer, preferred first.
 * The engine is transport-neutral (ADR-017 Decision 4), so the offer may name
 * steps a transport does not serve; each transport's mapper decides what it
 * makes of them.
 */

/** One offered step: its name and the params its screen needs. */
export type OfferedStep<N extends StepName = StepName> = {
  readonly [K in N]: { readonly step: K; readonly params: StepParams<K> };
}[N];

/** The step the engine asks for, and the error of a refused answer to it, from its closed set. */
export type CurrentStep<N extends StepName = StepName> = {
  readonly [K in N]: {
    readonly step: K;
    readonly params: StepParams<K>;
    readonly error?: StepError<K>;
  };
}[N];

/** The engine's next step, as both transports receive it. */
export interface StepOffer {
  readonly current: CurrentStep;
  readonly alternatives: readonly OfferedStep[];
  /**
   * Whether the current step is required, or only preferred: `false` lets a
   * transport that cannot serve it offer an alternative it can serve in its
   * place (the FiPA mapper does). Absent means required, so an offer that
   * says nothing fails closed. A bot challenge is offered alone, so it never
   * has an alternative to give way to; a second factor the transaction needs
   * is required.
   */
  readonly required?: boolean;
}

/** An offer after the grammar's checks: every params object parsed by its step's schema. */
export interface ReadOffer {
  readonly current: {
    readonly step: StepName;
    readonly params: unknown;
    readonly error?: StepErrorCode;
  };
  readonly alternatives: readonly { readonly step: StepName; readonly params: unknown }[];
  /** Whether the current step is required: `true` unless the offer said `false`. */
  readonly required: boolean;
}

/** Refuse a member `allowed` does not name: no prose can ride along on an undeclared member. */
export function refuseUnknownMembers(value: unknown, allowed: readonly string[], at: string): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new StepMappingError('unknown_member', `${at} is not an object`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new StepMappingError('unknown_member', `${at}.${key}`);
  }
}

/**
 * Parse `params` with step `name`'s schema: strict, so a sentence in an
 * undeclared member is refused. The mappers run it on the engine's params
 * and again on what each transport's per-step mapper returns.
 */
export function checkParams(name: StepName, params: unknown, at: string): unknown {
  const parsed = grammarStep(name).params.safeParse(params);
  if (!parsed.success) {
    const paths = parsed.error.issues.map((issue) => issue.path.join('.') || '(root)');
    throw new StepMappingError(
      'invalid_params',
      `${at} ${name}: ${[...new Set(paths)].join(', ')}`
    );
  }
  return parsed.data;
}

function readStep(value: unknown, at: string, allowError: boolean) {
  refuseUnknownMembers(value, allowError ? ['step', 'params', 'error'] : ['step', 'params'], at);
  const { step: name, params, error } = value as Record<string, unknown>;
  if (typeof name !== 'string' || !isStepName(name)) {
    throw new StepMappingError('unknown_step', `${at}.step`);
  }
  const step = grammarStep(name);
  const parsed = checkParams(name, params, at);
  if (error !== undefined && !(typeof error === 'string' && step.errors.includes(error))) {
    throw new StepMappingError('invalid_error', `${name}: not one of its errors`);
  }
  return { name, params: parsed, error: error as StepErrorCode | undefined };
}

/**
 * How many digits an email code has, by purpose (ADR-017 Decision 5): 8 for
 * recovery and registration, where the code alone creates a verified binding
 * or unlocks a reset; 6 after a password. Verifying an account is both: 8 at
 * registration (Decision 8), 6 after a correct password on an account not yet
 * verified (Decision 3's example).
 */
const EMAIL_CODE_LENGTHS: Readonly<Record<StepParams<'email_code'>['purpose'], readonly number[]>> =
  Object.freeze({ verify_account: [6, 8], recovery: [8], confirm_sign_in: [6] });

/** An email code is valid 10 minutes (ADR-017 Decision 5). */
const EMAIL_CODE_MAX_EXPIRES_IN = 600;

/**
 * The rules between members that a step's schema does not state, checked on
 * every offered step: `new_password` carries `reasons` exactly when it is the
 * current step and its last answer was refused with `password_rejected`
 * (ADR-017 Decision 3), and its bounds do not cross; an `email_code` has the
 * length its purpose takes and lives at most 10 minutes (ADR-017 Decision 5).
 * The published schema is wider on purpose: it describes every value a page
 * may meet, and the server's offers keep to these.
 */
function checkStepRules(name: StepName, params: unknown, error: StepErrorCode | undefined): void {
  if (name === 'email_code') {
    const { purpose, length, expires_in: expiresIn } = params as StepParams<'email_code'>;
    if (!EMAIL_CODE_LENGTHS[purpose].includes(length)) {
      throw new StepMappingError('invalid_params', `email_code: length for purpose ${purpose}`);
    }
    if (expiresIn > EMAIL_CODE_MAX_EXPIRES_IN) {
      throw new StepMappingError('invalid_params', 'email_code: expires_in above 600');
    }
    return;
  }
  if (name !== 'new_password') return;
  const { min_length: min, max_length: max, reasons } = params as StepParams<'new_password'>;
  if (min > max)
    throw new StepMappingError('invalid_params', 'new_password: min_length above max_length');
  if ((reasons !== undefined) !== (error === 'password_rejected')) {
    throw new StepMappingError(
      'invalid_error',
      'new_password: reasons go with password_rejected only'
    );
  }
}

/** The bot challenge: required when it comes, so it is offered alone (ADR-017 Decision 4). */
const BOT_CHALLENGE: StepName = 'captcha';

/**
 * Check an offer against the grammar, whatever the transport: known steps
 * only, every params object valid for its step (a strict schema, so a
 * sentence in an undeclared member is refused), an error only on the current
 * step and only from its closed set, no step offered twice, and a bot
 * challenge with no alternative and never as one: the pending step resumes
 * after it, so no other answer may skip it.
 */
export function readOffer(offer: StepOffer): ReadOffer {
  refuseUnknownMembers(offer, ['current', 'alternatives', 'required'], 'offer');
  if (!Array.isArray(offer.alternatives)) {
    throw new StepMappingError('unknown_member', 'offer.alternatives is not an array');
  }
  if (offer.required !== undefined && typeof offer.required !== 'boolean') {
    throw new StepMappingError('unknown_member', 'offer.required is not a boolean');
  }
  const current = readStep(offer.current, 'offer.current', true);
  checkStepRules(current.name, current.params, current.error);
  if (current.name === BOT_CHALLENGE && offer.alternatives.length > 0) {
    throw new StepMappingError('bot_challenge_not_alone', 'offer.alternatives');
  }
  const seen = new Set<StepName>([current.name]);
  const alternatives = offer.alternatives.map((alternative, index) => {
    const read = readStep(alternative, `offer.alternatives.${index}`, false);
    if (read.name === BOT_CHALLENGE) {
      throw new StepMappingError('bot_challenge_not_alone', `offer.alternatives.${index}`);
    }
    if (seen.has(read.name)) throw new StepMappingError('duplicate_step', read.name);
    seen.add(read.name);
    checkStepRules(read.name, read.params, undefined);
    return { step: read.name, params: read.params };
  });
  return {
    current: {
      step: current.name,
      params: current.params,
      ...(current.error === undefined ? {} : { error: current.error }),
    },
    alternatives,
    required: offer.required !== false,
  };
}
