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
}

/** An offer after the grammar's checks: every params object parsed by its step's schema. */
export interface ReadOffer {
  readonly current: {
    readonly step: StepName;
    readonly params: unknown;
    readonly error?: StepErrorCode;
  };
  readonly alternatives: readonly { readonly step: StepName; readonly params: unknown }[];
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

function readStep(value: unknown, at: string, allowError: boolean) {
  refuseUnknownMembers(value, allowError ? ['step', 'params', 'error'] : ['step', 'params'], at);
  const { step: name, params, error } = value as Record<string, unknown>;
  if (typeof name !== 'string' || !isStepName(name)) {
    throw new StepMappingError('unknown_step', `${at}.step`);
  }
  const step = grammarStep(name);
  const parsed = step.params.safeParse(params);
  if (!parsed.success) {
    const paths = parsed.error.issues.map((issue) => issue.path.join('.') || '(root)');
    throw new StepMappingError('invalid_params', `${name}: ${[...new Set(paths)].join(', ')}`);
  }
  if (error !== undefined && !(typeof error === 'string' && step.errors.includes(error))) {
    throw new StepMappingError('invalid_error', `${name}: not one of its errors`);
  }
  return { name, params: parsed.data, error: error as StepErrorCode | undefined };
}

/**
 * Check an offer against the grammar, whatever the transport: known steps
 * only, every params object valid for its step (a strict schema, so a
 * sentence in an undeclared member is refused), an error only on the current
 * step and only from its closed set, and no step offered twice.
 */
export function readOffer(offer: StepOffer): ReadOffer {
  refuseUnknownMembers(offer, ['current', 'alternatives'], 'offer');
  if (!Array.isArray(offer.alternatives)) {
    throw new StepMappingError('unknown_member', 'offer.alternatives is not an array');
  }
  const current = readStep(offer.current, 'offer.current', true);
  const seen = new Set<StepName>([current.name]);
  const alternatives = offer.alternatives.map((alternative, index) => {
    const read = readStep(alternative, `offer.alternatives.${index}`, false);
    if (seen.has(read.name)) throw new StepMappingError('duplicate_step', read.name);
    seen.add(read.name);
    return { step: read.name, params: read.params };
  });
  return {
    current: {
      step: current.name,
      params: current.params,
      ...(current.error === undefined ? {} : { error: current.error }),
    },
    alternatives,
  };
}
