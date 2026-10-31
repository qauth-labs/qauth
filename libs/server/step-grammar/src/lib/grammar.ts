import { INTERACTION_API_VERSION, stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { z } from 'zod';

/**
 * What a step of the step grammar is (ADR-017 Decision 3, ADR-019 Decision
 * 6): its name, which transports may serve it, the Zod schemas of its params,
 * personal data and answer, its closed error set and the `amr` values a
 * successful answer adds. The schemas are the single source of the step's
 * TypeScript types; the JSON Schema the Interaction API contract publishes is
 * generated from them and compared (`json-schema.test.ts`).
 */

/** The transports of the step grammar: the Interaction API and the FiPA authorization challenge endpoint. */
export type Transport = 'interaction' | 'fipa';

/**
 * Which transports may serve a step. The Interaction API serves every step;
 * the FiPA endpoint only the steps ADR-017 Decision 3 lists. Which of those a
 * deployment's transport actually serves is that transport's configuration,
 * not the grammar's.
 */
export type StepTransports = readonly ['interaction', 'fipa'] | readonly ['interaction'];

/** `urn:qauth:ia:<name>:v1-rc.0`. */
export type StepUrnOf<N extends string> = `urn:qauth:ia:${N}:${typeof INTERACTION_API_VERSION}`;

/** One step of the grammar. */
export interface GrammarStep<
  N extends string = string,
  T extends StepTransports = StepTransports,
  P extends z.ZodType = z.ZodType,
  D extends z.ZodType = z.ZodType,
  A extends z.ZodType = z.ZodType,
  E extends readonly string[] = readonly string[],
  M extends readonly string[] = readonly string[],
> {
  /** The short name, the `<name>` of the URN. */
  readonly name: N;
  /** The step name on the wire, on both transports. */
  readonly urn: StepUrnOf<N>;
  readonly transports: T;
  /** What the screen needs, which any reader of the interaction id may see: never personal data. */
  readonly params: P;
  /** What only the flow cookie's holder may read (Interaction API only). */
  readonly personal: D;
  /** The answer fields. Closed: an answer with another member is refused. */
  readonly answer: A;
  /** Why a rejected answer was rejected: a closed set, no prose. */
  readonly errors: E;
  /** The RFC 8176 `amr` values a successful answer adds; none for a step that proves no authenticator. */
  readonly amr: M;
}

/** Any step, whatever its name and schemas. */
export type AnyGrammarStep = GrammarStep<
  string,
  StepTransports,
  z.ZodType,
  z.ZodType,
  z.ZodType,
  readonly string[],
  readonly string[]
>;

/** The values RFC 8176 §2 registers: a step adds none other. */
const AMR_VALUES = new Set([
  'face',
  'fpt',
  'geo',
  'hwk',
  'iris',
  'kba',
  'mca',
  'mfa',
  'otp',
  'pin',
  'pop',
  'pwd',
  'rba',
  'retina',
  'sc',
  'sms',
  'swk',
  'tel',
  'user',
  'vbm',
  'wia',
]);

/** Define a step: derives its URN and checks what TypeScript cannot. */
export function defineStep<
  const N extends string,
  const T extends StepTransports,
  P extends z.ZodType,
  D extends z.ZodType,
  A extends z.ZodType,
  const E extends readonly string[],
  const M extends readonly string[],
>(step: Omit<GrammarStep<N, T, P, D, A, E, M>, 'urn'>): GrammarStep<N, T, P, D, A, E, M> {
  if (new Set(step.errors).size !== step.errors.length) {
    throw new Error(`${step.name}: an error is listed twice`);
  }
  for (const value of step.amr) {
    if (!AMR_VALUES.has(value)) throw new Error(`${step.name}: ${value} is not an amr value here`);
  }
  return Object.freeze({
    ...step,
    transports: Object.freeze([...step.transports]) as unknown as T,
    errors: Object.freeze([...step.errors]) as unknown as E,
    amr: Object.freeze([...step.amr]) as unknown as M,
    urn: stepUrn(step.name) as StepUrnOf<N>,
  });
}
