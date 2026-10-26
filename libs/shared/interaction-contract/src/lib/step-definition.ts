import { stepUrn } from './identifiers';
import type { JsonSchema } from './schema-kit';

/**
 * One step of the step grammar (ADR-017 Decision 3), as the Interaction API v1
 * publishes it.
 *
 * A step is the same object on both transports; only the envelope differs
 * (#591). Its params and answer fields keep the grammar's names on both, which
 * is why they are `snake_case` (`login_hint`, `expires_in`) while the
 * Interaction API's own envelope is `camelCase` like the other API families.
 */
export interface StepDefinition {
  /** The short name, the `<name>` of `urn:qauth:ia:<name>:v1-rc.0`. */
  readonly name: string;
  /** The full step name. */
  readonly urn: string;
  /**
   * Which transports serve it. The steps ADR-017 lists are served by both the
   * Interaction API and the FiPA authorization challenge endpoint; the others
   * only by the Interaction API, and the FiPA endpoint answers
   * `redirect_to_web` where one would come next.
   */
  readonly transports: readonly ('interaction' | 'fipa')[];
  /** One sentence: what the step asks of the person. */
  readonly summary: string;
  /** What the screen shows and why: the step's description in the schema. */
  readonly description: string;
  /** What any reader of the interaction id may see: never personal data. */
  readonly params: JsonSchema;
  /**
   * What only the flow cookie's holder may read (#592): the account's own
   * data, a secret shown once. An empty object for a step that has none.
   */
  readonly personal: JsonSchema;
  /** The answer fields. Closed: an answer with another member is refused. */
  readonly answer: JsonSchema;
  /**
   * The closed set of reasons a rejected answer gives. The step is shown
   * again, with `error` set and a new CSRF value; no prose says more.
   */
  readonly errors: readonly string[];
  /**
   * The RFC 8176 `amr` values a successful answer adds to the transaction.
   * Empty for a step that proves no authenticator.
   */
  readonly amr: readonly string[];
  /** The step's test vectors, which the schemas must accept (INT-02 reuses them). */
  readonly example: StepExample;
}

/** One example of each part of a step. */
export interface StepExample {
  /** The step object as a step read returns it, as the current step. */
  readonly step: { readonly type: string; readonly params: unknown; readonly error?: string };
  /** The answer fields, without the envelope's `type` and `csrf`. */
  readonly answer: Readonly<Record<string, unknown>>;
  /** The personal data, for a step that has any. */
  readonly personal?: Readonly<Record<string, unknown>>;
  /** The short names of the steps offered beside it in the example's step read. */
  readonly alternatives?: readonly string[];
  /** What the answer leads to in the example: the next step's name, or the final redirect. */
  readonly next: { readonly step: string } | { readonly redirect: string };
}

/** The input of {@link defineStep}: a definition without its derived name. */
export type StepInput = Omit<StepDefinition, 'urn' | 'example'> & {
  readonly example: Omit<StepExample, 'step'> & {
    readonly params: unknown;
    readonly error?: string;
  };
};

/** Define a step: derives its URN and the example's step object. */
export function defineStep(input: StepInput): StepDefinition {
  const urn = stepUrn(input.name);
  const { params, error, ...example } = input.example;
  return {
    ...input,
    urn,
    example: {
      ...example,
      step: { type: urn, params, ...(error === undefined ? {} : { error }) },
    },
  };
}
