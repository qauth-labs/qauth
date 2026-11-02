import {
  type AnswerEncoding,
  createInteractionMapper,
  grammarStep,
  type InteractionMapper,
  type InteractionPersonalView,
  type InteractionStepView,
  type ReadAnswer,
  STEP_URNS,
  StepAnswerError,
  stepNameOfUrn,
  type StepOffer,
} from '@qauth-labs/server-step-grammar';

/**
 * THE INTERACTION API'S SIDE OF THE STEP GRAMMAR (#616, ADR-019 Decision 6):
 * what the auth server's answer route needs from the grammar library, which
 * it may not import itself.
 *
 * - An offer of the engine is kept in the interaction record as a
 *   {@link StoredStep}: the current step's name and params, the names of its
 *   alternatives and their params, and the error of a refused answer. It is
 *   turned back into the offer it was ({@link offerOfStoredStep}) for the step
 *   read and for reading the next answer.
 * - An answer is read before the engine runs ({@link readInteractionAnswer}):
 *   it must name a step the last step read presented, carry no member the
 *   operation does not declare, and match that step's answer schema. The
 *   engine reads it again against the offer it computes for the round.
 */

/** The members of the answer envelope, beside a step's own answer members. */
export const INTERACTION_ANSWER_ENVELOPE = Object.freeze(['type', 'csrf'] as const);

/** The step URN of `webauthn_create`: the one answer allowed a 64 KiB body (ADR-017 Decision 7). */
export const WEBAUTHN_CREATE_STEP_URN: string = STEP_URNS.webauthn_create;

/**
 * An engine offer as the interaction record keeps it. Names are step URNs.
 * `alternativeParams` holds the params of each alternative, by its URN.
 */
export interface StoredStep {
  readonly name: string;
  readonly params: Readonly<Record<string, unknown>>;
  readonly alternatives: readonly string[];
  readonly alternativeParams?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly error?: string;
}

/** The Interaction API's mapper: every step served. */
export const INTERACTION_MAPPER: InteractionMapper = createInteractionMapper();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The engine's offer as the record keeps it. */
export function storedStepOf(offer: StepOffer): StoredStep {
  const alternativeParams: Record<string, Readonly<Record<string, unknown>>> = {};
  for (const alternative of offer.alternatives) {
    const params = alternative.params as Readonly<Record<string, unknown>>;
    if (Object.keys(params).length > 0) alternativeParams[STEP_URNS[alternative.step]] = params;
  }
  const { current } = offer;
  return {
    name: STEP_URNS[current.step],
    params: current.params as Readonly<Record<string, unknown>>,
    alternatives: offer.alternatives.map((alternative) => STEP_URNS[alternative.step]),
    ...(Object.keys(alternativeParams).length === 0 ? {} : { alternativeParams }),
    ...(current.error === undefined ? {} : { error: current.error }),
  };
}

/**
 * The offer a stored step was, for the grammar's mappers, which check it
 * again: a step name no step has, or params outside a step's schema, fail
 * there.
 *
 * @throws Error for a name that is no step URN
 */
export function offerOfStoredStep(stored: StoredStep): StepOffer {
  const nameOf = (urn: string) => {
    const name = stepNameOfUrn(urn);
    if (name === undefined) throw new Error('a stored step names no step of the grammar');
    return name;
  };
  return {
    current: {
      step: nameOf(stored.name),
      params: stored.params,
      ...(stored.error === undefined ? {} : { error: stored.error }),
    },
    alternatives: stored.alternatives.map((urn) => ({
      step: nameOf(urn),
      params: stored.alternativeParams?.[urn] ?? {},
    })),
  } as unknown as StepOffer;
}

/** The step read's grammar members for a stored step: `step`, `error`, `alternatives`, `params`. */
export function interactionStepView(stored: StoredStep): InteractionStepView {
  return INTERACTION_MAPPER.stepView(offerOfStoredStep(stored));
}

/** The personal-data read for a stored step and its personal data, parsed by the step's schema. */
export function interactionPersonalView(
  stored: StoredStep,
  personal: unknown
): InteractionPersonalView {
  return INTERACTION_MAPPER.personalView(offerOfStoredStep(stored), personal);
}

/**
 * The members an answer to the step `stepUrn` declares, beside the envelope's;
 * `undefined` for a URN no step has.
 */
export function answerMemberNames(stepUrn: string): readonly string[] | undefined {
  const name = stepNameOfUrn(stepUrn);
  if (name === undefined) return undefined;
  const shape = (grammarStep(name).answer as unknown as { shape?: Record<string, unknown> }).shape;
  return Object.keys(shape ?? {});
}

/**
 * Read an answer body before the engine runs. `body` is the whole JSON body or
 * form; `lastOffer` is the stored step the answer's CSRF value was given
 * with. The answer must name a step that step read presented (its `step` or
 * one of its `alternatives`), carry only the envelope's members and that
 * step's answer members, and match the step's answer schema and the params it
 * was offered with.
 *
 * @throws StepAnswerError `not_offered` or `invalid_answer`; its message
 *   names the step and the member, never a value
 */
export function readInteractionAnswer(
  lastOffer: StoredStep,
  body: unknown,
  encoding: AnswerEncoding
): ReadAnswer {
  if (!isRecord(body)) throw new StepAnswerError('invalid_answer', 'the body is not an object');
  const type = body['type'];
  if (typeof type !== 'string') throw new StepAnswerError('invalid_answer', 'type');
  const members = answerMemberNames(type);
  if (members === undefined) throw new StepAnswerError('not_offered', 'the answered step');
  const allowed = new Set<string>([...INTERACTION_ANSWER_ENVELOPE, ...members]);
  for (const key of Object.keys(body)) {
    if (!allowed.has(key)) throw new StepAnswerError('invalid_answer', 'an undeclared member');
  }
  return INTERACTION_MAPPER.readAnswer(offerOfStoredStep(lastOffer), type, body, encoding);
}
