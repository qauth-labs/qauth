import type { z } from 'zod';

import type { AnyGrammarStep } from './grammar';
import { StepMappingError } from './mapping-error';
import {
  type AnswerEncoding,
  checkParams,
  type ReadAnswer,
  readAnswer,
  readOffer,
  refuseUnknownMembers,
  type StepOffer,
} from './offer';
import {
  grammarStep,
  type GrammarStepUnion,
  isStepName,
  STEP_NAMES,
  STEP_URNS,
  type StepErrorCode,
  type StepName,
  type StepUrn,
} from './steps';
import { EMPTY_OBJECT } from './zod-kit';

/**
 * The Interaction API's mapper: an offer as the step grammar's members of a
 * step read (`Interaction` in the OpenAPI document of #590), `step`, `error`,
 * `alternatives` and `params`. The route adds the envelope's own members
 * (`csrf`, `client`, `brand`, `uiLocales`, `expiresAt`), which are not the
 * grammar's.
 */

/** What the Interaction API makes of one step's params: the same object, or a refusal. */
export type InteractionStepMapper<S extends AnyGrammarStep> = (
  params: z.output<S['params']>
) => z.output<S['params']>;

/**
 * One mapper per step. The table is keyed by the step union, so a step added
 * to the grammar without a mapper here fails the type check.
 */
export type InteractionMapperTable<S extends AnyGrammarStep = GrammarStepUnion> = {
  readonly [K in S as K['name']]: InteractionStepMapper<K>;
};

const same = <P>(params: P): P => params;

export const INTERACTION_STEP_MAPPERS: InteractionMapperTable = Object.freeze({
  identifier: same,
  password: same,
  email_code: (params) => {
    // The contract: `confirm_sign_in` is the FiPA endpoint's alone, and the
    // Interaction API never offers it.
    if (params.purpose === 'confirm_sign_in') {
      throw new StepMappingError('not_served', 'email_code.purpose confirm_sign_in');
    }
    return params;
  },
  new_password: same,
  password_reset: same,
  captcha: same,
  webauthn_get: same,
  webauthn_create: same,
  totp: same,
  recovery_code: same,
  recovery_codes: same,
  totp_setup: same,
  consent: same,
  select_account: same,
  device_code: same,
  device_confirm: same,
  logout_confirm: same,
});

/** The step grammar's members of a step read. */
export interface InteractionStepView {
  readonly step: StepUrn;
  readonly error?: StepErrorCode;
  readonly alternatives: readonly StepUrn[];
  /** The params of the current step and of every alternative, keyed by step name. */
  readonly params: Readonly<Partial<Record<StepUrn, unknown>>>;
}

/** The personal data read (`PersonalData` in the OpenAPI document of #590). */
export interface InteractionPersonalView {
  /** The current step, whose personal data this is. */
  readonly step: StepUrn;
  /** The current step's personal data under its step name; empty for a step that has none. */
  readonly data: Readonly<Partial<Record<StepUrn, unknown>>>;
}

/** Which steps a deployment's Interaction API serves. By default, every step. */
export interface InteractionTransportConfig {
  readonly serves: readonly StepName[];
}

/** The most alternatives a step read carries (the contract's `maxItems`). */
export const MAX_INTERACTION_ALTERNATIVES = 15;

export interface InteractionMapper {
  /** The steps this transport serves, in grammar order. */
  readonly serves: readonly StepName[];
  /**
   * The grammar's members of the step read for `offer`. The current step must
   * be one this transport serves, since the Interaction API is where every
   * other transport sends a step it cannot serve; an alternative it does not
   * serve is left out. One value is refused wherever it is offered, current
   * step or alternative: an `email_code` with the FiPA endpoint's own purpose,
   * `confirm_sign_in` (`not_served`). The steps the result names are the ones
   * the page may answer. Throws {@link StepMappingError} for an offer the
   * grammar refuses.
   */
  stepView(offer: StepOffer): InteractionStepView;
  /**
   * The personal data read for `offer`: `data`, the current step's personal
   * data, parsed by that step's strict schema into a new object. A member the
   * schema does not declare (a user row spread in whole, a password hash, a
   * flag) or a value outside it is refused, and the result shares nothing
   * with `data`. Only the current step's personal data is served; an
   * alternative's never is. The offer passes the same checks as in
   * {@link stepView}. Throws {@link StepMappingError}.
   */
  personalView(offer: StepOffer, data: unknown): InteractionPersonalView;
  /**
   * Read an answer to `lastOffer`, the offer the last step read was built
   * from: only a step that read named (its `step` or one of its
   * `alternatives`) may be answered, and only its answer members are taken
   * from `form`, the body, which arrived as `encoding` (a form post by
   * default; a JSON body takes `'json'`). Throws `StepAnswerError` for a
   * refused answer, and
   * {@link StepMappingError} for an offer the step read refuses.
   */
  readAnswer(
    lastOffer: StepOffer,
    stepUrn: string,
    form: unknown,
    encoding?: AnswerEncoding
  ): ReadAnswer;
}

/** Build the Interaction API's mapper for the steps `config` names. */
export function createInteractionMapper(
  config: InteractionTransportConfig = { serves: STEP_NAMES }
): InteractionMapper {
  refuseUnknownMembers(config, ['serves'], 'config');
  const serves = new Set<StepName>();
  for (const name of config.serves) {
    if (!isStepName(name)) throw new StepMappingError('invalid_configuration', `serves ${name}`);
    if (serves.has(name))
      throw new StepMappingError('invalid_configuration', `serves ${name} twice`);
    serves.add(name);
  }

  // What a per-step mapper returns is checked again, so no mapper can add a
  // member or a value the step's schema does not allow.
  const mapParams = (name: StepName, params: unknown) =>
    checkParams(
      name,
      (INTERACTION_STEP_MAPPERS[name] as (value: unknown) => unknown)(params),
      'interaction mapper'
    );

  const stepView = (offer: StepOffer): InteractionStepView => {
    const read = readOffer(offer);
    const { current } = read;
    if (!serves.has(current.step)) throw new StepMappingError('not_served', current.step);
    const alternatives = read.alternatives.filter((alternative) => serves.has(alternative.step));
    if (alternatives.length > MAX_INTERACTION_ALTERNATIVES) {
      throw new StepMappingError('too_many_alternatives', String(alternatives.length));
    }
    const offered = [current, ...alternatives];
    return {
      step: STEP_URNS[current.step],
      ...(current.error === undefined ? {} : { error: current.error }),
      alternatives: alternatives.map((alternative) => STEP_URNS[alternative.step]),
      params: Object.fromEntries(
        offered.map((step) => [STEP_URNS[step.step], mapParams(step.step, step.params)])
      ),
    };
  };

  const personalView = (offer: StepOffer, data: unknown): InteractionPersonalView => {
    const { step: urn } = stepView(offer);
    const name = offer.current.step;
    const schema = grammarStep(name).personal;
    const parsed = schema.safeParse(data);
    if (!parsed.success) {
      // Paths only: personal data never goes to the log.
      const paths = parsed.error.issues.map((issue) => issue.path.join('.') || '(root)');
      throw new StepMappingError(
        'invalid_personal_data',
        `${name}: ${[...new Set(paths)].join(', ')}`
      );
    }
    return { step: urn, data: schema === EMPTY_OBJECT ? {} : { [urn]: parsed.data } };
  };

  return {
    serves: Object.freeze(STEP_NAMES.filter((name) => serves.has(name))),
    stepView,
    personalView,
    readAnswer(lastOffer, stepUrn, form, encoding = 'form') {
      const presented = new Set<StepUrn>(stepView(lastOffer).alternatives);
      return readAnswer(
        {
          current: lastOffer.current,
          alternatives: lastOffer.alternatives.filter((alternative) =>
            presented.has(STEP_URNS[alternative.step])
          ),
        },
        stepUrn,
        form,
        encoding
      );
    },
  };
}
