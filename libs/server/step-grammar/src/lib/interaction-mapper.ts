import type { z } from 'zod';

import type { AnyGrammarStep } from './grammar';
import { StepMappingError } from './mapping-error';
import { readOffer, refuseUnknownMembers, type StepOffer } from './offer';
import {
  type GrammarStepUnion,
  isStepName,
  STEP_NAMES,
  STEP_URNS,
  type StepErrorCode,
  type StepName,
  type StepUrn,
} from './steps';

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

export const INTERACTION_STEP_MAPPERS: InteractionMapperTable = {
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
};

/** The step grammar's members of a step read. */
export interface InteractionStepView {
  readonly step: StepUrn;
  readonly error?: StepErrorCode;
  readonly alternatives: readonly StepUrn[];
  /** The params of the current step and of every alternative, keyed by step name. */
  readonly params: Readonly<Partial<Record<StepUrn, unknown>>>;
}

/** Which steps a deployment's Interaction API serves. By default, every step. */
export interface InteractionTransportConfig {
  readonly serves: readonly StepName[];
}

/** The most alternatives a step read carries (the contract's `maxItems`). */
export const MAX_INTERACTION_ALTERNATIVES = 15;

export interface InteractionMapper {
  /** The steps this transport serves. */
  readonly serves: ReadonlySet<StepName>;
  /**
   * The grammar's members of the step read for `offer`. The current step must
   * be one this transport serves, since the Interaction API is where every
   * other transport sends a step it cannot serve; an alternative it does not
   * serve is left out. Throws {@link StepMappingError} for an offer the
   * grammar refuses.
   */
  stepView(offer: StepOffer): InteractionStepView;
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

  const mapParams = (name: StepName, params: unknown) =>
    (INTERACTION_STEP_MAPPERS[name] as (value: unknown) => unknown)(params);

  return {
    serves,
    stepView(offer) {
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
    },
  };
}
