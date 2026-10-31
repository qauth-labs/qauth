import { INTERACTION_OPENAPI, stepNamed } from '@qauth-labs/shared-interaction-contract';
import { exampleInteraction } from '@qauth-labs/shared-interaction-contract/src/lib/openapi';
import {
  componentValidator,
  describeErrors,
} from '@qauth-labs/shared-interaction-contract/src/testing/schema-validator';
import { describe, expect, it } from 'vitest';

import {
  createInteractionMapper,
  INTERACTION_STEP_MAPPERS,
  MAX_INTERACTION_ALTERNATIVES,
} from './interaction-mapper';
import { StepMappingError, type StepMappingErrorCode } from './mapping-error';
import type { StepOffer } from './offer';
import { STEP_NAMES, STEP_URNS, type StepName } from './steps';

const validator = componentValidator(INTERACTION_OPENAPI);

/** The offer an example of the contract stands for: its step, error and alternatives. */
function exampleOffer(name: StepName): StepOffer {
  const { example } = stepNamed(name);
  return {
    current: {
      step: name,
      params: example.step.params,
      ...(example.step.error === undefined ? {} : { error: example.step.error }),
    },
    alternatives: (example.alternatives ?? []).map((alternative) => ({
      step: alternative,
      params: stepNamed(alternative).example.step.params,
    })),
  } as StepOffer;
}

/** The params of a step's example, for an offer built by hand. */
const paramsOf = (name: StepName) => stepNamed(name).example.step.params as never;

function expectRefusal(run: () => unknown, code: StepMappingErrorCode) {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(StepMappingError);
  expect((caught as StepMappingError).code).toBe(code);
}

const mapper = createInteractionMapper();

describe('the Interaction API mapper', () => {
  it('has a mapper for every step', () => {
    expect(Object.keys(INTERACTION_STEP_MAPPERS)).toEqual(STEP_NAMES);
    expect([...mapper.serves]).toEqual(STEP_NAMES);
  });

  // The step is the same object as the contract's example step read; the
  // route adds the envelope (csrf, client, brand, uiLocales, expiresAt).
  it.each(STEP_NAMES)(
    '%s: gives the step-grammar members of the contract’s example step read',
    (name) => {
      const view = mapper.stepView(exampleOffer(name));
      const { step, error, alternatives, params, ...envelope } = exampleInteraction(
        stepNamed(name)
      );
      expect(view).toStrictEqual({
        step,
        ...(error === undefined ? {} : { error }),
        alternatives,
        params,
      });
      const read = validator.schema('Interaction');
      expect(read({ ...envelope, ...view }), describeErrors(read)).toBe(true);
    }
  );

  it('keys the params by step name, the current step’s and each alternative’s', () => {
    const view = mapper.stepView({
      current: { step: 'password', params: {}, error: 'invalid_credentials' },
      alternatives: [
        { step: 'identifier', params: {} },
        { step: 'recovery_code', params: {} },
      ],
    });
    expect(view).toStrictEqual({
      step: STEP_URNS.password,
      error: 'invalid_credentials',
      alternatives: [STEP_URNS.identifier, STEP_URNS.recovery_code],
      params: {
        [STEP_URNS.password]: {},
        [STEP_URNS.identifier]: {},
        [STEP_URNS.recovery_code]: {},
      },
    });
  });

  it('serves the steps its configuration names: an alternative it does not serve is left out', () => {
    const narrow = createInteractionMapper({ serves: ['identifier', 'password'] });
    const view = narrow.stepView({
      current: { step: 'password', params: {} },
      alternatives: [
        { step: 'recovery_code', params: {} },
        { step: 'identifier', params: {} },
      ],
    });
    expect(view.alternatives).toEqual([STEP_URNS.identifier]);
    expect(Object.keys(view.params)).toEqual([STEP_URNS.password, STEP_URNS.identifier]);
    expectRefusal(
      () => narrow.stepView({ current: { step: 'recovery_code', params: {} }, alternatives: [] }),
      'not_served'
    );
  });

  it('never offers the FiPA endpoint’s own email code purpose, confirm_sign_in', () => {
    const confirm = {
      purpose: 'confirm_sign_in',
      length: 6,
      expires_in: 600,
      resend_after: 60,
    } as const;
    expectRefusal(
      () => mapper.stepView({ current: { step: 'email_code', params: confirm }, alternatives: [] }),
      'not_served'
    );
    expectRefusal(
      () =>
        mapper.stepView({
          current: { step: 'password', params: {} },
          alternatives: [{ step: 'email_code', params: confirm }],
        }),
      'not_served'
    );
  });

  it('refuses an error outside the current step’s closed set, and an error on an alternative', () => {
    expectRefusal(
      () =>
        mapper.stepView({
          current: { step: 'password', params: {}, error: 'code_expired' as never },
          alternatives: [],
        }),
      'invalid_error'
    );
    expectRefusal(
      () =>
        mapper.stepView({
          current: {
            step: 'consent',
            params: paramsOf('consent'),
            error: 'invalid_credentials' as never,
          },
          alternatives: [],
        }),
      'invalid_error'
    );
    expectRefusal(
      () =>
        mapper.stepView({
          current: { step: 'identifier', params: {} },
          alternatives: [{ step: 'password', params: {}, error: 'invalid_credentials' } as never],
        }),
      'unknown_member'
    );
  });

  it('refuses a step offered twice, or the current step as its own alternative', () => {
    expectRefusal(
      () =>
        mapper.stepView({
          current: { step: 'password', params: {} },
          alternatives: [{ step: 'password', params: {} }],
        }),
      'duplicate_step'
    );
    expectRefusal(
      () =>
        mapper.stepView({
          current: { step: 'password', params: {} },
          alternatives: [
            { step: 'identifier', params: {} },
            { step: 'identifier', params: {} },
          ],
        }),
      'duplicate_step'
    );
  });

  it('refuses an unknown step, params that do not match their step, and more alternatives than a read carries', () => {
    expectRefusal(
      () =>
        mapper.stepView({ current: { step: 'sms_code' as never, params: {} }, alternatives: [] }),
      'unknown_step'
    );
    expectRefusal(
      () =>
        mapper.stepView({
          current: { step: 'totp', params: { digits: 8 } as never },
          alternatives: [],
        }),
      'invalid_params'
    );
    const all = STEP_NAMES.filter((name) => name !== 'password');
    expect(all.length).toBeGreaterThan(MAX_INTERACTION_ALTERNATIVES);
    expectRefusal(
      () =>
        mapper.stepView({
          current: { step: 'password', params: {} },
          alternatives: all.map((name) => ({ step: name, params: paramsOf(name) })) as never,
        }),
      'too_many_alternatives'
    );
  });

  it('refuses a configuration that names an unknown step or a step twice', () => {
    expectRefusal(
      () => createInteractionMapper({ serves: ['sms_code' as never] }),
      'invalid_configuration'
    );
    expectRefusal(
      () => createInteractionMapper({ serves: ['password', 'password'] }),
      'invalid_configuration'
    );
    expectRefusal(
      () => createInteractionMapper({ serves: [], strict: true } as never),
      'unknown_member'
    );
  });
});
