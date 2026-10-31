import { INTERACTION_OPENAPI, stepNamed } from '@qauth-labs/shared-interaction-contract';
import {
  exampleInteraction,
  examplePersonal,
} from '@qauth-labs/shared-interaction-contract/src/lib/openapi';
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

  it('refuses an unknown step, and params that do not match their step', () => {
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
  });

  // The contract's `maxItems` for `alternatives`. Today's grammar cannot
  // exceed it: 17 steps, less the current one and the bot challenge, which is
  // never an alternative, leave 15. The check is there for the steps to come.
  it('carries at most the contract’s maximum of alternatives, and accepts the longest offer the grammar allows', () => {
    const { schemas } = INTERACTION_OPENAPI['components'] as {
      schemas: { Interaction: { properties: { alternatives: { maxItems: number } } } };
    };
    expect(MAX_INTERACTION_ALTERNATIVES).toBe(schemas.Interaction.properties.alternatives.maxItems);
    const all = STEP_NAMES.filter((name) => name !== 'password' && name !== 'captcha');
    expect(all).toHaveLength(MAX_INTERACTION_ALTERNATIVES);
    const view = mapper.stepView({
      current: { step: 'password', params: {} },
      alternatives: all.map((name) => ({
        step: name,
        params:
          name === 'new_password'
            ? { purpose: 'reset', min_length: 15, max_length: 256 }
            : paramsOf(name),
      })) as never,
    });
    expect(view.alternatives).toHaveLength(MAX_INTERACTION_ALTERNATIVES);
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

describe('the Interaction API mapper’s personal data read', () => {
  // The step's own example personal data, as the engine would hand it over.
  const personalOf = (name: StepName) => stepNamed(name).example.personal ?? {};

  it.each(STEP_NAMES)(
    '%s: gives the contract’s example personal data read, which validates against PersonalData',
    (name) => {
      const view = mapper.personalView(exampleOffer(name), personalOf(name));
      expect(view).toStrictEqual(examplePersonal(stepNamed(name)));
      const read = validator.schema('PersonalData');
      expect(read(view), describeErrors(read)).toBe(true);
    }
  );

  it('serves a new object: nothing the caller keeps a reference to', () => {
    const data = { identifier: 'alice@example.com' };
    const view = mapper.personalView(
      { current: { step: 'password', params: {} }, alternatives: [] },
      data
    );
    const served = view.data[STEP_URNS.password];
    expect(served).toStrictEqual(data);
    expect(served).not.toBe(data);
    data.identifier = 'mallory@example.com';
    expect(served).toStrictEqual({ identifier: 'alice@example.com' });
  });

  it('refuses a user row spread into the personal data, and names no value', () => {
    const user = {
      id: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
      passwordHash: '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA',
      emailVerified: false,
      enabled: true,
    };
    let caught: unknown;
    try {
      mapper.personalView(
        { current: { step: 'password', params: {} }, alternatives: [] },
        { ...user, identifier: 'alice@example.com' }
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(StepMappingError);
    expect((caught as StepMappingError).code).toBe('invalid_personal_data');
    expect((caught as Error).message).not.toContain('argon2id');
    expect((caught as Error).message).not.toContain('alice');
  });

  it('refuses personal data for a step that has none, and a value outside the schema', () => {
    expectRefusal(
      () =>
        mapper.personalView(
          { current: { step: 'identifier', params: {} }, alternatives: [] },
          { identifier: 'alice@example.com' }
        ),
      'invalid_personal_data'
    );
    expectRefusal(
      () =>
        mapper.personalView(
          { current: { step: 'totp_setup', params: paramsOf('totp_setup') }, alternatives: [] },
          { ...(personalOf('totp_setup') as object), secret: 'not-base32' }
        ),
      'invalid_personal_data'
    );
  });

  it('serves the current step’s personal data only, never an alternative’s', () => {
    const view = mapper.personalView(
      {
        current: { step: 'password', params: {} },
        alternatives: [{ step: 'recovery_code', params: {} }],
      },
      { identifier: 'alice@example.com' }
    );
    expect(Object.keys(view.data)).toEqual([STEP_URNS.password]);
    // The recovery codes are the current step's alone: offered as the step
    // read's current step, never through another step's read.
    expectRefusal(
      () =>
        mapper.personalView(
          { current: { step: 'password', params: {} }, alternatives: [] },
          personalOf('recovery_codes')
        ),
      'invalid_personal_data'
    );
  });

  it('refuses an offer the step read refuses', () => {
    const narrow = createInteractionMapper({ serves: ['password'] });
    expectRefusal(
      () =>
        narrow.personalView(
          { current: { step: 'recovery_code', params: {} }, alternatives: [] },
          {}
        ),
      'not_served'
    );
    expectRefusal(
      () =>
        mapper.personalView(
          { current: { step: 'password', params: { note: 'x' } as never }, alternatives: [] },
          {}
        ),
      'invalid_params'
    );
  });
});
