import {
  INTERACTION_API_VERSION,
  STEP_URN_SCHEMA_PATTERN,
  stepErrorCodes,
  STEPS,
} from '@qauth-labs/shared-interaction-contract';
import { describe, expect, expectTypeOf, it } from 'vitest';
import { z } from 'zod';

import { defineStep } from './grammar';
import {
  FIPA_STEP_NAMES,
  type FipaStepName,
  INTERACTION_ONLY_STEP_NAMES,
  type InteractionOnlyStepName,
  isFipaStepName,
  isStepName,
  STEP_AMR,
  STEP_ERROR_CODES,
  STEP_ERRORS,
  STEP_GRAMMAR,
  STEP_NAMES,
  STEP_URNS,
  type StepAnswer,
  type StepError,
  type StepName,
  stepNameOfUrn,
  type StepParams,
} from './steps';

/** The steps ADR-017 Decision 3 lists, which the FiPA endpoint may serve. */
const ADR_017_STEPS = [
  'identifier',
  'password',
  'email_code',
  'new_password',
  'password_reset',
  'captcha',
  'webauthn_get',
  'webauthn_create',
  'totp',
];

describe('the step grammar', () => {
  it('has the steps of the Interaction API contract, in its order', () => {
    expect(STEP_NAMES).toEqual(STEPS.map((step) => step.name));
    expect(Object.keys(STEP_GRAMMAR)).toEqual(STEP_NAMES);
  });

  it('names each step as the contract does: urn:qauth:ia:<name>:v1-rc.0', () => {
    expect(INTERACTION_API_VERSION).toBe('v1-rc.0');
    for (const step of STEPS) {
      const name = step.name as StepName;
      expect(STEP_URNS[name]).toBe(step.urn);
      expect(STEP_GRAMMAR[name].urn).toBe(`urn:qauth:ia:${name}:v1-rc.0`);
      expect(STEP_URNS[name]).toMatch(new RegExp(STEP_URN_SCHEMA_PATTERN, 'u'));
      expect(stepNameOfUrn(step.urn)).toBe(name);
    }
    expect(stepNameOfUrn('urn:qauth:ia:password:v1')).toBeUndefined();
    expect(stepNameOfUrn('urn:qauth:ia:password:v1-rc.1')).toBeUndefined();
  });

  it('types each URN as its literal, so the version label is part of the type', () => {
    expectTypeOf(STEP_URNS.password).toEqualTypeOf<'urn:qauth:ia:password:v1-rc.0'>();
    expectTypeOf(STEP_GRAMMAR.consent.urn).toEqualTypeOf<'urn:qauth:ia:consent:v1-rc.0'>();
  });

  it('marks the steps only the Interaction API serves, as the contract does', () => {
    for (const step of STEPS) {
      expect(STEP_GRAMMAR[step.name as StepName].transports, step.name).toEqual(step.transports);
    }
    expect(FIPA_STEP_NAMES).toEqual(ADR_017_STEPS);
    expect(INTERACTION_ONLY_STEP_NAMES).toEqual(
      STEP_NAMES.filter((name) => !ADR_017_STEPS.includes(name))
    );
    expect(INTERACTION_ONLY_STEP_NAMES).toHaveLength(8);
    for (const name of STEP_NAMES) expect(isFipaStepName(name)).toBe(ADR_017_STEPS.includes(name));
    expectTypeOf<'consent'>().not.toExtend<FipaStepName>();
    expectTypeOf<'recovery_code'>().toExtend<InteractionOnlyStepName>();
    expectTypeOf<'password'>().toExtend<FipaStepName>();
  });

  it('exports each step’s closed error set and their union, as the contract publishes them', () => {
    for (const step of STEPS) {
      expect(STEP_ERRORS[step.name as StepName], step.name).toEqual(step.errors);
    }
    expect(STEP_ERROR_CODES).toEqual(stepErrorCodes());
    expectTypeOf<StepError<'email_code'>>().toEqualTypeOf<'invalid_credentials' | 'code_expired'>();
    expectTypeOf<StepError<'consent'>>().toEqualTypeOf<never>();
  });

  it('exports the amr value each step adds (ADR-017 Decision 3), as the contract publishes them', () => {
    for (const step of STEPS) expect(STEP_AMR[step.name as StepName], step.name).toEqual(step.amr);
    expect(
      Object.fromEntries(Object.entries(STEP_AMR).filter(([, amr]) => amr.length > 0))
    ).toEqual({
      password: ['pwd'],
      webauthn_get: ['pop', 'mfa'],
      totp: ['otp'],
    });
  });

  it('types params and answers from the Zod schemas', () => {
    expectTypeOf<StepAnswer<'password'>>().toEqualTypeOf<{
      password: string;
      login_hint?: string | undefined;
    }>();
    expectTypeOf<StepParams<'totp'>>().toEqualTypeOf<{ digits: 6 }>();
    expectTypeOf<StepAnswer<'consent'>['remember']>().toEqualTypeOf<boolean>();
  });

  it('knows its step names and nothing else', () => {
    for (const name of STEP_NAMES) expect(isStepName(name)).toBe(true);
    for (const name of ['toString', '__proto__', 'Password', 'otp', '']) {
      expect(isStepName(name), name).toBe(false);
    }
  });
});

describe('defineStep', () => {
  const base = {
    transports: ['interaction'] as const,
    params: z.strictObject({}),
    personal: z.strictObject({}),
    answer: z.strictObject({}),
  };

  it('derives the URN from the name, and refuses a name that is not a step name', () => {
    expect(defineStep({ ...base, name: 'sample', errors: [], amr: [] }).urn).toBe(
      'urn:qauth:ia:sample:v1-rc.0'
    );
    expect(() => defineStep({ ...base, name: 'Sample', errors: [], amr: [] })).toThrow();
  });

  it('refuses an error listed twice and an amr value RFC 8176 does not register', () => {
    expect(() =>
      defineStep({ ...base, name: 'sample', errors: ['code_expired', 'code_expired'], amr: [] })
    ).toThrow(/twice/);
    expect(() => defineStep({ ...base, name: 'sample', errors: [], amr: ['password'] })).toThrow(
      /amr/
    );
  });
});
