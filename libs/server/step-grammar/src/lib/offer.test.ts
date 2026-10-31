import { stepNamed } from '@qauth-labs/shared-interaction-contract';
import { describe, expect, it } from 'vitest';

import { createFipaMapper, FIPA_SERVES_ALL, FIPA_STEP_MAPPERS } from './fipa-mapper';
import { createInteractionMapper, INTERACTION_STEP_MAPPERS } from './interaction-mapper';
import { StepMappingError, type StepMappingErrorCode } from './mapping-error';
import { checkParams, type StepOffer } from './offer';
import { FIPA_STEP_NAMES, STEP_GRAMMAR, STEP_NAMES } from './steps';

/**
 * The checks every offer passes on both transports, before either envelope:
 * the rules between members that no step schema states, and the second check
 * of what each transport's per-step mapper returns.
 */

const ROUND = {
  issuer: 'https://auth.example.com',
  newAuthSession: () => 'YXV0aC1zZXNzaW9uLWhhbmRsZS1vZi0zMi1ieXRlcyE',
  interactionTypesSupported: FIPA_STEP_NAMES.map((name) => STEP_GRAMMAR[name].urn),
};

const interaction = createInteractionMapper();
const fipa = createFipaMapper(FIPA_SERVES_ALL);

function refusedOnBoth(offer: unknown, code: StepMappingErrorCode) {
  for (const run of [
    () => interaction.stepView(offer as StepOffer),
    () => fipa.challenge(offer as StepOffer, ROUND),
  ]) {
    let caught: unknown;
    try {
      run();
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(StepMappingError);
    expect((caught as StepMappingError).code).toBe(code);
  }
}

const captcha = { step: 'captcha', params: stepNamed('captcha').example.step.params };
const newPassword = { purpose: 'reset', min_length: 15, max_length: 256 } as const;

describe('a bot challenge', () => {
  // ADR-017 Decision 4: the challenge comes next and the pending step
  // resumes after it, so no other answer may be offered beside it.
  it('is offered alone: with an alternative, or as one, the offer is refused', () => {
    refusedOnBoth(
      { current: captcha, alternatives: [{ step: 'password', params: {} }] },
      'bot_challenge_not_alone'
    );
    refusedOnBoth(
      { current: { step: 'password', params: {} }, alternatives: [captcha] },
      'bot_challenge_not_alone'
    );
    expect(
      interaction.stepView({ current: captcha, alternatives: [] } as StepOffer).alternatives
    ).toEqual([]);
  });
});

describe('new_password', () => {
  it('carries reasons exactly when its last answer was refused with password_rejected', () => {
    const ok = (offer: unknown) => interaction.stepView(offer as StepOffer);
    expect(() =>
      ok({
        current: {
          step: 'new_password',
          params: { ...newPassword, reasons: ['too_short'] },
          error: 'password_rejected',
        },
        alternatives: [],
      })
    ).not.toThrow();
    expect(() =>
      ok({ current: { step: 'new_password', params: newPassword }, alternatives: [] })
    ).not.toThrow();
    refusedOnBoth(
      {
        current: { step: 'new_password', params: newPassword, error: 'password_rejected' },
        alternatives: [],
      },
      'invalid_error'
    );
    refusedOnBoth(
      {
        current: { step: 'new_password', params: { ...newPassword, reasons: ['too_short'] } },
        alternatives: [],
      },
      'invalid_error'
    );
    refusedOnBoth(
      {
        current: { step: 'password', params: {} },
        alternatives: [
          { step: 'new_password', params: { ...newPassword, reasons: ['too_short'] } },
        ],
      },
      'invalid_error'
    );
  });

  it('never asks for a password longer than it accepts', () => {
    refusedOnBoth(
      {
        current: {
          step: 'new_password',
          params: { ...newPassword, min_length: 64, max_length: 32 },
        },
        alternatives: [],
      },
      'invalid_params'
    );
  });
});

describe('email_code', () => {
  const code = (purpose: string, length: number, expiresIn = 600) => ({
    current: {
      step: 'email_code',
      params: { purpose, length, expires_in: expiresIn, resend_after: 60 },
    },
    alternatives: [],
  });

  // ADR-017 Decision 5: 8 digits for recovery and registration, 6 after a
  // password; verifying an account is either, by where it comes.
  it('has the length its purpose takes', () => {
    for (const [purpose, length] of [
      ['verify_account', 8],
      ['verify_account', 6],
      ['recovery', 8],
    ] as const) {
      const view = interaction.stepView(code(purpose, length) as StepOffer);
      expect(view.params[STEP_GRAMMAR.email_code.urn]).toMatchObject({ purpose, length });
    }
    expect(fipa.challenge(code('confirm_sign_in', 6) as StepOffer, ROUND).body).toMatchObject({
      error: 'insufficient_authorization',
    });
    refusedOnBoth(code('recovery', 6), 'invalid_params');
    expect(() => fipa.challenge(code('confirm_sign_in', 8) as StepOffer, ROUND)).toThrow(
      StepMappingError
    );
  });

  it('lives at most 10 minutes', () => {
    expect(() => interaction.stepView(code('recovery', 8, 1) as StepOffer)).not.toThrow();
    refusedOnBoth(code('recovery', 8, 601), 'invalid_params');
    refusedOnBoth(code('recovery', 8, 86400), 'invalid_params');
    refusedOnBoth(
      {
        current: { step: 'password', params: {} },
        alternatives: [code('verify_account', 8, 3600).current],
      },
      'invalid_params'
    );
  });
});

describe('what a per-step mapper returns', () => {
  it('is parsed again by the step’s schema, so a mapper cannot add a member or a sentence', () => {
    expect(() =>
      checkParams('password', { note: 'Signing in from a new device?' }, 'test')
    ).toThrow(StepMappingError);
    expect(() => checkParams('totp', { digits: 8 }, 'test')).toThrow(StepMappingError);
    expect(checkParams('totp', { digits: 6 }, 'test')).toEqual({ digits: 6 });
  });

  it('comes from tables nobody can change at run time', () => {
    expect(Object.isFrozen(INTERACTION_STEP_MAPPERS)).toBe(true);
    expect(Object.isFrozen(FIPA_STEP_MAPPERS)).toBe(true);
    expect(() => {
      (INTERACTION_STEP_MAPPERS as Record<string, unknown>)['password'] = () => ({ note: 'x' });
    }).toThrow(TypeError);
  });
});

describe('the grammar’s own values', () => {
  it('are frozen: a step, its lists and the step list', () => {
    expect(Object.isFrozen(STEP_NAMES)).toBe(true);
    for (const name of STEP_NAMES) {
      const step = STEP_GRAMMAR[name];
      expect(Object.isFrozen(step), name).toBe(true);
      expect(Object.isFrozen(step.errors), name).toBe(true);
      expect(Object.isFrozen(step.amr), name).toBe(true);
      expect(Object.isFrozen(step.transports), name).toBe(true);
    }
    expect(() => (STEP_GRAMMAR.password.amr as unknown as string[]).push('mfa')).toThrow(TypeError);
  });

  it('give each mapper a frozen copy of what it serves', () => {
    const narrow = createInteractionMapper({ serves: ['password'] });
    expect(narrow.serves).toEqual(['password']);
    expect(() => (narrow.serves as string[]).push('identifier')).toThrow(TypeError);
    expect(() =>
      narrow.stepView({ current: { step: 'identifier', params: {} }, alternatives: [] })
    ).toThrow(StepMappingError);
    const f1 = createFipaMapper({ serves: ['password', 'identifier'] });
    expect(f1.serves).toEqual(['identifier', 'password']);
    expect(Object.isFrozen(f1.serves)).toBe(true);
  });
});
