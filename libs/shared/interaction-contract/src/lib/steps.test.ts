import { describe, expect, it } from 'vitest';

import { componentValidator, describeErrors, strictValidator } from '../testing/schema-validator';
import { INTERACTION_API_VERSION, STEP_URN_SCHEMA_PATTERN, stepUrn } from './identifiers';
import {
  exampleAnswer,
  exampleAnswerResult,
  exampleInteraction,
  examplePersonal,
  INTERACTION_OPENAPI,
  stepComponentNames,
} from './openapi';
import type { JsonSchema } from './schema-kit';
import { stepJsonSchema } from './step-schema';
import { stepErrorCodes, STEPS } from './steps';

/** The steps ADR-017 Decision 3 lists, which both transports serve. */
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

/** The steps only the Interaction API serves (#590). */
const INTERACTION_ONLY_STEPS = [
  'recovery_code',
  'recovery_codes',
  'totp_setup',
  'consent',
  'select_account',
  'device_code',
  'device_confirm',
  'logout_confirm',
];

const validator = componentValidator(INTERACTION_OPENAPI);

/** Validate `value` with a compiled schema, and say why when it fails. */
function expectValid(schema: ReturnType<typeof validator.schema>, value: unknown, at: string) {
  expect(schema(value), `${at}\n${describeErrors(schema)}`).toBe(true);
}

/** A strict validator for one part of a step's own schema file. */
function stepFilePart(step: (typeof STEPS)[number], part: string) {
  const file = stepJsonSchema(step);
  const ajv = strictValidator();
  ajv.addSchema(file);
  const validate = ajv.getSchema(
    part === '' ? String(file['$id']) : `${file['$id']}#/$defs/${part}`
  );
  if (validate === undefined) throw new Error(`${step.name}: no ${part}`);
  return validate;
}

describe('the steps', () => {
  it('are the steps ADR-017 lists, then the steps only the Interaction API serves', () => {
    expect(STEPS.map((step) => step.name)).toEqual([...ADR_017_STEPS, ...INTERACTION_ONLY_STEPS]);
  });

  it('are served by both transports exactly when ADR-017 lists them', () => {
    for (const step of STEPS) {
      expect(step.transports, step.name).toEqual(
        ADR_017_STEPS.includes(step.name) ? ['interaction', 'fipa'] : ['interaction']
      );
    }
  });

  // The acceptance criterion "all step names end in :v1", in the form ADR-018 §5
  // requires before 1.0.0: the version label `v1-rc.<M>`, the same as the path's.
  it('are named urn:qauth:ia:<name>:v1-rc.0, the version of the path', () => {
    expect(INTERACTION_API_VERSION).toBe('v1-rc.0');
    for (const step of STEPS) {
      expect(step.urn).toBe(`urn:qauth:ia:${step.name}:v1-rc.0`);
      expect(step.urn.endsWith(`:${INTERACTION_API_VERSION}`)).toBe(true);
      expect(step.urn).toMatch(new RegExp(STEP_URN_SCHEMA_PATTERN, 'u'));
    }
    expect(new Set(STEPS.map((step) => step.urn)).size).toBe(STEPS.length);
  });

  it('refuses a step name that is not lower-case ASCII', () => {
    expect(() => stepUrn('Password')).toThrow();
    expect(() => stepUrn('pass word')).toThrow();
  });

  it('add the amr values of ADR-017 Decision 3 and no others', () => {
    const amr = Object.fromEntries(STEPS.map((step) => [step.name, step.amr]));
    expect(amr).toEqual({
      identifier: [],
      password: ['pwd'],
      email_code: [],
      new_password: [],
      password_reset: [],
      captcha: [],
      webauthn_get: ['pop', 'mfa'],
      webauthn_create: [],
      totp: ['otp'],
      recovery_code: [],
      recovery_codes: [],
      totp_setup: [],
      consent: [],
      select_account: [],
      device_code: [],
      device_confirm: [],
      logout_confirm: [],
    });
  });

  it('refuse answers with the closed error sets, ADR-017 Decision 3’s among them', () => {
    expect(stepErrorCodes()).toEqual([
      'invalid_credentials',
      'code_expired',
      'password_rejected',
      'captcha_failed',
      'account_unavailable',
      'invalid_user_code',
    ]);
    for (const step of STEPS) {
      const file = stepJsonSchema(step);
      const defs = file['$defs'] as Record<string, JsonSchema>;
      if (step.errors.length === 0) {
        expect(defs['error'], step.name).toBeUndefined();
      } else {
        expect(defs['error']?.['enum'], step.name).toEqual(step.errors);
        expect('x-extensible-enum' in (defs['error'] ?? {}), step.name).toBe(false);
      }
    }
  });

  it('say why a new password is asked for: register, reset or update_required', () => {
    const newPassword = STEPS.find((step) => step.name === 'new_password');
    if (newPassword === undefined) throw new Error('no new_password step');
    const purpose = (newPassword.params['properties'] as Record<string, JsonSchema>)['purpose'];
    expect(purpose?.['enum']).toEqual(['register', 'reset', 'update_required']);
    expect(newPassword.params['required']).toContain('purpose');
  });

  it('close every answer: a member a step does not declare is refused', () => {
    for (const step of STEPS) {
      expect(step.answer['additionalProperties'], step.name).toBe(false);
      const answer = stepFilePart(step, 'answer');
      expect(answer({ ...step.example.answer, return_to: 'https://evil.example' }), step.name).toBe(
        false
      );
      const request = validator.schema(stepComponentNames(step).answer);
      expect(request({ ...exampleAnswer(step), redirect_uri: 'https://evil.example' })).toBe(false);
    }
  });

  it('need the CSRF value and the step name in every answer', () => {
    for (const step of STEPS) {
      const request = validator.schema(stepComponentNames(step).answer);
      const withoutCsrf: Record<string, unknown> = { ...exampleAnswer(step) };
      delete withoutCsrf['csrf'];
      const withoutType: Record<string, unknown> = { ...exampleAnswer(step) };
      delete withoutType['type'];
      expect(request(withoutCsrf), step.name).toBe(false);
      expect(request(withoutType), step.name).toBe(false);
    }
  });

  it('keep personal data out of the params: no account value is readable with the id alone', () => {
    const accountValues = (schema: unknown): number =>
      JSON.stringify(schema).split('"x-qauth-display":"account"').length - 1;
    for (const step of STEPS) {
      expect(accountValues(step.params), step.name).toBe(0);
    }
    const read = (INTERACTION_OPENAPI['components'] as { schemas: Record<string, unknown> })
      .schemas;
    for (const name of ['Interaction', 'ClientDisplay', 'Brand']) {
      expect(accountValues(read[name]), name).toBe(0);
    }
  });
});

describe('the step examples', () => {
  // The acceptance criterion: every step has a schema and an example, and the
  // example validates against the schema. INT-02 reuses them as test vectors.
  it.each(STEPS.map((step) => [step.name, step] as const))(
    '%s: each part validates against the step’s own schema file',
    (_name, step) => {
      expectValid(stepFilePart(step, ''), step.example.step, 'step object');
      expectValid(stepFilePart(step, 'params'), step.example.step.params, 'params');
      expectValid(stepFilePart(step, 'answer'), step.example.answer, 'answer');
      expectValid(stepFilePart(step, 'personal'), step.example.personal ?? {}, 'personal');
      if (step.example.step.error !== undefined) {
        expect(step.errors).toContain(step.example.step.error);
      }
      const file = stepJsonSchema(step);
      expect(file['examples']).toEqual([step.example.step]);
    }
  );

  it.each(STEPS.map((step) => [step.name, step] as const))(
    '%s: the request and responses of the example validate against the document',
    (_name, step) => {
      expectValid(validator.schema('Interaction'), exampleInteraction(step), 'step read');
      expectValid(validator.schema('AnswerRequest'), exampleAnswer(step), 'answer request');
      expectValid(validator.schema('AnswerResult'), exampleAnswerResult(step), 'answer result');
      expectValid(validator.schema('PersonalData'), examplePersonal(step), 'personal data');
    }
  );

  it('give every step that has personal data an example of it', () => {
    for (const step of STEPS) {
      const members = Object.keys((step.personal['properties'] ?? {}) as object);
      expect(step.example.personal !== undefined, step.name).toBe(members.length > 0);
    }
  });

  it('name only steps that exist as alternatives and next steps', () => {
    const names = new Set(STEPS.map((step) => step.name));
    for (const step of STEPS) {
      for (const alternative of step.example.alternatives ?? []) {
        expect(names.has(alternative), `${step.name} → ${alternative}`).toBe(true);
        expect(alternative).not.toBe(step.name);
      }
      if ('step' in step.example.next) expect(names.has(step.example.next.step)).toBe(true);
    }
  });

  it('are refused by the schemas when they are wrong, so the check is not vacuous', () => {
    const password = STEPS.find((step) => step.name === 'password');
    if (password === undefined) throw new Error('no password step');
    const answer = stepFilePart(password, 'answer');
    expect(answer({})).toBe(false);
    const read = validator.schema('Interaction');
    expect(read({ ...exampleInteraction(password), csrf: 'short' })).toBe(false);
    expect(
      read({ ...exampleInteraction(password), step: { ...password.example.step, error: 'nope' } })
    ).toBe(false);
  });
});
