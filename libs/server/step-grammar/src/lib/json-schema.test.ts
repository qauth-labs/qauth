import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import {
  STEP_SCHEMA_DIR,
  stepJsonSchema,
  stepNamed,
} from '@qauth-labs/shared-interaction-contract';
import {
  describeErrors,
  strictValidator,
} from '@qauth-labs/shared-interaction-contract/src/testing/schema-validator';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { toJsonSchemaPart } from './json-schema';
import { generatedStepSchemaFile, publishedStepSchemaPath } from './step-files';
import { grammarStep, STEP_GRAMMAR, STEP_NAMES, type StepName } from './steps';
import { matching } from './zod-kit';

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');

/** A value as it is written to a file and read back. */
const asJson = (value: unknown): unknown => JSON.parse(JSON.stringify(value));

const published = (name: StepName): unknown =>
  JSON.parse(readFileSync(join(REPO_ROOT, publishedStepSchemaPath(name)), 'utf8'));

const MISMATCH =
  'The step schema generated from the grammar’s Zod schemas differs from the file the Interaction API contract publishes. Change both libraries together: the Zod schema in libs/server/step-grammar/src/lib/steps/ and the step in libs/shared/interaction-contract/src/lib/steps/, then run `pnpm exec nx run shared-interaction-contract:contract-export`.';

/** A strict Ajv validator for one part of a step file (`''` for the whole record). */
function filePart(file: unknown, part: string) {
  const ajv = strictValidator();
  const schema = asJson(file) as { $id: string };
  ajv.addSchema(schema);
  const validate = ajv.getSchema(part === '' ? schema.$id : `${schema.$id}#/$defs/${part}`);
  if (validate === undefined) throw new Error(`no part ${part}`);
  return validate;
}

describe('the JSON Schema generated from the Zod schemas', () => {
  // The acceptance criterion: the generated JSON Schema equals the published
  // files. Equal as JSON values: member order carries no meaning in a schema.
  // CI's unit run compares them on every pull request.
  it.each(STEP_NAMES)('%s: equals the step file the Interaction API contract publishes', (name) => {
    expect(asJson(generatedStepSchemaFile(name)), MISMATCH).toStrictEqual(published(name));
  });

  it('covers every step file the contract publishes, and no other', () => {
    const files = readdirSync(join(REPO_ROOT, STEP_SCHEMA_DIR)).sort();
    expect(files).toEqual(STEP_NAMES.map((name) => `${name}.json`).sort());
  });

  it('sees a changed rule, so the comparison is not vacuous', () => {
    const answer = STEP_GRAMMAR.password.answer.extend({
      password: z.string().min(1).max(255),
    });
    const changed = stepJsonSchema({
      ...stepNamed('password'),
      answer: toJsonSchemaPart(answer),
    });
    expect(asJson(changed)).not.toStrictEqual(published('password'));
    const widened = stepJsonSchema({
      ...stepNamed('consent'),
      params: toJsonSchemaPart(STEP_GRAMMAR.consent.params.loose()),
    });
    expect(asJson(widened)).not.toStrictEqual(published('consent'));
  });
});

describe('the contract’s spelling of Zod’s JSON Schema', () => {
  it('writes a single string or boolean value as a bare const', () => {
    expect(toJsonSchemaPart(z.literal('public-key'))).toStrictEqual({ const: 'public-key' });
    expect(toJsonSchemaPart(z.literal(true))).toStrictEqual({ const: true });
  });

  it('writes integer values as an integer enum, and refuses a fraction', () => {
    expect(toJsonSchemaPart(z.literal([6, 8]))).toStrictEqual({ type: 'integer', enum: [6, 8] });
    expect(toJsonSchemaPart(z.literal(6))).toStrictEqual({ type: 'integer', enum: [6] });
    expect(() => toJsonSchemaPart(z.literal(1.5))).toThrow(/integer/);
  });

  it('writes an open object without additionalProperties, and keeps a closed one closed', () => {
    expect(toJsonSchemaPart(z.looseObject({}))).toStrictEqual({ type: 'object' });
    expect(toJsonSchemaPart(z.looseObject({ id: z.string() }))).toStrictEqual({
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
    });
    expect(toJsonSchemaPart(z.strictObject({}))).toStrictEqual({
      type: 'object',
      properties: {},
      additionalProperties: false,
    });
  });

  it('publishes a pattern as written, with its slashes, and checks it with the u flag', () => {
    const schema = matching(z.string(), '^otpauth://totp/\\p{L}+$');
    expect(toJsonSchemaPart(schema)).toStrictEqual({
      type: 'string',
      pattern: '^otpauth://totp/\\p{L}+$',
    });
    expect(schema.safeParse('otpauth://totp/Ä').success).toBe(true);
    expect(schema.safeParse('otpauth://totp/1').success).toBe(false);
  });

  it('refuses a Zod construct JSON Schema cannot express', () => {
    expect(() => toJsonSchemaPart(z.date())).toThrow();
  });
});

describe('the INT-01 examples', () => {
  // The acceptance criterion: every example of the Interaction API contract
  // validates against the schema generated from the grammar, and passes the
  // Zod schemas themselves, which are what the server runs.
  it.each(STEP_NAMES)('%s: validates against the generated schema', (name) => {
    const file = asJson(generatedStepSchemaFile(name)) as { examples: unknown[] };
    const { example } = stepNamed(name);
    const parts: [string, unknown][] = [
      ['', file.examples[0]],
      ['params', example.step.params],
      ['answer', example.answer],
      ['personal', example.personal ?? {}],
      ['amr', [...grammarStep(name).amr]],
    ];
    if (example.step.error !== undefined) parts.push(['error', example.step.error]);
    for (const [part, value] of parts) {
      const validate = filePart(file, part);
      expect(validate(value), `${part || 'record'}\n${describeErrors(validate)}`).toBe(true);
    }
  });

  it.each(STEP_NAMES)('%s: passes the grammar’s Zod schemas', (name) => {
    const step = grammarStep(name);
    const { example } = stepNamed(name);
    expect(step.params.safeParse(example.step.params).error).toBeUndefined();
    expect(step.answer.safeParse(example.answer).error).toBeUndefined();
    expect(step.personal.safeParse(example.personal ?? {}).error).toBeUndefined();
    if (example.step.error !== undefined) expect(step.errors).toContain(example.step.error);
  });
});

describe('the Zod schemas and the published schema', () => {
  /** Whether the Zod schema and the published part agree on `value`, and what they say. */
  function verdicts(name: StepName, part: 'params' | 'answer' | 'personal', value: unknown) {
    const zod = grammarStep(name)[part].safeParse(value).success;
    const json = filePart(published(name), part)(value);
    return { zod, json };
  }

  it.each(STEP_NAMES)('%s: both refuse a member the step does not declare', (name) => {
    const { example } = stepNamed(name);
    const parts = {
      params: example.step.params,
      answer: example.answer,
      personal: example.personal ?? {},
    };
    for (const [part, value] of Object.entries(parts)) {
      const withProse = { ...(value as object), message: 'Too many attempts. Try again later.' };
      expect(verdicts(name, part as 'params', withProse), `${name}.${part}`).toEqual({
        zod: false,
        json: false,
      });
    }
  });

  it('agree at the bounds and on the display rule', () => {
    const cases: [StepName, 'params' | 'answer' | 'personal', unknown, boolean][] = [
      ['password', 'answer', { password: 'x'.repeat(256) }, true],
      ['password', 'answer', { password: 'x'.repeat(257) }, false],
      ['password', 'answer', { password: '' }, false],
      ['identifier', 'answer', { login_hint: 'alice.example.com' }, false],
      ['identifier', 'answer', {}, false],
      ['email_code', 'answer', {}, true],
      ['email_code', 'answer', { otp: '12345' }, false],
      [
        'email_code',
        'params',
        { purpose: 'login', length: 6, expires_in: 600, resend_after: 60 },
        false,
      ],
      [
        'email_code',
        'params',
        { purpose: 'recovery', length: 7, expires_in: 600, resend_after: 60 },
        false,
      ],
      ['totp', 'params', { digits: 6.5 }, false],
      ['consent', 'answer', { decision: 'allow' }, true],
      [
        'consent',
        'params',
        {
          scopes: [
            {
              scope: 'notes:read',
              text: '<b>Read</b> your notes',
              sensitive: false,
              dangerous: false,
            },
          ],
          resources: [],
          remember_default: false,
        },
        false,
      ],
      [
        'consent',
        'params',
        {
          scopes: [
            {
              scope: 'notes:read',
              text: 'Read\u202eyour notes',
              sensitive: false,
              dangerous: false,
            },
          ],
          resources: [],
          remember_default: false,
        },
        false,
      ],
      [
        'consent',
        'params',
        {
          scopes: [{ scope: 'openid', sensitive: false, dangerous: false }],
          resources: ['javascript:alert(1)'],
          remember_default: false,
        },
        false,
      ],
      ['recovery_codes', 'personal', { codes: Array(10).fill('k7qd-2mvw-x4ra-p6tn') }, false],
      ['device_confirm', 'personal', {}, true],
      [
        'captcha',
        'params',
        { provider: 'pow', challenge: 'Qm9vbGVhbi1ub3QtYS1yZWFs', difficulty: 18, name: 'x' },
        false,
      ],
      ['captcha', 'params', { provider: 'hosted', name: 'turnstile', site_key: '0x4AAAA' }, true],
    ];
    for (const [name, part, value, valid] of cases) {
      expect(verdicts(name, part, value), `${name}.${part} ${JSON.stringify(value)}`).toEqual({
        zod: valid,
        json: valid,
      });
    }
  });

  it('differ on purpose in one place: the server parses a WebAuthn response, JSON Schema only annotates it', () => {
    expect(
      verdicts('webauthn_get', 'answer', { webauthn_response: '{"not":"a credential"}' })
    ).toEqual({
      zod: false,
      json: true,
    });
  });
});
