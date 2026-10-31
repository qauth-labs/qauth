import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  ANNOTATION_KEYS,
  assertPolicyField,
  isPolicyField,
  ordered,
  PolicyDefinitionError,
  policyField,
  type PolicyFieldAnnotations,
} from './field';

const DOC = { summary: 'A setting for this test.', link: 'https://docs.qauth.dev/reference/' };

const NUMBER: PolicyFieldAnnotations<number> = {
  seedEnv: 'TEST_SETTING',
  default: 5,
  direction: 'lower-is-stricter',
  securityWhen: 'loosening',
  effects: ['credential-path'],
  secret: false,
  environmentBound: false,
  doc: DOC,
};

/** `policyField` over `schema` with `NUMBER`'s annotations changed by `changes`, untyped on purpose. */
const define = (changes: Record<string, unknown>, schema: z.ZodType = z.number().int()) =>
  policyField(schema, { ...NUMBER, ...changes } as never);

describe('policyField', () => {
  it('makes a frozen, branded field', () => {
    const field = policyField(z.number().int(), NUMBER);
    expect(isPolicyField(field)).toBe(true);
    expect(Object.isFrozen(field)).toBe(true);
    expect(Object.isFrozen(field.effects)).toBe(true);
    expect(Object.isFrozen(field.doc)).toBe(true);
    expect(isPolicyField({ ...NUMBER })).toBe(false);
  });

  it('freezes a copy of the default, so the definition cannot change it later', () => {
    const list = ['a'];
    const field = policyField(z.array(z.string()), {
      ...NUMBER,
      default: list,
      direction: 'subset-is-stricter',
    });
    list.push('b');
    expect(field.default).toEqual(['a']);
    expect(Object.isFrozen(field.default)).toBe(true);
  });

  it.each(ANNOTATION_KEYS)('refuses a field without the annotation %s', (key) => {
    const annotations: Record<string, unknown> = { ...NUMBER };
    delete annotations[key];
    expect(() => policyField(z.number().int(), annotations as never)).toThrow(
      new PolicyDefinitionError(`the annotation "${key}" is missing`)
    );
  });

  it('refuses an annotation it does not know', () => {
    expect(() => define({ stricter: 'lower' })).toThrow(/"stricter" is not an annotation/);
  });

  it('refuses something that is not a Zod type', () => {
    expect(() => policyField({} as never, NUMBER as never)).toThrow(/needs a Zod type/);
    const lookalike = { safeParse: (data: unknown) => ({ success: true, data }) };
    expect(() => policyField(lookalike as never, NUMBER as never)).toThrow(/needs a Zod type/);
  });

  // An opaque string or object field, which the checks below vary.
  const OPAQUE = { direction: 'opaque', securityWhen: 'never', effects: [] };

  it('refuses a type with no JSON Schema in a form a view exports', () => {
    expect(() =>
      define(
        { ...OPAQUE, default: 'a' },
        z.string().transform((value) => value)
      )
    ).toThrow(/no JSON Schema \(output\): Transforms/);
    expect(() => define({ ...OPAQUE, default: new Date(0) }, z.date())).toThrow(
      /no JSON Schema \(input\): Date/
    );
    // The representation leaves a secret out, so only its input form is exported.
    expect(
      define(
        {
          ...OPAQUE,
          securityWhen: 'any-change',
          effects: ['credential-path'],
          secret: true,
          default: null,
        },
        z.string().transform((value) => value)
      ).secret
    ).toBe(true);
  });

  it('refuses a type that lets a member of the representation be absent', () => {
    for (const schema of [z.number().int().optional(), z.number().int().default(5), z.any()]) {
      expect(() => define({}, schema)).toThrow(/refuses undefined/);
    }
    expect(define({ ...OPAQUE, default: null }, z.string().nullable()).default).toBeNull();
  });

  it('refuses a default that is not plain JSON', () => {
    const at = new Date(0);
    expect(() => define({ ...OPAQUE, default: { at } }, z.record(z.string(), z.unknown()))).toThrow(
      /plain JSON/
    );
    expect(
      define({ ...OPAQUE, default: { at: 'noon' } }, z.record(z.string(), z.unknown())).default
    ).toEqual({ at: 'noon' });
  });

  it.each([
    ['an unknown direction', { direction: 'sideways' }, /direction "sideways"/],
    ['a bare ordered', { direction: 'ordered' }, /direction "ordered"/],
    [
      'an ordered direction of one value',
      { direction: { kind: 'ordered', order: ['a'] } },
      /at least two/,
    ],
    [
      'an ordered direction that repeats a value',
      { direction: { kind: 'ordered', order: ['a', 'a'] } },
      /distinct/,
    ],
    ['an unknown securityWhen', { securityWhen: 'sometimes' }, /securityWhen "sometimes"/],
    ['an effect outside the closed list', { effects: ['credential-paths'] }, /closed list/],
    ['a repeated effect', { effects: ['credential-path', 'credential-path'] }, /distinct/],
    [
      'effects on a field that is never a security operation',
      { securityWhen: 'never' },
      /has no effects/,
    ],
    ['no effect on a field that can be a security operation', { effects: [] }, /names the effects/],
    [
      'no effect on an any-change field',
      { effects: [], securityWhen: 'any-change' },
      /names the effects/,
    ],
    [
      'an opaque field that is a security operation when loosened',
      { direction: 'opaque' },
      /no loosening/,
    ],
    ['a seed key that is not an environment variable name', { seedEnv: 'test-setting' }, /seedEnv/],
    ['a non-boolean secret', { secret: 'no' }, /booleans/],
    ['a non-boolean environmentBound', { environmentBound: 1 }, /booleans/],
    ['a doc of two sentences', { doc: { ...DOC, summary: 'One. Two.' } }, /one sentence/],
    ['a doc without a full stop', { doc: { ...DOC, summary: 'A setting' } }, /one sentence/],
    ['a doc on two lines', { doc: { ...DOC, summary: 'A\nsetting.' } }, /one sentence/],
    [
      'a doc link outside the docs site',
      { doc: { ...DOC, link: 'https://example.com/' } },
      /docs\.qauth\.dev/,
    ],
    ['a doc with another member', { doc: { ...DOC, title: 'x' } }, /doc is/],
    ['a default the type refuses', { default: 5.5 }, /value of the type/],
    [
      'a default of another kind than the direction compares',
      { direction: 'true-is-stricter' },
      /does not fit/,
    ],
  ])('refuses %s', (_name, changes, message) => {
    expect(() => define(changes)).toThrow(PolicyDefinitionError);
    expect(() => define(changes)).toThrow(message);
  });

  it('refuses a default the type rewrites', () => {
    expect(() =>
      define(
        { default: ' padded ', direction: 'opaque', securityWhen: 'never', effects: [] },
        z.string().trim()
      )
    ).toThrow(/unchanged by it/);
  });

  it('refuses an order that leaves out a value of the enum, or names one it refuses', () => {
    const levels = z.enum(['low', 'mid', 'high']);
    expect(() => define({ default: 'low', direction: ordered(['low', 'high']) }, levels)).toThrow(
      /leaves out the value "mid"/
    );
    expect(() =>
      define({ default: 'low', direction: ordered(['low', 'mid', 'high', 'max']) }, levels)
    ).toThrow(/names "max"/);
    expect(
      define({ default: 'low', direction: ordered(['low', 'mid', 'high']) }, levels).direction
    ).toEqual({
      kind: 'ordered',
      order: ['low', 'mid', 'high'],
    });
  });

  it('refuses an ordered field whose type accepts a value outside the order', () => {
    const direction = ordered(['low', 'high']);
    expect(() => define({ default: 'low', direction }, z.string())).toThrow(/enum type/);
    expect(() => define({ default: 'low', direction }, z.enum(['low', 'high']).nullable())).toThrow(
      /leaves out the value "null"/
    );
    expect(
      define({ default: 'low', direction }, z.union([z.literal('low'), z.literal('high')])).default
    ).toBe('low');
  });

  it('refuses a secret that has a default, an order or a rule other than any-change', () => {
    const secret = {
      default: null,
      direction: 'opaque',
      securityWhen: 'any-change',
      secret: true,
    };
    const schema = z.string().min(1);
    expect(define(secret, schema).secret).toBe(true);
    expect(() => define({ ...secret, default: 'changeme' }, schema)).toThrow(/a secret field/);
    expect(() => define({ ...secret, direction: 'lower-is-stricter' }, schema)).toThrow(
      /a secret field/
    );
    expect(() => define({ ...secret, securityWhen: 'never', effects: [] }, schema)).toThrow(
      /a secret field/
    );
  });
});

describe('assertPolicyField', () => {
  it('accepts a field policyField made, and a copy of it', () => {
    const field = policyField(z.number().int(), NUMBER);
    expect(() => assertPolicyField(field)).not.toThrow();
    expect(() => assertPolicyField({ ...field })).not.toThrow();
  });

  it('refuses a value without the brand, and a branded one that breaks a rule', () => {
    expect(() => assertPolicyField({ ...NUMBER, schema: z.number() })).toThrow(/not a field/);
    const field = policyField(z.number().int(), NUMBER);
    expect(() => assertPolicyField({ ...field, effects: [] })).toThrow(/names the effects/);
    expect(() => assertPolicyField({ ...field, extra: true })).toThrow(
      /"extra" is not an annotation/
    );
    expect(() => assertPolicyField({ ...field, default: 'five' })).toThrow(/value of the type/);
  });
});
