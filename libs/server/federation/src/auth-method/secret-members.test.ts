import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { createSampleAuthMethod } from '../../testing/sample-auth-method.fixture';
import { AuthMethodContractError } from './errors';
import {
  authMethodSecretPaths,
  configMemberAt,
  configSpellsMemberOf,
  MAX_AUTH_METHOD_SECRET_MEMBERS,
  withConfigMembers,
  withoutConfigMembers,
} from './secret-members';

/** A method with `configSchema`, for the reader; the rest is the sample's. */
const withSchema = (configSchema: z.ZodType) => ({ type: 'oidc_corp', configSchema });

describe('authMethodSecretPaths (#600)', () => {
  it("reads the sample method's client secret", () => {
    expect(authMethodSecretPaths(createSampleAuthMethod())).toEqual(['clientSecret']);
  });

  it('reads optional, nullable, defaulted and nested secret members, in schema order', () => {
    const schema = z.object({
      clientId: z.string(),
      clientSecret: z.string().meta({ writeOnly: true }),
      spare: z.string().meta({ writeOnly: true }).optional(),
      wrapped: z.string().optional().meta({ writeOnly: true }),
      cleared: z.string().meta({ writeOnly: true }).nullable(),
      defaulted: z.string().meta({ writeOnly: true }).default('none'),
      mtls: z.object({ keyPassword: z.string().meta({ writeOnly: true }), certUrl: z.url() }),
    });
    expect(authMethodSecretPaths(withSchema(schema))).toEqual([
      'clientSecret',
      'spare',
      'wrapped',
      'cleared',
      'defaulted',
      'mtls.keyPassword',
    ]);
  });

  it('reads no secret from a config without one', () => {
    expect(authMethodSecretPaths(withSchema(z.object({ clientId: z.string() })))).toEqual([]);
    expect(authMethodSecretPaths(withSchema(z.object({})))).toEqual([]);
  });

  it.each<[string, z.ZodType]>([
    ['a config that is not an object', z.string()],
    ['a secret inside a list', z.object({ keys: z.array(z.string().meta({ writeOnly: true })) })],
    [
      'a secret inside a list of objects',
      z.object({ keys: z.array(z.object({ s: z.string().meta({ writeOnly: true }) })) }),
    ],
    [
      'a secret inside a union',
      z.object({
        auth: z.union([z.object({ s: z.string().meta({ writeOnly: true }) }), z.null()]),
      }),
    ],
    [
      'a secret record',
      z.object({ keys: z.record(z.string(), z.string().meta({ writeOnly: true })) }),
    ],
    ['a secret that is not a string', z.object({ pin: z.number().meta({ writeOnly: true }) })],
    ['a secret object', z.object({ key: z.object({ a: z.string() }).meta({ writeOnly: true }) })],
    ['a secret config', z.object({ a: z.string() }).meta({ writeOnly: true })],
    ['a secret whose name holds a dot', z.object({ 'a.b': z.string().meta({ writeOnly: true }) })],
  ])('refuses %s, so the boot fails rather than store a secret in the clear', (_case, schema) => {
    expect(() => authMethodSecretPaths(withSchema(schema))).toThrow(AuthMethodContractError);
  });

  it('refuses a schema with no JSON Schema form', () => {
    const notZod = { safeParse: () => ({ success: true }) } as unknown as z.ZodType;
    expect(() => authMethodSecretPaths(withSchema(notZod))).toThrow(/has no JSON Schema form/);
  });

  it('reads a mark on the output side of a pipe, as on its input side', () => {
    const schema = z.object({
      trimmed: z
        .string()
        .trim()
        .pipe(z.string().min(8).meta({ writeOnly: true })),
      reshaped: z
        .string()
        .transform((value) => ({ s: value }))
        .pipe(z.object({ s: z.string().meta({ writeOnly: true }) })),
      inputSide: z.string().meta({ writeOnly: true }).pipe(z.string().min(1)),
    });
    // `reshaped.s` is on the output side only, and is no member a request can
    // send: its path still counts, so the plugin is not stored in the clear.
    expect(authMethodSecretPaths(withSchema(schema))).toEqual([
      'inputSide',
      'trimmed',
      'reshaped.s',
    ]);
  });

  it.each<[string, z.ZodType]>([
    ['a Set', z.object({ keys: z.set(z.string().meta({ writeOnly: true })) })],
    ['a Map', z.object({ keys: z.map(z.string(), z.string().meta({ writeOnly: true })) })],
    ['a date', z.object({ since: z.date() })],
  ])('refuses a config schema holding %s, whose marks no JSON Schema shows', (_case, schema) => {
    expect(() => authMethodSecretPaths(withSchema(schema))).toThrow(/has no JSON Schema form/);
  });

  it('reads through a shared definition, and takes a recursive part that marks nothing', () => {
    const named = z.object({
      a: z.string().meta({ id: 'PlainA' }),
      key: z.string().meta({ id: 'SharedSecret', writeOnly: true }),
    });
    expect(authMethodSecretPaths(withSchema(named))).toEqual(['key']);

    interface Node {
      readonly label: string;
      readonly children: readonly Node[];
    }
    const node: z.ZodType<Node> = z.lazy(() =>
      z.object({ label: z.string(), children: z.array(node) })
    );
    expect(authMethodSecretPaths(withSchema(z.object({ tree: node })))).toEqual([]);
  });

  it('refuses a mark inside a recursive part', () => {
    interface Node {
      readonly secret: string;
      readonly next?: Node;
    }
    const node: z.ZodType<Node> = z.lazy(() =>
      z.object({ secret: z.string().meta({ writeOnly: true }), next: node.optional() })
    );
    expect(() => authMethodSecretPaths(withSchema(z.object({ chain: node })))).toThrow(
      AuthMethodContractError
    );
  });

  it(`refuses more than ${MAX_AUTH_METHOD_SECRET_MEMBERS} secret members`, () => {
    const shape = Object.fromEntries(
      Array.from({ length: MAX_AUTH_METHOD_SECRET_MEMBERS + 1 }, (_, index) => [
        `s${index}`,
        z.string().meta({ writeOnly: true }),
      ])
    );
    expect(() => authMethodSecretPaths(withSchema(z.object(shape)))).toThrow(
      AuthMethodContractError
    );
  });
});

describe('config members by path', () => {
  const config = { clientId: 'corp', clientSecret: 's3cret', mtls: { keyPassword: 'k', a: 1 } };

  it('reads a member at a path, and nothing past a missing or non-object step', () => {
    expect(configMemberAt(config, 'clientSecret')).toBe('s3cret');
    expect(configMemberAt(config, 'mtls.keyPassword')).toBe('k');
    expect(configMemberAt(config, 'mtls.missing')).toBeUndefined();
    expect(configMemberAt(config, 'clientId.length')).toBeUndefined();
    expect(configMemberAt({}, 'toString')).toBeUndefined();
  });

  it('removes the secret members from a copy and leaves the original alone', () => {
    const stripped = withoutConfigMembers(config, ['clientSecret', 'mtls.keyPassword']);
    expect(stripped).toEqual({ clientId: 'corp', mtls: { a: 1 } });
    expect(config.clientSecret).toBe('s3cret');
    expect(config.mtls.keyPassword).toBe('k');
  });

  it('puts secret members back into a copy, creating the objects on the way', () => {
    const merged = withConfigMembers(
      { clientId: 'corp' },
      new Map([
        ['clientSecret', 's3cret'],
        ['mtls.keyPassword', 'k'],
      ])
    );
    expect(merged).toEqual({
      clientId: 'corp',
      clientSecret: 's3cret',
      mtls: { keyPassword: 'k' },
    });
  });

  it('finds a secret path however a config spells it, nested or with dots in one name', () => {
    const paths = ['clientSecret', 'mtls.keyPassword'];
    expect(configSpellsMemberOf({ mtls: { keyPassword: 'x' } }, paths)).toBe(true);
    expect(configSpellsMemberOf({ 'mtls.keyPassword': 'x' }, paths)).toBe(true);
    expect(configSpellsMemberOf({ clientSecret: null }, paths)).toBe(true);
    expect(configSpellsMemberOf({ mtls: { certUrl: 'x' }, clientId: 'y' }, paths)).toBe(false);
    expect(configSpellsMemberOf({ clientSecret: 'x' }, [])).toBe(false);
  });

  it('sets a member named __proto__ as a member, never as a prototype', () => {
    const merged = withConfigMembers({}, new Map([['__proto__', 'x']]));
    expect(Object.getPrototypeOf(merged)).toBe(Object.prototype);
    expect(Object.hasOwn(merged, '__proto__')).toBe(true);
  });
});
