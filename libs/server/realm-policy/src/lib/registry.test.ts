import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { PolicyDefinitionError, policyField, type PolicyFieldAnnotations } from './field';
import { createPolicyRegistry, type PolicyGroupShape } from './registry';

const DOC = { summary: 'A setting for this test.', link: 'https://docs.qauth.dev/reference/' };

const lifetime = (overrides: Partial<PolicyFieldAnnotations<number>> = {}) =>
  policyField(z.number().int().positive(), {
    seedEnv: null,
    default: 60,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: false,
    doc: DOC,
    ...overrides,
  } as PolicyFieldAnnotations<number>);

const secret = () =>
  policyField(z.string().min(1), {
    seedEnv: null,
    default: null,
    direction: 'opaque',
    securityWhen: 'any-change',
    effects: ['credential-path'],
    secret: true,
    environmentBound: true,
    doc: DOC,
  });

describe('registerPolicyGroup', () => {
  // Acceptance criterion of #514.
  it('refuses a second group with a clashing name', () => {
    const registry = createPolicyRegistry();
    registry.registerPolicyGroup('sessions', { idleSeconds: lifetime() });
    expect(() => registry.registerPolicyGroup('sessions', { maxSeconds: lifetime() })).toThrow(
      new PolicyDefinitionError('a policy group named "sessions" is already registered')
    );
    expect(() => registry.registerPolicyGroup('Sessions', { maxSeconds: lifetime() })).toThrow(
      PolicyDefinitionError
    );
    expect(() => registry.registerPolicyGroup('sessionS', { maxSeconds: lifetime() })).toThrow(
      /differs only in case from the registered group "sessions"/
    );
    expect(registry.groups()).toEqual(['sessions']);
    expect(registry.fields().map((entry) => entry.path)).toEqual(['sessions.idleSeconds']);
  });

  it.each([
    [
      'a name that is not a lower camelCase word',
      'brute-force',
      { a: lifetime() },
      /lower camelCase/,
    ],
    ['an empty group', 'empty', {}, /at least one field/],
    ['a member that is neither a field nor a group', 'odd', { a: 5 }, /made by policyField/],
    ['a member given as a list', 'odd', { a: [lifetime()] }, /made by policyField/],
    ['an empty nested group', 'nested', { inner: {} }, /at least one field/],
    ['a member name with a dot', 'odd', { 'a.b': lifetime() }, /lower camelCase/],
    [
      'members that differ only in case',
      'odd',
      { maxAge: lifetime(), maxage: lifetime() },
      /differs only in case/,
    ],
    [
      'a secret beside a member named like its flag',
      'odd',
      { password: secret(), passwordSet: lifetime() },
      /passwordSet/,
    ],
    [
      'groups nested too deep',
      'deep',
      { a: { b: { c: { d: { e: lifetime() } } } } },
      /nest at most/,
    ],
  ])('refuses %s', (_name, name, shape, message) => {
    const registry = createPolicyRegistry();
    expect(() => registry.registerPolicyGroup(name, shape as unknown as PolicyGroupShape)).toThrow(
      message
    );
    expect(registry.groups()).toEqual([]);
  });

  it('refuses a seed key that already seeds another field, and registers nothing of the group', () => {
    const registry = createPolicyRegistry();
    registry.registerPolicyGroup('first', { a: lifetime({ seedEnv: 'TEST_LIFETIME' }) });
    expect(() =>
      registry.registerPolicyGroup('second', {
        b: lifetime(),
        c: lifetime({ seedEnv: 'TEST_LIFETIME' }),
      })
    ).toThrow(/TEST_LIFETIME already seeds first\.a/);
    expect(registry.groups()).toEqual(['first']);
    expect(registry.field('second.b')).toBeUndefined();
    expect(() =>
      registry.registerPolicyGroup('third', {
        b: lifetime({ seedEnv: 'TEST_OTHER' }),
        c: lifetime({ seedEnv: 'TEST_OTHER' }),
      })
    ).toThrow(/one key seeds one field/);
  });

  it('adds a later group to every view, the diff and the seeding', () => {
    const registry = createPolicyRegistry();
    registry.registerPolicyGroup('tokens', { accessSeconds: lifetime() });
    expect(registry.parse({})).toEqual({ tokens: { accessSeconds: 60 } });
    registry.registerPolicyGroup('sessions', {
      maxSeconds: lifetime({ seedEnv: 'TEST_SESSION_MAX', default: 3600 }),
      upstream: { clientSecret: secret() },
    });
    expect(registry.parse({})).toEqual({
      tokens: { accessSeconds: 60 },
      sessions: { maxSeconds: 3600, upstream: {} },
    });
    expect(registry.defaultsFromEnv({ TEST_SESSION_MAX: '7200' })).toEqual({
      tokens: { accessSeconds: 60 },
      sessions: { maxSeconds: 7200, upstream: {} },
    });
    expect(registry.diffPolicies({}, { sessions: { maxSeconds: 7200 } }).changes).toEqual([
      expect.objectContaining({
        path: 'sessions.maxSeconds',
        direction: 'loosening',
        class: 'security',
      }),
    ]);
    expect(registry.toRepresentation({}, ['sessions.upstream.clientSecret'])).toEqual({
      tokens: { accessSeconds: 60 },
      sessions: { maxSeconds: 3600, upstream: { clientSecretSet: true } },
    });
    const json = registry.toJsonSchema('representation');
    expect(Object.keys(json['properties'] as object)).toEqual(['tokens', 'sessions']);
  });
});

describe('createPolicyRegistry', () => {
  it('takes a schema version of the 1-rc.<M> or 1 form only', () => {
    expect(createPolicyRegistry({ version: '1-rc.3' }).version).toBe('1-rc.3');
    expect(createPolicyRegistry({ version: '1' }).version).toBe('1');
    for (const version of ['v1', '1.0', '1-rc', '1-rc.01', '01', '']) {
      expect(() => createPolicyRegistry({ version }), version).toThrow(PolicyDefinitionError);
    }
  });

  it('refuses a view it does not know, and parsing the representation', () => {
    const registry = createPolicyRegistry();
    expect(() => registry.schema('patch' as never)).toThrow(/not a view/);
    expect(() => registry.parse({}, 'representation' as never)).toThrow(/cannot be parsed/);
  });
});
