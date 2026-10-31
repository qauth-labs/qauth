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

  it.each(['constructor', 'toString', 'valueOf', 'hasOwnProperty'])(
    'refuses %s, which Object.prototype already has, as a group or a member name',
    (name) => {
      const registry = createPolicyRegistry();
      expect(() => registry.registerPolicyGroup(name, { a: lifetime() })).toThrow(
        /Object\.prototype/
      );
      expect(() => registry.registerPolicyGroup('sessions', { [name]: lifetime() })).toThrow(
        /Object\.prototype/
      );
      expect(registry.groups()).toEqual([]);
    }
  );

  it('holds a field from another copy of the library, or a forged one, to the same rules', () => {
    const registry = createPolicyRegistry();
    const forged = { ...lifetime(), securityWhen: 'loosening-or-widening' };
    expect(() => registry.registerPolicyGroup('sessions', { maxSeconds: forged as never })).toThrow(
      /sessions\.maxSeconds: securityWhen "loosening-or-widening"/
    );
    const silentSecret = { ...secret(), securityWhen: 'never', effects: [] };
    expect(() => registry.registerPolicyGroup('sessions', { key: silentSecret as never })).toThrow(
      /sessions\.key: a secret field/
    );
    expect(registry.groups()).toEqual([]);
    // A copy that keeps the rules is accepted: the brand is shared across copies.
    registry.registerPolicyGroup('sessions', { maxSeconds: { ...lifetime() } });
    expect(registry.field('sessions.maxSeconds')?.field.default).toBe(60);
  });

  it('keeps a frozen copy of each field, so changing the value given later changes no class', () => {
    const registry = createPolicyRegistry();
    // A copy, as from another copy of the library: branded, but not frozen.
    const field: Record<string, unknown> = { ...lifetime() };
    registry.registerPolicyGroup('sessions', { maxSeconds: field as never });
    field['securityWhen'] = 'never';
    field['effects'] = [];
    const registered = registry.field('sessions.maxSeconds')?.field;
    expect(Object.isFrozen(registered)).toBe(true);
    expect(registered?.securityWhen).toBe('loosening');
    const diff = registry.diffPolicies({}, { sessions: { maxSeconds: 120 } });
    expect(diff.class).toBe('security');
    expect(diff.effects).toEqual(['posture-loosening']);
  });

  it('reads a getter once, at registration, so a direction cannot turn after it', () => {
    const registry = createPolicyRegistry();
    const flag = policyField(z.boolean(), {
      seedEnv: null,
      default: true,
      direction: 'true-is-stricter',
      securityWhen: 'loosening',
      effects: ['credential-path'],
      secret: false,
      environmentBound: false,
      doc: DOC,
    });
    let reads = 0;
    // A copy whose direction is a getter, strict while it is checked.
    const field = Object.defineProperty({ ...flag }, 'direction', {
      enumerable: true,
      get: () => (reads++ === 0 ? 'true-is-stricter' : 'false-is-stricter'),
    });
    registry.registerPolicyGroup('sessions', { required: field as never });
    expect(reads).toBe(1);
    // true to false loosens a true-is-stricter field, so it is a security change.
    expect(registry.diffPolicies({}, { sessions: { required: false } }).changes).toEqual([
      expect.objectContaining({ direction: 'loosening', class: 'security' }),
    ]);
  });

  it('keeps a secret secret when the value given is turned into a plain field after registration', () => {
    const registry = createPolicyRegistry();
    const field: Record<string, unknown> = { ...secret() };
    registry.registerPolicyGroup('sessions', { upstream: { clientSecret: field as never } });
    Object.assign(field, { secret: false, securityWhen: 'never', effects: [] });
    const diff = registry.diffPolicies(
      {},
      { sessions: { upstream: { clientSecret: 'upstream-secret-value' } } }
    );
    expect(diff.changes).toEqual([
      expect.objectContaining({
        path: 'sessions.upstream.clientSecret',
        before: false,
        after: true,
        secret: true,
        class: 'security',
      }),
    ]);
    expect(JSON.stringify(diff)).not.toContain('upstream-secret-value');
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
