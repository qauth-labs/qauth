import { describe, expect, expectTypeOf, it } from 'vitest';
import { z } from 'zod';

import { defineEventType, type EventTypeDefinition, RELEASE_TAG_PATTERN } from './definition';
import { EXAMPLE_EVENT } from './docs-page';
import { EVENT_CATEGORIES } from './envelope';
import { EVENT_TYPE_PATTERN } from './identifier';
import { dataJsonSchema } from './json-schema';
import {
  EVENT_TYPES,
  type EventDataOf,
  EventValidationError,
  getEventType,
  isRegisteredEventType,
  parseEvent,
  validateRegistry,
} from './registry';

const validate = (definitions: readonly EventTypeDefinition[]) =>
  validateRegistry(definitions, dataJsonSchema);

const sample = (overrides: Partial<EventTypeDefinition> = {}): EventTypeDefinition => ({
  ...defineEventType({
    name: 'sample.happened',
    version: 1,
    description: 'A sample event.',
    category: 'user',
    severity: 'info',
    since: 'v0.2.0',
    data: z.strictObject({ count: z.int() }),
  }),
  ...overrides,
});

describe('the event type registry', () => {
  // The acceptance criterion of #456: every entry has a data schema, a
  // category, `since` and an identifier of the form urn:qauth:event:<name>:v<N>,
  // here with the release-candidate suffix -rc.<M>.
  it.each(EVENT_TYPES.map((definition) => [definition.type, definition] as const))(
    '%s has a data schema, a category, since and a well-formed identifier',
    (type, definition) => {
      expect(type).toMatch(EVENT_TYPE_PATTERN);
      expect(type).toBe(
        `urn:qauth:event:${definition.name}:v${definition.version}-rc.${definition.rc}`
      );
      expect(definition.data).toBeInstanceOf(z.ZodObject);
      expect(EVENT_CATEGORIES).toContain(definition.category);
      expect(definition.since).toMatch(RELEASE_TAG_PATTERN);
    }
  );

  // Nothing about a type is promised before QAuth 1.0.0 (ADR-018 §5). The
  // release that ships 1.0.0 drops the suffix from every type, and this test.
  it('keeps every type a release candidate until QAuth 1.0.0', () => {
    expect(EVENT_TYPES.filter((definition) => definition.rc === undefined)).toEqual([]);
  });

  it('passes every registry rule, the payload rules included', () => {
    expect(validate(EVENT_TYPES)).toEqual([]);
  });

  it('registers each type once', () => {
    const types = EVENT_TYPES.map((definition) => definition.type);
    expect(new Set(types).size).toBe(types.length);
  });

  it('types each registered identifier and its data', () => {
    expectTypeOf<EventDataOf<'urn:qauth:event:user.signed_in:v1-rc.0'>>().toEqualTypeOf<{
      method: 'password' | 'wallet';
      verifierProfile?: string | undefined;
    }>();
    // @ts-expect-error an identifier the registry does not hold
    expectTypeOf<EventDataOf<'urn:qauth:event:user.teleported:v1'>>().toBeObject();
  });

  it('looks types up by identifier', () => {
    expect(getEventType('urn:qauth:event:user.signed_in:v1-rc.0')?.name).toBe('user.signed_in');
    expect(getEventType('urn:qauth:event:user.signed_in:v1')).toBeUndefined();
    expect(getEventType('urn:qauth:event:user.signed_in:v9')).toBeUndefined();
    expect(isRegisteredEventType('urn:qauth:event:token.issued:v1-rc.0')).toBe(true);
    expect(isRegisteredEventType('user.signed_in')).toBe(false);
  });
});

describe('the registry rules catch a bad entry', () => {
  it('accepts the sample entry', () => {
    expect(validate([sample()])).toEqual([]);
  });

  it.each([
    [
      'an identifier of the wrong form',
      { type: 'urn:qauth:sample.happened:v1' },
      'the identifier must match',
    ],
    [
      'an identifier that is not built from the name and version',
      { type: 'urn:qauth:event:sample.other:v1' },
      'must be built from the name',
    ],
    [
      'an identifier with a candidate number the entry does not have',
      { type: 'urn:qauth:event:sample.happened:v1-rc.3' },
      'must be built from the name, the version and the candidate number',
    ],
    ['no data schema', { data: undefined }, 'must be a Zod object'],
    ['an open data schema', { data: z.object({ count: z.int() }) }, 'must be closed'],
    ['an unknown category', { category: 'system' }, 'the category must be one of'],
    ['no category', { category: undefined }, 'the category must be one of'],
    ['an unknown severity', { severity: 'debug' }, 'the severity must be one of'],
    ['no since', { since: undefined }, 'since must be the release'],
    ['a since that is not a release', { since: '0.2' }, 'since must be the release'],
    ['no description', { description: ' ' }, 'the description must say'],
    ['an unknown subject', { subject: 'realm' }, 'the subject must be one of'],
  ])('fails %s', (_label, overrides, message) => {
    const problems = validate([sample(overrides as Partial<EventTypeDefinition>)]);
    expect(problems.join('\n')).toContain(message);
  });

  // The acceptance criterion of #456: a registry test fails if a schema
  // declares a field named like a password, code, token, OTP, secret or link.
  it.each(['password', 'code', 'accessToken', 'otp', 'clientSecret', 'resetLink'])(
    'fails a data schema that declares %s',
    (field) => {
      const problems = validate([sample({ data: z.strictObject({ [field]: z.string() }) })]);
      expect(problems).toEqual([
        expect.stringContaining(`data/properties/${field}: "${field}" names a secret`),
      ]);
    }
  );

  it('fails a nested secret field too', () => {
    const data = z.strictObject({ list: z.array(z.strictObject({ refreshToken: z.string() })) });
    expect(validate([sample({ data })]).join('\n')).toContain('refreshToken');
  });

  it('fails undeclared personal data, and passes it once the type declares it', () => {
    const data = z.strictObject({ email: z.string() });
    expect(validate([sample({ data })]).join('\n')).toContain('names personal data');
    expect(validate([sample({ data, personalData: ['email'] })])).toEqual([]);
  });

  it('fails a type registered twice', () => {
    expect(validate([sample(), sample()]).join('\n')).toContain('registered twice');
  });

  describe('the versioning rules', () => {
    const v2 = () =>
      defineEventType({
        name: 'sample.happened',
        version: 2,
        description: 'A sample event, version 2.',
        category: 'user',
        severity: 'info',
        since: 'v1.3.0',
        data: z.strictObject({ total: z.int() }),
      });

    it('accepts a deprecated v1 beside the v2 that replaces it', () => {
      const v1 = sample({
        deprecated: { since: 'v1.3.0', replacedBy: 'urn:qauth:event:sample.happened:v2' },
      });
      expect(validate([v1, v2()])).toEqual([]);
    });

    it('accepts a v2 alone, once v1 is removed in a major release', () => {
      expect(validate([v2()])).toEqual([]);
    });

    it('fails a v1 that stays undeprecated beside its v2', () => {
      expect(validate([sample(), v2()]).join('\n')).toContain(
        'must be deprecated with replacedBy urn:qauth:event:sample.happened:v2'
      );
    });

    describe('release candidates', () => {
      const candidate = (rc: number, overrides: Partial<EventTypeDefinition> = {}) =>
        sample({
          ...defineEventType({
            name: 'sample.happened',
            version: 1,
            rc,
            description: 'A sample event.',
            category: 'user',
            severity: 'info',
            since: 'v0.2.0',
            data: z.strictObject({ count: z.int() }),
          }),
          ...overrides,
        });

      it('builds the identifier with the suffix', () => {
        expect(candidate(0).type).toBe('urn:qauth:event:sample.happened:v1-rc.0');
        expect(validate([candidate(0)])).toEqual([]);
      });

      it('accepts a candidate replaced in place by the next one', () => {
        expect(validate([candidate(1)])).toEqual([]);
      });

      it('orders a candidate before the next one, and every candidate before the release', () => {
        const rc0 = candidate(0, {
          deprecated: { since: 'v0.3.0', replacedBy: 'urn:qauth:event:sample.happened:v1-rc.1' },
        });
        const rc1 = candidate(1, {
          deprecated: { since: 'v1.0.0', replacedBy: 'urn:qauth:event:sample.happened:v1' },
        });
        expect(validate([sample(), rc1, rc0])).toEqual([]);
      });

      it('fails a candidate that stays undeprecated beside the next one', () => {
        expect(validate([candidate(0), candidate(1)]).join('\n')).toContain(
          'urn:qauth:event:sample.happened:v1-rc.0: must be deprecated with replacedBy urn:qauth:event:sample.happened:v1-rc.1'
        );
      });

      it('fails a deprecation that names an earlier candidate', () => {
        const rc1 = candidate(1, {
          deprecated: { since: 'v0.3.0', replacedBy: 'urn:qauth:event:sample.happened:v1-rc.0' },
        });
        expect(validate([candidate(0), rc1]).join('\n')).toContain(
          'replacedBy must name a later version'
        );
      });
    });

    it('fails a deprecation that names no registered later version', () => {
      const v1 = sample({
        deprecated: { since: 'v1.3.0', replacedBy: 'urn:qauth:event:sample.happened:v3' },
      });
      expect(validate([v1]).join('\n')).toContain(
        'replacedBy must name a registered later version'
      );
    });
  });
});

describe('parseEvent', () => {
  const event = (overrides: Record<string, unknown> = {}) => ({
    ...structuredClone(EXAMPLE_EVENT),
    ...overrides,
  });

  it('accepts the documented example', () => {
    expect(parseEvent(event())).toEqual(EXAMPLE_EVENT);
  });

  it('accepts a minimal event: no actor, subject, client or request', () => {
    const { id, type, time, realm, category, data } = EXAMPLE_EVENT;
    expect(() => parseEvent({ id, type, time, realm, category, data })).not.toThrow();
  });

  it('refuses an unknown type', () => {
    expect(() => parseEvent(event({ type: 'urn:qauth:event:user.teleported:v1-rc.0' }))).toThrow(
      /unknown event type/
    );
  });

  it.each([
    ['an id that is not a UUIDv7', { id: '6f1c2c4e-0f0a-4b1e-9c3d-2a1b0c9d8e7f' }, '/id'],
    ['a time with an offset', { time: '2026-10-22T11:30:00+02:00' }, '/time'],
    ['a time as a number', { time: 1_761_125_400_000 }, '/time'],
    ['a category the type does not have', { category: 'admin' }, '/category'],
    ['a null member', { client: null }, '/client'],
    ['an unknown envelope member', { extra: true }, 'extra'],
    ['data that misses a required member', { data: {} }, '/data/method'],
    [
      'data with an undeclared member',
      { data: { method: 'password', email: 'a@b.test' } },
      'email',
    ],
    ['data with a value outside a set', { data: { method: 'carrier_pigeon' } }, '/data/method'],
    [
      'a subject of the wrong kind',
      { subject: { type: 'client', id: 'notes-app' } },
      '/subject/type',
    ],
    [
      'an IPv4-mapped address in raw form',
      { request: { ip: '::ffff:203.0.113.5' } },
      '/request/ip',
    ],
  ])('refuses %s', (_label, overrides, where) => {
    expect(() => parseEvent(event(overrides))).toThrow(EventValidationError);
    expect(() => parseEvent(event(overrides))).toThrow(where);
  });

  it('refuses a subject on a type that has none', () => {
    const { id, time, realm, category, client } = EXAMPLE_EVENT;
    const revocation = {
      id,
      type: 'urn:qauth:event:token.revocation_failed:v1-rc.0',
      time,
      realm,
      category,
      client,
      data: { error: 'invalid_client' },
    };
    expect(() => parseEvent(revocation)).not.toThrow();
    expect(() => parseEvent({ ...revocation, subject: { type: 'user', id: 'u-1' } })).toThrow(
      '/subject: a token.revocation_failed event has no subject'
    );
  });

  it('refuses a token-shaped value outside data too', () => {
    const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
    expect(() => parseEvent(event({ actor: { type: 'user', id: jwt } }))).toThrow(
      '/actor/id: the value is shaped like a token'
    );
  });

  it('refuses a token-shaped value in a free-form member', () => {
    const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
    expect(() => parseEvent(event({ data: { method: 'wallet', verifierProfile: jwt } }))).toThrow(
      /shaped like a token/
    );
  });
});
