import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { defineEventType, type EventTypeDefinition, RELEASE_TAG_PATTERN } from './definition';
import { EXAMPLE_EVENT } from './docs-page';
import { EVENT_CATEGORIES } from './envelope';
import { EVENT_TYPE_PATTERN } from './identifier';
import { dataJsonSchema } from './json-schema';
import {
  EVENT_TYPES,
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
  // category, `since` and an identifier of the form urn:qauth:event:<name>:v<N>.
  it.each(EVENT_TYPES.map((definition) => [definition.type, definition] as const))(
    '%s has a data schema, a category, since and a well-formed identifier',
    (type, definition) => {
      expect(type).toMatch(EVENT_TYPE_PATTERN);
      expect(type).toBe(`urn:qauth:event:${definition.name}:v${definition.version}`);
      expect(definition.data).toBeInstanceOf(z.ZodObject);
      expect(EVENT_CATEGORIES).toContain(definition.category);
      expect(definition.since).toMatch(RELEASE_TAG_PATTERN);
    }
  );

  it('passes every registry rule, the payload rules included', () => {
    expect(validate(EVENT_TYPES)).toEqual([]);
  });

  it('registers each type once', () => {
    const types = EVENT_TYPES.map((definition) => definition.type);
    expect(new Set(types).size).toBe(types.length);
  });

  it('looks types up by identifier', () => {
    expect(getEventType('urn:qauth:event:user.signed_in:v1')?.name).toBe('user.signed_in');
    expect(getEventType('urn:qauth:event:user.signed_in:v9')).toBeUndefined();
    expect(isRegisteredEventType('urn:qauth:event:token.issued:v1')).toBe(true);
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
      'built from the name and the version',
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
    expect(() => parseEvent(event({ type: 'urn:qauth:event:user.teleported:v1' }))).toThrow(
      /unknown event type/
    );
  });

  it.each([
    ['an id that is not a UUIDv7', { id: '6f1c2c4e-0f0a-4b1e-9c3d-2a1b0c9d8e7f' }],
    ['a time with an offset', { time: '2026-10-22T11:30:00+02:00' }],
    ['a time as a number', { time: 1_761_125_400_000 }],
    ['a category the type does not have', { category: 'admin' }],
    ['a null member', { client: null }],
    ['an unknown envelope member', { extra: true }],
    ['data that misses a required member', { data: {} }],
    ['data with an undeclared member', { data: { method: 'password', email: 'a@b.test' } }],
    ['data with a value outside a set', { data: { method: 'carrier_pigeon' } }],
    ['a subject of the wrong kind', { subject: { type: 'client', id: 'notes-app' } }],
  ])('refuses %s', (_label, overrides) => {
    expect(() => parseEvent(event(overrides))).toThrow(EventValidationError);
  });

  it('refuses a token-shaped value in a free-form member', () => {
    const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
    expect(() => parseEvent(event({ data: { method: 'wallet', verifierProfile: jwt } }))).toThrow(
      /shaped like a token/
    );
  });
});
