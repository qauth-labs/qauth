import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { defineEventType, type EventTypeDefinition, type SsfEventMapping } from './definition';
import { dataJsonSchema } from './json-schema';
import { EVENT_TYPES, getEventType, validateRegistry } from './registry';
import {
  CAEP_CREDENTIAL_CHANGE,
  CAEP_SESSION_REVOKED,
  CAEP_TOKEN_CLAIMS_CHANGE,
  initiatingEntityOf,
  QAUTH_SECEVENT_PATTERN,
  QAUTH_SSF_EVENTS,
  QAUTH_TOKEN_REVOKED,
  ssfEventMembers,
  ssfMappingOf,
  STANDARD_SSF_EVENTS,
} from './ssf-mapping';

const validate = (definitions: readonly EventTypeDefinition[]) =>
  validateRegistry(definitions, dataJsonSchema);

/** A security type of a test's own, with a user subject and two data members. */
const securityType = (overrides: Partial<EventTypeDefinition> = {}): EventTypeDefinition => ({
  ...defineEventType({
    name: 'sample.changed',
    version: 1,
    rc: 0,
    description: 'A sample security change.',
    category: 'user',
    severity: 'info',
    since: 'v0.2.0',
    subject: 'user',
    data: z.strictObject({
      rebound: z.boolean().describe('A flag.'),
      note: z.string().optional().describe('An optional code.'),
    }),
    security: true,
    ssf: { event: CAEP_SESSION_REVOKED },
  }),
  ...overrides,
});

const withMapping = (ssf: SsfEventMapping) => securityType({ ssf });

describe('the SSF rule of the registry (#540)', () => {
  // The unit acceptance criterion of #540: a security type that declares
  // neither a mapping nor `ssf: 'none'` fails the registry test.
  it('fails a security type that has neither a mapping nor ssf: none', () => {
    expect(validate([securityType({ ssf: undefined })]).join('\n')).toContain(
      "a security type must declare its SSF mapping, or ssf: 'none'"
    );
  });

  it("accepts a security type with a mapping, and one with ssf: 'none'", () => {
    expect(validate([securityType()])).toEqual([]);
    expect(validate([securityType({ ssf: 'none' })])).toEqual([]);
  });

  it('fails a type that declares ssf without being a security type', () => {
    expect(validate([securityType({ security: undefined })]).join('\n')).toContain(
      'only a security type declares ssf'
    );
    expect(validate([securityType({ security: undefined, ssf: 'none' })]).join('\n')).toContain(
      'only a security type declares ssf'
    );
  });

  it('fails an ssfNote with no ssf', () => {
    expect(
      validate([securityType({ security: undefined, ssf: undefined, ssfNote: 'why' })]).join('\n')
    ).toContain('ssfNote explains a mapping, so it needs ssf');
  });

  it.each([
    [
      'an event URI QAuth does not know',
      { event: 'https://example.com/event-type/whatever' },
      'ssf.event must be a CAEP 1.0 or RISC 1.0 event',
    ],
    [
      'a QAuth-defined event that is not listed',
      { event: 'urn:qauth:secevent:sample-changed:v1-rc.0' },
      'is not a QAuth-defined SSF event',
    ],
    [
      'a member the event does not define',
      { event: CAEP_SESSION_REVOKED, members: { claims: { value: {} } } },
      'session-revoked defines no such member',
    ],
    [
      'no member the event requires',
      { event: CAEP_CREDENTIAL_CHANGE, members: { credential_type: { value: 'password' } } },
      'ssf.members.change_type: credential-change requires it',
    ],
    [
      'a value outside the member’s closed set',
      {
        event: CAEP_CREDENTIAL_CHANGE,
        members: { credential_type: { value: 'password' }, change_type: { value: 'rotate' } },
      },
      '"rotate" is not one of create, revoke, update, delete',
    ],
    [
      'a required member from an optional data member',
      { event: CAEP_TOKEN_CLAIMS_CHANGE, members: { claims: { data: 'note' } } },
      'a required member cannot come from the optional data.note',
    ],
    [
      'a required member through a map that misses a value',
      {
        event: CAEP_CREDENTIAL_CHANGE,
        members: {
          credential_type: { value: 'password' },
          change_type: { data: 'rebound', map: { true: 'update' } },
        },
      },
      'the map must list every value of data.rebound: false',
    ],
    [
      'a data member the type does not have',
      { event: CAEP_SESSION_REVOKED, members: { reason_admin: { data: 'missing' } } },
      'data.missing is not a member',
    ],
    [
      'a member QAuth computes',
      { event: CAEP_SESSION_REVOKED, members: { event_timestamp: { value: 1 } } },
      'QAuth sets event_timestamp from the envelope',
    ],
    [
      'a key subject without data.keyId',
      { event: CAEP_SESSION_REVOKED, subject: 'key' as const },
      'ssf.subject "key" needs a required data.keyId',
    ],
    [
      'an unknown initiating entity',
      { event: CAEP_SESSION_REVOKED, initiatingEntity: 'robot' },
      'ssf.initiatingEntity must be one of admin, user, policy, system',
    ],
  ])('fails %s', (_label, mapping, message) => {
    expect(validate([withMapping(mapping as SsfEventMapping)]).join('\n')).toContain(message);
  });

  it('fails a subject mapping for a type whose subject is not a user or a client', () => {
    expect(validate([securityType({ subject: 'api_key' })]).join('\n')).toContain(
      'ssf.subject "subject" needs a type whose subject is a user or a client'
    );
  });

  it('passes every registered type', () => {
    expect(validate(EVENT_TYPES)).toEqual([]);
  });
});

describe('the mapping table of #540', () => {
  const eventOf = (type: string) => ssfMappingOf(getEventType(type) as EventTypeDefinition)?.event;

  it('maps sign-out to CAEP session-revoked', () => {
    expect(eventOf('urn:qauth:event:user.signed_out:v1-rc.0')).toBe(CAEP_SESSION_REVOKED);
  });

  it('maps consent withdrawal to CAEP token-claims-change', () => {
    expect(eventOf('urn:qauth:event:consent.revoked:v1-rc.0')).toBe(CAEP_TOKEN_CLAIMS_CHANGE);
  });

  it('maps client secret, API key and wallet credential changes to CAEP credential-change', () => {
    for (const type of [
      'urn:qauth:event:client.secret_rotated:v1-rc.0',
      'urn:qauth:event:api_key.created:v1-rc.0',
      'urn:qauth:event:api_key.revoked:v1-rc.0',
      'urn:qauth:event:wallet.linked:v1-rc.0',
    ]) {
      expect(eventOf(type), type).toBe(CAEP_CREDENTIAL_CHANGE);
    }
  });

  it('maps a replay that revokes a refresh family to CAEP session-revoked', () => {
    expect(eventOf('urn:qauth:event:token.family_revoked:v1-rc.0')).toBe(CAEP_SESSION_REVOKED);
  });

  it('maps RFC 7009 revocation to a QAuth-defined, versioned event', () => {
    expect(eventOf('urn:qauth:event:token.revoked:v1-rc.0')).toBe(QAUTH_TOKEN_REVOKED);
    expect(QAUTH_TOKEN_REVOKED).toMatch(/^urn:qauth:[a-z:-]+:v[1-9][0-9]*(-rc\.(0|[1-9][0-9]*))?$/);
  });

  it('names the kid of an emergency key retirement', () => {
    const mapping = ssfMappingOf(
      getEventType('urn:qauth:event:key.emergency_retired:v1-rc.0') as EventTypeDefinition
    );
    expect(mapping).toMatchObject({ subject: 'key', members: { kid: { data: 'keyId' } } });
  });

  // Nothing about a QAuth-defined identifier is promised before QAuth 1.0.0
  // (ADR-018 §5). The release that ships 1.0.0 drops the suffix, and this test.
  it('keeps every QAuth-defined SSF event a release candidate until QAuth 1.0.0', () => {
    for (const event of QAUTH_SSF_EVENTS) {
      expect(event.uri).toMatch(QAUTH_SECEVENT_PATTERN);
      expect(QAUTH_SECEVENT_PATTERN.exec(event.uri)?.[3], event.uri).toBeDefined();
    }
  });

  it('maps only to events that are listed, and lists every QAuth-defined one in use', () => {
    const listed = new Set([...STANDARD_SSF_EVENTS, ...QAUTH_SSF_EVENTS].map((e) => e.uri));
    const used = EVENT_TYPES.flatMap((definition) => {
      const mapping = ssfMappingOf(definition);
      return mapping === undefined ? [] : [mapping.event];
    });
    for (const uri of used) expect(listed).toContain(uri);
    for (const event of QAUTH_SSF_EVENTS) expect(used).toContain(event.uri);
  });
});

describe('ssfEventMembers', () => {
  const event = (overrides: Record<string, unknown> = {}) => ({
    time: '2026-10-30T09:30:00.900Z',
    category: 'user' as const,
    actor: { type: 'user' as const, id: 'u-1' },
    data: {},
    ...overrides,
  });

  it('adds event_timestamp, the event time in whole seconds, and initiating_entity', () => {
    expect(ssfEventMembers({ event: CAEP_SESSION_REVOKED }, event())).toEqual({
      event_timestamp: Math.floor(Date.parse('2026-10-30T09:30:00.900Z') / 1000),
      initiating_entity: 'user',
    });
  });

  it('fills fixed members and members from data, through a map', () => {
    const mapping: SsfEventMapping = {
      event: CAEP_CREDENTIAL_CHANGE,
      members: {
        credential_type: { value: 'verifiable-credential' },
        change_type: { data: 'rebound', map: { true: 'update', false: 'create' } },
      },
    };
    expect(ssfEventMembers(mapping, event({ data: { rebound: true } }))).toMatchObject({
      credential_type: 'verifiable-credential',
      change_type: 'update',
    });
    expect(ssfEventMembers(mapping, event({ data: { rebound: false } }))).toMatchObject({
      change_type: 'create',
    });
  });

  it('leaves out a member whose data member is absent', () => {
    const members = ssfEventMembers(
      { event: QAUTH_TOKEN_REVOKED, members: { token_type_hint: { data: 'typeHint' } } },
      event()
    );
    expect(members).not.toHaveProperty('token_type_hint');
  });

  it('answers undefined when a required member cannot be filled', () => {
    expect(
      ssfEventMembers(
        {
          event: CAEP_CREDENTIAL_CHANGE,
          members: {
            credential_type: { value: 'password' },
            change_type: { data: 'missing' },
          },
        },
        event()
      )
    ).toBeUndefined();
  });

  it('lets a mapping fix initiating_entity', () => {
    expect(
      ssfEventMembers({ event: CAEP_SESSION_REVOKED, initiatingEntity: 'policy' }, event())
    ).toMatchObject({ initiating_entity: 'policy' });
  });

  it('reads initiating_entity from the actor (CAEP 1.0 §2)', () => {
    expect(initiatingEntityOf({ category: 'user', actor: { type: 'user' } })).toBe('user');
    expect(initiatingEntityOf({ category: 'admin', actor: { type: 'user' } })).toBe('admin');
    expect(initiatingEntityOf({ category: 'admin', actor: { type: 'operator_cli' } })).toBe(
      'admin'
    );
    expect(initiatingEntityOf({ category: 'user', actor: { type: 'system' } })).toBe('system');
    expect(initiatingEntityOf({ category: 'user', actor: { type: 'client' } })).toBeUndefined();
    expect(initiatingEntityOf({ category: 'user' })).toBeUndefined();
  });
});
