import { describe, expect, it } from 'vitest';

import { EVENT_TYPE_PATTERN, eventTypeId, parseEventType } from './identifier';

describe('event type identifiers', () => {
  it('builds urn:qauth:event:<name>:v<N>', () => {
    expect(eventTypeId('user.signed_in', 1)).toBe('urn:qauth:event:user.signed_in:v1');
    expect(eventTypeId('client.secret_rotated', 12)).toBe(
      'urn:qauth:event:client.secret_rotated:v12'
    );
  });

  it('parses the short name and the version back', () => {
    expect(parseEventType('urn:qauth:event:user.signed_in:v1')).toEqual({
      name: 'user.signed_in',
      version: 1,
    });
    expect(parseEventType('urn:qauth:event:api_key.revoked:v2')).toEqual({
      name: 'api_key.revoked',
      version: 2,
    });
  });

  it.each([
    'user.signed_in',
    'urn:qauth:event:user.signed_in',
    'urn:qauth:event:user.signed_in:1',
    'urn:qauth:event:user.signed_in:v0',
    'urn:qauth:event:user.signed_in:v01',
    'urn:qauth:event:user:v1',
    'urn:qauth:event:User.SignedIn:v1',
    'urn:qauth:event:user..signed_in:v1',
    'urn:qauth:event:user.signed-in:v1',
    'urn:qauth:ia:password:v1',
  ])('refuses %s', (type) => {
    expect(parseEventType(type)).toBeNull();
    expect(EVENT_TYPE_PATTERN.test(type)).toBe(false);
  });

  it.each([
    ['user', 1],
    ['User.signed_in', 1],
    ['user.signed in', 1],
    ['user.signed_in', 0],
    ['user.signed_in', 1.5],
  ])('refuses to build from %j and %j', (name, version) => {
    expect(() => eventTypeId(name as string, version as number)).toThrow();
  });
});
