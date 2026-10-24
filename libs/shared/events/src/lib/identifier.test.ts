import { describe, expect, it } from 'vitest';

import {
  compareEventVersions,
  EVENT_TYPE_PATTERN,
  eventTypeId,
  eventVersionLabel,
  parseEventType,
} from './identifier';

describe('event type identifiers', () => {
  it('builds urn:qauth:event:<name>:v<N>', () => {
    expect(eventTypeId('user.signed_in', 1)).toBe('urn:qauth:event:user.signed_in:v1');
    expect(eventTypeId('client.secret_rotated', 12)).toBe(
      'urn:qauth:event:client.secret_rotated:v12'
    );
  });

  it('builds urn:qauth:event:<name>:v<N>-rc.<M> for a release candidate', () => {
    expect(eventTypeId('user.signed_in', 1, 0)).toBe('urn:qauth:event:user.signed_in:v1-rc.0');
    expect(eventTypeId('user.signed_in', 2, 11)).toBe('urn:qauth:event:user.signed_in:v2-rc.11');
  });

  it('parses a candidate number back, and leaves it out for a released version', () => {
    expect(parseEventType('urn:qauth:event:user.signed_in:v1-rc.0')).toEqual({
      name: 'user.signed_in',
      version: 1,
      rc: 0,
    });
    expect(parseEventType('urn:qauth:event:user.signed_in:v1')).not.toHaveProperty('rc');
  });

  it('labels a version as the identifier ends', () => {
    expect(eventVersionLabel({ version: 1 })).toBe('v1');
    expect(eventVersionLabel({ version: 1, rc: 2 })).toBe('v1-rc.2');
  });

  it('orders candidates before the release, and majors by number', () => {
    const versions = [
      { version: 2 },
      { version: 1 },
      { version: 1, rc: 10 },
      { version: 2, rc: 0 },
      { version: 1, rc: 2 },
    ];
    expect([...versions].sort(compareEventVersions).map(eventVersionLabel)).toEqual([
      'v1-rc.2',
      'v1-rc.10',
      'v1',
      'v2-rc.0',
      'v2',
    ]);
    expect(compareEventVersions({ version: 1, rc: 0 }, { version: 1, rc: 0 })).toBe(0);
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
    'urn:qauth:ia:password:v1-rc.0',
    'urn:qauth:event:user.signed_in:v1-rc',
    'urn:qauth:event:user.signed_in:v1-rc.',
    'urn:qauth:event:user.signed_in:v1-rc.01',
    'urn:qauth:event:user.signed_in:v1-rc.-1',
    'urn:qauth:event:user.signed_in:v1-beta.0',
    'urn:qauth:event:user.signed_in:v1-rc0',
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

  it.each([-1, 0.5, Number.NaN])('refuses to build with candidate number %j', (rc) => {
    expect(() => eventTypeId('user.signed_in', 1, rc)).toThrow(/release-candidate number/);
  });
});
