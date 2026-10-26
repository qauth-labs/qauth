import { describe, expect, it } from 'vitest';

import { isReservedAudience, RESERVED_AUDIENCE_PREFIX } from './reserved-audiences';

describe('the reserved urn:qauth:aud: namespace (#509)', () => {
  it('is the urn:qauth:aud: prefix', () => {
    expect(RESERVED_AUDIENCE_PREFIX).toBe('urn:qauth:aud:');
  });

  it.each([
    'urn:qauth:aud:admin:v1-rc.0',
    'urn:qauth:aud:other',
    'URN:QAuth:AUD:developer:v1-rc.0',
    '  urn:qauth:aud:account:v1-rc.0',
  ])('reserves %j', (value) => {
    expect(isReservedAudience(value)).toBe(true);
  });

  it.each([
    'https://api.example.com',
    'urn:qauth:audience',
    'urn:qauth:event:user.signed_in:v1-rc.0',
    'urn:example:aud:admin',
    'x-urn:qauth:aud:admin',
  ])('leaves %j to its owner', (value) => {
    expect(isReservedAudience(value)).toBe(false);
  });
});
