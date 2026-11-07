import { describe, expect, it } from 'vitest';

import {
  keepsUpstreamAttributes,
  type KeptUpstreamAttribute,
  UPSTREAM_LINK_ATTRIBUTES_MAX_BYTES,
} from './interaction-record';

/**
 * What a `choosing` upstream link keeps for a new account (#670): what fits
 * the interaction record. The AuthMethod contract allows more, so a
 * provider's answer that does not fit offers no new account instead of
 * failing the record's write.
 */
describe('keepsUpstreamAttributes (#670)', () => {
  const attribute = (attrKey: string, attrValue: string): KeptUpstreamAttribute => ({
    attrKey,
    attrValue,
    verified: false,
  });

  it('keeps the claims of an ordinary provider', () => {
    expect(
      keepsUpstreamAttributes([
        { attrKey: 'email', attrValue: 'ada@example.com', verified: true },
        attribute('name', 'Ada Lovelace'),
      ])
    ).toBe(true);
    expect(keepsUpstreamAttributes([])).toBe(true);
  });

  it.each([
    ['an empty value, which a plugin may answer', [attribute('nickname', '')]],
    [
      'more than 32 attributes',
      Array.from({ length: 33 }, (_, index) => attribute(`claim_${index}`, 'x')),
    ],
    [
      'more than the byte budget',
      Array.from({ length: 3 }, (_, index) =>
        attribute(`claim_${index}`, 'x'.repeat(UPSTREAM_LINK_ATTRIBUTES_MAX_BYTES / 2))
      ),
    ],
    [
      'an expiry before 1970',
      [{ attrKey: 'email', attrValue: 'ada@example.com', verified: true, expiresAt: -1 }],
    ],
  ])('keeps none of %s', (_label, attributes) => {
    expect(keepsUpstreamAttributes(attributes)).toBe(false);
  });
});
