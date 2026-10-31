import { describe, expect, it } from 'vitest';

import {
  accessTokenIssuedAt,
  accountCredentialRefusal,
  issuedBeforeDisablement,
  NOT_VALID_BEFORE_MARGIN_MS,
} from './account-validity';

/**
 * Whether an account still accepts a credential it was issued (#748): a
 * disabled account accepts none, and an account enabled again accepts none
 * issued before it was last disabled.
 */
describe('account validity', () => {
  const DISABLED_AT = 1_793_000_000_123;

  describe('issuedBeforeDisablement', () => {
    it('accepts everything from an account that was never disabled', () => {
      expect(issuedBeforeDisablement({ notValidBefore: null }, 0)).toBe(false);
      expect(issuedBeforeDisablement({ notValidBefore: null }, undefined)).toBe(false);
    });

    it('refuses a credential issued before the disablement, or at it', () => {
      const user = { notValidBefore: DISABLED_AT };
      expect(issuedBeforeDisablement(user, DISABLED_AT - 86_400_000)).toBe(true);
      expect(issuedBeforeDisablement(user, DISABLED_AT - 1)).toBe(true);
      expect(issuedBeforeDisablement(user, DISABLED_AT)).toBe(true);
    });

    it('counts one issued within the margin after it as issued before, and no later one', () => {
      const user = { notValidBefore: DISABLED_AT };
      expect(issuedBeforeDisablement(user, DISABLED_AT + NOT_VALID_BEFORE_MARGIN_MS)).toBe(true);
      expect(issuedBeforeDisablement(user, DISABLED_AT + NOT_VALID_BEFORE_MARGIN_MS + 1)).toBe(
        false
      );
      expect(issuedBeforeDisablement(user, DISABLED_AT + 3_600_000)).toBe(false);
    });

    it('refuses a credential with no issue time once the account has been disabled', () => {
      const user = { notValidBefore: DISABLED_AT };
      expect(issuedBeforeDisablement(user, undefined)).toBe(true);
      expect(issuedBeforeDisablement(user, Number.NaN)).toBe(true);
    });

    it('covers each clock the issue times come from', () => {
      const disabledAt = 1_793_000_000_700;
      const user = { notValidBefore: disabledAt };
      // A refresh token or a code created 100 ms before the disablement: the
      // database rounds its `created_at` to the second, here up, past it.
      const createdAt = Math.round((disabledAt - 100) / 1000) * 1000;
      expect(createdAt).toBe(1_793_000_001_000);
      expect(issuedBeforeDisablement(user, createdAt)).toBe(true);
      // An access token issued 1 ms before it: `iat` is whole seconds.
      const issuedAt = accessTokenIssuedAt({ iat: Math.floor((disabledAt - 1) / 1000) });
      expect(issuedBeforeDisablement(user, issuedAt)).toBe(true);
    });
  });

  describe('accountCredentialRefusal', () => {
    it('refuses everything while the account is disabled', () => {
      expect(accountCredentialRefusal({ enabled: false, notValidBefore: null }, Date.now())).toBe(
        'user_disabled'
      );
      expect(
        accountCredentialRefusal({ enabled: false, notValidBefore: DISABLED_AT }, DISABLED_AT + 9e6)
      ).toBe('user_disabled');
    });

    it('refuses what was issued before the last disablement once the account is enabled again', () => {
      const user = { enabled: true, notValidBefore: DISABLED_AT };
      expect(accountCredentialRefusal(user, DISABLED_AT - 60_000)).toBe(
        'issued_before_disablement'
      );
      expect(accountCredentialRefusal(user, DISABLED_AT + 60_000)).toBeNull();
    });

    it('accepts everything from an enabled account that was never disabled', () => {
      expect(accountCredentialRefusal({ enabled: true, notValidBefore: null }, 0)).toBeNull();
    });
  });

  describe('accessTokenIssuedAt', () => {
    it('reads `iat` in seconds as epoch milliseconds', () => {
      expect(accessTokenIssuedAt({ iat: 1_793_000_000 })).toBe(1_793_000_000_000);
    });

    it('has no issue time for a token without a numeric `iat`', () => {
      expect(accessTokenIssuedAt({})).toBeUndefined();
      expect(accessTokenIssuedAt({ iat: Number.POSITIVE_INFINITY })).toBeUndefined();
    });
  });
});
