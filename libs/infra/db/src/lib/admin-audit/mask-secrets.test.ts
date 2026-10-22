import { describe, expect, it } from 'vitest';

import { ADMIN_AUDIT_SECRET_MARKER, maskSecrets } from './mask-secrets';
import type { AdminAuditDiff } from './types';

/**
 * Secret masking for admin audit diffs (issue #448, ADR-020 §3). A field
 * annotated as secret is replaced by the marker on both sides of the diff,
 * whatever it holds, and its value appears nowhere in the result.
 */
describe('maskSecrets', () => {
  const SECRET_BEFORE = 'argon2id$old-secret-hash';
  const SECRET_AFTER = 'argon2id$new-secret-hash';

  it('replaces a secret field by the marker on both sides, never by a value', () => {
    const diff: AdminAuditDiff = {
      before: { name: 'portal', clientSecretHash: SECRET_BEFORE },
      after: { name: 'portal', clientSecretHash: SECRET_AFTER },
    };

    const masked = maskSecrets(diff, { clientSecretHash: 'secret' });

    expect(masked).toEqual({
      before: { name: 'portal', clientSecretHash: ADMIN_AUDIT_SECRET_MARKER },
      after: { name: 'portal', clientSecretHash: ADMIN_AUDIT_SECRET_MARKER },
    });
    const stored = JSON.stringify(masked);
    expect(stored).not.toContain(SECRET_BEFORE);
    expect(stored).not.toContain(SECRET_AFTER);
  });

  it('masks a whole secret subtree, and a secret that is null', () => {
    const masked = maskSecrets(
      {
        before: { smtp: { host: 'mail.example.test', password: null }, signingKey: { d: 'x' } },
        after: { smtp: { host: 'mail.example.test', password: 'p4ss' }, signingKey: { d: 'y' } },
      },
      { 'smtp.password': 'secret', signingKey: 'secret' }
    );

    expect(masked).toEqual({
      before: {
        smtp: { host: 'mail.example.test', password: ADMIN_AUDIT_SECRET_MARKER },
        signingKey: ADMIN_AUDIT_SECRET_MARKER,
      },
      after: {
        smtp: { host: 'mail.example.test', password: ADMIN_AUDIT_SECRET_MARKER },
        signingKey: ADMIN_AUDIT_SECRET_MARKER,
      },
    });
  });

  it('matches any array element or member with *', () => {
    const masked = maskSecrets(
      {
        before: null,
        after: {
          webhooks: [
            { url: 'https://a.example.test/hook', secret: 'whsec-a' },
            { url: 'https://b.example.test/hook', secret: 'whsec-b' },
          ],
          headers: { authorization: 'Bearer abc', 'x-api-key': 'k' },
        },
      },
      { 'webhooks.*.secret': 'secret', 'headers.*': 'secret' }
    );

    expect(masked).toEqual({
      before: null,
      after: {
        webhooks: [
          { url: 'https://a.example.test/hook', secret: ADMIN_AUDIT_SECRET_MARKER },
          { url: 'https://b.example.test/hook', secret: ADMIN_AUDIT_SECRET_MARKER },
        ],
        headers: {
          authorization: ADMIN_AUDIT_SECRET_MARKER,
          'x-api-key': ADMIN_AUDIT_SECRET_MARKER,
        },
      },
    });
  });

  it('masks a set-up link annotated as secret in a creation diff', () => {
    const link = 'https://auth.example.test/ui/setup?code=one-time-code';
    const masked = maskSecrets(
      { before: null, after: { userId: 'u-1', setupLink: link } },
      { setupLink: 'secret' }
    );

    expect(JSON.stringify(masked)).not.toContain('one-time-code');
    expect(masked.after).toEqual({ userId: 'u-1', setupLink: ADMIN_AUDIT_SECRET_MARKER });
  });

  it('copies fields that are not annotated, and leaves the input unchanged', () => {
    const diff: AdminAuditDiff = {
      before: { redirectUris: ['https://app.example.test/cb'], secret: 's1' },
      after: { redirectUris: ['https://app.example.test/cb2'], secret: 's2' },
    };
    const copy = structuredClone(diff);

    const masked = maskSecrets(diff, { secret: 'secret', 'missing.path': 'secret' });

    expect(diff).toEqual(copy);
    expect(masked.before?.['redirectUris']).toEqual(['https://app.example.test/cb']);
    expect(masked.after?.['redirectUris']).toEqual(['https://app.example.test/cb2']);
  });

  it('keeps a member named __proto__ as a member', () => {
    const before = JSON.parse('{"__proto__":{"token":"t"},"a":1}');
    const masked = maskSecrets({ before, after: null }, { '__proto__.token': 'secret' });

    expect(Object.getPrototypeOf(masked.before)).toBe(Object.prototype);
    expect(JSON.stringify(masked.before)).toBe('{"__proto__":{"token":"***"},"a":1}');
  });

  it('refuses an annotation path with an empty segment', () => {
    expect(() => maskSecrets({ before: null, after: {} }, { 'a..b': 'secret' })).toThrow(TypeError);
  });
});
