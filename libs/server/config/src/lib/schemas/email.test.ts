import { describe, expect, it } from 'vitest';

import { emailEnvSchema } from './email';

/** The keys the mail schema requires, so each test varies only EMAIL_BASE_URL. */
const REQUIRED = { EMAIL_FROM_ADDRESS: 'noreply@example.com' };

describe('EMAIL_BASE_URL (#490)', () => {
  it('is optional: mail links start at the realm issuer, so nothing reads it', () => {
    const parsed = emailEnvSchema.parse(REQUIRED);
    expect(parsed.EMAIL_BASE_URL).toBeUndefined();
  });

  it('reads blank as unset, as `${EMAIL_BASE_URL:-}` in docker-compose.yml expands to', () => {
    expect(emailEnvSchema.parse({ ...REQUIRED, EMAIL_BASE_URL: '' }).EMAIL_BASE_URL).toBe(
      undefined
    );
    expect(emailEnvSchema.parse({ ...REQUIRED, EMAIL_BASE_URL: '  ' }).EMAIL_BASE_URL).toBe(
      undefined
    );
  });

  it('still accepts a URL, so a deployment that sets it keeps starting', () => {
    expect(
      emailEnvSchema.parse({ ...REQUIRED, EMAIL_BASE_URL: 'https://auth.example.com' })
        .EMAIL_BASE_URL
    ).toBe('https://auth.example.com');
  });

  it('refuses a value that is not a URL', () => {
    expect(emailEnvSchema.safeParse({ ...REQUIRED, EMAIL_BASE_URL: 'not a url' }).success).toBe(
      false
    );
  });
});

describe('the keys that seed realm mail policies (#514)', () => {
  it('read blank as unset, as a new realm seeded from them does', () => {
    for (const blank of ['', '  ']) {
      const parsed = emailEnvSchema.parse({
        ...REQUIRED,
        EMAIL_FROM_NAME: blank,
        SMTP_HOST: blank,
        SMTP_USER: blank,
      });
      expect(parsed.EMAIL_FROM_NAME).toBe('QAuth');
      expect(parsed.SMTP_HOST).toBeUndefined();
      expect(parsed.SMTP_USER).toBeUndefined();
    }
  });

  it('still read a set value', () => {
    const parsed = emailEnvSchema.parse({
      ...REQUIRED,
      EMAIL_FROM_NAME: 'Acme',
      SMTP_HOST: 'smtp.example.com',
      SMTP_USER: 'mailer',
    });
    expect(parsed).toMatchObject({
      EMAIL_FROM_NAME: 'Acme',
      SMTP_HOST: 'smtp.example.com',
      SMTP_USER: 'mailer',
    });
  });
});
