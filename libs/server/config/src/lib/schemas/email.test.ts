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

describe("the operator's SMTP switches (review of #937)", () => {
  it('requires STARTTLS and public hosts unless set', () => {
    const parsed = emailEnvSchema.parse(REQUIRED);
    expect(parsed.SMTP_ALLOW_PLAINTEXT).toBe(false);
    expect(parsed.SMTP_ALLOWED_HOSTS).toEqual([]);
    expect(
      emailEnvSchema.parse({ ...REQUIRED, SMTP_ALLOWED_HOSTS: '' }).SMTP_ALLOWED_HOSTS
    ).toEqual([]);
  });

  it('reads SMTP_ALLOW_PLAINTEXT as a flag, never any non-empty string as true', () => {
    expect(
      emailEnvSchema.parse({ ...REQUIRED, SMTP_ALLOW_PLAINTEXT: 'true' }).SMTP_ALLOW_PLAINTEXT
    ).toBe(true);
    expect(
      emailEnvSchema.parse({ ...REQUIRED, SMTP_ALLOW_PLAINTEXT: 'false' }).SMTP_ALLOW_PLAINTEXT
    ).toBe(false);
    expect(emailEnvSchema.safeParse({ ...REQUIRED, SMTP_ALLOW_PLAINTEXT: 'yes' }).success).toBe(
      false
    );
  });

  it('reads SMTP_ALLOWED_HOSTS as a list of host names and IP addresses, as the checks compare them', () => {
    expect(
      emailEnvSchema.parse({
        ...REQUIRED,
        SMTP_ALLOWED_HOSTS: ' LocalHost , mail.internal., 10.0.0.25,[::1]',
      }).SMTP_ALLOWED_HOSTS
    ).toEqual(['localhost', 'mail.internal', '10.0.0.25', '::1']);
    for (const bad of ['*.internal', 'mail internal', 'smtp://mail']) {
      expect(emailEnvSchema.safeParse({ ...REQUIRED, SMTP_ALLOWED_HOSTS: bad }).success, bad).toBe(
        false
      );
    }
  });
});
