import { PASSWORD_MAX_LENGTH } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

import {
  loginSchema,
  logoutHeadersSchema,
  registerSchema,
  resendVerificationSchema,
  verifyBodySchema,
} from './auth';

/**
 * `POST /auth/logout` checks its header twice: this schema first (400), then
 * the handler's own read of the token (401). The schema's `^Bearer .+$` lets
 * through a header that holds more than one token, so the handler's 401 is
 * reachable over HTTP (graphs/flows/core/logout, `invalid_token.missing_token`).
 */
describe('logoutHeadersSchema', () => {
  it('lets through a Bearer header that holds more than one token, for the handler to refuse', () => {
    expect(logoutHeadersSchema.safeParse({ authorization: 'Bearer a b' }).success).toBe(true);
  });

  it.each([
    ['no header', {}],
    ['another scheme', { authorization: 'Basic YTpi' }],
    ['a lower-case scheme', { authorization: 'bearer abc' }],
    ['an empty Bearer token', { authorization: 'Bearer ' }],
  ])('refuses %s', (_name, headers) => {
    expect(logoutHeadersSchema.safeParse(headers).success).toBe(false);
  });
});

/**
 * An email address is at most 254 characters (RFC 5321 §4.5.3.1.3: a path is
 * at most 256 octets, angle brackets included). It was unbounded on every
 * route that takes one: a refused sign-in wrote the whole address to
 * `audit_logs`, and resend-verification used it as a Redis key.
 */
describe.each([
  ['registerSchema', registerSchema, { password: 'correct horse battery staple' }],
  ['loginSchema', loginSchema, { password: 'correct horse battery staple' }],
  ['resendVerificationSchema', resendVerificationSchema, {}],
])('%s email bound', (_name, schema, rest) => {
  const atBound = `${'a'.repeat(254 - '@example.com'.length)}@example.com`;

  it('accepts a 254-character address', () => {
    expect(schema.safeParse({ ...rest, email: atBound }).success).toBe(true);
  });

  it('refuses a longer one with a single too_big issue, before the format check', () => {
    const result = schema.safeParse({ ...rest, email: `a${atBound}` });
    expect(result.success).toBe(false);
    expect(result.error?.issues.map(({ path, code }) => ({ path, code }))).toEqual([
      { path: ['email'], code: 'too_big' },
    ]);
  });

  it('still refuses a malformed address', () => {
    expect(schema.safeParse({ ...rest, email: 'not-an-address' }).success).toBe(false);
  });
});

/**
 * The register and login bodies bound `password` before a handler runs, so
 * zxcvbn scoring and Argon2id hashing never see attacker-sized input.
 */
describe.each([
  ['registerSchema', registerSchema],
  ['loginSchema', loginSchema],
])('%s password bound', (_name, schema) => {
  const email = 'dev@example.com';

  it('accepts a password of exactly PASSWORD_MAX_LENGTH characters', () => {
    expect(schema.safeParse({ email, password: 'a'.repeat(PASSWORD_MAX_LENGTH) }).success).toBe(
      true
    );
  });

  it('rejects a password one character over the bound', () => {
    expect(schema.safeParse({ email, password: 'a'.repeat(PASSWORD_MAX_LENGTH + 1) }).success).toBe(
      false
    );
  });

  it('rejects a very large password', () => {
    expect(schema.safeParse({ email, password: 'a'.repeat(100_000) }).success).toBe(false);
  });
});

/**
 * All three bodies count the bound in UTF-16 code units, the unit
 * `PASSWORD_MAX_LENGTH` is defined in. Zod 4.5+ `.max()` counts code points, so
 * a bare `z.string().max()` let 129 emoji (258 code units) through to the
 * handler: a 422 from the strength check on register instead of this 400, and
 * an Argon2id verify on login and verify.
 */
describe.each([
  ['registerSchema', registerSchema],
  ['loginSchema', loginSchema],
  ['verifyBodySchema', verifyBodySchema],
])('%s password bound in UTF-16 code units', (_name, schema) => {
  const body = { email: 'dev@example.com', token: 'a'.repeat(64) };
  /** U+1F600: one code point, two UTF-16 code units. */
  const astral = (count: number) => '\u{1F600}'.repeat(count);

  it('accepts astral characters filling exactly PASSWORD_MAX_LENGTH code units', () => {
    expect(schema.safeParse({ ...body, password: astral(PASSWORD_MAX_LENGTH / 2) }).success).toBe(
      true
    );
  });

  it('rejects astral characters past PASSWORD_MAX_LENGTH code units, with the bound in the message', () => {
    const result = schema.safeParse({ ...body, password: astral(PASSWORD_MAX_LENGTH / 2 + 1) });

    expect(result.success).toBe(false);
    expect(result.error?.issues.map(({ path, message }) => ({ path, message }))).toEqual([
      {
        path: ['password'],
        message: `Too big: expected string to have <=${PASSWORD_MAX_LENGTH} characters`,
      },
    ]);
  });
});
