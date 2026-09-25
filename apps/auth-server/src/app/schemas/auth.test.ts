import { PASSWORD_MAX_LENGTH } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

import { loginSchema, registerSchema } from './auth';

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
