import { describe, expect, it } from 'vitest';

import { UniqueConstraintError } from '../database/unique-constraint.error';
import { InvalidTokenError } from './invalid-token.error';
import { JWTExpiredError } from './jwt-expired.error';
import { JWTInvalidError } from './jwt-invalid.error';
import { MissingAccessTokenError } from './missing-access-token.error';
import { TokenAlreadyUsedError } from './token-already-used.error';
import { TokenExpiredError } from './token-expired.error';

/**
 * The codes the auth server publishes as problem codes, lower-cased (#513,
 * renamed before 1.0 on 2026-10-26): an access token is never a "JWT" on the
 * wire, a one-time token is the email verification token it is, and a
 * duplicate is `ALREADY_EXISTS` rather than the database's word for it.
 */
describe('token and duplicate error codes', () => {
  it.each([
    [new InvalidTokenError(), 400, 'INVALID_VERIFICATION_TOKEN'],
    [new TokenExpiredError(), 410, 'VERIFICATION_TOKEN_EXPIRED'],
    [new TokenAlreadyUsedError(), 409, 'VERIFICATION_TOKEN_USED'],
    [new JWTInvalidError(), 401, 'INVALID_ACCESS_TOKEN'],
    [new JWTExpiredError(), 401, 'ACCESS_TOKEN_EXPIRED'],
    [new MissingAccessTokenError(), 401, 'UNAUTHORIZED'],
    [new UniqueConstraintError('some_index'), 409, 'ALREADY_EXISTS'],
  ] as const)('%s carries %i and %s', (error, statusCode, code) => {
    expect(error.statusCode).toBe(statusCode);
    expect(error.code).toBe(code);
  });

  it('tells a request without an access token apart from a refused one (RFC 6750 §3.1)', () => {
    const missing = new MissingAccessTokenError();

    expect(missing).toBeInstanceOf(MissingAccessTokenError);
    expect(missing).toBeInstanceOf(Error);
    expect(missing).not.toBeInstanceOf(JWTInvalidError);
    expect(missing.name).toBe('MissingAccessTokenError');
    expect(missing.message).toBe('The request carries no access token');
  });
});
