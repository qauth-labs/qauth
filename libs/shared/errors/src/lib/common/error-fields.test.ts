import { describe, expect, it } from 'vitest';

import { TokenAlreadyUsedError } from '../auth/token-already-used.error';
import { BadRequestError } from './bad-request.error';
import { NotFoundError } from './not-found.error';
import { TooManyRequestsError } from './too-many-requests.error';

/**
 * Contract tests for the four error classes that previously shipped without a
 * `code` field (F-14). Every domain error in this package is expected to carry
 * a stable `statusCode` + UPPER_SNAKE_CASE `code` so consumers (and the global
 * error handler) can branch on `error.code` without a defensive `'code' in`
 * guard. These tests lock that contract in.
 */
describe('error code/statusCode contract (F-14)', () => {
  it('BadRequestError', () => {
    const err = new BadRequestError('bad input');
    expect(err).toBeInstanceOf(BadRequestError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('BadRequestError');
    expect(err.message).toBe('bad input');
    expect(err.statusCode).toBe(400);
    expect(err.code).toBe('BAD_REQUEST');
  });

  it('NotFoundError', () => {
    const err = new NotFoundError('User', 'abc-123');
    expect(err).toBeInstanceOf(NotFoundError);
    expect(err.name).toBe('NotFoundError');
    expect(err.message).toBe('User with id abc-123 not found');
    expect(err.statusCode).toBe(404);
    expect(err.code).toBe('NOT_FOUND');
  });

  it('TooManyRequestsError', () => {
    const err = new TooManyRequestsError();
    expect(err).toBeInstanceOf(TooManyRequestsError);
    expect(err.name).toBe('TooManyRequestsError');
    expect(err.message).toBe('Too many requests');
    expect(err.statusCode).toBe(429);
    expect(err.code).toBe('TOO_MANY_REQUESTS');
  });

  it('TokenAlreadyUsedError', () => {
    const err = new TokenAlreadyUsedError();
    expect(err).toBeInstanceOf(TokenAlreadyUsedError);
    expect(err.name).toBe('TokenAlreadyUsedError');
    expect(err.message).toBe('Token has already been used');
    expect(err.statusCode).toBe(409);
    expect(err.code).toBe('TOKEN_ALREADY_USED');
  });

  it('codes are unique across these classes', () => {
    const codes = [
      new BadRequestError('x').code,
      new NotFoundError('E', 'id').code,
      new TooManyRequestsError().code,
      new TokenAlreadyUsedError().code,
    ];
    expect(new Set(codes).size).toBe(codes.length);
  });
});
