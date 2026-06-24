import { describe, expect, it } from 'vitest';

import { extractConstraintName, isUniqueConstraintError } from './helpers';

/** A real pg unique-violation error as the driver exposes it. */
const pgUniqueViolation = {
  name: 'error',
  message: 'duplicate key value violates unique constraint "users_email_key"',
  severity: 'ERROR',
  code: '23505',
  constraint: 'users_email_key',
  detail: 'Key (email)=(a@b.com) already exists.',
};

describe('isUniqueConstraintError', () => {
  it('detects a top-level pg unique-violation error', () => {
    expect(isUniqueConstraintError(pgUniqueViolation)).toBe(true);
  });

  it('unwraps a drizzle-style wrapper exposing the pg error under .cause', () => {
    const wrapped = new Error('Failed query: insert into "users" ...');
    (wrapped as { cause?: unknown }).cause = pgUniqueViolation;
    expect(isUniqueConstraintError(wrapped)).toBe(true);
  });

  it('walks past a non-pg wrapper that carries its own unrelated code', () => {
    // Production wrappers (Fastify, custom handlers) attach generic codes such
    // as FST_ERR_* or INTERNAL_SERVER_ERROR. The walk must not stop here.
    const fastifyWrapper = {
      name: 'FastifyError',
      message: 'something went wrong',
      code: 'FST_ERR_VALIDATION',
      statusCode: 500,
      cause: pgUniqueViolation,
    };
    expect(isUniqueConstraintError(fastifyWrapper)).toBe(true);
    expect(extractConstraintName(fastifyWrapper)).toBe('users_email_key');
  });

  it('walks past a wrapper whose code is a different length than SQLSTATE', () => {
    const wrapper = {
      code: 'INTERNAL_SERVER_ERROR',
      cause: pgUniqueViolation,
    };
    expect(isUniqueConstraintError(wrapper)).toBe(true);
  });

  it('returns false when no pg error exists in the chain', () => {
    const wrapper = {
      code: 'FST_ERR_VALIDATION',
      cause: new Error('generic failure'),
    };
    expect(isUniqueConstraintError(wrapper)).toBe(false);
  });

  it('returns false for a non-unique pg error code', () => {
    const fkViolation = { code: '23503', constraint: 'fk_owner' };
    expect(isUniqueConstraintError(fkViolation)).toBe(false);
  });

  it('returns false for null/undefined/non-object input', () => {
    expect(isUniqueConstraintError(null)).toBe(false);
    expect(isUniqueConstraintError(undefined)).toBe(false);
    expect(isUniqueConstraintError('boom')).toBe(false);
  });

  it('does not loop forever on a cyclic cause chain', () => {
    const a: { code: string; cause?: unknown } = { code: 'WRAPPED_ERROR' };
    const b: { code: string; cause?: unknown } = { code: 'WRAPPED_ERROR' };
    a.cause = b;
    b.cause = a;
    expect(isUniqueConstraintError(a)).toBe(false);
  });

  it('identifies a pg error by constraint even without a SQLSTATE code', () => {
    // Some wrappers strip code but retain pg diagnostic fields.
    const err = { constraint: 'users_email_key', detail: 'duplicate' };
    // Not 23505, so not a *unique* error, but it is recognised as the pg link.
    expect(extractConstraintName(err)).toBe('users_email_key');
  });
});

describe('extractConstraintName', () => {
  it('returns the constraint name from a top-level pg error', () => {
    expect(extractConstraintName(pgUniqueViolation)).toBe('users_email_key');
  });

  it('returns the constraint from a pg error nested under .cause', () => {
    const wrapped = new Error('wrap');
    (wrapped as { cause?: unknown }).cause = pgUniqueViolation;
    expect(extractConstraintName(wrapped)).toBe('users_email_key');
  });

  it('returns undefined when there is no pg error in the chain', () => {
    expect(extractConstraintName(new Error('plain'))).toBeUndefined();
    expect(extractConstraintName(null)).toBeUndefined();
  });
});
