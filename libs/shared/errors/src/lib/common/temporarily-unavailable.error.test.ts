import { describe, expect, it } from 'vitest';

import { TemporarilyUnavailableError } from './temporarily-unavailable.error';

describe('TemporarilyUnavailableError', () => {
  it('carries the code/statusCode contract every domain error in this package has', () => {
    const err = new TemporarilyUnavailableError(1);

    expect(err).toBeInstanceOf(TemporarilyUnavailableError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('TemporarilyUnavailableError');
    expect(err.statusCode).toBe(503);
    expect(err.code).toBe('TEMPORARILY_UNAVAILABLE');
  });

  it('names the OAuth error code as its message, and keeps the retry delay', () => {
    const err = new TemporarilyUnavailableError(7);

    expect(err.message).toBe('temporarily_unavailable');
    expect(err.retryAfterSeconds).toBe(7);
  });

  it('keeps the reason on details, out of the fixed message', () => {
    const err = new TemporarilyUnavailableError(1, { reason: 'argon2_queue_full', queued: 32 });

    expect(err.details).toEqual({ reason: 'argon2_queue_full', queued: 32 });
    expect(new TemporarilyUnavailableError(1).details).toBeUndefined();
  });
});
