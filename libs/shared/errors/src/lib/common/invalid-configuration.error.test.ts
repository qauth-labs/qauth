import { describe, expect, it } from 'vitest';

import { InvalidConfigurationError } from './invalid-configuration.error';

describe('InvalidConfigurationError', () => {
  it('carries the code/statusCode contract every domain error in this package has', () => {
    const err = new InvalidConfigurationError('Setting X is unusable');

    expect(err).toBeInstanceOf(InvalidConfigurationError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('InvalidConfigurationError');
    expect(err.message).toBe('Setting X is unusable');
    expect(err.statusCode).toBe(500);
    expect(err.code).toBe('INVALID_CONFIGURATION');
  });

  it('keeps operator-supplied values on details, out of the message', () => {
    // The whole reason this class exists: a configuration fault is a 500, so
    // `message` can reach an HTTP body through the error handler's statusCode
    // branch and reaches logs unconditionally. Values go on `details`, which no
    // response path serializes.
    const err = new InvalidConfigurationError('Setting X is unusable', {
      setting: 'X',
      value: 'https://internal.example?token=abc',
    });

    expect(err.message).not.toContain('internal.example');
    expect(err.details).toEqual({ setting: 'X', value: 'https://internal.example?token=abc' });
  });

  it('omits details when none were supplied', () => {
    expect(new InvalidConfigurationError('nope').details).toBeUndefined();
  });
});
