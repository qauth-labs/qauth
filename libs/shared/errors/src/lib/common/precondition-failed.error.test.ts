import { describe, expect, it } from 'vitest';

import { PreconditionFailedError } from './precondition-failed.error';

describe('PreconditionFailedError', () => {
  it('carries the code/statusCode contract every domain error in this package has', () => {
    const err = new PreconditionFailedError();

    expect(err).toBeInstanceOf(PreconditionFailedError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('PreconditionFailedError');
    expect(err.statusCode).toBe(412);
    expect(err.code).toBe('PRECONDITION_FAILED');
  });

  it('keeps the context on details, out of the fixed message', () => {
    const err = new PreconditionFailedError({ operation: 'realms.policies.update' });

    expect(err.message).toBe('The resource has changed since the version the request names');
    expect(err.details).toEqual({ operation: 'realms.policies.update' });
  });

  it('omits details when none were supplied', () => {
    expect(new PreconditionFailedError().details).toBeUndefined();
  });
});
