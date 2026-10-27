import { describe, expect, it } from 'vitest';

import { PreconditionRequiredError } from './precondition-required.error';

describe('PreconditionRequiredError', () => {
  it('carries the code/statusCode contract every domain error in this package has', () => {
    const err = new PreconditionRequiredError();

    expect(err).toBeInstanceOf(PreconditionRequiredError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('PreconditionRequiredError');
    expect(err.statusCode).toBe(428);
    expect(err.code).toBe('PRECONDITION_REQUIRED');
  });

  it('keeps the context on details, out of the fixed message', () => {
    const err = new PreconditionRequiredError({ operation: 'realms.policies.update' });

    expect(err.message).toBe(
      'The request must name the version of the resource it changes, in If-Match'
    );
    expect(err.details).toEqual({ operation: 'realms.policies.update' });
  });

  it('omits details when none were supplied', () => {
    expect(new PreconditionRequiredError().details).toBeUndefined();
  });
});
