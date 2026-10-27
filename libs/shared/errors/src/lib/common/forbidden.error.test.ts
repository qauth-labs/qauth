import { describe, expect, it } from 'vitest';

import { ForbiddenError } from './forbidden.error';

describe('ForbiddenError', () => {
  it('is a 403 FORBIDDEN that names no scope unless given one', () => {
    const err = new ForbiddenError('No.');
    expect(err).toBeInstanceOf(ForbiddenError);
    expect(err.statusCode).toBe(403);
    expect(err.code).toBe('FORBIDDEN');
    expect(err.requiredScope).toBeUndefined();
  });

  it('keeps one scope as it is', () => {
    expect(new ForbiddenError('No.', { requiredScope: 'ssf:stream' }).requiredScope).toBe(
      'ssf:stream'
    );
  });

  // RFC 6750 §3: the `scope` attribute is a space-delimited list (#509).
  it('joins several scopes with a space, in the order given', () => {
    const required = ['qauth:admin:read', 'qauth:admin:write'];
    const err = new ForbiddenError('No.', { requiredScope: required });
    expect(err.requiredScope).toBe('qauth:admin:read qauth:admin:write');

    // A copy: the caller's list cannot change what the challenge names later.
    required.push('qauth:admin:security');
    expect(err.requiredScope).toBe('qauth:admin:read qauth:admin:write');
  });

  it('sets no scope for an empty list or an empty string', () => {
    expect(new ForbiddenError('No.', { requiredScope: [] }).requiredScope).toBeUndefined();
    expect(new ForbiddenError('No.', { requiredScope: '' }).requiredScope).toBeUndefined();
  });
});
