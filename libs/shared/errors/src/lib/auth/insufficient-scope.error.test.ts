import { describe, expect, it } from 'vitest';

import { InsufficientScopeError } from './insufficient-scope.error';

describe('InsufficientScopeError (RFC 6750 §3.1, #509)', () => {
  it('is the bare insufficient_scope code, 403, with the scopes the request needs', () => {
    const required = ['admin:read', 'admin:write'];
    const err = new InsufficientScopeError(required, 'the token lacks admin:write');
    expect(err).toBeInstanceOf(InsufficientScopeError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('InsufficientScopeError');
    expect(err.message).toBe('insufficient_scope');
    expect(err.statusCode).toBe(403);
    expect(err.code).toBe('INSUFFICIENT_SCOPE');
    expect(err.errorDescription).toBe('the token lacks admin:write');
    expect(err.requiredScopes).toEqual(['admin:read', 'admin:write']);

    // A copy: the caller's list cannot change what the challenge names later.
    required.push('admin:security');
    expect(err.requiredScopes).toEqual(['admin:read', 'admin:write']);
  });

  it('has no description unless one is given', () => {
    expect(new InsufficientScopeError(['x']).errorDescription).toBeUndefined();
  });
});
