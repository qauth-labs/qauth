import { describe, expect, it } from 'vitest';

import { InvalidDpopProofError } from './invalid-dpop-proof.error';

describe('InvalidDpopProofError (RFC 9449 §12.2, #480)', () => {
  it('is the bare invalid_dpop_proof code, 400 at the token endpoint', () => {
    const err = new InvalidDpopProofError();
    expect(err).toBeInstanceOf(InvalidDpopProofError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('InvalidDpopProofError');
    expect(err.message).toBe('invalid_dpop_proof');
    expect(err.statusCode).toBe(400);
    expect(err.code).toBe('INVALID_DPOP_PROOF');
    expect(err.errorDescription).toBeUndefined();
  });

  it('is 401 at a protected resource, and keeps a description apart from the code', () => {
    const err = new InvalidDpopProofError('a DPoP proof is required', { atResource: true });
    expect(err.statusCode).toBe(401);
    expect(err.message).toBe('invalid_dpop_proof');
    expect(err.errorDescription).toBe('a DPoP proof is required');
  });
});
