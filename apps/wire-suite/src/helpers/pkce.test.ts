import { describe, expect, it } from 'vitest';

import { createPkcePair, s256Challenge } from './pkce';

describe('PKCE pair', () => {
  it('derives the S256 challenge of the RFC 7636 Appendix B example', () => {
    expect(s256Challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
    );
  });

  it('creates a 43-character unreserved verifier, its challenge and the S256 method', () => {
    const pair = createPkcePair();

    expect(pair.verifier).toMatch(/^[A-Za-z0-9\-._~]{43}$/);
    expect(pair.challenge).toBe(s256Challenge(pair.verifier));
    expect(pair.method).toBe('S256');
  });

  it('creates a different verifier each time', () => {
    expect(createPkcePair().verifier).not.toBe(createPkcePair().verifier);
  });
});
