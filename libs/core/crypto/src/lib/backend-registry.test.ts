import { describe, expect, it } from 'vitest';

import { getSignatureBackend } from './backend-registry';
import { mlDsa65Backend } from './backends/ml-dsa-65';

describe('getSignatureBackend (runtime algorithm gating)', () => {
  it('returns the ML-DSA-65 backend when the algorithm is enabled', () => {
    const backend = getSignatureBackend('ML-DSA-65', ['EdDSA', 'ML-DSA-65']);
    expect(backend).toBe(mlDsa65Backend);
    expect(backend.algorithm).toBe('ML-DSA-65');
  });

  it('throws when ML-DSA-65 is requested but not enabled (fail-fast flag)', () => {
    expect(() => getSignatureBackend('ML-DSA-65', ['EdDSA'])).toThrow(/not enabled/);
  });

  it('mentions SIGNING_ALGORITHM_MODE in the gating error so operators know the knob', () => {
    expect(() => getSignatureBackend('ML-DSA-65', ['EdDSA'])).toThrow(/SIGNING_ALGORITHM_MODE/);
  });

  it('rejects EdDSA — it has no byte-level backend (signed via the jose token layer)', () => {
    expect(() => getSignatureBackend('EdDSA', ['EdDSA', 'ML-DSA-65'])).toThrow(
      /no byte-level SignatureBackend/
    );
  });

  it('throws on an empty enabled set', () => {
    expect(() => getSignatureBackend('ML-DSA-65', [])).toThrow(/not enabled/);
  });
});
