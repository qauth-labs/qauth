import { afterEach, describe, expect, it } from 'vitest';

import {
  getSignatureBackend,
  registerSignatureBackend,
  resetSignatureBackends,
} from './backend-registry';
import { mlDsa65Backend } from './backends/ml-dsa-65';
import type { SignatureBackend } from './primitives';

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

describe('registerSignatureBackend (native-backend seam — #248 F11)', () => {
  // The native backend lives in a library that DEPENDS on this one, so it
  // cannot be imported here. A stub standing in for it proves the seam.
  const stub = {
    algorithm: 'ML-DSA-65',
    generateKeyPair: () => {
      throw new Error('stub');
    },
    sign: () => {
      throw new Error('stub');
    },
    verify: () => {
      throw new Error('stub');
    },
    exportKey: () => {
      throw new Error('stub');
    },
    importKey: () => {
      throw new Error('stub');
    },
  } as unknown as SignatureBackend;

  afterEach(() => {
    resetSignatureBackends();
  });

  it('returns the built-in noble backend when nothing is registered', () => {
    expect(getSignatureBackend('ML-DSA-65', ['ML-DSA-65'])).toBe(mlDsa65Backend);
  });

  it('makes a registered backend selectable in place of the default', () => {
    registerSignatureBackend(stub);
    expect(getSignatureBackend('ML-DSA-65', ['ML-DSA-65'])).toBe(stub);
  });

  it('resetSignatureBackends() restores the built-in default', () => {
    registerSignatureBackend(stub);
    resetSignatureBackends();
    expect(getSignatureBackend('ML-DSA-65', ['ML-DSA-65'])).toBe(mlDsa65Backend);
  });

  it('registration does NOT bypass the operator allowlist (it is not an authz decision)', () => {
    registerSignatureBackend(stub);
    // SIGNING_ALGORITHM_MODE=ed25519: registering a backend must not smuggle
    // ML-DSA-65 into a deployment that has not enabled it.
    expect(() => getSignatureBackend('ML-DSA-65', ['EdDSA'])).toThrow(/not enabled/);
  });

  it('refuses to register a backend for EdDSA (no byte-level slot exists)', () => {
    expect(() =>
      registerSignatureBackend({ ...stub, algorithm: 'EdDSA' } as unknown as SignatureBackend)
    ).toThrow(/no byte-level SignatureBackend/);
  });
});
