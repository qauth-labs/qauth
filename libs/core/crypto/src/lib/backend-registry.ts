import type { SignatureAlgorithm } from './algorithms';
import { mlDsa65Backend } from './backends/ml-dsa-65';
import type { SignatureBackend } from './primitives';

/**
 * Resolve the byte-level {@link SignatureBackend} for an algorithm, gated by
 * the operator-enabled set (ADR-005 runtime algorithm selection, #243).
 *
 * `enabledAlgorithms` comes from config (`SIGNING_ALGORITHM_MODE`); asking for
 * an algorithm outside it throws, so the flag is a real fail-fast control, not
 * decorative. `'EdDSA'` has no byte-level backend — it is served by the jose
 * token layer (`sign`/`verify`) — so requesting it here is a usage error.
 *
 * The switch is EXHAUSTIVE over {@link SignatureAlgorithm}: adding a future
 * algorithm to the union forces a compile error here until it is handled
 * (`assertNever` default arm).
 *
 * @throws Error if `alg` is not in `enabledAlgorithms`, or has no byte-level
 * backend.
 */
export function getSignatureBackend(
  alg: SignatureAlgorithm,
  enabledAlgorithms: readonly SignatureAlgorithm[]
): SignatureBackend {
  if (!enabledAlgorithms.includes(alg)) {
    throw new Error(
      `Signature algorithm '${alg}' is not enabled (enabled: ${enabledAlgorithms.join(', ') || 'none'}). ` +
        `Enable it via SIGNING_ALGORITHM_MODE.`
    );
  }

  switch (alg) {
    case 'ML-DSA-65':
      return mlDsa65Backend;
    case 'EdDSA':
      throw new Error(
        "'EdDSA' has no byte-level SignatureBackend — it is signed via the jose token layer (sign/verify)."
      );
    default:
      return assertNever(alg);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unhandled signature algorithm: ${String(value)}`);
}
