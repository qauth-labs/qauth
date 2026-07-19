import type { SignatureAlgorithm } from './algorithms';
import { mlDsa65Backend } from './backends/ml-dsa-65';
import type { SignatureBackend } from './primitives';

/**
 * Optional per-algorithm backend overrides installed at boot (#248 F11).
 *
 * The native `aws-lc-rs` backend lives in `@qauth-labs/core-crypto-native`,
 * which DEPENDS on this library — so it cannot be imported here without a
 * cycle, and it is optional anyway (the prebuilt `.node` is not present on
 * every host). This registry is the seam that makes it selectable: the host
 * application decides at boot whether the native addon is available and, if so,
 * registers it; every consumer keeps calling {@link getSignatureBackend} and
 * transparently gets the selected implementation.
 */
const overrides = new Map<SignatureAlgorithm, SignatureBackend>();

/**
 * Install a {@link SignatureBackend} as the implementation returned by
 * {@link getSignatureBackend} for its algorithm.
 *
 * Call this ONCE at boot, before any signing or verification. Swapping a
 * backend mid-process is not supported: `MlDsaKey` objects are backend-tagged
 * (#248 F2), so keys derived under the previous backend would start failing
 * closed at `sign()`.
 *
 * Registration is NOT an authorization decision — {@link getSignatureBackend}
 * still gates on the operator's `SIGNING_ALGORITHM_MODE` allowlist, so
 * registering a backend for a disabled algorithm cannot enable it.
 *
 * @param backend - Backend to install; registered under its own `algorithm`.
 * @throws Error if `backend.algorithm` has no byte-level backend slot.
 */
export function registerSignatureBackend(backend: SignatureBackend): void {
  if (backend.algorithm === 'EdDSA') {
    throw new Error(
      "'EdDSA' has no byte-level SignatureBackend — it is signed via the jose token layer (sign/verify)."
    );
  }
  overrides.set(backend.algorithm, backend);
}

/**
 * Remove all registered overrides, restoring the built-in defaults.
 * Intended for tests that install a stub backend and must not leak it.
 */
export function resetSignatureBackends(): void {
  overrides.clear();
}

/**
 * Resolve the byte-level {@link SignatureBackend} for an algorithm, gated by
 * the operator-enabled set (ADR-005 runtime algorithm selection, #243).
 *
 * `enabledAlgorithms` comes from config (`SIGNING_ALGORITHM_MODE`); asking for
 * an algorithm outside it throws, so the flag is a real fail-fast control, not
 * decorative. Callers MUST thread the operator's configured set through
 * (`cryptoEnv.enabledSignatureAlgorithms`) rather than passing a hardcoded
 * literal — a hardcoded `['ML-DSA-65']` silently bypasses the allowlist
 * (#248 F7). `'EdDSA'` has no byte-level backend — it is served by the jose
 * token layer (`sign`/`verify`) — so requesting it here is a usage error.
 *
 * A backend installed via {@link registerSignatureBackend} wins over the
 * built-in default, which is how the optional native backend (#244) is
 * selected without this library depending on it.
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
      return overrides.get('ML-DSA-65') ?? mlDsa65Backend;
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
