import { createRequire } from 'node:module';
import { arch, platform } from 'node:os';

/**
 * Raw napi addon surface (see `src/lib.rs`). Names are camelCased by napi-rs
 * from the Rust `snake_case`.
 */
export interface NativeMlDsaAddon {
  mldsa65PublicKeyFromSeed(seed: Uint8Array): Uint8Array;
  mldsa65Sign(seed: Uint8Array, message: Uint8Array): Uint8Array;
  mldsa65Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
}

const nodeRequire = createRequire(__filename);

/**
 * Load the platform-specific native addon, or return null when it is not built
 * for this host. #244 ships the local binding + a build target; the per-platform
 * CI prebuild MATRIX is the explicitly deferred half of the issue, so a
 * deployment (or CI lane) without a prebuilt `.node` simply has no native
 * backend — callers fall back to the pure-TS `@noble/post-quantum` backend
 * (#243). This mirrors the repo's Docker-guarded integration-test pattern.
 */
function loadAddon(): NativeMlDsaAddon | null {
  const abi = platform() === 'linux' ? 'gnu' : platform() === 'win32' ? 'msvc' : '';
  const candidates = [
    `../qauth-crypto-native.${platform()}-${arch()}${abi ? `-${abi}` : ''}.node`,
    `../qauth-crypto-native.${platform()}-${arch()}.node`,
  ];
  for (const candidate of candidates) {
    try {
      return nodeRequire(candidate) as NativeMlDsaAddon;
    } catch {
      // Try the next candidate.
    }
  }
  return null;
}

const addon = loadAddon();

/** Whether the native ML-DSA-65 addon is available on this host. */
export function isNativeAddonAvailable(): boolean {
  return addon !== null;
}

/** The loaded addon, or throw a clear error if it was not built for this host. */
export function requireAddon(): NativeMlDsaAddon {
  if (addon === null) {
    throw new Error(
      'The native ML-DSA-65 addon is not built for this platform. Run `napi build` in ' +
        'libs/core/crypto-native, or use the @noble/post-quantum backend (#243).'
    );
  }
  return addon;
}
