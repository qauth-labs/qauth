import { createRequire } from 'node:module';
import { arch, platform } from 'node:os';

import {
  type AddonIntegrityMode,
  resolveIntegrityMode,
  verifyAddonIntegrity,
} from './addon-integrity';

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

/** Why the addon is not loaded, for a diagnosable error message. */
type LoadOutcome =
  | { readonly addon: NativeMlDsaAddon; readonly reasons: readonly string[] }
  | { readonly addon: null; readonly reasons: readonly string[] };

/** Candidate module specifiers for this host, most specific first. */
function addonCandidates(): readonly string[] {
  const abi = platform() === 'linux' ? 'gnu' : platform() === 'win32' ? 'msvc' : '';
  const triple = `${platform()}-${arch()}`;
  const names = [
    `qauth-crypto-native.${triple}${abi ? `-${abi}` : ''}.node`,
    `qauth-crypto-native.${triple}.node`,
  ];
  // `napi build` writes the .node to the package root, which is one level up
  // from `src/`. The package is consumed directly as TypeScript today
  // (`main: src/index.ts`), so `../` is correct — but a future compiled or
  // bundled layout can sit at a different depth, and a MODULE_NOT_FOUND there
  // would silently degrade to the pure-TS backend instead of failing loudly.
  // Searching both depths costs one extra resolve attempt on the miss path.
  return ['..', '../..'].flatMap((dir) => names.map((name) => `${dir}/${name}`));
}

/**
 * Load the platform-specific native addon, or return null when it is not built
 * for this host or fails its integrity check.
 *
 * **Integrity is verified before `dlopen`** (#277, F4): each candidate is
 * resolved to a path, hashed, and compared against its `.node.sha256` sidecar
 * from the reproducible/attested CI build. Only a `verified` (or, under
 * `QAUTH_NATIVE_ADDON_INTEGRITY=permissive`, an `unverified`) candidate is ever
 * `require()`-ed — a checksum mismatch is refused in every mode, because a
 * tampered shared object executes with full process privileges the moment it is
 * loaded.
 *
 * A host with no prebuilt `.node` simply has no native backend: callers fall
 * back to the pure-TS `@noble/post-quantum` backend (#243), mirroring the
 * repo's Docker-guarded integration-test pattern.
 */
function loadAddon(mode: AddonIntegrityMode): LoadOutcome {
  const reasons: string[] = [];
  for (const candidate of addonCandidates()) {
    let resolved: string;
    try {
      resolved = nodeRequire.resolve(candidate);
    } catch {
      // Not built for this host under this name; try the next candidate.
      continue;
    }

    const integrity = verifyAddonIntegrity(resolved, mode);
    if (integrity.status === 'rejected') {
      // FAIL CLOSED, and stop. A rejection means a candidate was found and its
      // checksum did not match (or its manifest was malformed) — that is a
      // tampering signal about this installation, not a "wrong filename for
      // this host" miss. Trying the next candidate could load a DIFFERENT
      // addon and silently paper over the violation, so refuse the native
      // backend outright and let the caller fall back to the pure-TS one.
      reasons.push(integrity.reason);
      return { addon: null, reasons };
    }
    if (integrity.status === 'unverified') {
      reasons.push(integrity.reason);
      // Loud, once, on an unverified native load.
      console.warn(`[qauth:crypto-native] ${integrity.reason}`);
    }

    try {
      return { addon: nodeRequire(resolved) as NativeMlDsaAddon, reasons };
    } catch (cause) {
      reasons.push(`failed to load ${resolved}: ${(cause as Error).message}`);
    }
  }
  return { addon: null, reasons };
}

const outcome: LoadOutcome = loadAddon(resolveIntegrityMode());

/** Whether the native ML-DSA-65 addon is available (and integrity-verified). */
export function isNativeAddonAvailable(): boolean {
  return outcome.addon !== null;
}

/**
 * Diagnostics for why the addon was not loaded, or why it loaded unverified.
 * Empty when a verified addon loaded cleanly.
 */
export function nativeAddonLoadDiagnostics(): readonly string[] {
  return outcome.reasons;
}

/** The loaded addon, or throw a clear error if it was not loadable on this host. */
export function requireAddon(): NativeMlDsaAddon {
  if (outcome.addon === null) {
    const detail = outcome.reasons.length > 0 ? ` Reasons: ${outcome.reasons.join('; ')}` : '';
    throw new Error(
      'The native ML-DSA-65 addon is not available on this platform. Run ' +
        '`pnpm nx run crypto-native:build-native` in this repo, install a ' +
        'provenance-attested prebuild, or use the @noble/post-quantum backend ' +
        `(#243).${detail}`
    );
  }
  return outcome.addon;
}
