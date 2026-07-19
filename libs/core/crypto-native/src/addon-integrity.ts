import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * Load-time integrity verification for the native ML-DSA-65 addon (#277, F4 of
 * the #248 security gate).
 *
 * The addon is a `dlopen`-ed shared object that runs with full process
 * privileges the instant it is loaded, so its checksum MUST be verified
 * **before** `require()` — after `dlopen` there is nothing left to enforce.
 * The reproducible CI build (`.github/workflows/crypto-native.yml`) emits a
 * `<addon>.node.sha256` sidecar next to every artifact it publishes, signed
 * over by an `actions/attest-build-provenance` SLSA attestation; the local
 * `build-native` target emits the same sidecar so developer builds behave
 * identically to published ones.
 *
 * This module is deliberately free of napi/dlopen imports so it can be unit
 * tested against real files without a built addon present.
 */

/**
 * Integrity policy for loading the native addon.
 *
 * - `enforce` (default): a matching `.sha256` sidecar is REQUIRED. A missing,
 *   malformed, or mismatching manifest refuses the load.
 * - `permissive`: a MISSING sidecar is tolerated (unverified load, for a
 *   developer working tree). A PRESENT sidecar must still match — a mismatch
 *   is never tolerated in any mode.
 */
export type AddonIntegrityMode = 'enforce' | 'permissive';

/** Outcome of verifying one candidate addon file. */
export type AddonIntegrityResult =
  /** Digest matched the sidecar manifest. Safe to `dlopen`. */
  | { readonly status: 'verified'; readonly digest: string }
  /** No manifest, and policy is `permissive`. Loaded without provenance. */
  | { readonly status: 'unverified'; readonly digest: string; readonly reason: string }
  /** Refused. MUST NOT be `dlopen`-ed. */
  | { readonly status: 'rejected'; readonly reason: string };

/** Environment variable selecting the {@link AddonIntegrityMode}. */
export const ADDON_INTEGRITY_ENV = 'QAUTH_NATIVE_ADDON_INTEGRITY';

/** Suffix of the checksum sidecar emitted next to each built `.node`. */
export const CHECKSUM_SIDECAR_SUFFIX = '.sha256';

const HEX_SHA256 = /^[0-9a-f]{64}$/;

/**
 * Resolve the integrity policy from the environment.
 *
 * Fails closed: an unrecognised value is a loud error rather than a silent
 * downgrade to `permissive`, so a typo can never disable the check.
 *
 * @param env - Environment to read (defaults to `process.env`).
 * @throws If {@link ADDON_INTEGRITY_ENV} is set to an unknown value.
 */
export function resolveIntegrityMode(env: NodeJS.ProcessEnv = process.env): AddonIntegrityMode {
  const raw = env[ADDON_INTEGRITY_ENV];
  if (raw === undefined || raw === '') {
    return 'enforce';
  }
  if (raw === 'enforce' || raw === 'permissive') {
    return raw;
  }
  throw new Error(
    `${ADDON_INTEGRITY_ENV} must be 'enforce' or 'permissive', got ${JSON.stringify(raw)}`
  );
}

/**
 * Parse a checksum sidecar.
 *
 * Accepts both a bare lowercase hex digest and the `sha256sum` output format
 * (`<hex>  <filename>`), which is what the CI build writes.
 *
 * @param contents - Raw sidecar text.
 * @returns The lowercase hex digest, or `null` if the sidecar is malformed.
 */
export function parseChecksumManifest(contents: string): string | null {
  // Skip blank lines and `#` comments: both are ordinary in checksum manifests
  // (sha256sum output concatenated with a header, for instance), and treating
  // one as a malformed manifest would reject a perfectly good addon.
  const first =
    contents
      .split('\n')
      .map((line) => line.trim())
      .find((line) => line.length > 0 && !line.startsWith('#')) ?? '';
  const digest = (first.split(/\s+/, 1)[0] ?? '').toLowerCase();
  return HEX_SHA256.test(digest) ? digest : null;
}

/** SHA-256 of a file, lowercase hex. */
function digestFile(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/** Constant-time hex-digest comparison (hygiene; both operands are public). */
function digestsMatch(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  return left.length === right.length && timingSafeEqual(left, right);
}

function isNotFound(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | null)?.code === 'ENOENT';
}

/**
 * Verify a resolved addon file against its checksum sidecar.
 *
 * Callers MUST treat anything other than `verified`/`unverified` as
 * non-loadable — never `dlopen` a `rejected` file.
 *
 * @param addonPath - Absolute path of the `.node` file to be loaded.
 * @param mode - Integrity policy in force.
 */
export function verifyAddonIntegrity(
  addonPath: string,
  mode: AddonIntegrityMode
): AddonIntegrityResult {
  const manifestPath = `${addonPath}${CHECKSUM_SIDECAR_SUFFIX}`;

  let digest: string;
  try {
    digest = digestFile(addonPath);
  } catch (cause) {
    return {
      status: 'rejected',
      reason: `cannot read addon at ${addonPath}: ${(cause as Error).message}`,
    };
  }

  let manifest: string;
  try {
    manifest = readFileSync(manifestPath, 'utf8');
  } catch (cause) {
    if (!isNotFound(cause)) {
      return {
        status: 'rejected',
        reason: `cannot read checksum manifest ${manifestPath}: ${(cause as Error).message}`,
      };
    }
    if (mode === 'permissive') {
      return {
        status: 'unverified',
        digest,
        reason:
          `no checksum manifest at ${manifestPath}; loaded under ` +
          `${ADDON_INTEGRITY_ENV}=permissive without provenance`,
      };
    }
    return {
      status: 'rejected',
      reason:
        `no checksum manifest at ${manifestPath}. Rebuild via ` +
        `\`pnpm nx run crypto-native:build-native\` (which writes one), install a ` +
        `provenance-attested artifact, or set ${ADDON_INTEGRITY_ENV}=permissive to ` +
        `accept an unverified addon.`,
    };
  }

  const expected = parseChecksumManifest(manifest);
  if (expected === null) {
    return {
      status: 'rejected',
      reason: `malformed checksum manifest ${manifestPath}: expected a hex SHA-256 digest`,
    };
  }
  // A present-but-mismatching manifest is refused in EVERY mode.
  if (!digestsMatch(digest, expected)) {
    return {
      status: 'rejected',
      reason:
        `checksum mismatch for ${addonPath}: manifest declares ${expected}, ` +
        `file hashes to ${digest}. Refusing to load a native addon that does not ` +
        `match its attested build.`,
    };
  }
  return { status: 'verified', digest };
}
