import type { CryptoKey } from 'jose';

/**
 * A single classical (Ed25519) asymmetric signing/verification key.
 *
 * Aliases the runtime-agnostic {@link CryptoKey} used by the jose token layer.
 * UNCHANGED since #242: ML-DSA keys are NOT WebCrypto keys and use the separate
 * {@link MlDsaKey} type — the two never share a variable, which keeps every
 * existing jose call site (and its `SigningKey` imports) compiling unchanged.
 */
export type SigningKey = CryptoKey;

/** A generated or imported classical (Ed25519) asymmetric key pair. */
export interface SigningKeyPair {
  /** Private key used to produce signatures. */
  privateKey: SigningKey;
  /** Public key used to verify signatures. */
  publicKey: SigningKey;
}

/** FIPS 204 ML-DSA-65 byte lengths (from `@noble/post-quantum`). */
export const ML_DSA_65_LENGTHS = {
  /** Seed (ξ) — the canonical private-key form; keys expand deterministically from it. */
  seed: 32,
  publicKey: 1952,
  /** Expanded secret key (derived from the seed; used for signing). */
  secretKey: 4032,
  signature: 3309,
} as const;

/**
 * Which {@link import('./primitives').SignatureBackend} produced a private
 * {@link MlDsaKey} (#248 F2).
 *
 * The two shipped ML-DSA-65 backends store DIFFERENT bytes in
 * {@link MlDsaKey.material}: the pure-TS `@noble/post-quantum` backend stores
 * the expanded 4032-byte secret key and signs from it, while the native
 * `aws-lc-rs` backend stores (and signs from) the 32-byte seed. The two are
 * interoperable at the SEED/WIRE level, but a key OBJECT is not portable between
 * them — handing a native key to the noble `sign()` would feed a 32-byte seed
 * where a 4032-byte secret key is expected. This tag makes that mismatch a loud,
 * fail-closed error instead of undefined byte-level behaviour.
 *
 * Only PRIVATE keys carry a backend tag. Public keys hold the raw 1952-byte
 * FIPS 204 public key in both backends, so they are genuinely portable and are
 * deliberately left untagged.
 */
export type MlDsaBackendId = 'noble' | 'native';

/**
 * A raw ML-DSA-65 key (FIPS 204). ML-DSA keys are opaque byte strings, not
 * WebCrypto {@link CryptoKey}s, so they get their own type rather than widening
 * {@link SigningKey} (which would ripple into every jose call site).
 *
 * The class wraps the key material behind accessor methods and redacts it from
 * `JSON.stringify` / `util.inspect`, so a stray log line can never dump the
 * 32-byte seed or the 4032-byte secret key. The `alg` literal is the dispatch
 * discriminant (structural algorithm-confusion defence: a key can only be used
 * with its own algorithm), and {@link backend} is the same defence across the
 * noble/native backend seam (#248 F2).
 */
export class MlDsaKey {
  /** Algorithm discriminant — always `'ML-DSA-65'`. */
  readonly alg = 'ML-DSA-65' as const;
  readonly kind: 'public' | 'private';
  /** Whether the private key material may be exported (advisory — see docs). */
  readonly extractable: boolean;
  /**
   * Backend that produced this key's private material — see
   * {@link MlDsaBackendId}. Always set by a backend for a private key; `undefined`
   * on public keys (portable) and on directly-constructed private keys, which
   * {@link assertMlDsaSigningKey} then refuses to sign with.
   */
  readonly backend?: MlDsaBackendId;

  #material: Uint8Array;
  /** Seed (ξ) — present only on private keys; the canonical export form. */
  #seed?: Uint8Array;
  #destroyed = false;

  /** @internal — construct via the backend's generate/import functions. */
  constructor(params: {
    kind: 'public' | 'private';
    /** Public key bytes (public keys) or the expanded 4032-byte secret key (private keys). */
    material: Uint8Array;
    /** 32-byte seed — required for private keys, omitted for public keys. */
    seed?: Uint8Array;
    extractable?: boolean;
    /** Producing backend — REQUIRED for private keys (#248 F2), omit for public. */
    backend?: MlDsaBackendId;
  }) {
    this.kind = params.kind;
    this.#material = params.material;
    this.#seed = params.seed;
    this.extractable = params.extractable ?? false;
    this.backend = params.backend;
  }

  #assertLive(): void {
    if (this.#destroyed) {
      throw new Error('MlDsaKey has been destroyed and can no longer be used');
    }
  }

  /** Public-key bytes (public keys) / expanded secret-key bytes (private keys). */
  material(): Uint8Array {
    this.#assertLive();
    return this.#material;
  }

  /** The 32-byte seed for a private key (its canonical serialized form). */
  seed(): Uint8Array {
    this.#assertLive();
    if (this.kind !== 'private' || this.#seed === undefined) {
      throw new Error('Seed is available only on a private MlDsaKey');
    }
    return this.#seed;
  }

  /**
   * Best-effort zeroization: overwrite the key material and mark the key
   * unusable. JS cannot guarantee no GC-copied bytes remain, so this reduces
   * but does not eliminate residual exposure.
   */
  destroy(): void {
    this.#material.fill(0);
    this.#seed?.fill(0);
    this.#destroyed = true;
  }

  /** Redact key material from JSON serialization. */
  toJSON(): Record<string, unknown> {
    return {
      type: 'MlDsaKey',
      alg: this.alg,
      kind: this.kind,
      ...(this.backend !== undefined ? { backend: this.backend } : {}),
      material: '[redacted]',
    };
  }

  /** Redact key material from `util.inspect` / console logging. */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `MlDsaKey<${this.alg} ${this.kind} [redacted]>`;
  }
}

/**
 * Gate a private {@link MlDsaKey} into a backend's `sign()` (#248 F2).
 *
 * Enforces three properties before ANY key bytes are read, so a mismatch can
 * never reach the underlying primitive:
 * 1. the algorithm discriminant is `ML-DSA-65`,
 * 2. the key is a private key,
 * 3. the key was produced by THIS backend.
 *
 * Property 3 closes the backend-portability footgun: `material()` means the
 * expanded secret key under the noble backend and the seed under the native
 * one, so a cross-backend key object would otherwise be interpreted as the
 * wrong byte string. An UNTAGGED private key (constructed directly rather than
 * via a backend) is also refused — fail-closed beats guessing a provenance.
 *
 * @param privateKey - Key offered for signing.
 * @param backend - The calling backend's {@link MlDsaBackendId}.
 * @throws Error if the key is not a private ML-DSA-65 key from `backend`.
 */
export function assertMlDsaSigningKey(privateKey: MlDsaKey, backend: MlDsaBackendId): void {
  if (privateKey.alg !== 'ML-DSA-65' || privateKey.kind !== 'private') {
    throw new Error('ML-DSA-65 sign requires a private ML-DSA-65 key');
  }
  if (privateKey.backend !== backend) {
    throw new Error(
      `ML-DSA-65 sign requires a key produced by the '${backend}' backend, got ` +
        `'${privateKey.backend ?? 'untagged'}'. MlDsaKey objects are not portable across ` +
        `backends (material() is the expanded secret key under 'noble' and the seed under ` +
        `'native'); re-import the key via this backend's importKey() instead.`
    );
  }
}

/** Type guard for {@link MlDsaKey}. */
export function isMlDsaKey(value: unknown): value is MlDsaKey {
  return value instanceof MlDsaKey;
}

/** A generated or imported raw ML-DSA-65 key pair. */
export interface RawSigningKeyPair {
  privateKey: MlDsaKey;
  publicKey: MlDsaKey;
}
