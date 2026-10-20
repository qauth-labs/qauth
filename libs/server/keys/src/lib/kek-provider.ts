import type { KeyAad } from './aad';

/**
 * Where the key-encryption key (KEK) lives (ADR-019 Decision 9).
 *
 * A provider wraps and unwraps data keys only. It never sees key material and
 * never signs: signing stays local in the signer, because KMS support for
 * EdDSA and ML-DSA varies. The default provider holds the KEK in memory
 * (`KEK_PROVIDER=local`). Optional packages add adapters for a cloud KMS, a
 * secrets vault or an HSM, and each one runs `runKekProviderContract()`.
 *
 * Errors: a provider reports a failure as a `KeyCustodyError` (`./errors`):
 * `KeyDecryptionError` when the wrapped bytes do not authenticate under the
 * associated data, `UnknownKekRefError` for a `kekRef` it holds no KEK for,
 * `KekUnavailableError` and `KekAccessDeniedError` for its backend. It never
 * falls back to another KEK.
 */
export interface KekProvider {
  /** The `KEK_PROVIDER` value that selects this provider, such as `local`. */
  readonly name: string;

  /**
   * Wrap a data key under the current KEK, bound to `aad`.
   *
   * The caller zeroes `dek` once the promise settles, so the provider must not
   * keep a reference to it.
   *
   * @returns the wrapped bytes and the reference of the KEK that wrapped them
   */
  wrap(dek: Uint8Array, aad: KeyAad): Promise<WrappedDataKey>;

  /**
   * Unwrap a data key that {@link wrap} returned, under the KEK `kekRef` names.
   *
   * @throws KeyDecryptionError when `wrapped` does not authenticate under `aad`
   * @throws UnknownKekRefError when the provider holds no KEK named `kekRef`
   */
  unwrap(wrapped: Uint8Array, aad: KeyAad, kekRef: string): Promise<Uint8Array>;

  /**
   * Whether the provider can wrap right now. Resolves in every case, with
   * `ok: false` and a reason when the backend cannot be used.
   */
  health(): Promise<KekProviderHealth>;
}

/** What {@link KekProvider.wrap} returns. Both values are stored with the key. */
export interface WrappedDataKey {
  /** The wrapped data key: the `wrapped_dek` column. */
  readonly wrapped: Uint8Array;
  /**
   * Names the KEK that wrapped the data key: the `kek_ref` column. Short and
   * safe to log. A KEK rotation re-wraps every row whose `kek_ref` is the old
   * one.
   */
  readonly kekRef: string;
}

/** What {@link KekProvider.health} reports. */
export interface KekProviderHealth {
  readonly ok: boolean;
  /** The provider's {@link KekProvider.name}. */
  readonly provider: string;
  /** The reference {@link KekProvider.wrap} currently returns, when known. */
  readonly kekRef?: string;
  /** Why the provider cannot be used, when `ok` is false. Never a secret. */
  readonly reason?: string;
}

/**
 * One configuration warning for the boot log, such as a KEK file that others
 * can read. The same shape as the configuration registry's `ConfigWarning`.
 */
export interface KekWarning {
  /** The variable the warning is about. */
  readonly variable: string;
  /** What the operator should know or do, in one line. Never a secret. */
  readonly message: string;
}

/** The environment a provider reads its settings from, such as `process.env`. */
export type KekEnv = Readonly<Record<string, string | undefined>>;

/** What a provider factory receives. */
export interface KekProviderContext {
  readonly env: KekEnv;
  /** Receives each configuration warning once, while the provider is created. */
  readonly warn: (warning: KekWarning) => void;
}

/**
 * The module an adapter package exports. `KEK_PROVIDER=<name>` loads the
 * package `@qauth-labs/keys-<name>` and calls its `createKekProvider`.
 */
export interface KekProviderModule {
  /**
   * Read the adapter's settings from `context.env` and return a ready
   * provider. A missing or invalid setting throws an
   * `InvalidConfigurationError` that names the variable.
   */
  createKekProvider(context: KekProviderContext): KekProvider | Promise<KekProvider>;
}
