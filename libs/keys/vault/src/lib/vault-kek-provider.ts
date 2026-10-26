import { randomBytes, timingSafeEqual } from 'node:crypto';

import { isKeyCustodyError, KeyDecryptionError, UnknownKekRefError } from '@qauth-labs/server-keys';
import {
  DATA_KEY_BYTES,
  type KekProvider,
  type KekProviderContext,
  type KekProviderHealth,
  type KekProviderModule,
  KEY_AAD_VERSION,
  type KeyAad,
  type WrappedDataKey,
} from '@qauth-labs/server-keys/custody';

import {
  describeVaultFailure,
  toKeyCustodyError,
  VaultAnswerError,
  VaultHttpError,
  VaultKeyRefusedError,
  type VaultOperation,
} from './errors';
import {
  createHttpsTransport,
  type VaultHttpResponse,
  type VaultTransport,
} from './https-transport';
import { formatKekRef, parseKekRef, transitKeyPath } from './kek-ref';
import {
  readVaultSettings,
  SECRET_ID_FILE_VARIABLE,
  TOKEN_FILE_VARIABLE,
  VAULT_KEK_PROVIDER,
} from './settings';
import { formatCiphertext, parseCiphertext, transitContextOf } from './transit';
import {
  createVaultClient,
  SYSTEM_CLOCK,
  type VaultCall,
  type VaultClient,
  type VaultClock,
} from './vault-client';
import {
  appRoleCredentials,
  createTokenSession,
  tokenFileCredentials,
  type TokenSession,
} from './vault-token';

/** What {@link createVaultKekProvider} needs. */
export interface VaultKekProviderOptions {
  readonly client: VaultClient;
  readonly session: TokenSession;
  /** The Transit mount path. */
  readonly transitMount: string;
  /** The Transit key name. */
  readonly keyName: string;
  /** The namespace, which `kekRef` names; the client sends it. */
  readonly namespace: string | undefined;
  /** The clock the key check ages on. Defaults to the process clock. */
  readonly clock?: VaultClock;
}

/**
 * How long a passed key check holds, in ms. The key's type and `derived` never
 * change, but the key can be deleted and created again under the same name,
 * and `exportable` can be switched on later.
 */
export const KEY_CHECK_MAX_AGE_MS = 15 * 60_000;

/**
 * The Transit key types the provider accepts: AEAD ciphers with a 256-bit key
 * that support key derivation.
 */
const KEY_TYPES: ReadonlySet<string> = new Set(['aes256-gcm96', 'chacha20-poly1305']);

/** The largest wrapped data key the provider sends to Vault, in bytes. */
const MAX_WRAPPED_BYTES = 1024;

/**
 * The associated data {@link KekProvider.health} wraps a random probe under,
 * the same as the KMS adapter's.
 */
const HEALTH_AAD: KeyAad = Object.freeze({
  realmId: 'qauth-kek-health',
  purpose: 'kek_health',
  scopeId: null,
  kid: 'kek-health',
  algorithm: 'A256GCM',
  version: KEY_AAD_VERSION,
});

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The `data` object of a Vault answer. */
function dataOf(operation: VaultOperation, answer: VaultHttpResponse): Record<string, unknown> {
  const data = (answer.body as { data?: unknown } | undefined)?.data;
  if (typeof data !== 'object' || data === null)
    throw new VaultAnswerError(operation, 'has no data');
  return data as Record<string, unknown>;
}

/** Why {@link KekProvider.health} fails: a code, a status, never a secret. */
function healthReason(error: unknown): string {
  if (!isKeyCustodyError(error)) return 'The Vault call failed unexpectedly';
  const vault = describeVaultFailure(error.cause);
  return vault === undefined
    ? `${error.code}: ${error.message}`
    : `${error.code}: ${error.message} (${vault})`;
}

/**
 * The Vault Transit KEK provider (ADR-019 Decision 9, #578): the KEK is a
 * Transit key in Vault, and it never leaves Vault.
 *
 * - Before its first wrap or unwrap, and again once
 *   {@link KEY_CHECK_MAX_AGE_MS} has passed, the provider reads the key's
 *   settings (`<mount>/keys/<name>`) and refuses a key that is not `derived`,
 *   not an AES-256-GCM or ChaCha20-Poly1305 key, that cannot both encrypt and
 *   decrypt, or that can leave Vault (`exportable`, `allow_plaintext_backup`).
 *   Vault ignores the `context` of a key that is not derived, so such a key
 *   would open a wrapped data key under any associated data.
 * - `wrap` sends the data key to `<mount>/encrypt/<name>` with the key's
 *   associated data as the `context` (`transit.ts`), then decrypts the result
 *   once, which proves that this token can open what it stores before
 *   anything is stored. `kekRef` names the key and the version that wrapped
 *   it (`kek-ref.ts`).
 * - `unwrap` refuses a `kekRef` that names another key, without a call, then
 *   sends the ciphertext rebuilt from the stored bytes and the version to
 *   `<mount>/decrypt/<name>` under the context, and checks that the result is
 *   a data key.
 * - `health` wraps and unwraps a random probe.
 *
 * Signing stays in the signer: Vault only wraps data keys. When Vault refuses
 * the token (403), the session logs in again and the call is made once more
 * (`vault-token.ts`). Every other failure is a typed error (`errors.ts`),
 * after the client's bounded retries (`vault-client.ts`).
 *
 * The data key crosses the wire in base64 inside a JSON string, as Vault's
 * API takes it; a JavaScript string cannot be zeroed, so it lasts until the
 * garbage collector reclaims it. The bytes the provider returns are the
 * caller's to zero.
 */
export function createVaultKekProvider(options: VaultKekProviderOptions): KekProvider {
  const { client, session, transitMount, keyName } = options;
  const clock = options.clock ?? SYSTEM_CLOCK;
  const keyPath = transitKeyPath(options.namespace, transitMount, keyName);

  /** One Vault call with the session's token; a token Vault no longer accepts is replaced once. */
  async function call(operation: VaultOperation, request: Omit<VaultCall, 'token'>) {
    const token = await session.token();
    try {
      return await client.send(operation, { ...request, token });
    } catch (error) {
      if (!(error instanceof VaultHttpError) || error.status !== 403) throw error;
      if (!(await session.refused(token))) throw error;
    }
    return client.send(operation, { ...request, token: await session.token() });
  }

  /** Run Vault calls, reporting their failure as a key-custody error. */
  async function custody<T>(run: () => Promise<T>, kekRef?: string): Promise<T> {
    try {
      return await run();
    } catch (error) {
      throw toKeyCustodyError(error, kekRef);
    }
  }

  async function checkKey(): Promise<void> {
    const data = dataOf(
      'read-key',
      await call('read-key', { method: 'GET', path: `${transitMount}/keys/${keyName}` })
    );
    if (data['derived'] !== true) {
      throw new VaultKeyRefusedError(
        `The Transit key ${keyPath} is not derived: Vault would ignore the context that binds each data key to its key. Create the key with derived=true.`
      );
    }
    if (typeof data['type'] !== 'string' || !KEY_TYPES.has(data['type'])) {
      throw new VaultKeyRefusedError(
        `The Transit key ${keyPath} must be of type aes256-gcm96 or chacha20-poly1305.`
      );
    }
    if (data['supports_encryption'] !== true || data['supports_decryption'] !== true) {
      throw new VaultKeyRefusedError(
        `The Transit key ${keyPath} must support both encryption and decryption.`
      );
    }
    if (data['exportable'] === true || data['allow_plaintext_backup'] === true) {
      throw new VaultKeyRefusedError(
        `The Transit key ${keyPath} can leave Vault (exportable or allow_plaintext_backup): a KEK must not.`
      );
    }
  }

  // A passed check holds for KEY_CHECK_MAX_AGE_MS; calls meanwhile share it.
  // A failed check is tried again at the next call.
  let keyChecked: { readonly at: number; readonly done: Promise<void> } | undefined;
  function ensureKey(): Promise<void> {
    const now = clock.now();
    if (keyChecked === undefined || now - keyChecked.at >= KEY_CHECK_MAX_AGE_MS) {
      const entry = {
        at: now,
        done: checkKey().catch((error: unknown) => {
          if (keyChecked === entry) keyChecked = undefined;
          throw error;
        }),
      };
      keyChecked = entry;
    }
    return keyChecked.done;
  }

  /** Decrypt `bytes` of key version `version` under `context`: a data key the caller owns. */
  async function decryptDataKey(
    bytes: Uint8Array,
    version: number,
    context: string
  ): Promise<Buffer> {
    const data = dataOf(
      'decrypt',
      await call('decrypt', {
        method: 'POST',
        path: `${transitMount}/decrypt/${keyName}`,
        body: { ciphertext: formatCiphertext(version, bytes), context },
      })
    );
    if (typeof data['plaintext'] !== 'string') {
      throw new VaultAnswerError('decrypt', 'has no plaintext');
    }
    const dek = Buffer.from(data['plaintext'], 'base64');
    if (dek.length !== DATA_KEY_BYTES) {
      dek.fill(0);
      throw new KeyDecryptionError({ detail: 'the wrapped value is not a data key' });
    }
    return dek;
  }

  async function wrap(dek: Uint8Array, aad: KeyAad): Promise<WrappedDataKey> {
    if (dek.length !== DATA_KEY_BYTES) {
      throw new RangeError(`A data key must be ${DATA_KEY_BYTES} bytes`);
    }
    const context = transitContextOf(aad);
    return custody(async () => {
      await ensureKey();
      const data = dataOf(
        'encrypt',
        await call('encrypt', {
          method: 'POST',
          path: `${transitMount}/encrypt/${keyName}`,
          body: {
            plaintext: Buffer.from(dek.buffer, dek.byteOffset, dek.byteLength).toString('base64'),
            context,
          },
        })
      );
      const ciphertext = parseCiphertext(data['ciphertext']);
      if (ciphertext === undefined)
        throw new VaultAnswerError('encrypt', 'has no Vault ciphertext');
      if (data['key_version'] !== undefined && data['key_version'] !== ciphertext.version) {
        throw new VaultAnswerError('encrypt', 'names two key versions');
      }

      const opened = await decryptDataKey(ciphertext.bytes, ciphertext.version, context);
      try {
        if (!sameBytes(opened, dek)) {
          throw new KeyDecryptionError({ detail: 'the wrapped data key opened to other bytes' });
        }
      } finally {
        opened.fill(0);
      }
      return Object.freeze({
        wrapped: ciphertext.bytes,
        kekRef: formatKekRef(keyPath, ciphertext.version),
      });
    });
  }

  return Object.freeze({
    name: VAULT_KEK_PROVIDER,

    wrap,

    async unwrap(wrapped: Uint8Array, aad: KeyAad, kekRef: string): Promise<Uint8Array> {
      const parsed = parseKekRef(kekRef);
      if (parsed === undefined || parsed.keyPath !== keyPath) throw new UnknownKekRefError(kekRef);

      let context: string;
      try {
        context = transitContextOf(aad);
      } catch (error) {
        throw new KeyDecryptionError({ detail: 'unusable associated data', cause: error });
      }
      if (wrapped.length === 0 || wrapped.length > MAX_WRAPPED_BYTES) {
        throw new KeyDecryptionError({ detail: 'malformed wrapped data key' });
      }
      return custody(async () => {
        await ensureKey();
        return decryptDataKey(wrapped, parsed.version, context);
      }, kekRef);
    },

    async health(): Promise<KekProviderHealth> {
      const probe = randomBytes(DATA_KEY_BYTES);
      try {
        const { kekRef } = await wrap(probe, HEALTH_AAD);
        return Object.freeze({ ok: true, provider: VAULT_KEK_PROVIDER, kekRef });
      } catch (error) {
        return Object.freeze({
          ok: false,
          provider: VAULT_KEK_PROVIDER,
          reason: healthReason(error),
        });
      } finally {
        probe.fill(0);
      }
    },
  });
}

/** What the entry point can replace, for tests. */
export interface VaultKekProviderDependencies {
  readonly clock?: VaultClock;
  /** Replaces the HTTPS transport to `KEK_VAULT_ADDR`, such as with a Vault test double. */
  readonly transport?: VaultTransport;
}

/**
 * The adapter's entry point: `KEK_PROVIDER=vault` makes the key library's
 * `loadKekProvider` import this package and call it.
 *
 * Reads the `KEK_VAULT_*` settings (`settings.ts`), checks the token or
 * secret ID file and the CA file, and creates the HTTPS client. It makes no
 * Vault call, so a Vault outage does not stop the boot; the first wrap or
 * unwrap logs in.
 *
 * @throws InvalidConfigurationError when a setting is missing or invalid
 */
export const createKekProvider: KekProviderModule['createKekProvider'] = (
  context: KekProviderContext
) => createKekProviderWith(context, {});

/** {@link createKekProvider}, with a replaceable clock and transport. */
export function createKekProviderWith(
  context: KekProviderContext,
  dependencies: VaultKekProviderDependencies
): KekProvider {
  const settings = readVaultSettings(context.env, context.warn);
  const client = createVaultClient({
    transport:
      dependencies.transport ??
      createHttpsTransport({
        origin: settings.address,
        ...(settings.caCertificates !== undefined ? { ca: settings.caCertificates } : {}),
      }),
    ...(settings.namespace !== undefined ? { namespace: settings.namespace } : {}),
    ...(dependencies.clock !== undefined ? { clock: dependencies.clock } : {}),
  });
  const credentials =
    settings.auth.method === 'token'
      ? tokenFileCredentials(settings.auth.tokenFile, TOKEN_FILE_VARIABLE)
      : appRoleCredentials({
          roleId: settings.auth.roleId,
          secretIdFile: settings.auth.secretIdFile,
          secretIdVariable: SECRET_ID_FILE_VARIABLE,
          mount: settings.auth.mount,
        });
  const session = createTokenSession({
    client,
    credentials,
    ...(dependencies.clock !== undefined ? { clock: dependencies.clock } : {}),
  });
  return createVaultKekProvider({
    client,
    session,
    transitMount: settings.transitMount,
    keyName: settings.keyName,
    namespace: settings.namespace,
    ...(dependencies.clock !== undefined ? { clock: dependencies.clock } : {}),
  });
}
