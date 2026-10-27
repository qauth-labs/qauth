import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, randomUUID } from 'node:crypto';

import type { VaultHttpRequest, VaultHttpResponse, VaultTransport } from '../lib/https-transport';

/**
 * A Vault test double: the Transit engine, tokens and AppRole held in memory,
 * with the behaviour the provider relies on (ADR-019 Decision 9, #578). It is
 * the provider's {@link VaultTransport}, so the client, the token session and
 * the provider run unchanged over it.
 *
 * - Transit keys have versions; `rotateKey` adds one, and decryption accepts
 *   every version from `min_decryption_version` to the latest, as in Vault.
 *   A derived key derives an AES-256-GCM key from each `context`; a key that
 *   is not derived ignores the context, as Vault does.
 * - Errors are Vault's statuses and messages, as a Vault 2.1 dev server
 *   answers them (the dev-server suite pins the same messages).
 * - Tokens expire on the test's clock, renew up to their maximum TTL, and can
 *   be revoked. A token's policy names the paths it may use, as an ACL
 *   policy does; the default policy grants lookup-self, renew-self and
 *   revoke-self.
 *
 * It never leaves the process. The dev-server suite runs the provider against
 * a real Vault.
 */

/** A capability of an ACL policy. */
export type Capability = 'create' | 'read' | 'update';

/** An ACL policy: the capabilities on each exact path. */
export type DoublePolicy = Readonly<Record<string, readonly Capability[]>>;

/** The policy of the signer role on the key `name` of the `transit` mount. */
export function signerPolicy(name = 'qauth-kek', mount = 'transit'): DoublePolicy {
  return {
    [`${mount}/encrypt/${name}`]: ['update'],
    [`${mount}/decrypt/${name}`]: ['update'],
    [`${mount}/keys/${name}`]: ['read'],
  };
}

const DEFAULT_POLICY: DoublePolicy = {
  'auth/token/lookup-self': ['read'],
  'auth/token/renew-self': ['update'],
  'auth/token/revoke-self': ['update'],
};

interface DoubleKey {
  readonly derived: boolean;
  readonly type: string;
  exportable: boolean;
  allowPlaintextBackup: boolean;
  deletionAllowed: boolean;
  readonly imported: boolean;
  readonly versions: Map<number, Buffer>;
  latest: number;
  minDecryptionVersion: number;
}

interface DoubleToken {
  /** Epoch ms; `null` never expires. */
  expiresAt: number | null;
  readonly maxExpiresAt: number | null;
  readonly ttlMs: number;
  readonly renewable: boolean;
  readonly policy: DoublePolicy | 'root';
  revoked: boolean;
}

interface DoubleRole {
  readonly secretIds: Set<string>;
  readonly tokenTtlMs: number;
  readonly tokenMaxTtlMs: number;
  readonly policy: DoublePolicy;
  readonly defaultPolicy: boolean;
}

/** What {@link VaultDouble.createToken} takes. */
export interface DoubleTokenOptions {
  /** The TTL in ms; `0` for a token that never expires. */
  readonly ttlMs: number;
  /** The longest the token can live, renewals included, in ms. */
  readonly maxTtlMs?: number;
  readonly renewable?: boolean;
  readonly policy: DoublePolicy;
  /** Whether the default policy applies too. Defaults to `true`. */
  readonly defaultPolicy?: boolean;
}

/** A canned answer for {@link VaultDouble.failNext}: a status, or an error the transport throws. */
export type DoubleFault =
  | { readonly status: number; readonly errors?: readonly string[] }
  | { readonly error: Error };

/** One request the double served. */
export interface DoubleRequest {
  readonly method: string;
  /** The path below `/v1/`. */
  readonly path: string;
  readonly token: string | undefined;
  readonly namespace: string | undefined;
  readonly body: Record<string, unknown> | undefined;
  /** The answer size cap the request set, if any. */
  readonly maxResponseBytes: number | undefined;
  readonly status: number;
}

/** A Vault test double. See the module comment. */
export interface VaultDouble {
  readonly transport: VaultTransport;
  /** Every request the double served, in order. */
  readonly requests: DoubleRequest[];
  /** The root token: every path, no expiry. */
  readonly rootToken: string;
  createKey(
    name: string,
    options?: { derived?: boolean; type?: string; mount?: string; imported?: boolean }
  ): void;
  /** Add a key version; new encryptions use it. */
  rotateKey(name: string, mount?: string): number;
  setMinDecryptionVersion(name: string, version: number, mount?: string): void;
  /** Change a key's export and deletion settings, as `<mount>/keys/<name>/config` does. */
  configureKey(
    name: string,
    config: { exportable?: boolean; allowPlaintextBackup?: boolean; deletionAllowed?: boolean }
  ): void;
  /** Delete a key, as Vault does once `deletion_allowed` is set. */
  deleteKey(name: string, mount?: string): void;
  createToken(options: DoubleTokenOptions): string;
  revokeToken(token: string): void;
  /** The token's expiry in epoch ms, `null` when it never expires, `undefined` when unknown. */
  tokenExpiry(token: string): number | null | undefined;
  /** Add an AppRole role on `mount` and return its role ID and a secret ID. */
  createAppRole(options: {
    readonly tokenTtlMs: number;
    readonly tokenMaxTtlMs: number;
    readonly policy: DoublePolicy;
    readonly mount?: string;
    /** Whether the role's tokens get the default policy too. Defaults to `true`. */
    readonly defaultPolicy?: boolean;
  }): { roleId: string; secretId: string };
  revokeSecretId(roleId: string, secretId: string): void;
  /** Answer the next `times` requests whose path matches `path` with `fault`. */
  failNext(fault: DoubleFault, options?: { times?: number; path?: RegExp }): void;
  /** Drop every fault {@link failNext} queued. */
  clearFaults(): void;
  /** Decrypt a Vault ciphertext under `context` (base64) directly, as a Vault operator could. */
  decrypt(name: string, ciphertext: string, context: string): Buffer;
}

const IV_BYTES = 12;
const TAG_BYTES = 16;

/** Thrown inside the double to answer with a status. */
class Refusal extends Error {
  constructor(
    readonly status: number,
    readonly errors: readonly string[]
  ) {
    super(errors.join('; '));
  }
}

const PERMISSION_DENIED = ['1 error occurred:\n\t* permission denied\n\n'];
const INVALID_TOKEN = ['2 errors occurred:\n\t* permission denied\n\t* invalid token\n\n'];

/** A Vault test double on `clock`. */
export function createVaultDouble(
  clock: { now(): number } = { now: () => Date.now() }
): VaultDouble {
  const keys = new Map<string, DoubleKey>();
  const tokens = new Map<string, DoubleToken>();
  const roles = new Map<string, DoubleRole>();
  const requests: DoubleRequest[] = [];
  const faults: Array<{ fault: DoubleFault; times: number; path: RegExp | undefined }> = [];
  const rootToken = `hvs.root-${randomUUID()}`;
  tokens.set(rootToken, {
    expiresAt: null,
    maxExpiresAt: null,
    ttlMs: 0,
    renewable: false,
    policy: 'root',
    revoked: false,
  });

  function newToken(options: DoubleTokenOptions): string {
    const now = clock.now();
    const token = `hvs.${randomBytes(18).toString('base64url')}`;
    const policy: DoublePolicy =
      options.defaultPolicy === false ? options.policy : { ...DEFAULT_POLICY, ...options.policy };
    tokens.set(token, {
      expiresAt: options.ttlMs > 0 ? now + options.ttlMs : null,
      maxExpiresAt:
        options.ttlMs > 0 && options.maxTtlMs !== undefined ? now + options.maxTtlMs : null,
      ttlMs: options.ttlMs,
      renewable: options.renewable ?? true,
      policy,
      revoked: false,
    });
    return token;
  }

  function liveToken(token: string | undefined): DoubleToken {
    const entry = token === undefined ? undefined : tokens.get(token);
    if (
      entry === undefined ||
      entry.revoked ||
      (entry.expiresAt !== null && clock.now() >= entry.expiresAt)
    ) {
      throw new Refusal(403, INVALID_TOKEN);
    }
    return entry;
  }

  function allowed(entry: DoubleToken, path: string, capability: Capability): boolean {
    return entry.policy === 'root' || (entry.policy[path]?.includes(capability) ?? false);
  }

  function demand(entry: DoubleToken, path: string, capability: Capability): void {
    if (!allowed(entry, path, capability)) throw new Refusal(403, PERMISSION_DENIED);
  }

  function keyOf(mount: string, name: string): DoubleKey | undefined {
    return keys.get(`${mount}/${name}`);
  }

  function addKey(
    mount: string,
    name: string,
    derived: boolean,
    type: string,
    imported = false
  ): DoubleKey {
    const key: DoubleKey = {
      derived,
      type,
      exportable: false,
      allowPlaintextBackup: false,
      deletionAllowed: false,
      imported,
      versions: new Map([[1, randomBytes(32)]]),
      latest: 1,
      minDecryptionVersion: 1,
    };
    keys.set(`${mount}/${name}`, key);
    return key;
  }

  function encryptionKey(key: DoubleKey, version: number, context: Buffer | undefined): Buffer {
    const material = key.versions.get(version) as Buffer;
    if (!key.derived) return material;
    if (context === undefined || context.length === 0) {
      throw new Refusal(400, [
        "missing 'context' for key derivation; the key was created using a derived key, which means additional, per-request information must be included in order to perform operations with the key",
      ]);
    }
    return Buffer.from(hkdfSync('sha256', material, Buffer.alloc(0), context, 32));
  }

  function decodeContext(value: unknown): Buffer | undefined {
    if (value === undefined || value === '') return undefined;
    if (typeof value !== 'string') throw new Refusal(400, ['failed to base64-decode context']);
    return Buffer.from(value, 'base64');
  }

  function decryptWith(key: DoubleKey, ciphertext: unknown, context: Buffer | undefined): Buffer {
    if (typeof ciphertext !== 'string' || !ciphertext.startsWith('vault:')) {
      throw new Refusal(400, ['invalid ciphertext: no prefix']);
    }
    const match = /^vault:v(\d+):(.*)$/s.exec(ciphertext);
    if (match === null) throw new Refusal(400, ['invalid ciphertext: wrong number of fields']);
    const version = Number(match[1]);
    if (version > key.latest) throw new Refusal(400, ['invalid ciphertext: version is too new']);
    if (version < key.minDecryptionVersion) {
      throw new Refusal(400, ['ciphertext or signature version is disallowed by policy (too old)']);
    }
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(match[2]) || match[2].length % 4 !== 0) {
      throw new Refusal(400, ['invalid ciphertext: could not decode base64']);
    }
    const bytes = Buffer.from(match[2], 'base64');
    if (bytes.length < IV_BYTES + TAG_BYTES) throw new Refusal(400, ['invalid ciphertext length']);
    const decipher = createDecipheriv(
      'aes-256-gcm',
      encryptionKey(key, version, context),
      bytes.subarray(0, IV_BYTES)
    );
    decipher.setAuthTag(bytes.subarray(bytes.length - TAG_BYTES));
    try {
      return Buffer.concat([
        decipher.update(bytes.subarray(IV_BYTES, bytes.length - TAG_BYTES)),
        decipher.final(),
      ]);
    } catch {
      throw new Refusal(400, ['cipher: message authentication failed']);
    }
  }

  function serve(
    method: string,
    path: string,
    token: string | undefined,
    body: Record<string, unknown> | undefined
  ): { status: number; body: unknown } {
    // AppRole login: no token.
    const login = /^auth\/(.+)\/login$/.exec(path);
    if (method === 'POST' && login !== null && login[1] !== 'token') {
      const role = roles.get(`${login[1]}/${String(body?.['role_id'])}`);
      if (role === undefined && ![...roles.keys()].some((id) => id.startsWith(`${login[1]}/`))) {
        throw new Refusal(403, ['permission denied']);
      }
      if (role === undefined || !role.secretIds.has(String(body?.['secret_id']))) {
        throw new Refusal(400, ['invalid role or secret ID']);
      }
      const issued = newToken({
        ttlMs: role.tokenTtlMs,
        maxTtlMs: role.tokenMaxTtlMs,
        policy: role.policy,
        defaultPolicy: role.defaultPolicy,
      });
      return {
        status: 200,
        body: {
          auth: {
            client_token: issued,
            lease_duration: Math.floor(role.tokenTtlMs / 1000),
            renewable: true,
            policies: ['default', 'signer'],
          },
        },
      };
    }

    const entry = liveToken(token);

    if (path === 'auth/token/lookup-self' && method === 'GET') {
      demand(entry, path, 'read');
      const ttl =
        entry.expiresAt === null
          ? 0
          : Math.max(0, Math.floor((entry.expiresAt - clock.now()) / 1000));
      return {
        status: 200,
        body: {
          data: {
            ttl,
            renewable: entry.renewable,
            expire_time: entry.expiresAt === null ? null : new Date(entry.expiresAt).toISOString(),
            policies: entry.policy === 'root' ? ['root'] : ['default', 'signer'],
          },
        },
      };
    }

    if (path === 'auth/token/revoke-self' && method === 'POST') {
      demand(entry, path, 'update');
      entry.revoked = true;
      return { status: 204, body: undefined };
    }

    if (path === 'auth/token/renew-self' && method === 'POST') {
      demand(entry, path, 'update');
      if (!entry.renewable || entry.expiresAt === null) {
        throw new Refusal(400, ['lease is not renewable']);
      }
      const now = clock.now();
      entry.expiresAt = Math.min(now + entry.ttlMs, entry.maxExpiresAt ?? Infinity);
      return {
        status: 200,
        body: {
          auth: {
            client_token: token,
            lease_duration: Math.floor((entry.expiresAt - now) / 1000),
            renewable: true,
          },
        },
      };
    }

    const transit = /^(.+)\/(encrypt|decrypt|keys)\/([^/]+)$/.exec(path);
    if (transit !== null) {
      const [, mount, operation, name] = transit;
      let key = keyOf(mount, name);
      if (operation === 'keys' && method === 'GET') {
        demand(entry, path, 'read');
        if (key === undefined) throw new Refusal(404, []);
        return {
          status: 200,
          body: {
            data: {
              name,
              type: key.type,
              derived: key.derived,
              latest_version: key.latest,
              min_decryption_version: key.minDecryptionVersion,
              supports_encryption: true,
              supports_decryption: true,
              exportable: key.exportable,
              allow_plaintext_backup: key.allowPlaintextBackup,
              deletion_allowed: key.deletionAllowed,
              imported_key: key.imported,
            },
          },
        };
      }
      if (operation === 'encrypt' && method === 'POST') {
        const context = decodeContext(body?.['context']);
        if (key === undefined) {
          // Vault creates a missing key on encrypt when the policy grants `create`.
          demand(entry, path, 'create');
          key = addKey(mount, name, context !== undefined, 'aes256-gcm96');
        } else {
          demand(entry, path, 'update');
        }
        if (typeof body?.['plaintext'] !== 'string') {
          throw new Refusal(400, ['missing plaintext to encrypt']);
        }
        const plaintext = Buffer.from(body['plaintext'], 'base64');
        const iv = randomBytes(IV_BYTES);
        const cipher = createCipheriv('aes-256-gcm', encryptionKey(key, key.latest, context), iv);
        const sealed = Buffer.concat([
          iv,
          cipher.update(plaintext),
          cipher.final(),
          cipher.getAuthTag(),
        ]);
        return {
          status: 200,
          body: {
            data: {
              ciphertext: `vault:v${key.latest}:${sealed.toString('base64')}`,
              key_version: key.latest,
            },
          },
        };
      }
      if (operation === 'decrypt' && method === 'POST') {
        demand(entry, path, 'update');
        if (key === undefined) throw new Refusal(400, ['encryption key not found']);
        const plaintext = decryptWith(key, body?.['ciphertext'], decodeContext(body?.['context']));
        return { status: 200, body: { data: { plaintext: plaintext.toString('base64') } } };
      }
    }

    demand(entry, path, 'read');
    throw new Refusal(404, [`no handler for route "${path}". route entry not found.`]);
  }

  const transport: VaultTransport = async (
    request: VaultHttpRequest
  ): Promise<VaultHttpResponse> => {
    const path = request.path.replace(/^\/v1\//, '');
    const body =
      request.body === undefined
        ? undefined
        : (JSON.parse(request.body) as Record<string, unknown>);
    const token = request.headers['X-Vault-Token'];
    const namespace = request.headers['X-Vault-Namespace'];
    const record = (status: number) =>
      requests.push({
        method: request.method,
        path,
        token,
        namespace,
        body,
        maxResponseBytes: request.maxResponseBytes,
        status,
      });

    const fault = faults.find((entry) => entry.path === undefined || entry.path.test(path));
    if (fault !== undefined) {
      fault.times -= 1;
      if (fault.times <= 0) faults.splice(faults.indexOf(fault), 1);
      if ('error' in fault.fault) {
        record(0);
        throw fault.fault.error;
      }
      record(fault.fault.status);
      return { status: fault.fault.status, body: { errors: fault.fault.errors ?? [] } };
    }

    try {
      const answer = serve(request.method, path, token, body);
      record(answer.status);
      return answer;
    } catch (error) {
      if (!(error instanceof Refusal)) throw error;
      record(error.status);
      return { status: error.status, body: { errors: error.errors } };
    }
  };

  return {
    transport,
    requests,
    rootToken,

    createKey(name, options = {}) {
      addKey(
        options.mount ?? 'transit',
        name,
        options.derived ?? true,
        options.type ?? 'aes256-gcm96',
        options.imported ?? false
      );
    },

    rotateKey(name, mount = 'transit') {
      const key = keyOf(mount, name);
      if (key === undefined) throw new Error(`No key ${mount}/${name}`);
      key.latest += 1;
      key.versions.set(key.latest, randomBytes(32));
      return key.latest;
    },

    setMinDecryptionVersion(name, version, mount = 'transit') {
      const key = keyOf(mount, name);
      if (key === undefined) throw new Error(`No key ${mount}/${name}`);
      key.minDecryptionVersion = version;
    },

    configureKey(name, config) {
      const key = keyOf('transit', name);
      if (key === undefined) throw new Error(`No key transit/${name}`);
      if (config.exportable !== undefined) key.exportable = config.exportable;
      if (config.allowPlaintextBackup !== undefined) {
        key.allowPlaintextBackup = config.allowPlaintextBackup;
      }
      if (config.deletionAllowed !== undefined) key.deletionAllowed = config.deletionAllowed;
    },

    deleteKey(name, mount = 'transit') {
      keys.delete(`${mount}/${name}`);
    },

    createToken: newToken,

    revokeToken(token) {
      const entry = tokens.get(token);
      if (entry !== undefined) entry.revoked = true;
    },

    tokenExpiry(token) {
      return tokens.get(token)?.expiresAt;
    },

    createAppRole(options) {
      const mount = options.mount ?? 'approle';
      const roleId = randomUUID();
      const secretId = randomUUID();
      roles.set(`${mount}/${roleId}`, {
        secretIds: new Set([secretId]),
        tokenTtlMs: options.tokenTtlMs,
        tokenMaxTtlMs: options.tokenMaxTtlMs,
        policy: options.policy,
        defaultPolicy: options.defaultPolicy ?? true,
      });
      return { roleId, secretId };
    },

    revokeSecretId(roleId, secretId) {
      for (const [id, role] of roles) {
        if (id.endsWith(`/${roleId}`)) role.secretIds.delete(secretId);
      }
    },

    failNext(fault, options = {}) {
      faults.push({ fault, times: options.times ?? 1, path: options.path });
    },

    clearFaults() {
      faults.length = 0;
    },

    decrypt(name, ciphertext, context) {
      const key = keyOf('transit', name);
      if (key === undefined) throw new Error(`No key transit/${name}`);
      return decryptWith(key, ciphertext, decodeContext(context));
    },
  };
}
