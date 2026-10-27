import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { isKeyCustodyError, type KeyCustodyErrorCode } from '@qauth-labs/server-keys';
import {
  createInProcessSigner,
  encodeKeyAad,
  generateKeyMaterial,
  type KekProvider,
  KEY_AAD_VERSION,
  type KeyAad,
  runKekProviderContract,
  sealKeyMaterial,
  type SignerKeyStore,
} from '@qauth-labs/server-keys/custody';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, describe, expect, it, type TestContext } from 'vitest';

import { type StartedVault, startVaultContainer } from '../testing/vault-container';
import { VaultHttpError } from './errors';
import { parseKekRef } from './kek-ref';
import { formatCiphertext } from './transit';
import { createKekProvider } from './vault-kek-provider';

/**
 * The provider against a real Vault (#578): a dev server in a container, over
 * HTTPS with the server's own CA. The signer's tokens and AppRole role carry
 * only the policy of the package README, applied as written, and no default
 * policy, so the suite also proves that the guide's paths are all the signer
 * needs.
 *
 * Requires Docker; self-skips without it, and fails on CI without it, like
 * the other container suites. Each token-lifetime case waits real seconds,
 * since Vault's clock is the container's.
 */

const KEY = 'qauth-kek';
const README = join(__dirname, '../../README.md');

const AAD: KeyAad = Object.freeze({
  realmId: '7b0e9a52-6f7c-4c55-9e43-2d7f1c0a9b11',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'kid-1',
  algorithm: 'EdDSA',
  version: KEY_AAD_VERSION,
});

/** The policy block of the README, for key `name`. */
function guidePolicy(name: string): string {
  const match = /```hcl\n([\s\S]+?)```/.exec(readFileSync(README, 'utf8'));
  if (match === null) throw new Error('The README has no hcl policy block');
  return match[1].replaceAll(`/${KEY}"`, `/${name}"`);
}

let dockerUp = false;
let vault: StartedVault;
const dir = mkdtempSync(join(tmpdir(), 'qauth-vault-it-'));
let next = 0;

function writeFile(value: string): string {
  const path = join(dir, `secret-${next++}`);
  writeFileSync(path, `${value}\n`, { mode: 0o600 });
  return path;
}

async function admin(method: 'GET' | 'POST', path: string, body?: Record<string, unknown>) {
  return (await vault.admin(method, path, body)) as {
    data?: Record<string, unknown>;
    auth?: Record<string, unknown>;
  };
}

/** A derived Transit key and the README's policy for it, under the policy name `name`. */
async function createKey(name: string, options: { derived?: boolean } = {}): Promise<void> {
  await admin('POST', `transit/keys/${name}`, {
    type: 'aes256-gcm96',
    derived: options.derived ?? true,
  });
  await admin('POST', `sys/policies/acl/signer-${name}`, { policy: guidePolicy(name) });
}

/** A token with only the signer policy of key `name`, written to a file. */
async function signerToken(
  name: string,
  options: { ttl?: string; maxTtl?: string } = {}
): Promise<{ token: string; file: string }> {
  const answer = await admin('POST', 'auth/token/create', {
    policies: [`signer-${name}`],
    no_default_policy: true,
    renewable: true,
    ttl: options.ttl ?? '1h',
    explicit_max_ttl: options.maxTtl ?? '24h',
  });
  const token = String(answer.auth?.['client_token']);
  return { token, file: writeFile(token) };
}

/** An AppRole role with only the signer policy of key `name`: its role ID and a secret ID file. */
async function signerRole(
  name: string,
  options: { ttl?: string; maxTtl?: string } = {}
): Promise<{ role: string; roleId: string; secretId: string; secretIdFile: string }> {
  const role = `signer-${name}-${next++}`;
  await admin('POST', `auth/approle/role/${role}`, {
    token_policies: [`signer-${name}`],
    token_no_default_policy: true,
    token_ttl: options.ttl ?? '1h',
    token_max_ttl: options.maxTtl ?? '24h',
    secret_id_num_uses: 0,
  });
  const roleId = String(
    (await admin('GET', `auth/approle/role/${role}/role-id`)).data?.['role_id']
  );
  const secretId = String(
    (await admin('POST', `auth/approle/role/${role}/secret-id`)).data?.['secret_id']
  );
  return { role, roleId, secretId, secretIdFile: writeFile(secretId) };
}

function provider(env: Record<string, string>): KekProvider {
  return createKekProvider({
    env: {
      KEK_VAULT_ADDR: vault.address,
      KEK_VAULT_CA_CERT_FILE: vault.caFile,
      KEK_VAULT_TRANSIT_KEY: KEY,
      ...env,
    },
    warn: () => undefined,
  }) as KekProvider;
}

async function expectCode(promise: Promise<unknown>, code: KeyCustodyErrorCode): Promise<Error> {
  const error = await promise.then(
    () => {
      throw new Error(`expected ${code}, but the call succeeded`);
    },
    (reason: unknown) => reason
  );
  expect(isKeyCustodyError(error, code), `expected ${code}, got ${String(error)}`).toBe(true);
  return error as Error;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** `it`, skipped without Docker; the contract kit registers its cases through it. */
function live(name: string, test: () => Promise<void>, timeout?: number): void {
  it(
    name,
    async (context: TestContext) => {
      if (!dockerUp) context.skip();
      await test();
    },
    timeout
  );
}

beforeAll(async () => {
  dockerUp = await requireDockerOrSkip();
  if (!dockerUp) return;
  vault = await startVaultContainer(dir);
  await admin('POST', 'sys/mounts/transit', { type: 'transit' });
  await admin('POST', 'sys/auth/approle', { type: 'approle' });
  await createKey(KEY);
}, 180_000);

afterAll(async () => {
  if (dockerUp) await vault.stop();
  rmSync(dir, { recursive: true, force: true });
});

describe('the KEK provider contract against a Vault dev server', () => {
  let tokenFile: string;
  let role: { roleId: string; secretIdFile: string };
  beforeAll(async () => {
    if (!dockerUp) return;
    tokenFile = (await signerToken(KEY)).file;
    role = await signerRole(KEY);
  });

  runKekProviderContract({
    name: 'vault (dev server, token file, the README policy)',
    createProvider: () => provider({ KEK_VAULT_TOKEN_FILE: tokenFile }),
    describe,
    it: live,
  });

  runKekProviderContract({
    name: 'vault (dev server, AppRole, the README policy)',
    createProvider: () =>
      provider({ KEK_VAULT_ROLE_ID: role.roleId, KEK_VAULT_SECRET_ID_FILE: role.secretIdFile }),
    describe,
    it: live,
  });
});

describe('vault against a Vault dev server', () => {
  live(
    'wraps under the context, and a wrong context makes Vault refuse the ciphertext',
    async () => {
      const kek = provider({ KEK_VAULT_TOKEN_FILE: (await signerToken(KEY)).file });
      const dek = randomBytes(32);

      const { wrapped, kekRef } = await kek.wrap(Buffer.from(dek), AAD);

      expect(kekRef).toBe(`vault:transit/keys/${KEY}#v1`);
      const ciphertext = formatCiphertext(parseKekRef(kekRef)?.version ?? 0, wrapped);
      const opened = await admin('POST', `transit/decrypt/${KEY}`, {
        ciphertext,
        context: encodeKeyAad(AAD).toString('base64'),
      });
      expect(Buffer.from(String(opened.data?.['plaintext']), 'base64')).toEqual(dek);
      await expect(
        admin('POST', `transit/decrypt/${KEY}`, {
          ciphertext,
          context: encodeKeyAad({ ...AAD, realmId: randomUUID() }).toString('base64'),
        })
      ).rejects.toMatchObject({ status: 400, errors: ['cipher: message authentication failed'] });
      await expectCode(
        kek.unwrap(wrapped, { ...AAD, kid: 'another-kid' }, kekRef),
        'KEY_DECRYPTION_FAILED'
      );
    }
  );

  live('refuses a Transit key that is not derived, whose context Vault would ignore', async () => {
    await createKey('plain-kek', { derived: false });
    const plaintext = randomBytes(32).toString('base64');
    const sealed = await admin('POST', 'transit/encrypt/plain-kek', {
      plaintext,
      context: encodeKeyAad(AAD).toString('base64'),
    });
    const elsewhere = await admin('POST', 'transit/decrypt/plain-kek', {
      ciphertext: sealed.data?.['ciphertext'],
      context: encodeKeyAad({ ...AAD, realmId: randomUUID() }).toString('base64'),
    });
    expect(elsewhere.data?.['plaintext']).toBe(plaintext);

    const kek = provider({
      KEK_VAULT_TRANSIT_KEY: 'plain-kek',
      KEK_VAULT_TOKEN_FILE: (await signerToken('plain-kek')).file,
    });
    const error = await expectCode(kek.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');
    expect(String(error.cause)).toMatch(/is not derived/);
  });

  live('cannot create a missing key under the README policy', async () => {
    await admin('POST', 'sys/policies/acl/signer-missing-kek', {
      policy: guidePolicy('missing-kek'),
    });
    const kek = provider({
      KEK_VAULT_TRANSIT_KEY: 'missing-kek',
      KEK_VAULT_TOKEN_FILE: (await signerToken('missing-kek')).file,
    });
    const { token } = await signerToken('missing-kek');

    await expectCode(kek.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');
    await expect(
      vault.call(token, 'POST', 'transit/encrypt/missing-kek', {
        plaintext: randomBytes(32).toString('base64'),
        context: encodeKeyAad(AAD).toString('base64'),
      })
    ).rejects.toMatchObject({ status: 403 });
    await expect(admin('GET', 'transit/keys/missing-kek')).rejects.toBeInstanceOf(VaultHttpError);
  });

  live(
    'after a Transit key rotation, wraps under the new version and re-wraps a stored key to it',
    async () => {
      await createKey('rotating-kek');
      const env = {
        KEK_VAULT_TRANSIT_KEY: 'rotating-kek',
        KEK_VAULT_TOKEN_FILE: (await signerToken('rotating-kek')).file,
      };
      const kek = provider(env);
      const dek = randomBytes(32);
      const stored = await kek.wrap(Buffer.from(dek), AAD);
      expect(stored.kekRef).toBe('vault:transit/keys/rotating-kek#v1');

      await admin('POST', 'transit/keys/rotating-kek/rotate');

      const current = (await kek.health()).kekRef;
      expect(current).toBe('vault:transit/keys/rotating-kek#v2');
      expect(Buffer.from(await kek.unwrap(stored.wrapped, AAD, stored.kekRef))).toEqual(dek);

      // The KEK rotation of #545, for one row: unwrap under the stored kekRef,
      // wrap again, and store the new pair, in a restarted signer.
      const restarted = provider(env);
      const opened = await restarted.unwrap(stored.wrapped, AAD, stored.kekRef);
      const rewrapped = await restarted.wrap(opened, AAD);
      opened.fill(0);
      expect(rewrapped.kekRef).toBe(current);

      await admin('POST', 'transit/keys/rotating-kek/config', { min_decryption_version: 2 });

      await expectCode(kek.unwrap(stored.wrapped, AAD, stored.kekRef), 'KEK_UNKNOWN_REF');
      expect(Buffer.from(await kek.unwrap(rewrapped.wrapped, AAD, rewrapped.kekRef))).toEqual(dek);
      await expectCode(
        kek.unwrap(rewrapped.wrapped, AAD, 'vault:transit/keys/rotating-kek#v9'),
        'KEK_UNKNOWN_REF'
      );
    }
  );

  live(
    'renews a token from a file before it expires, so an idle signer keeps it',
    async () => {
      const { token, file } = await signerToken(KEY, { ttl: '6s', maxTtl: '1m' });
      const kek = provider({ KEK_VAULT_TOKEN_FILE: file });
      const { wrapped, kekRef } = await kek.wrap(randomBytes(32), AAD);

      await sleep(10_000);

      await kek.unwrap(wrapped, AAD, kekRef);
      const lookup = await admin('POST', 'auth/token/lookup', { token });
      expect(Number(lookup.data?.['ttl'])).toBeGreaterThan(0);
    },
    30_000
  );

  live(
    'still unwraps and wraps after the AppRole token reaches its maximum TTL',
    async () => {
      const role = await signerRole(KEY, { ttl: '4s', maxTtl: '6s' });
      const kek = provider({
        KEK_VAULT_ROLE_ID: role.roleId,
        KEK_VAULT_SECRET_ID_FILE: role.secretIdFile,
      });
      const { wrapped, kekRef } = await kek.wrap(randomBytes(32), AAD);

      await sleep(9_000);

      await kek.unwrap(wrapped, AAD, kekRef);
      expect((await kek.health()).ok).toBe(true);
    },
    30_000
  );

  live(
    'replaces an expired token at its next use when the agent rewrote the file',
    async () => {
      const first = await signerToken(KEY, { ttl: '2s', maxTtl: '2s' });
      const kek = provider({ KEK_VAULT_TOKEN_FILE: first.file });
      const { wrapped, kekRef } = await kek.wrap(randomBytes(32), AAD);
      await sleep(3_000);

      await expectCode(kek.unwrap(wrapped, AAD, kekRef), 'KEK_ACCESS_DENIED');
      writeFileSync(first.file, `${(await signerToken(KEY)).token}\n`);
      await kek.unwrap(wrapped, AAD, kekRef);
    },
    30_000
  );

  live(
    'fails closed with a revoked token: typed errors, an unhealthy provider and a signer that cannot load its key',
    async () => {
      const { token, file } = await signerToken(KEY);
      const kek = provider({ KEK_VAULT_TOKEN_FILE: file });
      const realmId = randomUUID();
      const key = await generateKeyMaterial('EdDSA', { enabledSignatureAlgorithms: ['EdDSA'] });
      const identity = {
        realmId,
        purpose: 'token_signing',
        scopeId: null,
        kid: key.kid,
        algorithm: 'EdDSA',
      };
      const sealed = await sealKeyMaterial(kek, key.material, identity);
      key.material.fill(0);
      const store: SignerKeyStore = {
        findRealmIssuer: async () => 'https://issuer.example.test',
        listKeys: async (realm, filter) =>
          realm === realmId && filter.purpose === 'token_signing' && filter.scopeId === null
            ? [
                {
                  kid: key.kid,
                  algorithm: 'EdDSA',
                  status: 'active',
                  pairId: null,
                  retireAt: null,
                  createdAt: 0,
                },
              ]
            : [],
        getWrappedKey: async (realm, kid) =>
          realm === realmId && kid === key.kid
            ? { ...identity, ...sealed, status: 'active' }
            : undefined,
        listPublicKeys: async () => [],
        findUpstreamClient: async () => undefined,
      };
      const now = Date.now();
      const sign = (kekProvider: KekProvider) =>
        createInProcessSigner({
          store,
          kekProvider,
          enabledSignatureAlgorithms: ['EdDSA'],
          hybridSigning: false,
        }).signJws('local', {
          realmId,
          purpose: 'token_signing',
          typ: 'at+jwt',
          claims: {
            sub: 'user-1',
            aud: 'client-1',
            iat: Math.floor(now / 1000),
            exp: Math.floor(now / 1000) + 300,
          },
        });
      expect(typeof (await sign(provider({ KEK_VAULT_TOKEN_FILE: file })))).toBe('string');

      await admin('POST', 'auth/token/revoke', { token });

      const errors = [
        await expectCode(kek.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED'),
        await expectCode(sign(provider({ KEK_VAULT_TOKEN_FILE: file })), 'KEK_ACCESS_DENIED'),
      ];
      const health = await kek.health();
      expect(health).toMatchObject({ ok: false, provider: 'vault' });
      expect(health.reason).toMatch(/^KEK_ACCESS_DENIED: .*Vault answered 403/);
      for (const error of errors) {
        expect(`${error.message} ${String(error.cause)} ${JSON.stringify(error)}`).not.toContain(
          token
        );
      }
      expect(JSON.stringify(health)).not.toContain(token);
    }
  );

  live(
    'fails closed when the AppRole secret ID is destroyed, without the secret ID in the error',
    async () => {
      const role = await signerRole(KEY);
      await admin('POST', `auth/approle/role/${role.role}/secret-id/destroy`, {
        secret_id: role.secretId,
      });
      const kek = provider({
        KEK_VAULT_ROLE_ID: role.roleId,
        KEK_VAULT_SECRET_ID_FILE: role.secretIdFile,
      });

      const error = await expectCode(kek.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');
      expect(String(error.cause)).toContain('invalid role or secret ID');
      expect(`${error.message} ${String(error.cause)} ${JSON.stringify(error)}`).not.toContain(
        role.secretId
      );
    }
  );
});
