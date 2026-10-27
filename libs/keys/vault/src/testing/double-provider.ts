import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { KekProvider, KekWarning } from '@qauth-labs/server-keys/custody';

import type { VaultClock } from '../lib/vault-client';
import { createKekProviderWith } from '../lib/vault-kek-provider';
import { signerPolicy, type VaultDouble } from './vault-double';

/**
 * TEST SUPPORT: the provider as `KEK_PROVIDER=vault` builds it from its
 * settings, over a {@link VaultDouble} instead of HTTPS (#578).
 */

/** The address the settings name; the double answers in its place. */
export const DOUBLE_ADDR = 'https://vault.test:8200';
/** The Transit key the tests use. */
export const DOUBLE_KEY = 'qauth-kek';

/** Files holding tokens and secret IDs, in a directory removed by {@link SecretFiles.cleanup}. */
export interface SecretFiles {
  /** Write `value` to a new file readable only by its owner, and return its path. */
  write(value: string, mode?: number): string;
  /** Replace a file's content, as a Vault Agent sink does. */
  rewrite(path: string, value: string): void;
  cleanup(): void;
}

export function createSecretFiles(): SecretFiles {
  const dir = mkdtempSync(join(tmpdir(), 'qauth-vault-test-'));
  let next = 0;
  return {
    write(value, mode = 0o600) {
      const path = join(dir, `secret-${next++}`);
      writeFileSync(path, `${value}\n`, { mode });
      return path;
    },
    rewrite(path, value) {
      writeFileSync(path, `${value}\n`);
    },
    cleanup() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** What {@link doubleProvider} takes. */
export interface DoubleProviderOptions {
  /** Settings beside `KEK_VAULT_ADDR` and `KEK_VAULT_TRANSIT_KEY`. */
  readonly env: Readonly<Record<string, string>>;
  readonly clock?: VaultClock;
  readonly warnings?: KekWarning[];
}

/** The provider over `double`, created from settings as the entry point does. */
export function doubleProvider(double: VaultDouble, options: DoubleProviderOptions): KekProvider {
  return createKekProviderWith(
    {
      env: { KEK_VAULT_ADDR: DOUBLE_ADDR, KEK_VAULT_TRANSIT_KEY: DOUBLE_KEY, ...options.env },
      warn: (warning) => options.warnings?.push(warning),
    },
    {
      transport: double.transport,
      ...(options.clock !== undefined ? { clock: options.clock } : {}),
    }
  );
}

/** A long-lived, renewable signer token in a file: the settings that log in with it. */
export function tokenFileEnv(
  double: VaultDouble,
  files: SecretFiles,
  options: { ttlMs?: number; maxTtlMs?: number } = {}
): { readonly env: Record<string, string>; readonly token: string; readonly path: string } {
  const token = double.createToken({
    ttlMs: options.ttlMs ?? 3_600_000,
    maxTtlMs: options.maxTtlMs ?? 86_400_000,
    policy: signerPolicy(DOUBLE_KEY),
  });
  const path = files.write(token);
  return { env: { KEK_VAULT_TOKEN_FILE: path }, token, path };
}

/** An AppRole role for the signer: the settings that log in with it. */
export function appRoleEnv(
  double: VaultDouble,
  files: SecretFiles,
  options: { tokenTtlMs?: number; tokenMaxTtlMs?: number } = {}
): { readonly env: Record<string, string>; readonly roleId: string; readonly secretId: string } {
  const { roleId, secretId } = double.createAppRole({
    tokenTtlMs: options.tokenTtlMs ?? 3_600_000,
    tokenMaxTtlMs: options.tokenMaxTtlMs ?? 86_400_000,
    policy: signerPolicy(DOUBLE_KEY),
  });
  return {
    env: { KEK_VAULT_ROLE_ID: roleId, KEK_VAULT_SECRET_ID_FILE: files.write(secretId) },
    roleId,
    secretId,
  };
}
