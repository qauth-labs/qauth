import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { GenericContainer, type StartedTestContainer, Wait } from 'testcontainers';

import { createHttpsTransport } from '../lib/https-transport';
import { createVaultClient } from '../lib/vault-client';

/**
 * TEST SUPPORT: a throwaway Vault dev server in a container (#578).
 *
 * The dev server keeps everything in memory, unseals itself and has a known
 * root token. It runs with `-dev-tls`, so the provider talks to it over HTTPS
 * as in production: the server makes its own CA, which the test reads out of
 * the container and trusts through `KEK_VAULT_CA_CERT_FILE`. Its certificate
 * names `localhost` and 127.0.0.1.
 */

/** Pinned: a Vault release more than two weeks old when the suite was written (2026-10-26). */
export const VAULT_IMAGE = 'hashicorp/vault:2.1.2';

const TLS_DIR = '/tmp/qauth-vault-tls';

/** A running Vault dev server. */
export interface StartedVault {
  /** `https://localhost:<port>`. */
  readonly address: string;
  /** A file holding the dev server's CA certificate. */
  readonly caFile: string;
  /** The root token, for setting Vault up. Never given to the provider under test. */
  readonly rootToken: string;
  /**
   * Call the Vault API as root. Resolves with the answer's body; a status other
   * than 200 or 204 rejects with a `VaultHttpError`.
   */
  admin(method: 'GET' | 'POST', path: string, body?: Record<string, unknown>): Promise<unknown>;
  /** Call the Vault API with `token`. */
  call(
    token: string,
    method: 'GET' | 'POST',
    path: string,
    body?: Record<string, unknown>
  ): Promise<unknown>;
  stop(): Promise<void>;
}

/** Start a Vault dev server, writing its CA certificate into `dir`. */
export async function startVaultContainer(dir: string): Promise<StartedVault> {
  const rootToken = `root-${randomUUID()}`;
  const container: StartedTestContainer = await new GenericContainer(VAULT_IMAGE)
    .withEnvironment({ VAULT_DEV_ROOT_TOKEN_ID: rootToken })
    .withAddedCapabilities('IPC_LOCK')
    .withEntrypoint(['sh', '-c'])
    .withCommand([
      `mkdir -p ${TLS_DIR} && exec vault server -dev -dev-tls -dev-tls-cert-dir=${TLS_DIR} -dev-listen-address=0.0.0.0:8200`,
    ])
    .withExposedPorts(8200)
    .withWaitStrategy(Wait.forLogMessage(/Development mode should NOT be used in production/))
    .withStartupTimeout(120_000)
    .start();

  const ca = await container.exec(['cat', `${TLS_DIR}/vault-ca.pem`]);
  if (ca.exitCode !== 0) throw new Error('The Vault dev server wrote no CA certificate');
  const caFile = join(dir, 'vault-ca.pem');
  writeFileSync(caFile, ca.output);

  const address = `https://localhost:${container.getMappedPort(8200)}`;
  const client = createVaultClient({
    transport: createHttpsTransport({ origin: address, ca: readFileSync(caFile, 'utf8') }),
  });
  const call: StartedVault['call'] = async (token, method, path, body) =>
    (
      await client.send('read-key', {
        method,
        path,
        token,
        ...(body !== undefined ? { body } : {}),
      })
    ).body;

  // The listener can log readiness a moment before it answers.
  for (let attempt = 0; ; attempt++) {
    try {
      await call(rootToken, 'GET', 'sys/health');
      break;
    } catch (error) {
      if (attempt >= 20) throw error;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }

  return {
    address,
    caFile,
    rootToken,
    admin: (method, path, body) => call(rootToken, method, path, body),
    call,
    async stop() {
      await container.stop();
    },
  };
}
