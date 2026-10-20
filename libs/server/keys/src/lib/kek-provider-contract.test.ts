import { randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import * as entryPoint from '../index';
import { KEK_A, KEK_B, localProvider } from '../testing/keks';
import { KEY_AAD_VERSION, type KeyAad } from './aad';
import type { KekProvider } from './kek-provider';
import {
  KEK_PROVIDER_CONTRACT_CASES,
  type KekProviderContractCase,
  runKekProviderContract,
} from './kek-provider-contract';

const dir = mkdtempSync(join(tmpdir(), 'qauth-kek-contract-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
const kekPath = join(dir, 'kek');
writeFileSync(kekPath, KEK_A);
chmodSync(kekPath, 0o600);

// The default provider passes the contract, with its KEK in a variable, in a
// file, and during a KEK rotation.
runKekProviderContract({
  name: 'local, KEK',
  createProvider: () => localProvider({ KEK: KEK_A }),
  describe,
  it,
});
runKekProviderContract({
  name: 'local, KEK_PATH',
  createProvider: () => localProvider({ KEK_PATH: kekPath }),
  describe,
  it,
});
runKekProviderContract({
  name: 'local, KEK with KEK_PREVIOUS',
  createProvider: () => localProvider({ KEK: KEK_B, KEK_PREVIOUS: KEK_A }),
  describe,
  it,
});

describe('the contract kit', () => {
  it('is exported from the package entry point for adapters', () => {
    expect(entryPoint.runKekProviderContract).toBe(runKekProviderContract);
  });

  it('registers one suite with one test per case', () => {
    const suites: string[] = [];
    const tests: string[] = [];

    runKekProviderContract({
      name: 'double',
      createProvider: () => localProvider({ KEK: KEK_A }),
      describe: (name, body) => {
        suites.push(name);
        body();
      },
      it: (name) => tests.push(name),
    });

    expect(suites).toEqual(['KEK provider contract: double']);
    expect(tests).toEqual(KEK_PROVIDER_CONTRACT_CASES.map((check) => check.name));
  });
});

/**
 * Each broken provider below breaks one rule. The kit must catch it, or an
 * adapter with the same flaw would pass.
 */
describe('the contract kit fails a provider that', () => {
  function caseNamed(start: string): KekProviderContractCase {
    const found = KEK_PROVIDER_CONTRACT_CASES.find((check) => check.name.startsWith(start));
    if (found === undefined) throw new Error(`no contract case starts with "${start}"`);
    return found;
  }

  const sound = (): KekProvider => localProvider({ KEK: KEK_A });

  /** The associated data the broken providers wrap under instead of the caller's. */
  const FIXED: KeyAad = {
    realmId: 'fixed',
    purpose: 'fixed',
    scopeId: null,
    kid: 'fixed',
    algorithm: 'fixed',
    version: KEY_AAD_VERSION,
  };

  it('ignores the associated data', async () => {
    const ignoresAad = (): KekProvider => {
      const inner = sound();
      return {
        ...inner,
        wrap: (dek) => inner.wrap(dek, FIXED),
        unwrap: (wrapped, _aad, kekRef) => inner.unwrap(wrapped, FIXED, kekRef),
      };
    };

    await expect(caseNamed('refuses associated data').run(ignoresAad)).rejects.toThrow(
      /another realmId: expected a KEY_DECRYPTION_FAILED error, but the call succeeded/
    );
  });

  it('tries its current KEK for a kekRef it does not hold', async () => {
    const fallsBack = (): KekProvider => {
      const inner = sound();
      return {
        ...inner,
        unwrap: async (wrapped, aad) =>
          inner.unwrap(wrapped, aad, (await inner.health()).kekRef ?? ''),
      };
    };

    await expect(caseNamed('refuses a kekRef').run(fallsBack)).rejects.toThrow(
      /expected a KEK_UNKNOWN_REF error/
    );
  });

  it('stores the data key in the clear', async () => {
    const plain = (): KekProvider => ({
      ...sound(),
      wrap: async (dek) => ({ wrapped: Buffer.from(dek), kekRef: 'plain' }),
    });

    await expect(caseNamed('does not return the data key').run(plain)).rejects.toThrow(
      /contain the data key/
    );
  });

  it('reports tampering with an error of its own instead of a key-custody error', async () => {
    const untyped = (): KekProvider => {
      const inner = sound();
      return {
        ...inner,
        unwrap: (wrapped, aad, kekRef) =>
          inner.unwrap(wrapped, aad, kekRef).catch(() => {
            throw new Error('decrypt failed');
          }),
      };
    };

    await expect(caseNamed('refuses tampered').run(untyped)).rejects.toThrow(
      /expected a KEY_DECRYPTION_FAILED error, got Error/
    );
  });

  it('loses its KEK on restart', async () => {
    const forgetful = () => localProvider({ KEK: randomBytes(32).toString('base64') });

    await expect(caseNamed('opens with a second instance').run(forgetful)).rejects.toThrow();
  });

  it('reports itself unhealthy', async () => {
    const unhealthy = (): KekProvider => ({
      ...sound(),
      health: async () => ({ ok: false, provider: 'local', reason: 'down' }),
    });

    await expect(caseNamed('reports itself healthy').run(unhealthy)).rejects.toThrow(
      /health is ok/
    );
  });
});
