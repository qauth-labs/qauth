import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { KEY_AAD_VERSION, type KeyAad, type KeyIdentity } from './aad';
import { openKeyMaterial, sealKeyMaterial } from './envelope';
import { isKeyCustodyError, type KeyCustodyErrorCode } from './errors';
import type { KekProvider } from './kek-provider';
import { KEK_PROVIDER_NAME } from './load-kek-provider';

/**
 * The contract every KEK provider meets (ADR-019 Decision 9).
 *
 * The default provider runs it in this library, and each adapter package runs
 * it against its backend or a test double of it. The kit takes the test
 * runner's `describe` and `it` and asserts with `node:assert`, so the library
 * ships no test framework.
 *
 * ```ts
 * import { describe, it } from 'vitest';
 * import { runKekProviderContract } from '@qauth-labs/server-keys';
 *
 * runKekProviderContract({ name: 'cloud-kms', createProvider, describe, it });
 * ```
 *
 * Errors are checked by `code`, never by class, so an adapter that holds its
 * own copy of this library passes.
 */

/** What {@link runKekProviderContract} needs. */
export interface KekProviderContractOptions {
  /** Names the suite, such as `local`. */
  readonly name: string;
  /**
   * Returns a provider to test. The kit calls it once or twice per case. Every
   * call must give a provider over the same KEK, as a restarted signer has.
   */
  readonly createProvider: () => KekProvider | Promise<KekProvider>;
  /** The test runner's `describe`. */
  readonly describe: (name: string, body: () => void) => void;
  /** The test runner's `it`. */
  readonly it: (name: string, test: () => Promise<void>) => void;
}

/** One check of the contract. */
export interface KekProviderContractCase {
  readonly name: string;
  readonly run: (createProvider: KekProviderContractOptions['createProvider']) => Promise<void>;
}

/** The key the cases wrap for. */
const IDENTITY: KeyIdentity = Object.freeze({
  realmId: 'contract-realm-a',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'contract-kid-1',
  algorithm: 'EdDSA',
});

/** The associated data the cases wrap under. */
const AAD: KeyAad = Object.freeze({ ...IDENTITY, version: KEY_AAD_VERSION });

/** A `kekRef` no provider holds. */
const UNKNOWN_KEK_REF = 'contract-unknown-kek-ref';

function describeError(error: unknown): string {
  if (error instanceof Error) {
    const code = (error as { code?: unknown }).code;
    return code === undefined ? error.name : `${error.name} (${String(code)})`;
  }
  return typeof error;
}

async function rejectsWith(
  promise: Promise<unknown>,
  code: KeyCustodyErrorCode,
  what: string
): Promise<void> {
  await assert.rejects(
    promise,
    (error: unknown) => {
      assert.ok(
        isKeyCustodyError(error, code),
        `${what}: expected a ${code} error, got ${describeError(error)}`
      );
      return true;
    },
    `${what}: expected a ${code} error, but the call succeeded`
  );
}

async function wrapped(provider: KekProvider, aad: KeyAad = AAD) {
  const dek = randomBytes(32);
  const result = await provider.wrap(Buffer.from(dek), aad);
  return { dek, ...result };
}

/** Flip one bit of a copy of `bytes` at `index`. */
function flipped(bytes: Uint8Array, index: number): Buffer {
  const copy = Buffer.from(bytes);
  copy[index] ^= 0x01;
  return copy;
}

/** The checks, in the order the suite lists them. */
export const KEK_PROVIDER_CONTRACT_CASES: readonly KekProviderContractCase[] = [
  {
    name: 'unwraps what it wrapped to the same bytes, under a kekRef it names',
    async run(createProvider) {
      const provider = await createProvider();
      const dek = randomBytes(32);
      const given = Buffer.from(dek);

      const { wrapped: bytes, kekRef } = await provider.wrap(given, AAD);

      assert.equal(typeof kekRef, 'string', 'kekRef is a string');
      assert.ok(kekRef.length > 0, 'kekRef is not empty');
      assert.ok(bytes.length > 0, 'the wrapped data key is not empty');
      assert.deepEqual(given, dek, 'wrap leaves the data key it is given as it was');
      assert.deepEqual(Buffer.from(await provider.unwrap(bytes, AAD, kekRef)), dek);
    },
  },
  {
    name: 'opens with a second instance what the first one wrapped',
    async run(createProvider) {
      const { dek, wrapped: bytes, kekRef } = await wrapped(await createProvider());
      const restarted = await createProvider();

      assert.deepEqual(Buffer.from(await restarted.unwrap(bytes, AAD, kekRef)), dek);
    },
  },
  {
    name: 'does not return the data key in the wrapped bytes',
    async run(createProvider) {
      const { dek, wrapped: bytes } = await wrapped(await createProvider());

      assert.ok(!Buffer.from(bytes).includes(dek), 'the wrapped bytes contain the data key');
    },
  },
  {
    name: 'refuses associated data that differs in any field',
    async run(createProvider) {
      const provider = await createProvider();
      const unscoped = await wrapped(provider, AAD);
      const scopedAad: KeyAad = { ...AAD, scopeId: 'contract-scope-1' };
      const scoped = await wrapped(provider, scopedAad);

      const variants: ReadonlyArray<readonly [string, typeof unscoped, KeyAad]> = [
        ['another realmId', unscoped, { ...AAD, realmId: 'contract-realm-b' }],
        ['another purpose', unscoped, { ...AAD, purpose: 'event_signing' }],
        ['a scopeId where none was', unscoped, scopedAad],
        ['no scopeId where one was', scoped, AAD],
        ['another scopeId', scoped, { ...scopedAad, scopeId: 'contract-scope-2' }],
        ['another kid', unscoped, { ...AAD, kid: 'contract-kid-2' }],
        ['another algorithm', unscoped, { ...AAD, algorithm: 'ML-DSA-65' }],
      ];
      for (const [what, sealed, aad] of variants) {
        await rejectsWith(
          provider.unwrap(sealed.wrapped, aad, sealed.kekRef),
          'KEY_DECRYPTION_FAILED',
          `unwrap under ${what}`
        );
      }
    },
  },
  {
    name: 'refuses tampered, truncated or extended wrapped bytes',
    async run(createProvider) {
      const provider = await createProvider();
      const { wrapped: bytes, kekRef } = await wrapped(provider);
      const last = bytes.length - 1;

      const variants: ReadonlyArray<readonly [string, Uint8Array]> = [
        ['the first byte flipped', flipped(bytes, 0)],
        ['a middle byte flipped', flipped(bytes, Math.floor(bytes.length / 2))],
        ['the last byte flipped', flipped(bytes, last)],
        ['the last byte cut off', Buffer.from(bytes).subarray(0, last)],
        ['a byte added', Buffer.concat([Buffer.from(bytes), Buffer.from([0])])],
      ];
      for (const [what, tampered] of variants) {
        await rejectsWith(
          provider.unwrap(tampered, AAD, kekRef),
          'KEY_DECRYPTION_FAILED',
          `unwrap with ${what}`
        );
      }
    },
  },
  {
    name: 'refuses a kekRef it holds no KEK for, without trying another KEK',
    async run(createProvider) {
      const provider = await createProvider();
      const { wrapped: bytes } = await wrapped(provider);

      await rejectsWith(
        provider.unwrap(bytes, AAD, UNKNOWN_KEK_REF),
        'KEK_UNKNOWN_REF',
        'unwrap under an unknown kekRef'
      );
    },
  },
  {
    name: 'reports itself healthy under its own name and the kekRef it wraps under',
    async run(createProvider) {
      const provider = await createProvider();
      const { kekRef } = await wrapped(provider);
      const health = await provider.health();

      assert.ok(KEK_PROVIDER_NAME.test(provider.name), 'name is a valid KEK_PROVIDER value');
      assert.equal(health.ok, true, 'health is ok');
      assert.equal(health.provider, provider.name, 'health names the provider');
      if (health.kekRef !== undefined) {
        assert.equal(health.kekRef, kekRef, 'health names the kekRef wrap returns');
      }
    },
  },
  {
    name: 'seals key material that opens only under the same identity',
    async run(createProvider) {
      const provider = await createProvider();
      const material = randomBytes(48);

      const sealed = await sealKeyMaterial(provider, material, IDENTITY);

      assert.deepEqual(await openKeyMaterial(provider, sealed, IDENTITY), material);
      await rejectsWith(
        openKeyMaterial(provider, sealed, { ...IDENTITY, realmId: 'contract-realm-b' }),
        'KEY_DECRYPTION_FAILED',
        "open under another realm's identity"
      );
    },
  },
];

/**
 * Register the KEK provider contract as a suite of the test runner.
 *
 * Every adapter package calls it in a test file, against its backend or a
 * test double of it. See {@link KekProviderContractOptions}.
 */
export function runKekProviderContract(options: KekProviderContractOptions): void {
  options.describe(`KEK provider contract: ${options.name}`, () => {
    for (const check of KEK_PROVIDER_CONTRACT_CASES) {
      options.it(check.name, () => check.run(options.createProvider));
    }
  });
}
