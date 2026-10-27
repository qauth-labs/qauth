import { randomBytes, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { inspect } from 'node:util';

import { isKeyCustodyError, type KeyCustodyErrorCode } from '@qauth-labs/server-keys';
import {
  createInProcessSigner,
  encodeKeyAad,
  generateKeyMaterial,
  type KekProvider,
  type KekWarning,
  KEY_AAD_VERSION,
  type KeyAad,
  runKekProviderContract,
  sealKeyMaterial,
  type SignerKeyStore,
} from '@qauth-labs/server-keys/custody';
import { createManualClock, type ManualClock } from '@qauth-labs/shared-testing';
import { afterAll, describe, expect, it } from 'vitest';

import {
  appRoleEnv,
  createSecretFiles,
  DOUBLE_KEY,
  doubleProvider,
  tokenFileEnv,
} from '../testing/double-provider';
import { createVaultDouble, signerPolicy, type VaultDouble } from '../testing/vault-double';
import { MAX_KEY_READ_RESPONSE_BYTES } from './https-transport';
import { parseKekRef } from './kek-ref';
import { formatCiphertext } from './transit';
import { KEY_CHECK_MAX_AGE_MS } from './vault-kek-provider';

const files = createSecretFiles();
afterAll(() => files.cleanup());

const AAD: KeyAad = Object.freeze({
  realmId: '7b0e9a52-6f7c-4c55-9e43-2d7f1c0a9b11',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'kid-1',
  algorithm: 'EdDSA',
  version: KEY_AAD_VERSION,
});

const START = Date.parse('2026-10-26T00:00:00Z');

interface Setup {
  readonly double: VaultDouble;
  readonly clock: ManualClock;
  readonly provider: KekProvider;
  readonly token: string;
  readonly tokenPath: string;
  /** What the provider warned about. */
  readonly warnings: KekWarning[];
  /** Another provider over the same Vault and token: a restarted signer. */
  restart(): KekProvider;
}

function setup(
  options: { derived?: boolean; imported?: boolean; env?: Record<string, string> } = {}
): Setup {
  const clock = createManualClock(START);
  const double = createVaultDouble(clock);
  double.createKey(DOUBLE_KEY, {
    derived: options.derived ?? true,
    imported: options.imported ?? false,
  });
  const login = tokenFileEnv(double, files);
  const warnings: KekWarning[] = [];
  const create = () =>
    doubleProvider(double, { env: { ...login.env, ...options.env }, clock, warnings });
  return {
    double,
    clock,
    provider: create(),
    token: login.token,
    tokenPath: login.path,
    warnings,
    restart: create,
  };
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error('expected the call to fail');
    },
    (reason: unknown) => reason
  );
}

async function expectCode(promise: Promise<unknown>, code: KeyCustodyErrorCode): Promise<unknown> {
  const error = await failure(promise);
  expect(isKeyCustodyError(error, code), `expected ${code}, got ${String(error)}`).toBe(true);
  return error;
}

/** Settle `promise`, moving the manual clock so the client's backoff can pass. */
async function settled<T>(promise: Promise<T>, clock: ManualClock): Promise<T> {
  let done = false;
  promise.then(
    () => (done = true),
    () => (done = true)
  );
  for (let step = 0; step < 50 && !done; step++) await clock.advanceBy(250);
  return promise;
}

/** Every string an error and its causes carry, for a leak check. */
function everything(error: unknown): string {
  const parts: string[] = [];
  for (let at: unknown = error, depth = 0; at !== undefined && depth < 10; depth++) {
    if (!(at instanceof Error)) {
      parts.push(String(at));
      break;
    }
    parts.push(at.message, at.stack ?? '', JSON.stringify(at));
    at = at.cause;
  }
  return parts.join('\n');
}

function transitRequests(double: VaultDouble, operation: string) {
  return double.requests.filter((request) => request.path === `transit/${operation}/${DOUBLE_KEY}`);
}

describe('the KEK provider contract over the Vault test double', () => {
  const tokenDouble = createVaultDouble();
  tokenDouble.createKey(DOUBLE_KEY);
  const tokenLogin = tokenFileEnv(tokenDouble, files);
  runKekProviderContract({
    name: 'vault (test double, token file)',
    createProvider: () => doubleProvider(tokenDouble, { env: tokenLogin.env }),
    describe,
    it,
  });

  const appRoleDouble = createVaultDouble();
  appRoleDouble.createKey(DOUBLE_KEY);
  const appRole = appRoleEnv(appRoleDouble, files);
  runKekProviderContract({
    name: 'vault (test double, AppRole)',
    createProvider: () => doubleProvider(appRoleDouble, { env: appRole.env }),
    describe,
    it,
  });
});

describe('wrap', () => {
  it('sends the data key to Transit encrypt, with the associated data as the context', async () => {
    const { double, provider, token } = setup();
    const dek = randomBytes(32);

    await provider.wrap(Buffer.from(dek), AAD);

    const [encrypt] = transitRequests(double, 'encrypt');
    expect(encrypt.method).toBe('POST');
    expect(encrypt.token).toBe(token);
    expect(encrypt.body?.['context']).toBe(encodeKeyAad(AAD).toString('base64'));
    expect(Buffer.from(String(encrypt.body?.['plaintext']), 'base64')).toEqual(dek);
  });

  it('checks the key, encrypts, then decrypts the result, and requires Vault to refuse it under another context', async () => {
    const { double, provider } = setup();

    await provider.wrap(randomBytes(32), AAD);

    expect(double.requests.map((request) => request.path)).toEqual([
      'auth/token/lookup-self',
      `transit/keys/${DOUBLE_KEY}`,
      `transit/encrypt/${DOUBLE_KEY}`,
      `transit/decrypt/${DOUBLE_KEY}`,
      `transit/decrypt/${DOUBLE_KEY}`,
    ]);
    const [opened, otherContext] = transitRequests(double, 'decrypt');
    expect(opened.status).toBe(200);
    expect(otherContext.status).toBe(400);
    expect(otherContext.body?.['context']).not.toBe(opened.body?.['context']);
  });

  it('names the Transit key and the key version in kekRef, and stores the ciphertext bytes alone', async () => {
    const { double, provider } = setup();

    const { wrapped, kekRef } = await provider.wrap(randomBytes(32), AAD);

    expect(kekRef).toBe(`vault:transit/keys/${DOUBLE_KEY}#v1`);
    const answer = transitRequests(double, 'decrypt')[0].body?.['ciphertext'];
    expect(answer).toBe(formatCiphertext(1, wrapped));
    expect(Buffer.from(wrapped).toString('latin1')).not.toContain('vault:');
  });

  it('names the namespace and the mount in kekRef, and sends the namespace on every call', async () => {
    const clock = createManualClock(START);
    const double = createVaultDouble(clock);
    double.createKey(DOUBLE_KEY, { mount: 'secrets/transit' });
    const token = double.createToken({
      ttlMs: 3_600_000,
      policy: signerPolicy(DOUBLE_KEY, 'secrets/transit'),
    });
    const provider = doubleProvider(double, {
      env: {
        KEK_VAULT_TOKEN_FILE: files.write(token),
        KEK_VAULT_TRANSIT_MOUNT: 'secrets/transit',
        KEK_VAULT_NAMESPACE: 'team-a/',
      },
      clock,
    });

    const { kekRef } = await provider.wrap(randomBytes(32), AAD);

    expect(kekRef).toBe(`vault:team-a/secrets/transit/keys/${DOUBLE_KEY}#v1`);
    expect(new Set(double.requests.map((request) => request.namespace))).toEqual(
      new Set(['team-a'])
    );
  });

  it('checks the key once per provider', async () => {
    const { double, provider } = setup();

    await provider.wrap(randomBytes(32), AAD);
    await provider.wrap(randomBytes(32), AAD);
    await provider.wrap(randomBytes(32), { ...AAD, kid: 'kid-2' });

    expect(transitRequests(double, 'keys')).toHaveLength(1);
  });

  it('checks the key again once the check is 15 minutes old, and refuses a key recreated without derivation', async () => {
    const { double, clock, provider } = setup();
    await provider.wrap(randomBytes(32), AAD);

    await clock.advanceBy(14 * 60_000);
    await provider.wrap(randomBytes(32), AAD);
    expect(transitRequests(double, 'keys')).toHaveLength(1);

    double.deleteKey(DOUBLE_KEY);
    double.createKey(DOUBLE_KEY, { derived: false });
    await clock.advanceBy(60_000);
    const error = await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');
    expect(String((error as Error).cause)).toMatch(/is not derived/);
    expect(transitRequests(double, 'keys')).toHaveLength(2);
  });

  it.each([
    ['exportable', { exportable: true }],
    ['allow_plaintext_backup', { allowPlaintextBackup: true }],
  ])('refuses a key that can leave Vault (%s)', async (_what, config) => {
    const { double, provider } = setup();
    double.configureKey(DOUBLE_KEY, config);

    const error = await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');

    expect(String((error as Error).cause)).toMatch(/can leave Vault/);
    expect(transitRequests(double, 'encrypt')).toEqual([]);
  });

  it.each([
    ['exportable', { exportable: true }, /can leave Vault \(exportable\)/],
    [
      'allow_plaintext_backup',
      { allowPlaintextBackup: true },
      /can leave Vault \(allow_plaintext_backup\)/,
    ],
    ['deletion_allowed', { deletionAllowed: true }, /can be deleted \(deletion_allowed\)/],
  ])(
    'refuses wraps but still unwraps, with a warning, once a key is switched to %s',
    async (_what, config, reason) => {
      const { double, clock, provider, warnings } = setup();
      const dek = randomBytes(32);
      const { wrapped, kekRef } = await provider.wrap(Buffer.from(dek), AAD);

      double.configureKey(DOUBLE_KEY, config);
      await clock.advanceBy(KEY_CHECK_MAX_AGE_MS + 1);

      const error = await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');
      expect(String((error as Error).cause)).toMatch(reason);
      expect((await provider.health()).ok).toBe(false);
      expect(warnings).toEqual([]);

      expect(Buffer.from(await provider.unwrap(wrapped, AAD, kekRef))).toEqual(dek);
      expect(Buffer.from(await provider.unwrap(wrapped, AAD, kekRef))).toEqual(dek);
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatchObject({ variable: 'KEK_VAULT_TRANSIT_KEY' });
      expect(warnings[0].message).toMatch(reason);
      expect(warnings[0].message).toMatch(/every wrap is refused/);

      // The warning comes back with the next key check, not with every unwrap.
      await clock.advanceBy(KEY_CHECK_MAX_AGE_MS + 1);
      await provider.unwrap(wrapped, AAD, kekRef);
      expect(warnings).toHaveLength(2);
    }
  );

  it('wraps again once deletion_allowed is switched back off', async () => {
    const { double, provider } = setup();
    double.configureKey(DOUBLE_KEY, { deletionAllowed: true });
    await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');

    double.configureKey(DOUBLE_KEY, { deletionAllowed: false });

    await expect(provider.wrap(randomBytes(32), AAD)).resolves.toMatchObject({
      kekRef: `vault:transit/keys/${DOUBLE_KEY}#v1`,
    });
  });

  it('wraps and unwraps under an imported key, warning once', async () => {
    const { provider, warnings } = setup({ imported: true });

    const { wrapped, kekRef } = await provider.wrap(randomBytes(32), AAD);
    await provider.unwrap(wrapped, AAD, kekRef);
    await provider.wrap(randomBytes(32), AAD);

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({ variable: 'KEK_VAULT_TRANSIT_KEY' });
    expect(warnings[0].message).toMatch(/imported_key=true/);
  });

  it('refuses a wrap the key opens under another context, even inside the key check window', async () => {
    const { double, provider } = setup();
    await provider.wrap(randomBytes(32), AAD);

    // Recreated without derivation since the last check, which still holds.
    double.deleteKey(DOUBLE_KEY);
    double.createKey(DOUBLE_KEY, { derived: false });
    const error = await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');

    expect(String((error as Error).cause)).toMatch(/opened a data key under another context/);
    expect(transitRequests(double, 'keys')).toHaveLength(1);
    expect(transitRequests(double, 'decrypt').map((request) => request.status)).toEqual([
      200, 400, 200, 200,
    ]);
  });

  it('reads the key with a larger answer size cap, for a key with many versions', async () => {
    const { double, provider } = setup();

    await provider.wrap(randomBytes(32), AAD);

    expect(transitRequests(double, 'keys')[0].maxResponseBytes).toBe(MAX_KEY_READ_RESPONSE_BYTES);
    expect(transitRequests(double, 'encrypt')[0].maxResponseBytes).toBeUndefined();
  });

  it('refuses a Transit key that is not derived, before sending any data key', async () => {
    const { double, provider } = setup({ derived: false });

    const error = await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');

    expect(String((error as Error).cause)).toMatch(/is not derived/);
    expect(transitRequests(double, 'encrypt')).toEqual([]);
    await expectCode(
      provider.unwrap(randomBytes(60), AAD, `vault:transit/keys/${DOUBLE_KEY}#v1`),
      'KEK_ACCESS_DENIED'
    );
    expect(transitRequests(double, 'decrypt')).toEqual([]);
  });

  it('would lose the binding to the associated data on a key that is not derived, which is why it is refused', () => {
    const double = createVaultDouble();
    double.createKey('plain', { derived: false });
    const answer = double.transport({
      method: 'POST',
      path: '/v1/transit/encrypt/plain',
      headers: { 'X-Vault-Token': double.rootToken },
      body: JSON.stringify({
        plaintext: randomBytes(32).toString('base64'),
        context: encodeKeyAad(AAD).toString('base64'),
      }),
    });

    return answer.then(({ body }) => {
      const ciphertext = (body as { data: { ciphertext: string } }).data.ciphertext;
      const otherContext = encodeKeyAad({ ...AAD, realmId: randomUUID() }).toString('base64');
      expect(() => double.decrypt('plain', ciphertext, otherContext)).not.toThrow();
    });
  });

  it('refuses a key of another type, or a key that does not exist', async () => {
    const clock = createManualClock(START);
    const double = createVaultDouble(clock);
    double.createKey(DOUBLE_KEY, { type: 'aes128-gcm96' });
    const login = tokenFileEnv(double, files);
    const provider = doubleProvider(double, { env: login.env, clock });
    const missing = doubleProvider(double, {
      env: { ...login.env, KEK_VAULT_TRANSIT_KEY: 'missing-key' },
      clock,
    });

    await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');
    await expectCode(missing.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');
    expect(double.requests.some((request) => request.path.includes('encrypt'))).toBe(false);
  });

  it('refuses to hand back a data key this token may encrypt but not decrypt, so it is never stored', async () => {
    const clock = createManualClock(START);
    const double = createVaultDouble(clock);
    double.createKey(DOUBLE_KEY);
    const encryptOnly = Object.fromEntries(
      Object.entries(signerPolicy(DOUBLE_KEY)).filter(([path]) => !path.includes('/decrypt/'))
    );
    const token = double.createToken({ ttlMs: 3_600_000, policy: encryptOnly });
    const provider = doubleProvider(double, {
      env: { KEK_VAULT_TOKEN_FILE: files.write(token) },
      clock,
    });

    await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');
  });

  it('refuses a data key that is not 32 bytes, and associated data the format refuses, without a call', async () => {
    const { double, provider } = setup();

    await expect(provider.wrap(randomBytes(16), AAD)).rejects.toThrow(RangeError);
    await expect(provider.wrap(randomBytes(32), { ...AAD, kid: '' })).rejects.toThrow(TypeError);
    expect(double.requests).toEqual([]);
  });
});

describe('unwrap', () => {
  it('decrypts under the context of the associated data and gives the caller its own data key', async () => {
    const { double, provider } = setup();
    const dek = randomBytes(32);
    const { wrapped, kekRef } = await provider.wrap(Buffer.from(dek), AAD);
    double.requests.length = 0;

    const opened = await provider.unwrap(wrapped, AAD, kekRef);

    expect(Buffer.from(opened)).toEqual(dek);
    expect(double.requests.map((request) => request.path)).toEqual([
      `transit/decrypt/${DOUBLE_KEY}`,
    ]);
    expect(double.requests[0].body?.['context']).toBe(encodeKeyAad(AAD).toString('base64'));
  });

  it('fails under a wrong context: Vault refuses the ciphertext', async () => {
    const { double, provider } = setup();
    const { wrapped, kekRef } = await provider.wrap(randomBytes(32), AAD);
    const ciphertext = formatCiphertext(1, wrapped);

    expect(() =>
      double.decrypt(
        DOUBLE_KEY,
        ciphertext,
        encodeKeyAad({ ...AAD, realmId: randomUUID() }).toString('base64')
      )
    ).toThrow('cipher: message authentication failed');
    const error = await expectCode(
      provider.unwrap(wrapped, { ...AAD, kid: 'kid-2' }, kekRef),
      'KEY_DECRYPTION_FAILED'
    );
    expect(String((error as Error).cause)).toContain('message authentication failed');
  });

  it('refuses a kekRef that names another key, mount or namespace, or is not a Vault kekRef, without a call', async () => {
    const { double, provider } = setup();
    const { wrapped } = await provider.wrap(randomBytes(32), AAD);
    double.requests.length = 0;

    for (const kekRef of [
      'vault:transit/keys/other-key#v1',
      `vault:other-mount/keys/${DOUBLE_KEY}#v1`,
      `vault:team-a/transit/keys/${DOUBLE_KEY}#v1`,
      `vault:transit/keys/${DOUBLE_KEY}#v0`,
      `vault:transit/keys/${DOUBLE_KEY}`,
      'a1b2c3d4e5f60718',
    ]) {
      await expectCode(provider.unwrap(wrapped, AAD, kekRef), 'KEK_UNKNOWN_REF');
    }
    expect(double.requests).toEqual([]);
  });

  it('refuses a kekRef whose version the key does not have', async () => {
    const { provider } = setup();
    const { wrapped } = await provider.wrap(randomBytes(32), AAD);

    const error = await expectCode(
      provider.unwrap(wrapped, AAD, `vault:transit/keys/${DOUBLE_KEY}#v9`),
      'KEK_UNKNOWN_REF'
    );
    expect((error as { kekRef: string }).kekRef).toBe(`vault:transit/keys/${DOUBLE_KEY}#v9`);
  });

  it('refuses empty or oversized wrapped bytes, and unusable associated data, without a call', async () => {
    const { double, provider } = setup();
    const kekRef = `vault:transit/keys/${DOUBLE_KEY}#v1`;

    await expectCode(provider.unwrap(Buffer.alloc(0), AAD, kekRef), 'KEY_DECRYPTION_FAILED');
    await expectCode(provider.unwrap(randomBytes(1025), AAD, kekRef), 'KEY_DECRYPTION_FAILED');
    await expectCode(
      provider.unwrap(randomBytes(60), { ...AAD, purpose: '' }, kekRef),
      'KEY_DECRYPTION_FAILED'
    );
    expect(double.requests).toEqual([]);
  });

  it('refuses a ciphertext that opens to something other than a data key', async () => {
    const { double, provider } = setup();
    await provider.wrap(randomBytes(32), AAD);
    const { body } = await double.transport({
      method: 'POST',
      path: `/v1/transit/encrypt/${DOUBLE_KEY}`,
      headers: { 'X-Vault-Token': double.rootToken },
      body: JSON.stringify({
        plaintext: randomBytes(16).toString('base64'),
        context: encodeKeyAad(AAD).toString('base64'),
      }),
    });
    const ciphertext = (body as { data: { ciphertext: string } }).data.ciphertext;
    const bytes = Buffer.from(ciphertext.slice('vault:v1:'.length), 'base64');

    await expectCode(
      provider.unwrap(bytes, AAD, `vault:transit/keys/${DOUBLE_KEY}#v1`),
      'KEY_DECRYPTION_FAILED'
    );
  });
});

describe('a Transit key rotation', () => {
  it('wraps under the new version, still opens rows wrapped before, and a re-wrap moves a row to the new version', async () => {
    const { double, provider, restart } = setup();
    const dek = randomBytes(32);
    const before = await provider.wrap(Buffer.from(dek), AAD);
    expect(parseKekRef(before.kekRef)?.version).toBe(1);

    expect(double.rotateKey(DOUBLE_KEY)).toBe(2);

    const after = await provider.wrap(randomBytes(32), { ...AAD, kid: 'kid-2' });
    expect(after.kekRef).toBe(`vault:transit/keys/${DOUBLE_KEY}#v2`);
    expect((await provider.health()).kekRef).toBe(after.kekRef);
    expect(Buffer.from(await provider.unwrap(before.wrapped, AAD, before.kekRef))).toEqual(dek);

    // What a KEK rotation (#545) does with each row whose kekRef is not the
    // current one: unwrap under the old reference, wrap under the current.
    const opened = await provider.unwrap(before.wrapped, AAD, before.kekRef);
    const rewrapped = await restart().wrap(opened, AAD);
    opened.fill(0);
    expect(rewrapped.kekRef).toBe(after.kekRef);

    // Once Vault no longer decrypts version 1, only the re-wrapped row opens.
    double.setMinDecryptionVersion(DOUBLE_KEY, 2);
    await expectCode(provider.unwrap(before.wrapped, AAD, before.kekRef), 'KEK_UNKNOWN_REF');
    expect(Buffer.from(await provider.unwrap(rewrapped.wrapped, AAD, rewrapped.kekRef))).toEqual(
      dek
    );
  });

  it('refuses the old version of a row under the new version kekRef', async () => {
    const { double, provider } = setup();
    const before = await provider.wrap(randomBytes(32), AAD);
    double.rotateKey(DOUBLE_KEY);

    await expectCode(
      provider.unwrap(before.wrapped, AAD, `vault:transit/keys/${DOUBLE_KEY}#v2`),
      'KEY_DECRYPTION_FAILED'
    );
  });
});

describe('Vault failures', () => {
  const cases: ReadonlyArray<
    readonly [string, Parameters<VaultDouble['failNext']>[0], number, KeyCustodyErrorCode, number]
  > = [
    [
      'a sealed Vault (503), on every attempt',
      { status: 503, errors: ['Vault is sealed'] },
      3,
      'KEK_UNAVAILABLE',
      3,
    ],
    [
      'throttling (429), on every attempt',
      { status: 429, errors: ['request path "transit/decrypt": rate limit quota exceeded'] },
      3,
      'KEK_UNAVAILABLE',
      3,
    ],
    [
      'a server fault (500), on every attempt',
      { status: 500, errors: ['internal error'] },
      3,
      'KEK_UNAVAILABLE',
      3,
    ],
    [
      'a refused connection, on every attempt',
      { error: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) },
      3,
      'KEK_UNAVAILABLE',
      3,
    ],
    [
      'a certificate Vault calls do not trust',
      {
        error: Object.assign(new Error('self-signed certificate'), {
          code: 'DEPTH_ZERO_SELF_SIGNED_CERT',
        }),
      },
      1,
      'KEK_ACCESS_DENIED',
      1,
    ],
    ['a redirect to another node', { status: 307, errors: [] }, 1, 'KEK_UNAVAILABLE', 1],
    [
      'a malformed ciphertext (400)',
      { status: 400, errors: ['invalid ciphertext length'] },
      1,
      'KEY_DECRYPTION_FAILED',
      1,
    ],
    [
      'a key that was deleted',
      { status: 400, errors: ['encryption key not found'] },
      1,
      'KEK_ACCESS_DENIED',
      1,
    ],
    [
      'a version below min_decryption_version',
      {
        status: 400,
        errors: ['ciphertext or signature version is disallowed by policy (too old)'],
      },
      1,
      'KEK_UNKNOWN_REF',
      1,
    ],
  ];

  it.each(cases)('maps %s on unwrap', async (_what, fault, times, code, attempts) => {
    const { double, clock, provider } = setup();
    const { wrapped, kekRef } = await provider.wrap(randomBytes(32), AAD);
    double.requests.length = 0;
    double.failNext(fault, { times, path: /decrypt/ });

    await expectCode(settled(provider.unwrap(wrapped, AAD, kekRef), clock), code);

    expect(transitRequests(double, 'decrypt')).toHaveLength(attempts);
  });

  it('retries throttling and server faults, and succeeds when Vault answers in time', async () => {
    const { double, clock, provider } = setup();
    const dek = randomBytes(32);
    const { wrapped, kekRef } = await provider.wrap(Buffer.from(dek), AAD);
    double.requests.length = 0;
    double.failNext({ status: 429 }, { path: /decrypt/ });
    double.failNext({ status: 503 }, { path: /decrypt/ });

    expect(Buffer.from(await settled(provider.unwrap(wrapped, AAD, kekRef), clock))).toEqual(dek);
    expect(transitRequests(double, 'decrypt').map((request) => request.status)).toEqual([
      429, 503, 200,
    ]);
  });

  it('marks an outage as retryable', async () => {
    const { double, clock, provider } = setup();
    double.failNext({ status: 503 }, { times: 3 });

    const error = await expectCode(
      settled(provider.wrap(randomBytes(32), AAD), clock),
      'KEK_UNAVAILABLE'
    );

    expect((error as { retryable?: boolean }).retryable).toBe(true);
  });

  it('reads an answer without the fields Vault sends as an outage', async () => {
    const { double, provider } = setup();
    double.failNext({ status: 200 }, { path: /encrypt/ });

    const error = await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_UNAVAILABLE');

    expect(String((error as Error).cause)).toContain("Vault's answer to encrypt has no data");
  });
});

describe('a refused token', () => {
  it('keeps the token where inspecting or serialising the provider does not show it', async () => {
    const { provider, token } = setup();
    await provider.wrap(randomBytes(32), AAD);

    expect(inspect(provider, { depth: 10, showHidden: true })).not.toContain(token);
    expect(JSON.stringify(provider)).not.toContain(token);
  });

  it('logs in again once and repeats the call, for an AppRole token Vault revoked', async () => {
    const clock = createManualClock(START);
    const double = createVaultDouble(clock);
    double.createKey(DOUBLE_KEY);
    const provider = doubleProvider(double, { env: appRoleEnv(double, files).env, clock });
    const dek = randomBytes(32);
    const { wrapped, kekRef } = await provider.wrap(Buffer.from(dek), AAD);
    const first = transitRequests(double, 'encrypt')[0].token as string;

    double.revokeToken(first);

    expect(Buffer.from(await provider.unwrap(wrapped, AAD, kekRef))).toEqual(dek);
    const logins = double.requests.filter((request) => request.path === 'auth/approle/login');
    expect(logins).toHaveLength(2);
    expect(transitRequests(double, 'decrypt').at(-1)?.token).not.toBe(first);
  });

  it('keeps a token its policy refused, so a denied path never mints new AppRole tokens', async () => {
    const clock = createManualClock(START);
    const double = createVaultDouble(clock);
    double.createKey(DOUBLE_KEY);
    const { roleId, secretId } = double.createAppRole({
      tokenTtlMs: 3_600_000,
      tokenMaxTtlMs: 86_400_000,
      policy: {
        [`transit/keys/${DOUBLE_KEY}`]: ['read'],
        [`transit/encrypt/${DOUBLE_KEY}`]: ['update'],
      },
    });
    const provider = doubleProvider(double, {
      env: { KEK_VAULT_ROLE_ID: roleId, KEK_VAULT_SECRET_ID_FILE: files.write(secretId) },
      clock,
    });

    for (let call = 0; call < 5; call++) {
      await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');
    }

    expect(double.requests.filter((request) => request.path === 'auth/approle/login')).toHaveLength(
      1
    );
    expect(transitRequests(double, 'decrypt')).toHaveLength(5);
  });

  it('refuses a token file rewritten with a value that cannot be a token, as an operator fault', async () => {
    const { double, provider, token, tokenPath } = setup();
    await provider.wrap(randomBytes(32), AAD);
    double.revokeToken(token);
    writeFileSync(tokenPath, Buffer.from('hvs.\u0000broken', 'utf16le'));

    const error = await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');

    expect(String((error as Error).cause)).toMatch(/printable ASCII/);
  });

  it('fails closed with KEK_ACCESS_DENIED for a revoked token in a token file, on wrap, unwrap and health', async () => {
    const { double, provider, token } = setup();
    const { wrapped, kekRef } = await provider.wrap(randomBytes(32), AAD);

    double.revokeToken(token);

    const errors = [
      await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED'),
      await expectCode(provider.unwrap(wrapped, AAD, kekRef), 'KEK_ACCESS_DENIED'),
    ];
    const health = await provider.health();
    expect(health).toMatchObject({ ok: false, provider: 'vault' });
    expect(health.reason).toMatch(/^KEK_ACCESS_DENIED: .*Vault answered 403/);
    for (const text of [...errors.map(everything), JSON.stringify(health)]) {
      expect(text).not.toContain(token);
    }
  });

  it('fails closed with KEK_ACCESS_DENIED when the AppRole secret ID is revoked, without the secret ID in the error', async () => {
    const clock = createManualClock(START);
    const double = createVaultDouble(clock);
    double.createKey(DOUBLE_KEY);
    const appRole = appRoleEnv(double, files);
    double.revokeSecretId(appRole.roleId, appRole.secretId);
    const provider = doubleProvider(double, { env: appRole.env, clock });

    const error = await expectCode(provider.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');

    expect(everything(error)).toContain('invalid role or secret ID');
    expect(everything(error)).not.toContain(appRole.secretId);
  });

  it('stops a key load in the signer: a restarted signer cannot open its keys with a revoked token', async () => {
    const { double, provider, token, restart } = setup();
    const realmId = randomUUID();
    const key = await generateKeyMaterial('EdDSA', { enabledSignatureAlgorithms: ['EdDSA'] });
    const identity = {
      realmId,
      purpose: 'token_signing',
      scopeId: null,
      kid: key.kid,
      algorithm: 'EdDSA',
    };
    const sealed = await sealKeyMaterial(provider, key.material, identity);
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
                createdAt: START,
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
    const sign = (kekProvider: KekProvider) =>
      createInProcessSigner({
        store,
        kekProvider,
        enabledSignatureAlgorithms: ['EdDSA'],
        hybridSigning: false,
        now: () => START,
      }).signJws('local', {
        realmId,
        purpose: 'token_signing',
        typ: 'at+jwt',
        claims: { sub: 'user-1', aud: 'client-1', iat: START / 1000, exp: START / 1000 + 300 },
      });

    expect(typeof (await sign(provider))).toBe('string');

    double.revokeToken(token);

    await expectCode(sign(restart()), 'KEK_ACCESS_DENIED');
  });
});
