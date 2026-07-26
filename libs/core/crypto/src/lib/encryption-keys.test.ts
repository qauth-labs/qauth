/**
 * Per-Authorization-Request ephemeral `ECDH-ES` P-256 key material (#298,
 * HAIP §5: "ephemeral encryption public keys specific to each Authorization
 * Request").
 */
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  EPHEMERAL_ENCRYPTION_KEY_MAX_AGE_SECONDS,
  exportEncryptionPrivateJwk,
  exportEncryptionPublicJwk,
  generateEphemeralEncryptionKeyPair,
  importEncryptionPrivateJwk,
  importEncryptionPublicJwk,
  isEphemeralEncryptionKeyPairExpired,
} from './encryption-keys';
import { decryptJwe, encryptJwe } from './jwe';

const PINS = {
  keyManagementAlgorithms: ['ECDH-ES'],
  contentEncryptionAlgorithms: ['A128GCM', 'A256GCM'],
} as const;

describe('generateEphemeralEncryptionKeyPair', () => {
  it('generates an ECDH P-256 pair usable only for key agreement', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();

    expect(pair.privateKey.algorithm).toMatchObject({ name: 'ECDH', namedCurve: 'P-256' });
    expect(pair.privateKey.usages).toEqual(['deriveBits']);
    expect(pair.privateKey.usages).not.toContain('sign');
  });

  it('is per-request: two calls yield distinct keys and distinct kids', async () => {
    const first = await generateEphemeralEncryptionKeyPair();
    const second = await generateEphemeralEncryptionKeyPair();

    expect(first.kid).not.toBe(second.kid);
    const [a, b] = await Promise.all([
      exportEncryptionPublicJwk(first),
      exportEncryptionPublicJwk(second),
    ]);
    expect(a.x).not.toBe(b.x);
  });

  it('cannot decrypt a response encrypted to another request key', async () => {
    const requestA = await generateEphemeralEncryptionKeyPair();
    const requestB = await generateEphemeralEncryptionKeyPair();
    const jwe = await encryptJwe({ vp_token: 'x' }, requestA.publicKey, { enc: 'A256GCM' });

    await expect(decryptJwe(jwe, requestB.privateKey, PINS)).rejects.toThrow(
      /JWE decryption failed/
    );
  });

  it('generates a non-extractable private key by default', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();

    expect(pair.privateKey.extractable).toBe(false);
    await expect(exportEncryptionPrivateJwk(pair)).rejects.toThrow(/not extractable/);
  });

  it('accepts a caller-supplied kid and rejects an empty one', async () => {
    const pair = await generateEphemeralEncryptionKeyPair({ kid: 'req-01HZ' });
    expect(pair.kid).toBe('req-01HZ');

    await expect(generateEphemeralEncryptionKeyPair({ kid: '' })).rejects.toThrow(
      /must not be empty/
    );
  });

  it('stamps createdAt, defaulting to now', async () => {
    const before = Date.now();
    const pair = await generateEphemeralEncryptionKeyPair();
    expect(pair.createdAt).toBeGreaterThanOrEqual(before);
    expect(pair.createdAt).toBeLessThanOrEqual(Date.now());

    const fixed = await generateEphemeralEncryptionKeyPair({ createdAt: 1_700_000_000_000 });
    expect(fixed.createdAt).toBe(1_700_000_000_000);
  });
});

describe('isEphemeralEncryptionKeyPairExpired', () => {
  const createdAt = 1_700_000_000_000;

  it('is not expired inside the default window', () => {
    expect(
      isEphemeralEncryptionKeyPairExpired(
        { createdAt },
        { now: createdAt + (EPHEMERAL_ENCRYPTION_KEY_MAX_AGE_SECONDS - 1) * 1000 }
      )
    ).toBe(false);
  });

  it('is expired exactly at the boundary (the window is half-open)', () => {
    expect(
      isEphemeralEncryptionKeyPairExpired(
        { createdAt },
        { now: createdAt + EPHEMERAL_ENCRYPTION_KEY_MAX_AGE_SECONDS * 1000 }
      )
    ).toBe(true);
  });

  it('honours a caller-supplied maxAgeSeconds', () => {
    expect(
      isEphemeralEncryptionKeyPairExpired(
        { createdAt },
        { maxAgeSeconds: 60, now: createdAt + 59_000 }
      )
    ).toBe(false);
    expect(
      isEphemeralEncryptionKeyPairExpired(
        { createdAt },
        { maxAgeSeconds: 60, now: createdAt + 60_000 }
      )
    ).toBe(true);
  });

  it('fails closed for a non-positive max age', () => {
    expect(
      isEphemeralEncryptionKeyPairExpired({ createdAt }, { maxAgeSeconds: 0, now: createdAt })
    ).toBe(true);
    expect(
      isEphemeralEncryptionKeyPairExpired({ createdAt }, { maxAgeSeconds: -1, now: createdAt })
    ).toBe(true);
  });

  it('fails closed for a createdAt in the future (skew or a tampered record)', () => {
    expect(isEphemeralEncryptionKeyPairExpired({ createdAt }, { now: createdAt - 1 })).toBe(true);
  });
});

describe('exportEncryptionPublicJwk', () => {
  it('publishes a fully-specified, private-material-free JWK', async () => {
    const pair = await generateEphemeralEncryptionKeyPair({ kid: 'req-1' });

    const jwk = await exportEncryptionPublicJwk(pair);

    expect(jwk).toMatchObject({
      kty: 'EC',
      crv: 'P-256',
      alg: 'ECDH-ES',
      use: 'enc',
      kid: 'req-1',
    });
    expect(jwk.x).toBeTypeOf('string');
    expect(jwk.y).toBeTypeOf('string');
    expect(jwk.d).toBeUndefined();
  });

  it('refuses a private key', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();

    await expect(
      exportEncryptionPublicJwk({ kid: pair.kid, publicKey: pair.privateKey })
    ).rejects.toThrow(/requires a public key/);
  });

  it('is what a wallet encrypts to end-to-end', async () => {
    const pair = await generateEphemeralEncryptionKeyPair({ kid: 'req-2' });
    const published = await exportEncryptionPublicJwk(pair);

    // Wallet side: import the published metadata key, encrypt the response.
    const recipient = await importEncryptionPublicJwk(published);
    const jwe = await encryptJwe({ vp_token: 'vp', state: 'req-2' }, recipient, {
      enc: 'A256GCM',
      kid: published.kid,
    });

    // Verifier side: decrypt with the private half it kept.
    const { payload } = await decryptJwe(jwe, pair.privateKey, PINS);
    expect(payload).toEqual({ vp_token: 'vp', state: 'req-2' });
  });
});

describe('importEncryptionPublicJwk (untrusted peer key)', () => {
  async function publicJwk(): Promise<JWK> {
    const pair = await generateEphemeralEncryptionKeyPair({ kid: 'k' });
    return exportEncryptionPublicJwk(pair);
  }

  it('rejects a P-384 JWK — jose does NOT pin the curve for ECDH-ES, so this library must', async () => {
    const { publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-384', extractable: true });
    const jwk = await exportJWK(publicKey);
    expect(jwk.crv).toBe('P-384');

    await expect(importEncryptionPublicJwk(jwk)).rejects.toThrow(/'crv' must be 'P-256'/);
  });

  it('rejects a P-521 JWK', async () => {
    const { publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-521', extractable: true });

    await expect(importEncryptionPublicJwk(await exportJWK(publicKey))).rejects.toThrow(
      /'crv' must be 'P-256'/
    );
  });

  it('rejects an X25519 JWK (wrong kty)', async () => {
    const { publicKey } = await generateKeyPair('ECDH-ES', { crv: 'X25519', extractable: true });

    await expect(importEncryptionPublicJwk(await exportJWK(publicKey))).rejects.toThrow(
      /'kty' must be 'EC'/
    );
  });

  it('rejects a JWK carrying private material', async () => {
    const pair = await generateEphemeralEncryptionKeyPair({ extractable: true, kid: 'k' });
    const privateJwk = await exportEncryptionPrivateJwk(pair);

    await expect(importEncryptionPublicJwk(privateJwk)).rejects.toThrow(
      /must not carry private key material/
    );
  });

  it('rejects a JWK whose declared alg is not ECDH-ES', async () => {
    await expect(
      importEncryptionPublicJwk({ ...(await publicJwk()), alg: 'ES256' })
    ).rejects.toThrow(/declares alg 'ES256'/);
  });

  it("rejects a JWK declaring use:'sig'", async () => {
    await expect(importEncryptionPublicJwk({ ...(await publicJwk()), use: 'sig' })).rejects.toThrow(
      /must declare 'enc'/
    );
  });

  it('accepts a bare JWK with no alg/use hints', async () => {
    const { x, y, kty, crv } = await publicJwk();

    await expect(importEncryptionPublicJwk({ kty, crv, x, y })).resolves.toMatchObject({
      type: 'public',
    });
  });
});

describe('exportEncryptionPrivateJwk / importEncryptionPrivateJwk (cross-request persistence)', () => {
  it('round-trips an extractable private half and still decrypts the response', async () => {
    const pair = await generateEphemeralEncryptionKeyPair({ extractable: true, kid: 'req-3' });
    const jwe = await encryptJwe({ vp_token: 'vp' }, pair.publicKey, { enc: 'A256GCM' });

    // What a multi-instance deployment stores between the request that created
    // the key and the `direct_post.jwt` callback that consumes it.
    const stored = await exportEncryptionPrivateJwk(pair);
    expect(stored).toMatchObject({
      kty: 'EC',
      crv: 'P-256',
      alg: 'ECDH-ES',
      use: 'enc',
      kid: 'req-3',
    });
    expect(stored.d).toBeTypeOf('string');

    const restored = await importEncryptionPrivateJwk(stored);
    const { payload } = await decryptJwe(jwe, restored, PINS);
    expect(payload).toEqual({ vp_token: 'vp' });
  });

  it('refuses a public key', async () => {
    const pair = await generateEphemeralEncryptionKeyPair({ extractable: true });

    await expect(
      exportEncryptionPrivateJwk({ kid: pair.kid, privateKey: pair.publicKey })
    ).rejects.toThrow(/requires a private key/);
  });

  it("rejects a stored JWK with no 'd' member", async () => {
    const pair = await generateEphemeralEncryptionKeyPair({ extractable: true, kid: 'k' });
    const publicOnly = await exportEncryptionPublicJwk(pair);

    await expect(importEncryptionPrivateJwk(publicOnly)).rejects.toThrow(/must carry a 'd' member/);
  });

  it('rejects a stored JWK whose curve was switched (tampered shared state)', async () => {
    const { privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-384', extractable: true });
    const jwk = await exportJWK(privateKey);

    await expect(importEncryptionPrivateJwk(jwk)).rejects.toThrow(/'crv' must be 'P-256'/);
  });
});
