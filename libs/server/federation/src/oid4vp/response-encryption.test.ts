import { randomBytes } from 'node:crypto';

import {
  exportEncryptionPrivateJwk,
  generateEphemeralEncryptionKeyPair,
} from '@qauth-labs/core-crypto';
import { CompactEncrypt, exportJWK, generateKeyPair, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';

import { hashOid4vpState } from './request-state';
import {
  assertEncryptedResponseStateMatches,
  decryptOid4vpAuthorizationResponse,
  EPHEMERAL_KEY_PROTECTION_AES_256_GCM,
  EPHEMERAL_KEY_PROTECTION_PLAIN,
  MAX_ENCRYPTED_RESPONSE_LENGTH,
  MAX_ENCRYPTION_KID_LENGTH,
  OID4VP_ENCRYPTED_RESPONSE_ENC_VALUES,
  parseEphemeralKeyProtection,
  protectEphemeralKey,
  readEncryptedResponseKid,
  unprotectEphemeralKey,
} from './response-encryption';

/**
 * The `direct_post.jwt` intake primitives (#377 Phase C).
 *
 * Ciphertexts are produced with `jose` directly rather than with the library's
 * own `encryptJwe`, so that what is under test is the WIRE FORMAT a wallet
 * emits, not an agreement between two halves of this workspace.
 */

const KID = 'kid-for-this-request';

async function mintRecipient(): Promise<{ publicKey: CryptoKey; privateJwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair('ECDH-ES', {
    crv: 'P-256',
    extractable: true,
  });
  return {
    publicKey,
    privateJwk: { ...(await exportJWK(privateKey)), alg: 'ECDH-ES', use: 'enc', kid: KID },
  };
}

async function encrypt(
  publicKey: CryptoKey,
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {}
): Promise<string> {
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: KID, ...header } as never)
    .encrypt(publicKey);
}

describe('readEncryptedResponseKid (OID4VP 1.0 §8.3)', () => {
  it('reads the kid without decrypting anything', async () => {
    const { publicKey } = await mintRecipient();

    // No private key is involved at all — that is the property, not a
    // convenience: this runs on an unauthenticated POST before any row is known.
    expect(readEncryptedResponseKid(await encrypt(publicKey, { state: 's' }))).toBe(KID);
  });

  it('refuses a JWE carrying no kid', async () => {
    const { publicKey } = await mintRecipient();
    const withoutKid = await new CompactEncrypt(new TextEncoder().encode('{}'))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(publicKey);

    expect(() => readEncryptedResponseKid(withoutKid)).toThrow(/carries no 'kid'/);
  });

  it('refuses a kid longer than the column can address', () => {
    // Attacker-supplied, so it is bounded before it reaches a query. QAuth's own
    // kid is 22 characters.
    const oversized = `${'x'.repeat(MAX_ENCRYPTION_KID_LENGTH + 1)}`;
    const header = Buffer.from(
      JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM', kid: oversized }),
      'utf8'
    ).toString('base64url');

    expect(() => readEncryptedResponseKid(`${header}..a.b.c`)).toThrow(/exceeds the/);
  });

  it('refuses an oversized parameter before parsing it', () => {
    expect(() => readEncryptedResponseKid('x'.repeat(MAX_ENCRYPTED_RESPONSE_LENGTH + 1))).toThrow(
      /exceeds the/
    );
  });

  it('refuses something that is not a JOSE object', () => {
    expect(() => readEncryptedResponseKid('not-a-jwe')).toThrow(
      /no readable JOSE protected header/
    );
  });
});

describe('decryptOid4vpAuthorizationResponse', () => {
  it('returns the Authorization Response parameters', async () => {
    const { publicKey, privateJwk } = await mintRecipient();
    const jwe = await encrypt(publicKey, { state: 's', vp_token: { pid: ['p~'] } });

    const decrypted = await decryptOid4vpAuthorizationResponse(jwe, privateJwk);

    expect(decrypted.state).toBe('s');
    // The object form a conformant wallet sends is re-serialized, so exactly one
    // structural parser sees it on both response modes.
    expect(JSON.parse(decrypted.vpToken as string)).toEqual({ pid: ['p~'] });
  });

  it('accepts the string vp_token form too', async () => {
    const { publicKey, privateJwk } = await mintRecipient();
    const jwe = await encrypt(publicKey, { state: 's', vp_token: '{"pid":["p~"]}' });

    expect((await decryptOid4vpAuthorizationResponse(jwe, privateJwk)).vpToken).toBe(
      '{"pid":["p~"]}'
    );
  });

  it("refuses a payload with no 'state' (§5.3)", async () => {
    const { publicKey, privateJwk } = await mintRecipient();

    await expect(
      decryptOid4vpAuthorizationResponse(await encrypt(publicKey, { vp_token: {} }), privateJwk)
    ).rejects.toThrow(/carries no 'state'/);
  });

  it('refuses a ciphertext encrypted to another key', async () => {
    const { publicKey } = await mintRecipient();
    const other = await mintRecipient();

    await expect(
      decryptOid4vpAuthorizationResponse(await encrypt(publicKey, { state: 's' }), other.privateJwk)
    ).rejects.toThrow(/did not decrypt/);
  });

  it('refuses a compressed JWE (RFC 8725 §3.5)', async () => {
    // The recipient's public key is published in client metadata BY DESIGN, so
    // anyone can mint a `zip: 'DEF'` JWE. Refusing it here is what stops that
    // being a decompression-amplification primitive on an unauthenticated POST.
    const { publicKey, privateJwk } = await mintRecipient();
    const jwe = await encrypt(publicKey, { state: 's' }, { zip: 'DEF' });

    await expect(decryptOid4vpAuthorizationResponse(jwe, privateJwk)).rejects.toThrow(
      /did not decrypt/
    );
  });

  it('advertises exactly the enc values it will accept', () => {
    // Advertising an algorithm the decrypt path pins away would produce a
    // response QAuth asked for and cannot open.
    expect(OID4VP_ENCRYPTED_RESPONSE_ENC_VALUES).toEqual(['A128GCM', 'A256GCM']);
  });
});

describe('assertEncryptedResponseStateMatches (§5.3)', () => {
  it('accepts the state the request was issued with', () => {
    expect(() => assertEncryptedResponseStateMatches('s', hashOid4vpState('s'))).not.toThrow();
  });

  it('refuses any other state', () => {
    // The check the `kid` cannot make: §14.5 leaves the ciphertext unbound to a
    // request, so a matching `kid` proves only that someone read the metadata.
    expect(() => assertEncryptedResponseStateMatches('other', hashOid4vpState('s'))).toThrow(
      /not the one this request was issued with/
    );
  });

  it('refuses a stored digest of the wrong length rather than comparing loosely', () => {
    expect(() => assertEncryptedResponseStateMatches('s', 'truncated')).toThrow();
  });
});

describe('ephemeral key protection at rest (#377 Phase C, opt-in)', () => {
  async function privateJwk(): Promise<JWK> {
    return exportEncryptionPrivateJwk(
      await generateEphemeralEncryptionKeyPair({ kid: KID, extractable: true })
    );
  }

  it('stores the JWK plainly when the deployment configured no secret', async () => {
    const jwk = await privateJwk();
    const stored = protectEphemeralKey(jwk, { kid: KID });

    // The DEFAULT, and not a gap: no specification requires at-rest protection
    // of this value, and the row it lives on expires in minutes.
    expect(stored.protection).toBe(EPHEMERAL_KEY_PROTECTION_PLAIN);
    expect(JSON.parse(stored.value)).toEqual(jwk);
    expect(unprotectEphemeralKey(stored.value, stored.protection, { kid: KID })).toEqual(jwk);
  });

  it('encrypts the JWK when a secret is configured, and reads it back', async () => {
    const jwk = await privateJwk();
    const secret = randomBytes(32);
    const stored = protectEphemeralKey(jwk, { kid: KID, secret });

    expect(stored.protection).toBe(EPHEMERAL_KEY_PROTECTION_AES_256_GCM);
    expect(stored.value).not.toContain(jwk.d);
    expect(unprotectEphemeralKey(stored.value, stored.protection, { kid: KID, secret })).toEqual(
      jwk
    );
  });

  it('binds the envelope to its own kid, so a relocated ciphertext will not open', async () => {
    // Without the AAD, anyone with write access to the table could move one
    // row's key onto another row and the AEAD would open it happily.
    const secret = randomBytes(32);
    const stored = protectEphemeralKey(await privateJwk(), { kid: KID, secret });

    expect(() =>
      unprotectEphemeralKey(stored.value, stored.protection, { kid: 'another-row', secret })
    ).toThrow();
  });

  it('refuses to read an envelope with the wrong secret', async () => {
    const stored = protectEphemeralKey(await privateJwk(), { kid: KID, secret: randomBytes(32) });

    expect(() =>
      unprotectEphemeralKey(stored.value, stored.protection, { kid: KID, secret: randomBytes(32) })
    ).toThrow();
  });

  it('refuses to read an envelope when the secret is gone entirely', async () => {
    // The rotation constraint: the OLD secret must stay configured until every
    // row written under it has expired.
    const stored = protectEphemeralKey(await privateJwk(), { kid: KID, secret: randomBytes(32) });

    expect(() => unprotectEphemeralKey(stored.value, stored.protection, { kid: KID })).toThrow(
      /must stay configured/
    );
  });

  it('refuses a secret that is not exactly one AES-256 key', async () => {
    // Raised loudly rather than stretched or truncated: a silently derived key
    // is one the operator cannot reproduce, and every row written under it
    // becomes unreadable the moment anyone tries.
    const jwk = await privateJwk();

    expect(() => protectEphemeralKey(jwk, { kid: KID, secret: randomBytes(16) })).toThrow(
      /exactly 32 bytes/
    );
  });

  it('refuses an unrecognised envelope version', async () => {
    const secret = randomBytes(32);
    const stored = protectEphemeralKey(await privateJwk(), { kid: KID, secret });
    const bumped = `9${stored.value.slice(1)}`;

    expect(() =>
      unprotectEphemeralKey(bumped, EPHEMERAL_KEY_PROTECTION_AES_256_GCM, { kid: KID, secret })
    ).toThrow(/recognised at-rest envelope version/);
  });

  it('narrows a stored marker fail-closed', () => {
    expect(parseEphemeralKeyProtection('plain')).toBe(EPHEMERAL_KEY_PROTECTION_PLAIN);
    expect(parseEphemeralKeyProtection('aes-256-gcm')).toBe(EPHEMERAL_KEY_PROTECTION_AES_256_GCM);
    // An unrecognised marker must not default to `plain`, which would hand a
    // ciphertext to a JSON parser.
    expect(parseEphemeralKeyProtection('rot13')).toBeUndefined();
    expect(parseEphemeralKeyProtection(null)).toBeUndefined();
    expect(parseEphemeralKeyProtection(undefined)).toBeUndefined();
  });

  it('refuses a plain value that is not a JWK document', () => {
    expect(() =>
      unprotectEphemeralKey('not json', EPHEMERAL_KEY_PROTECTION_PLAIN, { kid: KID })
    ).toThrow(/not valid JSON/);
    expect(() => unprotectEphemeralKey('[]', EPHEMERAL_KEY_PROTECTION_PLAIN, { kid: KID })).toThrow(
      /not a JSON object/
    );
  });
});
