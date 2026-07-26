/**
 * ES256 (ECDSA P-256 + SHA-256) signing and verification — #298 Phase 1.
 *
 * Lives beside `signing.test.ts` rather than inside it so the EdDSA suite stays
 * a pure regression witness: if widening `JwsAlgorithm` had disturbed the
 * classical path, that file — untouched by this change — is what says so.
 */
import {
  CompactEncrypt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  SignJWT,
} from 'jose';
import { describe, expect, it } from 'vitest';

import {
  exportEncryptionPublicJwk,
  generateEphemeralEncryptionKeyPair,
  importEncryptionPublicJwk,
} from './encryption-keys';
import { CryptoVerificationError } from './errors';
import {
  exportPublicSigningJwk,
  generateSigningKeyPair,
  importPublicSigningJwk,
} from './key-management';
import { sign, verify, verifyWithHeader } from './signing';

const ISSUER = 'https://verifier.example.com';

/**
 * RFC 7515 Appendix A.3 — the specification's own ES256 example.
 *
 * A genuine KNOWN-ANSWER test, which ECDSA otherwise makes impossible: the
 * signature is randomized, so "sign and compare bytes" cannot exist. Verifying a
 * fixed third-party vector is the equivalent guarantee in the other direction —
 * it proves this library agrees with the spec about the signing input, the
 * `base64url` encoding, and the raw `r || s` signature form (as opposed to the
 * DER form OpenSSL emits, the classic ES256 interop bug).
 */
const RFC7515_A3 = {
  jwk: {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  } satisfies JWK,
  token:
    'eyJhbGciOiJFUzI1NiJ9.' +
    'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.' +
    'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
  /** Just inside the vector's `exp` of 1300819380, so the token is not expired. */
  currentDate: new Date(1_300_819_300 * 1000),
};

describe('ES256 known-answer vector (RFC 7515 A.3)', () => {
  it('verifies the specification vector with the algorithm pinned to ES256', async () => {
    const publicKey = await importPublicSigningJwk({ ...RFC7515_A3.jwk }, 'ES256');

    const { claims, protectedHeader } = await verifyWithHeader(RFC7515_A3.token, publicKey, {
      algorithms: ['ES256'],
      issuer: 'joe',
      currentDate: RFC7515_A3.currentDate,
    });

    expect(protectedHeader['alg']).toBe('ES256');
    expect(claims['iss']).toBe('joe');
    expect(claims['exp']).toBe(1_300_819_380);
    expect(claims['http://example.com/is_root']).toBe(true);
  });

  it('rejects the same vector when the verifier pins EdDSA', async () => {
    const publicKey = await importPublicSigningJwk({ ...RFC7515_A3.jwk }, 'ES256');

    await expect(
      verifyWithHeader(RFC7515_A3.token, publicKey, {
        algorithms: ['EdDSA'],
        currentDate: RFC7515_A3.currentDate,
      })
    ).rejects.toBeInstanceOf(CryptoVerificationError);
  });

  it('rejects the vector once its exp has passed', async () => {
    const publicKey = await importPublicSigningJwk({ ...RFC7515_A3.jwk }, 'ES256');

    await expect(
      verify(RFC7515_A3.token, publicKey, {
        algorithms: ['ES256'],
        currentDate: new Date(1_300_819_400 * 1000),
      })
    ).rejects.toMatchObject({ reason: 'expired' });
  });
});

describe('sign / verify (ES256)', () => {
  it('round-trips claims through a compact JWS', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('ES256');

    const token = await sign({ sub: 'wallet-1', nonce: 'n-1' }, privateKey, 'ES256', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'https://wallet.example.com',
    });

    expect(token.split('.')).toHaveLength(3);
    expect(decodeProtectedHeader(token).alg).toBe('ES256');

    const claims = await verify(token, publicKey, { algorithms: ['ES256'], issuer: ISSUER });
    expect(claims['sub']).toBe('wallet-1');
    expect(claims['nonce']).toBe('n-1');
  });

  it('produces a different signature each time (ECDSA is randomized)', async () => {
    const { privateKey } = await generateSigningKeyPair('ES256');
    const options = { issuer: ISSUER, expiresIn: 300, audience: 'a' };

    const first = await sign({ sub: 'u' }, privateKey, 'ES256', options);
    const second = await sign({ sub: 'u' }, privateKey, 'ES256', options);

    expect(first.split('.')[2]).not.toBe(second.split('.')[2]);
  });

  it('carries an OID4VP request-object typ and kid through the protected header', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('ES256');

    const token = await sign({ response_type: 'vp_token' }, privateKey, 'ES256', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'https://wallet.example.com',
      typ: 'oauth-authz-req+jwt',
      header: { kid: 'verifier-es256-1' },
    });

    const { protectedHeader } = await verifyWithHeader(token, publicKey, {
      algorithms: ['ES256'],
    });
    expect(protectedHeader).toEqual({
      alg: 'ES256',
      typ: 'oauth-authz-req+jwt',
      kid: 'verifier-es256-1',
    });
  });

  it('rejects a token signed by a different ES256 key', async () => {
    const signer = await generateSigningKeyPair('ES256');
    const other = await generateSigningKeyPair('ES256');

    const token = await sign({ sub: 'u' }, signer.privateKey, 'ES256', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'a',
    });

    await expect(verify(token, other.publicKey, { algorithms: ['ES256'] })).rejects.toBeInstanceOf(
      CryptoVerificationError
    );
  });

  it('rejects a token whose signature has been tampered with', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('ES256');
    const token = await sign({ sub: 'u' }, privateKey, 'ES256', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'a',
    });

    const [header, payload, signature] = token.split('.');
    // Flip one base64url character of the signature.
    const flipped = (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);

    await expect(
      verify([header, payload, flipped].join('.'), publicKey, { algorithms: ['ES256'] })
    ).rejects.toBeInstanceOf(CryptoVerificationError);
  });

  it('rejects a token whose payload has been tampered with', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('ES256');
    const token = await sign({ sub: 'user' }, privateKey, 'ES256', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'a',
    });

    const [header, payload, signature] = token.split('.');
    const forged = Buffer.from(
      JSON.stringify({
        ...(JSON.parse(Buffer.from(payload, 'base64url').toString()) as Record<string, unknown>),
        sub: 'admin',
      })
    ).toString('base64url');

    await expect(
      verify([header, forged, signature].join('.'), publicKey, { algorithms: ['ES256'] })
    ).rejects.toBeInstanceOf(CryptoVerificationError);
  });
});

describe('ES256 algorithm confusion (#298 acceptance: unexpected alg is rejected)', () => {
  it('rejects an EdDSA token at a verifier pinned to ES256', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA');
    const token = await sign({ sub: 'u' }, privateKey, 'EdDSA', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'a',
    });

    await expect(verify(token, publicKey, { algorithms: ['ES256'] })).rejects.toBeInstanceOf(
      CryptoVerificationError
    );
  });

  it('rejects an ES256 token at a verifier pinned to EdDSA (QAuth token-layer posture)', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('ES256');
    const token = await sign({ sub: 'u' }, privateKey, 'ES256', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'a',
    });

    await expect(verify(token, publicKey, { algorithms: ['EdDSA'] })).rejects.toBeInstanceOf(
      CryptoVerificationError
    );
  });

  it('rejects a token whose header alg was rewritten to a pinned algorithm', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('ES256');
    const token = await sign({ sub: 'u' }, privateKey, 'ES256', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'a',
    });

    const [, payload, signature] = token.split('.');
    const rewritten = Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString('base64url');

    // The header is part of the signing input, so rewriting it to the algorithm
    // the verifier accepts cannot help an attacker: the signature no longer
    // covers the bytes presented.
    await expect(
      verify([rewritten, payload, signature].join('.'), publicKey, { algorithms: ['EdDSA'] })
    ).rejects.toBeInstanceOf(CryptoVerificationError);
  });

  it("rejects an unsigned token claiming alg 'none'", async () => {
    const { publicKey } = await generateSigningKeyPair('ES256');
    const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({ sub: 'admin', iss: ISSUER, exp: 4_102_444_800 })
    ).toString('base64url');

    await expect(
      verify(`${header}.${payload}.`, publicKey, { algorithms: ['ES256'] })
    ).rejects.toBeInstanceOf(CryptoVerificationError);
  });

  it('rejects an ES384 (P-384) token at a verifier pinned to ES256', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES384', { extractable: false });
    const token = await new SignJWT({ sub: 'u' })
      .setProtectedHeader({ alg: 'ES384' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(verify(token, publicKey, { algorithms: ['ES256'] })).rejects.toBeInstanceOf(
      CryptoVerificationError
    );
  });
});

describe('exportPublicSigningJwk / importPublicSigningJwk (ES256)', () => {
  it('round-trips an ES256 verification key through a fully-specified JWK', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('ES256', { extractable: true });
    const jwk = await exportPublicSigningJwk(publicKey, { alg: 'ES256', kid: 'wallet-1' });

    expect(jwk).toMatchObject({
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      use: 'sig',
      kid: 'wallet-1',
    });
    expect(jwk.d).toBeUndefined();

    const reimported = await importPublicSigningJwk(jwk, 'ES256');
    const token = await sign({ sub: 'u' }, privateKey, 'ES256', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'a',
    });
    await expect(verify(token, reimported, { algorithms: ['ES256'] })).resolves.toMatchObject({
      sub: 'u',
    });
  });

  it('refuses to export a private key as a public JWK', async () => {
    const { privateKey } = await generateSigningKeyPair('ES256', { extractable: true });
    await expect(exportPublicSigningJwk(privateKey, { alg: 'ES256' })).rejects.toThrow(
      /requires a public key/
    );
  });

  it('rejects a JWK carrying private material', async () => {
    const { privateKey } = await generateSigningKeyPair('ES256', { extractable: true });
    const privateJwk = await exportJWK(privateKey);

    await expect(importPublicSigningJwk(privateJwk, 'ES256')).rejects.toThrow(
      /must not carry private key material/
    );
  });

  it('rejects a P-384 JWK imported as ES256 (wrong curve)', async () => {
    const { publicKey } = await generateKeyPair('ES384', { extractable: true });
    const jwk = await exportJWK(publicKey);

    await expect(importPublicSigningJwk(jwk, 'ES256')).rejects.toThrow(/'crv' must be 'P-256'/);
  });

  it('rejects an OKP (Ed25519) JWK imported as ES256 (wrong key type)', async () => {
    const { publicKey } = await generateSigningKeyPair('EdDSA', { extractable: true });
    const jwk = await exportJWK(publicKey);

    await expect(importPublicSigningJwk(jwk, 'ES256')).rejects.toThrow(/'kty' must be 'EC'/);
  });

  it('rejects a JWK whose own alg contradicts the caller pin', async () => {
    const { publicKey } = await generateSigningKeyPair('ES256', { extractable: true });
    const jwk = await exportPublicSigningJwk(publicKey, { alg: 'ES256' });

    await expect(importPublicSigningJwk({ ...jwk, alg: 'ES384' }, 'ES256')).rejects.toThrow(
      /declares alg 'ES384'/
    );
  });

  it("rejects a JWK marked use:'enc' as a signing key", async () => {
    const { publicKey } = await generateSigningKeyPair('ES256', { extractable: true });
    const jwk = await exportPublicSigningJwk(publicKey, { alg: 'ES256' });

    await expect(importPublicSigningJwk({ ...jwk, use: 'enc' }, 'ES256')).rejects.toThrow(
      /must declare 'sig'/
    );
  });

  it('still round-trips an EdDSA key, unchanged by the ES256 widening', async () => {
    const { publicKey } = await generateSigningKeyPair('EdDSA', { extractable: true });
    const jwk = await exportPublicSigningJwk(publicKey, { alg: 'EdDSA', kid: 'ed-1' });

    expect(jwk).toMatchObject({ kty: 'OKP', alg: 'EdDSA', use: 'sig' });
    await expect(importPublicSigningJwk(jwk, 'EdDSA')).resolves.toBeDefined();
  });
});

describe('ES256 signing keys are not encryption keys', () => {
  it('generates ECDSA keys whose WebCrypto usages exclude key agreement', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('ES256');

    expect(privateKey.algorithm.name).toBe('ECDSA');
    expect(privateKey.usages).toEqual(['sign']);
    expect(publicKey.usages).toEqual(['verify']);
    expect(privateKey.usages).not.toContain('deriveBits');
  });

  it('cannot be used for ECDH key agreement (the platform refuses)', async () => {
    const { publicKey } = await generateSigningKeyPair('ES256', { extractable: true });

    await expect(
      new CompactEncrypt(new TextEncoder().encode('{}'))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(publicKey)
    ).rejects.toThrow();
  });

  it('an ES256 key exported as a JWK is refused by the encryption importer', async () => {
    const { publicKey } = await generateSigningKeyPair('ES256', { extractable: true });
    const jwk = await exportPublicSigningJwk(publicKey, { alg: 'ES256' });

    await expect(importEncryptionPublicJwk(jwk)).rejects.toThrow(/declares alg 'ES256'/);
  });

  it('an ECDH-ES key JWK is refused by the signing importer', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const jwk = await exportEncryptionPublicJwk(pair);

    await expect(importPublicSigningJwk(jwk, 'ES256')).rejects.toThrow(/declares alg 'ECDH-ES'/);
  });

  it('a raw ECDH JWK stripped of its alg/use hints still cannot verify an ES256 token', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    // Strip the metadata so the key is indistinguishable from an ES256 key by
    // shape alone — `{kty:'EC', crv:'P-256', x, y}` — and import it as ES256.
    const bare = await exportJWK(pair.publicKey);
    const asSigningKey = await importJWK(bare, 'ES256');
    expect(asSigningKey).not.toBeInstanceOf(Uint8Array);

    const { privateKey } = await generateSigningKeyPair('ES256');
    const token = await sign({ sub: 'u' }, privateKey, 'ES256', {
      issuer: ISSUER,
      expiresIn: 300,
      audience: 'a',
    });

    // The bytes are a valid P-256 point, so the import succeeds — but it is a
    // DIFFERENT key, so verification fails. Cross-use cannot forge a signature;
    // the JWK-level guards above exist to make the mistake loud, not to be the
    // only thing standing between a wallet and a forged request object.
    await expect(
      verify(token, asSigningKey as CryptoKey, { algorithms: ['ES256'] })
    ).rejects.toBeInstanceOf(CryptoVerificationError);
  });
});
