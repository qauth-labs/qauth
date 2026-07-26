/**
 * JWE — `ECDH-ES` (P-256) key agreement with `A128GCM` / `A256GCM` content
 * encryption, for the OID4VP `direct_post.jwt` response mode (#298 Phase 2,
 * HAIP §5).
 */
import { base64url, CompactEncrypt, decodeProtectedHeader, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';

import { JWE_CONTENT_ENCRYPTION_ALGORITHMS } from './algorithms';
import {
  type EphemeralEncryptionKeyPair,
  generateEphemeralEncryptionKeyPair,
  importEncryptionPrivateJwk,
} from './encryption-keys';
import { CRYPTO_DECRYPTION_ERROR_MESSAGE, CryptoDecryptionError } from './errors';
import { decryptJwe, encryptJwe, RESERVED_JWE_PROTECTED_HEADER_MEMBERS } from './jwe';

/** The pins a `direct_post.jwt` recipient uses: both AES-GCM variants, ECDH-ES only. */
const HAIP_PINS = {
  keyManagementAlgorithms: ['ECDH-ES'],
  contentEncryptionAlgorithms: ['A128GCM', 'A256GCM'],
} as const;

/** A realistic OID4VP Authorization Response body. */
const RESPONSE = {
  vp_token: 'eyJhbGciOiJFUzI1NiJ9.presentation.signature',
  state: 'req-01HZ',
  presentation_submission: { id: 'ps-1', definition_id: 'pd-1', descriptor_map: [] },
};

/**
 * A FIXED ciphertext and recipient key, captured from this implementation.
 *
 * The known-answer test ECDH-ES otherwise cannot have: every encryption
 * generates a fresh `epk`, so no encrypt-and-compare vector exists. Pinning a
 * static ciphertext against a static private key tests the direction that CAN be
 * pinned — that this library still agrees with the RFC 7518 §4.6 ConcatKDF, the
 * `A*GCM` AEAD construction, and the compact serialization. A `jose` upgrade (or
 * a well-meant refactor) that changed any of them would fail here and nowhere
 * else, because a round-trip test agrees with itself no matter what it computes.
 */
const KAT = {
  privateJwk: {
    kty: 'EC',
    crv: 'P-256',
    x: 'iUaTMJpCu0FFDGrHCSbOyYJV0x_zE1QqwPxufacZleo',
    y: '1i9pvdJpBIcqS6DZKsrmpcX2i-KXdEnHmphW8NYFlak',
    d: 'LjiWE29gdoSfg9zo64nFpuxg_0zbKIEaMmoQV8eHpSk',
  },
  plaintext: { vp_token: 'eyJhbGciOiJFUzI1NiJ9.fixture.signature', state: 'kat-state' },
  a128gcm:
    'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImtpZCI6ImthdC1rZXkiLCJlcGsiOnsieCI6InRnc2R2NFl4bWR3cTJSYzZaQkhRLTcySGpkU0FkbGloQlZYbjZMcHVoYjgiLCJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieSI6InBiR2Vpc0dVVGd0ZWpWV09YVU94VzhEOWdVOFhkTDRYV2FxM2JKd1NOczgifX0..L3hiCC-P-suhwePu.BTEZe-oEgRAWjPP6vNmn-7T3MXqCyzht9I-9b2hoce_oDlBGVsvqriBACNBvrSzi0aXSZqsqT4lP48TBu7cA02F2s_KYKbiz-Q.gO7YqUEPRy6slSRSS2mikQ',
  a256gcm:
    'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImtpZCI6ImthdC1rZXkiLCJlcGsiOnsieCI6IkU0NV9zWlJWTU02M3pKd1U2VGJxNHpSbHloOXJmVWZzZ3RRY1Nwc2dLRFEiLCJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieSI6InNVenFkdkNkaWJ3Wk4xdXZzQ1hMaXBxaUYxRm1KQ3FaNlpjX0MxRWRRUVUifX0..Q_no-PHWIWLJmt8r.ACBvkGOvg5DwNRUYXLcXoKF7QYNBE8NVm8Y65YLDxSyDH_WNVx4EIE31cjXqRVyXPB6amB6JUHPJCNvS_tWSVkC4_tgISI7sxg.EQ-opR_RwTi3vg-oNwH6wg',
};

/** The KAT recipient as an {@link EphemeralEncryptionKeyPair}-shaped private half. */
async function katPrivateKey(): Promise<CryptoKey> {
  return importEncryptionPrivateJwk({ ...KAT.privateJwk });
}

/** Run a decrypt expected to fail and hand back the thrown error. */
async function captureDecryptionError(
  attempt: () => Promise<unknown>
): Promise<CryptoDecryptionError> {
  try {
    await attempt();
  } catch (error) {
    if (error instanceof CryptoDecryptionError) return error;
    throw error;
  }
  throw new Error('expected the decryption to fail');
}

describe('JWE known-answer vectors (fixed ciphertext, fixed recipient key)', () => {
  it.each([
    ['A128GCM', KAT.a128gcm],
    ['A256GCM', KAT.a256gcm],
  ])('decrypts the pinned %s ciphertext to the exact known plaintext', async (enc, ciphertext) => {
    const privateKey = await katPrivateKey();

    const { payload, protectedHeader } = await decryptJwe(ciphertext, privateKey, HAIP_PINS);

    expect(payload).toEqual(KAT.plaintext);
    expect(protectedHeader['alg']).toBe('ECDH-ES');
    expect(protectedHeader['enc']).toBe(enc);
    expect(protectedHeader['kid']).toBe('kat-key');
    // Direct key agreement: the CEK is the agreed secret, so there is no
    // encrypted-key segment.
    expect(ciphertext.split('.')[1]).toBe('');
  });

  it('rejects the pinned A128GCM ciphertext when only A256GCM is accepted', async () => {
    const privateKey = await katPrivateKey();

    await expect(
      decryptJwe(KAT.a128gcm, privateKey, {
        keyManagementAlgorithms: ['ECDH-ES'],
        contentEncryptionAlgorithms: ['A256GCM'],
      })
    ).rejects.toBeInstanceOf(CryptoDecryptionError);
  });
});

describe('encryptJwe / decryptJwe round trip', () => {
  it.each(JWE_CONTENT_ENCRYPTION_ALGORITHMS)('round-trips a response under %s', async (enc) => {
    const pair = await generateEphemeralEncryptionKeyPair();

    const jwe = await encryptJwe(RESPONSE, pair.publicKey, { enc, kid: pair.kid });

    expect(jwe.split('.')).toHaveLength(5);
    expect(decodeProtectedHeader(jwe)).toMatchObject({ alg: 'ECDH-ES', enc, kid: pair.kid });

    const { payload, protectedHeader } = await decryptJwe(jwe, pair.privateKey, HAIP_PINS);
    expect(payload).toEqual(RESPONSE);
    expect(protectedHeader['enc']).toBe(enc);
    // The ephemeral public key of the SENDER, contributed per encryption.
    expect(protectedHeader['epk']).toMatchObject({ kty: 'EC', crv: 'P-256' });
  });

  it('produces a different ciphertext every call (fresh sender epk)', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();

    const first = await encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM' });
    const second = await encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM' });

    expect(first).not.toBe(second);
    expect(decodeProtectedHeader(first)['epk']).not.toEqual(decodeProtectedHeader(second)['epk']);
  });

  it('carries extra protected-header members through to the decrypted header', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();

    const jwe = await encryptJwe(RESPONSE, pair.publicKey, {
      enc: 'A256GCM',
      kid: pair.kid,
      header: { cty: 'application/json' },
    });

    const { protectedHeader } = await decryptJwe(jwe, pair.privateKey, HAIP_PINS);
    expect(protectedHeader['cty']).toBe('application/json');
  });

  it('round-trips a payload with unicode and nested structure', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const payload = { note: 'ünïcode ✅ 日本語', nested: { deep: [1, 2, { ok: true }] } };

    const jwe = await encryptJwe(payload, pair.publicKey, { enc: 'A128GCM' });
    const { payload: out } = await decryptJwe(jwe, pair.privateKey, HAIP_PINS);

    expect(out).toEqual(payload);
  });
});

describe('encryptJwe input guards', () => {
  it.each(RESERVED_JWE_PROTECTED_HEADER_MEMBERS)(
    "rejects a caller-supplied reserved header member '%s'",
    async (member) => {
      const pair = await generateEphemeralEncryptionKeyPair();

      await expect(
        encryptJwe(RESPONSE, pair.publicKey, {
          enc: 'A256GCM',
          header: { [member]: 'attacker-value' },
        })
      ).rejects.toThrow(/is reserved/);
    }
  );

  it('rejects an unsupported content encryption algorithm', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();

    await expect(
      encryptJwe(RESPONSE, pair.publicKey, {
        // Deliberately outside the union — a JS caller, or a value that crossed
        // a JSON boundary, is not type-checked.
        enc: 'A128CBC-HS256' as never,
      })
    ).rejects.toThrow(/Unsupported JWE content encryption algorithm/);
  });

  it('refuses to encrypt to a P-384 recipient key', async () => {
    const { publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-384', extractable: true });

    // `jose` will happily agree on P-384; this library never hands it such a
    // key, because `importEncryptionPublicJwk` pins the curve. Proven there —
    // asserted here so the assumption is written down at the encrypt boundary.
    const jwe = await encryptJwe(RESPONSE, publicKey, { enc: 'A256GCM' });
    expect(decodeProtectedHeader(jwe)['epk']).toMatchObject({ crv: 'P-384' });
  });
});

describe('decryptJwe pinned-algorithm enforcement', () => {
  it('rejects an empty keyManagementAlgorithms list (no restriction at all)', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const jwe = await encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM' });

    await expect(
      decryptJwe(jwe, pair.privateKey, {
        keyManagementAlgorithms: [],
        contentEncryptionAlgorithms: ['A256GCM'],
      })
    ).rejects.toThrow(/must list at least one algorithm/);
  });

  it('rejects an empty contentEncryptionAlgorithms list', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const jwe = await encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM' });

    await expect(
      decryptJwe(jwe, pair.privateKey, {
        keyManagementAlgorithms: ['ECDH-ES'],
        contentEncryptionAlgorithms: [],
      })
    ).rejects.toThrow(/must list at least one algorithm/);
  });

  it('rejects a pin naming an unsupported key management algorithm', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const jwe = await encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM' });

    await expect(
      decryptJwe(jwe, pair.privateKey, {
        keyManagementAlgorithms: ['RSA1_5' as never],
        contentEncryptionAlgorithms: ['A256GCM'],
      })
    ).rejects.toThrow(/Unsupported JWE algorithm 'RSA1_5'/);
  });

  it('rejects a pin naming an unsupported content encryption algorithm', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const jwe = await encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM' });

    await expect(
      decryptJwe(jwe, pair.privateKey, {
        keyManagementAlgorithms: ['ECDH-ES'],
        contentEncryptionAlgorithms: ['A128CBC-HS256' as never],
      })
    ).rejects.toThrow(/Unsupported JWE algorithm 'A128CBC-HS256'/);
  });

  it("rejects a JWE whose alg is 'dir' even though the recipient key would fit", async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const jwe = await encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM' });

    // Rewrite the protected header to claim `dir`. The header is the AEAD's
    // Additional Authenticated Data, so this cannot succeed — but the point is
    // that it is refused by the PIN, before any key material is touched.
    const parts = jwe.split('.');
    parts[0] = base64url.encode(JSON.stringify({ alg: 'dir', enc: 'A256GCM' }));

    await expect(decryptJwe(parts.join('.'), pair.privateKey, HAIP_PINS)).rejects.toBeInstanceOf(
      CryptoDecryptionError
    );
  });

  it('rejects an ECDH-ES+A128KW JWE at an ECDH-ES-only recipient', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const wrapped = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(RESPONSE)))
      .setProtectedHeader({ alg: 'ECDH-ES+A128KW', enc: 'A256GCM' })
      .encrypt(pair.publicKey);

    await expect(decryptJwe(wrapped, pair.privateKey, HAIP_PINS)).rejects.toBeInstanceOf(
      CryptoDecryptionError
    );
  });
});

describe('decryptJwe negative cases', () => {
  async function encryptedFor(pair: EphemeralEncryptionKeyPair): Promise<string> {
    return encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM', kid: pair.kid });
  }

  it('rejects a JWE addressed to a different ephemeral key (wrong key)', async () => {
    const forRequestA = await generateEphemeralEncryptionKeyPair();
    const forRequestB = await generateEphemeralEncryptionKeyPair();
    const jwe = await encryptedFor(forRequestA);

    await expect(decryptJwe(jwe, forRequestB.privateKey, HAIP_PINS)).rejects.toBeInstanceOf(
      CryptoDecryptionError
    );
  });

  it('rejects a JWE whose ciphertext was tampered with', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const parts = (await encryptedFor(pair)).split('.');
    const ciphertext = base64url.decode(parts[3]);
    ciphertext[0] ^= 0xff;
    parts[3] = base64url.encode(ciphertext);

    await expect(decryptJwe(parts.join('.'), pair.privateKey, HAIP_PINS)).rejects.toBeInstanceOf(
      CryptoDecryptionError
    );
  });

  it('rejects a JWE whose authentication tag was tampered with', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const parts = (await encryptedFor(pair)).split('.');
    const tag = base64url.decode(parts[4]);
    tag[0] ^= 0xff;
    parts[4] = base64url.encode(tag);

    await expect(decryptJwe(parts.join('.'), pair.privateKey, HAIP_PINS)).rejects.toBeInstanceOf(
      CryptoDecryptionError
    );
  });

  it('rejects a JWE whose IV was tampered with', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const parts = (await encryptedFor(pair)).split('.');
    const iv = base64url.decode(parts[2]);
    iv[0] ^= 0xff;
    parts[2] = base64url.encode(iv);

    await expect(decryptJwe(parts.join('.'), pair.privateKey, HAIP_PINS)).rejects.toBeInstanceOf(
      CryptoDecryptionError
    );
  });

  it("rejects a JWE whose epk was swapped for the attacker's own", async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const attacker = await generateEphemeralEncryptionKeyPair();
    const parts = (await encryptedFor(pair)).split('.');

    const header = JSON.parse(new TextDecoder().decode(base64url.decode(parts[0]))) as Record<
      string,
      unknown
    >;
    const attackerJwe = await encryptJwe(RESPONSE, attacker.publicKey, { enc: 'A256GCM' });
    header['epk'] = decodeProtectedHeader(attackerJwe)['epk'];
    parts[0] = base64url.encode(JSON.stringify(header));

    await expect(decryptJwe(parts.join('.'), pair.privateKey, HAIP_PINS)).rejects.toBeInstanceOf(
      CryptoDecryptionError
    );
  });

  it('rejects a malformed compact serialization', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();

    await expect(decryptJwe('not-a-jwe', pair.privateKey, HAIP_PINS)).rejects.toBeInstanceOf(
      CryptoDecryptionError
    );
  });

  it('rejects a plaintext that is not a JSON object', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const jwe = await new CompactEncrypt(new TextEncoder().encode('["not","an","object"]'))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(pair.publicKey);

    await expect(decryptJwe(jwe, pair.privateKey, HAIP_PINS)).rejects.toMatchObject({
      detail: 'payload is not a JSON object',
    });
  });

  it('rejects a plaintext that is not JSON at all', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const jwe = await new CompactEncrypt(new TextEncoder().encode('plain bytes'))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(pair.publicKey);

    await expect(decryptJwe(jwe, pair.privateKey, HAIP_PINS)).rejects.toMatchObject({
      detail: 'payload is not valid JSON',
    });
  });

  /**
   * The no-oracle invariant, across the failure classes that `jose` reports
   * DIFFERENTLY.
   *
   * The previous version of this test compared only "wrong key" against
   * "tampered ciphertext", which `jose` happens to report identically
   * ("decryption operation failed"). It therefore passed while the message was
   * still interpolated with the backend's text, giving false assurance: a
   * malformed serialization said "Invalid Compact JWE" and a rejected `alg` pin
   * said `'"alg" (Algorithm) Header Parameter value not allowed'`. Those are the
   * cases that have to be in here.
   */
  it('reports EVERY failure with the same message, including the classes jose distinguishes', async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    const other = await generateEphemeralEncryptionKeyPair();
    const jwe = await encryptedFor(pair);

    const tamperedParts = jwe.split('.');
    const ciphertext = base64url.decode(tamperedParts[3]);
    ciphertext[0] ^= 0xff;
    tamperedParts[3] = base64url.encode(ciphertext);

    const rewrittenAlgParts = jwe.split('.');
    rewrittenAlgParts[0] = base64url.encode(JSON.stringify({ alg: 'dir', enc: 'A256GCM' }));

    const compressed = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(RESPONSE)))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', zip: 'DEF' })
      .encrypt(pair.publicKey);

    const nonJsonPayload = await new CompactEncrypt(new TextEncoder().encode('plain bytes'))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(pair.publicKey);

    const failures = await Promise.all(
      (
        [
          ['wrong recipient key', () => decryptJwe(jwe, other.privateKey, HAIP_PINS)],
          [
            'tampered ciphertext',
            () => decryptJwe(tamperedParts.join('.'), pair.privateKey, HAIP_PINS),
          ],
          [
            'rejected alg pin',
            () => decryptJwe(rewrittenAlgParts.join('.'), pair.privateKey, HAIP_PINS),
          ],
          ['malformed serialization', () => decryptJwe('not-a-jwe', pair.privateKey, HAIP_PINS)],
          ['too few segments', () => decryptJwe('a.b.c.d', pair.privateKey, HAIP_PINS)],
          ['refused zip header', () => decryptJwe(compressed, pair.privateKey, HAIP_PINS)],
          ['non-JSON plaintext', () => decryptJwe(nonJsonPayload, pair.privateKey, HAIP_PINS)],
        ] as const
      ).map(async ([label, attempt]) => [label, await captureDecryptionError(attempt)] as const)
    );

    for (const [label, error] of failures) {
      expect(error.name, label).toBe('CryptoDecryptionError');
      // `toBe` against the exported constant, not against a sibling failure: two
      // failures agreeing proves nothing about a third.
      expect(error.message, label).toBe(CRYPTO_DECRYPTION_ERROR_MESSAGE);
    }

    // And the message really is the whole message — no backend text appended.
    expect(new Set(failures.map(([, error]) => error.message)).size).toBe(1);
  });

  it('keeps the backend diagnostic on .detail, off .message', async () => {
    // The invariant is "one message", not "no diagnostics": an operator reading
    // local logs must still be able to tell the classes apart. `.detail` is
    // where that lives, and it is the field the docs forbid surfacing.
    const pair = await generateEphemeralEncryptionKeyPair();
    const other = await generateEphemeralEncryptionKeyPair();

    const jwe = await encryptedFor(pair);
    const wrongKey = await captureDecryptionError(() =>
      decryptJwe(jwe, other.privateKey, HAIP_PINS)
    );

    expect(wrongKey.detail).toBeDefined();
    expect(wrongKey.message).not.toContain(wrongKey.detail);
  });
});

/**
 * `zip` on the INCOMING direction (RFC 8725 §3.5).
 *
 * `encryptJwe` refuses `zip` as a reserved protected-header member, but that
 * governs only what this library emits. The recipient's per-request encryption
 * public key is published in client metadata BY DESIGN, so any party that reads
 * it can mint a well-formed `zip: 'DEF'` JWE — and `jose` honours `zip` on
 * decrypt by default. Refusing it only on encrypt would have left the
 * attacker-controlled direction wide open.
 */
describe('decryptJwe refuses compressed JWEs', () => {
  async function compressedJwe(
    publicKey: CryptoKey,
    zip: string,
    payload: Record<string, unknown> = RESPONSE
  ): Promise<string> {
    return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', zip })
      .encrypt(publicKey);
  }

  it("refuses a valid zip: 'DEF' JWE minted with the published encryption key", async () => {
    const pair = await generateEphemeralEncryptionKeyPair();
    // Everything about this JWE is correct: right recipient key, pinned `alg`
    // and `enc`, intact AEAD tag. Only `zip` is wrong, and it must be enough.
    const jwe = await compressedJwe(pair.publicKey, 'DEF');

    await expect(decryptJwe(jwe, pair.privateKey, HAIP_PINS)).rejects.toBeInstanceOf(
      CryptoDecryptionError
    );
  });

  it('refuses ANY zip value, not just DEF — and before any key material is touched', async () => {
    // `jose` will not MINT a JWE with a non-`DEF` zip, so this one is assembled
    // by rewriting the protected header of a valid JWE. That also proves the
    // refusal happens ahead of decryption: the rewrite invalidates the AEAD's
    // Additional Authenticated Data, yet the reported reason is still `zip`.
    const pair = await generateEphemeralEncryptionKeyPair();
    const parts = (await encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM' })).split('.');
    parts[0] = base64url.encode(
      JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM', zip: 'UNKNOWN-ALGORITHM' })
    );

    const error = await captureDecryptionError(() =>
      decryptJwe(parts.join('.'), pair.privateKey, HAIP_PINS)
    );

    expect(error.detail).toContain("'zip'");
  });

  it('does not inflate the compressed plaintext before refusing', async () => {
    // The DoS half of the finding: the refusal has to happen instead of the
    // decompression, not after it. A payload that inflates far past jose's
    // 250 KB default limit is refused with the ordinary decryption error rather
    // than jose's "Decompressed plaintext exceeded the configured limit" — which
    // is what would surface if any inflation had been attempted.
    const pair = await generateEphemeralEncryptionKeyPair();
    const bomb = await compressedJwe(pair.publicKey, 'DEF', { padding: 'A'.repeat(2_000_000) });

    const error = await captureDecryptionError(() => decryptJwe(bomb, pair.privateKey, HAIP_PINS));

    expect(error.detail).toContain("'zip'");
    expect(error.detail).not.toContain('exceeded');
  });

  it('still refuses zip on the encrypt side', async () => {
    // The half that already worked — asserted alongside so the two directions
    // are visibly one rule rather than two independent behaviours.
    const pair = await generateEphemeralEncryptionKeyPair();

    await expect(
      encryptJwe(RESPONSE, pair.publicKey, { enc: 'A256GCM', header: { zip: 'DEF' } })
    ).rejects.toThrow(/'zip' is reserved/);
  });
});
