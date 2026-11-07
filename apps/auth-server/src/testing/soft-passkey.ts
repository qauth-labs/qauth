import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from 'node:crypto';

/**
 * A SOFTWARE PASSKEY FOR THE TESTS (#651): one ES256 credential (P-256,
 * COSE algorithm -7), held in memory, which answers a `webauthn_get`
 * ceremony as a browser posts it: `PublicKeyCredential.toJSON()` of an
 * assertion, as a JSON string; and, for a registration (#655), the
 * `webauthn_create` ceremony, with a `none` attestation. Its authenticator data names the RP ID's hash,
 * the user-presence flag, the user-verification flag unless a test turns it
 * off, and a counter that grows with each assertion; its signature is the
 * DER-encoded ECDSA signature over the authenticator data and the hash of the
 * client data, as WebAuthn Level 3 §6.3.3 has an authenticator sign.
 *
 * Never part of the server: the tests store its {@link SoftPasskey.credentialData}
 * on an account as an enrolment would, and answer with {@link SoftPasskey.assert}.
 */

/** The request options a `webauthn_get` step carries. */
export interface SoftPasskeyRequest {
  readonly challenge: string;
  readonly rpId: string;
}

/** The creation options a `webauthn_create` step carries, as far as a registration reads them. */
export interface SoftPasskeyCreation {
  readonly challenge: string;
  readonly rp: { readonly id: string };
}

/** What one assertion may change. */
export interface SoftAssertionOptions {
  /** Whether the authenticator verified the user (the UV flag). Default `true`. */
  readonly userVerified?: boolean;
  /** The origin the browser writes in the client data. Default `https://<rpId>`. */
  readonly origin?: string;
}

export interface SoftPasskey {
  /** The credential id, base64url: the row's `external_sub`. */
  readonly credentialId: string;
  /** The account's user handle, base64url. */
  readonly userHandle: string;
  /** The row's `credential_data`, as the WebAuthn provider stores it after a registration. */
  readonly credentialData: Record<string, unknown>;
  /** The browser's answer to `request`, as the page posts it in `webauthn_response`. */
  assert(request: SoftPasskeyRequest, options?: SoftAssertionOptions): string;
  /**
   * The browser's answer to a registration's `options` (#655), as the page
   * posts it in `webauthn_response`: this credential, created for the RP ID
   * the options name, with a `none` attestation and a sign counter of 0.
   */
  create(options: SoftPasskeyCreation, assertion?: SoftAssertionOptions): string;
}

const b64url = (bytes: Buffer): string => bytes.toString('base64url');
const sha256 = (data: Buffer | string): Buffer => createHash('sha256').update(data).digest();

/** The COSE_Key (RFC 9053 §7.1.1) of an EC2 P-256 public key with `alg` -7, CBOR-encoded. */
function coseKeyOf(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: 'jwk' });
  if (jwk.x === undefined || jwk.y === undefined) throw new Error('not an EC public key');
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  return Buffer.concat([
    // map(5): 1 (kty) → 2 (EC2), 3 (alg) → -7 (ES256), -1 (crv) → 1 (P-256)
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]),
    // -2 (x) → bytes(32), -3 (y) → bytes(32)
    Buffer.from([0x21, 0x58, 0x20]),
    x,
    Buffer.from([0x22, 0x58, 0x20]),
    y,
  ]);
}

/** A CBOR head (RFC 8949 §3) of major type `major` and argument `length`. */
function cborHead(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 256) return Buffer.from([(major << 5) | 24, length]);
  const head = Buffer.alloc(3);
  head[0] = (major << 5) | 25;
  head.writeUInt16BE(length, 1);
  return head;
}

const cborText = (text: string): Buffer =>
  Buffer.concat([cborHead(3, Buffer.byteLength(text)), Buffer.from(text, 'utf8')]);
const cborBytes = (bytes: Buffer): Buffer => Buffer.concat([cborHead(2, bytes.length), bytes]);

/** A new software passkey for an account of the RP `rpId`. */
export function softPasskey(rpId: string, userHandle = b64url(randomBytes(32))): SoftPasskey {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const credentialId = b64url(randomBytes(32));
  let counter = 0;
  return {
    credentialId,
    userHandle,
    credentialData: {
      public_key: b64url(coseKeyOf(publicKey)),
      algorithm: -7,
      sign_count: 0,
      transports: ['internal'],
      backup_eligible: false,
      backed_up: false,
      aaguid: '00000000-0000-0000-0000-000000000000',
      rp_id: rpId,
      user_handle: userHandle,
      nickname: null,
      created_at: Date.now(),
      last_used_at: null,
      sign_counter_regressed_at: null,
    },
    assert(request, options = {}) {
      counter += 1;
      const clientDataJSON = Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: request.challenge,
          origin: options.origin ?? `https://${request.rpId}`,
          crossOrigin: false,
        }),
        'utf8'
      );
      // UP (0x01), and UV (0x04) unless the test says the user was not verified.
      const flags = 0x01 | (options.userVerified === false ? 0 : 0x04);
      const signCount = Buffer.alloc(4);
      signCount.writeUInt32BE(counter);
      const authenticatorData = Buffer.concat([
        sha256(request.rpId),
        Buffer.from([flags]),
        signCount,
      ]);
      const signature = sign(
        'sha256',
        Buffer.concat([authenticatorData, sha256(clientDataJSON)]),
        privateKey
      );
      return JSON.stringify({
        id: credentialId,
        rawId: credentialId,
        type: 'public-key',
        response: {
          clientDataJSON: b64url(clientDataJSON),
          authenticatorData: b64url(authenticatorData),
          signature: b64url(signature),
          userHandle,
        },
        authenticatorAttachment: 'platform',
        clientExtensionResults: {},
      });
    },
    create(options, assertion = {}) {
      const clientDataJSON = Buffer.from(
        JSON.stringify({
          type: 'webauthn.create',
          challenge: options.challenge,
          origin: assertion.origin ?? `https://${options.rp.id}`,
          crossOrigin: false,
        }),
        'utf8'
      );
      // UP (0x01), UV (0x04) unless the test says otherwise, AT (0x40): the
      // attested credential data follows (WebAuthn Level 3 §6.5.1).
      const flags = 0x01 | 0x40 | (assertion.userVerified === false ? 0 : 0x04);
      const rawId = Buffer.from(credentialId, 'base64url');
      const idLength = Buffer.alloc(2);
      idLength.writeUInt16BE(rawId.length);
      const authenticatorData = Buffer.concat([
        sha256(options.rp.id),
        Buffer.from([flags]),
        Buffer.alloc(4),
        // The AAGUID of an authenticator that names no model.
        Buffer.alloc(16),
        idLength,
        rawId,
        coseKeyOf(publicKey),
      ]);
      // { "fmt": "none", "attStmt": {}, "authData": <bytes> } (§8.7).
      const attestationObject = Buffer.concat([
        Buffer.from([0xa3]),
        cborText('fmt'),
        cborText('none'),
        cborText('attStmt'),
        Buffer.from([0xa0]),
        cborText('authData'),
        cborBytes(authenticatorData),
      ]);
      return JSON.stringify({
        id: credentialId,
        rawId: credentialId,
        type: 'public-key',
        response: {
          clientDataJSON: b64url(clientDataJSON),
          attestationObject: b64url(attestationObject),
          transports: ['internal'],
        },
        authenticatorAttachment: 'platform',
        clientExtensionResults: {},
      });
    },
  };
}
