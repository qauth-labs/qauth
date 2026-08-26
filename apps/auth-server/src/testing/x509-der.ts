import {
  generateKeyPairSync,
  type KeyObject,
  sign as signBytes,
  X509Certificate,
} from 'node:crypto';

/**
 * TEST SUPPORT — a minimal X.509 certificate encoder for `apps/auth-server`'s
 * E2E fixtures (issues #297, #377).
 *
 * ## Why the app has its own encoder at all
 *
 * `libs/server/federation/src/status/test/x509-fixtures.ts` is the VERIFIER's
 * own fixture, and `apps/auth-server` is `scope:app`: the workspace's module
 * boundaries forbid it from importing `scope:server` libraries at all. That is
 * not an obstacle to work around, it is the property that makes these suites
 * interoperability tests — if QAuth's chain reader and this encoder ever
 * disagree about DER, the E2E fails rather than a shared helper absorbing the
 * divergence. `mock-wallet.ts` and `mock-status-list.ts` each make the same
 * argument for their own halves of the ecosystem.
 *
 * ## Why there is only ONE of it inside the app
 *
 * The boundary that buys independence is the app/lib one. Two encoders inside
 * `src/testing/` would buy nothing and cost the usual thing: one copy quietly
 * stops emitting an extension the other still does, and the suite that needed it
 * starts passing for the wrong reason. So the DER lives here and every in-app
 * fixture — the status issuer's chain, the verifier's own PKI — builds on it.
 *
 * ## What is implemented
 *
 * Only what those fixtures exercise: ECDSA P-256 keys, `ecdsa-with-SHA256`, a
 * single-CN name, a validity window, `basicConstraints`, `keyUsage` and
 * `dNSName` SANs. It is a TEST helper and must not become a certificate-issuing
 * utility.
 */

/** ASN.1 tag numbers used below. */
const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  UTC_TIME: 0x17,
} as const;

/** Encode a DER length header. */
function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Wrap `content` in a DER TLV with the given tag. */
function der(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

/** A context-specific constructed `[n]` wrapper. */
function contextConstructed(n: number, content: Buffer): Buffer {
  return der(0xa0 | n, content);
}

/** DER INTEGER from a non-negative JS integer. */
function derInteger(value: number): Buffer {
  const bytes: number[] = [];
  let remaining = value;
  do {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  } while (remaining > 0);
  // A leading bit of 1 would make the INTEGER negative.
  if (((bytes[0] as number) & 0x80) !== 0) bytes.unshift(0x00);
  return der(TAG.INTEGER, Buffer.from(bytes));
}

/** Encode a dotted OID string as DER. */
function derOid(dotted: string): Buffer {
  const parts = dotted.split('.').map((part) => Number.parseInt(part, 10));
  const first = (parts[0] as number) * 40 + (parts[1] as number);
  const bytes: number[] = [first];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f];
    let remaining = part >> 7;
    while (remaining > 0) {
      chunk.unshift((remaining & 0x7f) | 0x80);
      remaining >>= 7;
    }
    bytes.push(...chunk);
  }
  return der(TAG.OID, Buffer.from(bytes));
}

/** `AlgorithmIdentifier` for `ecdsa-with-SHA256` (no parameters). */
function ecdsaWithSha256(): Buffer {
  return der(TAG.SEQUENCE, derOid('1.2.840.10045.4.3.2'));
}

/** A `Name` holding a single CN. */
function commonName(value: string): Buffer {
  const attribute = der(
    TAG.SEQUENCE,
    Buffer.concat([derOid('2.5.4.3'), der(TAG.UTF8_STRING, Buffer.from(value, 'utf8'))])
  );
  return der(TAG.SEQUENCE, der(TAG.SET, attribute));
}

/** `UTCTime` as `YYMMDDHHMMSSZ`. */
function utcTime(date: Date): Buffer {
  const pad = (n: number): string => n.toString().padStart(2, '0');
  const text =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
  return der(TAG.UTC_TIME, Buffer.from(text, 'ascii'));
}

/** A single X.509 v3 extension. */
function extension(oid: string, critical: boolean, value: Buffer): Buffer {
  return der(
    TAG.SEQUENCE,
    Buffer.concat([
      derOid(oid),
      ...(critical ? [der(TAG.BOOLEAN, Buffer.from([0xff]))] : []),
      der(TAG.OCTET_STRING, value),
    ])
  );
}

/** `basicConstraints`; `cA` is omitted when false, per DER DEFAULT rules. */
function basicConstraints(isCa: boolean): Buffer {
  return extension(
    '2.5.29.19',
    true,
    der(TAG.SEQUENCE, isCa ? der(TAG.BOOLEAN, Buffer.from([0xff])) : Buffer.alloc(0))
  );
}

/** `subjectAltName` holding `dNSName` entries (`[2] IMPLICIT IA5String`). */
function subjectAltName(dnsNames: readonly string[]): Buffer {
  return extension(
    '2.5.29.17',
    false,
    der(
      TAG.SEQUENCE,
      Buffer.concat(dnsNames.map((name) => der(0x80 | 2, Buffer.from(name, 'ascii'))))
    )
  );
}

/** Bit positions in the `KeyUsage` BIT STRING (RFC 5280 §4.2.1.3). */
const KEY_USAGE_BIT = {
  digitalSignature: 0,
  nonRepudiation: 1,
  keyEncipherment: 2,
  dataEncipherment: 3,
  keyAgreement: 4,
  keyCertSign: 5,
  cRLSign: 6,
} as const;

/** A `keyUsage` bit name a fixture can assert. */
export type TestKeyUsage = keyof typeof KEY_USAGE_BIT;

/**
 * `keyUsage` as a DER BIT STRING (RFC 5280 §4.2.1.3).
 *
 * The named-bit-list form must carry no trailing zero bits under DER, so the
 * "unused bits" count is derived from the HIGHEST bit actually asserted rather
 * than fixed at zero. Getting that wrong would produce a certificate whose
 * extension QAuth's own reader parses differently from OpenSSL — which is
 * exactly the divergence an independent encoder exists to expose.
 */
function keyUsageExtension(usages: readonly TestKeyUsage[]): Buffer {
  let byte = 0;
  let highest = -1;
  for (const usage of usages) {
    const bit = KEY_USAGE_BIT[usage];
    byte |= 0x80 >> bit;
    if (bit > highest) highest = bit;
  }
  const content = highest < 0 ? Buffer.from([0x00]) : Buffer.from([7 - highest, byte]);
  return extension('2.5.29.15', true, der(TAG.BIT_STRING, content));
}

/** A built test certificate and everything a fixture needs to use it. */
export interface TestCertificate {
  /** PEM form — what an operator puts in an env variable. */
  readonly pem: string;
  /** DER bytes, i.e. what an `x509_hash` Client Identifier digests. */
  readonly der: Buffer;
  /** Standard-alphabet base64 DER, i.e. an `x5c` entry. */
  readonly x5c: string;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  readonly subject: string;
}

/** What {@link createTestCertificate} may vary. */
export interface CreateTestCertificateOptions {
  /** CN of the certificate. Also the issuer CN when self-signed. */
  readonly subject: string;
  /** Issuer; omit for a self-signed certificate. */
  readonly issuer?: TestCertificate;
  /** Whether `basicConstraints` marks this as a CA. Defaults to `false`. */
  readonly ca?: boolean;
  /**
   * `keyUsage` bits to assert. Omit for a certificate with NO `keyUsage`
   * extension — the unconstrained case RFC 5280 §4.2.1.3 leaves permissible.
   */
  readonly keyUsage?: readonly TestKeyUsage[];
  /** `dNSName` SAN entries. */
  readonly dnsNames?: readonly string[];
  readonly notBefore?: Date;
  readonly notAfter?: Date;
}

let nextSerial = 1;

/**
 * Build a signed X.509 v3 certificate with a fresh EC P-256 key.
 *
 * @param options - see {@link CreateTestCertificateOptions}.
 * @returns the certificate plus its DER, PEM, `x5c` form and keys.
 */
export function createTestCertificate(options: CreateTestCertificateOptions): TestCertificate {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const notBefore = options.notBefore ?? new Date(Date.now() - 3_600_000);
  const notAfter = options.notAfter ?? new Date(Date.now() + 30 * 24 * 3_600_000);

  const extensions: Buffer[] = [basicConstraints(options.ca === true)];
  if (options.keyUsage !== undefined) extensions.push(keyUsageExtension(options.keyUsage));
  if (options.dnsNames !== undefined && options.dnsNames.length > 0) {
    extensions.push(subjectAltName(options.dnsNames));
  }

  const tbs = der(
    TAG.SEQUENCE,
    Buffer.concat([
      contextConstructed(0, derInteger(2)),
      derInteger(nextSerial++),
      ecdsaWithSha256(),
      commonName(options.issuer?.subject ?? options.subject),
      der(TAG.SEQUENCE, Buffer.concat([utcTime(notBefore), utcTime(notAfter)])),
      commonName(options.subject),
      Buffer.from(publicKey.export({ type: 'spki', format: 'der' })),
      contextConstructed(3, der(TAG.SEQUENCE, Buffer.concat(extensions))),
    ])
  );

  const signature = signBytes('sha256', tbs, options.issuer?.privateKey ?? privateKey);

  const certificateDer = der(
    TAG.SEQUENCE,
    Buffer.concat([
      tbs,
      ecdsaWithSha256(),
      der(TAG.BIT_STRING, Buffer.concat([Buffer.from([0x00]), signature])),
    ])
  );

  return {
    pem: new X509Certificate(certificateDer).toString(),
    der: certificateDer,
    x5c: certificateDer.toString('base64'),
    privateKey,
    publicKey,
    subject: options.subject,
  };
}

/** Export a private key as the PKCS#8 PEM an operator puts in an env variable. */
export function toPkcs8Pem(key: KeyObject): string {
  return key.export({ type: 'pkcs8', format: 'pem' }).toString();
}
