import {
  generateKeyPairSync,
  type KeyObject,
  sign as signBytes,
  X509Certificate,
} from 'node:crypto';

/**
 * Minimal X.509 certificate factory for the status-path tests (issue #297).
 *
 * ## Why this exists instead of checked-in fixtures
 *
 * `status-list-chain.ts` has to be tested against expired certificates,
 * self-signed leaves, chains that reach no anchor, chains that smuggle the
 * anchor in, non-CA intermediates and SAN mismatches. Static PEM fixtures
 * cannot express "expired relative to now" without either a fixed clock in
 * every test or a fixture that starts failing on a future date, and generating
 * them would need a certificate library — a new dependency in a workspace whose
 * lockfile is contended.
 *
 * So the tests build certificates from `node:crypto` primitives plus about a
 * hundred lines of DER. Only what the tests exercise is implemented: ECDSA
 * P-256 keys, `ecdsa-with-SHA256`, a single-CN name, a validity window,
 * `basicConstraints` and `dNSName` SANs. It is a TEST helper and lives under
 * `test/` (excluded from coverage) — it is not, and must not become, a
 * certificate-issuing utility.
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
  IA5_STRING: 0x16,
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
  if ((bytes[0] as number) & 0x80) bytes.unshift(0x00);
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
  const inner = isCa ? der(TAG.BOOLEAN, Buffer.from([0xff])) : Buffer.alloc(0);
  return extension('2.5.29.19', true, der(TAG.SEQUENCE, inner));
}

/** `subjectAltName` holding `dNSName` entries (`[2] IMPLICIT IA5String`). */
function subjectAltName(dnsNames: readonly string[]): Buffer {
  const names = dnsNames.map((name) => der(0x80 | 2, Buffer.from(name, 'ascii')));
  return extension('2.5.29.17', false, der(TAG.SEQUENCE, Buffer.concat(names)));
}

/** An EC P-256 key pair in the shape the fixtures pass around. */
export interface TestKeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

/** Generate an EC P-256 key pair. */
export function generateTestKeyPair(): TestKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { privateKey, publicKey };
}

/** Generate an Ed25519 key pair, for the unsupported-leaf-key test. */
export function generateEd25519TestKeyPair(): TestKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privateKey, publicKey };
}

/** A built test certificate and everything a test needs to use it. */
export interface TestCertificate {
  readonly certificate: X509Certificate;
  readonly pem: string;
  readonly der: Buffer;
  /** Standard-alphabet base64 DER, i.e. an `x5c` entry. */
  readonly x5c: string;
  readonly keys: TestKeyPair;
  readonly subject: string;
}

/** Inputs for {@link createTestCertificate}. */
export interface CreateTestCertificateOptions {
  /** CN of the certificate. Also the issuer CN when self-signed. */
  readonly subject: string;
  /** Issuer; omit for a self-signed certificate. */
  readonly issuer?: TestCertificate;
  /** Whether `basicConstraints` marks this as a CA. Defaults to `false`. */
  readonly ca?: boolean;
  /** `dNSName` SAN entries. */
  readonly dnsNames?: readonly string[];
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  /** Supply a key pair to reuse; one is generated otherwise. */
  readonly keys?: TestKeyPair;
  /** Serial number. Defaults to a counter. */
  readonly serial?: number;
}

let nextSerial = 1;

/**
 * Build a signed X.509 v3 certificate.
 *
 * @param options - see {@link CreateTestCertificateOptions}.
 * @returns the certificate plus its DER, PEM, `x5c` form and keys.
 */
export function createTestCertificate(options: CreateTestCertificateOptions): TestCertificate {
  const keys = options.keys ?? generateTestKeyPair();
  const notBefore = options.notBefore ?? new Date(Date.now() - 60_000);
  const notAfter = options.notAfter ?? new Date(Date.now() + 3_600_000);
  const issuerName = options.issuer?.subject ?? options.subject;
  const signingKey = options.issuer?.keys.privateKey ?? keys.privateKey;
  const serial = options.serial ?? nextSerial++;

  const extensions: Buffer[] = [basicConstraints(options.ca === true)];
  if (options.dnsNames !== undefined && options.dnsNames.length > 0) {
    extensions.push(subjectAltName(options.dnsNames));
  }

  const spki = keys.publicKey.export({ type: 'spki', format: 'der' });

  const tbs = der(
    TAG.SEQUENCE,
    Buffer.concat([
      contextConstructed(0, derInteger(2)),
      derInteger(serial),
      ecdsaWithSha256(),
      commonName(issuerName),
      der(TAG.SEQUENCE, Buffer.concat([utcTime(notBefore), utcTime(notAfter)])),
      commonName(options.subject),
      Buffer.from(spki),
      contextConstructed(3, der(TAG.SEQUENCE, Buffer.concat(extensions))),
    ])
  );

  // The `AlgorithmIdentifier` above is hard-coded to `ecdsa-with-SHA256`, so
  // the ISSUING key must be EC. A leaf key may be Ed25519 (that is how the
  // unsupported-leaf-key rejection is exercised) — such a leaf is issued by an
  // EC CA, never self-signed.
  if (signingKey.asymmetricKeyType !== 'ec') {
    throw new Error('Test certificates must be signed by an EC P-256 key.');
  }
  const signature = signBytes('sha256', tbs, signingKey);

  const certificateDer = der(
    TAG.SEQUENCE,
    Buffer.concat([
      tbs,
      ecdsaWithSha256(),
      der(TAG.BIT_STRING, Buffer.concat([Buffer.from([0x00]), signature])),
    ])
  );

  const certificate = new X509Certificate(certificateDer);

  return {
    certificate,
    pem: certificate.toString(),
    der: certificateDer,
    x5c: certificateDer.toString('base64'),
    keys,
    subject: options.subject,
  };
}
