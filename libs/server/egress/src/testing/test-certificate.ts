import { generateKeyPairSync, type KeyObject, sign, X509Certificate } from 'node:crypto';

/**
 * TEST SUPPORT — the smallest X.509 encoder the egress tests need: a CA and a
 * server certificate it signs, for local TLS servers. ECDSA P-256 keys,
 * `ecdsa-with-SHA256`, a one-CN name, `basicConstraints`, `keyUsage` on the CA
 * and `dNSName` SANs on the server certificate. The library may import no
 * other workspace library but core and shared ones, so it does not share the
 * auth server's encoder (`apps/auth-server/src/testing/x509-der.ts`).
 */

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let rest = length; rest > 0; rest >>= 8) bytes.unshift(rest & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, ...content: Buffer[]): Buffer {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

const sequence = (...content: Buffer[]): Buffer => der(0x30, ...content);

function oid(dotted: string): Buffer {
  const [first, second, ...rest] = dotted.split('.').map(Number);
  const bytes = [first * 40 + second];
  for (const part of rest) {
    const chunk = [part & 0x7f];
    for (let more = part >> 7; more > 0; more >>= 7) chunk.unshift((more & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return der(0x06, Buffer.from(bytes));
}

function integer(value: number): Buffer {
  const bytes: number[] = [];
  let rest = value;
  do {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  } while (rest > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return der(0x02, Buffer.from(bytes));
}

const ecdsaWithSha256 = (): Buffer => sequence(oid('1.2.840.10045.4.3.2'));

const commonName = (cn: string): Buffer =>
  sequence(der(0x31, sequence(oid('2.5.4.3'), der(0x0c, Buffer.from(cn, 'utf8')))));

function utcTime(date: Date): Buffer {
  const text = date
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z')
    .slice(2);
  return der(0x17, Buffer.from(text, 'ascii'));
}

const extension = (id: string, critical: boolean, value: Buffer): Buffer =>
  sequence(oid(id), ...(critical ? [der(0x01, Buffer.from([0xff]))] : []), der(0x04, value));

/** A certificate and its private key. */
export interface TestCertificate {
  readonly pem: string;
  readonly keyPem: string;
  readonly privateKey: KeyObject;
  readonly subject: string;
}

let serial = 1;

/**
 * A CA certificate when `issuer` is omitted, else a server certificate for
 * `dnsNames` that `issuer` signs.
 */
export function createTestCertificate(options: {
  subject: string;
  issuer?: TestCertificate;
  dnsNames?: readonly string[];
}): TestCertificate {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const isCa = options.issuer === undefined;
  const extensions = isCa
    ? [
        extension('2.5.29.19', true, sequence(der(0x01, Buffer.from([0xff])))),
        // keyCertSign is bit 5: the byte 0x04, with 2 unused bits.
        extension('2.5.29.15', true, der(0x03, Buffer.from([0x02, 0x04]))),
      ]
    : [
        extension('2.5.29.19', true, sequence()),
        extension(
          '2.5.29.17',
          false,
          sequence(...(options.dnsNames ?? []).map((name) => der(0x82, Buffer.from(name, 'ascii'))))
        ),
      ];
  const now = Date.now();
  const tbs = sequence(
    der(0xa0, integer(2)),
    integer(serial++),
    ecdsaWithSha256(),
    commonName(options.issuer?.subject ?? options.subject),
    sequence(utcTime(new Date(now - 3_600_000)), utcTime(new Date(now + 24 * 3_600_000))),
    commonName(options.subject),
    Buffer.from(publicKey.export({ type: 'spki', format: 'der' })),
    der(0xa3, sequence(...extensions))
  );
  const signature = sign('sha256', tbs, options.issuer?.privateKey ?? privateKey);
  const certificate = sequence(tbs, ecdsaWithSha256(), der(0x03, Buffer.from([0]), signature));
  return {
    pem: new X509Certificate(certificate).toString(),
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    privateKey,
    subject: options.subject,
  };
}
