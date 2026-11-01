import { generateKeyPairSync, type KeyObject, sign } from 'node:crypto';

/**
 * TEST SUPPORT — the smallest X.509 certificate `node:crypto` parses, naming
 * a given EC P-256 public key (#546).
 *
 * `signRequestObject` reads only the leaf's public key: it checks that the
 * certificate names the key it signs with, and leaves chain validation to the
 * auth server's boot and to the wallet. So this builds a v3 certificate with
 * one common name, a validity window and no extension, signed by a throwaway
 * key. It must not become a certificate-issuing utility.
 */

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let remaining = length; remaining > 0; remaining >>= 8) bytes.unshift(remaining & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

const SEQUENCE = 0x30;
/** `ecdsa-with-SHA256` (1.2.840.10045.4.3.2). */
const ECDSA_WITH_SHA256 = der(SEQUENCE, Buffer.from('06082a8648ce3d040302', 'hex'));

function commonName(value: string): Buffer {
  // SET { SEQUENCE { id-at-commonName, UTF8String } }
  const attribute = der(
    SEQUENCE,
    Buffer.concat([Buffer.from('0603550403', 'hex'), der(0x0c, Buffer.from(value, 'utf8'))])
  );
  return der(SEQUENCE, der(0x31, attribute));
}

function utcTime(date: Date): Buffer {
  const text = date.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z';
  return der(0x17, Buffer.from(text, 'ascii'));
}

/**
 * A certificate for `publicKey`, as the standard-base64 DER an `x5c` member
 * holds. Fresh P-256 key when none is given.
 */
export function testCertificateFor(
  publicKey: KeyObject = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey,
  subject = 'verifier.example.test'
): string {
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const tbs = der(
    SEQUENCE,
    Buffer.concat([
      der(0xa0, Buffer.from('020102', 'hex')), // [0] version v3
      Buffer.from('020101', 'hex'), // serial 1
      ECDSA_WITH_SHA256,
      commonName('test issuer'),
      der(
        SEQUENCE,
        Buffer.concat([
          utcTime(new Date(Date.UTC(2020, 0, 1))),
          utcTime(new Date(Date.UTC(2049, 0, 1))),
        ])
      ),
      commonName(subject),
      Buffer.from(publicKey.export({ type: 'spki', format: 'der' })),
    ])
  );
  const signature = sign('sha256', tbs, issuer.privateKey);
  return der(
    SEQUENCE,
    Buffer.concat([tbs, ECDSA_WITH_SHA256, der(0x03, Buffer.concat([Buffer.from([0]), signature]))])
  ).toString('base64');
}
