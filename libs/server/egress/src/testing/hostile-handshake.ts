import { randomBytes } from 'node:crypto';

import { commonName, der, integer, oid, sequence, utcTime } from './test-certificate';

/**
 * TEST SUPPORT — a TLS host that keeps its client inside OpenSSL
 * (ANT-2026-3OJSXV7G), for the pool's test that a fetch process stuck there is
 * killed at its deadline. Ported from the auth server's `x509-der.ts` and
 * `ssrf-safe-fetch.test.ts`, which this library may not import.
 */

/** `base ** exponent mod modulus` over bigints. */
function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if ((e & 1n) === 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

function bigInteger(value: bigint): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  const bytes = Buffer.from(hex, 'hex');
  // A leading bit of 1 would make the INTEGER negative.
  return der(0x02, (bytes[0] & 0x80) !== 0 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes);
}

/**
 * A 658-bit field prime of the form `15·2^654 + 1`. A modular square root
 * modulo it is Tonelli-Shanks with 654 rounds.
 */
const SLOW_SQUARE_ROOT_PRIME = 15n * 2n ** 654n + 1n;

let serial = 1;

/**
 * DER of an UNSIGNED certificate whose subject key is an EC point on a curve
 * spelled out in the key itself, over {@link SLOW_SQUARE_ROOT_PRIME}. Its
 * points are compressed with x = 0 on `y² = x³ + n²` (n the smallest quadratic
 * non-residue), so OpenSSL decodes them with a slow modular square root while
 * it parses the certificate, before anything is verified: a large fraction of
 * a second per certificate, in one synchronous call for the whole message.
 */
export function explicitCurveCertificate(): Buffer {
  const prime = SLOW_SQUARE_ROOT_PRIME;
  let nonResidue = 2n;
  while (modPow(nonResidue, (prime - 1n) / 2n, prime) === 1n) nonResidue += 1n;

  const fieldBytes = Math.ceil(prime.toString(2).length / 8);
  const compressedPoint = Buffer.concat([
    Buffer.from([2 + Number(nonResidue % 2n)]),
    Buffer.alloc(fieldBytes),
  ]);
  const curveB = Buffer.alloc(2);
  curveB.writeUInt16BE(Number(nonResidue * nonResidue));

  const ecParameters = sequence(
    integer(1),
    sequence(oid('1.2.840.10045.1.1'), bigInteger(prime)),
    sequence(der(0x04, Buffer.from([0])), der(0x04, curveB)),
    der(0x04, compressedPoint),
    integer(7)
  );
  const subjectPublicKeyInfo = sequence(
    sequence(oid('1.2.840.10045.2.1'), ecParameters),
    der(0x03, Buffer.from([0]), compressedPoint)
  );
  const ed25519 = sequence(oid('1.3.101.112'));
  const tbs = sequence(
    der(0xa0, integer(2)),
    integer(serial++),
    ed25519,
    commonName('unsigned issuer'),
    sequence(utcTime(new Date(Date.now() - 3_600_000)), utcTime(new Date(Date.now() + 3_600_000))),
    commonName('unsigned subject'),
    subjectPublicKeyInfo
  );
  return sequence(tbs, ed25519, der(0x03, Buffer.alloc(65)));
}

/**
 * The server's first TLS 1.2 flight — ServerHello and Certificate — written by
 * hand, so that the Certificate message can carry certificates no TLS server
 * would load. ECDHE-RSA-AES128-GCM-SHA256 is picked from the client's offer;
 * the empty `renegotiation_info` is what OpenSSL 3 insists on before it reads
 * further.
 */
export function serverFirstFlight(certificates: readonly Buffer[]): Buffer {
  const uint16 = (n: number) => Buffer.from([n >> 8, n & 0xff]);
  const uint24 = (n: number) => Buffer.from([n >> 16, (n >> 8) & 0xff, n & 0xff]);
  const message = (type: number, body: Buffer) =>
    Buffer.concat([Buffer.from([type]), uint24(body.length), body]);
  const serverHello = message(
    2,
    Buffer.concat([
      Buffer.from([3, 3]),
      randomBytes(32),
      Buffer.from([0]),
      Buffer.from([0xc0, 0x2f]),
      Buffer.from([0]),
      uint16(5),
      Buffer.from([0xff, 0x01, 0x00, 0x01, 0x00]),
    ])
  );
  const list = Buffer.concat(
    certificates.map((cert) => Buffer.concat([uint24(cert.length), cert]))
  );
  const handshake = Buffer.concat([
    serverHello,
    message(11, Buffer.concat([uint24(list.length), list])),
  ]);
  const records: Buffer[] = [];
  for (let offset = 0; offset < handshake.length; offset += 16_384) {
    const fragment = handshake.subarray(offset, offset + 16_384);
    records.push(Buffer.from([22, 3, 3]), uint16(fragment.length), fragment);
  }
  return Buffer.concat(records);
}
