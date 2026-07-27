import { sign as signBytes } from 'node:crypto';
import { deflateSync } from 'node:zlib';

import type { TestCertificate } from './x509-fixtures';

/**
 * Status List Token fixtures for the #297 tests.
 *
 * The JWS is assembled by hand rather than through `@qauth-labs/core-crypto`'s
 * `sign()` on purpose: that helper always stamps `iat`, `exp` and `aud`, and
 * half of what has to be tested here is a token with a member MISSING or WRONG
 * (`typ` of the wrong media type, absent `iat`, a `sub` that does not match the
 * fetched URI, a signature that does not verify). A signer that cannot produce
 * a malformed token cannot be used to test rejection of malformed tokens.
 *
 * `dsaEncoding: 'ieee-p1363'` is what makes this a JWS rather than an X.509
 * signature: JOSE ES256 is the raw 64-byte R‖S pair, while `node:crypto`
 * defaults to the DER-wrapped form.
 */

/** base64url without padding. */
function b64url(input: Buffer | string): string {
  return Buffer.from(input as never).toString('base64url');
}

/**
 * Pack status values into the draft-14 §4.1 byte array and compress it.
 *
 * Entries are packed from the LEAST significant bit of each byte upward, which
 * is the direction a status list's correctness hinges on — see
 * `status-list-bits.ts`.
 *
 * @param entries - status value per index, in index order.
 * @param bits - 1, 2, 4 or 8.
 * @returns the `status_list.lst` value: base64url of a ZLIB stream.
 */
export function encodeStatusList(entries: readonly number[], bits: 1 | 2 | 4 | 8): string {
  const entriesPerByte = 8 / bits;
  const byteLength = Math.ceil(entries.length / entriesPerByte);
  const bytes = Buffer.alloc(byteLength);

  entries.forEach((value, index) => {
    const byteIndex = Math.floor(index / entriesPerByte);
    const shift = (index % entriesPerByte) * bits;
    bytes[byteIndex] = (bytes[byteIndex] as number) | ((value & ((1 << bits) - 1)) << shift);
  });

  return b64url(deflateSync(bytes));
}

/** Inputs for {@link signStatusListToken}. */
export interface SignStatusListTokenOptions {
  /** Protected-header members; merged over `{ alg: 'ES256' }`. */
  readonly header?: Record<string, unknown>;
  /** The full claims set, verbatim — nothing is added or defaulted. */
  readonly claims: Record<string, unknown>;
  /** The certificate whose PRIVATE key signs. */
  readonly signer: TestCertificate;
  /** Corrupt the signature so verification must fail. */
  readonly tamper?: boolean;
}

/**
 * Sign a compact ES256 JWS with complete control over header and claims.
 *
 * @param options - see {@link SignStatusListTokenOptions}.
 * @returns the compact JWS.
 */
export function signStatusListToken(options: SignStatusListTokenOptions): string {
  const header = { alg: 'ES256', ...options.header };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(options.claims))}`;

  const signature = signBytes('sha256', Buffer.from(signingInput, 'ascii'), {
    key: options.signer.keys.privateKey,
    dsaEncoding: 'ieee-p1363',
  });

  if (options.tamper === true) {
    signature[0] = signature[0] === 0 ? 1 : 0;
  }

  return `${signingInput}.${signature.toString('base64url')}`;
}
