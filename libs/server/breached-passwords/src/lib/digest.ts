import { createHash } from 'node:crypto';

/** A SHA-1 digest written as 40 hex characters, in either case. */
export const SHA1_HEX_PATTERN = /^[0-9A-Fa-f]{40}$/;

/** The length of a SHA-1 digest, in bytes. */
export const SHA1_BYTES = 20;

/**
 * The SHA-1 digest of the password's UTF-8 bytes, 40 upper-case hex
 * characters: what breach corpora such as Have I Been Pwned index.
 *
 * The password is hashed exactly as given; the caller decides which form it
 * checks (as typed, or the NFC form a credential stores). SHA-1 is not used
 * here for its strength: the breach corpora are indexed by it, and only its
 * first five hex characters ever leave the server (#635).
 */
export function passwordSha1(password: string): string {
  return createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
}

/** `sha1Hex` as 40 upper-case hex characters; a `TypeError` when it is not a SHA-1 digest. */
export function checkedSha1Hex(sha1Hex: unknown): string {
  if (typeof sha1Hex !== 'string' || !SHA1_HEX_PATTERN.test(sha1Hex)) {
    throw new TypeError('a breach list is searched with a SHA-1 digest of 40 hex characters');
  }
  return sha1Hex.toUpperCase();
}
