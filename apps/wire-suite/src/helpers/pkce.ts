import { createHash, randomBytes } from 'node:crypto';

/** A PKCE code verifier with its S256 challenge (RFC 7636 §4.1, §4.2). */
export interface PkcePair {
  readonly verifier: string;
  readonly challenge: string;
  readonly method: 'S256';
}

/** BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), RFC 7636 §4.2. */
export function s256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/**
 * A fresh verifier: 32 random octets, base64url-encoded to 43 characters, as
 * RFC 7636 §4.1 recommends. Computed here, not by the server's PKCE library, so
 * a wrong encoding on either side shows up as a refused exchange.
 */
export function createPkcePair(): PkcePair {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: s256Challenge(verifier), method: 'S256' };
}
