import * as crypto from 'node:crypto';

import type { PkcePair } from '../types/pkce';

/** Regex for RFC 7636 code verifier: 43–128 chars [A-Za-z0-9._~-] */
const CODE_VERIFIER_REGEX = /^[A-Za-z0-9._~-]{43,128}$/;

/**
 * Generate a cryptographically random code verifier (RFC 7636).
 * Uses 32 octets (256 bits) random → base64url → 43 chars.
 *
 * @returns 43-character base64url-encoded string
 * @see https://www.rfc-editor.org/rfc/rfc7636
 *
 * @example
 * ```ts
 * const verifier = generateCodeVerifier();
 * // "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
 * ```
 */
export function generateCodeVerifier(): string {
  const bytes = crypto.randomBytes(32);
  return bytes.toString('base64url');
}

/**
 * Validate code verifier format per RFC 7636.
 * Must be 43–128 characters, matching [A-Za-z0-9._~-].
 *
 * @param verifier - Value to check (any type)
 * @returns true if valid format
 * @see https://www.rfc-editor.org/rfc/rfc7636
 *
 * @example
 * ```ts
 * isValidCodeVerifierFormat('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'); // true
 * isValidCodeVerifierFormat('short'); // false
 * isValidCodeVerifierFormat(null); // false
 * ```
 */
export function isValidCodeVerifierFormat(verifier: unknown): boolean {
  if (verifier == null || typeof verifier !== 'string') {
    return false;
  }
  return CODE_VERIFIER_REGEX.test(verifier);
}

/**
 * Compute S256 code challenge from code verifier (RFC 7636).
 * challenge = BASE64URL(SHA256(ASCII(verifier))).
 *
 * @param verifier - Code verifier string
 * @returns 43-character base64url code challenge
 * @throws Error if verifier format is invalid
 * @see https://www.rfc-editor.org/rfc/rfc7636
 *
 * @example
 * ```ts
 * const challenge = generateCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
 * // "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
 * ```
 */
export function generateCodeChallenge(verifier: string): string {
  if (!isValidCodeVerifierFormat(verifier)) {
    throw new Error('Invalid code verifier format');
  }
  const digest = crypto.createHash('sha256').update(verifier, 'utf8').digest();
  return digest.toString('base64url');
}

/**
 * Verify code verifier against stored challenge (RFC 7636 S256).
 * Uses timing-safe comparison to prevent timing attacks.
 * Returns false for invalid verifier format or length mismatch (no throw).
 *
 * @param verifier - Code verifier from client
 * @param storedChallenge - Code challenge stored at authorize time
 * @returns true if verifier matches challenge
 * @see https://www.rfc-editor.org/rfc/rfc7636
 *
 * @example
 * ```ts
 * const ok = verifyCodeChallenge(verifier, storedChallenge);
 * ```
 */
export function verifyCodeChallenge(verifier: string, storedChallenge: string): boolean {
  if (!isValidCodeVerifierFormat(verifier)) {
    return false;
  }
  const computed = generateCodeChallenge(verifier);
  const computedBuf = Buffer.from(computed, 'utf8');
  const storedBuf = Buffer.from(storedChallenge, 'utf8');
  if (computedBuf.length !== storedBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(computedBuf, storedBuf);
}

/**
 * Generate a PKCE pair (verifier + challenge) for OAuth 2.1 (RFC 7636).
 * Client stores codeVerifier, sends codeChallenge in authorize request.
 *
 * @returns `{ codeVerifier, codeChallenge }`
 * @see https://www.rfc-editor.org/rfc/rfc7636
 *
 * @example
 * ```ts
 * const { codeVerifier, codeChallenge } = generatePkcePair();
 * // Store codeVerifier; send code_challenge=codeChallenge to /oauth/authorize
 * ```
 */
export function generatePkcePair(): PkcePair {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  return { codeVerifier, codeChallenge };
}
