/**
 * PKCE pair for OAuth 2.1 Authorization Code Flow (RFC 7636).
 * Client generates, stores codeVerifier, sends codeChallenge in authorize request.
 */
export interface PkcePair {
  /** Cryptographically random string (43 chars base64url); send to token endpoint */
  codeVerifier: string;
  /** BASE64URL(SHA256(codeVerifier)); send in authorize request as code_challenge */
  codeChallenge: string;
}
