/**
 * Extract JWT token from Authorization header
 * Format: "Bearer <token>"
 *
 * @param authHeader - Authorization header value
 * @returns JWT token string or null if header is missing or invalid
 *
 * @example
 * ```typescript
 * const token = extractJWTFromHeader(request.headers.authorization);
 * if (!token) {
 *   throw new Error('Missing or invalid Authorization header');
 * }
 * ```
 */
export function extractJWTFromHeader(authHeader: string | undefined): string | null {
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }

  return parts[1];
}

/** The access token of an `Authorization` header and the scheme it came under. */
export interface AccessTokenCredential {
  /** `Bearer` (RFC 6750 §2.1) or `DPoP` (RFC 9449 §7.1). */
  scheme: 'Bearer' | 'DPoP';
  token: string;
}

/**
 * Extract the access token from an `Authorization` header that uses the
 * `Bearer` scheme or, when `allowDpop` is set, the `DPoP` scheme (RFC 9449
 * §7.1, whose credential syntax is Bearer's). The scheme is matched exactly,
 * as {@link extractJWTFromHeader} matches `Bearer`.
 *
 * Without `allowDpop` a `DPoP` header is no credential at all, exactly as
 * before DPoP: a server that does not verify DPoP proofs must not read one.
 *
 * @returns the scheme and token, or null if the header is missing or in
 *   another form
 */
export function extractAccessTokenCredential(
  authHeader: string | undefined,
  options: { allowDpop?: boolean } = {}
): AccessTokenCredential | null {
  // An empty token (`Bearer `) is no credential, as `requireJwt` has always
  // read it.
  const bearer = extractJWTFromHeader(authHeader);
  if (bearer) return { scheme: 'Bearer', token: bearer };
  if (!options.allowDpop || !authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'DPoP' || parts[1] === '') {
    return null;
  }
  return { scheme: 'DPoP', token: parts[1] };
}
