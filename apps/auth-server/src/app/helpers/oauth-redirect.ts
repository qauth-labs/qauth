/**
 * Build redirect URL for authorize success or error (RFC 6749 4.1.2, 4.1.2.1).
 * redirect_uri is exact; we append ?key=value&...
 * Fragment is stripped (OAuth 2.1).
 */
export function buildRedirectUrl(
  redirectUri: string,
  params:
    | { code: string; state?: string }
    | { error: string; error_description?: string; state?: string }
): string {
  const u = new URL(redirectUri);
  u.hash = '';
  for (const [k, v] of Object.entries(params)) {
    if (v != null && v !== '') u.searchParams.set(k, v);
  }
  return u.toString();
}
