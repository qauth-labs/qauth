/**
 * The parts of a session cookie value, for container suites (#493). They
 * cannot import `helpers/session-cookie`: it reads the environment at import,
 * before the harness has set it. Nothing here verifies the MAC; the server
 * does that.
 */

/** The session cookie's name, `SESSION_COOKIE_NAME`, written out for the same reason. */
export const SESSION_COOKIE = '__Host-qauth_session';

/** What a `<kid>.<payload>.<mac>` session cookie value holds, unverified. */
export interface SessionCookieParts {
  readonly kid: string;
  /** The listed session ids. */
  readonly sessionIds: readonly string[];
  /** The active session id: the one the browser acts as. */
  readonly sid: string;
  readonly mac: string;
}

/** Split a session cookie value into its parts; throws when it is not `<kid>.<payload>.<mac>`. */
export function sessionCookieParts(value: string): SessionCookieParts {
  const parts = value.split('.');
  if (parts.length !== 3) throw new Error(`not a <kid>.<payload>.<mac> cookie value: ${value}`);
  const [kid, payload, mac] = parts;
  const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
    s: string[];
    a: string;
  };
  return { kid, sessionIds: decoded.s, sid: decoded.a, mac };
}

/** The active session id a session cookie value names. */
export function sessionIdOfCookie(value: string): string {
  return sessionCookieParts(value).sid;
}
