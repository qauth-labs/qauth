/**
 * A small cookie jar, so a test can act as one browser across requests.
 *
 * It follows the parts of RFC 6265 §5.3 and §5.4 that a sign-in flow against
 * one server needs: host-only and `Domain` cookies, `Path`, `Secure`,
 * `Max-Age` and `Expires`, and deletion by expiry. It ignores `SameSite`: every
 * request a test makes is a top-level request to the server under test, and the
 * jar never sends a cookie to another host. It is written for this suite and
 * shares no code with the server.
 */

interface StoredCookie {
  readonly name: string;
  readonly value: string;
  /** Lower-case host the cookie was set by, or the `Domain` attribute. */
  readonly domain: string;
  /** True when no `Domain` attribute was given: the cookie goes to that host only. */
  readonly hostOnly: boolean;
  readonly path: string;
  readonly secure: boolean;
  /** Epoch milliseconds, or null for a session cookie. */
  readonly expiresAt: number | null;
}

/** RFC 6265 §5.1.4: the directory of the request path, used when `Path` is absent. */
function defaultPath(pathname: string): string {
  if (!pathname.startsWith('/')) return '/';
  const last = pathname.lastIndexOf('/');
  return last <= 0 ? '/' : pathname.slice(0, last);
}

/** RFC 6265 §5.1.3. */
function domainMatches(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

/** RFC 6265 §5.1.4. */
function pathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath.charAt(cookiePath.length) === '/';
}

/** Loopback hosts count as secure, as browsers treat `http://localhost`. */
function isSecureOrigin(url: URL): boolean {
  return (
    url.protocol === 'https:' ||
    url.hostname === 'localhost' ||
    url.hostname === '127.0.0.1' ||
    url.hostname === '[::1]'
  );
}

export class CookieJar {
  private cookies: StoredCookie[] = [];

  /** Store every `Set-Cookie` header of a response to a request for `url`. */
  storeFrom(url: string | URL, response: Response): void {
    for (const header of response.headers.getSetCookie()) {
      this.store(url, header);
    }
  }

  /** Store one `Set-Cookie` header value received from `url`. */
  store(url: string | URL, setCookie: string, now: number = Date.now()): void {
    const requestUrl = new URL(url);
    const [pair, ...attributes] = setCookie.split(';');
    const equals = pair.indexOf('=');
    if (equals <= 0) return;
    const name = pair.slice(0, equals).trim();
    const value = pair.slice(equals + 1).trim();
    if (name === '') return;

    const host = requestUrl.hostname.toLowerCase();
    let domain = host;
    let hostOnly = true;
    let path = defaultPath(requestUrl.pathname);
    let secure = false;
    let maxAge: number | undefined;
    let expires: number | undefined;

    for (const attribute of attributes) {
      const separator = attribute.indexOf('=');
      const key = (separator === -1 ? attribute : attribute.slice(0, separator))
        .trim()
        .toLowerCase();
      const attributeValue = separator === -1 ? '' : attribute.slice(separator + 1).trim();
      switch (key) {
        case 'domain': {
          const candidate = attributeValue.replace(/^\./, '').toLowerCase();
          if (candidate === '') break;
          // RFC 6265 §5.3 step 6: a server may not set a cookie for another domain.
          if (!domainMatches(host, candidate)) return;
          domain = candidate;
          hostOnly = false;
          break;
        }
        case 'path':
          path = attributeValue.startsWith('/') ? attributeValue : defaultPath(requestUrl.pathname);
          break;
        case 'secure':
          secure = true;
          break;
        case 'max-age': {
          const seconds = Number(attributeValue);
          if (/^-?\d+$/.test(attributeValue) && Number.isFinite(seconds)) maxAge = seconds;
          break;
        }
        case 'expires': {
          const at = Date.parse(attributeValue);
          if (!Number.isNaN(at)) expires = at;
          break;
        }
      }
    }

    // RFC 6265 §5.3 step 3: Max-Age wins over Expires.
    const expiresAt =
      maxAge !== undefined ? now + maxAge * 1000 : expires !== undefined ? expires : null;

    this.cookies = this.cookies.filter(
      (cookie) => !(cookie.name === name && cookie.domain === domain && cookie.path === path)
    );
    if (expiresAt !== null && expiresAt <= now) return;
    if (secure && !isSecureOrigin(requestUrl)) return;

    this.cookies.push({ name, value, domain, hostOnly, path, secure, expiresAt });
  }

  /** The `Cookie` header for a request to `url`, or undefined when no cookie applies. */
  headerFor(url: string | URL, now: number = Date.now()): string | undefined {
    const requestUrl = new URL(url);
    const host = requestUrl.hostname.toLowerCase();
    this.cookies = this.cookies.filter(
      (cookie) => cookie.expiresAt === null || cookie.expiresAt > now
    );
    const matching = this.cookies
      .filter((cookie) =>
        cookie.hostOnly ? host === cookie.domain : domainMatches(host, cookie.domain)
      )
      .filter((cookie) => pathMatches(requestUrl.pathname, cookie.path))
      .filter((cookie) => !cookie.secure || isSecureOrigin(requestUrl))
      // RFC 6265 §5.4 step 2: longer paths first.
      .sort((a, b) => b.path.length - a.path.length);
    if (matching.length === 0) return undefined;
    return matching.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ');
  }

  /** The value of the named cookie that would be sent to `url`, if any. */
  get(url: string | URL, name: string): string | undefined {
    const header = this.headerFor(url);
    if (!header) return undefined;
    for (const pair of header.split('; ')) {
      const equals = pair.indexOf('=');
      if (pair.slice(0, equals) === name) return pair.slice(equals + 1);
    }
    return undefined;
  }
}
