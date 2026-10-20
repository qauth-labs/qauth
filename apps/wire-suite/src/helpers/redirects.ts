import { CookieJar } from './cookie-jar';

/** One response on the way, in the order the requests were sent. */
export interface Hop {
  readonly method: string;
  readonly url: string;
  readonly status: number;
  /** The absolute `Location` the response pointed to, if it was a redirect. */
  readonly location?: string;
}

export interface FollowOptions {
  readonly method?: string;
  readonly headers?: Record<string, string>;
  /** Sent with the first request only, unless a 307 or 308 carries it on. */
  readonly body?: string | URLSearchParams;
  /**
   * Stop BEFORE requesting a URL this returns true for — typically the
   * client's redirect URI, which no server listens on during a test. The
   * redirect that pointed there is the last hop, and its `location` is the
   * authorization response.
   */
  readonly stopAt?: (url: URL) => boolean;
  /** Most requests to send. Default 10. */
  readonly maxHops?: number;
}

export interface FollowResult {
  /** The last response received. Its body has not been read. */
  readonly response: Response;
  readonly hops: readonly Hop[];
  /** Set when {@link FollowOptions.stopAt} stopped the chain: the URL not requested. */
  readonly stoppedAt?: URL;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Send a request and follow its redirects the way a browser would, with the
 * cookie jar carrying state between hops.
 *
 * - `fetch` runs with `redirect: 'manual'`, so every hop is visible and every
 *   `Set-Cookie` is stored before the next request.
 * - A 303, and a 301 or 302 answering a POST, turn into a GET without a body
 *   (Fetch standard, HTTP-redirect fetch, step 12). A 307 or 308 repeats the
 *   method and the body.
 * - A relative `Location` resolves against the URL that answered.
 *
 * @throws when the chain is longer than `maxHops` or a redirect has no `Location`
 */
export async function followRedirects(
  jar: CookieJar,
  startUrl: string | URL,
  options: FollowOptions = {}
): Promise<FollowResult> {
  const maxHops = options.maxHops ?? 10;
  const hops: Hop[] = [];
  let url = new URL(startUrl);
  let method = (options.method ?? 'GET').toUpperCase();
  let body = options.body;

  for (let sent = 0; sent < maxHops; sent++) {
    const headers = new Headers(options.headers);
    const cookie = jar.headerFor(url);
    if (cookie) headers.set('cookie', cookie);
    // A redirect that dropped the body drops its content type with it.
    if (body === undefined) headers.delete('content-type');

    const response = await fetch(url, { method, headers, body, redirect: 'manual' });
    jar.storeFrom(url, response);

    const locationHeader = response.headers.get('location');
    if (!REDIRECT_STATUSES.has(response.status)) {
      hops.push({ method, url: url.href, status: response.status });
      return { response, hops };
    }
    if (!locationHeader) {
      throw new Error(`${method} ${url.href} answered ${response.status} with no Location header`);
    }

    const next = new URL(locationHeader, url);
    hops.push({ method, url: url.href, status: response.status, location: next.href });
    // Redirect responses are not read; release the connection.
    await response.body?.cancel();

    if (options.stopAt?.(next)) {
      return { response, hops, stoppedAt: next };
    }

    if (
      response.status === 303 ||
      ((response.status === 301 || response.status === 302) && method === 'POST')
    ) {
      method = 'GET';
      body = undefined;
    }
    url = next;
  }

  throw new Error(
    `more than ${maxHops} requests following redirects from ${new URL(startUrl).href}: ` +
      hops.map((hop) => `${hop.status} ${hop.url}`).join(' -> ')
  );
}
