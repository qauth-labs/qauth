import { CookieJar } from './cookie-jar';
import { findForm, formBody } from './html-form';
import { followRedirects, type FollowResult, type Hop } from './redirects';

/**
 * One browser: a cookie jar and the redirects it follows, driving the server's
 * sign-in page (`/ui/login`) and consent screen (`/ui/consent`) the way a
 * person does, until the server sends it to the client's redirect URI.
 */

/** The account a browser signs in with. */
export interface BrowserCredentials {
  readonly email: string;
  readonly password: string;
}

/** A page the browser was shown on the way to the redirect URI. */
export type Page = 'sign-in' | 'consent';

export interface AuthorizationResponse {
  /** The redirect URI with the response parameters, as the browser was sent to it. */
  readonly url: URL;
  /** Its query: `code`, `state`, `iss`, or `error`, `error_description`, `state`, `iss`. */
  readonly params: URLSearchParams;
  /** The pages the browser was shown, in order. */
  readonly pages: readonly Page[];
  /** Every response on the way, in order. */
  readonly hops: readonly Hop[];
}

export interface AuthorizeOptions {
  /** The account to sign in with, should the server ask. */
  readonly credentials: BrowserCredentials;
  /** The button pressed on the consent screen. Default `allow`. */
  readonly decision?: 'allow' | 'deny';
  /** Whether "Remember this decision" stays ticked. Default true, as the page renders it. */
  readonly rememberConsent?: boolean;
}

const LOGIN_ACTION = '/ui/login';
const CONSENT_ACTION = '/ui/consent';

/** The most pages one authorization may show: sign-in, then consent. */
const MAX_PAGES = 3;

/** Whether `url` is the redirect URI, whatever query the server added. */
function isRedirectTarget(url: URL, redirectUri: URL): boolean {
  return url.origin === redirectUri.origin && url.pathname === redirectUri.pathname;
}

export class Browser {
  readonly jar = new CookieJar();

  /**
   * Open an authorization URL and act as the user until the server sends the
   * browser to `redirectUri`: sign in with `credentials` when the server shows
   * the sign-in page, and press `decision` when it shows the consent screen.
   * The redirect URI itself is never requested.
   *
   * @throws when the server answers with anything but a redirect, the sign-in
   *   page or the consent screen, when it shows the sign-in page again after
   *   the credentials were submitted, or after more than three pages
   */
  async authorize(
    authorizationUrl: URL,
    redirectUri: string,
    options: AuthorizeOptions
  ): Promise<AuthorizationResponse> {
    const target = new URL(redirectUri);
    const stopAt = (url: URL) => isRedirectTarget(url, target);
    const pages: Page[] = [];
    const hops: Hop[] = [];

    let result: FollowResult = await followRedirects(this.jar, authorizationUrl, { stopAt });
    for (;;) {
      hops.push(...result.hops);
      if (result.stoppedAt) {
        return { url: result.stoppedAt, params: result.stoppedAt.searchParams, pages, hops };
      }
      const last = result.hops[result.hops.length - 1];
      const html = await result.response.text();
      const context = `${last.method} ${last.url} answered ${result.response.status}: ${html.slice(0, 300)}`;
      if (pages.length >= MAX_PAGES) {
        throw new Error(`more than ${MAX_PAGES} pages before the redirect URI — ${context}`);
      }

      const login = findForm(html, LOGIN_ACTION);
      const consent = login ? undefined : findForm(html, CONSENT_ACTION);
      let body: URLSearchParams;
      let action: string;
      if (login) {
        if (pages.includes('sign-in')) {
          throw new Error(
            `the server refused to sign in ${options.credentials.email} and showed the sign-in ` +
              `page again. If it requires verified accounts (REQUIRE_VERIFIED_ACCOUNT, on by ` +
              `default), point QAUTH_WIRE_MAIL_URL at the mail sink it delivers to — ${context}`
          );
        }
        pages.push('sign-in');
        body = formBody(login, {
          set: { email: options.credentials.email, password: options.credentials.password },
        });
        action = login.action;
      } else if (consent) {
        pages.push('consent');
        body = formBody(consent, {
          set: options.rememberConsent === false ? { allow_forever: null } : {},
          press: options.decision ?? 'allow',
        });
        action = consent.action;
      } else {
        throw new Error(`expected a redirect, the sign-in page or the consent screen — ${context}`);
      }

      result = await followRedirects(this.jar, new URL(action, last.url), {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
        stopAt,
      });
    }
  }
}
