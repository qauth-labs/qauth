import { describe, expect, it } from 'vitest';

import { wireConfig } from '../../config';
import {
  authorizationRequest,
  authorizeAs,
  consentedBrowser,
  exchangeCode,
  issueCode,
  readTokenResponse,
  type SignedInBrowser,
} from '../../fixtures/authorization';
import { confidentialClient } from '../../fixtures/clients';
import { Browser } from '../../helpers/browser';
import { formBody, type HtmlForm, readForms } from '../../helpers/html-form';
import { call, operationUrl } from '../../helpers/operations';

/**
 * RP-initiated logout (#675): the end-session endpoint and its status page,
 * as an app and a browser see them. The app sends the browser to
 * `/oauth/end-session`; the browser comes back to a URI the app registered
 * (`post_logout_redirect_uris` of the seeded client, `seed/clients.json`),
 * signed out, or to a page of the server's own.
 */

const { baseUrl } = wireConfig();

/** The post-logout redirect URI `seed/clients.json` registers for the confidential client. Nothing listens on it. */
const RETURN_URI = 'http://127.0.0.1:9/wire-suite/signed-out';

/** The browser session cookie. */
const SESSION_COOKIE = '__Host-qauth_session';

/** The answer path of an Interaction API interaction, as the confirm form posts to it. */
const ANSWER_ACTION = /^\/interaction\/v1-rc\.0\/[A-Za-z0-9_-]{43}\/answer$/;

/** The end-session URL, for the cookie jar: both methods share it. */
const END_SESSION_URL = operationUrl('GET /oauth/end-session');

/** The `Cookie` header the browser sends to the end-session URL. */
function cookieOf(browser: Browser): Record<string, string> {
  const cookie = browser.jar.headerFor(END_SESSION_URL);
  return cookie === undefined ? {} : { cookie };
}

/** Send the browser to `GET /oauth/end-session` with `params` as the query. */
async function endSessionGet(browser: Browser, params: Record<string, string>): Promise<Response> {
  const response = await call('GET /oauth/end-session', {
    query: params,
    headers: cookieOf(browser),
  });
  browser.jar.storeFrom(END_SESSION_URL, response);
  return response;
}

/** Send the browser to `POST /oauth/end-session` with `params` as a form body. */
async function endSessionPost(browser: Browser, params: Record<string, string>): Promise<Response> {
  const response = await call('POST /oauth/end-session', {
    form: params,
    headers: cookieOf(browser),
  });
  browser.jar.storeFrom(END_SESSION_URL, response);
  return response;
}

/** A signed-in browser that consented to the seeded client, and an ID token of its session. */
async function signedInWithIdToken(): Promise<{ session: SignedInBrowser; idToken: string }> {
  const session = await consentedBrowser();
  const tokens = await readTokenResponse(await exchangeCode(await issueCode(session)));
  if (typeof tokens.id_token !== 'string') throw new Error('the code exchange issued no ID token');
  return { session, idToken: tokens.id_token };
}

/** A 303 back to the registered return URI, with `state` in its query. */
function expectReturned(response: Response, state: string): void {
  expect(response.status).toBe(303);
  expect(response.headers.get('cache-control')).toBe('no-store');
  const location = new URL(response.headers.get('location') ?? '');
  expect(`${location.origin}${location.pathname}`).toBe(RETURN_URI);
  expect(location.searchParams.get('state')).toBe(state);
}

/** The response deleted the session cookie: an empty value with `Max-Age=0`. */
function expectSessionCookieCleared(response: Response, session: SignedInBrowser): void {
  const line = response.headers
    .getSetCookie()
    .find((header) => header.startsWith(`${SESSION_COOKIE}=`));
  expect(line, 'no Set-Cookie for the session cookie').toBeDefined();
  expect(line).toMatch(new RegExp(`^${SESSION_COOKIE}=;`));
  expect(line).toMatch(/;\s*Max-Age=0(?:;|$)/i);
  expect(session.browser.jar.get(END_SESSION_URL, SESSION_COOKIE)).toBeUndefined();
}

/** The response left the session cookie alone. */
function expectSessionCookieKept(response: Response): void {
  const touched = response.headers
    .getSetCookie()
    .some((header) => header.startsWith(`${SESSION_COOKIE}=`));
  expect(touched).toBe(false);
}

/** The browser's session still answers an authorization request with a code, and no page. */
async function expectStillSignedIn(session: SignedInBrowser): Promise<void> {
  const { response } = await issueCode(session);
  expect(response.pages).toEqual([]);
}

/** The browser's next authorization request shows the sign-in page again. */
async function expectSignedOut(session: SignedInBrowser): Promise<void> {
  const response = await authorizeAs(session, authorizationRequest());
  expect(response.pages).toContain('sign-in');
  expect(response.params.get('code')).toBeTruthy();
}

/** An HTML page of the server's own, never a redirect. */
async function htmlPage(response: Response, status: number): Promise<string> {
  const text = await response.text();
  expect(response.status, text.slice(0, 300)).toBe(status);
  expect(response.headers.get('location')).toBeNull();
  expect(response.headers.get('content-type') ?? '').toMatch(/^text\/html\b/i);
  expect(response.headers.get('cache-control')).toBe('no-store');
  return text;
}

/** The confirm step's form on a page the end-session route drew. */
function confirmForm(html: string): HtmlForm {
  const form = readForms(html).find((one) => ANSWER_ACTION.test(one.action));
  if (form === undefined) throw new Error(`the page has no confirm form: ${html.slice(0, 300)}`);
  expect(form.method).toBe('POST');
  expect(form.buttons.map(([, value]) => value).sort()).toEqual(['logout', 'logout_all', 'stay']);
  return form;
}

/** Press a button of the confirm form, as the browser posts it from the server's page. */
async function answerConfirm(
  session: SignedInBrowser,
  form: HtmlForm,
  decision: 'logout' | 'logout_all' | 'stay'
): Promise<Response> {
  const url = new URL(form.action, END_SESSION_URL);
  const cookie = session.browser.jar.headerFor(url);
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: new URL(baseUrl).origin,
      'sec-fetch-site': 'same-origin',
      ...(cookie === undefined ? {} : { cookie }),
    },
    body: formBody(form, { press: decision }).toString(),
    redirect: 'manual',
  });
  session.browser.jar.storeFrom(url, response);
  return response;
}

/** What the status page says about `browser`. */
async function statusOf(browser: Browser): Promise<'signed in' | 'signed out'> {
  const html = await htmlPage(
    await call('GET /oauth/end-session/status', { headers: cookieOf(browser) }),
    200
  );
  if (/still signed in/i.test(html)) return 'signed in';
  expect(html).toMatch(/signed out/i);
  return 'signed out';
}

describe('[GET /oauth/end-session] OpenID Connect RP-Initiated Logout 1.0 — the end-session endpoint, by query', () => {
  it('ends the session for a valid id_token_hint and sends the browser back to the registered URI with state (§2, §3)', async () => {
    const { session, idToken } = await signedInWithIdToken();

    const response = await endSessionGet(session.browser, {
      id_token_hint: idToken,
      post_logout_redirect_uri: RETURN_URI,
      state: 'wire-logout-state',
    });

    expectReturned(response, 'wire-logout-state');
    expectSessionCookieCleared(response, session);
    await expectSignedOut(session);
  });

  it('accepts client_id beside the hint when it names the hint’s audience (§2)', async () => {
    const { session, idToken } = await signedInWithIdToken();

    const response = await endSessionGet(session.browser, {
      id_token_hint: idToken,
      client_id: confidentialClient().id,
      post_logout_redirect_uri: RETURN_URI,
      state: 'wire-client-state',
    });

    expectReturned(response, 'wire-client-state');
    expectSessionCookieCleared(response, session);
  });

  it('refuses a post_logout_redirect_uri the client did not register with a page, never a redirect, and ends nothing (§3.1)', async () => {
    const { session, idToken } = await signedInWithIdToken();

    const response = await endSessionGet(session.browser, {
      id_token_hint: idToken,
      post_logout_redirect_uri: 'http://127.0.0.1:9/wire-suite/elsewhere',
      state: 'wire-unregistered-state',
    });

    const html = await htmlPage(response, 400);
    expect(html).not.toContain('wire-unregistered-state');
    expectSessionCookieKept(response);
    await expectStillSignedIn(session);
  });

  it('refuses a client_id that is not the hint’s audience, and ends nothing (§2)', async () => {
    const { session, idToken } = await signedInWithIdToken();

    const response = await endSessionGet(session.browser, {
      id_token_hint: idToken,
      client_id: 'wire-suite-another-client',
      post_logout_redirect_uri: RETURN_URI,
    });

    await htmlPage(response, 400);
    expectSessionCookieKept(response);
    await expectStillSignedIn(session);
  });

  it('asks a signed-in browser to confirm when there is no hint, and ends nothing until it answers', async () => {
    const session = await consentedBrowser();

    const response = await endSessionGet(session.browser, {
      client_id: confidentialClient().id,
      post_logout_redirect_uri: RETURN_URI,
      state: 'wire-confirm-state',
    });

    confirmForm(await htmlPage(response, 200));
    expectSessionCookieKept(response);
    await expectStillSignedIn(session);
  });

  it('ends the session once the person answers the confirm step with logout, and goes back with state (§3)', async () => {
    const session = await consentedBrowser();
    const form = confirmForm(
      await htmlPage(
        await endSessionGet(session.browser, {
          client_id: confidentialClient().id,
          post_logout_redirect_uri: RETURN_URI,
          state: 'wire-answer-state',
        }),
        200
      )
    );

    const answered = await answerConfirm(session, form, 'logout');

    expectReturned(answered, 'wire-answer-state');
    expectSessionCookieCleared(answered, session);
    await expectSignedOut(session);
  });

  it('keeps the session when the person stays signed in, and still goes back with state (§3)', async () => {
    const session = await consentedBrowser();
    const form = confirmForm(
      await htmlPage(
        await endSessionGet(session.browser, {
          client_id: confidentialClient().id,
          post_logout_redirect_uri: RETURN_URI,
          state: 'wire-stay-state',
        }),
        200
      )
    );

    const answered = await answerConfirm(session, form, 'stay');

    expectReturned(answered, 'wire-stay-state');
    expectSessionCookieKept(answered);
    await expectStillSignedIn(session);
  });

  it('sends a browser that is not signed in back to the registered URI with state (§3)', async () => {
    const response = await endSessionGet(new Browser(), {
      client_id: confidentialClient().id,
      post_logout_redirect_uri: RETURN_URI,
      state: 'wire-nobody-state',
    });

    expectReturned(response, 'wire-nobody-state');
  });
});

describe('[POST /oauth/end-session] OpenID Connect RP-Initiated Logout 1.0 — the end-session endpoint, by form post', () => {
  it('ends the session for a valid id_token_hint in the form body and sends the browser back with state (§2, §3)', async () => {
    const { session, idToken } = await signedInWithIdToken();

    const response = await endSessionPost(session.browser, {
      id_token_hint: idToken,
      post_logout_redirect_uri: RETURN_URI,
      state: 'wire-post-state',
    });

    expectReturned(response, 'wire-post-state');
    expectSessionCookieCleared(response, session);
    await expectSignedOut(session);
  });

  it('sends a POST without the session cookie again as a GET with the same parameters, ending nothing on that leg (§2)', async () => {
    const { session, idToken } = await signedInWithIdToken();
    const params = {
      id_token_hint: idToken,
      post_logout_redirect_uri: RETURN_URI,
      state: 'wire-resend-state',
    };

    // A cross-site form post: the SameSite=Lax session cookie stays behind.
    const posted = await call('POST /oauth/end-session', { form: params });

    expect(posted.status).toBe(303);
    expect(posted.headers.get('cache-control')).toBe('no-store');
    const location = new URL(posted.headers.get('location') ?? '', END_SESSION_URL);
    expect(`${location.origin}${location.pathname}`).toBe(END_SESSION_URL.href);
    expect(Object.fromEntries(location.searchParams)).toEqual(params);
    expectSessionCookieKept(posted);
    await expectStillSignedIn(session);

    // The browser follows the 303 with its cookie: now the session ends.
    const cookie = session.browser.jar.headerFor(location);
    const followed = await fetch(location, {
      headers: cookie === undefined ? {} : { cookie },
      redirect: 'manual',
    });
    session.browser.jar.storeFrom(location, followed);
    expectReturned(followed, 'wire-resend-state');
    expectSessionCookieCleared(followed, session);
    await expectSignedOut(session);
  });

  it('refuses a post_logout_redirect_uri the client did not register, and ends nothing (§3.1)', async () => {
    const { session, idToken } = await signedInWithIdToken();

    const response = await endSessionPost(session.browser, {
      id_token_hint: idToken,
      post_logout_redirect_uri: 'http://127.0.0.1:9/wire-suite/elsewhere',
    });

    await htmlPage(response, 400);
    expectSessionCookieKept(response);
    await expectStillSignedIn(session);
  });
});

describe('[GET /oauth/end-session/status] OpenID Connect RP-Initiated Logout 1.0 — the sign-out status page', () => {
  it('says a browser with no session is signed out', async () => {
    expect(await statusOf(new Browser())).toBe('signed out');
  });

  it('says a signed-in browser is still signed in, and signed out once its session ended', async () => {
    const { session, idToken } = await signedInWithIdToken();
    expect(await statusOf(session.browser)).toBe('signed in');

    expectReturned(
      await endSessionGet(session.browser, {
        id_token_hint: idToken,
        post_logout_redirect_uri: RETURN_URI,
        state: 'wire-status-state',
      }),
      'wire-status-state'
    );

    expect(await statusOf(session.browser)).toBe('signed out');
  });
});
