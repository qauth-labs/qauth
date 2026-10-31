import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Browser } from './browser';
import { type LoopbackServer, startLoopbackServer } from './loopback-server';

/**
 * A loopback imitation of the server's browser flow: the authorization
 * endpoint sends a browser without a session to the sign-in page, the sign-in
 * POST checks its CSRF pair and the password, and the consent screen sends the
 * decision to the redirect URI. Consent is remembered per session when asked.
 */
const PASSWORD = 'right-password';
const REDIRECT_URI = 'http://127.0.0.1:9/wire-suite/callback';

let server: LoopbackServer;
const remembered = new Set<string>();
let posts: { path: string; body: URLSearchParams }[] = [];

function cookieOf(header: string | undefined, name: string): string | undefined {
  return header
    ?.split('; ')
    .find((pair) => pair.startsWith(`${name}=`))
    ?.slice(name.length + 1);
}

beforeAll(async () => {
  server = await startLoopbackServer((request, response, rawBody) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    const session = cookieOf(request.headers.cookie, 'sid');
    const page = (status: number, html: string, cookie?: string) => {
      response.writeHead(status, {
        'content-type': 'text/html; charset=utf-8',
        ...(cookie ? { 'set-cookie': cookie } : {}),
      });
      response.end(html);
    };
    const redirect = (location: string, cookie?: string) => {
      response.writeHead(302, { location, ...(cookie ? { 'set-cookie': cookie } : {}) });
      response.end();
    };
    const body = new URLSearchParams(rawBody);
    if (request.method === 'POST') posts.push({ path: url.pathname, body });

    switch (`${request.method} ${url.pathname}`) {
      case 'GET /authorize':
        if (!session) return redirect('/ui/login?return_to=%2Fresume%2Fh1');
        if (remembered.has(session)) return redirect(`${REDIRECT_URI}?code=c2&state=s&iss=x`);
        return redirect('/ui/consent?state=s');
      case 'GET /ui/login':
        return page(
          200,
          `<form method="post" action="/ui/login">
             <input type="hidden" name="return_to" value="/resume/h1" />
             <input type="hidden" name="csrf_token" value="t&amp;1" />
             <input type="email" name="email" value="" />
             <input type="password" name="password" />
             <button type="submit">Sign in</button>
           </form>`,
          'csrf=t&1; Path=/; HttpOnly'
        );
      case 'POST /ui/login':
        if (cookieOf(request.headers.cookie, 'csrf') !== body.get('csrf_token')) {
          return page(403, '<p>csrf</p>');
        }
        if (body.get('password') !== PASSWORD) {
          return page(401, '<form method="post" action="/ui/login"></form>');
        }
        return redirect(body.get('return_to') ?? '/', `sid=${body.get('email')}; Path=/`);
      case 'GET /resume/h1':
        return redirect('/authorize?resumed=1');
      case 'GET /ui/consent':
        return page(
          200,
          `<form method="post" action="/ui/consent">
             <input type="checkbox" name="allow_forever" value="1" checked />
             <input type="hidden" name="state" value="s" />
             <button type="submit" name="decision" value="deny">Deny</button>
             <button type="submit" name="decision" value="allow">Allow</button>
           </form>`
        );
      case 'POST /ui/consent':
        if (!session) return page(401, 'no session');
        if (body.get('decision') !== 'allow') {
          return redirect(`${REDIRECT_URI}?error=access_denied&state=s&iss=x`);
        }
        if (body.get('allow_forever') === '1') remembered.add(session);
        return redirect(`${REDIRECT_URI}?code=c1&state=${body.get('state')}&iss=x`);
      default:
        return page(404, 'not found');
    }
  });
});

afterAll(async () => {
  await server.close();
});

function authorizationUrl(): URL {
  return new URL('/authorize', server.url);
}

describe('a browser driving the sign-in page and the consent screen', () => {
  it('signs in, allows, and stops at the redirect URI without requesting it', async () => {
    posts = [];
    const browser = new Browser();

    const response = await browser.authorize(authorizationUrl(), REDIRECT_URI, {
      credentials: { email: 'a@example.com', password: PASSWORD },
    });

    expect(response.pages).toEqual(['sign-in', 'consent']);
    expect(response.params.get('code')).toBe('c1');
    expect(response.url.origin + response.url.pathname).toBe(REDIRECT_URI);
    expect(posts.map((post) => post.path)).toEqual(['/ui/login', '/ui/consent']);
    expect(Object.fromEntries(posts[0].body)).toEqual({
      return_to: '/resume/h1',
      csrf_token: 't&1',
      email: 'a@example.com',
      password: PASSWORD,
    });
    expect([...posts[1].body]).toEqual([
      ['allow_forever', '1'],
      ['state', 's'],
      ['decision', 'allow'],
    ]);
    expect(response.hops.at(-1)?.location).toContain('code=c1');
  });

  it('goes straight to the redirect URI once the decision is remembered', async () => {
    const browser = new Browser();
    const credentials = { email: 'b@example.com', password: PASSWORD };
    await browser.authorize(authorizationUrl(), REDIRECT_URI, { credentials });

    const again = await browser.authorize(authorizationUrl(), REDIRECT_URI, { credentials });

    expect(again.pages).toEqual([]);
    expect(again.params.get('code')).toBe('c2');
  });

  it('presses deny and unticks "Remember this decision" when told to', async () => {
    posts = [];
    const browser = new Browser();
    const credentials = { email: 'c@example.com', password: PASSWORD };

    const denied = await browser.authorize(authorizationUrl(), REDIRECT_URI, {
      credentials,
      decision: 'deny',
      rememberConsent: false,
    });

    expect(denied.params.get('error')).toBe('access_denied');
    expect(posts[1].body.get('decision')).toBe('deny');
    expect(posts[1].body.has('allow_forever')).toBe(false);
  });

  it('names the verified-account setting when the sign-in page comes back', async () => {
    const browser = new Browser();

    await expect(
      browser.authorize(authorizationUrl(), REDIRECT_URI, {
        credentials: { email: 'd@example.com', password: 'wrong' },
      })
    ).rejects.toThrow(/refused to sign in d@example\.com.*QAUTH_WIRE_MAIL_URL/s);
  });

  it('refuses a page that is neither a redirect nor one of the two forms', async () => {
    const browser = new Browser();

    await expect(
      browser.authorize(new URL('/elsewhere', server.url), REDIRECT_URI, {
        credentials: { email: 'e@example.com', password: PASSWORD },
      })
    ).rejects.toThrow(/expected a redirect, the sign-in page or the consent screen.*404/s);
  });
});
