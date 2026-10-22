import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { CookieJar } from './cookie-jar';
import { type LoopbackServer, startLoopbackServer } from './loopback-server';
import { followRedirects } from './redirects';

interface Seen {
  method: string;
  url: string;
  cookie?: string;
  body: string;
  contentType?: string;
}

let server: LoopbackServer;
const seen: Seen[] = [];

beforeAll(async () => {
  server = await startLoopbackServer((request, response, body) => {
    const url = request.url ?? '/';
    seen.push({
      method: request.method ?? '',
      url,
      cookie: request.headers.cookie,
      body,
      contentType: request.headers['content-type'],
    });
    const redirect = (status: number, location: string, cookie?: string) => {
      response.writeHead(status, { location, ...(cookie ? { 'set-cookie': cookie } : {}) });
      response.end();
    };
    switch (url.split('?')[0]) {
      case '/login':
        return redirect(302, '/authorize', 'sid=s1; Path=/; HttpOnly');
      case '/authorize':
        return redirect(302, 'http://127.0.0.1:9/callback?code=abc&state=xyz');
      case '/post-303':
        return redirect(303, '/landing');
      case '/post-302':
        return redirect(302, '/landing');
      case '/post-307':
        return redirect(307, '/echo');
      case '/loop':
        return redirect(302, '/loop');
      case '/no-location':
        response.writeHead(302);
        return response.end();
      default:
        response.writeHead(200, { 'content-type': 'text/plain' });
        return response.end('done');
    }
  });
});

afterAll(async () => {
  await server.close();
});

function sinceNow(): () => Seen[] {
  const start = seen.length;
  return () => seen.slice(start);
}

describe('followRedirects', () => {
  it('carries cookies across hops and stops before the client redirect URI', async () => {
    const requests = sinceNow();
    const jar = new CookieJar();
    const result = await followRedirects(jar, `${server.url}/login`, {
      stopAt: (url) => url.port === '9',
    });

    expect(result.stoppedAt?.searchParams.get('code')).toBe('abc');
    expect(result.hops.map((hop) => hop.status)).toEqual([302, 302]);
    expect(result.hops[1].location).toBe('http://127.0.0.1:9/callback?code=abc&state=xyz');
    // The cookie set on the first hop went out with the second request.
    expect(requests().map((r) => r.cookie)).toEqual([undefined, 'sid=s1']);
    expect(jar.get(server.url, 'sid')).toBe('s1');
  });

  it('turns a POST into a body-less GET on 303, and on 302', async () => {
    for (const path of ['/post-303', '/post-302']) {
      const requests = sinceNow();
      const result = await followRedirects(new CookieJar(), `${server.url}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ a: '1' }),
      });

      expect(result.response.status).toBe(200);
      const [first, second] = requests();
      expect(first).toMatchObject({ method: 'POST', body: 'a=1' });
      expect(second).toMatchObject({ method: 'GET', url: '/landing', body: '' });
      expect(second.contentType).toBeUndefined();
    }
  });

  it('repeats the method and the body on 307', async () => {
    const requests = sinceNow();
    await followRedirects(new CookieJar(), `${server.url}/post-307`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'a=1',
    });

    expect(requests()[1]).toMatchObject({ method: 'POST', url: '/echo', body: 'a=1' });
  });

  it('gives up after maxHops instead of looping', async () => {
    await expect(
      followRedirects(new CookieJar(), `${server.url}/loop`, { maxHops: 3 })
    ).rejects.toThrow(/more than 3 requests/);
  });

  it('fails on a redirect with no Location', async () => {
    await expect(followRedirects(new CookieJar(), `${server.url}/no-location`)).rejects.toThrow(
      /no Location header/
    );
  });
});
