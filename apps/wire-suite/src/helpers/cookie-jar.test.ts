import { describe, expect, it } from 'vitest';

import { CookieJar } from './cookie-jar';

const NOW = Date.parse('2026-10-20T00:00:00Z');

describe('CookieJar', () => {
  it('sends a host-only cookie back to the host that set it, and to no other host', () => {
    const jar = new CookieJar();
    jar.store('http://localhost:3000/ui/login', 'sid=abc; Path=/; HttpOnly', NOW);

    expect(jar.headerFor('http://localhost:3000/oauth/authorize', NOW)).toBe('sid=abc');
    expect(jar.headerFor('http://127.0.0.1:3000/oauth/authorize', NOW)).toBeUndefined();
    expect(jar.headerFor('http://sub.localhost:3000/', NOW)).toBeUndefined();
  });

  it('sends a Domain cookie to that domain and its subdomains', () => {
    const jar = new CookieJar();
    jar.store('https://id.example/', 'a=1; Domain=id.example; Path=/', NOW);

    expect(jar.headerFor('https://id.example/', NOW)).toBe('a=1');
    expect(jar.headerFor('https://eu.id.example/', NOW)).toBe('a=1');
    expect(jar.headerFor('https://other.example/', NOW)).toBeUndefined();
  });

  it('ignores a cookie whose Domain does not cover the host that set it', () => {
    const jar = new CookieJar();
    jar.store('https://id.example/', 'a=1; Domain=attacker.example', NOW);

    expect(jar.headerFor('https://attacker.example/', NOW)).toBeUndefined();
    expect(jar.headerFor('https://id.example/', NOW)).toBeUndefined();
  });

  it('defaults Path to the directory of the request path and matches it on segment boundaries', () => {
    const jar = new CookieJar();
    jar.store('http://localhost/ui/login', 'a=1', NOW);

    expect(jar.headerFor('http://localhost/ui', NOW)).toBe('a=1');
    expect(jar.headerFor('http://localhost/ui/consent', NOW)).toBe('a=1');
    expect(jar.headerFor('http://localhost/uix', NOW)).toBeUndefined();
    expect(jar.headerFor('http://localhost/', NOW)).toBeUndefined();
  });

  it('orders cookies with longer paths first', () => {
    const jar = new CookieJar();
    jar.store('http://localhost/', 'outer=1; Path=/', NOW);
    jar.store('http://localhost/', 'inner=2; Path=/ui', NOW);

    expect(jar.headerFor('http://localhost/ui/login', NOW)).toBe('inner=2; outer=1');
  });

  it('replaces a cookie with the same name, domain and path', () => {
    const jar = new CookieJar();
    jar.store('http://localhost/', 'sid=old; Path=/', NOW);
    jar.store('http://localhost/', 'sid=new; Path=/', NOW);

    expect(jar.headerFor('http://localhost/', NOW)).toBe('sid=new');
  });

  it('deletes a cookie on Max-Age=0 or an Expires in the past', () => {
    const jar = new CookieJar();
    jar.store('http://localhost/', 'a=1; Path=/', NOW);
    jar.store('http://localhost/', 'b=2; Path=/', NOW);
    jar.store('http://localhost/', 'a=; Path=/; Max-Age=0', NOW);
    jar.store('http://localhost/', 'b=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT', NOW);

    expect(jar.headerFor('http://localhost/', NOW)).toBeUndefined();
  });

  it('lets Max-Age win over Expires and drops a cookie once it has expired', () => {
    const jar = new CookieJar();
    jar.store(
      'http://localhost/',
      'a=1; Path=/; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
      NOW
    );

    expect(jar.headerFor('http://localhost/', NOW + 59_000)).toBe('a=1');
    expect(jar.headerFor('http://localhost/', NOW + 61_000)).toBeUndefined();
  });

  it('keeps a Secure cookie off plain http, except to loopback hosts', () => {
    const jar = new CookieJar();
    jar.store('https://id.example/', '__Host-sid=1; Secure; Path=/', NOW);
    jar.store('http://localhost/', '__Host-sid=2; Secure; Path=/', NOW);
    jar.store('http://plain.example/', 'insecure=3; Secure; Path=/', NOW);

    expect(jar.headerFor('https://id.example/', NOW)).toBe('__Host-sid=1');
    expect(jar.headerFor('http://id.example/', NOW)).toBeUndefined();
    expect(jar.headerFor('http://localhost/', NOW)).toBe('__Host-sid=2');
    expect(jar.headerFor('http://plain.example/', NOW)).toBeUndefined();
  });

  it('keeps a value that contains "=" intact', () => {
    const jar = new CookieJar();
    jar.store('http://localhost/', 'sig=a.b=c==; Path=/', NOW);

    expect(jar.get('http://localhost/', 'sig')).toBe('a.b=c==');
  });

  it('ignores a header with no name', () => {
    const jar = new CookieJar();
    jar.store('http://localhost/', '=value; Path=/', NOW);
    jar.store('http://localhost/', 'novalue', NOW);

    expect(jar.headerFor('http://localhost/', NOW)).toBeUndefined();
  });

  it('stores every Set-Cookie header of a response', () => {
    const jar = new CookieJar();
    const headers = new Headers();
    headers.append('set-cookie', 'a=1; Path=/');
    headers.append('set-cookie', 'b=2; Path=/');
    jar.storeFrom('http://localhost/', new Response(null, { headers }));

    expect(jar.headerFor('http://localhost/')).toBe('a=1; b=2');
  });
});
