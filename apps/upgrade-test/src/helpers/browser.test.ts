import { describe, expect, it } from 'vitest';

import { CookieJar, decodeHtmlAttribute, formBody, parseForms } from './browser';

/** The shape of the hosted login page: a multi-line input, hidden fields, a link. */
const LOGIN_PAGE = `<!doctype html><html><body>
  <form class="card" method="post" action="/ui/login">
    <input type="hidden" name="return_to" value="/ui/resume/abc&amp;x=1" />
    <input type="hidden" name="csrf_token" value="tok_&#x41;&#66;" />
    <label>Email
      <input
        type="email"
        name="email"
        value="old@example.com"
        autocomplete="username"
        required
      />
    </label>
    <input type="password" name="password" autocomplete="current-password" required />
    <button type="submit">Sign in</button>
  </form>
  <a href="/ui/wallet-login?return_to=%2F">Use a wallet</a>
</body></html>`;

/** The shape of the consent page: a checked box, an unchecked one, two named buttons. */
const CONSENT_PAGE = `<form method="POST" action='/ui/consent'>
  <input type="hidden" name="client_id" value="app" />
  <input type="hidden" name="resource" value="https://a.example" />
  <input type="hidden" name="resource" value="https://b.example" />
  <input type="checkbox" name="allow_forever" value="1" checked />
  <input type="checkbox" name="marketing" value="1" />
  <input type="hidden" name="csrf_token" value="c1" />
  <button type="submit" name="decision" value="deny" class="deny">Deny</button>
  <button type="submit" name="decision" value="allow" class="allow">Allow</button>
</form>`;

describe('parseForms', () => {
  it('reads action, method, every named input and the buttons', () => {
    const [form] = parseForms(LOGIN_PAGE);
    expect(form.action).toBe('/ui/login');
    expect(form.method).toBe('post');
    expect(form.inputs).toEqual([
      { name: 'return_to', type: 'hidden', value: '/ui/resume/abc&x=1' },
      { name: 'csrf_token', type: 'hidden', value: 'tok_AB' },
      { name: 'email', type: 'email', value: 'old@example.com' },
      { name: 'password', type: 'password', value: '' },
    ]);
    expect(form.buttons).toEqual([]);
  });

  it('leaves unchecked boxes out and keeps repeated names', () => {
    const [form] = parseForms(CONSENT_PAGE);
    expect(form.method).toBe('post');
    expect(form.action).toBe('/ui/consent');
    expect(form.inputs.map((input) => input.name)).toEqual([
      'client_id',
      'resource',
      'resource',
      'allow_forever',
      'csrf_token',
    ]);
    expect(form.buttons).toEqual([
      { name: 'decision', value: 'deny' },
      { name: 'decision', value: 'allow' },
    ]);
  });

  it('defaults the method to get and finds every form', () => {
    expect(parseForms('<form action="/a"></form><form method="post"></form>')).toEqual([
      { action: '/a', method: 'get', inputs: [], buttons: [] },
      { action: '', method: 'post', inputs: [], buttons: [] },
    ]);
  });
});

describe('formBody', () => {
  it('sends the rendered values, overriding the fields given', () => {
    const [form] = parseForms(LOGIN_PAGE);
    expect(formBody(form, { email: 'new@example.com', password: 'pw' }).toString()).toBe(
      'return_to=%2Fui%2Fresume%2Fabc%26x%3D1&csrf_token=tok_AB&email=new%40example.com&password=pw'
    );
  });

  it('adds the chosen submit button, as a browser does', () => {
    const [form] = parseForms(CONSENT_PAGE);
    const body = formBody(form, {}, { name: 'decision', value: 'allow' });
    expect(body.getAll('resource')).toEqual(['https://a.example', 'https://b.example']);
    expect(body.get('allow_forever')).toBe('1');
    expect(body.has('marketing')).toBe(false);
    expect(body.getAll('decision')).toEqual(['allow']);
  });

  it('refuses a button the form does not have', () => {
    const [form] = parseForms(LOGIN_PAGE);
    expect(() => formBody(form, {}, { name: 'decision', value: 'allow' })).toThrow(
      /has no decision=allow button/
    );
  });
});

describe('decodeHtmlAttribute', () => {
  it('decodes named, decimal and hex references and leaves unknown ones', () => {
    expect(decodeHtmlAttribute('a&amp;b&quot;&#39;&#x3c;&unknown;')).toBe('a&b"\'<&unknown;');
  });
});

describe('CookieJar', () => {
  it('keeps the latest value per name and sends them all', () => {
    const jar = new CookieJar();
    expect(jar.header()).toBeUndefined();
    jar.store('__Host-qauth_login_csrf=one; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400');
    jar.store('qauth_session=s1; Path=/');
    jar.store('__Host-qauth_login_csrf=two; Path=/');
    expect(jar.header()).toBe('__Host-qauth_login_csrf=two; qauth_session=s1');
  });

  it('forgets a cookie cleared by Max-Age=0 or a past Expires', () => {
    const jar = new CookieJar();
    jar.store('a=1');
    jar.store('b=2');
    jar.store('a=; Max-Age=0');
    jar.store('b=; Expires=Thu, 01 Jan 1970 00:00:00 GMT', Date.UTC(2026, 0, 1));
    expect(jar.header()).toBeUndefined();
  });

  it('reads every Set-Cookie header of a response', () => {
    const jar = new CookieJar();
    const headers = new Headers();
    headers.append('set-cookie', 'a=1; Path=/');
    headers.append('set-cookie', 'b=2; Path=/');
    jar.storeFrom(new Response(null, { headers }));
    expect(jar.header()).toBe('a=1; b=2');
  });
});
