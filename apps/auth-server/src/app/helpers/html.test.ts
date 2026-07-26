import { describe, expect, it } from 'vitest';

import { esc, html, render, safe, safeCustomSchemeUrl, safeUrl } from './html';

describe('html helpers', () => {
  it('esc escapes HTML-special characters', () => {
    expect(esc(`<script>alert("x")</script>`)).toBe(
      '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;'
    );
    expect(esc(undefined)).toBe('');
    expect(esc(null)).toBe('');
  });

  it('html template tag escapes interpolations', () => {
    const out = render(html`<p>${'<b>hi</b>'}</p>`);
    expect(out).toBe('<p>&lt;b&gt;hi&lt;/b&gt;</p>');
  });

  it('safe() bypasses escaping for trusted fragments', () => {
    const fragment = safe('<b>trust</b>');
    const out = render(html`<p>${fragment}</p>`);
    expect(out).toBe('<p><b>trust</b></p>');
  });

  it('arrays of values are concatenated with each element escaped', () => {
    const items = ['<a>', '<b>'];
    const out = render(html`${items}`);
    expect(out).toBe('&lt;a&gt;&lt;b&gt;');
  });

  it('esc neutralises single quotes (attribute breakout defence)', () => {
    expect(esc(`' onmouseover='alert(1)`)).toBe('&#39; onmouseover=&#39;alert(1)');
  });
});

describe('safeUrl (#112)', () => {
  it('accepts http(s) and mailto URLs unchanged', () => {
    expect(safeUrl('https://example.com/app')).toBe('https://example.com/app');
    expect(safeUrl('http://example.com')).toBe('http://example.com');
    expect(safeUrl('mailto:ops@example.com')).toBe('mailto:ops@example.com');
  });

  it('rejects javascript:/data:/vbscript: URLs (XSS vectors)', () => {
    expect(safeUrl('javascript:alert(1)')).toBeUndefined();
    expect(safeUrl('JavaScript:alert(1)')).toBeUndefined();
    expect(safeUrl('data:text/html,<script>alert(1)</script>')).toBeUndefined();
    expect(safeUrl('vbscript:msgbox(1)')).toBeUndefined();
  });

  it('rejects relative URLs and non-string/empty input', () => {
    expect(safeUrl('/relative/path')).toBeUndefined();
    expect(safeUrl('not a url')).toBeUndefined();
    expect(safeUrl('')).toBeUndefined();
    expect(safeUrl(undefined)).toBeUndefined();
    expect(safeUrl(null)).toBeUndefined();
    expect(safeUrl(42)).toBeUndefined();
  });

  it('a rejected href is not rendered as a clickable link in a page fragment', () => {
    const evil = 'javascript:alert(document.cookie)';
    const href = safeUrl(evil);
    const out = render(href ? html`<a href="${href}">link</a>` : html`<span>no link</span>`);
    expect(out).not.toContain('javascript:');
    expect(out).toBe('<span>no link</span>');
  });
});

describe('safeCustomSchemeUrl (#239)', () => {
  it.each([
    'openid4vp://',
    'openid4vp://authorize?request_uri=https%3A%2F%2Fa.example%2Fr',
    'OpenID4VP://authorize',
    'haip://',
    'eudi-wallet://authorize',
    'mdoc-openid4vp://',
    'x-wallet.vendor+v2://go',
    'https://wallet.example/authorize',
  ])('passes the open-ended wallet scheme %j through unchanged', (value) => {
    // The whole reason this is not an allowlist: no closed set of wallet
    // schemes exists, and a fix that only permitted https would delete the
    // custom-scheme deep link the feature is built on.
    expect(safeCustomSchemeUrl(value)).toBe(value);
  });

  it.each([
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    'jAvAsCrIpT:alert(1)',
    'vbscript:msgbox(1)',
    'livescript:alert(1)',
    'mocha:alert(1)',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'blob:https://evil.example/1234',
    'java\tscript:alert(1)',
    'java\u0000script:alert(1)',
    'java script:alert(1)',
    ' javascript:alert(1)',
    'java&#9;script:alert(1)',
    'java&Tab;script:alert(1)',
    '&#106;avascript:alert(1)',
    '&#x6A;avascript:alert(1)',
    'javascript&colon;alert(1)',
  ])('refuses the script-capable %j', (value) => {
    expect(safeCustomSchemeUrl(value)).toBeUndefined();
  });

  it('refuses a relative reference and non-string/empty input', () => {
    expect(safeCustomSchemeUrl('/ui/login')).toBeUndefined();
    expect(safeCustomSchemeUrl('no-scheme')).toBeUndefined();
    expect(safeCustomSchemeUrl('')).toBeUndefined();
    expect(safeCustomSchemeUrl(undefined)).toBeUndefined();
    expect(safeCustomSchemeUrl(null)).toBeUndefined();
    expect(safeCustomSchemeUrl(42)).toBeUndefined();
  });

  it('is strictly weaker than safeUrl and must not be used in its place', () => {
    // Pins the relationship the JSDoc states: every scheme safeUrl admits, this
    // admits too — so a careless swap would silently widen a client-data href
    // from three schemes to "anything not obviously executable".
    for (const url of ['https://example.com/a', 'http://example.com', 'mailto:ops@example.com']) {
      expect(safeUrl(url)).toBe(url);
      expect(safeCustomSchemeUrl(url)).toBe(url);
    }
    expect(safeUrl('openid4vp://authorize')).toBeUndefined();
    expect(safeCustomSchemeUrl('openid4vp://authorize')).toBe('openid4vp://authorize');
  });
});
