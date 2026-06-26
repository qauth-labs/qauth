import { describe, expect, it } from 'vitest';

import { esc, html, render, safe, safeUrl } from './html';

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
