import { describe, expect, it } from 'vitest';

import { esc, html, render, safe } from './html';

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
});
